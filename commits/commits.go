// SPDX-License-Identifier: MIT

// Package commits extracts deterministic commit-level evidence from a
// local git repository. Output conforms to wake-core's evidence schema
// and is suitable as input to downstream event classification.
package commits

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/skaphos/wake-core/evidence"
)

// Field/record separators are ASCII control characters that never appear in
// commit metadata, so a multi-line commit body and diff text can be carried as
// ordinary delimited fields without ambiguity.
const (
	recordSep = "\x1e" // start of each commit record
	fieldSep  = "\x1f" // between header fields, and after the body
)

// DefaultMaxDiffBytes bounds per-file patch text when diffs are requested and
// no explicit budget is given.
const DefaultMaxDiffBytes = 60000

// Options describes an extraction request. RevRange is passed through to
// `git log` (empty means all reachable commits); Subpaths narrow the
// history to the given paths (empty means the whole tree).
type Options struct {
	RepoPath     string
	Subpaths     []string
	RevisionFrom string
	RevisionTo   string
	// IncludeDiffs additionally captures unified-diff text per touched path
	// (via `git log --patch`). Off by default because diffs are large.
	IncludeDiffs bool
	// MaxDiffBytes caps captured patch text per path when IncludeDiffs is set
	// (0 uses DefaultMaxDiffBytes).
	MaxDiffBytes int
}

// Extract walks the repository history and returns a bundle of commit
// records. The caller is responsible for opening/validating the repo;
// Options.RepoPath is forwarded to `git -C`.
func Extract(ctx context.Context, opts Options) (evidence.Bundle, error) {
	if strings.TrimSpace(opts.RepoPath) == "" {
		return evidence.Bundle{}, fmt.Errorf("repository path must not be empty")
	}

	revRange, err := buildRevRange(opts.RevisionFrom, opts.RevisionTo)
	if err != nil {
		return evidence.Bundle{}, err
	}

	// Header fields are delimited so the full body (%B) can be multi-line; the
	// trailing fieldSep separates the body from the --raw/--numstat/--patch
	// block that git appends after the formatted line.
	format := "--format=" + recordSep + "%H" + fieldSep + "%P" + fieldSep +
		"%aI" + fieldSep + "%aN" + fieldSep + "%aE" + fieldSep + "%B" + fieldSep

	args := []string{
		"-C", opts.RepoPath,
		"log",
		"--no-color",
		"--date=iso-strict",
		format,
		"--raw",
		"--numstat",
	}
	if opts.IncludeDiffs {
		args = append(args, "--patch")
	}
	if revRange != "" {
		args = append(args, revRange)
	}
	if len(opts.Subpaths) > 0 {
		args = append(args, "--")
		args = append(args, opts.Subpaths...)
	}

	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Env = append(cmd.Env, "LC_ALL=C", "TZ=UTC", "GIT_CONFIG_NOSYSTEM=1")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return evidence.Bundle{}, fmt.Errorf("git log failed: %w: %s", err, strings.TrimSpace(stderr.String()))
	}

	maxDiff := opts.MaxDiffBytes
	if maxDiff == 0 {
		maxDiff = DefaultMaxDiffBytes
	}
	commits, err := parseLog(out, opts.IncludeDiffs, maxDiff)
	if err != nil {
		return evidence.Bundle{}, err
	}

	return evidence.Bundle{
		SchemaVersion: evidence.SchemaVersion,
		GeneratedAt:   time.Now().UTC(),
		Target: evidence.RepositoryTarget{
			Repository:   opts.RepoPath,
			Subpaths:     append([]string(nil), opts.Subpaths...),
			RevisionFrom: opts.RevisionFrom,
			RevisionTo:   opts.RevisionTo,
		},
		Commits: commits,
	}, nil
}

func buildRevRange(from, to string) (string, error) {
	from = strings.TrimSpace(from)
	to = strings.TrimSpace(to)
	switch {
	case from == "" && to == "":
		return "", nil
	case from == "" && to != "":
		return to, nil
	case from != "" && to == "":
		return from + "..HEAD", nil
	default:
		return from + ".." + to, nil
	}
}

func parseLog(raw []byte, includeDiffs bool, maxDiffBytes int) ([]evidence.CommitRecord, error) {
	var records []evidence.CommitRecord

	// Each commit record begins with recordSep; the first split element is the
	// empty prefix before the first record.
	for _, chunk := range strings.Split(string(raw), recordSep) {
		if strings.TrimSpace(chunk) == "" {
			continue
		}
		rec, err := parseCommit(chunk, includeDiffs, maxDiffBytes)
		if err != nil {
			return nil, err
		}
		records = append(records, rec)
	}
	return records, nil
}

// parseCommit parses one recordSep-delimited commit chunk. The chunk is
// "sha US parents US date US name US email US body US rest", where rest holds
// the --raw/--numstat (and optional --patch) block git appended.
func parseCommit(chunk string, includeDiffs bool, maxDiffBytes int) (evidence.CommitRecord, error) {
	parts := strings.SplitN(chunk, fieldSep, 7)
	if len(parts) < 7 {
		return evidence.CommitRecord{}, fmt.Errorf("malformed commit record: %d fields", len(parts))
	}

	sha := strings.TrimSpace(parts[0])
	if sha == "" {
		return evidence.CommitRecord{}, fmt.Errorf("missing commit sha")
	}
	var parents []string
	if p := strings.TrimSpace(parts[1]); p != "" {
		parents = strings.Fields(p)
	}
	authoredAt, err := time.Parse(time.RFC3339, strings.TrimSpace(parts[2]))
	if err != nil {
		return evidence.CommitRecord{}, fmt.Errorf("parse authored_at for %s: %w", sha, err)
	}

	body := strings.TrimRight(parts[5], "\n")
	rec := evidence.CommitRecord{
		SHA:     sha,
		Parents: parents,
		Author: evidence.ContributorIdentity{
			CanonicalName:  strings.TrimSpace(parts[3]),
			CanonicalEmail: strings.TrimSpace(parts[4]),
		},
		AuthoredAt: authoredAt.UTC(),
		Summary:    firstLine(body),
		Message:    body,
	}

	if err := applyChanges(parts[6], &rec, includeDiffs, maxDiffBytes); err != nil {
		return evidence.CommitRecord{}, err
	}
	return rec, nil
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i != -1 {
		return s[:i]
	}
	return s
}

// applyChanges parses the --raw/--numstat block (and, when present, the
// --patch section) and populates the commit's TouchedPath deltas in first-seen
// order.
func applyChanges(rest string, rec *evidence.CommitRecord, includeDiffs bool, maxDiffBytes int) error {
	deltas := map[string]*evidence.PathDelta{}
	var order []string
	ensure := func(path string) *evidence.PathDelta {
		d, ok := deltas[path]
		if !ok {
			d = &evidence.PathDelta{Path: path}
			deltas[path] = d
			order = append(order, path)
		}
		return d
	}

	lines := strings.Split(rest, "\n")
	i := 0
	// Metadata phase: --raw (":"-prefixed) and --numstat lines, until the
	// patch section begins or the block ends.
	for ; i < len(lines); i++ {
		line := lines[i]
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "diff --git ") {
			break
		}
		if strings.HasPrefix(line, ":") {
			path, kind, err := parseRawLine(line)
			if err != nil {
				return err
			}
			ensure(path).Change = kind
			continue
		}
		path, add, del, err := parseNumstatLine(line)
		if err != nil {
			// Not a numstat line; ignore defensively rather than failing the run.
			continue
		}
		d := ensure(path)
		d.Additions = add
		d.Deletions = del
	}

	if includeDiffs {
		applyPatches(lines[i:], ensure, maxDiffBytes)
	}

	for _, p := range order {
		rec.TouchedPath = append(rec.TouchedPath, *deltas[p])
	}
	return nil
}

// applyPatches attributes unified-diff hunks to their path. Each file's patch
// runs from its "diff --git a/<old> b/<new>" header to the next one.
func applyPatches(lines []string, ensure func(string) *evidence.PathDelta, maxDiffBytes int) {
	var curPath string
	var buf strings.Builder
	flush := func() {
		if curPath == "" {
			return
		}
		patch := buf.String()
		d := ensure(curPath)
		if maxDiffBytes > 0 && len(patch) > maxDiffBytes {
			patch = patch[:maxDiffBytes]
			d.PatchTruncated = true
		}
		d.Patch = patch
		buf.Reset()
	}
	for _, line := range lines {
		if strings.HasPrefix(line, "diff --git ") {
			flush()
			curPath = pathFromDiffHeader(line)
		}
		if curPath != "" {
			buf.WriteString(line)
			buf.WriteByte('\n')
		}
	}
	flush()
}

// pathFromDiffHeader extracts the new ("b/") path from a "diff --git" line.
func pathFromDiffHeader(line string) string {
	if idx := strings.Index(line, " b/"); idx != -1 {
		return strings.TrimSpace(line[idx+len(" b/"):])
	}
	return ""
}

func parseRawLine(line string) (string, evidence.ChangeKind, error) {
	// Format: ":<src_mode> <dst_mode> <src_sha> <dst_sha> <status>\t<path>[\t<dst>]"
	tab := strings.IndexByte(line, '\t')
	if tab == -1 {
		return "", "", fmt.Errorf("raw line missing tab: %q", line)
	}
	meta := line[:tab]
	parts := strings.Fields(meta)
	if len(parts) < 5 {
		return "", "", fmt.Errorf("raw line malformed: %q", line)
	}
	status := parts[4]
	rest := line[tab+1:]
	paths := strings.Split(rest, "\t")

	kind, err := statusToKind(status)
	if err != nil {
		return "", "", err
	}
	// For renames/copies, git emits `<src>\t<dst>`; we report the new path.
	path := paths[len(paths)-1]
	return path, kind, nil
}

func statusToKind(status string) (evidence.ChangeKind, error) {
	if status == "" {
		return "", fmt.Errorf("empty status letter")
	}
	switch status[0] {
	case 'A':
		return evidence.ChangeAdd, nil
	case 'M', 'T':
		return evidence.ChangeModify, nil
	case 'D':
		return evidence.ChangeDelete, nil
	case 'R', 'C':
		return evidence.ChangeRename, nil
	default:
		return "", fmt.Errorf("unsupported status letter %q", status)
	}
}

func parseNumstatLine(line string) (string, int, int, error) {
	parts := strings.SplitN(line, "\t", 3)
	if len(parts) != 3 {
		return "", 0, 0, fmt.Errorf("numstat line malformed: %q", line)
	}
	add, err := parseNumstatCount(parts[0])
	if err != nil {
		return "", 0, 0, fmt.Errorf("numstat additions in %q: %w", line, err)
	}
	del, err := parseNumstatCount(parts[1])
	if err != nil {
		return "", 0, 0, fmt.Errorf("numstat deletions in %q: %w", line, err)
	}
	// Rename format is "<old> => <new>"; prefer the new path.
	path := parts[2]
	if idx := strings.LastIndex(path, " => "); idx != -1 {
		path = path[idx+len(" => "):]
	}
	return path, add, del, nil
}

func parseNumstatCount(token string) (int, error) {
	if token == "-" {
		// Binary file; counts unavailable.
		return 0, nil
	}
	return strconv.Atoi(token)
}
