// SPDX-License-Identifier: MIT

// Package commits extracts deterministic commit-level evidence from a
// local git repository. Output conforms to wake-core's evidence schema
// and is suitable as input to downstream event classification.
package commits

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/skaphos/wake-core/evidence"
)

const commitSentinel = "\x1ewake-commit\x1e"

// Options describes an extraction request. RevRange is passed through to
// `git log` (empty means all reachable commits); Subpaths narrow the
// history to the given paths (empty means the whole tree).
type Options struct {
	RepoPath     string
	Subpaths     []string
	RevisionFrom string
	RevisionTo   string
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

	args := []string{
		"-C", opts.RepoPath,
		"log",
		"--no-color",
		"--date=iso-strict",
		"--format=" + commitSentinel + "%n%H%n%P%n%aI%n%aN%n%aE%n%s",
		"--raw",
		"--numstat",
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

	commits, err := parseLog(out)
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

func parseLog(raw []byte) ([]evidence.CommitRecord, error) {
	var records []evidence.CommitRecord
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)

	// State: we look for the sentinel, then consume the header (6 lines),
	// a single blank line, then a mixed block of raw and numstat lines
	// until the next sentinel or EOF.
	var (
		inCommit bool
		header   []string
		rec      evidence.CommitRecord
		deltas   map[string]*evidence.PathDelta
		order    []string
	)

	finish := func() {
		if !inCommit {
			return
		}
		for _, p := range order {
			rec.TouchedPath = append(rec.TouchedPath, *deltas[p])
		}
		records = append(records, rec)
	}

	for scanner.Scan() {
		line := scanner.Text()
		if line == commitSentinel {
			finish()
			inCommit = true
			header = header[:0]
			rec = evidence.CommitRecord{}
			deltas = map[string]*evidence.PathDelta{}
			order = order[:0]
			continue
		}
		if !inCommit {
			continue
		}
		if len(header) < 6 {
			header = append(header, line)
			if len(header) == 6 {
				parsed, err := parseHeader(header)
				if err != nil {
					return nil, err
				}
				rec = parsed
			}
			continue
		}
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, ":") {
			path, kind, err := parseRawLine(line)
			if err != nil {
				return nil, err
			}
			d, ok := deltas[path]
			if !ok {
				d = &evidence.PathDelta{Path: path}
				deltas[path] = d
				order = append(order, path)
			}
			d.Change = kind
			continue
		}
		// numstat line
		path, add, del, err := parseNumstatLine(line)
		if err != nil {
			return nil, err
		}
		d, ok := deltas[path]
		if !ok {
			d = &evidence.PathDelta{Path: path}
			deltas[path] = d
			order = append(order, path)
		}
		d.Additions = add
		d.Deletions = del
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan git output: %w", err)
	}
	finish()

	return records, nil
}

func parseHeader(lines []string) (evidence.CommitRecord, error) {
	sha := strings.TrimSpace(lines[0])
	if sha == "" {
		return evidence.CommitRecord{}, fmt.Errorf("missing commit sha in header")
	}

	var parents []string
	if p := strings.TrimSpace(lines[1]); p != "" {
		parents = strings.Fields(p)
	}

	authoredAt, err := time.Parse(time.RFC3339, strings.TrimSpace(lines[2]))
	if err != nil {
		return evidence.CommitRecord{}, fmt.Errorf("parse authored_at for %s: %w", sha, err)
	}

	return evidence.CommitRecord{
		SHA:     sha,
		Parents: parents,
		Author: evidence.ContributorIdentity{
			CanonicalName:  strings.TrimSpace(lines[3]),
			CanonicalEmail: strings.TrimSpace(lines[4]),
		},
		AuthoredAt: authoredAt.UTC(),
		Summary:    lines[5],
	}, nil
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
