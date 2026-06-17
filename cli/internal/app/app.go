// SPDX-License-Identifier: MIT

package app

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/skaphos/wake-cli/internal/analyze"
	"github.com/skaphos/wake-cli/internal/authcmd"
	"github.com/skaphos/wake-cli/internal/workspace"
	"github.com/skaphos/wake-forensics-mcp/source"
)

// Run dispatches the top-level wake-cli command.
func Run(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return printUsage(os.Stderr)
	}
	switch args[0] {
	case "analyze":
		return runAnalyze(ctx, args[1:], os.Stdout)
	case "auth":
		return authcmd.Run(ctx, args[1:], os.Stdin, os.Stdout, os.Stderr)
	case "help", "-h", "--help":
		return printUsage(os.Stdout)
	case "version", "--version":
		fmt.Fprintln(os.Stdout, version())
		return nil
	default:
		return fmt.Errorf("unknown command %q — run 'wake help' for usage", args[0])
	}
}

func runAnalyze(ctx context.Context, args []string, out io.Writer) error {
	fs := flag.NewFlagSet("analyze", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage:")
		fmt.Fprintln(os.Stderr, "  wake analyze [flags] <repository-path>      analyze a local Git checkout")
		fmt.Fprintln(os.Stderr, "  wake analyze --remote github --author <a>    analyze remote GitHub/GitLab evidence")
		fs.PrintDefaults()
	}

	var (
		format    string
		revFrom   string
		revTo     string
		subpaths  stringSliceFlag
		rf        remoteFlags
		repos     stringSliceFlag
		useWS     bool
		wsLabel   string
		wsField   string
		wsName    string
		rkCommand string
	)
	// Local mode.
	fs.StringVar(&format, "format", "markdown", "output format: text | markdown | json")
	fs.StringVar(&revFrom, "from", "", "revision lower bound (e.g. HEAD~100 or @{1.year.ago})")
	fs.StringVar(&revTo, "to", "", "revision upper bound (default HEAD)")
	fs.Var(&subpaths, "path", "restrict analysis to this subpath (repeatable)")

	// Remote mode (adapted from the retired sting tool).
	fs.StringVar(&rf.provider, "remote", "", "remote provider: github | gitlab (enables remote analysis)")
	fs.StringVar(&rf.author, "author", "", "author whose commits to retrieve (required for remote)")
	fs.StringVar(&rf.org, "org", "", "organization (GitHub) or group (GitLab) to scope/enumerate")
	fs.Var(&repos, "repo", "owner/repo (GitHub) or project path (GitLab) target (repeatable)")
	fs.StringVar(&rf.scope, "scope", "", "discovery scope: search | repos | org (default search)")
	fs.StringVar(&rf.window, "window", "", "look-back window when --since is omitted (e.g. 7d, 2w, 48h; default 30d)")
	fs.StringVar(&rf.since, "since", "", "window start (RFC3339 or YYYY-MM-DD)")
	fs.StringVar(&rf.until, "until", "", "window end (RFC3339 or YYYY-MM-DD; default now)")
	fs.BoolVar(&rf.stats, "stats", false, "fetch per-commit additions/deletions (extra API calls)")
	fs.BoolVar(&rf.files, "files", false, "fetch per-file change summaries (extra API calls)")
	fs.BoolVar(&rf.diffs, "diffs", false, "capture per-path unified-diff text in the evidence (local and remote; token-heavy)")
	fs.StringVar(&rf.baseURL, "base-url", "", "API base URL for GitHub Enterprise / self-hosted GitLab")
	fs.IntVar(&rf.perPage, "per-page", 100, "API page size (1-100)")
	fs.IntVar(&rf.maxCommits, "max-commits", 0, "cap on commits returned (0 = no cap)")
	fs.StringVar(&rf.configPath, "config", "", "config file (default: search ~/.config/wake/config.yaml etc.)")

	var emitEvidence bool
	fs.BoolVar(&emitEvidence, "evidence", false, "output raw evidence bundles as JSON (full messages + diffs) instead of the report")

	// Workspace mode (enumerate local checkouts via the RepoKeeper MCP server).
	fs.BoolVar(&useWS, "workspace", false, "analyze every matching repo in the local workspace (via RepoKeeper)")
	fs.StringVar(&wsLabel, "label", "", "workspace label selector (e.g. team=platform,role=service)")
	fs.StringVar(&wsField, "field", "", "workspace field selector (e.g. tracking.status=behind)")
	fs.StringVar(&wsName, "match", "", "workspace repo_id substring match")
	fs.StringVar(&rkCommand, "repokeeper", "", "path to the repokeeper binary (default: found on PATH)")

	if err := fs.Parse(args); err != nil {
		return err
	}
	rf.repos = []string(repos)
	rf.set = map[string]bool{}
	fs.Visit(func(f *flag.Flag) { rf.set[f.Name] = true })

	opts := analyze.Options{
		Format:       analyze.Format(format),
		Writer:       out,
		ErrWriter:    os.Stderr,
		EmitEvidence: emitEvidence,
	}

	if rf.provider != "" && useWS {
		return fmt.Errorf("--remote and --workspace are mutually exclusive")
	}

	if rf.provider != "" {
		if len(fs.Args()) != 0 {
			fs.Usage()
			return fmt.Errorf("remote analysis takes no positional repository path; use --repo/--org")
		}
		src, err := buildRemoteSource(rf, time.Now())
		if err != nil {
			return err
		}
		opts.Sources = []source.Source{src}
		return analyze.Run(ctx, opts)
	}

	if useWS {
		if len(fs.Args()) != 0 {
			fs.Usage()
			return fmt.Errorf("workspace analysis takes no positional repository path; use --label/--field/--match")
		}
		enum := workspace.RepoKeeper{Command: rkCommand}
		query := workspace.Query{LabelSelector: wsLabel, FieldSelector: wsField, NameMatch: wsName}
		sources, err := buildWorkspaceSources(ctx, enum, query, revFrom, revTo)
		if err != nil {
			return err
		}
		opts.Sources = sources
		return analyze.Run(ctx, opts)
	}

	pos := fs.Args()
	if len(pos) != 1 {
		fs.Usage()
		return fmt.Errorf("analyze requires exactly one repository path argument (or use --remote)")
	}
	opts.Repository = pos[0]
	opts.Subpaths = []string(subpaths)
	opts.RevisionFrom = revFrom
	opts.RevisionTo = revTo
	opts.IncludeDiffs = rf.diffs
	return analyze.Run(ctx, opts)
}

func printUsage(w io.Writer) error {
	_, err := io.WriteString(w, `wake — repository forensics and contributor behavior analysis

Usage:
  wake <command> [flags]

Commands:
  analyze <repo>   Run forensics extraction and generic event classification.
                   Modes:
                     wake analyze <path>                  local Git checkout
                     wake analyze --remote github ...      remote GitHub/GitLab
                     wake analyze --workspace [--label …]  every matching local
                                                           repo (via RepoKeeper)
  auth <provider>  Authenticate with GitHub or GitLab (OAuth). Subcommands:
                     wake auth github | gitlab | status | logout
  version          Print the CLI version.
  help             Show this help.

Run 'wake analyze --help' for command flags.
`)
	return err
}

func version() string {
	return "wake-cli v0.1.0-pre"
}

type stringSliceFlag []string

func (s *stringSliceFlag) String() string { return strings.Join(*s, ",") }
func (s *stringSliceFlag) Set(v string) error {
	if v == "" {
		return fmt.Errorf("value must not be empty")
	}
	*s = append(*s, v)
	return nil
}
