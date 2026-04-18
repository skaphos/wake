// SPDX-License-Identifier: MIT

package app

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/skaphos/wake-cli/internal/analyze"
)

// Run dispatches the top-level wake-cli command.
func Run(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return printUsage(os.Stderr)
	}
	switch args[0] {
	case "analyze":
		return runAnalyze(ctx, args[1:], os.Stdout)
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
		fmt.Fprintln(os.Stderr, "Usage: wake analyze [flags] <repository-path>")
		fs.PrintDefaults()
	}

	var (
		format   string
		revFrom  string
		revTo    string
		subpaths stringSliceFlag
	)
	fs.StringVar(&format, "format", "markdown", "output format: text | markdown | json")
	fs.StringVar(&revFrom, "from", "", "revision lower bound (e.g. HEAD~100 or @{1.year.ago})")
	fs.StringVar(&revTo, "to", "", "revision upper bound (default HEAD)")
	fs.Var(&subpaths, "path", "restrict analysis to this subpath (repeatable)")

	if err := fs.Parse(args); err != nil {
		return err
	}

	pos := fs.Args()
	if len(pos) != 1 {
		fs.Usage()
		return fmt.Errorf("analyze requires exactly one repository path argument")
	}

	opts := analyze.Options{
		Repository:   pos[0],
		Subpaths:     []string(subpaths),
		RevisionFrom: revFrom,
		RevisionTo:   revTo,
		Format:       analyze.Format(format),
		Writer:       out,
	}
	return analyze.Run(ctx, opts)
}

func printUsage(w io.Writer) error {
	_, err := io.WriteString(w, `wake — repository forensics and contributor behavior analysis

Usage:
  wake <command> [flags]

Commands:
  analyze <repo>   Run forensics extraction and generic event classification.
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
