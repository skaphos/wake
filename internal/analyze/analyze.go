// SPDX-License-Identifier: MIT

// Package analyze orchestrates the end-to-end forensics + classify
// pipeline for the wake CLI and renders a human-facing report.
package analyze

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/skaphos/wake-events-mcp/classify"
	"github.com/skaphos/wake-forensics-mcp/commits"
	"github.com/skaphos/wake-forensics-mcp/repository"
	"github.com/skaphos/wake-forensics-mcp/target"
)

// Options configures a single analyze run.
type Options struct {
	Repository   string
	Subpaths     []string
	RevisionFrom string
	RevisionTo   string
	Format       Format
	Writer       io.Writer
	Now          func() time.Time
}

// Run executes the forensics → classify pipeline and writes the
// resulting report to opts.Writer in the requested format.
func Run(ctx context.Context, opts Options) error {
	if opts.Repository == "" {
		return fmt.Errorf("repository path is required")
	}
	if opts.Writer == nil {
		return fmt.Errorf("output writer is required")
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}

	resolved, err := target.Resolve(target.Input{
		Repository:   opts.Repository,
		Subpaths:     opts.Subpaths,
		RevisionFrom: opts.RevisionFrom,
		RevisionTo:   opts.RevisionTo,
	})
	if err != nil {
		return fmt.Errorf("resolve target: %w", err)
	}

	opened, err := repository.OpenReadOnly(resolved.RepositoryPath)
	if err != nil {
		return fmt.Errorf("open repository: %w", err)
	}

	bundle, err := commits.Extract(ctx, commits.Options{
		RepoPath:     opened.RootPath,
		Subpaths:     resolved.Subpaths,
		RevisionFrom: resolved.RevisionFrom,
		RevisionTo:   resolved.RevisionTo,
	})
	if err != nil {
		return fmt.Errorf("extract commits: %w", err)
	}

	candidates := classify.Classify(bundle)
	report := BuildReport(bundle, candidates, now())

	return Render(opts.Writer, opts.Format, report)
}
