// SPDX-License-Identifier: MIT

// Package analyze orchestrates the end-to-end forensics + classify
// pipeline for the wake CLI and renders a human-facing report.
package analyze

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/skaphos/wake-core/evidence"
	"github.com/skaphos/wake-forensics-mcp/source"
	"github.com/skaphos/wake-forensics-mcp/source/local"
	"github.com/skaphos/wake-forensics-mcp/target"
)

// Options configures a single analyze run.
//
// There are two ways to supply evidence:
//   - Sources: an explicit set of evidence sources (remote queries, workspace
//     enumeration, etc.) built by the caller. Used as-is when non-empty.
//   - Repository (+ Subpaths/Revisions): the convenience local single-repo
//     path, used when Sources is empty.
type Options struct {
	// Local single-repository convenience inputs.
	Repository   string
	Subpaths     []string
	RevisionFrom string
	RevisionTo   string
	// IncludeDiffs captures per-path unified-diff text in local mode.
	IncludeDiffs bool

	// Sources, when non-empty, fully determines the evidence to analyze and
	// the Repository fields are ignored. Each source yields one bundle per
	// repository in its scope.
	Sources []source.Source

	// EmitEvidence outputs the raw evidence bundles (with full messages and,
	// when --diffs is set, patch text) as JSON instead of the analysis report.
	EmitEvidence bool

	Format Format
	Writer io.Writer
	Now    func() time.Time
}

// Run extracts evidence from the configured source(s), runs the
// classify pipeline, and writes the aggregated report to opts.Writer in
// the requested format.
func Run(ctx context.Context, opts Options) error {
	if opts.Writer == nil {
		return fmt.Errorf("output writer is required")
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}

	sources := opts.Sources
	if len(sources) == 0 {
		if opts.Repository == "" {
			return fmt.Errorf("a repository path or at least one source is required")
		}
		sources = []source.Source{local.NewWithDiffs(target.Input{
			Repository:   opts.Repository,
			Subpaths:     opts.Subpaths,
			RevisionFrom: opts.RevisionFrom,
			RevisionTo:   opts.RevisionTo,
		}, opts.IncludeDiffs, 0)}
	}

	var bundles []evidence.Bundle
	for _, src := range sources {
		extracted, err := src.Extract(ctx)
		if err != nil {
			return fmt.Errorf("extract evidence (%s): %w", src.Kind(), err)
		}
		bundles = append(bundles, extracted...)
	}

	if opts.EmitEvidence {
		return emitEvidence(opts.Writer, bundles)
	}

	report := BuildReport(bundles, now())
	return Render(opts.Writer, opts.Format, report)
}

// emitEvidence writes the raw evidence bundles as indented JSON. This exposes
// the full commit messages and per-path diff text carried in the bundle, for
// downstream tooling or inspection.
func emitEvidence(w io.Writer, bundles []evidence.Bundle) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(bundles)
}
