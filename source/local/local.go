// SPDX-License-Identifier: MIT

// Package local implements [source.Source] over a single local Git checkout.
// It is a thin wrapper around the existing target -> repository -> commits
// extraction path, presenting it through the unified source abstraction so
// the CLI can treat local and remote evidence uniformly.
package local

import (
	"context"

	"github.com/skaphos/wake-core/evidence"
	"github.com/skaphos/wake-forensics-mcp/commits"
	"github.com/skaphos/wake-forensics-mcp/repository"
	"github.com/skaphos/wake-forensics-mcp/target"
)

// Source extracts evidence from one local Git repository.
type Source struct {
	input        target.Input
	includeDiffs bool
	maxDiffBytes int
}

// New builds a local Source for the given target input.
func New(input target.Input) Source {
	return Source{input: input}
}

// NewWithDiffs builds a local Source that also captures per-path unified-diff
// text (bounded by maxDiffBytes; 0 uses the extractor default).
func NewWithDiffs(input target.Input, includeDiffs bool, maxDiffBytes int) Source {
	return Source{input: input, includeDiffs: includeDiffs, maxDiffBytes: maxDiffBytes}
}

// Kind identifies this source.
func (s Source) Kind() string { return "local" }

// Extract resolves the target, opens the repository read-only, and extracts a
// deterministic commit bundle. It returns a single-element slice to satisfy
// the one-bundle-per-repository contract of [source.Source].
func (s Source) Extract(ctx context.Context) ([]evidence.Bundle, error) {
	resolved, err := target.Resolve(s.input)
	if err != nil {
		return nil, err
	}
	opened, err := repository.OpenReadOnly(resolved.RepositoryPath)
	if err != nil {
		return nil, err
	}
	bundle, err := commits.Extract(ctx, commits.Options{
		RepoPath:     opened.RootPath,
		Subpaths:     resolved.Subpaths,
		RevisionFrom: resolved.RevisionFrom,
		RevisionTo:   resolved.RevisionTo,
		IncludeDiffs: s.includeDiffs,
		MaxDiffBytes: s.maxDiffBytes,
	})
	if err != nil {
		return nil, err
	}
	return []evidence.Bundle{bundle}, nil
}
