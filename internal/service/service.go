// SPDX-License-Identifier: MIT

package service

import (
	"context"
	"fmt"

	"github.com/skaphos/wake-core/evidence"
	"github.com/skaphos/wake-forensics-mcp/internal/commits"
	"github.com/skaphos/wake-forensics-mcp/internal/config"
	"github.com/skaphos/wake-forensics-mcp/internal/repository"
	"github.com/skaphos/wake-forensics-mcp/internal/target"
)

type Service struct {
	config config.Config
}

func New(cfg config.Config) Service {
	return Service{config: cfg}
}

func (s Service) Validate() error {
	if s.config.ListenNetwork == "" {
		return fmt.Errorf("listen network must not be empty")
	}
	return nil
}

func (s Service) ResolveTarget(input target.Input) (target.Resolved, error) {
	return target.Resolve(input)
}

func (s Service) OpenRepository(resolved target.Resolved) (repository.Opened, error) {
	return repository.OpenReadOnly(resolved.RepositoryPath)
}

// ExtractCommits runs the full forensics path: resolve target, open the
// repository read-only, and extract a deterministic bundle of commit
// records. It is the primary entry point for downstream event MCPs.
func (s Service) ExtractCommits(ctx context.Context, input target.Input) (evidence.Bundle, error) {
	resolved, err := s.ResolveTarget(input)
	if err != nil {
		return evidence.Bundle{}, err
	}
	opened, err := s.OpenRepository(resolved)
	if err != nil {
		return evidence.Bundle{}, err
	}
	return commits.Extract(ctx, commits.Options{
		RepoPath:     opened.RootPath,
		Subpaths:     resolved.Subpaths,
		RevisionFrom: resolved.RevisionFrom,
		RevisionTo:   resolved.RevisionTo,
	})
}
