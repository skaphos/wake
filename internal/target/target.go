// SPDX-License-Identifier: MIT

package target

import (
	"fmt"
	"path/filepath"
	"strings"
)

type Input struct {
	Repository   string
	Subpaths     []string
	RevisionFrom string
	RevisionTo   string
}

type Resolved struct {
	RepositoryPath string
	Subpaths       []string
	RevisionFrom   string
	RevisionTo     string
}

func Resolve(input Input) (Resolved, error) {
	if strings.TrimSpace(input.Repository) == "" {
		return Resolved{}, fmt.Errorf("repository path must not be empty")
	}

	repoPath, err := filepath.Abs(input.Repository)
	if err != nil {
		return Resolved{}, fmt.Errorf("resolve repository path: %w", err)
	}

	resolved := Resolved{
		RepositoryPath: filepath.Clean(repoPath),
		RevisionFrom:   strings.TrimSpace(input.RevisionFrom),
		RevisionTo:     strings.TrimSpace(input.RevisionTo),
	}

	for _, subpath := range input.Subpaths {
		clean, err := normalizeSubpath(subpath)
		if err != nil {
			return Resolved{}, err
		}
		resolved.Subpaths = append(resolved.Subpaths, clean)
	}

	return resolved, nil
}

func normalizeSubpath(subpath string) (string, error) {
	trimmed := strings.TrimSpace(subpath)
	if trimmed == "" {
		return "", fmt.Errorf("subpath must not be empty")
	}
	if filepath.IsAbs(trimmed) {
		return "", fmt.Errorf("subpath %q must be relative", subpath)
	}

	cleaned := filepath.Clean(trimmed)
	if cleaned == "." {
		return "", fmt.Errorf("subpath %q must not resolve to repository root", subpath)
	}
	if cleaned == ".." || strings.HasPrefix(cleaned, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("subpath %q escapes repository root", subpath)
	}

	return cleaned, nil
}
