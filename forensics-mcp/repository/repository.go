// SPDX-License-Identifier: MIT

// Package repository validates and opens a local git repository for
// read-only inspection. It returns the absolute root and the location
// of the repository's `.git` metadata without mutating anything on
// disk. Downstream packages such as commits consume the resulting
// Opened value to extract evidence.
package repository

import (
	"fmt"
	"os"
	"path/filepath"
)

type Opened struct {
	RootPath string
	GitPath  string
}

func OpenReadOnly(root string) (Opened, error) {
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return Opened{}, fmt.Errorf("resolve repository root: %w", err)
	}
	absRoot = filepath.Clean(absRoot)

	info, err := os.Stat(absRoot)
	if err != nil {
		return Opened{}, fmt.Errorf("stat repository root: %w", err)
	}
	if !info.IsDir() {
		return Opened{}, fmt.Errorf("repository root %q is not a directory", absRoot)
	}

	gitPath := filepath.Join(absRoot, ".git")
	gitInfo, err := os.Stat(gitPath)
	if err != nil {
		return Opened{}, fmt.Errorf("repository root %q does not look like a git repository", absRoot)
	}
	if !gitInfo.IsDir() && !gitInfo.Mode().IsRegular() {
		return Opened{}, fmt.Errorf("repository root %q has unsupported .git entry", absRoot)
	}

	return Opened{RootPath: absRoot, GitPath: gitPath}, nil
}
