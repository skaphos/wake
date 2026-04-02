// SPDX-License-Identifier: MIT

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
	if !(gitInfo.IsDir() || gitInfo.Mode().IsRegular()) {
		return Opened{}, fmt.Errorf("repository root %q has unsupported .git entry", absRoot)
	}

	return Opened{RootPath: absRoot, GitPath: gitPath}, nil
}
