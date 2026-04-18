// SPDX-License-Identifier: MIT

package repository_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/skaphos/wake-forensics-mcp/repository"
)

func TestOpenReadOnly(t *testing.T) {
	t.Parallel()

	repoRoot := t.TempDir()
	if err := os.Mkdir(filepath.Join(repoRoot, ".git"), 0o755); err != nil {
		t.Fatalf("create .git dir: %v", err)
	}

	opened, err := repository.OpenReadOnly(repoRoot)
	if err != nil {
		t.Fatalf("open repository: %v", err)
	}

	if opened.RootPath != filepath.Clean(repoRoot) {
		t.Fatalf("root path = %q, want %q", opened.RootPath, filepath.Clean(repoRoot))
	}
}

func TestOpenReadOnlyRejectsNonRepository(t *testing.T) {
	t.Parallel()

	_, err := repository.OpenReadOnly(t.TempDir())
	if err == nil {
		t.Fatal("expected missing .git to fail")
	}
}
