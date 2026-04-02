// SPDX-License-Identifier: MIT

package target_test

import (
	"path/filepath"
	"testing"

	"github.com/skaphos/wake-forensics-mcp/internal/target"
)

func TestResolve(t *testing.T) {
	t.Parallel()

	repoRoot := t.TempDir()
	resolved, err := target.Resolve(target.Input{
		Repository: repoRoot,
		Subpaths:   []string{"cmd", "internal/service"},
	})
	if err != nil {
		t.Fatalf("resolve target: %v", err)
	}

	if resolved.RepositoryPath != filepath.Clean(repoRoot) {
		t.Fatalf("repository path = %q, want %q", resolved.RepositoryPath, filepath.Clean(repoRoot))
	}
	if len(resolved.Subpaths) != 2 || resolved.Subpaths[0] != "cmd" || resolved.Subpaths[1] != filepath.Join("internal", "service") {
		t.Fatalf("unexpected subpaths: %#v", resolved.Subpaths)
	}
}

func TestResolveRejectsEscapingSubpath(t *testing.T) {
	t.Parallel()

	_, err := target.Resolve(target.Input{Repository: t.TempDir(), Subpaths: []string{"../secrets"}})
	if err == nil {
		t.Fatal("expected escaping subpath to fail")
	}
}

func TestResolveRejectsEmptyRepository(t *testing.T) {
	t.Parallel()

	_, err := target.Resolve(target.Input{})
	if err == nil {
		t.Fatal("expected empty repository to fail")
	}
}
