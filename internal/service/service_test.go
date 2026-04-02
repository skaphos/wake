// SPDX-License-Identifier: MIT

package service_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/skaphos/wake-forensics-mcp/internal/config"
	"github.com/skaphos/wake-forensics-mcp/internal/service"
	"github.com/skaphos/wake-forensics-mcp/internal/target"
)

func TestResolveTargetAndOpenRepository(t *testing.T) {
	t.Parallel()

	repoRoot := t.TempDir()
	if err := os.Mkdir(filepath.Join(repoRoot, ".git"), 0o755); err != nil {
		t.Fatalf("create .git dir: %v", err)
	}

	svc := service.New(config.Default())
	resolved, err := svc.ResolveTarget(target.Input{Repository: repoRoot, Subpaths: []string{"internal"}})
	if err != nil {
		t.Fatalf("resolve target: %v", err)
	}

	opened, err := svc.OpenRepository(resolved)
	if err != nil {
		t.Fatalf("open repository: %v", err)
	}

	if opened.GitPath != filepath.Join(filepath.Clean(repoRoot), ".git") {
		t.Fatalf("git path = %q, want %q", opened.GitPath, filepath.Join(filepath.Clean(repoRoot), ".git"))
	}
}
