// SPDX-License-Identifier: MIT

package app_test

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/skaphos/wake-forensics-mcp/internal/app"
)

func TestRunResolve(t *testing.T) {
	t.Parallel()

	repoRoot := t.TempDir()
	if err := os.Mkdir(filepath.Join(repoRoot, ".git"), 0o755); err != nil {
		t.Fatalf("create .git dir: %v", err)
	}

	stdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe stdout: %v", err)
	}
	os.Stdout = w
	defer func() { os.Stdout = stdout }()

	err = app.Run(context.Background(), []string{"resolve", repoRoot, "internal/service"})
	_ = w.Close()
	if err != nil {
		t.Fatalf("run resolve: %v", err)
	}

	data, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	if !strings.Contains(string(data), filepath.Join("internal", "service")) {
		t.Fatalf("output %q did not contain resolved subpath", string(data))
	}
}

func TestRunResolveRequiresRepositoryArgument(t *testing.T) {
	t.Parallel()

	err := app.Run(context.Background(), []string{"resolve"})
	if err == nil {
		t.Fatal("expected missing repository argument to fail")
	}
}
