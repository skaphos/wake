// SPDX-License-Identifier: MIT

package app_test

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"slices"
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
	// Decode rather than substring-match: subpaths use the OS separator, which
	// JSON escapes on Windows (internal\\service), so a raw Contains check
	// against filepath.Join(...) would spuriously fail there.
	var resolved struct {
		Subpaths []string `json:"subpaths"`
	}
	if err := json.Unmarshal(data, &resolved); err != nil {
		t.Fatalf("decode output %q: %v", string(data), err)
	}
	want := filepath.Join("internal", "service")
	if !slices.Contains(resolved.Subpaths, want) {
		t.Fatalf("subpaths %v did not contain %q", resolved.Subpaths, want)
	}
}

func TestRunResolveRequiresRepositoryArgument(t *testing.T) {
	t.Parallel()

	err := app.Run(context.Background(), []string{"resolve"})
	if err == nil {
		t.Fatal("expected missing repository argument to fail")
	}
}
