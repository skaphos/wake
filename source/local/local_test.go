// SPDX-License-Identifier: MIT

package local

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/skaphos/wake-forensics-mcp/target"
)

// gitInitWithCommit creates a throwaway repository with a single commit and
// returns its path. Identity is supplied via environment so the test does not
// depend on (or mutate) global git config. HOME/USERPROFILE are isolated so a
// developer's config cannot influence the result.
func gitInitWithCommit(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()

	t.Setenv("HOME", dir)
	t.Setenv("USERPROFILE", dir)

	run := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(),
			"GIT_AUTHOR_NAME=Tester",
			"GIT_AUTHOR_EMAIL=tester@example.com",
			"GIT_COMMITTER_NAME=Tester",
			"GIT_COMMITTER_EMAIL=tester@example.com",
		)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}

	run("init", "-b", "main")
	if err := os.WriteFile(filepath.Join(dir, "file.txt"), []byte("hello\n"), 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}
	run("add", ".")
	run("commit", "-m", "initial commit")
	return dir
}

func TestSourceExtractLocalRepo(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}

	dir := gitInitWithCommit(t)
	src := New(target.Input{Repository: dir})

	if src.Kind() != "local" {
		t.Errorf("Kind = %q, want local", src.Kind())
	}

	bundles, err := src.Extract(context.Background())
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	if len(bundles) != 1 {
		t.Fatalf("got %d bundles, want 1", len(bundles))
	}
	if len(bundles[0].Commits) == 0 {
		t.Fatal("expected at least one commit in bundle")
	}
}

func TestSourceExtractEmptyRepositoryErrors(t *testing.T) {
	t.Parallel()
	if _, err := New(target.Input{}).Extract(context.Background()); err == nil {
		t.Fatal("expected error for empty repository path")
	}
}
