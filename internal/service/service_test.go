// SPDX-License-Identifier: MIT

package service_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/skaphos/wake-core/evidence"
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

func TestExtractCommits(t *testing.T) {
	t.Parallel()

	repoRoot := t.TempDir()
	runGit(t, repoRoot, "init", "-q", "-b", "main")
	runGit(t, repoRoot, "config", "user.email", "tester@example.com")
	runGit(t, repoRoot, "config", "user.name", "Tester")
	runGit(t, repoRoot, "config", "commit.gpgsign", "false")

	if err := os.WriteFile(filepath.Join(repoRoot, "hello.txt"), []byte("hi\n"), 0o644); err != nil {
		t.Fatalf("write seed file: %v", err)
	}
	runGit(t, repoRoot, "add", "hello.txt")
	commitWithDate(t, repoRoot, "seed", "2026-04-02T10:00:00Z")

	svc := service.New(config.Default())
	bundle, err := svc.ExtractCommits(context.Background(), target.Input{Repository: repoRoot})
	if err != nil {
		t.Fatalf("extract commits: %v", err)
	}
	if bundle.SchemaVersion != evidence.SchemaVersion {
		t.Fatalf("schema version: want %q got %q", evidence.SchemaVersion, bundle.SchemaVersion)
	}
	if len(bundle.Commits) != 1 {
		t.Fatalf("want 1 commit, got %d", len(bundle.Commits))
	}
	if bundle.Commits[0].Summary != "seed" {
		t.Fatalf("summary: want %q got %q", "seed", bundle.Commits[0].Summary)
	}
	if bundle.Target.Repository == "" {
		t.Fatalf("target repository not set")
	}
}

func runGit(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	cmd.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
}

func commitWithDate(t *testing.T, dir, msg, isoTimestamp string) {
	t.Helper()
	cmd := exec.Command("git", "-C", dir, "commit", "-q", "-m", msg)
	cmd.Env = append(os.Environ(),
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_AUTHOR_NAME=Tester",
		"GIT_AUTHOR_EMAIL=tester@example.com",
		"GIT_COMMITTER_NAME=Tester",
		"GIT_COMMITTER_EMAIL=tester@example.com",
		"GIT_AUTHOR_DATE="+isoTimestamp,
		"GIT_COMMITTER_DATE="+isoTimestamp,
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("commit: %v\n%s", err, out)
	}
}
