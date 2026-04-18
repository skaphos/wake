// SPDX-License-Identifier: MIT

package commits_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/skaphos/wake-core/evidence"
	"github.com/skaphos/wake-forensics-mcp/internal/commits"
)

func TestExtractLinearHistory(t *testing.T) {
	t.Parallel()

	repo := newTestRepo(t)
	repo.writeFile(t, "a.txt", "one\n")
	repo.commit(t, "init a", "2026-04-02T10:00:00Z")
	repo.writeFile(t, "a.txt", "one\ntwo\n")
	repo.writeFile(t, "b.txt", "b\n")
	repo.commit(t, "add b modify a", "2026-04-02T11:00:00Z")
	repo.run(t, "mv", "a.txt", "a2.txt")
	repo.commit(t, "rename a", "2026-04-02T12:00:00Z")
	repo.run(t, "rm", "b.txt")
	repo.commit(t, "drop b", "2026-04-02T13:00:00Z")

	bundle, err := commits.Extract(context.Background(), commits.Options{RepoPath: repo.dir})
	if err != nil {
		t.Fatalf("extract: %v", err)
	}

	if bundle.SchemaVersion != evidence.SchemaVersion {
		t.Fatalf("schema version: want %q got %q", evidence.SchemaVersion, bundle.SchemaVersion)
	}
	if len(bundle.Commits) != 4 {
		t.Fatalf("want 4 commits, got %d", len(bundle.Commits))
	}

	// git log is reverse-chronological; newest first.
	wantSummaries := []string{"drop b", "rename a", "add b modify a", "init a"}
	for i, want := range wantSummaries {
		if bundle.Commits[i].Summary != want {
			t.Fatalf("commit[%d] summary: want %q got %q", i, want, bundle.Commits[i].Summary)
		}
	}

	drop := bundle.Commits[0]
	if drop.Author.CanonicalName != "Tester" || drop.Author.CanonicalEmail != "tester@example.com" {
		t.Fatalf("author identity wrong: %+v", drop.Author)
	}
	if drop.AuthoredAt.Location() != time.UTC {
		t.Fatalf("authored_at not in UTC: %s", drop.AuthoredAt)
	}
	if len(drop.TouchedPath) != 1 || drop.TouchedPath[0].Path != "b.txt" || drop.TouchedPath[0].Change != evidence.ChangeDelete {
		t.Fatalf("drop commit path deltas wrong: %+v", drop.TouchedPath)
	}

	rename := bundle.Commits[1]
	if len(rename.TouchedPath) != 1 || rename.TouchedPath[0].Path != "a2.txt" || rename.TouchedPath[0].Change != evidence.ChangeRename {
		t.Fatalf("rename commit path deltas wrong: %+v", rename.TouchedPath)
	}

	mixed := bundle.Commits[2]
	if len(mixed.TouchedPath) != 2 {
		t.Fatalf("mixed commit path count: %+v", mixed.TouchedPath)
	}
	seen := map[string]evidence.PathDelta{}
	for _, pd := range mixed.TouchedPath {
		seen[pd.Path] = pd
	}
	if a := seen["a.txt"]; a.Change != evidence.ChangeModify || a.Additions != 1 || a.Deletions != 0 {
		t.Fatalf("a.txt delta wrong: %+v", a)
	}
	if b := seen["b.txt"]; b.Change != evidence.ChangeAdd || b.Additions != 1 || b.Deletions != 0 {
		t.Fatalf("b.txt delta wrong: %+v", b)
	}

	first := bundle.Commits[3]
	if len(first.Parents) != 0 {
		t.Fatalf("first commit should have no parents, got %+v", first.Parents)
	}
	if len(first.TouchedPath) != 1 || first.TouchedPath[0].Change != evidence.ChangeAdd {
		t.Fatalf("first commit path wrong: %+v", first.TouchedPath)
	}
}

func TestExtractRequiresRepoPath(t *testing.T) {
	t.Parallel()
	if _, err := commits.Extract(context.Background(), commits.Options{}); err == nil {
		t.Fatalf("expected error for empty repo path")
	}
}

func TestExtractSubpathFilter(t *testing.T) {
	t.Parallel()

	repo := newTestRepo(t)
	repo.writeFile(t, "keep/x.txt", "x\n")
	repo.writeFile(t, "skip/y.txt", "y\n")
	repo.commit(t, "seed", "2026-04-02T10:00:00Z")
	repo.writeFile(t, "keep/x.txt", "x\nx\n")
	repo.commit(t, "touch keep", "2026-04-02T11:00:00Z")
	repo.writeFile(t, "skip/y.txt", "y\ny\n")
	repo.commit(t, "touch skip", "2026-04-02T12:00:00Z")

	bundle, err := commits.Extract(context.Background(), commits.Options{
		RepoPath: repo.dir,
		Subpaths: []string{"keep"},
	})
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	if len(bundle.Commits) != 2 {
		t.Fatalf("want 2 commits touching keep/, got %d: %+v", len(bundle.Commits), bundle.Commits)
	}
}

type testRepo struct {
	dir string
}

func newTestRepo(t *testing.T) *testRepo {
	t.Helper()
	dir := t.TempDir()
	r := &testRepo{dir: dir}
	r.run(t, "init", "-q", "-b", "main")
	r.run(t, "config", "user.email", "tester@example.com")
	r.run(t, "config", "user.name", "Tester")
	r.run(t, "config", "commit.gpgsign", "false")
	return r
}

func (r *testRepo) run(t *testing.T, args ...string) {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", r.dir}, args...)...)
	cmd.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
}

func (r *testRepo) writeFile(t *testing.T, rel, content string) {
	t.Helper()
	p := filepath.Join(r.dir, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", rel, err)
	}
}

func (r *testRepo) commit(t *testing.T, msg, isoTimestamp string) {
	t.Helper()
	r.run(t, "add", "-A")
	cmd := exec.Command("git", "-C", r.dir, "commit", "-q", "-m", msg)
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
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("commit: %v\n%s", err, out)
	}
}
