// SPDX-License-Identifier: MIT

package commits_test

import (
	"context"
	"strings"
	"testing"

	"github.com/skaphos/wake-forensics-mcp/commits"
)

func TestExtractCarriesMessageAndDiffs(t *testing.T) {
	t.Parallel()

	repo := newTestRepo(t)
	repo.writeFile(t, "f.txt", "alpha\n")
	repo.run(t, "add", "-A")
	// Two -m flags produce "subject\n\nbody".
	repo.run(t, "commit", "-q", "-m", "add f", "-m", "detailed body explaining why")

	// Without diffs: full message is carried, but no patch text.
	bundle, err := commits.Extract(context.Background(), commits.Options{RepoPath: repo.dir})
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	if len(bundle.Commits) != 1 {
		t.Fatalf("want 1 commit, got %d", len(bundle.Commits))
	}
	c := bundle.Commits[0]
	if c.Summary != "add f" {
		t.Errorf("Summary = %q, want first line only", c.Summary)
	}
	if !strings.Contains(c.Message, "add f") || !strings.Contains(c.Message, "detailed body explaining why") {
		t.Errorf("Message missing subject or body: %q", c.Message)
	}
	if len(c.TouchedPath) != 1 || c.TouchedPath[0].Patch != "" {
		t.Errorf("patch should be empty without IncludeDiffs: %+v", c.TouchedPath)
	}

	// With diffs: the touched path carries unified-diff text.
	withDiffs, err := commits.Extract(context.Background(), commits.Options{RepoPath: repo.dir, IncludeDiffs: true})
	if err != nil {
		t.Fatalf("extract with diffs: %v", err)
	}
	pd := withDiffs.Commits[0].TouchedPath[0]
	if pd.Path != "f.txt" {
		t.Fatalf("path = %q, want f.txt", pd.Path)
	}
	if !strings.Contains(pd.Patch, "+alpha") {
		t.Errorf("patch should contain the added line, got:\n%s", pd.Patch)
	}
	if pd.PatchTruncated {
		t.Error("patch should not be truncated with the default budget")
	}

	// Truncation honors MaxDiffBytes.
	truncated, err := commits.Extract(context.Background(), commits.Options{RepoPath: repo.dir, IncludeDiffs: true, MaxDiffBytes: 8})
	if err != nil {
		t.Fatalf("extract truncated: %v", err)
	}
	tpd := truncated.Commits[0].TouchedPath[0]
	if !tpd.PatchTruncated || len(tpd.Patch) != 8 {
		t.Errorf("expected patch truncated to 8 bytes, got len=%d truncated=%v", len(tpd.Patch), tpd.PatchTruncated)
	}
}
