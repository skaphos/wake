// SPDX-License-Identifier: MIT

package evidencemap

import (
	"testing"
	"time"

	"github.com/skaphos/wake-core/evidence"
	"github.com/skaphos/wake-forensics-mcp/source/remote/model"
)

func TestBundlesGroupsByRepoSorted(t *testing.T) {
	t.Parallel()

	generated := time.Date(2026, 5, 31, 12, 0, 0, 0, time.UTC)
	result := model.Result{
		Provider:    model.ProviderGitHub,
		GeneratedAt: generated,
		Commits: []model.Commit{
			{SHA: "z1", Repo: "skaphos/zeta", AuthorName: "Ann", Date: generated},
			{SHA: "a1", Repo: "skaphos/alpha", AuthorName: "Bob", Date: generated},
			{SHA: "a2", Repo: "skaphos/alpha", AuthorName: "Bob", Date: generated},
		},
	}

	bundles := Bundles(result)

	if len(bundles) != 2 {
		t.Fatalf("got %d bundles, want 2", len(bundles))
	}
	// Sorted by repository name: alpha before zeta.
	if got, want := bundles[0].Target.Repository, "github:skaphos/alpha"; got != want {
		t.Errorf("bundle[0] target = %q, want %q", got, want)
	}
	if got, want := bundles[1].Target.Repository, "github:skaphos/zeta"; got != want {
		t.Errorf("bundle[1] target = %q, want %q", got, want)
	}
	if got := len(bundles[0].Commits); got != 2 {
		t.Errorf("alpha bundle commits = %d, want 2", got)
	}
	if bundles[0].SchemaVersion != evidence.SchemaVersion {
		t.Errorf("schema version = %q, want %q", bundles[0].SchemaVersion, evidence.SchemaVersion)
	}
	if !bundles[0].GeneratedAt.Equal(generated) {
		t.Errorf("generated at = %v, want %v", bundles[0].GeneratedAt, generated)
	}
}

func TestBundlesMapsCommitFields(t *testing.T) {
	t.Parallel()

	result := model.Result{
		Provider: model.ProviderGitLab,
		Commits: []model.Commit{{
			SHA:        "deadbeef",
			Repo:       "group/proj",
			Author:     "octocat",
			AuthorName: "Octo Cat",
			Email:      "octo@example.com",
			Message:    "fix: thing\n\nbody",
			Files: []model.File{
				{Path: "a.go", Status: "added", Additions: 3, Patch: "@@ +alpha", PatchTruncated: true},
				{Path: "b.go", Status: "removed", Deletions: 5},
				{Path: "c.go", Status: "renamed", PreviousPath: "old.go"},
				{Path: "d.go", Status: "modified", Additions: 1, Deletions: 1},
			},
		}},
	}

	bundles := Bundles(result)
	if len(bundles) != 1 || len(bundles[0].Commits) != 1 {
		t.Fatalf("unexpected bundle shape: %#v", bundles)
	}
	c := bundles[0].Commits[0]

	if c.Summary != "fix: thing" {
		t.Errorf("summary = %q, want first line only", c.Summary)
	}
	if c.Message != "fix: thing\n\nbody" {
		t.Errorf("message = %q, want full body carried through", c.Message)
	}
	if c.TouchedPath[0].Patch != "@@ +alpha" || !c.TouchedPath[0].PatchTruncated {
		t.Errorf("patch not carried: %+v", c.TouchedPath[0])
	}
	if c.Author.CanonicalName != "Octo Cat" || c.Author.CanonicalEmail != "octo@example.com" {
		t.Errorf("contributor identity = %+v", c.Author)
	}
	if len(c.Author.Aliases) != 1 || c.Author.Aliases[0] != "octocat" {
		t.Errorf("aliases = %v, want [octocat]", c.Author.Aliases)
	}
	wantKinds := []evidence.ChangeKind{evidence.ChangeAdd, evidence.ChangeDelete, evidence.ChangeRename, evidence.ChangeModify}
	if len(c.TouchedPath) != len(wantKinds) {
		t.Fatalf("touched paths = %d, want %d", len(c.TouchedPath), len(wantKinds))
	}
	for i, want := range wantKinds {
		if c.TouchedPath[i].Change != want {
			t.Errorf("path[%d] change = %q, want %q", i, c.TouchedPath[i].Change, want)
		}
	}
}

func TestBundlesEmptyResult(t *testing.T) {
	t.Parallel()
	if got := Bundles(model.Result{}); len(got) != 0 {
		t.Errorf("empty result -> %d bundles, want 0", len(got))
	}
}

func TestTargetRepositoryWithoutProvider(t *testing.T) {
	t.Parallel()
	if got := targetRepository("", "owner/repo"); got != "owner/repo" {
		t.Errorf("unqualified target = %q, want owner/repo", got)
	}
}
