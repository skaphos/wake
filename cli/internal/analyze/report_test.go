// SPDX-License-Identifier: MIT

package analyze

import (
	"testing"
	"time"

	"github.com/skaphos/wake-core/evidence"
)

func bundle(repo string, commits ...evidence.CommitRecord) evidence.Bundle {
	return evidence.Bundle{
		SchemaVersion: evidence.SchemaVersion,
		Target:        evidence.RepositoryTarget{Repository: repo},
		Commits:       commits,
	}
}

func commit(sha, name, email string, paths ...evidence.PathDelta) evidence.CommitRecord {
	return evidence.CommitRecord{
		SHA:         sha,
		Author:      evidence.ContributorIdentity{CanonicalName: name, CanonicalEmail: email},
		AuthoredAt:  time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC),
		Summary:     "summary " + sha,
		TouchedPath: paths,
	}
}

func TestBuildReportSingleBundleSetsTarget(t *testing.T) {
	t.Parallel()
	b := bundle("github:o/r", commit("a", "Ann", "ann@x.io", evidence.PathDelta{Path: "main.go", Change: evidence.ChangeAdd}))
	rep := BuildReport([]evidence.Bundle{b}, time.Now())

	if rep.Target.Repository != "github:o/r" {
		t.Errorf("Target = %q, want github:o/r", rep.Target.Repository)
	}
	if rep.TotalCommits != 1 {
		t.Errorf("TotalCommits = %d, want 1", rep.TotalCommits)
	}
	if len(rep.Repositories) != 1 {
		t.Errorf("Repositories = %d, want 1", len(rep.Repositories))
	}
}

func TestBuildReportMultiBundleAggregates(t *testing.T) {
	t.Parallel()
	bundles := []evidence.Bundle{
		bundle("github:o/alpha",
			commit("a1", "Ann", "ann@x.io", evidence.PathDelta{Path: "new.go", Change: evidence.ChangeAdd}),
			commit("a2", "Bob", "bob@x.io"),
		),
		bundle("github:o/beta",
			commit("b1", "Ann", "ann@x.io"),
		),
	}
	rep := BuildReport(bundles, time.Now())

	if rep.Target.Repository != "" {
		t.Errorf("multi-bundle Target should be empty, got %q", rep.Target.Repository)
	}
	if rep.TotalCommits != 3 {
		t.Errorf("TotalCommits = %d, want 3", rep.TotalCommits)
	}
	if len(rep.Repositories) != 2 {
		t.Fatalf("Repositories = %d, want 2", len(rep.Repositories))
	}
	// Ann appears in both repos and must aggregate to a single contributor row
	// with 2 commits.
	var ann *ContributorStats
	for i := range rep.Contributors {
		if rep.Contributors[i].Email == "ann@x.io" {
			ann = &rep.Contributors[i]
		}
	}
	if ann == nil {
		t.Fatal("Ann not found in contributors")
	}
	if ann.TotalCommits != 2 {
		t.Errorf("Ann commits = %d, want 2 (aggregated across repos)", ann.TotalCommits)
	}
}
