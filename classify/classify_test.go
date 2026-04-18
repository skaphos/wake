// SPDX-License-Identifier: MIT

package classify_test

import (
	"testing"
	"time"

	"github.com/skaphos/wake-core/events"
	"github.com/skaphos/wake-core/evidence"
	"github.com/skaphos/wake-events-mcp/classify"
)

func TestClassifyDocumentationUpdate(t *testing.T) {
	t.Parallel()

	bundle := bundleOf(
		commit("abc1234def", "docs: clarify install flow",
			delta("README.md", evidence.ChangeModify),
			delta("docs/install.md", evidence.ChangeAdd),
		),
	)
	got := classify.Classify(bundle)
	mustOneCandidate(t, got, events.KindDocumentationUpdate, "doc-abc1234")
}

func TestClassifyRetirement(t *testing.T) {
	t.Parallel()

	bundle := bundleOf(
		commit("ret0000000", "drop legacy helpers",
			delta("legacy/helpers.go", evidence.ChangeDelete),
			delta("legacy/helpers_test.go", evidence.ChangeDelete),
		),
	)
	got := classify.Classify(bundle)
	mustOneCandidate(t, got, events.KindRetirement, "ret-ret0000")
}

func TestClassifyStructuralRefactor(t *testing.T) {
	t.Parallel()

	bundle := bundleOf(
		commit("ref1111111", "move forensics internals to public",
			delta("commits/commits.go", evidence.ChangeRename),
			delta("target/target.go", evidence.ChangeRename),
		),
	)
	got := classify.Classify(bundle)
	mustOneCandidate(t, got, events.KindStructuralRefactor, "ref-ref1111")
}

func TestClassifyOperationalMaintenance(t *testing.T) {
	t.Parallel()

	bundle := bundleOf(
		commit("ops2222222", "bump deps",
			delta("go.mod", evidence.ChangeModify),
			delta("go.sum", evidence.ChangeModify),
			delta(".github/workflows/ci.yml", evidence.ChangeModify),
		),
	)
	got := classify.Classify(bundle)
	mustOneCandidate(t, got, events.KindOperationalMaintenance, "ops-ops2222")
}

func TestClassifyCapabilityIntroduction(t *testing.T) {
	t.Parallel()

	bundle := bundleOf(
		commit("cap3333333", "add classify package",
			delta("classify/classify.go", evidence.ChangeAdd),
			delta("classify/classify_test.go", evidence.ChangeAdd),
		),
	)
	got := classify.Classify(bundle)
	mustOneCandidate(t, got, events.KindCapabilityIntroduction, "cap-cap3333")
}

func TestClassifySkipsMergeCommits(t *testing.T) {
	t.Parallel()

	bundle := bundleOf(
		commit("merge0000", "Merge branch 'topic' into main"),
	)
	if got := classify.Classify(bundle); len(got) != 0 {
		t.Fatalf("merge commit should not be classified, got %d candidates", len(got))
	}
}

func TestClassifyMixedCodeAndDocsFallsThroughToCapability(t *testing.T) {
	t.Parallel()

	// Adds a source file and touches docs: not pure docs, so it should
	// match the capability rule (new source file present).
	bundle := bundleOf(
		commit("mix4444444", "introduce classifier with docs",
			delta("classify/classify.go", evidence.ChangeAdd),
			delta("README.md", evidence.ChangeModify),
		),
	)
	got := classify.Classify(bundle)
	mustOneCandidate(t, got, events.KindCapabilityIntroduction, "cap-mix4444")
}

func TestClassifyUnmatchedCommitYieldsNoCandidate(t *testing.T) {
	t.Parallel()

	// Only modifications to non-maintenance, non-doc, non-rename paths,
	// with no additions: no generic rule fires. Adapters should refine.
	bundle := bundleOf(
		commit("amb5555555", "tweak internal helper",
			delta("internal/helper.go", evidence.ChangeModify),
		),
	)
	if got := classify.Classify(bundle); len(got) != 0 {
		t.Fatalf("ambiguous commit should not be classified, got %d candidates", len(got))
	}
}

func TestClassifyPreservesSourcesAndSummary(t *testing.T) {
	t.Parallel()

	bundle := bundleOf(
		commit("src6666666", "extend taxonomy",
			delta("events/events.go", evidence.ChangeAdd),
		),
	)
	got := classify.Classify(bundle)
	if len(got) != 1 {
		t.Fatalf("want 1 candidate, got %d", len(got))
	}
	ev := got[0].Event
	if ev.Summary != "extend taxonomy" {
		t.Fatalf("summary: want %q got %q", "extend taxonomy", ev.Summary)
	}
	if len(ev.Sources) != 1 {
		t.Fatalf("want 1 source ref, got %d", len(ev.Sources))
	}
	src := ev.Sources[0]
	if src.CommitSHA != "src6666666" {
		t.Fatalf("source commit_sha: want %q got %q", "src6666666", src.CommitSHA)
	}
	if len(src.Paths) != 1 || src.Paths[0] != "events/events.go" {
		t.Fatalf("source paths wrong: %+v", src.Paths)
	}
	if got[0].Evidence.SHA != "src6666666" {
		t.Fatalf("candidate evidence SHA mismatch: %q", got[0].Evidence.SHA)
	}
}

// --- helpers ---

func bundleOf(records ...evidence.CommitRecord) evidence.Bundle {
	return evidence.Bundle{
		SchemaVersion: evidence.SchemaVersion,
		GeneratedAt:   time.Date(2026, 4, 18, 12, 0, 0, 0, time.UTC),
		Target:        evidence.RepositoryTarget{Repository: "/tmp/test-repo"},
		Commits:       records,
	}
}

func commit(sha, summary string, deltas ...evidence.PathDelta) evidence.CommitRecord {
	return evidence.CommitRecord{
		SHA:         sha,
		Author:      evidence.ContributorIdentity{CanonicalName: "Tester", CanonicalEmail: "tester@example.com"},
		AuthoredAt:  time.Date(2026, 4, 18, 12, 0, 0, 0, time.UTC),
		Summary:     summary,
		TouchedPath: deltas,
	}
}

func delta(path string, kind evidence.ChangeKind) evidence.PathDelta {
	return evidence.PathDelta{Path: path, Change: kind}
}

func mustOneCandidate(t *testing.T, got []events.Candidate, wantKind events.Kind, wantID string) {
	t.Helper()
	if len(got) != 1 {
		t.Fatalf("want 1 candidate, got %d: %+v", len(got), got)
	}
	if got[0].Event.Kind != wantKind {
		t.Fatalf("kind: want %q got %q", wantKind, got[0].Event.Kind)
	}
	if got[0].Event.ID != wantID {
		t.Fatalf("event id: want %q got %q", wantID, got[0].Event.ID)
	}
}
