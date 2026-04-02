// SPDX-License-Identifier: MIT

package evidence_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/skaphos/wake-core/evidence"
)

func TestBundleJSONFixture(t *testing.T) {
	t.Parallel()

	bundle := evidence.Bundle{
		SchemaVersion: evidence.SchemaVersion,
		GeneratedAt:   time.Date(2026, time.April, 2, 12, 0, 0, 0, time.UTC),
		Target: evidence.RepositoryTarget{
			Repository:   "github.com/skaphos/wake-core",
			Subpaths:     []string{"evidence", "events"},
			RevisionFrom: "abc123",
			RevisionTo:   "def456",
		},
		Commits: []evidence.CommitRecord{{
			SHA:        "def456",
			AuthoredAt: time.Date(2026, time.April, 1, 8, 30, 0, 0, time.UTC),
			Parents:    []string{"abc123"},
			Summary:    "Add initial contract packages",
			Author: evidence.ContributorIdentity{
				CanonicalName:  "Shawn Stratton",
				CanonicalEmail: "shawn@example.com",
				Aliases:        []string{"sstratton"},
			},
			TouchedPath: []evidence.PathDelta{{
				Path:      "evidence/evidence.go",
				Change:    evidence.ChangeAdd,
				Additions: 45,
			}},
			Artifacts: map[string]evidence.Artifact{
				"proposal": {Kind: evidence.ArtifactDocumentation, Path: "README.md"},
			},
		}},
	}

	assertGoldenJSON(t, filepath.Join("testdata", "bundle.golden.json"), bundle)
}

func assertGoldenJSON(t *testing.T, fixturePath string, value any) {
	t.Helper()

	got, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Fatalf("marshal fixture: %v", err)
	}
	got = append(got, '\n')

	want, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatalf("read golden fixture: %v", err)
	}

	if string(got) != string(want) {
		t.Fatalf("golden fixture mismatch\nwant:\n%s\n got:\n%s", want, got)
	}
}
