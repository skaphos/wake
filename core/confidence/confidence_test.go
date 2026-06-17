// SPDX-License-Identifier: MIT

package confidence_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/skaphos/wake-core/confidence"
)

func TestAssessmentJSONFixture(t *testing.T) {
	t.Parallel()

	assessment := confidence.Assessment{
		SchemaVersion: confidence.SchemaVersion,
		Band:          confidence.BandHigh,
		EvidenceCount: 3,
		EvidenceTypes: []string{"commit", "path_delta", "artifact"},
		Caveats: []confidence.Caveat{{
			Code:    "incomplete_history_window",
			Message: "analysis window excludes older commits",
		}},
		Constraints: []string{"git history is evidence, not final truth"},
	}

	assertGoldenJSON(t, filepath.Join("testdata", "assessment.golden.json"), assessment)
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
