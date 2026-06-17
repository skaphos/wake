// SPDX-License-Identifier: MIT

package report_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/skaphos/wake-core/confidence"
	"github.com/skaphos/wake-core/events"
	"github.com/skaphos/wake-core/evidence"
	"github.com/skaphos/wake-core/report"
)

func TestPayloadJSONFixture(t *testing.T) {
	t.Parallel()

	payload := report.Payload{
		SchemaVersion: report.SchemaVersion,
		GeneratedAt:   time.Date(2026, time.April, 2, 12, 5, 0, 0, time.UTC),
		Target: evidence.RepositoryTarget{
			Repository: "github.com/skaphos/wake-core",
		},
		Sections: []report.Section{{
			Title:   "Evolution Summary",
			Summary: "Wake core now exposes typed contract packages.",
			Items:   []string{"evidence", "events", "confidence", "report"},
		}},
		Events: []events.Event{{
			ID:      "evt-001",
			Kind:    events.KindCapabilityIntroduction,
			Summary: "Introduce confidence contract package",
			Sources: []events.SourceRef{{CommitSHA: "def456", Paths: []string{"confidence/confidence.go"}}},
		}},
		Confidence: confidence.Assessment{
			SchemaVersion: confidence.SchemaVersion,
			Band:          confidence.BandHigh,
			EvidenceCount: 3,
		},
	}

	assertGoldenJSON(t, filepath.Join("testdata", "payload.golden.json"), payload)
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
