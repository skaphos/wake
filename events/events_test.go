// SPDX-License-Identifier: MIT

package events_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/skaphos/wake-core/events"
)

func TestEventJSONFixture(t *testing.T) {
	t.Parallel()

	event := events.Event{
		ID:      "evt-001",
		Kind:    events.KindCapabilityIntroduction,
		Summary: "Introduce confidence contract package",
		Sources: []events.SourceRef{{
			CommitSHA: "def456",
			Paths:     []string{"confidence/confidence.go"},
		}},
	}

	assertGoldenJSON(t, filepath.Join("testdata", "event.golden.json"), event)
}

func TestKindsIsStableAndComplete(t *testing.T) {
	t.Parallel()

	want := []events.Kind{
		events.KindCapabilityIntroduction,
		events.KindStructuralRefactor,
		events.KindOperationalMaintenance,
		events.KindDocumentationUpdate,
		events.KindRetirement,
	}

	got := events.Kinds()
	if len(got) != len(want) {
		t.Fatalf("unexpected kind count: want %d, got %d", len(want), len(got))
	}
	for i, kind := range want {
		if got[i] != kind {
			t.Fatalf("kind at index %d: want %q, got %q", i, kind, got[i])
		}
	}
}

func TestRetirementEventFixture(t *testing.T) {
	t.Parallel()

	event := events.Event{
		ID:      "evt-retire-001",
		Kind:    events.KindRetirement,
		Summary: "Drop legacy v0 inference helpers",
		Sources: []events.SourceRef{{
			CommitSHA: "abc123",
			Paths:     []string{"inference/v0/helpers.go"},
		}},
	}

	assertGoldenJSON(t, filepath.Join("testdata", "event_retirement.golden.json"), event)
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
