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
