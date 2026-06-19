// SPDX-License-Identifier: MIT

package audit

import (
	"strings"
	"testing"
)

func TestLoadLayer_RoundTrip(t *testing.T) {
	const y = `
name: team:payments
edits:
  - verb: add
    control:
      id: sbom
      title: SBOM published
      kind: boolean
      severity: hard
      evidence:
        - path_globs: [sbom.json]
  - verb: strengthen
    id: quality-gate
    promote_to_hard: true
  - verb: relax
    id: license-file
    reason: internal-only service
`
	l, err := LoadLayer(strings.NewReader(y))
	if err != nil {
		t.Fatalf("LoadLayer: %v", err)
	}
	if l.Name != "team:payments" {
		t.Errorf("name = %q", l.Name)
	}
	if len(l.Edits) != 3 {
		t.Fatalf("edits = %d, want 3", len(l.Edits))
	}
	if l.Edits[0].Verb != VerbAdd || l.Edits[0].Control == nil || l.Edits[0].Control.ID != "sbom" {
		t.Errorf("add edit decoded wrong: %+v", l.Edits[0])
	}
	if !l.Edits[1].PromoteToHard {
		t.Errorf("promote_to_hard not decoded")
	}
	if l.Edits[2].Verb != VerbRelax || l.Edits[2].Reason == "" {
		t.Errorf("relax edit decoded wrong: %+v", l.Edits[2])
	}

	// The decoded layer composes cleanly over the base.
	if _, err := Resolve(layerBase(), l); err != nil {
		t.Fatalf("Resolve with loaded layer: %v", err)
	}
}

func TestLoadLayer_RejectsUnknownField(t *testing.T) {
	const y = `
name: team
bogus: true
edits: []
`
	if _, err := LoadLayer(strings.NewReader(y)); err == nil {
		t.Fatal("want error on unknown field, got nil")
	}
}

func TestLoadLayer_RejectsInvalid(t *testing.T) {
	const y = `
name: team
edits:
  - verb: relax
    id: license-file
`
	_, err := LoadLayer(strings.NewReader(y))
	if err == nil || !strings.Contains(err.Error(), "requires a reason") {
		t.Fatalf("err = %v, want reason-required", err)
	}
}
