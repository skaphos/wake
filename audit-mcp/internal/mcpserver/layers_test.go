// SPDX-License-Identifier: MIT

package mcpserver

import (
	"strings"
	"testing"

	"github.com/skaphos/wake-core/audit"
)

func TestResolveEffectivePolicy_ComposesLayers(t *testing.T) {
	org := `
name: org:acme
edits:
  - verb: strengthen
    id: quality-gate
    promote_to_hard: true
`
	team := `
name: team:web
edits:
  - verb: relax
    id: deployment-intent
    reason: internal batch job
`
	ep, err := resolveEffectivePolicy("", org, team)
	if err != nil {
		t.Fatalf("resolveEffectivePolicy: %v", err)
	}
	if want := []string{"wake-default", "org:acme", "team:web"}; strings.Join(ep.Layers, ",") != strings.Join(want, ",") {
		t.Errorf("layers = %v, want %v", ep.Layers, want)
	}
	if len(ep.Waivers) != 1 || ep.Waivers[0].ControlID != "deployment-intent" {
		t.Errorf("waivers = %+v, want one for deployment-intent", ep.Waivers)
	}
	// quality-gate is promoted to hard in the effective set.
	var found bool
	for _, c := range ep.RuleSet.Controls {
		if c.ID == "quality-gate" {
			found = true
			if c.Severity != audit.Hard {
				t.Errorf("quality-gate severity = %q, want hard", c.Severity)
			}
		}
	}
	if !found {
		t.Error("quality-gate missing from effective rule set")
	}
}

func TestResolveEffectivePolicy_BadLayerErrors(t *testing.T) {
	_, err := resolveEffectivePolicy("", "name: org\nedits:\n  - verb: relax\n    id: x\n", "")
	if err == nil || !strings.Contains(err.Error(), "org layer") {
		t.Fatalf("err = %v, want org-layer error", err)
	}
}

func TestRenderRepo_ShowsWaiversAndLayers(t *testing.T) {
	r := audit.RepoReport{
		Repository:     "acme/web",
		Classification: audit.Classification{Archetype: audit.ArchetypeService},
		Layers:         []string{"wake-default", "team:web"},
		Waivers:        []audit.Waiver{{ControlID: "license-file", Title: "License present", Layer: "team:web", Reason: "internal"}},
	}
	md := renderRepo(r, "wake-default")
	if !strings.Contains(md, "Policy layers:") || !strings.Contains(md, "team:web") {
		t.Errorf("missing layers line:\n%s", md)
	}
	if !strings.Contains(md, "Waived") || !strings.Contains(md, "License present") {
		t.Errorf("missing waiver block:\n%s", md)
	}
}
