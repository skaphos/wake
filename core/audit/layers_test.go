// SPDX-License-Identifier: MIT

package audit

import (
	"slices"
	"strings"
	"testing"
)

// layerBase is a small base pack: two hard controls (one requiring the other)
// and two soft controls, mirroring the shape of the default pack.
func layerBase() RuleSet {
	return RuleSet{
		Name:    "base-pack",
		Version: "v1",
		Controls: []Control{
			{
				ID: "ci-pipeline", Title: "CI pipeline", Kind: KindBoolean, Severity: Hard,
				Evidence: []EvidencePattern{{PathGlobs: []string{".github/workflows/*.yml"}}},
			},
			{
				ID: "unit-tests", Title: "Unit tests", Kind: KindBoolean, Severity: Hard,
				Requires: []string{"ci-pipeline"},
				Evidence: []EvidencePattern{{PathGlobs: []string{"**/*_test.go"}}},
			},
			{
				ID: "quality-gate", Title: "Quality gate", Kind: KindBoolean, Severity: Soft,
				Evidence: []EvidencePattern{{PathGlobs: []string{"sonar-project.properties"}}},
			},
			{
				ID: "license-file", Title: "License present", Kind: KindBoolean, Severity: Soft,
				Evidence: []EvidencePattern{{PathGlobs: []string{"LICENSE"}}},
			},
		},
	}
}

func controlByID(rs RuleSet, id string) (Control, bool) {
	for _, c := range rs.Controls {
		if c.ID == id {
			return c, true
		}
	}
	return Control{}, false
}

func waiverByID(ws []Waiver, id string) (Waiver, bool) {
	for _, w := range ws {
		if w.ControlID == id {
			return w, true
		}
	}
	return Waiver{}, false
}

func TestResolve_NoLayers_ReturnsBase(t *testing.T) {
	ep, err := Resolve(layerBase())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got, want := len(ep.RuleSet.Controls), 4; got != want {
		t.Fatalf("controls = %d, want %d", got, want)
	}
	if len(ep.Waivers) != 0 {
		t.Fatalf("waivers = %v, want none", ep.Waivers)
	}
	if got := ep.Layers; len(got) != 1 || got[0] != "base-pack" {
		t.Fatalf("layers = %v, want [base-pack]", got)
	}
	for _, c := range ep.RuleSet.Controls {
		if ep.Origin[c.ID] != "base-pack" {
			t.Errorf("origin[%s] = %q, want base-pack", c.ID, ep.Origin[c.ID])
		}
	}
}

func TestResolve_Add(t *testing.T) {
	team := Layer{Name: "team:payments", Edits: []LayerEdit{
		{Verb: VerbAdd, Control: &Control{
			ID: "sbom", Title: "SBOM published", Kind: KindBoolean, Severity: Hard,
			Evidence: []EvidencePattern{{PathGlobs: []string{"sbom.json"}}},
		}},
	}}
	ep, err := Resolve(layerBase(), team)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	c, ok := controlByID(ep.RuleSet, "sbom")
	if !ok {
		t.Fatal("added control sbom missing from effective rule set")
	}
	if c.Severity != Hard {
		t.Errorf("sbom severity = %q, want hard", c.Severity)
	}
	if ep.Origin["sbom"] != "team:payments" {
		t.Errorf("origin[sbom] = %q, want team:payments", ep.Origin["sbom"])
	}
	// Added control keeps declaration order at the end.
	if last := ep.RuleSet.Controls[len(ep.RuleSet.Controls)-1].ID; last != "sbom" {
		t.Errorf("last control = %q, want sbom (added controls append)", last)
	}
}

func TestResolve_AddDuplicateIsRejected(t *testing.T) {
	team := Layer{Name: "team", Edits: []LayerEdit{
		{Verb: VerbAdd, Control: &Control{
			ID: "ci-pipeline", Title: "dup", Kind: KindBoolean, Severity: Hard,
		}},
	}}
	_, err := Resolve(layerBase(), team)
	if err == nil || !strings.Contains(err.Error(), "already defined") {
		t.Fatalf("err = %v, want already-defined error", err)
	}
}

func TestResolve_StrengthenPromotesSoftToHard(t *testing.T) {
	org := Layer{Name: "org:acme", Edits: []LayerEdit{
		{Verb: VerbStrengthen, ID: "quality-gate", PromoteToHard: true, Reason: "acme requires a quality gate"},
	}}
	ep, err := Resolve(layerBase(), org)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	c, _ := controlByID(ep.RuleSet, "quality-gate")
	if c.Severity != Hard {
		t.Errorf("quality-gate severity = %q, want hard after promotion", c.Severity)
	}
	if ep.Origin["quality-gate"] != "org:acme" {
		t.Errorf("origin = %q, want org:acme", ep.Origin["quality-gate"])
	}
}

func TestResolve_StrengthenOverridesFields(t *testing.T) {
	org := Layer{Name: "org", Edits: []LayerEdit{
		{Verb: VerbStrengthen, ID: "ci-pipeline", Control: &Control{
			Remediation: "use the golden pipeline template",
			Evidence:    []EvidencePattern{{PathGlobs: []string{".github/workflows/ci.yml"}}},
		}},
	}}
	ep, err := Resolve(layerBase(), org)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	c, _ := controlByID(ep.RuleSet, "ci-pipeline")
	if c.Remediation != "use the golden pipeline template" {
		t.Errorf("remediation not overridden: %q", c.Remediation)
	}
	if c.Severity != Hard {
		t.Errorf("severity changed unexpectedly: %q", c.Severity)
	}
	if len(c.Evidence) != 1 || c.Evidence[0].PathGlobs[0] != ".github/workflows/ci.yml" {
		t.Errorf("evidence not overridden: %+v", c.Evidence)
	}
}

func TestResolve_StrengthenCannotDowngrade(t *testing.T) {
	org := Layer{Name: "org", Edits: []LayerEdit{
		{Verb: VerbStrengthen, ID: "ci-pipeline", Control: &Control{Severity: Soft}},
	}}
	_, err := Resolve(layerBase(), org)
	if err == nil || !strings.Contains(err.Error(), "downgrade") {
		t.Fatalf("err = %v, want downgrade rejection", err)
	}
}

func TestResolve_RelaxSoftRecordsWaiver(t *testing.T) {
	team := Layer{Name: "team:web", Edits: []LayerEdit{
		{Verb: VerbRelax, ID: "license-file", Reason: "internal-only service, no license needed"},
	}}
	ep, err := Resolve(layerBase(), team)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if _, ok := controlByID(ep.RuleSet, "license-file"); ok {
		t.Fatal("relaxed control still present in effective rule set")
	}
	w, ok := waiverByID(ep.Waivers, "license-file")
	if !ok {
		t.Fatal("no waiver recorded for relaxed control")
	}
	if w.Layer != "team:web" {
		t.Errorf("waiver layer = %q, want team:web", w.Layer)
	}
	if w.Reason == "" || w.Title != "License present" {
		t.Errorf("waiver missing provenance: %+v", w)
	}
}

func TestResolve_RelaxHardIsRejected(t *testing.T) {
	team := Layer{Name: "team", Edits: []LayerEdit{
		{Verb: VerbRelax, ID: "ci-pipeline", Reason: "we do not use CI"},
	}}
	_, err := Resolve(layerBase(), team)
	if err == nil || !strings.Contains(err.Error(), "cannot relax hard control") {
		t.Fatalf("err = %v, want hard-relax rejection", err)
	}
}

func TestResolve_RelaxRequiredControlIsRejected(t *testing.T) {
	// Make ci-pipeline soft so relax is severity-legal, but unit-tests still
	// requires it: relaxing it would orphan the dependency.
	base := layerBase()
	for i := range base.Controls {
		if base.Controls[i].ID == "ci-pipeline" {
			base.Controls[i].Severity = Soft
		}
	}
	team := Layer{Name: "team", Edits: []LayerEdit{
		{Verb: VerbRelax, ID: "ci-pipeline", Reason: "x"},
	}}
	_, err := Resolve(base, team)
	if err == nil || !strings.Contains(err.Error(), "still requires it") {
		t.Fatalf("err = %v, want required-by rejection", err)
	}
}

func TestResolve_LayerOrderTeamOverridesOrg(t *testing.T) {
	// org promotes quality-gate soft→hard; team then tries to relax it →
	// must fail because by the time team runs the control is hard.
	org := Layer{Name: "org", Edits: []LayerEdit{
		{Verb: VerbStrengthen, ID: "quality-gate", PromoteToHard: true},
	}}
	team := Layer{Name: "team", Edits: []LayerEdit{
		{Verb: VerbRelax, ID: "quality-gate", Reason: "team opts out"},
	}}
	_, err := Resolve(layerBase(), org, team)
	if err == nil || !strings.Contains(err.Error(), "cannot relax hard control") {
		t.Fatalf("err = %v, want relax rejected after org promotion", err)
	}
}

func TestResolve_EvaluatePolicyCarriesWaiversAndOrigin(t *testing.T) {
	org := Layer{Name: "org:acme", Edits: []LayerEdit{
		{Verb: VerbStrengthen, ID: "quality-gate", PromoteToHard: true},
	}}
	team := Layer{Name: "team:web", Edits: []LayerEdit{
		{Verb: VerbRelax, ID: "license-file", Reason: "internal service"},
		{Verb: VerbAdd, Control: &Control{
			ID: "dockerfile", Title: "Dockerfile present", Kind: KindBoolean, Severity: Soft,
			Evidence: []EvidencePattern{{PathGlobs: []string{"Dockerfile"}}},
		}},
	}}
	ep, err := Resolve(layerBase(), org, team)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	tree := memTree{
		info:  RepoInfo{Name: "acme/web"},
		files: map[string]string{".github/workflows/ci.yml": "x", "foo_test.go": "x"},
	}
	report := EvaluatePolicy(tree, Classification{Archetype: ArchetypeService}, ep)

	if !slices.Equal(report.Layers, []string{"base-pack", "org:acme", "team:web"}) {
		t.Errorf("layers = %v", report.Layers)
	}
	if _, ok := waiverByID(report.Waivers, "license-file"); !ok {
		t.Errorf("report missing license-file waiver: %+v", report.Waivers)
	}
	qg, ok := findingByID(report, "quality-gate")
	if !ok || qg.Origin != "org:acme" {
		t.Errorf("quality-gate finding origin = %q (ok=%v), want org:acme", qg.Origin, ok)
	}
	dk, ok := findingByID(report, "dockerfile")
	if !ok || dk.Origin != "team:web" {
		t.Errorf("dockerfile finding origin = %q (ok=%v), want team:web", dk.Origin, ok)
	}
	// quality-gate is now hard and has no sonar evidence → a hard violation.
	if !report.OutOfPolicy() {
		t.Errorf("expected repo out of policy (promoted quality-gate fails hard)")
	}
}

func TestLayerValidate(t *testing.T) {
	cases := []struct {
		name    string
		layer   Layer
		wantErr string
	}{
		{"empty name", Layer{Edits: nil}, "name is required"},
		{"unknown verb", Layer{Name: "l", Edits: []LayerEdit{{Verb: "delete", ID: "x"}}}, "unknown verb"},
		{"add without body", Layer{Name: "l", Edits: []LayerEdit{{Verb: VerbAdd, ID: "x"}}}, "add requires a control body"},
		{"add id mismatch", Layer{Name: "l", Edits: []LayerEdit{{Verb: VerbAdd, ID: "x", Control: &Control{ID: "y"}}}}, "does not match"},
		{"strengthen no-op", Layer{Name: "l", Edits: []LayerEdit{{Verb: VerbStrengthen, ID: "x"}}}, "no-op"},
		{"relax without reason", Layer{Name: "l", Edits: []LayerEdit{{Verb: VerbRelax, ID: "x"}}}, "requires a reason"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.layer.Validate()
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want containing %q", err, tc.wantErr)
			}
		})
	}
}

func TestResolve_StrengthenUnknownControlRejected(t *testing.T) {
	org := Layer{Name: "org", Edits: []LayerEdit{
		{Verb: VerbStrengthen, ID: "nope", PromoteToHard: true},
	}}
	_, err := Resolve(layerBase(), org)
	if err == nil || !strings.Contains(err.Error(), "strengthen unknown control") {
		t.Fatalf("err = %v, want unknown-control rejection", err)
	}
}
