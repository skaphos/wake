// SPDX-License-Identifier: MIT

package policyfile

import (
	"os"
	"path/filepath"
	"testing"
)

func write(t *testing.T, name, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestRuleSet(t *testing.T) {
	p := write(t, "rules.yaml", "name: custom\ncontrols:\n  - id: readme\n    title: README\n    kind: boolean\n    severity: soft\n    evidence:\n      - path_globs: [README.md]\n")
	rs, err := RuleSet(p)
	if err != nil {
		t.Fatalf("RuleSet: %v", err)
	}
	if rs.Name != "custom" || len(rs.Controls) != 1 {
		t.Errorf("rs = %+v", rs)
	}
	if _, err := RuleSet("/no/such/file"); err == nil {
		t.Error("want error for missing file")
	}
}

func TestLayers_OrderAndSkip(t *testing.T) {
	org := write(t, "org.yaml", "name: org\nedits:\n  - verb: strengthen\n    id: quality-gate\n    promote_to_hard: true\n")
	team := write(t, "team.yaml", "name: team\nedits: []\n")

	got, err := Layers(org, team)
	if err != nil {
		t.Fatalf("Layers: %v", err)
	}
	if len(got) != 2 || got[0].Name != "org" || got[1].Name != "team" {
		t.Errorf("layers = %+v, want [org team]", got)
	}
	// Empty paths are skipped.
	got, err = Layers("", "")
	if err != nil || len(got) != 0 {
		t.Errorf("empty layers: got=%v err=%v", got, err)
	}
}

func TestOverrides(t *testing.T) {
	p := write(t, "own.yaml", "overrides:\n  - repo: acme/web\n    teams: [platform]\n")
	ovs, err := Overrides(p)
	if err != nil {
		t.Fatalf("Overrides: %v", err)
	}
	if len(ovs) != 1 || ovs[0].Repo != "acme/web" {
		t.Errorf("ovs = %+v", ovs)
	}
	// Empty path → no overrides, no error.
	if ovs, err := Overrides(""); err != nil || ovs != nil {
		t.Errorf("empty overrides: got=%v err=%v", ovs, err)
	}
}
