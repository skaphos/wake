// SPDX-License-Identifier: MIT

package audit

import (
	"strings"
	"testing"
)

func TestDefaultRuleSetValidates(t *testing.T) {
	if err := DefaultRuleSet().Validate(); err != nil {
		t.Fatalf("default rule set is invalid: %v", err)
	}
}

func TestDefaultPack_GoServiceCompliant(t *testing.T) {
	tr := memTree{info: RepoInfo{Name: "svc"}, files: map[string]string{
		"go.mod":          "module x",
		"cmd/svc/main.go": "package main",
		"Dockerfile":      "FROM scratch",
		".github/workflows/ci.yml": "jobs:\n  build:\n    steps:\n" +
			"      - run: go test ./...\n      - run: sonar-scanner\n    environment: production\n",
		"app_test.go": "package app",
	}}
	cls := Classify(tr)
	if cls.Archetype != ArchetypeService {
		t.Fatalf("classify archetype = %q, want service", cls.Archetype)
	}
	r := Evaluate(tr, cls, DefaultRuleSet())
	for _, id := range []string{"ci-pipeline", "unit-tests", "quality-gate"} {
		f, _ := findingByID(r, id)
		if f.Outcome != OutcomePass {
			t.Errorf("%s = %q, want pass", id, f.Outcome)
		}
	}
	if f, _ := findingByID(r, "deployment-intent"); f.Category != "production" {
		t.Errorf("deployment-intent = %q, want production", f.Category)
	}
}

func TestDefaultPack_DocsRepoExcusesCodeControls(t *testing.T) {
	tr := tree("docs", "README.md", "docs/guide.md")
	r := Evaluate(tr, Classify(tr), DefaultRuleSet())
	for _, id := range []string{"ci-pipeline", "unit-tests", "quality-gate"} {
		f, _ := findingByID(r, id)
		if f.Outcome != OutcomeNA {
			t.Errorf("%s on docs repo = %q, want n/a", id, f.Outcome)
		}
	}
}

func TestDefaultPack_PipelineWithoutTestsFailsHard(t *testing.T) {
	tr := memTree{info: RepoInfo{Name: "svc"}, files: map[string]string{
		"go.mod":                   "module x",
		"main.go":                  "package main",
		".github/workflows/ci.yml": "jobs:\n  build:\n    steps:\n      - run: go build ./...\n",
	}}
	r := Evaluate(tr, Classify(tr), DefaultRuleSet())
	f, _ := findingByID(r, "unit-tests")
	if f.Outcome != OutcomeFail || f.Severity != Hard {
		t.Errorf("unit-tests = %q sev %q, want fail/hard (pipeline present, no tests)", f.Outcome, f.Severity)
	}
}

func TestLoadRuleSet_RoundTrip(t *testing.T) {
	yamlPack := `
name: custom-pack
version: v1
controls:
  - id: license-file
    title: License present
    kind: boolean
    severity: hard
    evidence:
      - path_globs: ["LICENSE", "LICENSE.*"]
  - id: dockerfile
    title: Container build
    kind: boolean
    severity: soft
    applies_when:
      exclude_archetypes: ["docs"]
    evidence:
      - path_globs: ["Dockerfile", "**/Dockerfile"]
`
	rs, err := LoadRuleSet(strings.NewReader(yamlPack))
	if err != nil {
		t.Fatalf("LoadRuleSet: %v", err)
	}
	if rs.Name != "custom-pack" || len(rs.Controls) != 2 {
		t.Fatalf("loaded pack = %+v", rs)
	}
	tr := tree("svc", "LICENSE", "Dockerfile", "main.go", "go.mod")
	r := Evaluate(tr, Classify(tr), rs)
	if f, _ := findingByID(r, "license-file"); f.Outcome != OutcomePass {
		t.Errorf("license-file = %q, want pass", f.Outcome)
	}
	if f, _ := findingByID(r, "dockerfile"); f.Outcome != OutcomePass {
		t.Errorf("dockerfile = %q, want pass", f.Outcome)
	}
}

func TestLoadRuleSet_RejectsInvalid(t *testing.T) {
	bad := []string{
		"name: x\ncontrols:\n  - id: a\n    kind: boolean\n    severity: maybe\n", // bad severity
		"name: x\nbogus_field: true\ncontrols: []\n",                              // unknown field
	}
	for i, b := range bad {
		if _, err := LoadRuleSet(strings.NewReader(b)); err == nil {
			t.Errorf("case %d: expected error, got nil", i)
		}
	}
}
