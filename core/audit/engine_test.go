// SPDX-License-Identifier: MIT

package audit

import (
	"fmt"
	"sort"
	"testing"

	"github.com/skaphos/wake-core/confidence"
)

// memTree is an in-memory FileTree for tests.
type memTree struct {
	info  RepoInfo
	files map[string]string
}

func (t memTree) Paths() []string {
	ps := make([]string, 0, len(t.files))
	for p := range t.files {
		ps = append(ps, p)
	}
	sort.Strings(ps)
	return ps
}

func (t memTree) ReadFile(p string) ([]byte, error) {
	c, ok := t.files[p]
	if !ok {
		return nil, fmt.Errorf("not found: %s", p)
	}
	return []byte(c), nil
}

func (t memTree) Repo() RepoInfo { return t.info }

func findingByID(r RepoReport, id string) (Finding, bool) {
	for _, f := range r.Findings {
		if f.ControlID == id {
			return f, true
		}
	}
	return Finding{}, false
}

// rulePack is a small but representative rule set: a CI control, a
// unit-tests control that requires CI, a Sonar control that requires CI and
// only applies to non-docs repos, and a categorical deployment-intent.
func rulePack() RuleSet {
	return RuleSet{
		Name: "test-pack",
		Controls: []Control{
			{
				ID: "ci-pipeline", Title: "CI pipeline", Kind: KindBoolean, Severity: Hard,
				Evidence:    []EvidencePattern{{PathGlobs: []string{".github/workflows/*.yml", "azure-pipelines.yml"}}},
				Remediation: "add a CI pipeline",
			},
			{
				ID: "unit-tests", Title: "Unit tests in CI", Kind: KindBoolean, Severity: Hard,
				Requires:    []string{"ci-pipeline"},
				AppliesWhen: Applicability{ExcludeArchetypes: []Archetype{ArchetypeDocs}},
				Evidence: []EvidencePattern{{
					PathGlobs:       []string{".github/workflows/*.yml"},
					ContentPatterns: []string{`(?i)go test|npm test|pytest|dotnet test`},
				}},
			},
			{
				ID: "quality-gate", Title: "SonarQube", Kind: KindBoolean, Severity: Soft,
				Requires:    []string{"ci-pipeline"},
				AppliesWhen: Applicability{ExcludeArchetypes: []Archetype{ArchetypeDocs, ArchetypeGitOps}},
				Evidence: []EvidencePattern{{
					PathGlobs:       []string{".github/workflows/*.yml"},
					ContentPatterns: []string{`sonar-scanner|SonarQubeAnalyze`},
				}},
			},
			{
				ID: "deployment-intent", Title: "Deployment intent", Kind: KindCategorical, Severity: Soft,
				Categories: []Category{
					{Name: "production", Evidence: []EvidencePattern{{
						PathGlobs: []string{".github/workflows/*.yml"}, ContentPatterns: []string{`environment:\s*production`}}}},
					{Name: "non-production", Evidence: []EvidencePattern{{
						PathGlobs: []string{".github/workflows/*.yml"}, ContentPatterns: []string{`environment:`}}}},
				},
				DefaultCategory: "none",
			},
		},
	}
}

func TestEvaluate_ServiceRepoFullySignalled(t *testing.T) {
	tree := memTree{
		info: RepoInfo{Name: "svc"},
		files: map[string]string{
			".github/workflows/ci.yml": "steps:\n  - run: go test ./...\n  - run: sonar-scanner\nenvironment: production\n",
			"main.go":                  "package main",
		},
	}
	r := Evaluate(tree, Classification{Archetype: ArchetypeService, Languages: []string{"go"}}, rulePack())

	want := map[string]Outcome{"ci-pipeline": OutcomePass, "unit-tests": OutcomePass, "quality-gate": OutcomePass}
	for id, w := range want {
		f, _ := findingByID(r, id)
		if f.Outcome != w {
			t.Errorf("%s outcome = %q, want %q", id, f.Outcome, w)
		}
	}
	// CI passes via path existence → medium; unit-tests passes via content → high.
	if f, _ := findingByID(r, "ci-pipeline"); f.Confidence.Band != confidence.BandMedium {
		t.Errorf("ci-pipeline band = %q, want medium", f.Confidence.Band)
	}
	if f, _ := findingByID(r, "unit-tests"); f.Confidence.Band != confidence.BandHigh {
		t.Errorf("unit-tests band = %q, want high", f.Confidence.Band)
	}
	if f, _ := findingByID(r, "deployment-intent"); f.Category != "production" {
		t.Errorf("deployment-intent category = %q, want production", f.Category)
	}
}

func TestEvaluate_RequiresUnmetIsUnknownNotFail(t *testing.T) {
	// No pipeline at all: unit-tests requires ci-pipeline → unknown, not fail.
	tree := memTree{info: RepoInfo{Name: "svc"}, files: map[string]string{"main.go": "package main"}}
	r := Evaluate(tree, Classification{Archetype: ArchetypeService}, rulePack())

	if f, _ := findingByID(r, "ci-pipeline"); f.Outcome != OutcomeFail {
		t.Errorf("ci-pipeline = %q, want fail", f.Outcome)
	}
	f, _ := findingByID(r, "unit-tests")
	if f.Outcome != OutcomeUnknown {
		t.Errorf("unit-tests = %q, want unknown (prerequisite unmet)", f.Outcome)
	}
	if len(f.Confidence.Caveats) == 0 || f.Confidence.Caveats[0].Code != "prerequisite_unmet" {
		t.Errorf("unit-tests missing prerequisite_unmet caveat: %+v", f.Confidence.Caveats)
	}
}

func TestEvaluate_PipelineButNoTestsIsFail(t *testing.T) {
	// Pipeline exists but runs no tests: unit-tests is fail (evaluable, no evidence).
	tree := memTree{info: RepoInfo{Name: "svc"}, files: map[string]string{
		".github/workflows/ci.yml": "steps:\n  - run: go build ./...\n",
	}}
	r := Evaluate(tree, Classification{Archetype: ArchetypeService}, rulePack())
	if f, _ := findingByID(r, "unit-tests"); f.Outcome != OutcomeFail {
		t.Errorf("unit-tests = %q, want fail", f.Outcome)
	}
}

func TestEvaluate_ApplicabilityNA(t *testing.T) {
	// A docs repo: unit-tests and quality-gate do not apply → n/a.
	tree := memTree{info: RepoInfo{Name: "docs"}, files: map[string]string{"README.md": "# docs"}}
	r := Evaluate(tree, Classification{Archetype: ArchetypeDocs}, rulePack())
	for _, id := range []string{"unit-tests", "quality-gate"} {
		f, _ := findingByID(r, id)
		if f.Outcome != OutcomeNA {
			t.Errorf("%s = %q, want n/a on a docs repo", id, f.Outcome)
		}
		if f.Confidence.Band != confidence.BandUnknown {
			t.Errorf("%s band = %q, want unknown", id, f.Confidence.Band)
		}
	}
}

func TestEvaluate_CategoricalDefault(t *testing.T) {
	tree := memTree{info: RepoInfo{Name: "svc"}, files: map[string]string{
		".github/workflows/ci.yml": "steps:\n  - run: echo hi\n",
	}}
	r := Evaluate(tree, Classification{Archetype: ArchetypeService}, rulePack())
	if f, _ := findingByID(r, "deployment-intent"); f.Category != "none" {
		t.Errorf("deployment-intent category = %q, want none (default)", f.Category)
	}
}

func TestMatchPath(t *testing.T) {
	cases := []struct {
		glob, path string
		want       bool
	}{
		{"go.mod", "go.mod", true},
		{"go.mod", "sub/dir/go.mod", true}, // basename match at depth
		{"*.Tests.csproj", "src/App.Tests.csproj", true},
		{".github/workflows/*.yml", ".github/workflows/ci.yml", true},
		{".github/workflows/*.yml", ".github/workflows/nested/ci.yml", false}, // * doesn't cross /
		{"**/*.tf", "infra/modules/vpc/main.tf", true},
		{"**/test/*", "a/b/test/x.go", true},
		{"azure-pipelines.yml", "azure-pipelines.yml", true},
		{"azure-pipelines.yml", "ci/azure-pipelines.yml", true}, // basename
	}
	for _, c := range cases {
		if got := matchPath(c.glob, c.path); got != c.want {
			t.Errorf("matchPath(%q, %q) = %v, want %v", c.glob, c.path, got, c.want)
		}
	}
}

func TestValidate(t *testing.T) {
	good := rulePack()
	if err := good.Validate(); err != nil {
		t.Fatalf("valid pack rejected: %v", err)
	}
	tests := []struct {
		name string
		rs   RuleSet
	}{
		{"empty id", RuleSet{Controls: []Control{{Title: "x", Kind: KindBoolean, Severity: Hard}}}},
		{"dup id", RuleSet{Controls: []Control{
			{ID: "a", Kind: KindBoolean, Severity: Hard}, {ID: "a", Kind: KindBoolean, Severity: Hard}}}},
		{"bad severity", RuleSet{Controls: []Control{{ID: "a", Kind: KindBoolean, Severity: "maybe"}}}},
		{"bad kind", RuleSet{Controls: []Control{{ID: "a", Kind: "weird", Severity: Hard}}}},
		{"unknown requires", RuleSet{Controls: []Control{{ID: "a", Kind: KindBoolean, Severity: Hard, Requires: []string{"ghost"}}}}},
		{"bad regex", RuleSet{Controls: []Control{{ID: "a", Kind: KindBoolean, Severity: Hard,
			Evidence: []EvidencePattern{{ContentPatterns: []string{"("}}}}}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.rs.Validate(); err == nil {
				t.Errorf("expected validation error for %s", tt.name)
			}
		})
	}
}
