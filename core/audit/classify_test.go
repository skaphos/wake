// SPDX-License-Identifier: MIT

package audit

import (
	"reflect"
	"testing"
)

func tree(name string, files ...string) memTree {
	m := memTree{info: RepoInfo{Name: name}, files: map[string]string{}}
	for _, f := range files {
		m.files[f] = "x"
	}
	return m
}

func TestClassify(t *testing.T) {
	cases := []struct {
		name      string
		tree      memTree
		archetype Archetype
		langs     []string
	}{
		{
			name:      "go service",
			tree:      tree("svc", "go.mod", "cmd/svc/main.go", "internal/app/app.go", "Dockerfile"),
			archetype: ArchetypeService,
			langs:     []string{"go"},
		},
		{
			name:      "go library",
			tree:      tree("lib", "go.mod", "lib.go", "lib_test.go"),
			archetype: ArchetypeLibrary,
			langs:     []string{"go"},
		},
		{
			name:      "docs only",
			tree:      tree("docs", "README.md", "docs/guide.md", "LICENSE"),
			archetype: ArchetypeDocs,
			langs:     nil,
		},
		{
			name:      "terraform iac",
			tree:      tree("infra", "main.tf", "variables.tf", "modules/vpc/main.tf"),
			archetype: ArchetypeIaC,
			langs:     []string{"terraform"},
		},
		{
			name:      "gitops kustomize",
			tree:      tree("gitops", "base/kustomization.yaml", "overlays/prod/kustomization.yaml", "README.md"),
			archetype: ArchetypeGitOps,
			langs:     nil,
		},
		{
			name:      "helm gitops",
			tree:      tree("chart", "Chart.yaml", "values.yaml", "templates/deploy.yaml"),
			archetype: ArchetypeGitOps,
			langs:     nil,
		},
		{
			name:      "node service",
			tree:      tree("web", "package.json", "src/index.ts", "Dockerfile"),
			archetype: ArchetypeService,
			langs:     []string{"javascript", "typescript"},
		},
		{
			name:      "empty",
			tree:      tree("empty"),
			archetype: ArchetypeUnknown,
			langs:     nil,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := Classify(c.tree)
			if got.Archetype != c.archetype {
				t.Errorf("archetype = %q, want %q", got.Archetype, c.archetype)
			}
			if !reflect.DeepEqual(got.Languages, c.langs) {
				t.Errorf("languages = %v, want %v", got.Languages, c.langs)
			}
		})
	}
}

// Classification should drive applicability end-to-end: a docs repo makes
// code-oriented controls n/a.
func TestClassifyDrivesApplicability(t *testing.T) {
	docs := tree("docs", "README.md", "docs/x.md")
	cls := Classify(docs)
	r := Evaluate(docs, cls, rulePack())
	if f, _ := findingByID(r, "unit-tests"); f.Outcome != OutcomeNA {
		t.Errorf("unit-tests on classified docs repo = %q, want n/a", f.Outcome)
	}
}
