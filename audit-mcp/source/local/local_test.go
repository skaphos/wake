// SPDX-License-Identifier: MIT

package local

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/skaphos/wake-core/audit"
)

func writeTree(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for rel, content := range files {
		full := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func TestNew_PathsAndIgnores(t *testing.T) {
	root := writeTree(t, map[string]string{
		"go.mod":                   "module x",
		"cmd/svc/main.go":          "package main",
		".github/workflows/ci.yml": "jobs: {}",
		".git/config":              "[core]",         // ignored
		"vendor/dep/dep.go":        "package dep",    // ignored
		"node_modules/m/index.js":  "module.exports", // ignored
	})
	tr, err := New(root)
	if err != nil {
		t.Fatal(err)
	}
	got := tr.Paths()
	want := []string{".github/workflows/ci.yml", "cmd/svc/main.go", "go.mod"}
	if !slices.Equal(got, want) {
		t.Fatalf("paths = %v, want %v (ignored dirs must be skipped)", got, want)
	}
	if tr.Repo().Name != filepath.Base(root) {
		t.Errorf("repo name = %q, want %q", tr.Repo().Name, filepath.Base(root))
	}
}

func TestReadFile(t *testing.T) {
	root := writeTree(t, map[string]string{"a/b.txt": "hello"})
	tr, _ := New(root)
	b, err := tr.ReadFile("a/b.txt")
	if err != nil || string(b) != "hello" {
		t.Fatalf("ReadFile = %q, %v; want hello", b, err)
	}
	// Traversal is rejected.
	if _, err := tr.ReadFile("../../etc/passwd"); err == nil {
		t.Error("expected error reading outside the tree")
	}
}

// The local tree must satisfy audit.FileTree and drive a real evaluation.
func TestLocalTreeEvaluates(t *testing.T) {
	root := writeTree(t, map[string]string{
		"go.mod":                   "module x",
		"main.go":                  "package main",
		"Dockerfile":               "FROM scratch",
		".github/workflows/ci.yml": "steps:\n  - run: go test ./...\n",
	})
	tr, err := New(root)
	if err != nil {
		t.Fatal(err)
	}
	var _ audit.FileTree = tr
	rep := audit.Evaluate(tr, audit.Classify(tr), audit.DefaultRuleSet())
	if rep.Classification.Archetype != audit.ArchetypeService {
		t.Errorf("archetype = %q, want service", rep.Classification.Archetype)
	}
	var ci, ut audit.Finding
	for _, f := range rep.Findings {
		switch f.ControlID {
		case "ci-pipeline":
			ci = f
		case "unit-tests":
			ut = f
		}
	}
	if ci.Outcome != audit.OutcomePass {
		t.Errorf("ci-pipeline = %q, want pass", ci.Outcome)
	}
	if ut.Outcome != audit.OutcomePass {
		t.Errorf("unit-tests = %q, want pass", ut.Outcome)
	}
}
