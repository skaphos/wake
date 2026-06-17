// SPDX-License-Identifier: MIT

package remote

import (
	"context"
	"fmt"
	"reflect"
	"testing"

	"github.com/skaphos/wake-core/audit"
)

// fakeAPI is an in-memory API for testing the FileTree logic without HTTP.
type fakeAPI struct {
	trees   map[string][]string
	content map[string]map[string]string
	org     []RepoRef
	reads   int
}

func (f *fakeAPI) Tree(_ context.Context, r RepoRef) ([]string, bool, error) {
	return f.trees[r.FullName()], false, nil
}

func (f *fakeAPI) Content(_ context.Context, r RepoRef, p string) ([]byte, error) {
	f.reads++
	c, ok := f.content[r.FullName()][p]
	if !ok {
		return nil, fmt.Errorf("not found: %s", p)
	}
	return []byte(c), nil
}

func (f *fakeAPI) ListOrgRepos(_ context.Context, _ string) ([]RepoRef, error) {
	return f.org, nil
}

func TestTree_PathsAndLazyCachedReads(t *testing.T) {
	ref := RepoRef{Owner: "acme", Name: "svc", DefaultBranch: "main"}
	api := &fakeAPI{
		trees: map[string][]string{"acme/svc": {
			"main.go", "go.mod", ".github/workflows/ci.yml",
			"README.md", "internal/a.go", "internal/b.go",
		}},
		content: map[string]map[string]string{"acme/svc": {
			".github/workflows/ci.yml": "steps:\n  - run: go test ./...\n",
		}},
	}
	tr, err := NewTree(context.Background(), api, ref)
	if err != nil {
		t.Fatal(err)
	}

	// Paths are sorted.
	want := []string{".github/workflows/ci.yml", "README.md", "go.mod", "internal/a.go", "internal/b.go", "main.go"}
	if !reflect.DeepEqual(tr.Paths(), want) {
		t.Fatalf("paths = %v, want %v", tr.Paths(), want)
	}
	if tr.Repo().Name != "svc" {
		t.Errorf("repo name = %q", tr.Repo().Name)
	}

	// Evaluate the default pack. Only the workflow file's content is needed
	// (the content-scanned controls), and it must be fetched exactly once
	// despite several controls reading it — proving targeted + cached fetch.
	rep := audit.Evaluate(tr, audit.Classify(tr), audit.DefaultRuleSet())
	if api.reads != 1 {
		t.Errorf("content reads = %d, want 1 (only the pipeline file, cached across controls)", api.reads)
	}
	var ut audit.Finding
	for _, f := range rep.Findings {
		if f.ControlID == "unit-tests" {
			ut = f
		}
	}
	if ut.Outcome != audit.OutcomePass {
		t.Errorf("unit-tests = %q, want pass (go test in workflow)", ut.Outcome)
	}
}

func TestEligibleRepos(t *testing.T) {
	repos := []RepoRef{
		{Owner: "o", Name: "z-active"},
		{Owner: "o", Name: "a-archived", Archived: true},
		{Owner: "o", Name: "m-fork", Fork: true},
		{Owner: "o", Name: "b-active"},
	}
	got := EligibleRepos(repos, false, false)
	var names []string
	for _, r := range got {
		names = append(names, r.Name)
	}
	want := []string{"b-active", "z-active"} // archived + fork excluded, sorted by full name
	if !reflect.DeepEqual(names, want) {
		t.Errorf("eligible = %v, want %v", names, want)
	}
	if len(EligibleRepos(repos, true, true)) != 4 {
		t.Error("including archived+forks should keep all repos")
	}
}
