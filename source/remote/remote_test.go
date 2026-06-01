// SPDX-License-Identifier: MIT

package remote

import (
	"context"
	"errors"
	"testing"

	"github.com/skaphos/wake-forensics-mcp/source/remote/model"
)

type fakeCollector struct {
	result model.Result
	err    error
	gotQ   model.Query
}

func (f *fakeCollector) Collect(_ context.Context, q model.Query) (model.Result, error) {
	f.gotQ = q
	return f.result, f.err
}

func TestSourceExtractMapsResult(t *testing.T) {
	t.Parallel()

	fc := &fakeCollector{result: model.Result{
		Provider: model.ProviderGitHub,
		Commits: []model.Commit{
			{SHA: "1", Repo: "o/r", AuthorName: "A"},
		},
	}}
	s := Source{provider: model.ProviderGitHub, client: fc, query: model.Query{Author: "a"}}

	bundles, err := s.Extract(context.Background())
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	if len(bundles) != 1 {
		t.Fatalf("got %d bundles, want 1", len(bundles))
	}
	if bundles[0].Target.Repository != "github:o/r" {
		t.Errorf("target = %q", bundles[0].Target.Repository)
	}
	if s.Kind() != "remote:github" {
		t.Errorf("kind = %q", s.Kind())
	}
}

func TestSourceExtractPropagatesError(t *testing.T) {
	t.Parallel()

	sentinel := errors.New("boom")
	s := Source{provider: model.ProviderGitLab, client: &fakeCollector{err: sentinel}}
	if _, err := s.Extract(context.Background()); !errors.Is(err, sentinel) {
		t.Fatalf("err = %v, want %v", err, sentinel)
	}
}

func TestConstructorsSetProvider(t *testing.T) {
	t.Parallel()

	gh, err := NewGitHub("", "", 50, model.Query{Author: "a"})
	if err != nil {
		t.Fatalf("NewGitHub: %v", err)
	}
	if gh.query.Provider != model.ProviderGitHub || gh.Kind() != "remote:github" {
		t.Errorf("github source misconfigured: %+v", gh)
	}

	gl, err := NewGitLab("", "", 50, model.Query{Author: "a"})
	if err != nil {
		t.Fatalf("NewGitLab: %v", err)
	}
	if gl.query.Provider != model.ProviderGitLab || gl.Kind() != "remote:gitlab" {
		t.Errorf("gitlab source misconfigured: %+v", gl)
	}
}
