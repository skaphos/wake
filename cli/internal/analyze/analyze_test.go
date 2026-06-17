// SPDX-License-Identifier: MIT

package analyze

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/skaphos/wake-core/evidence"
	"github.com/skaphos/wake-forensics-mcp/source"
)

// fakeSource is a Source whose Extract result is fixed at construction.
type fakeSource struct {
	kind    string
	bundles []evidence.Bundle
	err     error
}

func (f fakeSource) Extract(context.Context) ([]evidence.Bundle, error) {
	return f.bundles, f.err
}
func (f fakeSource) Kind() string { return f.kind }

func okSource(kind, repo string) source.Source {
	return fakeSource{kind: kind, bundles: []evidence.Bundle{{
		SchemaVersion: evidence.SchemaVersion,
		Target:        evidence.RepositoryTarget{Repository: repo},
	}}}
}

func failSource(kind string) source.Source {
	return fakeSource{kind: kind, err: errors.New("boom")}
}

func runWith(t *testing.T, srcs []source.Source) (out, errw string, err error) {
	t.Helper()
	var o, e bytes.Buffer
	err = Run(context.Background(), Options{
		Sources:      srcs,
		Format:       FormatJSON,
		Writer:       &o,
		ErrWriter:    &e,
		EmitEvidence: true, // emit bundles so we can assert on which survived
		Now:          func() time.Time { return time.Unix(0, 0).UTC() },
	})
	return o.String(), e.String(), err
}

func TestRun_PartialResults_OneSourceFails(t *testing.T) {
	out, errw, err := runWith(t, []source.Source{
		okSource("local", "good-repo"),
		failSource("remote:github"),
	})
	if err != nil {
		t.Fatalf("partial run should succeed, got %v", err)
	}
	if !strings.Contains(out, "good-repo") {
		t.Errorf("output missing surviving bundle; got:\n%s", out)
	}
	if !strings.Contains(errw, "warning: skipped failed source") || !strings.Contains(errw, "remote:github") {
		t.Errorf("expected diagnostic for failed source on stderr; got:\n%s", errw)
	}
}

func TestRun_AllSourcesFail_ReturnsError(t *testing.T) {
	_, _, err := runWith(t, []source.Source{
		failSource("local"),
		failSource("remote:github"),
	})
	if err == nil {
		t.Fatal("expected error when all sources fail")
	}
	if !strings.Contains(err.Error(), "all 2 source(s) failed") {
		t.Errorf("unexpected error message: %v", err)
	}
	// The joined cause must be unwrappable to a SourceFailure.
	var sf *SourceFailure
	if !errors.As(err, &sf) {
		t.Errorf("error chain should contain *SourceFailure, got %v", err)
	}
}

func TestRun_AllSucceed_NoWarnings(t *testing.T) {
	_, errw, err := runWith(t, []source.Source{
		okSource("local", "a"),
		okSource("local", "b"),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if errw != "" {
		t.Errorf("expected no diagnostics, got:\n%s", errw)
	}
}
