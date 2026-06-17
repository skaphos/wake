// SPDX-License-Identifier: MIT

package query

import (
	"reflect"
	"testing"
	"time"

	"github.com/skaphos/wake-core/events"
	"github.com/skaphos/wake-core/evidence"
)

func at(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		panic(err)
	}
	return t
}

// cand builds a candidate with the fields the query package reads.
func cand(sha, author string, kind events.Kind, when time.Time, paths ...string) events.Candidate {
	return events.Candidate{
		Event: events.Event{
			ID:      string(kind) + "-" + sha,
			Kind:    kind,
			Sources: []events.SourceRef{{CommitSHA: sha, Paths: paths}},
		},
		Evidence: evidence.CommitRecord{
			SHA:        sha,
			Author:     evidence.ContributorIdentity{CanonicalName: author},
			AuthoredAt: when,
		},
	}
}

func sample() []events.Candidate {
	return []events.Candidate{
		cand("a1", "Alice", events.KindCapabilityIntroduction, at("2026-01-10T00:00:00Z"), "core/events/events.go"),
		cand("b2", "Bob", events.KindDocumentationUpdate, at("2026-02-15T00:00:00Z"), "docs/readme.md"),
		cand("a3", "Alice", events.KindStructuralRefactor, at("2026-02-20T00:00:00Z"), "core/report/report.go", "cli/main.go"),
		cand("c4", "Carol", events.KindOperationalMaintenance, at("2026-01-25T00:00:00Z"), "go.mod"),
	}
}

func keys(groups []Group) []string {
	out := make([]string, len(groups))
	for i, g := range groups {
		out[i] = g.Key
	}
	return out
}

func TestByContributor(t *testing.T) {
	groups := ByContributor(sample())
	if got, want := keys(groups), []string{"Alice", "Bob", "Carol"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("keys = %v, want %v", got, want)
	}
	if groups[0].Count != 2 {
		t.Errorf("Alice count = %d, want 2", groups[0].Count)
	}
	// Within a group, candidates are chronological.
	if a, b := groups[0].Events[0].Evidence.SHA, groups[0].Events[1].Evidence.SHA; a != "a1" || b != "a3" {
		t.Errorf("Alice order = %s,%s, want a1,a3", a, b)
	}
}

func TestByKind(t *testing.T) {
	groups := ByKind(sample())
	want := []string{
		string(events.KindCapabilityIntroduction),
		string(events.KindDocumentationUpdate),
		string(events.KindOperationalMaintenance),
		string(events.KindStructuralRefactor),
	}
	if got := keys(groups); !reflect.DeepEqual(got, want) {
		t.Fatalf("keys = %v, want %v", got, want)
	}
}

func TestByComponentMultiComponentMembership(t *testing.T) {
	groups := ByComponent(sample(), 1)
	// a3 touches core/ and cli/, so it appears under both.
	if got, want := keys(groups), []string{".", "cli", "core", "docs"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("keys = %v, want %v", got, want)
	}
	byKey := map[string]Group{}
	for _, g := range groups {
		byKey[g.Key] = g
	}
	if byKey["core"].Count != 2 { // a1 + a3
		t.Errorf("core count = %d, want 2", byKey["core"].Count)
	}
	if byKey["cli"].Count != 1 || byKey["cli"].Events[0].Evidence.SHA != "a3" {
		t.Errorf("cli group = %+v, want single a3", byKey["cli"])
	}
	if byKey["."].Count != 1 || byKey["."].Events[0].Evidence.SHA != "c4" {
		t.Errorf("root component group = %+v, want single c4 (go.mod)", byKey["."])
	}
}

func TestByComponentDepth(t *testing.T) {
	groups := ByComponent(sample(), 2)
	got := keys(groups)
	want := []string{".", "cli", "core/events", "core/report", "docs"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("depth-2 keys = %v, want %v", got, want)
	}
}

func TestByPeriod(t *testing.T) {
	if got, want := keys(ByPeriod(sample(), Monthly)), []string{"2026-01", "2026-02"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("monthly keys = %v, want %v", got, want)
	}
	// Weekly buckets to the Monday of the ISO week. 2026-01-10 is a Saturday
	// (week of Mon 2026-01-05); 2026-01-25 is a Sunday (week of Mon 2026-01-19).
	wk := keys(ByPeriod(sample(), Weekly))
	want := []string{"2026-01-05", "2026-01-19", "2026-02-09", "2026-02-16"}
	if !reflect.DeepEqual(wk, want) {
		t.Fatalf("weekly keys = %v, want %v", wk, want)
	}
}

func TestFilter(t *testing.T) {
	all := sample()
	tests := []struct {
		name string
		crit Criteria
		want []string // SHAs, in input order
	}{
		{"empty matches all", Criteria{}, []string{"a1", "b2", "a3", "c4"}},
		{"by contributor", Criteria{Contributor: "Alice"}, []string{"a1", "a3"}},
		{"by kind", Criteria{Kinds: []events.Kind{events.KindDocumentationUpdate}}, []string{"b2"}},
		{"by component", Criteria{Component: "core", ComponentDepth: 1}, []string{"a1", "a3"}},
		{"by time window", Criteria{From: at("2026-02-01T00:00:00Z"), To: at("2026-02-28T00:00:00Z")}, []string{"b2", "a3"}},
		{"combined", Criteria{Contributor: "Alice", From: at("2026-02-01T00:00:00Z")}, []string{"a3"}},
		{"no match", Criteria{Contributor: "Nobody"}, []string{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Filter(all, tt.crit)
			shas := make([]string, 0, len(got))
			for _, c := range got {
				shas = append(shas, c.Evidence.SHA)
			}
			if len(shas) == 0 {
				shas = []string{}
			}
			if !reflect.DeepEqual(shas, tt.want) {
				t.Errorf("Filter() = %v, want %v", shas, tt.want)
			}
		})
	}
}

func TestEmptyInput(t *testing.T) {
	if got := ByContributor(nil); len(got) != 0 {
		t.Errorf("ByContributor(nil) = %v, want empty", got)
	}
	if got := Filter(nil, Criteria{Contributor: "Alice"}); len(got) != 0 {
		t.Errorf("Filter(nil) = %v, want empty", got)
	}
}
