// SPDX-License-Identifier: MIT

// Package query provides deterministic filtering and grouping over
// normalized event candidates produced by the classify pipeline.
//
// It defines the contract for the three grouped views Wake reports on —
// by contributor, by component, and by time window — plus a Criteria
// filter that composes the same dimensions. All results are returned in
// a stable order so callers (CLI renderers, MCP responses) emit
// reproducible output.
package query

import (
	"path"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/skaphos/wake-core/events"
)

// Criteria narrows a candidate set. Zero-valued fields impose no
// constraint, so the zero Criteria matches everything.
type Criteria struct {
	// Contributor matches a candidate's canonical author name exactly.
	Contributor string
	// Component matches candidates that touch the given component key at
	// ComponentDepth (see Component). A candidate touching several
	// components matches if any of them equals Component.
	Component string
	// ComponentDepth controls how many leading path segments form a
	// component key when Component is set. Values < 1 are treated as 1.
	ComponentDepth int
	// Kinds, when non-empty, restricts results to these event kinds.
	Kinds []events.Kind
	// From and To bound the commit AuthoredAt time, inclusive. The zero
	// time leaves the corresponding bound open.
	From time.Time
	To   time.Time
}

// Group is a set of candidates sharing a key under one grouping
// dimension. Count is always len(Events) and is provided so callers can
// render summaries without recomputing it.
type Group struct {
	Key    string             `json:"key"`
	Count  int                `json:"count"`
	Events []events.Candidate `json:"events"`
}

// Period is a calendar bucket size for the time-window view.
type Period string

const (
	Daily   Period = "daily"
	Weekly  Period = "weekly"
	Monthly Period = "monthly"
)

// Filter returns the candidates matching c, preserving input order.
func Filter(cands []events.Candidate, c Criteria) []events.Candidate {
	depth := max(c.ComponentDepth, 1)
	kinds := make(map[events.Kind]struct{}, len(c.Kinds))
	for _, k := range c.Kinds {
		kinds[k] = struct{}{}
	}

	out := make([]events.Candidate, 0, len(cands))
	for _, cand := range cands {
		if c.Contributor != "" && cand.Evidence.Author.CanonicalName != c.Contributor {
			continue
		}
		if len(kinds) > 0 {
			if _, ok := kinds[cand.Event.Kind]; !ok {
				continue
			}
		}
		at := cand.Evidence.AuthoredAt
		if !c.From.IsZero() && at.Before(c.From) {
			continue
		}
		if !c.To.IsZero() && at.After(c.To) {
			continue
		}
		if c.Component != "" && !touchesComponent(cand, c.Component, depth) {
			continue
		}
		out = append(out, cand)
	}
	return out
}

// ByContributor groups candidates by canonical author name. Groups are
// ordered by key; candidates within a group keep chronological order.
func ByContributor(cands []events.Candidate) []Group {
	return groupBy(cands, func(c events.Candidate) []string {
		return []string{c.Evidence.Author.CanonicalName}
	})
}

// ByKind groups candidates by normalized event kind.
func ByKind(cands []events.Candidate) []Group {
	return groupBy(cands, func(c events.Candidate) []string {
		return []string{string(c.Event.Kind)}
	})
}

// ByComponent groups candidates by component key derived from the
// leading depth segments of each touched path. A candidate that touches
// multiple components appears in each of their groups. depth < 1 is
// treated as 1.
func ByComponent(cands []events.Candidate, depth int) []Group {
	depth = max(depth, 1)
	return groupBy(cands, func(c events.Candidate) []string {
		return components(c, depth)
	})
}

// ByPeriod groups candidates into calendar buckets of the given period,
// keyed by the bucket start in a stable, sortable form (YYYY-MM-DD for
// daily/weekly, YYYY-MM for monthly). Times are bucketed in UTC.
func ByPeriod(cands []events.Candidate, p Period) []Group {
	return groupBy(cands, func(c events.Candidate) []string {
		return []string{periodKey(c.Evidence.AuthoredAt, p)}
	})
}

// keysOf returns the grouping keys for a candidate. A candidate may map
// to more than one key (e.g. multiple components).
type keysOf func(events.Candidate) []string

func groupBy(cands []events.Candidate, key keysOf) []Group {
	buckets := map[string][]events.Candidate{}
	for _, c := range cands {
		seen := map[string]struct{}{}
		for _, k := range key(c) {
			if k == "" {
				continue
			}
			if _, dup := seen[k]; dup {
				continue
			}
			seen[k] = struct{}{}
			buckets[k] = append(buckets[k], c)
		}
	}

	keys := make([]string, 0, len(buckets))
	for k := range buckets {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	groups := make([]Group, 0, len(keys))
	for _, k := range keys {
		evs := buckets[k]
		sort.SliceStable(evs, func(i, j int) bool {
			ai, aj := evs[i].Evidence.AuthoredAt, evs[j].Evidence.AuthoredAt
			if !ai.Equal(aj) {
				return ai.Before(aj)
			}
			return evs[i].Evidence.SHA < evs[j].Evidence.SHA
		})
		groups = append(groups, Group{Key: k, Count: len(evs), Events: evs})
	}
	return groups
}

func components(c events.Candidate, depth int) []string {
	var out []string
	seen := map[string]struct{}{}
	for _, src := range c.Event.Sources {
		for _, p := range src.Paths {
			key := componentKey(p, depth)
			if key == "" {
				continue
			}
			if _, dup := seen[key]; dup {
				continue
			}
			seen[key] = struct{}{}
			out = append(out, key)
		}
	}
	return out
}

func touchesComponent(c events.Candidate, want string, depth int) bool {
	return slices.Contains(components(c, depth), want)
}

// componentKey returns the leading depth segments of a cleaned path. A
// path with fewer than depth segments collapses to its directory (or
// "." for a bare filename) so root-level files share one component.
func componentKey(p string, depth int) string {
	clean := path.Clean(strings.TrimSpace(p))
	if clean == "" || clean == "." {
		return ""
	}
	clean = strings.TrimPrefix(clean, "/")
	segs := strings.Split(clean, "/")
	if len(segs) <= depth {
		// Root-level file (no directory prefix) groups under ".".
		if len(segs) == 1 {
			return "."
		}
		return strings.Join(segs[:len(segs)-1], "/")
	}
	return strings.Join(segs[:depth], "/")
}

func periodKey(t time.Time, p Period) string {
	u := t.UTC()
	switch p {
	case Monthly:
		return u.Format("2006-01")
	case Weekly:
		// Bucket to the Monday of the ISO week for a stable, sortable key.
		offset := (int(u.Weekday()) + 6) % 7 // days since Monday
		monday := u.AddDate(0, 0, -offset)
		return monday.Format("2006-01-02")
	default: // Daily
		return u.Format("2006-01-02")
	}
}
