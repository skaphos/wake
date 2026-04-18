// SPDX-License-Identifier: MIT

package analyze

import (
	"sort"
	"strings"
	"time"

	"github.com/skaphos/wake-core/events"
	"github.com/skaphos/wake-core/evidence"
)

// Report is the shape shown to operators at the end of an analyze
// run. It is deliberately narrow for the first prerelease: enough to
// eyeball who is doing what without committing to a rich inference
// surface that belongs in wake-inference-mcp later.
type Report struct {
	Target         evidence.RepositoryTarget `json:"target"`
	GeneratedAt    time.Time                 `json:"generated_at"`
	WindowStart    time.Time                 `json:"window_start"`
	WindowEnd      time.Time                 `json:"window_end"`
	TotalCommits   int                       `json:"total_commits"`
	Classified     int                       `json:"classified_events"`
	EventsByKind   []KindCount               `json:"events_by_kind"`
	Contributors   []ContributorStats        `json:"contributors"`
	SampleEvents   []events.Event            `json:"sample_events,omitempty"`
}

type KindCount struct {
	Kind  events.Kind `json:"kind"`
	Count int         `json:"count"`
}

type ContributorStats struct {
	Name         string      `json:"name"`
	Email        string      `json:"email,omitempty"`
	TotalCommits int         `json:"total_commits"`
	TotalEvents  int         `json:"total_events"`
	ByKind       []KindCount `json:"by_kind"`
}

// BuildReport derives a Report from a forensics bundle and the
// classifier output. Contributor stats are grouped by canonical email
// (falling back to canonical name) so that a contributor who shows up
// with two aliases still appears once — alias normalization proper
// lives in a later ticket.
func BuildReport(bundle evidence.Bundle, candidates []events.Candidate, now time.Time) Report {
	rep := Report{
		Target:       bundle.Target,
		GeneratedAt:  now.UTC(),
		TotalCommits: len(bundle.Commits),
		Classified:   len(candidates),
	}

	rep.WindowStart, rep.WindowEnd = commitWindow(bundle.Commits)
	rep.EventsByKind = countByKind(candidates)
	rep.Contributors = aggregateContributors(bundle.Commits, candidates)
	rep.SampleEvents = sampleEvents(candidates, 10)

	return rep
}

func commitWindow(records []evidence.CommitRecord) (start, end time.Time) {
	for i, c := range records {
		if i == 0 || c.AuthoredAt.Before(start) {
			start = c.AuthoredAt
		}
		if i == 0 || c.AuthoredAt.After(end) {
			end = c.AuthoredAt
		}
	}
	return start, end
}

func countByKind(candidates []events.Candidate) []KindCount {
	counts := map[events.Kind]int{}
	for _, c := range candidates {
		counts[c.Event.Kind]++
	}
	out := make([]KindCount, 0, len(events.Kinds()))
	for _, kind := range events.Kinds() {
		if n := counts[kind]; n > 0 {
			out = append(out, KindCount{Kind: kind, Count: n})
		}
	}
	return out
}

func aggregateContributors(records []evidence.CommitRecord, candidates []events.Candidate) []ContributorStats {
	// Index commit→author so we can attribute each candidate's source
	// back to the authoring contributor.
	commitAuthor := make(map[string]evidence.ContributorIdentity, len(records))
	for _, c := range records {
		commitAuthor[c.SHA] = c.Author
	}

	type acc struct {
		identity evidence.ContributorIdentity
		commits  int
		byKind   map[events.Kind]int
	}
	buckets := map[string]*acc{}

	keyFor := func(id evidence.ContributorIdentity) string {
		key := strings.ToLower(strings.TrimSpace(id.CanonicalEmail))
		if key == "" {
			key = strings.ToLower(strings.TrimSpace(id.CanonicalName))
		}
		return key
	}

	ensure := func(id evidence.ContributorIdentity) *acc {
		key := keyFor(id)
		b, ok := buckets[key]
		if !ok {
			b = &acc{identity: id, byKind: map[events.Kind]int{}}
			buckets[key] = b
		}
		return b
	}

	for _, c := range records {
		ensure(c.Author).commits++
	}
	for _, cand := range candidates {
		if len(cand.Event.Sources) == 0 {
			continue
		}
		sha := cand.Event.Sources[0].CommitSHA
		author, ok := commitAuthor[sha]
		if !ok {
			continue
		}
		b := ensure(author)
		b.byKind[cand.Event.Kind]++
	}

	out := make([]ContributorStats, 0, len(buckets))
	for _, b := range buckets {
		stats := ContributorStats{
			Name:         b.identity.CanonicalName,
			Email:        b.identity.CanonicalEmail,
			TotalCommits: b.commits,
		}
		for _, kind := range events.Kinds() {
			if n := b.byKind[kind]; n > 0 {
				stats.ByKind = append(stats.ByKind, KindCount{Kind: kind, Count: n})
				stats.TotalEvents += n
			}
		}
		out = append(out, stats)
	}

	sort.SliceStable(out, func(i, j int) bool {
		if out[i].TotalEvents != out[j].TotalEvents {
			return out[i].TotalEvents > out[j].TotalEvents
		}
		if out[i].TotalCommits != out[j].TotalCommits {
			return out[i].TotalCommits > out[j].TotalCommits
		}
		return out[i].Name < out[j].Name
	})
	return out
}

func sampleEvents(candidates []events.Candidate, max int) []events.Event {
	if len(candidates) == 0 {
		return nil
	}
	if max > len(candidates) {
		max = len(candidates)
	}
	out := make([]events.Event, 0, max)
	for i := 0; i < max; i++ {
		out = append(out, candidates[i].Event)
	}
	return out
}
