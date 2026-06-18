// SPDX-License-Identifier: MIT

// Package ownership models the many-to-many ownership relation between teams
// and repositories and rolls a set of per-repository policy audits up into a
// per-team view — the headline cut of the policy report: which teams own
// repositories that are out of policy.
//
// The package is pure: the Graph is built from team→repo assignments supplied
// by a caller (e.g. derived from a Git host's team API) and optionally
// augmented by a per-repository Override config for attribution the host
// misses. Repositories are identified by full name ("owner/name") so a rollup
// keys cleanly against audit.RepoReport.Repository; teams are identified by
// slug.
package ownership

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Graph is a many-to-many team↔repo ownership mapping, queryable in both
// directions. Edges are idempotent; the zero value is not usable — construct
// with NewGraph.
type Graph struct {
	teamRepos map[string]map[string]bool
	repoTeams map[string]map[string]bool
}

// NewGraph returns an empty ownership graph.
func NewGraph() *Graph {
	return &Graph{
		teamRepos: map[string]map[string]bool{},
		repoTeams: map[string]map[string]bool{},
	}
}

// Add records that team owns repo. It is idempotent and registers both the
// team and the repo even if the edge already exists.
func (g *Graph) Add(team, repo string) {
	if g.teamRepos[team] == nil {
		g.teamRepos[team] = map[string]bool{}
	}
	if g.repoTeams[repo] == nil {
		g.repoTeams[repo] = map[string]bool{}
	}
	g.teamRepos[team][repo] = true
	g.repoTeams[repo][team] = true
}

// removeRepo drops every ownership edge for repo (used by a replace override).
// The repo remains known with an empty owner set so it still surfaces as
// unowned in a rollup.
func (g *Graph) removeRepo(repo string) {
	for team := range g.repoTeams[repo] {
		delete(g.teamRepos[team], repo)
		if len(g.teamRepos[team]) == 0 {
			delete(g.teamRepos, team)
		}
	}
	g.repoTeams[repo] = map[string]bool{}
}

// Has reports whether team owns repo.
func (g *Graph) Has(team, repo string) bool {
	return g.teamRepos[team][repo]
}

// Teams returns every team with at least one owned repo, sorted.
func (g *Graph) Teams() []string { return sortedKeys(g.teamRepos) }

// Repos returns every known repo, sorted (including repos left unowned by a
// replace override).
func (g *Graph) Repos() []string { return sortedKeys(g.repoTeams) }

// ReposForTeam returns the repos team owns, sorted.
func (g *Graph) ReposForTeam(team string) []string { return sortedKeys(g.teamRepos[team]) }

// TeamsForRepo returns the teams that own repo, sorted.
func (g *Graph) TeamsForRepo(repo string) []string { return sortedKeys(g.repoTeams[repo]) }

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Override augments the host-derived ownership of one repository with team
// attribution the host does not capture. By default the listed teams extend
// the existing owners; when Replace is set they become the repository's
// complete ownership, discarding host-derived edges for that repo.
type Override struct {
	Repo    string   `json:"repo" yaml:"repo"`
	Teams   []string `json:"teams" yaml:"teams"`
	Replace bool     `json:"replace,omitempty" yaml:"replace,omitempty"`
}

// OverrideConfig is the file shape for a set of per-repo ownership overrides.
type OverrideConfig struct {
	Overrides []Override `json:"overrides" yaml:"overrides"`
}

// ApplyOverrides applies per-repo ownership overrides to the graph in order.
// A replace override first clears the repo's host-derived owners.
func (g *Graph) ApplyOverrides(overrides []Override) {
	for _, ov := range overrides {
		if ov.Replace {
			g.removeRepo(ov.Repo)
		}
		for _, team := range ov.Teams {
			g.Add(team, ov.Repo)
		}
	}
}

// Validate checks an override config for well-formedness: each override names
// a repo and at least one team.
func (c OverrideConfig) Validate() error {
	for i, ov := range c.Overrides {
		if strings.TrimSpace(ov.Repo) == "" {
			return fmt.Errorf("override %d: repo is required", i)
		}
		if len(ov.Teams) == 0 {
			return fmt.Errorf("override %d (%s): at least one team is required", i, ov.Repo)
		}
		for j, t := range ov.Teams {
			if strings.TrimSpace(t) == "" {
				return fmt.Errorf("override %d (%s): team %d is empty", i, ov.Repo, j)
			}
		}
	}
	return nil
}

// LoadOverrides decodes and validates a YAML ownership-override config.
func LoadOverrides(r io.Reader) (OverrideConfig, error) {
	var c OverrideConfig
	dec := yaml.NewDecoder(r)
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil {
		if err == io.EOF {
			return OverrideConfig{}, nil // empty file: no overrides
		}
		return OverrideConfig{}, fmt.Errorf("decode ownership overrides: %w", err)
	}
	if err := c.Validate(); err != nil {
		return OverrideConfig{}, fmt.Errorf("invalid ownership overrides: %w", err)
	}
	return c, nil
}
