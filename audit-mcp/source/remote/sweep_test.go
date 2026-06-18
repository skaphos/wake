// SPDX-License-Identifier: MIT

package remote

import (
	"context"
	"testing"

	"github.com/skaphos/wake-core/audit"
)

func TestBuildOwnershipGraph(t *testing.T) {
	api := &fakeAPI{
		teams: []Team{{Slug: "platform"}, {Slug: "payments"}},
		teamRepos: map[string][]RepoRef{
			"platform": {{Owner: "acme", Name: "web"}, {Owner: "acme", Name: "api"}},
			"payments": {{Owner: "acme", Name: "web"}}, // shared repo → many-to-many
		},
	}
	g, err := BuildOwnershipGraph(context.Background(), api, "acme")
	if err != nil {
		t.Fatalf("BuildOwnershipGraph: %v", err)
	}
	if got := g.TeamsForRepo("acme/web"); len(got) != 2 {
		t.Errorf("teams for acme/web = %v, want platform+payments", got)
	}
	if !g.Has("platform", "acme/api") {
		t.Error("platform should own acme/api")
	}
}

func TestSweepOrg_FiltersCapsAndAudits(t *testing.T) {
	ci, ciContent := simpleCITree()
	api := &fakeAPI{
		org: []RepoRef{
			{Owner: "acme", Name: "a"},
			{Owner: "acme", Name: "b"},
			{Owner: "acme", Name: "archived", Archived: true},
		},
		trees:   map[string][]string{"acme/a": ci, "acme/b": ci},
		content: map[string]map[string]string{"acme/a": ciContent, "acme/b": ciContent},
	}
	ep := audit.EffectivePolicy{RuleSet: audit.DefaultRuleSet()}

	// Archived excluded by default; cap to 1 → truncated.
	res, err := SweepOrg(context.Background(), api, "acme", SweepOptions{MaxRepos: 1}, ep)
	if err != nil {
		t.Fatalf("SweepOrg: %v", err)
	}
	if res.Audited != 1 || !res.Truncated {
		t.Errorf("audited=%d truncated=%v, want 1 audited + truncated", res.Audited, res.Truncated)
	}

	// No cap, archived still excluded → 2 audited.
	res, err = SweepOrg(context.Background(), api, "acme", SweepOptions{}, ep)
	if err != nil {
		t.Fatalf("SweepOrg: %v", err)
	}
	if res.Audited != 2 || res.Truncated {
		t.Errorf("audited=%d truncated=%v, want 2 audited, not truncated", res.Audited, res.Truncated)
	}
}

// simpleCITree is a Go service with a CI pipeline running tests — passes the
// default pack's hard controls.
func simpleCITree() ([]string, map[string]string) {
	return []string{"go.mod", "main.go", "svc_test.go", ".github/workflows/ci.yml"},
		map[string]string{".github/workflows/ci.yml": "steps:\n  - run: go test ./...\n"}
}
