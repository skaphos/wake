// SPDX-License-Identifier: MIT

package ownership

import (
	"slices"
	"strings"
	"testing"

	"github.com/skaphos/wake-core/audit"
)

func TestGraph_ManyToMany(t *testing.T) {
	g := NewGraph()
	g.Add("platform", "acme/web")
	g.Add("payments", "acme/web") // a repo with two owners
	g.Add("platform", "acme/api")
	g.Add("platform", "acme/web") // idempotent

	if !slices.Equal(g.TeamsForRepo("acme/web"), []string{"payments", "platform"}) {
		t.Errorf("teams for acme/web = %v", g.TeamsForRepo("acme/web"))
	}
	if !slices.Equal(g.ReposForTeam("platform"), []string{"acme/api", "acme/web"}) {
		t.Errorf("repos for platform = %v", g.ReposForTeam("platform"))
	}
	if !slices.Equal(g.Teams(), []string{"payments", "platform"}) {
		t.Errorf("teams = %v", g.Teams())
	}
	if !g.Has("payments", "acme/web") || g.Has("payments", "acme/api") {
		t.Errorf("Has wrong")
	}
}

func TestApplyOverrides_Extend(t *testing.T) {
	g := NewGraph()
	g.Add("platform", "acme/web")
	g.ApplyOverrides([]Override{{Repo: "acme/web", Teams: []string{"security"}}})

	if !slices.Equal(g.TeamsForRepo("acme/web"), []string{"platform", "security"}) {
		t.Errorf("extend override = %v, want [platform security]", g.TeamsForRepo("acme/web"))
	}
}

func TestApplyOverrides_Replace(t *testing.T) {
	g := NewGraph()
	g.Add("platform", "acme/web")
	g.Add("platform", "acme/api")
	g.ApplyOverrides([]Override{{Repo: "acme/web", Teams: []string{"payments"}, Replace: true}})

	if !slices.Equal(g.TeamsForRepo("acme/web"), []string{"payments"}) {
		t.Errorf("replace override = %v, want [payments]", g.TeamsForRepo("acme/web"))
	}
	// platform keeps its other repo, loses only acme/web.
	if !slices.Equal(g.ReposForTeam("platform"), []string{"acme/api"}) {
		t.Errorf("platform repos after replace = %v, want [acme/api]", g.ReposForTeam("platform"))
	}
}

func TestLoadOverrides(t *testing.T) {
	const y = `
overrides:
  - repo: acme/web
    teams: [platform, payments]
  - repo: acme/legacy
    teams: [platform]
    replace: true
`
	c, err := LoadOverrides(strings.NewReader(y))
	if err != nil {
		t.Fatalf("LoadOverrides: %v", err)
	}
	if len(c.Overrides) != 2 || !c.Overrides[1].Replace {
		t.Fatalf("decoded wrong: %+v", c.Overrides)
	}
}

func TestLoadOverrides_RejectsMissingTeams(t *testing.T) {
	_, err := LoadOverrides(strings.NewReader("overrides:\n  - repo: acme/web\n    teams: []\n"))
	if err == nil || !strings.Contains(err.Error(), "at least one team") {
		t.Fatalf("err = %v, want team-required", err)
	}
}

func TestLoadOverrides_EmptyFile(t *testing.T) {
	c, err := LoadOverrides(strings.NewReader(""))
	if err != nil || len(c.Overrides) != 0 {
		t.Fatalf("empty file: c=%+v err=%v", c, err)
	}
}

// report builds a RepoReport with a single hard finding of the given outcome.
func report(name string, outcome audit.Outcome) audit.RepoReport {
	return audit.RepoReport{
		Repository: name,
		Findings: []audit.Finding{
			{ControlID: "ci", Severity: audit.Hard, Outcome: outcome},
		},
	}
}

func TestRollup_HeadlinePerTeam(t *testing.T) {
	g := NewGraph()
	g.Add("platform", "acme/web") // out of policy
	g.Add("platform", "acme/api") // compliant
	g.Add("payments", "acme/web") // shared; out of policy
	g.Add("docs", "acme/guide")   // skipped → not audited

	reports := []audit.RepoReport{
		report("acme/web", audit.OutcomeFail),
		report("acme/api", audit.OutcomePass),
		{Repository: "acme/guide", Skipped: true, SkipReason: "unreachable"},
		report("acme/orphan", audit.OutcomeFail), // no team owns it
	}

	rep := Rollup(g, reports)

	// platform and payments both own an out-of-policy repo; both have 1.
	// Ordering: by out-of-policy desc then name → payments(1), platform(1), docs(0).
	if len(rep.Teams) != 3 {
		t.Fatalf("teams = %d, want 3", len(rep.Teams))
	}
	if rep.Teams[len(rep.Teams)-1].Team != "docs" {
		t.Errorf("last team = %q, want docs (0 out of policy)", rep.Teams[len(rep.Teams)-1].Team)
	}

	platform := teamByName(rep.Teams, "platform")
	if platform.ReposOwned != 2 || platform.ReposAudited != 2 || platform.ReposOutOfPolicy != 1 {
		t.Errorf("platform rollup = %+v", platform)
	}
	docs := teamByName(rep.Teams, "docs")
	if docs.ReposOwned != 1 || docs.ReposAudited != 0 || docs.ReposOutOfPolicy != 0 {
		t.Errorf("docs rollup (skipped repo) = %+v", docs)
	}

	// orphan repo is out of policy but unowned → surfaced in Unowned.
	if len(rep.Unowned) != 1 || rep.Unowned[0].Repository != "acme/orphan" || !rep.Unowned[0].OutOfPolicy {
		t.Errorf("unowned = %+v, want [acme/orphan out-of-policy]", rep.Unowned)
	}
}

func teamByName(ts []TeamRollup, name string) TeamRollup {
	for _, tr := range ts {
		if tr.Team == name {
			return tr
		}
	}
	return TeamRollup{}
}
