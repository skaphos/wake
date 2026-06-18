// SPDX-License-Identifier: MIT

package mcpserver

import (
	"context"
	"strings"
	"testing"

	"github.com/skaphos/wake-audit-mcp/internal/config"
	"github.com/skaphos/wake-audit-mcp/source/remote"
	"github.com/skaphos/wake-core/ownership"
)

func TestAuditTeams_RollupAndOverrides(t *testing.T) {
	ciPaths, ciContent := ciTree() // compliant Go service
	// A Go service with no CI pipeline → ci-pipeline fails hard (out of policy).
	noCI := []string{"go.mod", "main.go"}
	api := &fakeAPI{
		org: []remote.RepoRef{{Owner: "acme", Name: "good"}, {Owner: "acme", Name: "bad"}},
		trees: map[string][]string{
			"acme/good": ciPaths,
			"acme/bad":  noCI,
		},
		content: map[string]map[string]string{
			"acme/good": ciContent,
			"acme/bad":  {"go.mod": "module bad\n", "main.go": "package main\nfunc main() {}\n"},
		},
		teams: []remote.Team{{Slug: "platform", Name: "Platform"}},
		teamRepos: map[string][]remote.RepoRef{
			"platform": {{Owner: "acme", Name: "good"}},
		},
	}
	h := &handler{
		cfg:    config.Config{},
		newAPI: func(_, _ string) (remote.API, error) { return api, nil },
	}
	// Override attributes acme/bad to the payments team (GitHub doesn't know it).
	overrides := "overrides:\n  - repo: acme/bad\n    teams: [payments]\n"

	res, out, err := h.auditTeams(context.Background(), nil, AuditTeamsInput{Org: "acme", OverridesYAML: overrides})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("tool error: %s", textOf(res))
	}
	if out.ReposAudited != 2 {
		t.Errorf("repos audited = %d, want 2", out.ReposAudited)
	}

	payments := rollupTeam(out.Rollup, "payments")
	if payments.ReposOutOfPolicy != 1 {
		t.Errorf("payments out-of-policy = %d, want 1 (owns acme/bad via override)", payments.ReposOutOfPolicy)
	}
	platform := rollupTeam(out.Rollup, "platform")
	if platform.ReposOutOfPolicy != 0 {
		t.Errorf("platform out-of-policy = %d, want 0 (owns compliant acme/good)", platform.ReposOutOfPolicy)
	}

	md := textOf(res)
	if !strings.Contains(md, "Team policy rollup: acme") || !strings.Contains(md, "payments") {
		t.Errorf("rollup markdown missing headline/team:\n%s", md)
	}
}

func TestAuditTeams_OrgRequired(t *testing.T) {
	h := &handler{cfg: config.Config{}}
	res, _, err := h.auditTeams(context.Background(), nil, AuditTeamsInput{})
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError {
		t.Error("want tool error when org is empty")
	}
}

func TestRenderTeams_HeadlineAndUnowned(t *testing.T) {
	rep := ownership.Report{
		Teams: []ownership.TeamRollup{
			{Team: "payments", ReposOwned: 2, ReposAudited: 2, ReposOutOfPolicy: 1,
				Repos: []ownership.RepoStatus{
					{Repository: "acme/pay", Audited: true, OutOfPolicy: true, HardViolations: 2},
					{Repository: "acme/ok", Audited: true},
				}},
		},
		Unowned: []ownership.RepoStatus{{Repository: "acme/orphan", Audited: true, OutOfPolicy: true, HardViolations: 1}},
	}
	md := renderTeams("acme", "wake-default", rep, false, []string{"wake-default", "team:x"}, nil)
	if !strings.Contains(md, "payments") || !strings.Contains(md, "acme/pay (2 hard violation") {
		t.Errorf("missing team out-of-policy detail:\n%s", md)
	}
	if !strings.Contains(md, "Unowned") || !strings.Contains(md, "acme/orphan") {
		t.Errorf("missing unowned section:\n%s", md)
	}
}

func rollupTeam(rep ownership.Report, name string) ownership.TeamRollup {
	for _, tr := range rep.Teams {
		if tr.Team == name {
			return tr
		}
	}
	return ownership.TeamRollup{}
}
