// SPDX-License-Identifier: MIT

package teamscmd

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/skaphos/wake-audit-mcp/source/remote"
	"github.com/skaphos/wake-core/audit"
	"github.com/skaphos/wake-core/ownership"
)

func sampleRollup() ownership.Report {
	return ownership.Report{
		Teams: []ownership.TeamRollup{
			{Team: "payments", ReposOwned: 2, ReposAudited: 2, ReposOutOfPolicy: 1,
				Repos: []ownership.RepoStatus{
					{Repository: "acme/pay", Audited: true, OutOfPolicy: true, HardViolations: 1},
					{Repository: "acme/ledger", Audited: true},
				}},
			{Team: "docs", ReposOwned: 1, ReposAudited: 1},
		},
		Unowned: []ownership.RepoStatus{{Repository: "acme/orphan", Audited: true, OutOfPolicy: true, HardViolations: 2}},
	}
}

func TestRenderMarkdown_Headline(t *testing.T) {
	ep := audit.EffectivePolicy{
		RuleSet: audit.RuleSet{Name: "wake-default"},
		Layers:  []string{"wake-default", "org:acme"},
	}
	sweep := remote.SweepResult{Audited: 3, Skipped: 0}
	md := renderMarkdown("acme", ep, sweep, sampleRollup())

	if !strings.Contains(md, "Team policy rollup: acme") {
		t.Errorf("missing headline:\n%s", md)
	}
	if !strings.Contains(md, "Policy layers: wake-default ⊕ org:acme") {
		t.Errorf("missing layers line:\n%s", md)
	}
	if !strings.Contains(md, "**payments** — out of policy:") || !strings.Contains(md, "acme/pay (1 hard violation") {
		t.Errorf("missing per-team detail:\n%s", md)
	}
	if !strings.Contains(md, "Unowned") || !strings.Contains(md, "acme/orphan") {
		t.Errorf("missing unowned section:\n%s", md)
	}
}

func TestRender_JSON(t *testing.T) {
	var buf bytes.Buffer
	ep := audit.EffectivePolicy{RuleSet: audit.RuleSet{Name: "wake-default"}}
	err := render(&buf, "json", "acme", ep, remote.SweepResult{Audited: 1}, sampleRollup())
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Org    string `json:"org"`
		Rollup struct {
			Teams []struct {
				Team             string `json:"team"`
				ReposOutOfPolicy int    `json:"repos_out_of_policy"`
			} `json:"teams"`
		} `json:"rollup"`
	}
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("json: %v", err)
	}
	if got.Org != "acme" || len(got.Rollup.Teams) != 2 {
		t.Errorf("decoded = %+v", got)
	}
}

func TestResolveToken_Precedence(t *testing.T) {
	if got := resolveToken("explicit"); got != "explicit" {
		t.Errorf("explicit token = %q, want explicit", got)
	}
	t.Setenv("WAKE_GITHUB_TOKEN", "")
	t.Setenv("GITHUB_TOKEN", "gh-env")
	t.Setenv("GH_TOKEN", "ghtok")
	if got := resolveToken(""); got != "gh-env" {
		t.Errorf("env token = %q, want gh-env (GITHUB_TOKEN before GH_TOKEN)", got)
	}
}

func TestRun_OrgRequired(t *testing.T) {
	var out, errw bytes.Buffer
	err := Run(context.Background(), nil, &out, &errw)
	if err == nil || !strings.Contains(err.Error(), "requires --org") {
		t.Fatalf("err = %v, want org-required", err)
	}
}

func TestRun_NegativeMaxReposRejected(t *testing.T) {
	var out, errw bytes.Buffer
	err := Run(context.Background(), []string{"--org", "acme", "--max-repos", "-1"}, &out, &errw)
	if err == nil || !strings.Contains(err.Error(), "max-repos") {
		t.Fatalf("err = %v, want max-repos rejection", err)
	}
}

func TestRun_BadLayerRejectedBeforeNetwork(t *testing.T) {
	// A malformed team layer must fail during policy resolution, before any
	// GitHub call.
	dir := t.TempDir()
	bad := dir + "/team.yaml"
	if err := writeFileT(t, bad, "name: team\nedits:\n  - verb: relax\n    id: x\n"); err != nil {
		t.Fatal(err)
	}
	var out, errw bytes.Buffer
	err := Run(context.Background(), []string{"--org", "acme", "--team-layer", bad}, &out, &errw)
	if err == nil || !strings.Contains(err.Error(), "requires a reason") {
		t.Fatalf("err = %v, want layer-validation error", err)
	}
}
