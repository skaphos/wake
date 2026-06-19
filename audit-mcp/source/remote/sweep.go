// SPDX-License-Identifier: MIT

package remote

import (
	"context"

	"github.com/skaphos/wake-core/audit"
	"github.com/skaphos/wake-core/ownership"
)

// SweepOptions scopes an org-wide audit sweep.
type SweepOptions struct {
	IncludeArchived bool
	IncludeForks    bool
	// MaxRepos caps the number of repositories audited after eligibility
	// filtering; 0 means no cap. When the cap drops eligible repos, the result
	// is marked Truncated.
	MaxRepos int
}

// SweepResult is the outcome of an org sweep: one report per repository (audited
// or skipped), plus the audited/skipped tallies and whether a cap truncated the
// scan.
type SweepResult struct {
	Reports   []audit.RepoReport
	Audited   int
	Skipped   int
	Truncated bool
}

// AuditRepo audits one remote repository against the effective policy. A fetch
// failure becomes a skipped report so one unreachable repo does not abort a
// sweep.
func AuditRepo(ctx context.Context, api API, ref RepoRef, ep audit.EffectivePolicy) audit.RepoReport {
	tree, err := NewTree(ctx, api, ref)
	if err != nil {
		return audit.RepoReport{Repository: ref.FullName(), Skipped: true, SkipReason: err.Error()}
	}
	return audit.EvaluatePolicy(tree, audit.Classify(tree), ep)
}

// SweepOrg enumerates an organization's repositories, filters them to the audit
// scope, applies the optional cap, and audits each against the effective
// policy.
func SweepOrg(ctx context.Context, api API, org string, opt SweepOptions, ep audit.EffectivePolicy) (SweepResult, error) {
	repos, err := api.ListOrgRepos(ctx, org)
	if err != nil {
		return SweepResult{}, err
	}
	eligible := EligibleRepos(repos, opt.IncludeArchived, opt.IncludeForks)
	res := SweepResult{}
	if opt.MaxRepos > 0 && len(eligible) > opt.MaxRepos {
		eligible = eligible[:opt.MaxRepos]
		res.Truncated = true
	}
	res.Reports = make([]audit.RepoReport, 0, len(eligible))
	for _, ref := range eligible {
		report := AuditRepo(ctx, api, ref, ep)
		if report.Skipped {
			res.Skipped++
		} else {
			res.Audited++
		}
		res.Reports = append(res.Reports, report)
	}
	return res, nil
}

// BuildOwnershipGraph enumerates an organization's teams and their repository
// assignments into an ownership graph keyed by repository full name ("owner/
// name") and team slug — the substrate for a per-team policy rollup.
func BuildOwnershipGraph(ctx context.Context, api API, org string) (*ownership.Graph, error) {
	g := ownership.NewGraph()
	teams, err := api.ListTeams(ctx, org)
	if err != nil {
		return nil, err
	}
	for _, t := range teams {
		repos, err := api.ListTeamRepos(ctx, org, t.Slug)
		if err != nil {
			return nil, err
		}
		for _, r := range repos {
			g.Add(t.Slug, r.FullName())
		}
	}
	return g, nil
}
