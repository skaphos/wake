// SPDX-License-Identifier: MIT

package ownership

import (
	"sort"

	"github.com/skaphos/wake-core/audit"
)

// RepoStatus is one repository's compliance status within a team's rollup.
// Audited is false when the repo was owned but had no usable report (skipped
// or not in scope), in which case OutOfPolicy is not meaningful.
type RepoStatus struct {
	Repository     string `json:"repository"`
	Audited        bool   `json:"audited"`
	OutOfPolicy    bool   `json:"out_of_policy"`
	HardViolations int    `json:"hard_violations"`
}

// TeamRollup is one team's slice of the policy report: the repositories it
// owns and how many are out of policy.
type TeamRollup struct {
	Team             string       `json:"team"`
	ReposOwned       int          `json:"repos_owned"`
	ReposAudited     int          `json:"repos_audited"`
	ReposOutOfPolicy int          `json:"repos_out_of_policy"`
	Repos            []RepoStatus `json:"repos"`
}

// Report is the per-team rollup of a set of repository audits, plus the
// audited repositories that no team owns (the attribution gap).
type Report struct {
	Teams   []TeamRollup `json:"teams"`
	Unowned []RepoStatus `json:"unowned,omitempty"`
}

// Rollup joins the ownership graph with a set of repository audit reports into
// a per-team view. Teams are ordered by their out-of-policy repo count
// (descending) then name, so the worst-off teams lead — the headline "which
// teams own repos out of policy". Unowned collects audited repos that no team
// claims, surfacing the attribution gap rather than hiding it.
func Rollup(g *Graph, reports []audit.RepoReport) Report {
	byRepo := make(map[string]audit.RepoReport, len(reports))
	for _, r := range reports {
		byRepo[r.Repository] = r
	}

	statusFor := func(repo string) RepoStatus {
		st := RepoStatus{Repository: repo}
		if r, ok := byRepo[repo]; ok && !r.Skipped {
			st.Audited = true
			st.HardViolations = len(r.HardViolations())
			st.OutOfPolicy = st.HardViolations > 0
		}
		return st
	}

	teams := make([]TeamRollup, 0, len(g.Teams()))
	for _, team := range g.Teams() {
		tr := TeamRollup{Team: team}
		for _, repo := range g.ReposForTeam(team) {
			st := statusFor(repo)
			tr.Repos = append(tr.Repos, st)
			tr.ReposOwned++
			if st.Audited {
				tr.ReposAudited++
			}
			if st.OutOfPolicy {
				tr.ReposOutOfPolicy++
			}
		}
		teams = append(teams, tr)
	}
	sort.SliceStable(teams, func(i, j int) bool {
		if teams[i].ReposOutOfPolicy != teams[j].ReposOutOfPolicy {
			return teams[i].ReposOutOfPolicy > teams[j].ReposOutOfPolicy
		}
		return teams[i].Team < teams[j].Team
	})

	var unowned []RepoStatus
	for _, r := range reports {
		if r.Skipped {
			continue
		}
		if len(g.TeamsForRepo(r.Repository)) == 0 {
			unowned = append(unowned, statusFor(r.Repository))
		}
	}
	sort.Slice(unowned, func(i, j int) bool { return unowned[i].Repository < unowned[j].Repository })

	return Report{Teams: teams, Unowned: unowned}
}
