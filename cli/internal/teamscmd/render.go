// SPDX-License-Identifier: MIT

package teamscmd

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/skaphos/wake-audit-mcp/source/remote"
	"github.com/skaphos/wake-core/audit"
	"github.com/skaphos/wake-core/ownership"
)

func render(w io.Writer, format, org string, ep audit.EffectivePolicy, sweep remote.SweepResult, rollup ownership.Report) error {
	if format == "json" {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(struct {
			Org          string           `json:"org"`
			RuleSet      string           `json:"rule_set"`
			Layers       []string         `json:"layers,omitempty"`
			Waivers      []audit.Waiver   `json:"waivers,omitempty"`
			ReposAudited int              `json:"repos_audited"`
			ReposSkipped int              `json:"repos_skipped"`
			Truncated    bool             `json:"truncated"`
			Rollup       ownership.Report `json:"rollup"`
		}{org, ep.RuleSet.Name, ep.Layers, ep.Waivers, sweep.Audited, sweep.Skipped, sweep.Truncated, rollup})
	}
	_, err := io.WriteString(w, renderMarkdown(org, ep, sweep, rollup))
	return err
}

func renderMarkdown(org string, ep audit.EffectivePolicy, sweep remote.SweepResult, rollup ownership.Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Team policy rollup: %s\n\n", org)
	fmt.Fprintf(&b, "- Rule pack: `%s`\n", ep.RuleSet.Name)
	if len(ep.Layers) > 1 {
		fmt.Fprintf(&b, "- Policy layers: %s\n", strings.Join(ep.Layers, " ⊕ "))
	}
	var outOfPolicyTeams int
	for _, tr := range rollup.Teams {
		if tr.ReposOutOfPolicy > 0 {
			outOfPolicyTeams++
		}
	}
	trunc := ""
	if sweep.Truncated {
		trunc = " (capped — raise --max-repos to cover every repo)"
	}
	fmt.Fprintf(&b, "- Repositories audited: %d (%d skipped)%s\n", sweep.Audited, sweep.Skipped, trunc)
	fmt.Fprintf(&b, "- Teams: %d (%d own out-of-policy repos)\n\n", len(rollup.Teams), outOfPolicyTeams)

	fmt.Fprintln(&b, "| Team | Repos owned | Audited | Out of policy |")
	fmt.Fprintln(&b, "|------|-------------|---------|---------------|")
	for _, tr := range rollup.Teams {
		fmt.Fprintf(&b, "| %s | %d | %d | %d |\n", mdEscape(tr.Team), tr.ReposOwned, tr.ReposAudited, tr.ReposOutOfPolicy)
	}

	for _, tr := range rollup.Teams {
		if tr.ReposOutOfPolicy == 0 {
			continue
		}
		fmt.Fprintf(&b, "\n**%s** — out of policy:\n", mdEscape(tr.Team))
		for _, rs := range tr.Repos {
			if rs.OutOfPolicy {
				fmt.Fprintf(&b, "- %s (%d hard violation(s))\n", mdEscape(rs.Repository), rs.HardViolations)
			}
		}
	}

	if len(rollup.Unowned) > 0 {
		fmt.Fprintf(&b, "\n**Unowned (no team attribution):**\n")
		for _, rs := range rollup.Unowned {
			status := "in policy"
			if rs.OutOfPolicy {
				status = fmt.Sprintf("%d hard violation(s)", rs.HardViolations)
			}
			fmt.Fprintf(&b, "- %s — %s\n", mdEscape(rs.Repository), status)
		}
	}

	if len(ep.Waivers) > 0 {
		fmt.Fprintf(&b, "\n**Waived (recorded, not enforced):**\n")
		for _, wv := range ep.Waivers {
			title := wv.Title
			if title == "" {
				title = wv.ControlID
			}
			fmt.Fprintf(&b, "- %s — waived by `%s`: %s\n", mdEscape(title), mdEscape(wv.Layer), mdEscape(wv.Reason))
		}
	}
	return b.String()
}

func mdEscape(s string) string { return strings.ReplaceAll(s, "|", "\\|") }
