// SPDX-License-Identifier: MIT

package mcpserver

import (
	"fmt"
	"strings"

	"github.com/skaphos/wake-core/audit"
	"github.com/skaphos/wake-core/ownership"
)

// Summary aggregates a repo report into compliance counts. It is part of the
// structured tool output so the calling agent gets the headline numbers
// without re-deriving them from the findings.
type Summary struct {
	HardViolations int `json:"hard_violations"` // hard controls that failed
	SoftRecos      int `json:"soft_recommendations"`
	Passing        int `json:"passing"`
	NA             int `json:"na"`
	Unknown        int `json:"unknown"`
}

func (s Summary) add(o Summary) Summary {
	return Summary{
		HardViolations: s.HardViolations + o.HardViolations,
		SoftRecos:      s.SoftRecos + o.SoftRecos,
		Passing:        s.Passing + o.Passing,
		NA:             s.NA + o.NA,
		Unknown:        s.Unknown + o.Unknown,
	}
}

func summarize(r audit.RepoReport) Summary {
	var s Summary
	for _, f := range r.Findings {
		switch f.Outcome {
		case audit.OutcomePass:
			s.Passing++
		case audit.OutcomeNA:
			s.NA++
		case audit.OutcomeUnknown:
			s.Unknown++
		case audit.OutcomeFail:
			if f.Severity == audit.Hard {
				s.HardViolations++
			} else {
				s.SoftRecos++
			}
		}
	}
	return s
}

// resultCell renders the human-facing outcome cell for a finding.
func resultCell(f audit.Finding) string {
	if f.Kind == audit.KindCategorical && f.Category != "" {
		return f.Category
	}
	return string(f.Outcome)
}

func evidenceCell(f audit.Finding) string {
	switch {
	case len(f.Evidence) == 0:
		return "—"
	case len(f.Evidence) == 1:
		return f.Evidence[0]
	default:
		return fmt.Sprintf("%s (+%d)", f.Evidence[0], len(f.Evidence)-1)
	}
}

func langs(l []string) string {
	if len(l) == 0 {
		return "no languages detected"
	}
	return strings.Join(l, ", ")
}

func mdEscape(s string) string { return strings.ReplaceAll(s, "|", "\\|") }

// renderRepo renders a single repository's findings as Markdown.
func renderRepo(r audit.RepoReport, packName string) string {
	s := summarize(r)
	var b strings.Builder
	fmt.Fprintf(&b, "# Policy audit: %s\n\n", r.Repository)
	if r.Skipped {
		fmt.Fprintf(&b, "_Skipped: %s_\n", r.SkipReason)
		return b.String()
	}
	fmt.Fprintf(&b, "- Rule pack: `%s`\n", packName)
	if len(r.Layers) > 1 {
		fmt.Fprintf(&b, "- Policy layers: %s\n", strings.Join(r.Layers, " ⊕ "))
	}
	fmt.Fprintf(&b, "- Classification: **%s** (%s)\n", r.Classification.Archetype, langs(r.Classification.Languages))
	fmt.Fprintf(&b, "- Summary: **%d hard violation(s)**, %d soft recommendation(s), %d passing, %d n/a, %d unknown\n\n",
		s.HardViolations, s.SoftRecos, s.Passing, s.NA, s.Unknown)

	fmt.Fprintln(&b, "| Control | Severity | Result | Confidence | Evidence |")
	fmt.Fprintln(&b, "|---------|----------|--------|------------|----------|")
	for _, f := range r.Findings {
		fmt.Fprintf(&b, "| %s | %s | %s | %s | %s |\n",
			f.Title, f.Severity, resultCell(f), f.Confidence.Band, mdEscape(evidenceCell(f)))
	}

	b.WriteString(renderWaivers(r.Waivers))

	fmt.Fprint(&b, "\n")
	for _, f := range r.Findings {
		if f.Outcome == audit.OutcomeFail && f.Remediation != "" {
			fmt.Fprintf(&b, "- **%s** (%s): %s\n", f.Title, f.Severity, f.Remediation)
		}
	}
	return b.String()
}

// renderWaivers renders the recorded waivers (soft controls disabled by a
// policy layer) so a relaxed control is visible with its provenance rather
// than silently absent from the findings table.
func renderWaivers(waivers []audit.Waiver) string {
	if len(waivers) == 0 {
		return ""
	}
	var b strings.Builder
	fmt.Fprintf(&b, "\n**Waived (recorded, not enforced):**\n")
	for _, w := range waivers {
		title := w.Title
		if title == "" {
			title = w.ControlID
		}
		reason := w.Reason
		if reason == "" {
			reason = "no reason given"
		}
		fmt.Fprintf(&b, "- %s — waived by `%s`: %s\n", mdEscape(title), mdEscape(w.Layer), mdEscape(reason))
	}
	return b.String()
}

// renderOrg renders an org-wide rollup: one row per repository with its
// headline counts, followed by an aggregate line. truncated reports that the
// scan was capped before every eligible repo was audited.
func renderOrg(org, packName string, reports []audit.RepoReport, truncated bool, waivers []audit.Waiver) string {
	// Build the rows first so the header can report accurate audited/skipped
	// counts (reports includes skipped entries, which must not inflate the
	// "audited" total).
	var total Summary
	var audited, skipped int
	var rows strings.Builder
	for _, r := range reports {
		if r.Skipped {
			skipped++
			fmt.Fprintf(&rows, "| %s | _skipped_ | — | — | — | — | — |\n", mdEscape(r.Repository))
			continue
		}
		audited++
		s := summarize(r)
		total = total.add(s)
		fmt.Fprintf(&rows, "| %s | %s | %d | %d | %d | %d | %d |\n",
			mdEscape(r.Repository), r.Classification.Archetype,
			s.HardViolations, s.SoftRecos, s.Passing, s.NA, s.Unknown)
	}

	var b strings.Builder
	fmt.Fprintf(&b, "# Org policy audit: %s\n\n", org)
	fmt.Fprintf(&b, "- Rule pack: `%s`\n", packName)
	if layers := orgLayers(reports); len(layers) > 1 {
		fmt.Fprintf(&b, "- Policy layers: %s\n", strings.Join(layers, " ⊕ "))
	}
	fmt.Fprintf(&b, "- Repositories audited: %d%s%s\n\n", audited, skippedNote(skipped), truncatedNote(truncated))

	fmt.Fprintln(&b, "| Repository | Archetype | Hard | Soft | Pass | N/A | Unknown |")
	fmt.Fprintln(&b, "|------------|-----------|------|------|------|-----|---------|")
	b.WriteString(rows.String())
	fmt.Fprintf(&b, "\n**Org totals:** %d hard violation(s), %d soft recommendation(s), %d passing across %d repositories.\n",
		total.HardViolations, total.SoftRecos, total.Passing, audited)
	b.WriteString(renderWaivers(waivers))
	return b.String()
}

// orgLayers returns the resolved policy-layer names from the first audited
// report (every repo in a sweep runs the same effective policy, so the layer
// stack is uniform). It returns nil when no layering was applied.
func orgLayers(reports []audit.RepoReport) []string {
	for _, r := range reports {
		if !r.Skipped && len(r.Layers) > 0 {
			return r.Layers
		}
	}
	return nil
}

// renderTeams renders the per-team policy rollup: a table of teams ordered by
// how many owned repos are out of policy (the headline cut), the offending
// repos per team, and any audited repos no team owns.
func renderTeams(org, packName string, rep ownership.Report, truncated bool, layers []string, waivers []audit.Waiver) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Team policy rollup: %s\n\n", org)
	fmt.Fprintf(&b, "- Rule pack: `%s`\n", packName)
	if len(layers) > 1 {
		fmt.Fprintf(&b, "- Policy layers: %s\n", strings.Join(layers, " ⊕ "))
	}
	var outOfPolicyTeams int
	for _, tr := range rep.Teams {
		if tr.ReposOutOfPolicy > 0 {
			outOfPolicyTeams++
		}
	}
	fmt.Fprintf(&b, "- Teams: %d (%d own out-of-policy repos)%s\n\n", len(rep.Teams), outOfPolicyTeams, truncatedNote(truncated))

	fmt.Fprintln(&b, "| Team | Repos owned | Audited | Out of policy |")
	fmt.Fprintln(&b, "|------|-------------|---------|---------------|")
	for _, tr := range rep.Teams {
		fmt.Fprintf(&b, "| %s | %d | %d | %d |\n", mdEscape(tr.Team), tr.ReposOwned, tr.ReposAudited, tr.ReposOutOfPolicy)
	}

	for _, tr := range rep.Teams {
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

	if len(rep.Unowned) > 0 {
		fmt.Fprintf(&b, "\n**Unowned (no team attribution):**\n")
		for _, rs := range rep.Unowned {
			status := "in policy"
			if rs.OutOfPolicy {
				status = fmt.Sprintf("%d hard violation(s)", rs.HardViolations)
			}
			fmt.Fprintf(&b, "- %s — %s\n", mdEscape(rs.Repository), status)
		}
	}

	b.WriteString(renderWaivers(waivers))
	return b.String()
}

func skippedNote(skipped int) string {
	if skipped > 0 {
		return fmt.Sprintf(" (%d skipped — unreachable)", skipped)
	}
	return ""
}

func truncatedNote(truncated bool) string {
	if truncated {
		return " (capped — more eligible repositories were not audited; raise max_repos to cover them)"
	}
	return ""
}
