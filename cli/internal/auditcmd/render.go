// SPDX-License-Identifier: MIT

package auditcmd

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/skaphos/wake-core/audit"
)

// summary aggregates a repo report into compliance counts.
type summary struct {
	HardViolations int // hard controls that failed
	SoftRecos      int // soft controls that failed
	Passing        int // applicable controls that passed
	NA             int // not-applicable controls
	Unknown        int
}

func summarize(r audit.RepoReport) summary {
	var s summary
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

func render(w io.Writer, format string, r audit.RepoReport, packName string) error {
	switch format {
	case "json":
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(struct {
			RuleSet string           `json:"rule_set"`
			Layers  []string         `json:"layers,omitempty"`
			Waivers []audit.Waiver   `json:"waivers,omitempty"`
			Report  audit.RepoReport `json:"report"`
			Summary summary          `json:"summary"`
		}{packName, r.Layers, r.Waivers, r, summarize(r)})
	case "text":
		return renderText(w, r, packName)
	default:
		return renderMarkdown(w, r, packName)
	}
}

// result renders the human-facing outcome cell for a finding.
func result(f audit.Finding) string {
	if f.Kind == audit.KindCategorical {
		if f.Category != "" {
			return f.Category
		}
		return string(f.Outcome)
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

func renderMarkdown(w io.Writer, r audit.RepoReport, packName string) error {
	s := summarize(r)
	var b strings.Builder
	fmt.Fprintf(&b, "# Policy audit: %s\n\n", r.Repository)
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
			f.Title, f.Severity, result(f), f.Confidence.Band, mdEscape(evidenceCell(f)))
	}

	b.WriteString(renderWaivers(r.Waivers))

	fmt.Fprint(&b, "\n")
	for _, f := range r.Findings {
		if f.Outcome == audit.OutcomeFail && f.Remediation != "" {
			fmt.Fprintf(&b, "- **%s** (%s): %s\n", f.Title, f.Severity, f.Remediation)
		}
	}
	_, err := io.WriteString(w, b.String())
	return err
}

func renderText(w io.Writer, r audit.RepoReport, packName string) error {
	s := summarize(r)
	var b strings.Builder
	fmt.Fprintf(&b, "Policy audit: %s  [%s]\n", r.Repository, r.Classification.Archetype)
	fmt.Fprintf(&b, "  pack=%s  hard-violations=%d soft-recos=%d passing=%d n/a=%d unknown=%d\n",
		packName, s.HardViolations, s.SoftRecos, s.Passing, s.NA, s.Unknown)
	if len(r.Layers) > 1 {
		fmt.Fprintf(&b, "  layers=%s\n", strings.Join(r.Layers, " ⊕ "))
	}
	fmt.Fprintln(&b)
	for _, f := range r.Findings {
		fmt.Fprintf(&b, "  [%-7s] %-10s %s (%s)\n", result(f), f.Severity, f.Title, f.Confidence.Band)
	}
	for _, wv := range r.Waivers {
		title := wv.Title
		if title == "" {
			title = wv.ControlID
		}
		fmt.Fprintf(&b, "  [waived ] %-10s %s (by %s: %s)\n", "soft", title, wv.Layer, wv.Reason)
	}
	_, err := io.WriteString(w, b.String())
	return err
}

// renderWaivers renders recorded waivers (soft controls disabled by a policy
// layer) with their provenance, so a relaxed control stays visible rather than
// silently dropping out of the findings table.
func renderWaivers(waivers []audit.Waiver) string {
	if len(waivers) == 0 {
		return ""
	}
	var b strings.Builder
	fmt.Fprintf(&b, "\n**Waived (recorded, not enforced):**\n")
	for _, wv := range waivers {
		title := wv.Title
		if title == "" {
			title = wv.ControlID
		}
		reason := wv.Reason
		if reason == "" {
			reason = "no reason given"
		}
		fmt.Fprintf(&b, "- %s — waived by `%s`: %s\n", mdEscape(title), mdEscape(wv.Layer), mdEscape(reason))
	}
	return b.String()
}

func langs(l []string) string {
	if len(l) == 0 {
		return "no languages detected"
	}
	return strings.Join(l, ", ")
}

func mdEscape(s string) string { return strings.ReplaceAll(s, "|", "\\|") }
