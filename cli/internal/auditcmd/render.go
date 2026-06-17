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
			Report  audit.RepoReport `json:"report"`
			Summary summary          `json:"summary"`
		}{packName, r, summarize(r)})
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
	fmt.Fprintf(&b, "- Classification: **%s** (%s)\n", r.Classification.Archetype, langs(r.Classification.Languages))
	fmt.Fprintf(&b, "- Summary: **%d hard violation(s)**, %d soft recommendation(s), %d passing, %d n/a, %d unknown\n\n",
		s.HardViolations, s.SoftRecos, s.Passing, s.NA, s.Unknown)

	fmt.Fprintln(&b, "| Control | Severity | Result | Confidence | Evidence |")
	fmt.Fprintln(&b, "|---------|----------|--------|------------|----------|")
	for _, f := range r.Findings {
		fmt.Fprintf(&b, "| %s | %s | %s | %s | %s |\n",
			f.Title, f.Severity, result(f), f.Confidence.Band, mdEscape(evidenceCell(f)))
	}

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
	fmt.Fprintf(&b, "  pack=%s  hard-violations=%d soft-recos=%d passing=%d n/a=%d unknown=%d\n\n",
		packName, s.HardViolations, s.SoftRecos, s.Passing, s.NA, s.Unknown)
	for _, f := range r.Findings {
		fmt.Fprintf(&b, "  [%-7s] %-10s %s (%s)\n", result(f), f.Severity, f.Title, f.Confidence.Band)
	}
	_, err := io.WriteString(w, b.String())
	return err
}

func langs(l []string) string {
	if len(l) == 0 {
		return "no languages detected"
	}
	return strings.Join(l, ", ")
}

func mdEscape(s string) string { return strings.ReplaceAll(s, "|", "\\|") }
