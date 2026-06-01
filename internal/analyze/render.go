// SPDX-License-Identifier: MIT

package analyze

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"
)

// Format identifies a supported output renderer.
type Format string

const (
	FormatText     Format = "text"
	FormatMarkdown Format = "markdown"
	FormatJSON     Format = "json"
)

// ValidFormats returns the set of format tokens accepted on the CLI.
func ValidFormats() []Format {
	return []Format{FormatText, FormatMarkdown, FormatJSON}
}

// Render writes the report to w using the selected format.
func Render(w io.Writer, format Format, rep Report) error {
	switch format {
	case FormatJSON:
		return renderJSON(w, rep)
	case FormatMarkdown:
		return renderMarkdown(w, rep)
	case FormatText, "":
		return renderText(w, rep)
	default:
		return fmt.Errorf("unsupported format %q", format)
	}
}

func renderJSON(w io.Writer, rep Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(rep)
}

func renderMarkdown(w io.Writer, rep Report) error {
	var b strings.Builder
	fmt.Fprintf(&b, "# Wake analyze report\n\n")
	if rep.Target.Repository != "" {
		fmt.Fprintf(&b, "- **Repository:** `%s`\n", rep.Target.Repository)
		if len(rep.Target.Subpaths) > 0 {
			fmt.Fprintf(&b, "- **Subpaths:** `%s`\n", strings.Join(rep.Target.Subpaths, "`, `"))
		}
	} else {
		fmt.Fprintf(&b, "- **Repositories:** %d\n", len(rep.Repositories))
	}
	fmt.Fprintf(&b, "- **Commits analyzed:** %d\n", rep.TotalCommits)
	fmt.Fprintf(&b, "- **Classified events:** %d\n", rep.Classified)
	if !rep.WindowStart.IsZero() {
		fmt.Fprintf(&b, "- **Window:** %s → %s\n", formatDate(rep.WindowStart), formatDate(rep.WindowEnd))
	}
	fmt.Fprintf(&b, "- **Generated:** %s\n\n", rep.GeneratedAt.Format(time.RFC3339))

	if len(rep.Repositories) > 1 {
		fmt.Fprintf(&b, "## Repositories\n\n")
		fmt.Fprintf(&b, "| Repository | Commits | Events |\n|---|---:|---:|\n")
		for _, r := range rep.Repositories {
			fmt.Fprintf(&b, "| `%s` | %d | %d |\n", r.Repository, r.Commits, r.Events)
		}
		fmt.Fprintln(&b)
	}

	fmt.Fprintf(&b, "## Events by kind\n\n")
	if len(rep.EventsByKind) == 0 {
		fmt.Fprintf(&b, "_No commits matched the generic classifier._\n\n")
	} else {
		fmt.Fprintf(&b, "| Kind | Count |\n|---|---:|\n")
		for _, k := range rep.EventsByKind {
			fmt.Fprintf(&b, "| %s | %d |\n", k.Kind, k.Count)
		}
		fmt.Fprintln(&b)
	}

	fmt.Fprintf(&b, "## Contributors\n\n")
	if len(rep.Contributors) == 0 {
		fmt.Fprintf(&b, "_No contributors recorded._\n\n")
	} else {
		fmt.Fprintf(&b, "| Contributor | Commits | Events | Breakdown |\n|---|---:|---:|---|\n")
		for _, c := range rep.Contributors {
			id := c.Name
			if c.Email != "" {
				id = fmt.Sprintf("%s <%s>", c.Name, c.Email)
			}
			fmt.Fprintf(&b, "| %s | %d | %d | %s |\n", id, c.TotalCommits, c.TotalEvents, breakdownString(c.ByKind))
		}
		fmt.Fprintln(&b)
	}

	if len(rep.SampleEvents) > 0 {
		fmt.Fprintf(&b, "## Sample events\n\n")
		for _, ev := range rep.SampleEvents {
			sha := ""
			path := ""
			if len(ev.Sources) > 0 {
				sha = shortSHA(ev.Sources[0].CommitSHA)
				if len(ev.Sources[0].Paths) > 0 {
					path = ev.Sources[0].Paths[0]
					if len(ev.Sources[0].Paths) > 1 {
						path = fmt.Sprintf("%s (+%d more)", path, len(ev.Sources[0].Paths)-1)
					}
				}
			}
			fmt.Fprintf(&b, "- `%s` **%s** — %s  \n  `%s` · %s\n", sha, ev.Kind, ev.Summary, ev.ID, path)
		}
		fmt.Fprintln(&b)
	}

	_, err := io.WriteString(w, b.String())
	return err
}

func renderText(w io.Writer, rep Report) error {
	var b strings.Builder
	fmt.Fprintln(&b, "Wake analyze report")
	fmt.Fprintln(&b, strings.Repeat("=", 19))
	if rep.Target.Repository != "" {
		fmt.Fprintf(&b, "Repository:        %s\n", rep.Target.Repository)
		if len(rep.Target.Subpaths) > 0 {
			fmt.Fprintf(&b, "Subpaths:          %s\n", strings.Join(rep.Target.Subpaths, ", "))
		}
	} else {
		fmt.Fprintf(&b, "Repositories:      %d\n", len(rep.Repositories))
	}
	fmt.Fprintf(&b, "Commits analyzed:  %d\n", rep.TotalCommits)
	fmt.Fprintf(&b, "Classified events: %d\n", rep.Classified)
	if !rep.WindowStart.IsZero() {
		fmt.Fprintf(&b, "Window:            %s → %s\n", formatDate(rep.WindowStart), formatDate(rep.WindowEnd))
	}
	fmt.Fprintf(&b, "Generated:         %s\n", rep.GeneratedAt.Format(time.RFC3339))

	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "Events by kind")
	fmt.Fprintln(&b, strings.Repeat("-", 14))
	if len(rep.EventsByKind) == 0 {
		fmt.Fprintln(&b, "  (no commits matched the generic classifier)")
	} else {
		for _, k := range rep.EventsByKind {
			fmt.Fprintf(&b, "  %-28s %d\n", k.Kind, k.Count)
		}
	}

	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "Contributors (by events, then commits)")
	fmt.Fprintln(&b, strings.Repeat("-", 38))
	if len(rep.Contributors) == 0 {
		fmt.Fprintln(&b, "  (no contributors)")
	} else {
		for _, c := range rep.Contributors {
			id := c.Name
			if c.Email != "" {
				id = fmt.Sprintf("%s <%s>", c.Name, c.Email)
			}
			fmt.Fprintf(&b, "  %s\n", id)
			fmt.Fprintf(&b, "    commits=%d events=%d  %s\n", c.TotalCommits, c.TotalEvents, breakdownString(c.ByKind))
		}
	}

	_, err := io.WriteString(w, b.String())
	return err
}

func breakdownString(kc []KindCount) string {
	if len(kc) == 0 {
		return "-"
	}
	parts := make([]string, 0, len(kc))
	for _, c := range kc {
		parts = append(parts, fmt.Sprintf("%s=%d", c.Kind, c.Count))
	}
	return strings.Join(parts, ", ")
}

func shortSHA(sha string) string {
	if len(sha) > 7 {
		return sha[:7]
	}
	return sha
}

func formatDate(t time.Time) string {
	return t.UTC().Format("2006-01-02")
}
