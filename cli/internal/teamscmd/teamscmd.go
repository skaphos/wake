// SPDX-License-Identifier: MIT

// Package teamscmd implements `wake teams`: audit a GitHub organization and
// roll the results up by owning team — the headline "which teams own repos out
// of policy" view. It builds the team↔repo ownership graph from GitHub team
// assignments (optionally extended by per-repo overrides) and audits every
// eligible repo against the composed policy.
package teamscmd

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/skaphos/wake-audit-mcp/source/remote"
	"github.com/skaphos/wake-cli/internal/policyfile"
	"github.com/skaphos/wake-core/audit"
	"github.com/skaphos/wake-core/ownership"
)

// Run dispatches `wake teams`.
func Run(ctx context.Context, args []string, out, errw io.Writer) error {
	fs := flag.NewFlagSet("teams", flag.ContinueOnError)
	fs.SetOutput(errw)

	var (
		org, format                            string
		rulesPath, orgLayerPath, teamLayerPath string
		overridesPath, baseURL, token          string
		includeArchived, includeForks          bool
		maxRepos                               int
	)
	fs.StringVar(&org, "org", "", "GitHub organization to audit (required)")
	fs.StringVar(&format, "format", "markdown", "output format: markdown | json")
	fs.StringVar(&rulesPath, "rules", "", "custom rule pack (YAML); default: the built-in wake pack")
	fs.StringVar(&orgLayerPath, "org-layer", "", "organizational policy layer (YAML) applied over the base pack")
	fs.StringVar(&teamLayerPath, "team-layer", "", "team policy layer (YAML) applied over the org layer")
	fs.StringVar(&overridesPath, "overrides", "", "ownership overrides (YAML): per-repo team attribution GitHub teams miss")
	fs.BoolVar(&includeArchived, "include-archived", false, "include archived repositories (excluded by default)")
	fs.BoolVar(&includeForks, "include-forks", false, "include forked repositories (excluded by default)")
	fs.IntVar(&maxRepos, "max-repos", 300, "cap repositories audited after filtering (0 = no cap)")
	fs.StringVar(&baseURL, "base-url", "", "GitHub Enterprise API base URL (e.g. https://ghe.example.com/api/v3/)")
	fs.StringVar(&token, "token", "", "GitHub token; default: WAKE_GITHUB_TOKEN, GITHUB_TOKEN, or GH_TOKEN")
	fs.Usage = func() {
		fmt.Fprintln(errw, "Usage:")
		fmt.Fprintln(errw, "  wake teams --org <org> [flags]   audit an org and roll policy results up by owning team")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if org == "" {
		fs.Usage()
		return fmt.Errorf("teams requires --org")
	}
	if maxRepos < 0 {
		return fmt.Errorf("--max-repos must not be negative")
	}

	base := audit.DefaultRuleSet()
	if rulesPath != "" {
		var err error
		if base, err = policyfile.RuleSet(rulesPath); err != nil {
			return err
		}
	}
	layers, err := policyfile.Layers(orgLayerPath, teamLayerPath)
	if err != nil {
		return err
	}
	ep, err := audit.Resolve(base, layers...)
	if err != nil {
		return fmt.Errorf("resolve policy: %w", err)
	}
	overrides, err := policyfile.Overrides(overridesPath)
	if err != nil {
		return err
	}

	api, err := remote.NewGitHub(resolveToken(token), baseURL)
	if err != nil {
		return err
	}

	graph, err := remote.BuildOwnershipGraph(ctx, api, org)
	if err != nil {
		return fmt.Errorf("build ownership graph: %w", err)
	}
	graph.ApplyOverrides(overrides)

	sweep, err := remote.SweepOrg(ctx, api, org, remote.SweepOptions{
		IncludeArchived: includeArchived,
		IncludeForks:    includeForks,
		MaxRepos:        maxRepos,
	}, ep)
	if err != nil {
		return fmt.Errorf("audit org: %w", err)
	}

	rollup := ownership.Rollup(graph, sweep.Reports)
	return render(out, format, org, ep, sweep, rollup)
}

// resolveToken returns the explicit token when set, otherwise the first
// non-empty value from the conventional GitHub token environment variables.
func resolveToken(explicit string) string {
	if explicit != "" {
		return explicit
	}
	for _, env := range []string{"WAKE_GITHUB_TOKEN", "GITHUB_TOKEN", "GH_TOKEN"} {
		if v := os.Getenv(env); v != "" {
			return v
		}
	}
	return ""
}
