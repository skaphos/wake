// SPDX-License-Identifier: MIT

// Package auditcmd implements `wake audit`: evaluate a repository's policy
// adherence against a rule pack and render the findings.
//
// This is the single-repository (opt-in) path. Org-wide and remote modes
// (the default subject per DECISIONS/0004) are added on top of the same
// engine in a later change.
package auditcmd

import (
	"context"
	"flag"
	"fmt"
	"io"

	"github.com/skaphos/wake-audit-mcp/source/local"
	"github.com/skaphos/wake-cli/internal/policyfile"
	"github.com/skaphos/wake-core/audit"
)

// Run dispatches `wake audit`.
func Run(ctx context.Context, args []string, out, errw io.Writer) error {
	fs := flag.NewFlagSet("audit", flag.ContinueOnError)
	fs.SetOutput(errw)

	var format, rulesPath, orgLayerPath, teamLayerPath string
	fs.StringVar(&format, "format", "markdown", "output format: text | markdown | json")
	fs.StringVar(&rulesPath, "rules", "", "custom rule pack (YAML); default: the built-in wake pack")
	fs.StringVar(&orgLayerPath, "org-layer", "", "organizational policy layer (YAML) applied over the base pack")
	fs.StringVar(&teamLayerPath, "team-layer", "", "team policy layer (YAML) applied over the org layer; relax is permitted on soft controls only")
	fs.Usage = func() {
		fmt.Fprintln(errw, "Usage:")
		fmt.Fprintln(errw, "  wake audit [flags] <repository-path>   audit a local checkout against the policy pack")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	pos := fs.Args()
	if len(pos) != 1 {
		fs.Usage()
		return fmt.Errorf("audit requires exactly one repository path argument")
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

	tree, err := local.New(pos[0])
	if err != nil {
		return fmt.Errorf("open repository: %w", err)
	}
	report := audit.EvaluatePolicy(tree, audit.Classify(tree), ep)
	return render(out, format, report, ep.RuleSet.Name)
}
