// SPDX-License-Identifier: MIT

// Package mcpserver exposes Wake's repository policy-audit engine as MCP tools
// over a stdio transport, so an LLM agent can audit a single repository (local
// checkout or remote GitHub repo) or sweep an entire GitHub org against a rule
// pack and receive evidence-backed, confidence-scored findings.
package mcpserver

import (
	"context"
	"fmt"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/skaphos/wake-audit-mcp/internal/config"
	"github.com/skaphos/wake-audit-mcp/source/local"
	"github.com/skaphos/wake-audit-mcp/source/remote"
	"github.com/skaphos/wake-core/audit"
	"github.com/skaphos/wake-core/ownership"
)

// defaultMaxRepos bounds an org sweep when the caller does not specify a cap,
// keeping the tool output and API volume bounded for large orgs.
const defaultMaxRepos = 300

// AuditRepositoryInput is the argument schema for the audit_repository tool.
// Exactly one target must be given: a local Path, or an Owner+Repo pair for a
// remote GitHub audit.
type AuditRepositoryInput struct {
	Path          string `json:"path,omitempty" jsonschema:"local repository checkout path to audit; mutually exclusive with owner/repo"`
	Owner         string `json:"owner,omitempty" jsonschema:"GitHub owner or org for a remote audit; requires repo"`
	Repo          string `json:"repo,omitempty" jsonschema:"GitHub repository name for a remote audit; requires owner"`
	RulesYAML     string `json:"rules_yaml,omitempty" jsonschema:"optional custom rule pack as YAML; defaults to the built-in wake pack"`
	OrgLayerYAML  string `json:"org_layer_yaml,omitempty" jsonschema:"optional organizational policy layer (add/strengthen/relax edits) applied over the base pack"`
	TeamLayerYAML string `json:"team_layer_yaml,omitempty" jsonschema:"optional team policy layer applied over the org layer; relax is permitted on soft controls only"`
}

// RepoResult is the structured output of audit_repository.
type RepoResult struct {
	RuleSet string           `json:"rule_set"`
	Layers  []string         `json:"layers,omitempty"`
	Waivers []audit.Waiver   `json:"waivers,omitempty"`
	Report  audit.RepoReport `json:"report"`
	Summary Summary          `json:"summary"`
}

// AuditOrgInput is the argument schema for the audit_org tool.
type AuditOrgInput struct {
	Org             string `json:"org" jsonschema:"GitHub organization (or user) whose repositories to audit"`
	IncludeArchived bool   `json:"include_archived,omitempty" jsonschema:"include archived repositories (excluded by default)"`
	IncludeForks    bool   `json:"include_forks,omitempty" jsonschema:"include forked repositories (excluded by default)"`
	MaxRepos        int    `json:"max_repos,omitempty" jsonschema:"cap the number of repositories audited after filtering; 0 uses the server default (300); a negative value is rejected"`
	RulesYAML       string `json:"rules_yaml,omitempty" jsonschema:"optional custom rule pack as YAML; defaults to the built-in wake pack"`
	OrgLayerYAML    string `json:"org_layer_yaml,omitempty" jsonschema:"optional organizational policy layer (add/strengthen/relax edits) applied over the base pack"`
	TeamLayerYAML   string `json:"team_layer_yaml,omitempty" jsonschema:"optional team policy layer applied over the org layer; relax is permitted on soft controls only"`
}

// OrgResult is the structured output of audit_org. ReposAudited counts the
// repositories that were actually evaluated; ReposSkipped counts those that
// were enumerated but could not be fetched (their reports carry Skipped).
type OrgResult struct {
	Org          string             `json:"org"`
	RuleSet      string             `json:"rule_set"`
	ReposAudited int                `json:"repos_audited"`
	ReposSkipped int                `json:"repos_skipped"`
	Truncated    bool               `json:"truncated"`
	Layers       []string           `json:"layers,omitempty"`
	Waivers      []audit.Waiver     `json:"waivers,omitempty"`
	Summary      Summary            `json:"summary"`
	Repositories []audit.RepoReport `json:"repositories"`
}

// AuditTeamsInput is the argument schema for the audit_teams tool. It audits an
// org like audit_org, then rolls the results up by owning team.
type AuditTeamsInput struct {
	Org             string `json:"org" jsonschema:"GitHub organization whose teams and repositories to audit"`
	IncludeArchived bool   `json:"include_archived,omitempty" jsonschema:"include archived repositories (excluded by default)"`
	IncludeForks    bool   `json:"include_forks,omitempty" jsonschema:"include forked repositories (excluded by default)"`
	MaxRepos        int    `json:"max_repos,omitempty" jsonschema:"cap the number of repositories audited after filtering; 0 uses the server default (300); a negative value is rejected"`
	RulesYAML       string `json:"rules_yaml,omitempty" jsonschema:"optional custom rule pack as YAML; defaults to the built-in wake pack"`
	OrgLayerYAML    string `json:"org_layer_yaml,omitempty" jsonschema:"optional organizational policy layer applied over the base pack"`
	TeamLayerYAML   string `json:"team_layer_yaml,omitempty" jsonschema:"optional team policy layer applied over the org layer"`
	OverridesYAML   string `json:"overrides_yaml,omitempty" jsonschema:"optional ownership overrides (per-repo team attribution GitHub teams miss); extends or replaces host-derived ownership"`
}

// TeamsResult is the structured output of audit_teams: the policy sweep tallies
// plus the per-team rollup keyed on which teams own out-of-policy repositories.
type TeamsResult struct {
	Org          string           `json:"org"`
	RuleSet      string           `json:"rule_set"`
	Layers       []string         `json:"layers,omitempty"`
	Waivers      []audit.Waiver   `json:"waivers,omitempty"`
	ReposAudited int              `json:"repos_audited"`
	ReposSkipped int              `json:"repos_skipped"`
	Truncated    bool             `json:"truncated"`
	Summary      Summary          `json:"summary"`
	Rollup       ownership.Report `json:"rollup"`
}

// handler holds the dependencies shared across tool calls.
type handler struct {
	cfg config.Config
	// newAPI constructs the remote host API; it is a seam so tests can inject a
	// fake. When nil it defaults to remote.NewGitHub.
	newAPI func(token, baseURL string) (remote.API, error)
}

// makeAPI builds the remote API from the handler's config, using the injected
// constructor when set and the real GitHub client otherwise.
func (h *handler) makeAPI() (remote.API, error) {
	newAPI := h.newAPI
	if newAPI == nil {
		newAPI = remote.NewGitHub
	}
	return newAPI(h.cfg.GitHubToken, h.cfg.GitHubBaseURL)
}

// New builds an MCP server exposing the audit tools, configured from cfg.
func New(cfg config.Config) (*mcp.Server, error) {
	h := &handler{cfg: cfg}

	server := mcp.NewServer(&mcp.Implementation{
		Name:    "wake-audit-mcp",
		Version: "0.1.0",
	}, nil)

	mcp.AddTool(server, &mcp.Tool{
		Name: "audit_repository",
		Description: "Audit one repository's policy adherence against a rule pack. " +
			"Target either a local checkout (path) or a remote GitHub repo (owner+repo). " +
			"Returns evidence-backed, confidence-scored findings plus a Markdown summary.",
		Annotations: &mcp.ToolAnnotations{
			ReadOnlyHint:  true,
			OpenWorldHint: boolPtr(true), // reaches GitHub for remote targets
		},
	}, h.auditRepository)

	mcp.AddTool(server, &mcp.Tool{
		Name: "audit_org",
		Description: "Audit every eligible repository in a GitHub organization against a rule pack " +
			"(archived and forked repos are excluded by default). Returns a per-repository report " +
			"array, an org rollup, and a Markdown summary table.",
		Annotations: &mcp.ToolAnnotations{
			ReadOnlyHint:  true,
			OpenWorldHint: boolPtr(true),
		},
	}, h.auditOrg)

	mcp.AddTool(server, &mcp.Tool{
		Name: "audit_teams",
		Description: "Audit a GitHub organization and roll the results up by owning team. " +
			"Builds the team↔repo ownership graph from GitHub team assignments (optionally " +
			"extended by per-repo overrides) and reports which teams own repositories that are " +
			"out of policy, plus any audited repos no team owns.",
		Annotations: &mcp.ToolAnnotations{
			ReadOnlyHint:  true,
			OpenWorldHint: boolPtr(true),
		},
	}, h.auditTeams)

	return server, nil
}

// ReadOnlyTools lists the names of tools whose ReadOnlyHint is true. It is the
// single source of truth for which tools an installer may safely auto-approve,
// so the install permissions snippet cannot drift from what the server marks
// read-only. Every tool audit-mcp exposes is read-only by design.
func ReadOnlyTools() []string {
	return []string{"audit_repository", "audit_org", "audit_teams"}
}

func boolPtr(b bool) *bool { return &b }

func (h *handler) auditRepository(ctx context.Context, _ *mcp.CallToolRequest, in AuditRepositoryInput) (*mcp.CallToolResult, RepoResult, error) {
	ep, err := resolveEffectivePolicy(in.RulesYAML, in.OrgLayerYAML, in.TeamLayerYAML)
	if err != nil {
		return errorResult(err), RepoResult{}, nil
	}

	hasLocal := in.Path != ""
	hasRemote := in.Owner != "" || in.Repo != ""
	switch {
	case hasLocal && hasRemote:
		return errorResult(fmt.Errorf("specify either path or owner/repo, not both")), RepoResult{}, nil
	case !hasLocal && !hasRemote:
		return errorResult(fmt.Errorf("a target is required: set path, or owner and repo")), RepoResult{}, nil
	case hasRemote && (in.Owner == "" || in.Repo == ""):
		return errorResult(fmt.Errorf("a remote audit needs both owner and repo")), RepoResult{}, nil
	}

	var tree audit.FileTree
	if hasLocal {
		tree, err = local.New(in.Path)
	} else {
		var api remote.API
		api, err = h.makeAPI()
		if err == nil {
			tree, err = remote.NewTree(ctx, api, remote.RepoRef{Owner: in.Owner, Name: in.Repo})
		}
	}
	if err != nil {
		return errorResult(err), RepoResult{}, nil
	}

	report := audit.EvaluatePolicy(tree, audit.Classify(tree), ep)
	out := RepoResult{
		RuleSet: ep.RuleSet.Name,
		Layers:  ep.Layers,
		Waivers: ep.Waivers,
		Report:  report,
		Summary: summarize(report),
	}
	return textResult(renderRepo(report, ep.RuleSet.Name)), out, nil
}

func (h *handler) auditOrg(ctx context.Context, _ *mcp.CallToolRequest, in AuditOrgInput) (*mcp.CallToolResult, OrgResult, error) {
	if in.Org == "" {
		return errorResult(fmt.Errorf("org is required")), OrgResult{}, nil
	}
	if in.MaxRepos < 0 {
		return errorResult(fmt.Errorf("max_repos must not be negative")), OrgResult{}, nil
	}
	max := in.MaxRepos
	if max == 0 {
		max = defaultMaxRepos
	}
	ep, err := resolveEffectivePolicy(in.RulesYAML, in.OrgLayerYAML, in.TeamLayerYAML)
	if err != nil {
		return errorResult(err), OrgResult{}, nil
	}

	api, err := h.makeAPI()
	if err != nil {
		return errorResult(err), OrgResult{}, nil
	}
	sweep, err := remote.SweepOrg(ctx, api, in.Org, remote.SweepOptions{
		IncludeArchived: in.IncludeArchived,
		IncludeForks:    in.IncludeForks,
		MaxRepos:        max,
	}, ep)
	if err != nil {
		return errorResult(err), OrgResult{}, nil
	}

	var total Summary
	for _, r := range sweep.Reports {
		if !r.Skipped {
			total = total.add(summarize(r))
		}
	}

	out := OrgResult{
		Org:          in.Org,
		RuleSet:      ep.RuleSet.Name,
		ReposAudited: sweep.Audited,
		ReposSkipped: sweep.Skipped,
		Truncated:    sweep.Truncated,
		Layers:       ep.Layers,
		Waivers:      ep.Waivers,
		Summary:      total,
		Repositories: sweep.Reports,
	}
	return textResult(renderOrg(in.Org, ep.RuleSet.Name, sweep.Reports, sweep.Truncated, ep.Waivers)), out, nil
}

func (h *handler) auditTeams(ctx context.Context, _ *mcp.CallToolRequest, in AuditTeamsInput) (*mcp.CallToolResult, TeamsResult, error) {
	if in.Org == "" {
		return errorResult(fmt.Errorf("org is required")), TeamsResult{}, nil
	}
	if in.MaxRepos < 0 {
		return errorResult(fmt.Errorf("max_repos must not be negative")), TeamsResult{}, nil
	}
	max := in.MaxRepos
	if max == 0 {
		max = defaultMaxRepos
	}
	ep, err := resolveEffectivePolicy(in.RulesYAML, in.OrgLayerYAML, in.TeamLayerYAML)
	if err != nil {
		return errorResult(err), TeamsResult{}, nil
	}
	overrides, err := resolveOverrides(in.OverridesYAML)
	if err != nil {
		return errorResult(err), TeamsResult{}, nil
	}

	api, err := h.makeAPI()
	if err != nil {
		return errorResult(err), TeamsResult{}, nil
	}

	graph, err := remote.BuildOwnershipGraph(ctx, api, in.Org)
	if err != nil {
		return errorResult(err), TeamsResult{}, nil
	}
	graph.ApplyOverrides(overrides)

	sweep, err := remote.SweepOrg(ctx, api, in.Org, remote.SweepOptions{
		IncludeArchived: in.IncludeArchived,
		IncludeForks:    in.IncludeForks,
		MaxRepos:        max,
	}, ep)
	if err != nil {
		return errorResult(err), TeamsResult{}, nil
	}

	var total Summary
	for _, r := range sweep.Reports {
		if !r.Skipped {
			total = total.add(summarize(r))
		}
	}
	rollup := ownership.Rollup(graph, sweep.Reports)

	out := TeamsResult{
		Org:          in.Org,
		RuleSet:      ep.RuleSet.Name,
		Layers:       ep.Layers,
		Waivers:      ep.Waivers,
		ReposAudited: sweep.Audited,
		ReposSkipped: sweep.Skipped,
		Truncated:    sweep.Truncated,
		Summary:      total,
		Rollup:       rollup,
	}
	return textResult(renderTeams(in.Org, ep.RuleSet.Name, rollup, sweep.Truncated, ep.Layers, ep.Waivers)), out, nil
}

// resolveOverrides parses the optional ownership-override YAML, returning no
// overrides when the input is empty.
func resolveOverrides(overridesYAML string) ([]ownership.Override, error) {
	if strings.TrimSpace(overridesYAML) == "" {
		return nil, nil
	}
	cfg, err := ownership.LoadOverrides(strings.NewReader(overridesYAML))
	if err != nil {
		return nil, err
	}
	return cfg.Overrides, nil
}

// auditOne audits a single remote repo against the effective policy. It is a
// thin alias over remote.AuditRepo retained for the server's unit tests.
func auditOne(ctx context.Context, api remote.API, ref remote.RepoRef, ep audit.EffectivePolicy) audit.RepoReport {
	return remote.AuditRepo(ctx, api, ref, ep)
}

// resolveRuleSet returns the custom pack parsed from rulesYAML, or the
// built-in default pack when rulesYAML is empty.
func resolveRuleSet(rulesYAML string) (audit.RuleSet, error) {
	if strings.TrimSpace(rulesYAML) == "" {
		return audit.DefaultRuleSet(), nil
	}
	return audit.LoadRuleSet(strings.NewReader(rulesYAML))
}

// resolveEffectivePolicy composes the base rule pack (from rulesYAML or the
// built-in default) with the optional organizational and team policy layers,
// applied in that order, into an EffectivePolicy ready for EvaluatePolicy.
func resolveEffectivePolicy(rulesYAML, orgLayerYAML, teamLayerYAML string) (audit.EffectivePolicy, error) {
	base, err := resolveRuleSet(rulesYAML)
	if err != nil {
		return audit.EffectivePolicy{}, err
	}
	var layers []audit.Layer
	if strings.TrimSpace(orgLayerYAML) != "" {
		l, err := audit.LoadLayer(strings.NewReader(orgLayerYAML))
		if err != nil {
			return audit.EffectivePolicy{}, fmt.Errorf("org layer: %w", err)
		}
		layers = append(layers, l)
	}
	if strings.TrimSpace(teamLayerYAML) != "" {
		l, err := audit.LoadLayer(strings.NewReader(teamLayerYAML))
		if err != nil {
			return audit.EffectivePolicy{}, fmt.Errorf("team layer: %w", err)
		}
		layers = append(layers, l)
	}
	return audit.Resolve(base, layers...)
}

func textResult(md string) *mcp.CallToolResult {
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: md}}}
}

// errorResult reports a tool-level error back to the agent as text so it can
// self-correct, rather than surfacing a protocol error.
func errorResult(err error) *mcp.CallToolResult {
	return &mcp.CallToolResult{
		IsError: true,
		Content: []mcp.Content{&mcp.TextContent{Text: err.Error()}},
	}
}
