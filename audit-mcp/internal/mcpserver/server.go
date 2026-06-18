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
)

// defaultMaxRepos bounds an org sweep when the caller does not specify a cap,
// keeping the tool output and API volume bounded for large orgs.
const defaultMaxRepos = 300

// AuditRepositoryInput is the argument schema for the audit_repository tool.
// Exactly one target must be given: a local Path, or an Owner+Repo pair for a
// remote GitHub audit.
type AuditRepositoryInput struct {
	Path      string `json:"path,omitempty" jsonschema:"local repository checkout path to audit; mutually exclusive with owner/repo"`
	Owner     string `json:"owner,omitempty" jsonschema:"GitHub owner or org for a remote audit; requires repo"`
	Repo      string `json:"repo,omitempty" jsonschema:"GitHub repository name for a remote audit; requires owner"`
	RulesYAML string `json:"rules_yaml,omitempty" jsonschema:"optional custom rule pack as YAML; defaults to the built-in wake pack"`
}

// RepoResult is the structured output of audit_repository.
type RepoResult struct {
	RuleSet string           `json:"rule_set"`
	Report  audit.RepoReport `json:"report"`
	Summary Summary          `json:"summary"`
}

// AuditOrgInput is the argument schema for the audit_org tool.
type AuditOrgInput struct {
	Org             string `json:"org" jsonschema:"GitHub organization (or user) whose repositories to audit"`
	IncludeArchived bool   `json:"include_archived,omitempty" jsonschema:"include archived repositories (excluded by default)"`
	IncludeForks    bool   `json:"include_forks,omitempty" jsonschema:"include forked repositories (excluded by default)"`
	MaxRepos        int    `json:"max_repos,omitempty" jsonschema:"cap the number of repositories audited after filtering; 0 uses the server default (300)"`
	RulesYAML       string `json:"rules_yaml,omitempty" jsonschema:"optional custom rule pack as YAML; defaults to the built-in wake pack"`
}

// OrgResult is the structured output of audit_org.
type OrgResult struct {
	Org          string             `json:"org"`
	RuleSet      string             `json:"rule_set"`
	ReposAudited int                `json:"repos_audited"`
	Truncated    bool               `json:"truncated"`
	Summary      Summary            `json:"summary"`
	Repositories []audit.RepoReport `json:"repositories"`
}

// handler holds the dependencies shared across tool calls.
type handler struct {
	cfg config.Config
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

	return server, nil
}

// ReadOnlyTools lists the names of tools whose ReadOnlyHint is true. It is the
// single source of truth for which tools an installer may safely auto-approve,
// so the install permissions snippet cannot drift from what the server marks
// read-only. Every tool audit-mcp exposes is read-only by design.
func ReadOnlyTools() []string {
	return []string{"audit_repository", "audit_org"}
}

func boolPtr(b bool) *bool { return &b }

func (h *handler) auditRepository(ctx context.Context, _ *mcp.CallToolRequest, in AuditRepositoryInput) (*mcp.CallToolResult, RepoResult, error) {
	rs, err := resolveRuleSet(in.RulesYAML)
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
		api, err = remote.NewGitHub(h.cfg.GitHubToken, h.cfg.GitHubBaseURL)
		if err == nil {
			tree, err = remote.NewTree(ctx, api, remote.RepoRef{Owner: in.Owner, Name: in.Repo})
		}
	}
	if err != nil {
		return errorResult(err), RepoResult{}, nil
	}

	report := audit.Evaluate(tree, audit.Classify(tree), rs)
	out := RepoResult{RuleSet: rs.Name, Report: report, Summary: summarize(report)}
	return textResult(renderRepo(report, rs.Name)), out, nil
}

func (h *handler) auditOrg(ctx context.Context, _ *mcp.CallToolRequest, in AuditOrgInput) (*mcp.CallToolResult, OrgResult, error) {
	if in.Org == "" {
		return errorResult(fmt.Errorf("org is required")), OrgResult{}, nil
	}
	rs, err := resolveRuleSet(in.RulesYAML)
	if err != nil {
		return errorResult(err), OrgResult{}, nil
	}

	api, err := remote.NewGitHub(h.cfg.GitHubToken, h.cfg.GitHubBaseURL)
	if err != nil {
		return errorResult(err), OrgResult{}, nil
	}
	repos, err := api.ListOrgRepos(ctx, in.Org)
	if err != nil {
		return errorResult(err), OrgResult{}, nil
	}

	eligible := remote.EligibleRepos(repos, in.IncludeArchived, in.IncludeForks)
	max := in.MaxRepos
	if max <= 0 {
		max = defaultMaxRepos
	}
	truncated := false
	if len(eligible) > max {
		eligible = eligible[:max]
		truncated = true
	}

	reports := make([]audit.RepoReport, 0, len(eligible))
	var total Summary
	for _, ref := range eligible {
		report := auditOne(ctx, api, ref, rs)
		total = total.add(summarize(report))
		reports = append(reports, report)
	}

	out := OrgResult{
		Org:          in.Org,
		RuleSet:      rs.Name,
		ReposAudited: len(reports),
		Truncated:    truncated,
		Summary:      total,
		Repositories: reports,
	}
	return textResult(renderOrg(in.Org, rs.Name, reports, truncated)), out, nil
}

// auditOne audits a single remote repo, converting a fetch failure into a
// skipped report so one unreachable repo does not abort the whole org sweep.
func auditOne(ctx context.Context, api remote.API, ref remote.RepoRef, rs audit.RuleSet) audit.RepoReport {
	tree, err := remote.NewTree(ctx, api, ref)
	if err != nil {
		return audit.RepoReport{Repository: ref.FullName(), Skipped: true, SkipReason: err.Error()}
	}
	return audit.Evaluate(tree, audit.Classify(tree), rs)
}

// resolveRuleSet returns the custom pack parsed from rulesYAML, or the
// built-in default pack when rulesYAML is empty.
func resolveRuleSet(rulesYAML string) (audit.RuleSet, error) {
	if strings.TrimSpace(rulesYAML) == "" {
		return audit.DefaultRuleSet(), nil
	}
	return audit.LoadRuleSet(strings.NewReader(rulesYAML))
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
