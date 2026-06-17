// SPDX-License-Identifier: MIT

package app

import (
	"context"
	"fmt"
	"time"

	"github.com/skaphos/wake-cli/internal/workspace"
	"github.com/skaphos/wake-forensics-mcp/source"
	"github.com/skaphos/wake-forensics-mcp/source/local"
	remotesource "github.com/skaphos/wake-forensics-mcp/source/remote"
	"github.com/skaphos/wake-forensics-mcp/source/remote/commitclient"
	rconfig "github.com/skaphos/wake-forensics-mcp/source/remote/config"
	"github.com/skaphos/wake-forensics-mcp/source/remote/configload"
	"github.com/skaphos/wake-forensics-mcp/target"
)

// remoteFlags holds the remote-analysis inputs parsed from the CLI. set
// records which flags the user explicitly passed, so config-file values are
// only overridden by flags that were actually provided.
type remoteFlags struct {
	provider   string
	author     string
	org        string
	repos      []string
	scope      string
	window     string
	since      string
	until      string
	stats      bool
	files      bool
	diffs      bool
	baseURL    string
	perPage    int
	maxCommits int
	configPath string
	set        map[string]bool
}

// buildRemoteSource resolves configuration (defaults < config file < env <
// flags) and turns it into a single evidence source backed by the GitHub or
// GitLab client. Tokens resolve as WAKE_GITHUB_TOKEN -> GITHUB_TOKEN ->
// GH_TOKEN -> config file -> OAuth credential store (`wake auth`); the store
// fallback is applied inside commitclient.
func buildRemoteSource(rf remoteFlags, now time.Time) (source.Source, error) {
	cfg, err := configload.Load(rf.configPath)
	if err != nil {
		return nil, err
	}

	// Flags override the resolved config, but only when explicitly set.
	if rf.set["base-url"] {
		cfg.BaseURL = rf.baseURL
		cfg.GitLabBaseURL = rf.baseURL
	}
	if rf.set["per-page"] {
		cfg.PerPage = rf.perPage
	}
	if rf.set["max-commits"] {
		cfg.MaxCommits = rf.maxCommits
	}
	// Depth flags are additive: --stats/--files/--diffs turn the depth on; the
	// config file may also enable them.
	cfg.IncludeStats = cfg.IncludeStats || rf.stats
	cfg.IncludeFiles = cfg.IncludeFiles || rf.files
	cfg.IncludeDiffs = cfg.IncludeDiffs || rf.diffs

	req := rconfigRequest(rf)
	query, err := cfg.Resolve(req, now)
	if err != nil {
		return nil, fmt.Errorf("resolve remote query: %w", err)
	}

	client, err := commitclient.New(cfg, query.Provider)
	if err != nil {
		return nil, err
	}
	return remotesource.NewSource(query.Provider, client, query), nil
}

// rconfigRequest builds the per-invocation query request from the CLI flags.
// Empty fields fall back to the resolved config defaults during Resolve.
func rconfigRequest(rf remoteFlags) rconfig.Request {
	return rconfig.Request{
		Provider: rf.provider,
		Author:   rf.author,
		Org:      rf.org,
		Repos:    rf.repos,
		Scope:    rf.scope,
		Window:   rf.window,
		Since:    rf.since,
		Until:    rf.until,
	}
}

// buildWorkspaceSources enumerates workspace repositories via the RepoKeeper
// MCP server and returns one local Git source per checked-out repository,
// honoring the shared revision window. This powers the "follow a teammate"
// model: a developer scans every repo a colleague touches without naming each
// one or hitting a remote API.
func buildWorkspaceSources(ctx context.Context, enum workspace.Enumerator, q workspace.Query, revFrom, revTo string) ([]source.Source, error) {
	repos, err := enum.Enumerate(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("enumerate workspace: %w", err)
	}
	if len(repos) == 0 {
		return nil, fmt.Errorf("no workspace repositories matched the selector")
	}

	sources := make([]source.Source, 0, len(repos))
	for _, repo := range repos {
		sources = append(sources, local.New(target.Input{
			Repository:   repo.Path,
			RevisionFrom: revFrom,
			RevisionTo:   revTo,
		}))
	}
	return sources, nil
}
