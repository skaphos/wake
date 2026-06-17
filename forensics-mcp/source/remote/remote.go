// SPDX-License-Identifier: MIT

// Package remote implements [source.Source] over a remote Git hosting
// platform (GitHub or GitLab). It adapts the commit-collection logic moved
// from the retired sting tool (the ghclient/gitlabclient/model/config
// packages now living under source/remote) and maps the provider result onto
// Wake's evidence contract via the evidencemap package.
package remote

import (
	"context"

	"github.com/skaphos/wake-core/evidence"
	"github.com/skaphos/wake-forensics-mcp/source/evidencemap"
	"github.com/skaphos/wake-forensics-mcp/source/remote/ghclient"
	"github.com/skaphos/wake-forensics-mcp/source/remote/gitlabclient"
	"github.com/skaphos/wake-forensics-mcp/source/remote/model"
)

// Collector is the provider-agnostic commit-collection surface that both the
// GitHub and GitLab clients satisfy.
type Collector interface {
	Collect(ctx context.Context, q model.Query) (model.Result, error)
}

// Source extracts evidence from a remote provider for a single query.
type Source struct {
	provider model.Provider
	client   Collector
	query    model.Query
}

// NewGitHub builds a remote Source backed by the GitHub client. token may be
// empty (unauthenticated, heavily rate limited). baseURL targets a GitHub
// Enterprise API root when set. perPage is clamped to GitHub's 1-100 range.
func NewGitHub(token, baseURL string, perPage int, query model.Query) (Source, error) {
	c, err := ghclient.New(token, baseURL, perPage)
	if err != nil {
		return Source{}, err
	}
	query.Provider = model.ProviderGitHub
	return Source{provider: model.ProviderGitHub, client: c, query: query}, nil
}

// NewGitLab builds a remote Source backed by the GitLab client. token may be
// empty for public data. baseURL targets a GitLab API v4 root when set.
func NewGitLab(token, baseURL string, perPage int, query model.Query) (Source, error) {
	c, err := gitlabclient.New(token, baseURL, perPage)
	if err != nil {
		return Source{}, err
	}
	query.Provider = model.ProviderGitLab
	return Source{provider: model.ProviderGitLab, client: c, query: query}, nil
}

// NewSource wraps an already-built Collector (for example one returned by the
// commitclient package, which resolves credentials from the store) as a
// Source. This lets callers reuse credential-aware client construction instead
// of passing a raw token to NewGitHub/NewGitLab.
func NewSource(provider model.Provider, client Collector, query model.Query) Source {
	query.Provider = provider
	return Source{provider: provider, client: client, query: query}
}

// Kind identifies this source (e.g. "remote:github").
func (s Source) Kind() string { return "remote:" + string(s.provider) }

// Extract collects commits from the provider and maps the result into one
// evidence.Bundle per repository.
func (s Source) Extract(ctx context.Context) ([]evidence.Bundle, error) {
	result, err := s.client.Collect(ctx, s.query)
	if err != nil {
		return nil, err
	}
	return evidencemap.Bundles(result), nil
}
