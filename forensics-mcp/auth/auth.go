// SPDX-License-Identifier: MIT

// Package auth defines how Wake forensics obtains credentials for remote
// providers. It is deliberately a thin seam: today the only implementation is
// a static token (a PAT or pre-issued token sourced from the environment or
// config), which serves the local "follow a teammate" CLI model.
//
// The TokenProvider interface exists so that the future organization-wide
// service model — a long-running, GitHub-App-authenticated deployment that
// mints short-lived per-installation tokens for org-wide reach — can be added
// without changing the remote source or its callers. That server is out of
// scope for now (see the Wake decision record on the source abstraction); the
// seam is here so adopting it later is additive, not a rewrite.
package auth

import (
	"context"
	"errors"
	"os"

	"github.com/skaphos/wake-forensics-mcp/source/remote/model"
)

// TokenProvider yields a credential for a provider at call time. Returning an
// empty string is allowed and means "unauthenticated" (public data only,
// heavily rate limited).
type TokenProvider interface {
	Token(ctx context.Context, provider model.Provider) (string, error)
}

// StaticToken is a TokenProvider that always returns the same per-provider
// token. It is the default for the CLI model.
type StaticToken struct {
	GitHub string
	GitLab string
}

// Token returns the configured token for the provider.
func (s StaticToken) Token(_ context.Context, provider model.Provider) (string, error) {
	switch provider {
	case model.ProviderGitHub:
		return s.GitHub, nil
	case model.ProviderGitLab:
		return s.GitLab, nil
	default:
		return "", nil
	}
}

// FromEnv builds a StaticToken from environment variables, preferring Wake's
// own variables and falling back to the conventional provider variables so a
// machine already set up for gh/glab works without extra configuration:
//
//	GitHub: WAKE_GITHUB_TOKEN, then GITHUB_TOKEN, then GH_TOKEN
//	GitLab: WAKE_GITLAB_TOKEN, then GITLAB_TOKEN
func FromEnv() StaticToken {
	return StaticToken{
		GitHub: firstNonEmpty(os.Getenv("WAKE_GITHUB_TOKEN"), os.Getenv("GITHUB_TOKEN"), os.Getenv("GH_TOKEN")),
		GitLab: firstNonEmpty(os.Getenv("WAKE_GITLAB_TOKEN"), os.Getenv("GITLAB_TOKEN")),
	}
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

// ErrNotImplemented marks an auth mode that is reserved but not yet built.
var ErrNotImplemented = errors.New("auth: not implemented")

// GitHubApp is the reserved seam for GitHub App installation authentication
// used by the future organization-wide service model. It mints short-lived
// installation tokens for org-wide reach without per-user PATs.
//
// It is intentionally unimplemented: the type and method exist so the org
// server can be wired in later without changing the remote source. Do not
// build the server on top of this until the corresponding decision record
// supersedes wake/DECISIONS/0001 (the current "no API servers" constraint).
type GitHubApp struct {
	AppID          int64
	InstallationID int64
	PrivateKeyPEM  []byte
}

// Token is not yet implemented; see the type doc.
func (GitHubApp) Token(context.Context, model.Provider) (string, error) {
	return "", ErrNotImplemented
}
