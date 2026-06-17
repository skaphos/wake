// SPDX-License-Identifier: MIT

package auth

import (
	"context"
	"errors"
	"testing"

	"github.com/skaphos/wake-forensics-mcp/source/remote/model"
)

func TestStaticTokenPerProvider(t *testing.T) {
	t.Parallel()
	s := StaticToken{GitHub: "gh-tok", GitLab: "gl-tok"}
	cases := map[model.Provider]string{
		model.ProviderGitHub:    "gh-tok",
		model.ProviderGitLab:    "gl-tok",
		model.Provider("other"): "",
	}
	for provider, want := range cases {
		got, err := s.Token(context.Background(), provider)
		if err != nil {
			t.Fatalf("Token(%q): %v", provider, err)
		}
		if got != want {
			t.Errorf("Token(%q) = %q, want %q", provider, got, want)
		}
	}
}

func TestFromEnvPrefersWakeVars(t *testing.T) {
	// Not parallel: mutates process environment.
	t.Setenv("WAKE_GITHUB_TOKEN", "wake-gh")
	t.Setenv("GITHUB_TOKEN", "plain-gh")
	t.Setenv("GITLAB_TOKEN", "plain-gl")

	s := FromEnv()
	if s.GitHub != "wake-gh" {
		t.Errorf("GitHub = %q, want wake-gh (WAKE_ var wins)", s.GitHub)
	}
	if s.GitLab != "plain-gl" {
		t.Errorf("GitLab = %q, want plain-gl (fallback)", s.GitLab)
	}
}

func TestFromEnvFallbackChain(t *testing.T) {
	t.Setenv("WAKE_GITHUB_TOKEN", "")
	t.Setenv("GITHUB_TOKEN", "")
	t.Setenv("GH_TOKEN", "gh-token-var")

	if s := FromEnv(); s.GitHub != "gh-token-var" {
		t.Errorf("GitHub = %q, want gh-token-var", s.GitHub)
	}
}

func TestGitHubAppNotImplemented(t *testing.T) {
	t.Parallel()
	_, err := GitHubApp{AppID: 1}.Token(context.Background(), model.ProviderGitHub)
	if !errors.Is(err, ErrNotImplemented) {
		t.Errorf("err = %v, want ErrNotImplemented", err)
	}
}
