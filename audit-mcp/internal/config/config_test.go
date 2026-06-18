// SPDX-License-Identifier: MIT

package config

import "testing"

func TestFromEnv_TokenPrecedence(t *testing.T) {
	for _, k := range []string{"WAKE_GITHUB_TOKEN", "GITHUB_TOKEN", "GH_TOKEN", "WAKE_GITHUB_BASE_URL"} {
		t.Setenv(k, "")
	}

	// GH_TOKEN is the lowest-precedence source.
	t.Setenv("GH_TOKEN", "gh")
	if got := FromEnv().GitHubToken; got != "gh" {
		t.Errorf("token = %q, want gh", got)
	}

	// GITHUB_TOKEN beats GH_TOKEN.
	t.Setenv("GITHUB_TOKEN", "github")
	if got := FromEnv().GitHubToken; got != "github" {
		t.Errorf("token = %q, want github", got)
	}

	// WAKE_GITHUB_TOKEN beats all.
	t.Setenv("WAKE_GITHUB_TOKEN", "wake")
	if got := FromEnv().GitHubToken; got != "wake" {
		t.Errorf("token = %q, want wake", got)
	}

	t.Setenv("WAKE_GITHUB_BASE_URL", "https://ghe.example.com/api/v3/")
	if got := FromEnv().GitHubBaseURL; got != "https://ghe.example.com/api/v3/" {
		t.Errorf("base url = %q", got)
	}
}

func TestFromEnv_Empty(t *testing.T) {
	for _, k := range []string{"WAKE_GITHUB_TOKEN", "GITHUB_TOKEN", "GH_TOKEN", "WAKE_GITHUB_BASE_URL"} {
		t.Setenv(k, "")
	}
	cfg := FromEnv()
	if cfg.GitHubToken != "" || cfg.GitHubBaseURL != "" {
		t.Errorf("want empty config, got %+v", cfg)
	}
}
