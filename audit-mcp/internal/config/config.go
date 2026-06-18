// SPDX-License-Identifier: MIT

// Package config resolves the credentials the audit MCP server needs for
// remote and org-wide scans. Local-path audits need none of it, so a server
// started with no token still serves the local path of every tool.
package config

import "os"

// Config holds the GitHub credentials used for remote (owner/repo) and
// org-wide audits.
type Config struct {
	// GitHubToken authenticates remote calls. Empty is allowed: the GitHub
	// API is reachable unauthenticated for public repos, at a low rate limit.
	GitHubToken string
	// GitHubBaseURL targets a GitHub Enterprise Server API root (e.g.
	// "https://ghe.example.com/api/v3/") when non-empty; empty means
	// github.com.
	GitHubBaseURL string
}

// FromEnv resolves config from the environment, following the same precedence
// as the rest of Wake: WAKE_GITHUB_TOKEN, then GITHUB_TOKEN, then GH_TOKEN for
// the token; WAKE_GITHUB_BASE_URL for an enterprise API root.
func FromEnv() Config {
	return Config{
		GitHubToken:   firstNonEmpty(os.Getenv("WAKE_GITHUB_TOKEN"), os.Getenv("GITHUB_TOKEN"), os.Getenv("GH_TOKEN")),
		GitHubBaseURL: os.Getenv("WAKE_GITHUB_BASE_URL"),
	}
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
