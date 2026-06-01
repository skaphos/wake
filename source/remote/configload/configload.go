// SPDX-License-Identifier: MIT

// Package configload resolves the remote-query configuration for Wake from a
// config file and the environment, keeping the config package itself
// dependency-light. Resolution precedence is:
//
//	defaults  <  config file  <  environment
//
// (CLI flags, when present, are layered on top by the caller.)
//
// Config files are named config.yaml and searched, most specific first, in:
//
//	$XDG_CONFIG_HOME/wake/   (or ~/.config/wake/)
//	~/.wake/
//	.                        (current directory)
//
// Tokens follow an explicit fall-through so a machine already set up for the
// provider CLIs works without extra configuration:
//
//	GitHub: WAKE_GITHUB_TOKEN  ->  GITHUB_TOKEN  ->  GH_TOKEN  ->  config file
//	GitLab: WAKE_GITLAB_TOKEN  ->  GITLAB_TOKEN  ->  config file
//
// When no token resolves here, the commitclient package applies its final
// fallback: the OAuth credential store populated by `wake auth`.
package configload

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"

	"github.com/skaphos/wake-forensics-mcp/source/remote/config"
	"github.com/skaphos/wake-forensics-mcp/source/remote/model"
)

// fileConfig is the on-disk YAML shape. Pointers distinguish "absent" from a
// zero value so a config file only overrides the keys it actually sets.
type fileConfig struct {
	Provider      string   `yaml:"provider"`
	Token         string   `yaml:"token"`
	BaseURL       string   `yaml:"base_url"`
	GitLabToken   string   `yaml:"gitlab_token"`
	GitLabBaseURL string   `yaml:"gitlab_base_url"`
	DefaultScope  string   `yaml:"default_scope"`
	DefaultWindow string   `yaml:"default_window"`
	DefaultRepos  []string `yaml:"default_repos"`
	DefaultOrg    string   `yaml:"default_org"`
	DefaultFormat string   `yaml:"default_format"`
	PerPage       *int     `yaml:"per_page"`
	MaxCommits    *int     `yaml:"max_commits"`
	IncludeStats  *bool    `yaml:"include_stats"`
	IncludeFiles  *bool    `yaml:"include_files"`
	IncludeDiffs  *bool    `yaml:"include_diffs"`
	MaxDiffBytes  *int     `yaml:"max_diff_bytes"`
}

// Load builds a config.Config from defaults, then the config file (explicit
// path when non-empty, otherwise the first found in the search path), then the
// environment. The returned config is validated.
func Load(explicitPath string) (config.Config, error) {
	cfg := config.Default()

	path, err := resolvePath(explicitPath)
	if err != nil {
		return config.Config{}, err
	}
	if path != "" {
		if err := applyFile(&cfg, path); err != nil {
			return config.Config{}, err
		}
	}

	applyEnv(&cfg)

	if err := cfg.Validate(); err != nil {
		return config.Config{}, err
	}
	return cfg, nil
}

// resolvePath returns the config file to read. An explicit path must exist; an
// empty explicit path triggers a search that returns "" when nothing is found
// (which is fine — defaults + env still apply).
func resolvePath(explicitPath string) (string, error) {
	if explicitPath != "" {
		if _, err := os.Stat(explicitPath); err != nil {
			return "", fmt.Errorf("config file %q: %w", explicitPath, err)
		}
		return explicitPath, nil
	}
	for _, dir := range searchDirs() {
		candidate := filepath.Join(dir, "config.yaml")
		if _, err := os.Stat(candidate); err == nil {
			return candidate, nil
		}
	}
	return "", nil
}

// searchDirs returns the directories searched for config.yaml, most specific
// first. All paths use the "wake" name (never "sting").
func searchDirs() []string {
	var dirs []string
	if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" {
		dirs = append(dirs, filepath.Join(xdg, "wake"))
	}
	if home, err := os.UserHomeDir(); err == nil {
		dirs = append(dirs,
			filepath.Join(home, ".config", "wake"),
			filepath.Join(home, ".wake"),
		)
	}
	return append(dirs, ".")
}

func applyFile(cfg *config.Config, path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read config file %q: %w", path, err)
	}
	var fc fileConfig
	if err := yaml.Unmarshal(data, &fc); err != nil {
		return fmt.Errorf("parse config file %q: %w", path, err)
	}

	overlayString(&cfg.Token, fc.Token)
	overlayString(&cfg.BaseURL, fc.BaseURL)
	overlayString(&cfg.GitLabToken, fc.GitLabToken)
	overlayString(&cfg.GitLabBaseURL, fc.GitLabBaseURL)
	overlayString(&cfg.DefaultWindow, fc.DefaultWindow)
	overlayString(&cfg.DefaultFormat, fc.DefaultFormat)
	overlayString(&cfg.DefaultOrg, fc.DefaultOrg)
	if fc.Provider != "" {
		cfg.DefaultProvider = providerOf(fc.Provider)
	}
	if fc.DefaultScope != "" {
		cfg.DefaultScope = scopeOf(fc.DefaultScope)
	}
	if len(fc.DefaultRepos) > 0 {
		cfg.DefaultRepos = fc.DefaultRepos
	}
	if fc.PerPage != nil {
		cfg.PerPage = *fc.PerPage
	}
	if fc.MaxCommits != nil {
		cfg.MaxCommits = *fc.MaxCommits
	}
	if fc.IncludeStats != nil {
		cfg.IncludeStats = *fc.IncludeStats
	}
	if fc.IncludeFiles != nil {
		cfg.IncludeFiles = *fc.IncludeFiles
	}
	if fc.IncludeDiffs != nil {
		cfg.IncludeDiffs = *fc.IncludeDiffs
	}
	if fc.MaxDiffBytes != nil {
		cfg.MaxDiffBytes = *fc.MaxDiffBytes
	}
	return nil
}

// applyEnv layers environment overrides on top of file/defaults. Only tokens
// and base URLs are environment-driven; query defaults live in the file.
func applyEnv(cfg *config.Config) {
	if tok := firstNonEmpty(os.Getenv("WAKE_GITHUB_TOKEN"), os.Getenv("GITHUB_TOKEN"), os.Getenv("GH_TOKEN")); tok != "" {
		cfg.Token = tok
	}
	if tok := firstNonEmpty(os.Getenv("WAKE_GITLAB_TOKEN"), os.Getenv("GITLAB_TOKEN")); tok != "" {
		cfg.GitLabToken = tok
	}
	if u := os.Getenv("WAKE_GITHUB_BASE_URL"); u != "" {
		cfg.BaseURL = u
	}
	if u := os.Getenv("WAKE_GITLAB_BASE_URL"); u != "" {
		cfg.GitLabBaseURL = u
	}
}

func overlayString(dst *string, v string) {
	if v != "" {
		*dst = v
	}
}

func providerOf(s string) model.Provider { return model.Provider(s) }

func scopeOf(s string) model.Scope { return model.Scope(s) }

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
