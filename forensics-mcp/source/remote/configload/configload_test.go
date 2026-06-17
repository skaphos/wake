// SPDX-License-Identifier: MIT

package configload

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/skaphos/wake-forensics-mcp/source/remote/model"
)

// isolate points the loader at a throwaway config home and clears token env.
func isolate(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	t.Setenv("HOME", dir)
	for _, k := range []string{"WAKE_GITHUB_TOKEN", "GITHUB_TOKEN", "GH_TOKEN", "WAKE_GITLAB_TOKEN", "GITLAB_TOKEN", "WAKE_GITHUB_BASE_URL", "WAKE_GITLAB_BASE_URL"} {
		t.Setenv(k, "")
	}
	return dir
}

func writeConfig(t *testing.T, xdg, body string) {
	t.Helper()
	dir := filepath.Join(xdg, "wake")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(body), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
}

func TestLoadDefaultsWhenNoFile(t *testing.T) {
	isolate(t)
	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.DefaultProvider != model.ProviderGitHub || cfg.PerPage != 100 {
		t.Errorf("unexpected defaults: %+v", cfg)
	}
}

func TestLoadFileOverlaysDefaults(t *testing.T) {
	xdg := isolate(t)
	writeConfig(t, xdg, "default_window: 14d\ndefault_scope: org\nper_page: 50\ntoken: file-gh-token\ninclude_diffs: true\n")

	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.DefaultWindow != "14d" {
		t.Errorf("DefaultWindow = %q, want 14d", cfg.DefaultWindow)
	}
	if cfg.DefaultScope != model.ScopeOrg {
		t.Errorf("DefaultScope = %q, want org", cfg.DefaultScope)
	}
	if cfg.PerPage != 50 {
		t.Errorf("PerPage = %d, want 50", cfg.PerPage)
	}
	if cfg.Token != "file-gh-token" {
		t.Errorf("Token = %q, want file-gh-token", cfg.Token)
	}
	if !cfg.IncludeDiffs {
		t.Error("IncludeDiffs should be true from file")
	}
}

func TestEnvTokenBeatsFileWithFallThrough(t *testing.T) {
	xdg := isolate(t)
	writeConfig(t, xdg, "token: file-gh-token\n")

	// GITHUB_TOKEN set but WAKE_GITHUB_TOKEN empty -> GITHUB_TOKEN wins over file.
	t.Setenv("GITHUB_TOKEN", "env-gh-token")
	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Token != "env-gh-token" {
		t.Errorf("Token = %q, want env-gh-token (env beats file)", cfg.Token)
	}

	// WAKE_GITHUB_TOKEN takes precedence over GITHUB_TOKEN.
	t.Setenv("WAKE_GITHUB_TOKEN", "wake-gh-token")
	cfg, _ = Load("")
	if cfg.Token != "wake-gh-token" {
		t.Errorf("Token = %q, want wake-gh-token (WAKE_ beats GITHUB_TOKEN)", cfg.Token)
	}
}

func TestExplicitPathMustExist(t *testing.T) {
	isolate(t)
	if _, err := Load("/no/such/config.yaml"); err == nil {
		t.Fatal("expected error for missing explicit config path")
	}
}

func TestInvalidConfigRejected(t *testing.T) {
	xdg := isolate(t)
	writeConfig(t, xdg, "per_page: 999\n") // out of 1-100 range
	if _, err := Load(""); err == nil {
		t.Fatal("expected validation error for per_page out of range")
	}
}
