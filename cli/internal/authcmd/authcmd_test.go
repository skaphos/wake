// SPDX-License-Identifier: MIT

package authcmd

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

// isolateStore points the credential store at a throwaway config dir so the
// test never touches the developer's real credentials or keyring.
func isolateStore(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	t.Setenv("HOME", dir)
	t.Setenv("WAKE_GITHUB_TOKEN", "")
	t.Setenv("GITHUB_TOKEN", "")
	t.Setenv("GH_TOKEN", "")
	t.Setenv("WAKE_GITLAB_TOKEN", "")
	t.Setenv("GITLAB_TOKEN", "")
}

func run(t *testing.T, stdin string, args ...string) string {
	t.Helper()
	var out bytes.Buffer
	if err := Run(context.Background(), args, strings.NewReader(stdin), &out, &out); err != nil {
		t.Fatalf("Run(%v): %v\noutput:\n%s", args, err, out.String())
	}
	return out.String()
}

func TestWithTokenStatusLogoutRoundTrip(t *testing.T) {
	isolateStore(t)

	// Store a PAT via stdin (insecure file storage for determinism).
	out := run(t, "glpat-dummy\n", "gitlab", "--with-token", "--insecure-storage")
	if !strings.Contains(out, "Token saved") {
		t.Fatalf("login output missing confirmation:\n%s", out)
	}

	// Status reflects the stored GitLab credential.
	out = run(t, "", "status")
	if !strings.Contains(out, "Logged into gitlab.com") {
		t.Fatalf("status did not show gitlab login:\n%s", out)
	}

	// Logout removes it.
	run(t, "", "logout", "gitlab")
	out = run(t, "", "status")
	if strings.Contains(out, "Logged into gitlab.com") {
		t.Fatalf("status still shows gitlab after logout:\n%s", out)
	}
}

func TestStatusShowsEnvFallback(t *testing.T) {
	isolateStore(t)
	t.Setenv("WAKE_GITHUB_TOKEN", "ghp_dummy")

	out := run(t, "", "status")
	if !strings.Contains(out, "Legacy token available") {
		t.Fatalf("status did not report env PAT fallback:\n%s", out)
	}
}

func TestUnknownSubcommand(t *testing.T) {
	var out bytes.Buffer
	err := Run(context.Background(), []string{"bogus"}, strings.NewReader(""), &out, &out)
	if err == nil {
		t.Fatal("expected error for unknown subcommand")
	}
}

func TestEmptyWithTokenStdinErrors(t *testing.T) {
	isolateStore(t)
	var out bytes.Buffer
	err := Run(context.Background(), []string{"gitlab", "--with-token", "--insecure-storage"}, strings.NewReader("\n  \n"), &out, &out)
	if err == nil {
		t.Fatal("expected error when no token is provided on stdin")
	}
}
