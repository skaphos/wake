// SPDX-License-Identifier: MIT

package auditcmd

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeRepo lays out a temp repository tree and returns its path.
func writeRepo(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for rel, content := range files {
		full := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func writeFile(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "layer.yaml")
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// a Go service with CI and tests: passes the hard base controls, leaving the
// soft controls (quality-gate, deployment-intent) as the interesting surface.
func goServiceFiles() map[string]string {
	return map[string]string{
		"go.mod":                   "module x\n",
		"main.go":                  "package main\nfunc main() {}\n",
		"svc_test.go":              "package main\n",
		".github/workflows/ci.yml": "steps:\n  - run: go test ./...\n",
	}
}

func TestAudit_TeamLayerRelaxRecordsWaiver(t *testing.T) {
	repo := writeRepo(t, goServiceFiles())
	teamLayer := writeFile(t, `
name: team:payments
edits:
  - verb: relax
    id: deployment-intent
    reason: batch job, no deploy target
`)
	var out, errw bytes.Buffer
	err := Run(context.Background(), []string{"--team-layer", teamLayer, repo}, &out, &errw)
	if err != nil {
		t.Fatalf("Run: %v (stderr=%s)", err, errw.String())
	}
	s := out.String()
	if !strings.Contains(s, "Waived") || !strings.Contains(s, "team:payments") {
		t.Errorf("expected recorded waiver with provenance, got:\n%s", s)
	}
	if !strings.Contains(s, "Policy layers:") {
		t.Errorf("expected policy layers line, got:\n%s", s)
	}
	// The relaxed control must not also appear as a regular finding row.
	if strings.Contains(s, "| Deployment intent |") {
		t.Errorf("relaxed control should not appear as a finding row:\n%s", s)
	}
}

func TestAudit_OrgPromotionMakesSoftControlAHardViolation(t *testing.T) {
	repo := writeRepo(t, goServiceFiles()) // no sonar config → quality-gate fails
	orgLayer := writeFile(t, `
name: org:acme
edits:
  - verb: strengthen
    id: quality-gate
    promote_to_hard: true
`)
	var out, errw bytes.Buffer
	err := Run(context.Background(), []string{"--format", "text", "--org-layer", orgLayer, repo}, &out, &errw)
	if err != nil {
		t.Fatalf("Run: %v (stderr=%s)", err, errw.String())
	}
	s := out.String()
	// Promoted quality-gate now fails hard → at least one hard violation.
	if strings.Contains(s, "hard-violations=0") {
		t.Errorf("expected a hard violation after promotion, got:\n%s", s)
	}
}

func TestAudit_RelaxHardControlIsRejected(t *testing.T) {
	repo := writeRepo(t, goServiceFiles())
	teamLayer := writeFile(t, `
name: team
edits:
  - verb: relax
    id: ci-pipeline
    reason: we do not use CI
`)
	var out, errw bytes.Buffer
	err := Run(context.Background(), []string{"--team-layer", teamLayer, repo}, &out, &errw)
	if err == nil || !strings.Contains(err.Error(), "cannot relax hard control") {
		t.Fatalf("err = %v, want hard-relax rejection", err)
	}
}
