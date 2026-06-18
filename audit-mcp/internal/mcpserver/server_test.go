// SPDX-License-Identifier: MIT

package mcpserver

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/skaphos/wake-audit-mcp/internal/config"
	"github.com/skaphos/wake-audit-mcp/source/remote"
	"github.com/skaphos/wake-core/audit"
)

// writeRepo materializes a minimal Go service checkout in a temp dir.
func writeRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	files := map[string]string{
		"go.mod":                   "module example.com/svc\n\ngo 1.26\n",
		"main.go":                  "package main\n\nfunc main() {}\n",
		".github/workflows/ci.yml": "on: [push]\njobs:\n  test:\n    steps:\n      - run: go test ./...\n",
	}
	for p, c := range files {
		full := filepath.Join(dir, filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(c), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func findingByID(r audit.RepoReport, id string) (audit.Finding, bool) {
	for _, f := range r.Findings {
		if f.ControlID == id {
			return f, true
		}
	}
	return audit.Finding{}, false
}

func TestAuditRepository_Local(t *testing.T) {
	h := &handler{cfg: config.Config{}}
	res, out, err := h.auditRepository(context.Background(), nil, AuditRepositoryInput{Path: writeRepo(t)})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("unexpected tool error: %v", res.Content)
	}
	if out.RuleSet == "" || len(out.Report.Findings) == 0 {
		t.Fatalf("empty result: %+v", out)
	}
	// The CI workflow with `go test` should satisfy ci-pipeline and unit-tests.
	if f, ok := findingByID(out.Report, "ci-pipeline"); !ok || f.Outcome != audit.OutcomePass {
		t.Errorf("ci-pipeline = %+v, want pass", f)
	}
	if out.Summary.Passing == 0 {
		t.Errorf("summary shows no passing controls: %+v", out.Summary)
	}
	if md := textOf(res); !strings.Contains(md, "Policy audit:") {
		t.Errorf("markdown missing header: %q", md)
	}
}

func TestAuditRepository_TargetValidation(t *testing.T) {
	h := &handler{cfg: config.Config{}}
	cases := map[string]AuditRepositoryInput{
		"no target":    {},
		"both targets": {Path: ".", Owner: "o", Repo: "r"},
		"owner only":   {Owner: "o"},
		"repo only":    {Repo: "r"},
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			res, _, err := h.auditRepository(context.Background(), nil, in)
			if err != nil {
				t.Fatalf("handler returned protocol error: %v", err)
			}
			if !res.IsError {
				t.Errorf("want tool error for %q input, got success", name)
			}
		})
	}
}

func TestAuditRepository_BadRulePack(t *testing.T) {
	h := &handler{cfg: config.Config{}}
	res, _, err := h.auditRepository(context.Background(), nil, AuditRepositoryInput{
		Path:      writeRepo(t),
		RulesYAML: "this: is: not: a: valid: ruleset",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError {
		t.Error("want tool error for malformed rule pack")
	}
}

// fakeAPI implements remote.API in memory for org/remote tests without HTTP.
type fakeAPI struct {
	trees   map[string][]string
	content map[string]map[string]string
	org     []remote.RepoRef
	treeErr map[string]error
}

func (f *fakeAPI) Tree(_ context.Context, r remote.RepoRef) ([]string, bool, error) {
	if e := f.treeErr[r.FullName()]; e != nil {
		return nil, false, e
	}
	return f.trees[r.FullName()], false, nil
}

func (f *fakeAPI) Content(_ context.Context, r remote.RepoRef, p string) ([]byte, error) {
	return []byte(f.content[r.FullName()][p]), nil
}

func (f *fakeAPI) ListOrgRepos(_ context.Context, _ string) ([]remote.RepoRef, error) {
	return f.org, nil
}

func ciTree() ([]string, map[string]string) {
	return []string{"go.mod", "main.go", ".github/workflows/ci.yml"},
		map[string]string{".github/workflows/ci.yml": "steps:\n  - run: go test ./...\n"}
}

func TestAuditOne_Success(t *testing.T) {
	paths, content := ciTree()
	api := &fakeAPI{
		trees:   map[string][]string{"acme/svc": paths},
		content: map[string]map[string]string{"acme/svc": content},
	}
	rep := auditOne(context.Background(), api, remote.RepoRef{Owner: "acme", Name: "svc"}, audit.DefaultRuleSet())
	if rep.Skipped {
		t.Fatalf("unexpected skip: %s", rep.SkipReason)
	}
	if rep.Repository != "acme/svc" {
		t.Errorf("repository = %q, want acme/svc", rep.Repository)
	}
	if f, ok := findingByID(rep, "ci-pipeline"); !ok || f.Outcome != audit.OutcomePass {
		t.Errorf("ci-pipeline = %+v, want pass", f)
	}
}

func TestAuditOne_FetchErrorBecomesSkip(t *testing.T) {
	api := &fakeAPI{treeErr: map[string]error{"acme/down": context.DeadlineExceeded}}
	rep := auditOne(context.Background(), api, remote.RepoRef{Owner: "acme", Name: "down"}, audit.DefaultRuleSet())
	if !rep.Skipped || rep.SkipReason == "" {
		t.Errorf("want skipped report with reason, got %+v", rep)
	}
}

func TestResolveRuleSet(t *testing.T) {
	def, err := resolveRuleSet("")
	if err != nil {
		t.Fatal(err)
	}
	if def.Name != audit.DefaultRuleSet().Name {
		t.Errorf("empty rules_yaml = %q, want default pack", def.Name)
	}

	custom := "name: custom\nversion: \"1\"\ncontrols:\n  - id: has-readme\n    title: README present\n    kind: boolean\n    severity: soft\n    evidence:\n      - path_globs: [\"README.md\"]\n"
	rs, err := resolveRuleSet(custom)
	if err != nil {
		t.Fatalf("custom pack: %v", err)
	}
	if rs.Name != "custom" || len(rs.Controls) != 1 {
		t.Errorf("custom pack = %+v", rs)
	}
}

func TestRenderOrg_Truncated(t *testing.T) {
	reports := []audit.RepoReport{
		{Repository: "acme/a", Classification: audit.Classification{Archetype: audit.ArchetypeService}},
		{Repository: "acme/b", Skipped: true, SkipReason: "unreachable"},
	}
	md := renderOrg("acme", "wake", reports, true)
	if !strings.Contains(md, "acme/a") || !strings.Contains(md, "_skipped_") {
		t.Errorf("org markdown missing rows: %q", md)
	}
	if !strings.Contains(md, "capped") {
		t.Errorf("truncated note missing: %q", md)
	}
}

func TestReadOnlyTools(t *testing.T) {
	got := ReadOnlyTools()
	want := map[string]bool{"audit_repository": true, "audit_org": true}
	if len(got) != len(want) {
		t.Fatalf("ReadOnlyTools = %v", got)
	}
	for _, n := range got {
		if !want[n] {
			t.Errorf("unexpected tool %q", n)
		}
	}
}

// textOf concatenates the text content of a tool result.
func textOf(res *mcp.CallToolResult) string {
	var b strings.Builder
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			b.WriteString(tc.Text)
		}
	}
	return b.String()
}
