// SPDX-License-Identifier: MIT

package workspace

import "testing"

// realFixture is a verbatim select_repositories payload captured from the live
// RepoKeeper MCP server, so the parser is tested against the real contract.
const realFixture = `{"repositories":[` +
	`{"repo_id":"github.com/skaphos/wake","path":"/home/sstratton/work/skaphos/wake","match_reason":"name:wake"},` +
	`{"repo_id":"github.com/skaphos/wake-cli","path":"/home/sstratton/work/skaphos/wake-cli","match_reason":"name:wake"}` +
	`]}`

func TestParseSelectResultRealShape(t *testing.T) {
	t.Parallel()
	repos, err := parseSelectResult([]byte(realFixture))
	if err != nil {
		t.Fatalf("parseSelectResult: %v", err)
	}
	if len(repos) != 2 {
		t.Fatalf("got %d repos, want 2", len(repos))
	}
	if repos[0].RepoID != "github.com/skaphos/wake" {
		t.Errorf("repo[0].RepoID = %q", repos[0].RepoID)
	}
	if repos[1].Path != "/home/sstratton/work/skaphos/wake-cli" {
		t.Errorf("repo[1].Path = %q", repos[1].Path)
	}
}

func TestParseSelectResultEmpty(t *testing.T) {
	t.Parallel()
	repos, err := parseSelectResult([]byte(`{"repositories":[]}`))
	if err != nil {
		t.Fatalf("parseSelectResult: %v", err)
	}
	if len(repos) != 0 {
		t.Errorf("got %d repos, want 0", len(repos))
	}
}

func TestParseSelectResultBadJSON(t *testing.T) {
	t.Parallel()
	if _, err := parseSelectResult([]byte(`not json`)); err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}
