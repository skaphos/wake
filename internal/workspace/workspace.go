// SPDX-License-Identifier: MIT

// Package workspace enumerates the repositories on the operator's machine so
// the "follow a teammate" model can fan out local Git forensics across a
// whole workspace rather than crawling a remote API.
//
// Per Wake DECISIONS/0002, Wake couples to the RepoKeeper MCP server (which is
// already in use on the machine for managing those checkouts) rather than
// importing RepoKeeper as a library. This package therefore defines a small
// Enumerator seam with a RepoKeeper MCP-client implementation; the result
// parsing is isolated and tested against RepoKeeper's real tool output.
package workspace

import (
	"context"
	"encoding/json"
	"fmt"
)

// Repo is a workspace repository: its stable identity and local checkout path.
type Repo struct {
	RepoID string `json:"repo_id"`
	Path   string `json:"path"`
}

// Query selects which workspace repositories to enumerate. The fields map
// directly onto RepoKeeper's select_repositories tool. A zero Query matches
// everything.
type Query struct {
	LabelSelector string // e.g. "team=platform,role=service"
	FieldSelector string // e.g. "tracking.status=behind"
	NameMatch     string // substring match on repo_id
}

// Enumerator returns the workspace repositories matching a query.
type Enumerator interface {
	Enumerate(ctx context.Context, q Query) ([]Repo, error)
}

// parseSelectResult parses the JSON payload returned by RepoKeeper's
// select_repositories tool:
//
//	{"repositories":[{"repo_id":"github.com/org/repo","path":"/abs/path", ...}]}
//
// It is the single, testable contract point between Wake and RepoKeeper's
// output shape.
func parseSelectResult(data []byte) ([]Repo, error) {
	var payload struct {
		Repositories []Repo `json:"repositories"`
	}
	if err := json.Unmarshal(data, &payload); err != nil {
		return nil, fmt.Errorf("parse select_repositories result: %w", err)
	}
	return payload.Repositories, nil
}
