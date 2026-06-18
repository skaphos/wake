// SPDX-License-Identifier: MIT

// Package remote provides audit.FileTree sources backed by remote Git
// hosting APIs (GitHub now, GitLab later). A repository's path listing comes
// from one recursive tree call; file content is fetched lazily and only for
// the files a rule actually needs, keeping API volume bounded for org-scale
// scans (DECISIONS/0004).
package remote

import (
	"context"
	"sort"

	"github.com/skaphos/wake-core/audit"
)

// RepoRef identifies a remote repository and carries the metadata needed for
// eligibility filtering and tree/content fetches.
type RepoRef struct {
	Owner         string
	Name          string
	DefaultBranch string
	Archived      bool
	Fork          bool
}

// FullName is "owner/name".
func (r RepoRef) FullName() string { return r.Owner + "/" + r.Name }

// API is the minimal remote-host surface the audit needs. It is abstracted
// so the FileTree logic is testable without network access; ghAPI is the
// go-github-backed implementation.
type API interface {
	// Tree returns every blob (file) path in the repo at ref, repo-root
	// relative with forward slashes. truncated reports that the host capped
	// the listing for a very large repo.
	Tree(ctx context.Context, r RepoRef) (paths []string, truncated bool, err error)
	// Content returns the bytes of one file at ref.
	Content(ctx context.Context, r RepoRef, path string) ([]byte, error)
	// ListOrgRepos enumerates an organization's repositories.
	ListOrgRepos(ctx context.Context, org string) ([]RepoRef, error)
}

// Tree is an audit.FileTree for one remote repository. Paths are fetched
// once at construction; content is fetched lazily through the API and
// cached.
type Tree struct {
	ctx       context.Context
	api       API
	ref       RepoRef
	paths     []string
	truncated bool
	cache     map[string][]byte
}

// NewTree lists the repository tree and returns a FileTree. The context is
// retained for lazy content fetches (the audit.FileTree.ReadFile signature
// carries no context).
func NewTree(ctx context.Context, api API, ref RepoRef) (*Tree, error) {
	paths, truncated, err := api.Tree(ctx, ref)
	if err != nil {
		return nil, err
	}
	sort.Strings(paths)
	return &Tree{ctx: ctx, api: api, ref: ref, paths: paths, truncated: truncated, cache: map[string][]byte{}}, nil
}

// Truncated reports whether the host capped the tree listing (a very large
// repo); callers may surface this as a coverage caveat.
func (t *Tree) Truncated() bool { return t.truncated }

// Paths implements audit.FileTree.
func (t *Tree) Paths() []string { return t.paths }

// Repo implements audit.FileTree. Name is the owner/name full name so that
// org-wide scans — where different owners may share a repo name — stay
// uniquely identifiable in the report's Repository field (core/audit
// engine.go uses Repo().Name verbatim).
func (t *Tree) Repo() audit.RepoInfo {
	return audit.RepoInfo{Name: t.ref.FullName(), Archived: t.ref.Archived, Fork: t.ref.Fork}
}

// ReadFile implements audit.FileTree, fetching content lazily and caching it.
func (t *Tree) ReadFile(p string) ([]byte, error) {
	if b, ok := t.cache[p]; ok {
		return b, nil
	}
	b, err := t.api.Content(t.ctx, t.ref, p)
	if err != nil {
		return nil, err
	}
	t.cache[p] = b
	return b, nil
}

// EligibleRepos filters enumerated repos to the audit scope: non-archived,
// non-fork by default. The returned slice is sorted by full name for stable
// scan order.
func EligibleRepos(repos []RepoRef, includeArchived, includeForks bool) []RepoRef {
	out := make([]RepoRef, 0, len(repos))
	for _, r := range repos {
		if r.Archived && !includeArchived {
			continue
		}
		if r.Fork && !includeForks {
			continue
		}
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].FullName() < out[j].FullName() })
	return out
}
