// SPDX-License-Identifier: MIT

package remote

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/google/go-github/v82/github"
)

// ghAPI implements API over the GitHub REST API via go-github.
type ghAPI struct {
	client *github.Client
}

// NewGitHub returns an API backed by GitHub. token may be empty for
// unauthenticated (public, low-rate-limit) access. baseURL targets a GitHub
// Enterprise Server instance when non-empty; it must be the API-root URL
// (e.g. "https://ghe.example.com/api/v3/"), not the web UI base, since it is
// passed to go-github's WithEnterpriseURLs.
func NewGitHub(token, baseURL string) (API, error) {
	c := github.NewClient(nil)
	if token != "" {
		c = c.WithAuthToken(token)
	}
	if baseURL != "" {
		var err error
		c, err = c.WithEnterpriseURLs(baseURL, baseURL)
		if err != nil {
			return nil, fmt.Errorf("configure enterprise URLs: %w", err)
		}
	}
	return &ghAPI{client: c}, nil
}

func ref(r RepoRef) string {
	if r.DefaultBranch != "" {
		return r.DefaultBranch
	}
	return "HEAD"
}

func (g *ghAPI) Tree(ctx context.Context, r RepoRef) ([]string, bool, error) {
	var tree *github.Tree
	err := withRetry(ctx, func() error {
		t, _, e := g.client.Git.GetTree(ctx, r.Owner, r.Name, ref(r), true)
		tree = t
		return e
	})
	if err != nil {
		if isEmptyRepo(err) {
			return nil, false, nil // empty repo: no files, not an access failure
		}
		return nil, false, apiErr("tree", r, err)
	}
	var paths []string
	for _, e := range tree.Entries {
		if e.GetType() == "blob" {
			paths = append(paths, e.GetPath())
		}
	}
	return paths, tree.GetTruncated(), nil
}

func (g *ghAPI) Content(ctx context.Context, r RepoRef, path string) ([]byte, error) {
	var fc *github.RepositoryContent
	err := withRetry(ctx, func() error {
		f, _, _, e := g.client.Repositories.GetContents(ctx, r.Owner, r.Name, path, &github.RepositoryContentGetOptions{Ref: ref(r)})
		fc = f
		return e
	})
	if err != nil {
		return nil, apiErr("content "+path, r, err)
	}
	if fc == nil {
		return nil, fmt.Errorf("%s: %s is not a file", r.FullName(), path)
	}
	s, err := fc.GetContent()
	if err != nil {
		return nil, fmt.Errorf("%s: decode %s: %w", r.FullName(), path, err)
	}
	return []byte(s), nil
}

func (g *ghAPI) ListOrgRepos(ctx context.Context, org string) ([]RepoRef, error) {
	var out []RepoRef
	opt := &github.RepositoryListByOrgOptions{ListOptions: github.ListOptions{PerPage: 100}}
	for {
		var repos []*github.Repository
		var resp *github.Response
		err := withRetry(ctx, func() error {
			rs, r, e := g.client.Repositories.ListByOrg(ctx, org, opt)
			repos, resp = rs, r
			return e
		})
		if err != nil {
			return nil, fmt.Errorf("list org %q repos: %w", org, err)
		}
		for _, rp := range repos {
			out = append(out, RepoRef{
				Owner:         rp.GetOwner().GetLogin(),
				Name:          rp.GetName(),
				DefaultBranch: rp.GetDefaultBranch(),
				Archived:      rp.GetArchived(),
				Fork:          rp.GetFork(),
			})
		}
		if resp == nil || resp.NextPage == 0 {
			break
		}
		opt.Page = resp.NextPage
	}
	return out, nil
}

func apiErr(op string, r RepoRef, err error) error {
	return fmt.Errorf("%s %s: %w", op, r.FullName(), err)
}

// isEmptyRepo reports the GitHub 409 "Git Repository is empty" response,
// which must be treated as "no files" rather than an access failure.
func isEmptyRepo(err error) bool {
	var er *github.ErrorResponse
	if errors.As(err, &er) {
		return er.Response != nil && er.Response.StatusCode == http.StatusConflict
	}
	return false
}

// withRetry retries fn on GitHub rate-limit / secondary-rate-limit errors,
// waiting for the reset (capped), and returns other errors immediately.
func withRetry(ctx context.Context, fn func() error) error {
	const maxAttempts = 4
	for attempt := 0; ; attempt++ {
		err := fn()
		if err == nil {
			return nil
		}
		var rle *github.RateLimitError
		var are *github.AbuseRateLimitError
		switch {
		case errors.As(err, &rle):
			if attempt >= maxAttempts || !sleepCtx(ctx, time.Until(rle.Rate.Reset.Time)) {
				return err
			}
		case errors.As(err, &are):
			if attempt >= maxAttempts || !sleepCtx(ctx, are.GetRetryAfter()) {
				return err
			}
		default:
			return err
		}
	}
}

// sleepCtx waits for d (capped at two minutes), returning false if the
// context is cancelled first.
func sleepCtx(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return true
	}
	if max := 2 * time.Minute; d > max {
		d = max
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}
