// SPDX-License-Identifier: MIT

// Package evidencemap converts a remote provider result (the sting-derived
// model.Result) into Wake's canonical evidence contract. It is the single
// place where the remote shape is mapped onto wake-core's evidence.Bundle, so
// the rest of Wake stays source-agnostic.
//
// Because evidence.Bundle is single-repository (its Target names one
// repository and CommitRecord carries no repo field), a remote result that
// spans many repositories is split into one Bundle per repository. The
// repository is recorded on the target as "<provider>:<owner>/<repo>" so
// downstream consumers can tell remote evidence from local.
package evidencemap

import (
	"sort"

	"github.com/skaphos/wake-core/evidence"
	"github.com/skaphos/wake-forensics-mcp/source/remote/model"
)

// Bundles maps a model.Result into one evidence.Bundle per repository,
// ordered by repository name for deterministic output.
func Bundles(result model.Result) []evidence.Bundle {
	byRepo := make(map[string][]evidence.CommitRecord)
	for _, c := range result.Commits {
		byRepo[c.Repo] = append(byRepo[c.Repo], commitRecord(c))
	}

	repos := make([]string, 0, len(byRepo))
	for repo := range byRepo {
		repos = append(repos, repo)
	}
	sort.Strings(repos)

	bundles := make([]evidence.Bundle, 0, len(repos))
	for _, repo := range repos {
		bundles = append(bundles, evidence.Bundle{
			SchemaVersion: evidence.SchemaVersion,
			GeneratedAt:   result.GeneratedAt,
			Target: evidence.RepositoryTarget{
				Repository: targetRepository(result.Provider, repo),
			},
			Commits: byRepo[repo],
		})
	}
	return bundles
}

// targetRepository qualifies a remote repository with its provider so the
// target is unambiguous (e.g. "github:skaphos/sting").
func targetRepository(provider model.Provider, repo string) string {
	if provider == "" {
		return repo
	}
	return string(provider) + ":" + repo
}

// commitRecord maps a single remote commit onto the evidence contract. The
// full message and (when fetched) per-file patch text are carried through;
// Summary remains the first line. Parents are not captured by the remote
// provider model and are left empty.
func commitRecord(c model.Commit) evidence.CommitRecord {
	return evidence.CommitRecord{
		SHA:         c.SHA,
		Author:      contributor(c),
		AuthoredAt:  c.Date,
		Summary:     c.Summary(),
		Message:     c.Message,
		TouchedPath: touchedPaths(c.Files),
	}
}

// contributor builds a contributor identity from a remote commit. The git
// author name/email are canonical; the provider login (if known) is recorded
// as an alias so identity reconciliation can use it later.
func contributor(c model.Commit) evidence.ContributorIdentity {
	id := evidence.ContributorIdentity{
		CanonicalName:  c.AuthorName,
		CanonicalEmail: c.Email,
	}
	if c.Author != "" && c.Author != c.AuthorName {
		id.Aliases = []string{c.Author}
	}
	return id
}

func touchedPaths(files []model.File) []evidence.PathDelta {
	if len(files) == 0 {
		return nil
	}
	deltas := make([]evidence.PathDelta, 0, len(files))
	for _, f := range files {
		deltas = append(deltas, evidence.PathDelta{
			Path:           f.Path,
			Change:         changeKind(f.Status),
			Additions:      f.Additions,
			Deletions:      f.Deletions,
			Patch:          f.Patch,
			PatchTruncated: f.PatchTruncated,
		})
	}
	return deltas
}

// changeKind maps provider file statuses onto evidence.ChangeKind. GitHub and
// GitLab both normalize to added|removed|renamed|modified in model.File.
func changeKind(status string) evidence.ChangeKind {
	switch status {
	case "added":
		return evidence.ChangeAdd
	case "removed", "deleted":
		return evidence.ChangeDelete
	case "renamed":
		return evidence.ChangeRename
	default:
		return evidence.ChangeModify
	}
}
