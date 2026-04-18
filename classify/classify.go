// SPDX-License-Identifier: MIT

// Package classify applies adapter-free rules to forensics evidence
// and emits normalized Wake event candidates.
//
// The generic rule set recognizes documentation updates, retirements,
// structural refactors, operational maintenance, and capability
// introductions. Commits that do not match any rule are left
// unclassified so that adapters can refine them later without
// fighting a low-confidence generic guess.
package classify

import (
	"path"
	"strings"

	"github.com/skaphos/wake-core/events"
	"github.com/skaphos/wake-core/evidence"
)

// Classify walks every commit in bundle and returns the candidates
// produced by the default generic rule set. Commits with empty touched
// paths (e.g. merge commits) and commits that match no rule are
// skipped.
func Classify(bundle evidence.Bundle) []events.Candidate {
	var out []events.Candidate
	for _, commit := range bundle.Commits {
		if kind, ok := classifyCommit(commit); ok {
			out = append(out, makeCandidate(commit, kind))
		}
	}
	return out
}

func classifyCommit(c evidence.CommitRecord) (events.Kind, bool) {
	if len(c.TouchedPath) == 0 {
		return "", false
	}
	switch {
	case allDocPaths(c.TouchedPath):
		return events.KindDocumentationUpdate, true
	case allDeletes(c.TouchedPath):
		return events.KindRetirement, true
	case renameHeavy(c.TouchedPath):
		return events.KindStructuralRefactor, true
	case allMaintenancePaths(c.TouchedPath):
		return events.KindOperationalMaintenance, true
	case hasNewSource(c.TouchedPath):
		return events.KindCapabilityIntroduction, true
	}
	return "", false
}

func makeCandidate(c evidence.CommitRecord, kind events.Kind) events.Candidate {
	paths := make([]string, 0, len(c.TouchedPath))
	for _, pd := range c.TouchedPath {
		paths = append(paths, pd.Path)
	}
	prefix := c.SHA
	if len(prefix) > 7 {
		prefix = prefix[:7]
	}
	return events.Candidate{
		Event: events.Event{
			ID:      eventID(kind, prefix),
			Kind:    kind,
			Summary: c.Summary,
			Sources: []events.SourceRef{{
				CommitSHA: c.SHA,
				Paths:     paths,
			}},
		},
		Evidence: c,
	}
}

func eventID(kind events.Kind, prefix string) string {
	switch kind {
	case events.KindCapabilityIntroduction:
		return "cap-" + prefix
	case events.KindStructuralRefactor:
		return "ref-" + prefix
	case events.KindOperationalMaintenance:
		return "ops-" + prefix
	case events.KindDocumentationUpdate:
		return "doc-" + prefix
	case events.KindRetirement:
		return "ret-" + prefix
	}
	return "evt-" + prefix
}

func allDocPaths(paths []evidence.PathDelta) bool {
	for _, p := range paths {
		if !isDocPath(p.Path) {
			return false
		}
	}
	return true
}

func allDeletes(paths []evidence.PathDelta) bool {
	for _, p := range paths {
		if p.Change != evidence.ChangeDelete {
			return false
		}
	}
	return true
}

func renameHeavy(paths []evidence.PathDelta) bool {
	renames := 0
	for _, p := range paths {
		if p.Change == evidence.ChangeRename {
			renames++
		}
	}
	return renames > 0 && renames*2 >= len(paths)
}

func allMaintenancePaths(paths []evidence.PathDelta) bool {
	for _, p := range paths {
		if !isMaintenancePath(p.Path) {
			return false
		}
	}
	return true
}

func hasNewSource(paths []evidence.PathDelta) bool {
	for _, p := range paths {
		if p.Change != evidence.ChangeAdd {
			continue
		}
		if isDocPath(p.Path) || isMaintenancePath(p.Path) {
			continue
		}
		return true
	}
	return false
}

var docExtensions = []string{".md", ".mdx", ".rst", ".txt", ".adoc"}

var docBaseExact = map[string]struct{}{
	"readme":       {},
	"license":      {},
	"licence":      {},
	"authors":      {},
	"contributors": {},
	"changelog":    {},
	"changes":      {},
	"notice":       {},
	"contributing": {},
}

var docBasePrefixes = []string{
	"readme.", "license.", "licence.", "changelog.",
	"changes.", "notice.", "contributing.", "authors.",
}

func isDocPath(p string) bool {
	lower := strings.ToLower(p)
	base := path.Base(lower)

	for _, ext := range docExtensions {
		if strings.HasSuffix(base, ext) {
			return true
		}
	}

	for _, segment := range strings.Split(lower, "/") {
		switch segment {
		case "docs", "doc", "documentation":
			return true
		}
	}

	if _, ok := docBaseExact[base]; ok {
		return true
	}
	for _, prefix := range docBasePrefixes {
		if strings.HasPrefix(base, prefix) {
			return true
		}
	}
	return false
}

var maintenanceBases = map[string]struct{}{
	"go.mod":                  {},
	"go.sum":                  {},
	"package.json":            {},
	"package-lock.json":       {},
	"yarn.lock":               {},
	"pnpm-lock.yaml":          {},
	"cargo.toml":              {},
	"cargo.lock":              {},
	"pyproject.toml":          {},
	"poetry.lock":             {},
	"requirements.txt":        {},
	"pipfile":                 {},
	"pipfile.lock":            {},
	"gemfile":                 {},
	"gemfile.lock":            {},
	"composer.json":           {},
	"composer.lock":           {},
	"dockerfile":              {},
	"makefile":                {},
	"reuse.toml":              {},
	".pre-commit-config.yaml": {},
}

func isMaintenancePath(p string) bool {
	lower := strings.ToLower(p)
	base := path.Base(lower)
	if _, ok := maintenanceBases[base]; ok {
		return true
	}
	switch {
	case strings.HasPrefix(lower, ".github/workflows/"):
		return true
	case strings.HasPrefix(lower, ".github/"):
		return true
	case strings.HasPrefix(lower, ".gitlab/"):
		return true
	case strings.HasPrefix(lower, ".circleci/"):
		return true
	}
	return false
}
