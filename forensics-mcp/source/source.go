// SPDX-License-Identifier: MIT

// Package source defines the unified evidence-source abstraction for Wake
// forensics. A Source yields commit evidence for one or more repositories,
// whether the underlying origin is a local Git checkout or a remote Git
// hosting platform (GitHub, GitLab).
//
// Every Source returns one [evidence.Bundle] per repository in scope. This
// keeps the single-repository evidence.Bundle contract intact for both the
// local-git path and the remote (cross-org, cross-repo) path: remote analysis
// of an author across many repositories simply produces many bundles.
package source

import (
	"context"

	"github.com/skaphos/wake-core/evidence"
)

// Source provides commit evidence for the repositories in its scope.
//
// Implementations:
//   - source/local:  a single local Git checkout (wraps target+repository+commits)
//   - source/remote:  a GitHub or GitLab author/org/repo query (adapted from sting)
//
// A higher layer (the CLI or service) may combine several Sources — for
// example, a repokeeper enumeration that fans out to one local Source per
// checked-out repository, with a remote Source as the fallback for
// repositories that are not present locally.
type Source interface {
	// Extract returns one bundle per repository in scope. The slice is
	// ordered deterministically so repeated runs are comparable.
	Extract(ctx context.Context) ([]evidence.Bundle, error)

	// Kind identifies the source for diagnostics and provenance
	// (e.g. "local", "remote:github", "remote:gitlab").
	Kind() string
}
