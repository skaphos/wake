// SPDX-License-Identifier: MIT

package events

import "github.com/skaphos/wake-core/evidence"

const SchemaVersion = evidence.SchemaVersion

// Kind enumerates the normalized Wake event vocabulary. The set is
// intentionally small so generic classification stays stable across
// repository types; adapters refine these into domain-specific meaning.
type Kind string

const (
	// KindCapabilityIntroduction covers changes that add user-visible
	// capability, such as new public APIs, commands, or features.
	KindCapabilityIntroduction Kind = "capability_introduction"
	// KindStructuralRefactor covers reorganizations of code or modules
	// that preserve behavior (renames, splits, dependency shuffles).
	KindStructuralRefactor Kind = "structural_refactor"
	// KindOperationalMaintenance covers routine upkeep: dependency
	// bumps, build/CI tweaks, lint fixes, and similar low-signal work.
	KindOperationalMaintenance Kind = "operational_maintenance"
	// KindDocumentationUpdate covers changes whose primary artifact is
	// documentation: READMEs, docstrings, guides, code comments.
	KindDocumentationUpdate Kind = "documentation_update"
	// KindRetirement covers removals of capability, deprecated API
	// deletion, feature sunsets, and file/module drop events.
	KindRetirement Kind = "retirement"
)

// Kinds returns the ordered list of normalized event kinds recognized
// by the v1 vocabulary. The order is stable for deterministic output.
func Kinds() []Kind {
	return []Kind{
		KindCapabilityIntroduction,
		KindStructuralRefactor,
		KindOperationalMaintenance,
		KindDocumentationUpdate,
		KindRetirement,
	}
}

type Event struct {
	ID      string      `json:"id"`
	Kind    Kind        `json:"kind"`
	Summary string      `json:"summary"`
	Sources []SourceRef `json:"sources,omitempty"`
}

type SourceRef struct {
	CommitSHA string   `json:"commit_sha"`
	Paths     []string `json:"paths,omitempty"`
}

type Candidate struct {
	Event    Event                 `json:"event"`
	Evidence evidence.CommitRecord `json:"evidence"`
}
