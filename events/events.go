// SPDX-License-Identifier: MIT

package events

import "github.com/skaphos/wake-core/evidence"

const SchemaVersion = evidence.SchemaVersion

type Kind string

const (
	KindCapabilityIntroduction Kind = "capability_introduction"
	KindStructuralRefactor     Kind = "structural_refactor"
	KindOperationalMaintenance Kind = "operational_maintenance"
	KindDocumentationUpdate    Kind = "documentation_update"
)

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
