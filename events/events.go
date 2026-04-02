// SPDX-License-Identifier: MIT

package events

import "github.com/skaphos/wake-core/evidence"

type Kind string

const (
	KindCapabilityIntroduction Kind = "capability_introduction"
	KindStructuralRefactor     Kind = "structural_refactor"
	KindOperationalMaintenance Kind = "operational_maintenance"
	KindDocumentationUpdate    Kind = "documentation_update"
)

type Event struct {
	Kind         Kind     `json:"kind"`
	Summary      string   `json:"summary"`
	EvidenceSHAs []string `json:"evidence_shas,omitempty"`
	Paths        []string `json:"paths,omitempty"`
}

type Candidate struct {
	Event    Event                 `json:"event"`
	Evidence evidence.CommitRecord `json:"evidence"`
}
