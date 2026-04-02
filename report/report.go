// SPDX-License-Identifier: MIT

package report

import (
	"time"

	"github.com/skaphos/wake-core/confidence"
	"github.com/skaphos/wake-core/events"
	"github.com/skaphos/wake-core/evidence"
)

const SchemaVersion = evidence.SchemaVersion

type Section struct {
	Title   string   `json:"title"`
	Summary string   `json:"summary"`
	Items   []string `json:"items,omitempty"`
}

type Payload struct {
	SchemaVersion string                    `json:"schema_version"`
	GeneratedAt   time.Time                 `json:"generated_at"`
	Target        evidence.RepositoryTarget `json:"target"`
	Sections      []Section                 `json:"sections"`
	Events        []events.Event            `json:"events,omitempty"`
	Confidence    confidence.Assessment     `json:"confidence"`
}
