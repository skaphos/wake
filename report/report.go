// SPDX-License-Identifier: MIT

package report

import (
	"github.com/skaphos/wake-core/confidence"
	"github.com/skaphos/wake-core/events"
)

type Section struct {
	Title   string   `json:"title"`
	Summary string   `json:"summary"`
	Items   []string `json:"items,omitempty"`
}

type Payload struct {
	Sections   []Section             `json:"sections"`
	Events     []events.Event        `json:"events,omitempty"`
	Confidence confidence.Assessment `json:"confidence"`
}
