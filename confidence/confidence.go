// SPDX-License-Identifier: MIT

package confidence

type Band string

const (
	BandLow    Band = "low"
	BandMedium Band = "medium"
	BandHigh   Band = "high"
)

type Caveat struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type Assessment struct {
	Band          Band     `json:"band"`
	EvidenceCount int      `json:"evidence_count"`
	EvidenceTypes []string `json:"evidence_types,omitempty"`
	Caveats       []Caveat `json:"caveats,omitempty"`
	Constraints   []string `json:"constraints,omitempty"`
}
