// SPDX-License-Identifier: MIT

package confidence

const SchemaVersion = "wake.skaphos.io/contracts/v1alpha1"

type Band string

const (
	BandUnknown Band = "unknown"
	BandLow     Band = "low"
	BandMedium  Band = "medium"
	BandHigh    Band = "high"
)

type Caveat struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type Assessment struct {
	SchemaVersion string   `json:"schema_version"`
	Band          Band     `json:"band"`
	EvidenceCount int      `json:"evidence_count"`
	EvidenceTypes []string `json:"evidence_types,omitempty"`
	Caveats       []Caveat `json:"caveats,omitempty"`
	Constraints   []string `json:"constraints,omitempty"`
}
