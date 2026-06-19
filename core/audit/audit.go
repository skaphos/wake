// SPDX-License-Identifier: MIT

// Package audit defines the contracts for Wake's repository policy-audit
// engine: configurable controls grouped into rule packs, evaluated against
// a repository's file tree to produce evidence-backed, confidence-scored
// findings.
//
// The package is pure — it has no I/O, git, or network dependencies. A
// FileTree (provided by a caller) supplies file paths and contents; the
// engine (see Evaluate) is deterministic over that input. Struct tags carry
// both json and yaml so rule packs can be shipped as YAML and findings
// serialized as JSON.
package audit

import "github.com/skaphos/wake-core/confidence"

// SchemaVersion identifies the audit contract version.
const SchemaVersion = confidence.SchemaVersion

// Archetype is a coarse repository category used to gate policy
// applicability. The v1 set is deliberately small (DECISIONS/0004).
type Archetype string

const (
	ArchetypeDocs    Archetype = "docs"
	ArchetypeGitOps  Archetype = "gitops"
	ArchetypeIaC     Archetype = "iac"
	ArchetypeService Archetype = "service"
	ArchetypeLibrary Archetype = "library"
	ArchetypeUnknown Archetype = "unknown"
)

// Classification is the deterministic profile of a repository. It is
// produced by a classifier (a separate concern) and consumed here to decide
// which controls apply.
type Classification struct {
	Languages []string  `json:"languages,omitempty" yaml:"languages,omitempty"`
	Archetype Archetype `json:"archetype" yaml:"archetype"`
}

// Severity expresses whether a control is an enforced floor or advisory.
type Severity string

const (
	// Hard controls are an enforced floor: they may be strengthened but
	// never disabled, and a failure is a violation.
	Hard Severity = "hard"
	// Soft controls are advisory: they may be relaxed or turned off at a
	// higher policy layer, and a failure is a recommendation.
	Soft Severity = "soft"
)

// ControlKind distinguishes a boolean present/absent control from a
// categorical control that selects one of several labeled categories.
type ControlKind string

const (
	KindBoolean     ControlKind = "boolean"
	KindCategorical ControlKind = "categorical"
)

// Outcome is the result of evaluating a control against a repository.
type Outcome string

const (
	// OutcomePass: a boolean control's evidence was found.
	OutcomePass Outcome = "pass"
	// OutcomeFail: the control applies and was evaluable, but no evidence
	// was found.
	OutcomeFail Outcome = "fail"
	// OutcomeNA: the control does not apply to this repository (by
	// classification). Excluded from compliance denominators.
	OutcomeNA Outcome = "n/a"
	// OutcomeUnknown: the control could not be evaluated (e.g. a required
	// prerequisite control did not pass).
	OutcomeUnknown Outcome = "unknown"
)

// EvidencePattern matches files in a FileTree. Semantics:
//   - PathGlobs only: a file whose path matches any glob is evidence
//     (existence check).
//   - PathGlobs + ContentPatterns: a file whose path matches a glob AND
//     whose content matches any content regex is evidence (scoped content
//     scan — the common, bounded case).
//   - ContentPatterns only: any file whose content matches is evidence
//     (unscoped scan; heavier — prefer scoping with PathGlobs).
//
// Glob semantics (see matchPath): a glob without "/" matches a file's
// basename; with "/" it matches the full repo-relative path (so "*" does
// not cross "/"); a leading "**/" matches at any depth.
type EvidencePattern struct {
	PathGlobs       []string `json:"path_globs,omitempty" yaml:"path_globs,omitempty"`
	ContentPatterns []string `json:"content_patterns,omitempty" yaml:"content_patterns,omitempty"`
	Description     string   `json:"description,omitempty" yaml:"description,omitempty"`
}

// Applicability gates whether a control applies to a repository, evaluated
// against its Classification. A zero Applicability applies to everything.
type Applicability struct {
	// Archetypes, when non-empty, limits the control to repos whose
	// archetype is in this set.
	Archetypes []Archetype `json:"archetypes,omitempty" yaml:"archetypes,omitempty"`
	// ExcludeArchetypes removes repos whose archetype is in this set.
	ExcludeArchetypes []Archetype `json:"exclude_archetypes,omitempty" yaml:"exclude_archetypes,omitempty"`
	// Languages, when non-empty, limits the control to repos that include
	// at least one of these languages.
	Languages []string `json:"languages,omitempty" yaml:"languages,omitempty"`
}

// Category is one labeled option of a categorical control. The first
// category (in declared order) with matching evidence wins.
type Category struct {
	Name     string            `json:"name" yaml:"name"`
	Evidence []EvidencePattern `json:"evidence" yaml:"evidence"`
}

// Control is a single auditable policy.
type Control struct {
	ID          string        `json:"id" yaml:"id"`
	Title       string        `json:"title" yaml:"title"`
	Kind        ControlKind   `json:"kind" yaml:"kind"`
	Severity    Severity      `json:"severity" yaml:"severity"`
	AppliesWhen Applicability `json:"applies_when" yaml:"applies_when,omitempty"`
	// Requires lists control IDs that must pass before this control is
	// evaluable; if any does not pass, this control's outcome is Unknown.
	// (e.g. unit-tests requires ci-pipeline: no pipeline → unknown, not fail.)
	Requires []string `json:"requires,omitempty" yaml:"requires,omitempty"`

	// Evidence is used for boolean controls: pass if any pattern matches.
	Evidence []EvidencePattern `json:"evidence,omitempty" yaml:"evidence,omitempty"`

	// Categories and DefaultCategory are used for categorical controls.
	Categories      []Category `json:"categories,omitempty" yaml:"categories,omitempty"`
	DefaultCategory string     `json:"default_category,omitempty" yaml:"default_category,omitempty"`

	// Remediation is surfaced when a boolean control fails.
	Remediation string `json:"remediation,omitempty" yaml:"remediation,omitempty"`
}

// RuleSet is a named, versioned pack of controls.
type RuleSet struct {
	Name     string    `json:"name" yaml:"name"`
	Version  string    `json:"version,omitempty" yaml:"version,omitempty"`
	Controls []Control `json:"controls" yaml:"controls"`
}

// Finding is the evaluated result of one control against one repository.
type Finding struct {
	ControlID string      `json:"control_id"`
	Title     string      `json:"title"`
	Kind      ControlKind `json:"kind"`
	Severity  Severity    `json:"severity"`
	Outcome   Outcome     `json:"outcome,omitempty"`
	Category  string      `json:"category,omitempty"`
	Evidence  []string    `json:"evidence,omitempty"`
	// Origin names the policy layer that contributed or last modified this
	// control during layer resolution (empty for an unlayered audit).
	Origin      string                `json:"origin,omitempty"`
	Confidence  confidence.Assessment `json:"confidence"`
	Remediation string                `json:"remediation,omitempty"`
}

// RepoReport is the audit result for a single repository.
type RepoReport struct {
	Repository     string         `json:"repository"`
	Classification Classification `json:"classification"`
	Findings       []Finding      `json:"findings"`
	// Waivers lists soft controls disabled by a policy layer for this audit,
	// carried through so the report records them with provenance rather than
	// silently omitting the control. Populated by EvaluatePolicy.
	Waivers []Waiver `json:"waivers,omitempty"`
	// Layers names the resolved policy layers (base first) when the audit ran
	// against a layered EffectivePolicy.
	Layers []string `json:"layers,omitempty"`
	// Skipped repos (archived/forks excluded from scope) carry a reason and
	// no findings.
	Skipped    bool   `json:"skipped,omitempty"`
	SkipReason string `json:"skip_reason,omitempty"`
}

// HardViolations returns the findings for hard controls that failed — the
// enforced-floor breaches that put a repository out of policy. (Soft failures
// are recommendations, not violations.)
func (r RepoReport) HardViolations() []Finding {
	var out []Finding
	for _, f := range r.Findings {
		if f.Severity == Hard && f.Outcome == OutcomeFail {
			out = append(out, f)
		}
	}
	return out
}

// OutOfPolicy reports whether the repository has any hard violation. It is the
// canonical "out of policy" predicate used by per-team rollups.
func (r RepoReport) OutOfPolicy() bool {
	return len(r.HardViolations()) > 0
}

// RepoInfo describes the repository a FileTree exposes, for eligibility
// filtering.
type RepoInfo struct {
	Name     string `json:"name"`
	Archived bool   `json:"archived,omitempty"`
	Fork     bool   `json:"fork,omitempty"`
}

// FileTree is a read-only view of a repository's files for auditing.
// Implementations back it with a local checkout, a remote API tree, etc.
type FileTree interface {
	// Paths returns all file paths (forward-slash, repo-root-relative) in a
	// deterministic order.
	Paths() []string
	// ReadFile returns the content of a path. Implementations may cap size;
	// truncation is acceptable for evidence scanning.
	ReadFile(path string) ([]byte, error)
	// Repo identifies the repository and carries eligibility metadata.
	Repo() RepoInfo
}
