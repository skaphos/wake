// SPDX-License-Identifier: MIT

package audit

import (
	"fmt"
	"path"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/skaphos/wake-core/confidence"
)

// Evaluate runs every control in rs against the repository exposed by tree,
// using cls to gate applicability, and returns the per-control findings.
// It is deterministic and performs no I/O beyond FileTree.ReadFile (which is
// cached per call).
func Evaluate(tree FileTree, cls Classification, rs RuleSet) RepoReport {
	e := &evaluator{
		tree:   tree,
		cls:    cls,
		byID:   make(map[string]Control, len(rs.Controls)),
		cache:  map[string][]byte{},
		memo:   map[string]Finding{},
		inProg: map[string]bool{},
	}
	for _, c := range rs.Controls {
		e.byID[c.ID] = c
	}

	findings := make([]Finding, 0, len(rs.Controls))
	for _, c := range rs.Controls {
		findings = append(findings, e.eval(c.ID))
	}
	return RepoReport{
		Repository:     tree.Repo().Name,
		Classification: cls,
		Findings:       findings,
	}
}

type evaluator struct {
	tree   FileTree
	cls    Classification
	byID   map[string]Control
	cache  map[string][]byte
	memo   map[string]Finding
	inProg map[string]bool
}

func (e *evaluator) eval(id string) Finding {
	if f, ok := e.memo[id]; ok {
		return f
	}
	c, ok := e.byID[id]
	if !ok {
		return Finding{ControlID: id, Outcome: OutcomeUnknown,
			Confidence: assess(confidence.BandUnknown, 0, nil, caveat("unknown_control", "control "+id+" is not defined in the rule set"))}
	}
	if e.inProg[id] {
		f := Finding{ControlID: id, Title: c.Title, Kind: c.Kind, Severity: c.Severity, Outcome: OutcomeUnknown,
			Confidence: assess(confidence.BandUnknown, 0, nil, caveat("requires_cycle", "control "+id+" is part of a requires cycle"))}
		e.memo[id] = f
		return f
	}
	e.inProg[id] = true
	f := e.evalControl(c)
	delete(e.inProg, id)
	e.memo[id] = f
	return f
}

func (e *evaluator) evalControl(c Control) Finding {
	f := Finding{ControlID: c.ID, Title: c.Title, Kind: c.Kind, Severity: c.Severity}

	if !applies(c.AppliesWhen, e.cls) {
		f.Outcome = OutcomeNA
		f.Confidence = assess(confidence.BandUnknown, 0, nil,
			caveat("not_applicable", fmt.Sprintf("control does not apply to a %q repository", e.cls.Archetype)))
		return f
	}

	for _, req := range c.Requires {
		if e.eval(req).Outcome != OutcomePass {
			f.Outcome = OutcomeUnknown
			f.Confidence = assess(confidence.BandUnknown, 0, nil,
				caveat("prerequisite_unmet", "requires "+req+", which did not pass"))
			return f
		}
	}

	if c.Kind == KindCategorical {
		return e.evalCategorical(c, f)
	}
	return e.evalBoolean(c, f)
}

func (e *evaluator) evalBoolean(c Control, f Finding) Finding {
	paths, viaContent := e.matchPatterns(c.Evidence)
	if len(paths) > 0 {
		f.Outcome = OutcomePass
		f.Evidence = paths
		if viaContent {
			f.Confidence = assess(confidence.BandHigh, len(paths), []string{"pipeline-step"})
		} else {
			f.Confidence = assess(confidence.BandMedium, len(paths), []string{"config-present"})
		}
		return f
	}
	f.Outcome = OutcomeFail
	f.Remediation = c.Remediation
	f.Confidence = assess(confidence.BandMedium, 0, nil, caveat("no_evidence", "no files matched the control's evidence patterns"))
	return f
}

func (e *evaluator) evalCategorical(c Control, f Finding) Finding {
	for _, cat := range c.Categories {
		paths, viaContent := e.matchPatterns(cat.Evidence)
		if len(paths) > 0 {
			f.Category = cat.Name
			f.Evidence = paths
			if viaContent {
				f.Confidence = assess(confidence.BandHigh, len(paths), []string{"pipeline-step"})
			} else {
				f.Confidence = assess(confidence.BandMedium, len(paths), []string{"config-present"})
			}
			return f
		}
	}
	if c.DefaultCategory != "" {
		f.Category = c.DefaultCategory
		f.Confidence = assess(confidence.BandUnknown, 0, nil, caveat("defaulted", "no category evidence matched; used default category"))
		return f
	}
	f.Outcome = OutcomeUnknown
	f.Category = string(ArchetypeUnknown)
	f.Confidence = assess(confidence.BandUnknown, 0, nil, caveat("no_category_match", "no category evidence found"))
	return f
}

// matchPatterns returns the deduped, sorted set of paths matched by any of
// the patterns, and whether any match was made via a content regex (a
// stronger signal than mere file existence).
func (e *evaluator) matchPatterns(pats []EvidencePattern) (paths []string, viaContent bool) {
	matched := map[string]bool{}
	for _, p := range pats {
		res, vc := e.matchPattern(p)
		for _, m := range res {
			matched[m] = true
		}
		if vc {
			viaContent = true
		}
	}
	out := make([]string, 0, len(matched))
	for m := range matched {
		out = append(out, m)
	}
	sort.Strings(out)
	return out, viaContent && len(out) > 0
}

func (e *evaluator) matchPattern(p EvidencePattern) (paths []string, viaContent bool) {
	var candidates []string
	if len(p.PathGlobs) > 0 {
		for _, fp := range e.tree.Paths() {
			if matchAnyGlob(p.PathGlobs, fp) {
				candidates = append(candidates, fp)
			}
		}
	} else {
		candidates = e.tree.Paths()
	}

	if len(p.ContentPatterns) == 0 {
		return candidates, false // existence check
	}

	res := compilePatterns(p.ContentPatterns)
	var out []string
	for _, fp := range candidates {
		content, err := e.readFile(fp)
		if err != nil {
			continue
		}
		for _, re := range res {
			if re.Match(content) {
				out = append(out, fp)
				break
			}
		}
	}
	return out, len(out) > 0
}

func (e *evaluator) readFile(p string) ([]byte, error) {
	if b, ok := e.cache[p]; ok {
		return b, nil
	}
	b, err := e.tree.ReadFile(p)
	if err != nil {
		return nil, err
	}
	e.cache[p] = b
	return b, nil
}

func applies(a Applicability, cls Classification) bool {
	if len(a.Archetypes) > 0 && !slices.Contains(a.Archetypes, cls.Archetype) {
		return false
	}
	if slices.Contains(a.ExcludeArchetypes, cls.Archetype) {
		return false
	}
	if len(a.Languages) > 0 {
		hit := false
		for _, want := range a.Languages {
			if slices.Contains(cls.Languages, want) {
				hit = true
				break
			}
		}
		if !hit {
			return false
		}
	}
	return true
}

func compilePatterns(pats []string) []*regexp.Regexp {
	out := make([]*regexp.Regexp, 0, len(pats))
	for _, p := range pats {
		if re, err := regexp.Compile(p); err == nil {
			out = append(out, re)
		}
	}
	return out
}

func matchAnyGlob(globs []string, p string) bool {
	for _, g := range globs {
		if matchPath(g, p) {
			return true
		}
	}
	return false
}

// matchPath matches a glob against a repo-relative, forward-slash path:
//   - a glob without "/" matches the file's basename (so "go.mod" or
//     "*.Tests.csproj" match at any depth);
//   - a glob with "/" matches the full path via path.Match ("*" does not
//     cross "/"), e.g. ".github/workflows/*.yml";
//   - a leading "**/" matches the remainder at any depth (segment-aligned).
func matchPath(glob, p string) bool {
	glob = strings.TrimPrefix(glob, "./")
	p = strings.TrimPrefix(p, "./")

	if rest, ok := strings.CutPrefix(glob, "**/"); ok {
		if segmentMatch(rest, p) {
			return true
		}
		if !strings.Contains(rest, "/") {
			if ok, _ := path.Match(rest, path.Base(p)); ok {
				return true
			}
		}
		return false
	}
	if !strings.Contains(glob, "/") {
		ok, _ := path.Match(glob, path.Base(p))
		return ok
	}
	ok, _ := path.Match(glob, p)
	return ok
}

// segmentMatch reports whether glob matches p or any of p's suffixes that
// begin at a "/" boundary.
func segmentMatch(glob, p string) bool {
	if ok, _ := path.Match(glob, p); ok {
		return true
	}
	for i := 0; i < len(p); i++ {
		if p[i] == '/' {
			if ok, _ := path.Match(glob, p[i+1:]); ok {
				return true
			}
		}
	}
	return false
}

func assess(band confidence.Band, n int, etypes []string, caveats ...confidence.Caveat) confidence.Assessment {
	return confidence.Assessment{
		SchemaVersion: confidence.SchemaVersion,
		Band:          band,
		EvidenceCount: n,
		EvidenceTypes: etypes,
		Caveats:       caveats,
	}
}

func caveat(code, msg string) confidence.Caveat {
	return confidence.Caveat{Code: code, Message: msg}
}

// Validate checks a RuleSet for well-formedness: unique non-empty control
// IDs, known kinds/severities, resolvable requires references, and
// compilable content regexes. It is intended for callers loading custom
// rule packs before evaluation.
func (rs RuleSet) Validate() error {
	ids := map[string]bool{}
	for _, c := range rs.Controls {
		if c.ID == "" {
			return fmt.Errorf("control with empty id (title %q)", c.Title)
		}
		if ids[c.ID] {
			return fmt.Errorf("duplicate control id %q", c.ID)
		}
		ids[c.ID] = true
		if c.Severity != Hard && c.Severity != Soft {
			return fmt.Errorf("control %q: severity must be hard or soft, got %q", c.ID, c.Severity)
		}
		if c.Kind != KindBoolean && c.Kind != KindCategorical {
			return fmt.Errorf("control %q: kind must be boolean or categorical, got %q", c.ID, c.Kind)
		}
		if err := validatePatterns(c.ID, c.Evidence); err != nil {
			return err
		}
		for _, cat := range c.Categories {
			if err := validatePatterns(c.ID, cat.Evidence); err != nil {
				return err
			}
		}
	}
	for _, c := range rs.Controls {
		for _, req := range c.Requires {
			if !ids[req] {
				return fmt.Errorf("control %q requires unknown control %q", c.ID, req)
			}
		}
	}
	return nil
}

func validatePatterns(controlID string, pats []EvidencePattern) error {
	for _, p := range pats {
		for _, cp := range p.ContentPatterns {
			if _, err := regexp.Compile(cp); err != nil {
				return fmt.Errorf("control %q: invalid content pattern %q: %w", controlID, cp, err)
			}
		}
	}
	return nil
}
