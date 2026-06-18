// SPDX-License-Identifier: MIT

package audit

import (
	"fmt"
	"slices"
	"strings"
)

// Verb is the operation a policy layer applies to a control in the composed
// rule set. The verbs encode the hard/soft contract:
//
//   - add introduces a control the lower layers did not define.
//   - strengthen tightens an existing control — most commonly promoting a
//     soft control to hard, but it may also override the control's body with
//     a stricter definition. A strengthen may never downgrade hard→soft.
//   - relax disables a control. It is permitted on soft controls only (a hard
//     control is an enforced floor that may be strengthened but never
//     disabled). A relaxed control is not silently dropped: it is recorded as
//     a Waiver with provenance.
type Verb string

const (
	VerbAdd        Verb = "add"
	VerbStrengthen Verb = "strengthen"
	VerbRelax      Verb = "relax"
)

// LayerEdit is a single operation a Layer applies during resolution.
type LayerEdit struct {
	Verb Verb `json:"verb" yaml:"verb"`
	// ID is the target control ID. For add it may be omitted when Control
	// carries the ID; if both are set they must agree.
	ID string `json:"id,omitempty" yaml:"id,omitempty"`
	// Reason justifies the edit. It is required for relax (it becomes the
	// waiver's recorded justification) and optional otherwise.
	Reason string `json:"reason,omitempty" yaml:"reason,omitempty"`
	// Control carries the control body. For add it is the full new control.
	// For strengthen, each non-empty field overrides the base control's,
	// letting a layer restate evidence, applicability, requirements, or
	// remediation more strictly. Ignored for relax.
	Control *Control `json:"control,omitempty" yaml:"control,omitempty"`
	// PromoteToHard is a strengthen convenience that raises a soft control to
	// hard without restating its body. Equivalent to overriding Severity with
	// Hard.
	PromoteToHard bool `json:"promote_to_hard,omitempty" yaml:"promote_to_hard,omitempty"`
}

// targetID returns the control ID an edit operates on.
func (e LayerEdit) targetID() string {
	if e.ID != "" {
		return e.ID
	}
	if e.Control != nil {
		return e.Control.ID
	}
	return ""
}

// Layer is a named overlay applied over a base rule set during resolution.
// Layers compose in order — e.g. an organizational standard then a team
// layer — and a later layer observes the result of earlier ones. The Name is
// recorded as provenance on every control the layer contributes or modifies
// and on every waiver it creates, so the report can attribute each effective
// policy back to the layer that set it.
type Layer struct {
	Name  string      `json:"name" yaml:"name"`
	Edits []LayerEdit `json:"edits" yaml:"edits"`
}

// Waiver records a soft control disabled by a layer. It preserves provenance —
// who waived it (Layer) and why (Reason) — so the audit surfaces a recorded
// waiver rather than a silent omission.
type Waiver struct {
	ControlID string `json:"control_id" yaml:"control_id"`
	Title     string `json:"title,omitempty" yaml:"title,omitempty"`
	Layer     string `json:"layer" yaml:"layer"`
	Reason    string `json:"reason,omitempty" yaml:"reason,omitempty"`
}

// EffectivePolicy is the result of composing a base rule set with ordered
// layers: the RuleSet to evaluate, the Waivers it produced (disabled soft
// controls, never silently dropped), per-control provenance, and the ordered
// list of layer names that contributed (base first).
type EffectivePolicy struct {
	RuleSet RuleSet           `json:"rule_set"`
	Waivers []Waiver          `json:"waivers,omitempty"`
	Origin  map[string]string `json:"origin,omitempty"`
	Layers  []string          `json:"layers,omitempty"`
}

// Resolve composes base with the given layers, applied in order, into an
// EffectivePolicy. The base supplies the tool default controls; each layer
// adds, strengthens, or relaxes them under the hard/soft rules (see Verb).
// Resolution is deterministic and order-sensitive: layer N observes the
// controls as left by layer N-1.
//
// Resolve validates base and every layer, rejects illegal edits (relaxing a
// hard control, downgrading via strengthen, adding a duplicate ID, targeting
// an unknown control, or relaxing a control another still requires), and
// validates the composed rule set before returning it.
func Resolve(base RuleSet, layers ...Layer) (EffectivePolicy, error) {
	if err := base.Validate(); err != nil {
		return EffectivePolicy{}, fmt.Errorf("base rule set %q: %w", base.Name, err)
	}

	// order preserves declaration order; byID holds the current control body;
	// origin attributes each control to the layer that last set it.
	order := make([]string, 0, len(base.Controls))
	byID := make(map[string]Control, len(base.Controls))
	origin := make(map[string]string, len(base.Controls))
	baseName := base.Name
	if baseName == "" {
		baseName = "base"
	}
	for _, c := range base.Controls {
		order = append(order, c.ID)
		byID[c.ID] = c
		origin[c.ID] = baseName
	}

	var waivers []Waiver
	layerNames := []string{baseName}

	for _, layer := range layers {
		if err := layer.Validate(); err != nil {
			return EffectivePolicy{}, fmt.Errorf("layer %q: %w", layer.Name, err)
		}
		layerNames = append(layerNames, layer.Name)
		for i, edit := range layer.Edits {
			id := edit.targetID()
			switch edit.Verb {
			case VerbAdd:
				if _, exists := byID[id]; exists {
					return EffectivePolicy{}, fmt.Errorf("layer %q edit %d: add control %q: already defined by %q (use strengthen or relax)", layer.Name, i, id, origin[id])
				}
				c := *edit.Control
				c.ID = id
				order = append(order, id)
				byID[id] = c
				origin[id] = layer.Name

			case VerbStrengthen:
				base, exists := byID[id]
				if !exists {
					return EffectivePolicy{}, fmt.Errorf("layer %q edit %d: strengthen unknown control %q", layer.Name, i, id)
				}
				strengthened, err := strengthen(base, edit)
				if err != nil {
					return EffectivePolicy{}, fmt.Errorf("layer %q edit %d: strengthen %q: %w", layer.Name, i, id, err)
				}
				byID[id] = strengthened
				origin[id] = layer.Name

			case VerbRelax:
				target, exists := byID[id]
				if !exists {
					return EffectivePolicy{}, fmt.Errorf("layer %q edit %d: relax unknown control %q", layer.Name, i, id)
				}
				if target.Severity == Hard {
					return EffectivePolicy{}, fmt.Errorf("layer %q edit %d: cannot relax hard control %q (a hard control is an enforced floor; relax is permitted on soft controls only)", layer.Name, i, id)
				}
				if dependent := requiredBy(order, byID, id); dependent != "" {
					return EffectivePolicy{}, fmt.Errorf("layer %q edit %d: cannot relax %q: control %q still requires it", layer.Name, i, id, dependent)
				}
				waivers = append(waivers, Waiver{
					ControlID: id,
					Title:     target.Title,
					Layer:     layer.Name,
					Reason:    edit.Reason,
				})
				order = slices.DeleteFunc(order, func(s string) bool { return s == id })
				delete(byID, id)
				delete(origin, id)
			}
		}
	}

	controls := make([]Control, 0, len(order))
	for _, id := range order {
		controls = append(controls, byID[id])
	}
	rs := RuleSet{Name: base.Name, Version: base.Version, Controls: controls}
	if err := rs.Validate(); err != nil {
		return EffectivePolicy{}, fmt.Errorf("composed rule set: %w", err)
	}

	return EffectivePolicy{RuleSet: rs, Waivers: waivers, Origin: origin, Layers: layerNames}, nil
}

// strengthen applies a strengthen edit to a control: it may promote the
// severity to hard and override individual fields with stricter values. It
// rejects any attempt to downgrade severity to soft.
func strengthen(c Control, edit LayerEdit) (Control, error) {
	if edit.PromoteToHard {
		c.Severity = Hard
	}
	if o := edit.Control; o != nil {
		if o.Severity != "" {
			if o.Severity == Soft && c.Severity == Hard {
				return Control{}, fmt.Errorf("strengthen cannot downgrade a hard control to soft; use relax (permitted on soft only)")
			}
			c.Severity = o.Severity
		}
		if o.Title != "" {
			c.Title = o.Title
		}
		if o.Kind != "" {
			c.Kind = o.Kind
		}
		if len(o.Evidence) > 0 {
			c.Evidence = o.Evidence
		}
		if len(o.Categories) > 0 {
			c.Categories = o.Categories
		}
		if o.DefaultCategory != "" {
			c.DefaultCategory = o.DefaultCategory
		}
		if len(o.Requires) > 0 {
			c.Requires = o.Requires
		}
		if o.Remediation != "" {
			c.Remediation = o.Remediation
		}
		if !o.AppliesWhen.isZero() {
			c.AppliesWhen = o.AppliesWhen
		}
	}
	return c, nil
}

// requiredBy returns the ID of a still-present control that lists id in its
// Requires, or "" if none does. It is used to block relaxing a control that
// another control depends on (which would otherwise produce an Unknown
// outcome on the dependent).
func requiredBy(order []string, byID map[string]Control, id string) string {
	for _, other := range order {
		if other == id {
			continue
		}
		if slices.Contains(byID[other].Requires, id) {
			return other
		}
	}
	return ""
}

// isZero reports whether the Applicability is the empty value (applies to
// everything), used to decide whether a strengthen override should replace
// the base applicability.
func (a Applicability) isZero() bool {
	return len(a.Archetypes) == 0 && len(a.ExcludeArchetypes) == 0 && len(a.Languages) == 0
}

// Validate checks a Layer for well-formedness independent of any base rule
// set: a non-empty name, known verbs, a resolvable target ID per edit, and
// the per-verb payload requirements (add carries a control; relax carries a
// reason; strengthen actually changes something).
func (l Layer) Validate() error {
	if strings.TrimSpace(l.Name) == "" {
		return fmt.Errorf("layer name is required")
	}
	for i, e := range l.Edits {
		id := e.targetID()
		switch e.Verb {
		case VerbAdd:
			if e.Control == nil {
				return fmt.Errorf("edit %d: add requires a control body", i)
			}
			if e.ID != "" && e.Control.ID != "" && e.ID != e.Control.ID {
				return fmt.Errorf("edit %d: add id %q does not match control id %q", i, e.ID, e.Control.ID)
			}
			if id == "" {
				return fmt.Errorf("edit %d: add requires a control id", i)
			}
		case VerbStrengthen:
			if id == "" {
				return fmt.Errorf("edit %d: strengthen requires a target control id", i)
			}
			if !e.PromoteToHard && e.Control == nil {
				return fmt.Errorf("edit %d: strengthen %q is a no-op (set promote_to_hard or a control override)", i, id)
			}
		case VerbRelax:
			if id == "" {
				return fmt.Errorf("edit %d: relax requires a target control id", i)
			}
			if strings.TrimSpace(e.Reason) == "" {
				return fmt.Errorf("edit %d: relax %q requires a reason (recorded as the waiver justification)", i, id)
			}
		default:
			return fmt.Errorf("edit %d: unknown verb %q (want add, strengthen, or relax)", i, e.Verb)
		}
	}
	return nil
}
