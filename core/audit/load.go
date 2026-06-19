// SPDX-License-Identifier: MIT

package audit

import (
	"fmt"
	"io"

	"gopkg.in/yaml.v3"
)

// LoadRuleSet decodes a YAML rule pack and validates it. Use this to load a
// custom organizational or team policy pack; DefaultRuleSet provides the
// built-in baseline.
func LoadRuleSet(r io.Reader) (RuleSet, error) {
	var rs RuleSet
	dec := yaml.NewDecoder(r)
	dec.KnownFields(true)
	if err := dec.Decode(&rs); err != nil {
		return RuleSet{}, fmt.Errorf("decode rule set: %w", err)
	}
	if err := rs.Validate(); err != nil {
		return RuleSet{}, fmt.Errorf("invalid rule set: %w", err)
	}
	return rs, nil
}

// LoadLayer decodes a YAML policy layer (an organizational standard or team
// layer of add/strengthen/relax edits) and validates it for well-formedness.
// Edits are validated against a base rule set only at Resolve time, where the
// target controls are known.
func LoadLayer(r io.Reader) (Layer, error) {
	var l Layer
	dec := yaml.NewDecoder(r)
	dec.KnownFields(true)
	if err := dec.Decode(&l); err != nil {
		return Layer{}, fmt.Errorf("decode policy layer: %w", err)
	}
	if err := l.Validate(); err != nil {
		return Layer{}, fmt.Errorf("invalid policy layer: %w", err)
	}
	return l, nil
}
