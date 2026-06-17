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
