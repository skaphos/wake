// SPDX-License-Identifier: MIT

// Package policyfile loads Wake policy inputs from files on disk: a base rule
// pack, the org/team policy layers composed over it, and per-repo ownership
// overrides. It is the shared file-IO seam between the `wake audit` and `wake
// teams` commands, keeping the decode/validate path in one place.
package policyfile

import (
	"fmt"
	"os"

	"github.com/skaphos/wake-core/audit"
	"github.com/skaphos/wake-core/ownership"
)

// RuleSet opens and decodes a YAML rule pack from path.
func RuleSet(path string) (audit.RuleSet, error) {
	f, err := os.Open(path)
	if err != nil {
		return audit.RuleSet{}, fmt.Errorf("open rule pack: %w", err)
	}
	defer func() { _ = f.Close() }()
	rs, err := audit.LoadRuleSet(f)
	if err != nil {
		return audit.RuleSet{}, err
	}
	return rs, nil
}

// Layers reads the optional org and team policy layers (in that order),
// skipping any path left empty. The returned slice is ordered for Resolve.
func Layers(orgPath, teamPath string) ([]audit.Layer, error) {
	var layers []audit.Layer
	for _, p := range []struct{ role, path string }{{"org", orgPath}, {"team", teamPath}} {
		if p.path == "" {
			continue
		}
		f, err := os.Open(p.path)
		if err != nil {
			return nil, fmt.Errorf("open %s layer: %w", p.role, err)
		}
		l, err := audit.LoadLayer(f)
		_ = f.Close()
		if err != nil {
			return nil, fmt.Errorf("%s layer: %w", p.role, err)
		}
		layers = append(layers, l)
	}
	return layers, nil
}

// Overrides reads an optional ownership-override file, returning no overrides
// when path is empty.
func Overrides(path string) ([]ownership.Override, error) {
	if path == "" {
		return nil, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open ownership overrides: %w", err)
	}
	defer func() { _ = f.Close() }()
	cfg, err := ownership.LoadOverrides(f)
	if err != nil {
		return nil, err
	}
	return cfg.Overrides, nil
}
