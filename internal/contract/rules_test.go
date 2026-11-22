// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

package contract

import (
	"encoding/json"
	"maps"
	"slices"
	"strings"
	"testing"
)

func TestFieldRules_CoverSchema(t *testing.T) { // CON-12
	t.Parallel()
	var doc map[string]any
	if err := json.Unmarshal(SchemaJSON(), &doc); err != nil {
		t.Fatal(err)
	}
	rules := fieldRules()
	reached := map[string]bool{}
	// A property is a leaf if it has a rule. Otherwise it must be an object with
	// properties, reached directly or through a $ref. Keywords that could hide a
	// field from this walk are failures, so a field added that way cannot be skipped.
	resolve := func(ptr string, node map[string]any) map[string]any {
		ref, ok := node["$ref"].(string)
		if !ok {
			return node
		}
		name, found := strings.CutPrefix(ref, "#/$defs/")
		defs, _ := doc["$defs"].(map[string]any)
		target, _ := defs[name].(map[string]any)
		if !found || target == nil {
			t.Errorf("%s: cannot resolve $ref %q", ptr, ref)
			return node
		}
		return target
	}
	var walk func(ptr string, node map[string]any)
	walk = func(ptr string, node map[string]any) {
		for _, kw := range []string{"allOf", "anyOf", "oneOf", "patternProperties", "if", "then", "else", "dependentSchemas", "unevaluatedProperties"} {
			if _, ok := node[kw]; ok {
				t.Errorf("%s: schema keyword %q is not handled by the rule walk", ptr, kw)
			}
		}
		if ap, ok := node["additionalProperties"]; ok && ap != false {
			t.Errorf("%s: additionalProperties %v is not handled by the rule walk", ptr, ap)
		}
		props, _ := node["properties"].(map[string]any)
		for name, raw := range props {
			child := ptr + "/" + name
			sub, _ := raw.(map[string]any)
			if _, ok := rules[child]; ok {
				// A rule-bearing property is a leaf: do not look inside arrays or $ref targets.
				reached[child] = true
				continue
			}
			sub = resolve(child, sub)
			if _, nested := sub["properties"]; !nested {
				t.Errorf("schema leaf %s has no merge rule", child)
				continue
			}
			walk(child, sub)
		}
	}
	walk("", doc)
	for key := range rules {
		if !reached[key] {
			t.Errorf("rule %s names a field that is not in the schema", key)
		}
	}
	for key, class := range rules {
		if class.String() == "" {
			t.Errorf("rule %s has an empty class", key)
		}
	}
}

func TestFieldRules_EveryRuleFieldParses(t *testing.T) { // CON-12
	t.Parallel()
	gate := "gates:\n  verify:\n" + gateItem("a", rev40, true)
	tests := map[string]struct {
		yaml string
		set  func(*Contract) bool
	}{
		"/apiVersion":                {"", func(c *Contract) bool { return c.APIVersion != "" }},
		"/kind":                      {"", func(c *Contract) bool { return c.Kind != "" }},
		"/paths/writable":            {"paths:\n  writable: ['**']\n", func(c *Contract) bool { return c.Paths.Writable != nil && len(*c.Paths.Writable) > 0 }},
		"/paths/readOnly":            {"paths:\n  readOnly: ['a']\n", func(c *Contract) bool { return len(c.Paths.ReadOnly) > 0 }},
		"/paths/forbidden":           {"paths:\n  forbidden: ['a']\n", func(c *Contract) bool { return len(c.Paths.Forbidden) > 0 }},
		"/paths/sensitive":           {"paths:\n  sensitive: ['a']\n", func(c *Contract) bool { return len(c.Paths.Sensitive) > 0 }},
		"/paths/generated":           {"paths:\n  generated: ['a']\n", func(c *Contract) bool { return c.Paths.Generated != nil && len(*c.Paths.Generated) > 0 }},
		"/gates/verify":              {gate, func(c *Contract) bool { return len(c.Gates.Verify) > 0 }},
		"/gates/union":               {strings.Replace(gate, "verify", "union", 1), func(c *Contract) bool { return len(c.Gates.Union) > 0 }},
		"/gates/darkMergeOracle":     {"gates:\n  darkMergeOracle:\n    producerId: github-app:1\n    workflowId: 7\n    workflowRevision: " + rev40 + "\n    checkId: o\n    observables: [reads]\n" + manifestLine, func(c *Contract) bool { return c.Gates.DarkMergeOracle != nil }},
		"/agents/verify":             {"agents:\n  verify: [payments-specialist]\n", func(c *Contract) bool { return len(c.Agents.Verify) > 0 }},
		"/lightsOn":                  {"lightsOn: true\n", func(c *Contract) bool { return c.LightsOn != nil }},
		"/overrides/switchStaleDays": {"overrides:\n  switchStaleDays: 3\n", func(c *Contract) bool { return c.Overrides.SwitchStaleDays != nil && *c.Overrides.SwitchStaleDays == 3 }},
		"/overrides/switchAbandonedDays": {"overrides:\n  switchAbandonedDays: 3\n", func(c *Contract) bool {
			return c.Overrides.SwitchAbandonedDays != nil && *c.Overrides.SwitchAbandonedDays == 3
		}},
		"/overrides/reviewBudgetLines": {"overrides:\n  reviewBudgetLines: 3\n", func(c *Contract) bool {
			return c.Overrides.ReviewBudgetLines != nil && *c.Overrides.ReviewBudgetLines == 3
		}},
	}
	rules := fieldRules()
	if got, want := slices.Sorted(maps.Keys(tests)), slices.Sorted(maps.Keys(rules)); !slices.Equal(got, want) {
		t.Fatalf("drift table keys = %v, rule keys = %v", got, want)
	}
	p := newParser(t)
	for key, tt := range tests {
		c, err := p.Parse("", []byte(head+tt.yaml))
		if err != nil {
			t.Errorf("%s: parse: %v", key, err)
			continue
		}
		if !tt.set(c) {
			t.Errorf("%s: the Go field is zero after parsing", key)
		}
	}
}
