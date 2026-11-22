// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

package contract

// RuleClass says how a contract field combines down the tree (CON-12).
type RuleClass string

// Rule classes.
const (
	// RuleMeta marks fields that identify the document and are not merged.
	RuleMeta RuleClass = "meta"
	// RuleSafetyNarrow marks a safety field that can only get narrower: a path is
	// allowed only if every level that declares the field allows it.
	RuleSafetyNarrow RuleClass = "safety-narrow"
	// RuleSafetyAccumulate marks a safety field whose entries add up down the
	// tree and can never be removed.
	RuleSafetyAccumulate RuleClass = "safety-accumulate"
	// RuleSafetyOnlyOn marks a safety flag that can be turned on but never off.
	RuleSafetyOnlyOn RuleClass = "safety-only-on"
	// RuleOverride marks a field where the lowest level that sets it wins, else
	// the install default (CON-9).
	RuleOverride RuleClass = "override"
)

// String returns the class name.
func (c RuleClass) String() string { return string(c) }

// fieldRules maps the JSON pointer of every schema leaf to its merge rule
// (CON-12). It is a function, not a package variable, so nothing can mutate it.
// A test walks the embedded schema and fails if a leaf has no rule or a rule
// names a field that is not in the schema.
func fieldRules() map[string]RuleClass {
	return map[string]RuleClass{
		"/apiVersion":                    RuleMeta,
		"/kind":                          RuleMeta,
		"/paths/writable":                RuleSafetyNarrow,
		"/paths/readOnly":                RuleSafetyAccumulate,
		"/paths/forbidden":               RuleSafetyAccumulate,
		"/paths/sensitive":               RuleSafetyAccumulate,
		"/paths/generated":               RuleOverride,
		"/gates/verify":                  RuleSafetyAccumulate,
		"/gates/union":                   RuleSafetyAccumulate,
		"/gates/darkMergeOracle":         RuleSafetyAccumulate,
		"/agents/verify":                 RuleSafetyAccumulate,
		"/lightsOn":                      RuleSafetyOnlyOn,
		"/overrides/switchStaleDays":     RuleOverride,
		"/overrides/switchAbandonedDays": RuleOverride,
		"/overrides/reviewBudgetLines":   RuleOverride,
	}
}
