// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

package contract

import (
	"errors"
	"fmt"
	"regexp"
	"slices"

	"github.com/elliott-davis/lightsout/internal/pathglob"
)

// Value sources that are not contract files.
const (
	// SourceInstallDefault marks a value that came from the install defaults (CON-9).
	SourceInstallDefault = "install default"
	// SourceBaseline marks a value that came from the factory baseline (CON-5, AGD-3).
	SourceBaseline = "factory baseline"
	// SourceProtected marks an access verdict that comes from a protected path:
	// a contract file, or a pattern in Baseline.Protected.
	SourceProtected = "factory protected path"
)

// MaxStackDepth is the most contracts one path may have on its stack. Compile
// rejects a deeper tree (CodeTooMany) so that resolving a path stays cheap.
const MaxStackDepth = 32

// Work budgets, in the units of matchWork (rune comparisons, roughly). Each is
// the most work one operation may do before it fails closed. They were set
// from the worst measured cost of a unit, about 3 ns (BenchmarkUnitCost_*, see
// docs/design/contracts.md), so that the worst case is about 2 s for Compile,
// 50 ms for ForPath and 5 s for Resolve.
const (
	defaultCompileBudget int64 = 650_000_000
	defaultForPathBudget int64 = 16_000_000
	defaultResolveBudget int64 = 1_600_000_000
)

// budgets are the work limits of a Policy. Tests lower them.
type budgets struct {
	compile, forPath, resolve int64
}

func defaultBudgets() budgets {
	return budgets{compile: defaultCompileBudget, forPath: defaultForPathBudget, resolve: defaultResolveBudget}
}

// Baseline is the factory's own policy from install config: gates no contract
// can waive and reviewers every change gets. WI-07 produces it.
type Baseline struct {
	// Verify holds the factory's baseline Verify gates. All must be Mandatory (CON-5).
	Verify []Gate
	// Union holds the factory's baseline Union gates. All must be Mandatory.
	Union []Gate
	// Reviewers are the core verify reviewers, such as "pr-reviewer" and
	// "security-reviewer" (AGD-3). Every change gets them.
	Reviewers []string
	// SecurityReviewer is the role that signs off sensitive paths (SEC-5). It
	// must be one of Reviewers.
	SecurityReviewer string
	// PRReviewer is the role that reviews every change (AGD-3). It must be one of
	// Reviewers.
	PRReviewer string
	// Protected are root-anchored patterns, such as ".github/workflows/**" and
	// "CODEOWNERS", that agents may never change. They are matched with the deny
	// rules (descendants, folded forms). Contract files are always protected.
	Protected []string
	// KnownAgents lists every agent name a contract may put under agents.verify.
	// Reviewers are implicitly known.
	KnownAgents []string
	// InstallRevision is the commit of the install config this baseline came from:
	// 40 or 64 lowercase hex digits, or empty in tests that build a baseline by
	// hand. It is part of the policy identity: Effective carries it and the trust
	// digest covers it, so changing a baseline gate can never leave the identity of
	// the evidence unchanged.
	InstallRevision string
}

// Defaults are the install-wide values that contracts override (CON-9). Each must be at least 1.
type Defaults struct {
	SwitchStaleDays     int
	SwitchAbandonedDays int
	ReviewBudgetLines   int
}

// Policy is the immutable compiled form of a Set that passed relational
// validation. It is safe for concurrent use.
type Policy struct {
	revision string
	tree     *tree
	base     Baseline
	defaults Defaults
	known    map[string]bool
	// Work limits (see budgets). They are fields so tests can lower them.
	compileBudget, forPathBudget, resolveBudget int64
	compileSpent                                int64 // work Compile spent validating, for tests and tuning
	// protected matches paths no contract may open up: contract files and Baseline.Protected.
	protected []pat
	root      *stackData // baseline-only stack data, for paths no contract covers
}

// Compile validates every contract in set against the others and the
// baseline, and compiles the result for resolving. It does not trust set:
// NewSet accepts hand-built contracts, so Compile re-checks apiVersion and kind
// and recompiles every pattern. It collects every problem and fails closed: any
// problem returns a *ValidationError and no Policy. A bad Baseline, bad
// Defaults or a nil set returns a plain error.
func Compile(set *Set, b Baseline, d Defaults) (*Policy, error) {
	return compile(set, b, d, defaultBudgets())
}

func compile(set *Set, b Baseline, d Defaults, limits budgets) (*Policy, error) {
	p, problems, err := analyze(set, b, d, limits, nil)
	if err != nil {
		return nil, err
	}
	if len(problems) > 0 {
		return nil, newValidationError(problems)
	}
	return p, nil
}

// analyze is the one path Compile and ValidateChanged share: build the levels,
// run the per-contract and relational checks, and build the stacks. scope nil
// means every contract (Compile). Otherwise only the directories in scope are
// schema-checked and validated, and the problems of the others are dropped:
// they were validated at their trusted revision (CON-13).
func analyze(set *Set, b Baseline, d Defaults, limits budgets, scope []string) (*Policy, []Problem, error) {
	if set == nil {
		return nil, nil, errors.New("compile policy: nil contract set")
	}
	parser, err := NewParser()
	if err != nil {
		return nil, nil, fmt.Errorf("compile policy: %w", err)
	}
	if err = checkBaseline(parser, b); err != nil {
		return nil, nil, fmt.Errorf("compile policy: %w", err)
	}
	if err = checkDefaults(d); err != nil {
		return nil, nil, fmt.Errorf("compile policy: %w", err)
	}
	protected, err := compileProtected(b.Protected)
	if err != nil {
		return nil, nil, fmt.Errorf("compile policy: %w", err)
	}
	dirs := set.Dirs()
	if scope != nil {
		dirs = scope
	}
	// NewSet accepts hand-built contracts, so check each against the schema too.
	var problems []Problem
	for _, dir := range dirs {
		c, ok := set.Get(dir)
		if !ok {
			continue
		}
		problems = append(problems, parser.validateContract(filePath(dir), c)...)
	}
	t, tp := buildTree(set)
	if scope != nil {
		in := make(map[string]bool, len(scope))
		for _, dir := range scope {
			in[filePath(dir)] = true
		}
		tp = slices.DeleteFunc(tp, func(pr Problem) bool { return !in[pr.File] })
	}
	p := &Policy{
		revision:  set.Revision(),
		tree:      t,
		base:      cloneBaseline(b),
		defaults:  d,
		known:     knownAgents(b),
		protected: protected,
		root:      baselineStack(b),

		compileBudget: limits.compile, forPathBudget: limits.forPath, resolveBudget: limits.resolve,
	}
	problems = append(problems, tp...)
	validateDirs := t.dirs
	if scope != nil {
		validateDirs = scope
	}
	vp, spent := p.validate(validateDirs)
	p.compileSpent = spent
	return p, append(problems, vp...), nil
}

// compileProtected compiles the contract file names and the baseline's
// protected patterns. Contract changes go through their own review path
// (CON-2, CON-6), so an agent must never be able to write one.
func compileProtected(extra []string) ([]pat, error) {
	var out []pat
	for _, text := range append([]string{"**/" + FileName, "**/" + misnamedFile}, extra...) {
		p, err := compilePat(text, "")
		if err != nil {
			return nil, fmt.Errorf("protected pattern %s: %w", quote(text), err)
		}
		out = append(out, p)
	}
	return out, nil
}

// Revision is the commit the contract set was read from.
func (p *Policy) Revision() string { return p.revision }

// agentName is the schema's pattern for an agent name (agents.verify items).
var agentName = regexp.MustCompile(`^[a-z][a-z0-9-]{0,63}$`)

// installRevision is the form of Baseline.InstallRevision: a full commit ID.
var installRevision = regexp.MustCompile(`^([0-9a-f]{40}|[0-9a-f]{64})$`)

func checkBaseline(parser *Parser, b Baseline) error {
	if b.InstallRevision != "" && !installRevision.MatchString(b.InstallRevision) {
		return fmt.Errorf("baseline install revision %s must be 40 or 64 lowercase hex digits", quote(b.InstallRevision))
	}
	// Hold the baseline's gates to the schema, like any contract's, by checking
	// a synthetic contract that carries them.
	synthetic := &Contract{
		APIVersion: APIVersion, Kind: Kind,
		Paths: Paths{Writable: &[]string{}},
		Gates: Gates{Verify: b.Verify, Union: b.Union},
	}
	if ps := parser.validateContract("baseline", synthetic); len(ps) > 0 {
		return fmt.Errorf("baseline gates are invalid: %s", ps[0])
	}
	for _, stage := range []struct {
		name  string
		gates []Gate
	}{{stageVerify, b.Verify}, {stageUnion, b.Union}} {
		seen := map[GateKey]bool{}
		for i, g := range stage.gates {
			if !g.Mandatory {
				return fmt.Errorf("baseline %s gate %d (%s) must be mandatory", stage.name, i, quote(g.Name))
			}
			if seen[g.Key()] {
				return fmt.Errorf("baseline %s gate %d (%s) duplicates an earlier gate identity", stage.name, i, quote(g.Name))
			}
			seen[g.Key()] = true
		}
	}
	for _, name := range slices.Concat(b.Reviewers, b.KnownAgents) {
		if !agentName.MatchString(name) {
			return fmt.Errorf("baseline agent name %s is not a valid agent name", quote(name))
		}
	}
	if !slices.Contains(b.Reviewers, b.SecurityReviewer) {
		return fmt.Errorf("baseline security reviewer %s must be one of the baseline reviewers", quote(b.SecurityReviewer))
	}
	if !slices.Contains(b.Reviewers, b.PRReviewer) {
		return fmt.Errorf("baseline PR reviewer %s must be one of the baseline reviewers", quote(b.PRReviewer))
	}
	if b.PRReviewer == b.SecurityReviewer {
		return fmt.Errorf("baseline PR reviewer and security reviewer must be different roles, both are %s", quote(b.PRReviewer))
	}
	return nil
}

func checkDefaults(d Defaults) error {
	for _, f := range []struct {
		name string
		v    int
	}{
		{"SwitchStaleDays", d.SwitchStaleDays},
		{"SwitchAbandonedDays", d.SwitchAbandonedDays},
		{"ReviewBudgetLines", d.ReviewBudgetLines},
	} {
		if f.v < 1 {
			return fmt.Errorf("default %s must be at least 1, got %d", f.name, f.v)
		}
	}
	return nil
}

func cloneBaseline(b Baseline) Baseline {
	b.Verify = slices.Clone(b.Verify)
	b.Union = slices.Clone(b.Union)
	b.Reviewers = slices.Clone(b.Reviewers)
	b.KnownAgents = slices.Clone(b.KnownAgents)
	b.Protected = slices.Clone(b.Protected)
	return b
}

func knownAgents(b Baseline) map[string]bool {
	m := make(map[string]bool, len(b.KnownAgents)+len(b.Reviewers))
	for _, a := range b.KnownAgents {
		m[a] = true
	}
	for _, r := range b.Reviewers {
		m[r] = true
	}
	return m
}

// level is one contract compiled for evaluation. Patterns are anchored at the
// contract's directory. Everything is copied from the Contract, so later
// changes to the Set's contracts cannot change a Policy.
type level struct {
	dir       string
	file      string   // repo-relative contract file, also the value source
	keys      []string // dirKey of each segment of dir; nil for the root
	keyStr    string   // keys joined with "/": the canonical identity of the directory
	writable  []pat
	hasWrite  bool // writable declared, possibly empty
	readOnly  []pat
	forbidden []pat
	sensitive []pat
	generated []pat
	hasGen    bool // generated declared, possibly empty
	lightsOn  *bool
	overrides Overrides
	verify    []Gate
	union     []Gate
	oracle    *Oracle
	agents    []string

	data *stackData // merged obligations of this stack; set by buildStacks
	up   *stackData // the parent's data, for the gate checks

	writableExact []pathglob.Pattern // writable patterns, case-sensitive
	reach         []pathglob.Pattern // writable and readOnly (with descendants) patterns
}
