// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

package contract

import (
	"cmp"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/elliott-davis/lightsout/internal/pathglob"
)

// Access is what the contract stack allows for a path. Higher is more permissive (CON-7).
type Access int

// Access levels, from least to most permissive. The effective access of a path is the
// minimum over the contracts that cover it.
const (
	AccessForbidden Access = iota
	AccessNone
	AccessReadOnly
	AccessWritable
)

// String returns "forbidden", "none", "read-only" or "writable".
func (a Access) String() string {
	switch a {
	case AccessForbidden:
		return "forbidden"
	case AccessNone:
		return "none"
	case AccessReadOnly:
		return "read-only"
	case AccessWritable:
		return fieldWritable
	default:
		return fmt.Sprintf("access(%d)", int(a))
	}
}

// Valued is a resolved value and the source that set it: a contract file,
// [SourceInstallDefault] or [SourceBaseline].
type Valued[T any] struct {
	Value  T
	Source string
}

// Owner says who declared a gate.
type Owner string

// Gate owners (CON-5).
const (
	OwnerFactory  Owner = "factory"
	OwnerContract Owner = "contract"
)

// Obligation is a gate that a change must satisfy, merged over every declaration of the
// same identity and pinned revision. Mandatory is true if any declaration is mandatory.
// Name is the display name of the first declaration in source order. Owner is
// OwnerFactory if the baseline declares the gate.
type Obligation struct {
	Gate    Gate
	Owner   Owner
	Sources []string
}

// OracleObligation is a dark-merge oracle a change must satisfy. Observables is the sorted
// union over declarations with the same identity and revision.
type OracleObligation struct {
	Oracle  Oracle
	Sources []string
}

// Requirement is a reviewer role a change needs and who required it.
type Requirement struct {
	Role    string
	Sources []string
}

// Conflict reports one gate identity pinned at different revisions across the
// stacks of one change. Verify treats a conflict as a block.
type Conflict struct {
	Stage     string // "verify", "union" or "darkMergeOracle"
	Key       GateKey
	Revisions []string
	Sources   []string
}

// StackPolicy is what one stack of contracts contributes to a change: the
// contracts on it and the merged obligations of their declarations and the
// baseline. Every path on a stack shares it.
type StackPolicy struct {
	Stack       []string // contract files, root to leaf; empty for paths no contract covers
	VerifyGates []Obligation
	UnionGates  []Obligation
	Oracles     []OracleObligation
	Reviewers   []Requirement
}

// PathPolicy is the effective contract for one path.
//
// ForPath fills VerifyGates, UnionGates, Oracles and Reviewers. In the paths of
// an Effective they are nil: those lists are the same for every path on a
// stack, so Resolve returns them once per stack in Effective.Stacks, and
// StackIndex says which. StackIndex is meaningful only in an Effective.
//
// Patterns are anchored at the directory of the contract that declares them, so a
// pattern "*.pem" in certs/.factory.yaml matches certs/x.pem and not certs/a/x.pem
// or key.pem elsewhere. Use "**/*.pem" to match at any depth.
type PathPolicy struct {
	Path    string
	Covered bool     // false when no contract covers the path (CON-1)
	Stack   []string // covering contract files, root to leaf
	Access  Access
	// AccessSource is the shallowest contract file whose local verdict equals
	// Access, [SourceProtected] for a protected path, or "" if the path is uncovered.
	AccessSource string
	// Protected is true for contract files and the baseline's protected paths.
	// They are always AccessForbidden: contract changes go through their own
	// review path (CON-2, CON-6), never through an agent's change.
	Protected           bool
	Sensitive           bool
	SensitiveSources    []string
	Generated           Valued[bool]
	LightsOn            bool
	LightsOnSources     []string
	SwitchStaleDays     Valued[int]
	SwitchAbandonedDays Valued[int]
	ReviewBudgetLines   Valued[int]
	VerifyGates         []Obligation
	UnionGates          []Obligation
	Oracles             []OracleObligation
	Reviewers           []Requirement
	StackIndex          int // index into Effective.Stacks; set by Resolve only
}

// Effective is the effective contract for a change: the union of the stacks of every path
// it touches (CON-3).
type Effective struct {
	Revision string
	Paths    []PathPolicy // sorted by path, without duplicates
	// Stacks are the distinct stacks of the touched paths, root-most first.
	// Each path's StackIndex points into it.
	Stacks    []StackPolicy
	Uncovered []string
	// VerifyGates and UnionGates are keyed by gate identity and revision.
	VerifyGates []Obligation
	UnionGates  []Obligation
	Oracles     []OracleObligation
	Reviewers   []Requirement
	// SecuritySignoffRequired is true when a touched path is sensitive (SEC-5).
	SecuritySignoffRequired bool
	SecurityReviewer        string // the role whose sign-off a sensitive path needs
	SensitivePaths          []string
	LightsOn                bool // OR over every touched stack (CON-8 data)
	LightsOnSources         []string
	Conflicts               []Conflict
}

// MaxResolvePaths is the most paths one Resolve accepts. Work is also bounded
// by the Policy's budgets (see ErrTooComplex).
const MaxResolvePaths = 20000

// ErrTooComplex is wrapped by errors from ForPath and Resolve when the work
// exceeds its budget. The answer is unknown, so it fails closed: Verify treats
// it as a block.
var ErrTooComplex = errors.New("contract: path or change is too complex to resolve")

// ForPath resolves the effective contract for one path. An invalid path, or one
// with a form that is not a valid path, returns an error wrapping
// [pathglob.ErrInvalidPath], never an "allowed" result. A path that costs too
// much to evaluate returns an error wrapping [ErrTooComplex].
//
// PathPolicy carries raw repository path text. A consumer that writes it to a
// PR comment, check run or log must escape it first.
func (p *Policy) ForPath(path string) (PathPolicy, error) {
	b := &workBudget{limit: p.forPathBudget}
	pp, data, err := p.forPath(path, b)
	if err != nil {
		return PathPolicy{}, err
	}
	// One unit per obligation copied: a path pays for its own stack only.
	if b.spent += data.size(); b.over() {
		return PathPolicy{}, fmt.Errorf("resolve path %s: %w", quote(path), ErrTooComplex)
	}
	sp := data.stackPolicy()
	pp.VerifyGates, pp.UnionGates, pp.Oracles, pp.Reviewers = sp.VerifyGates, sp.UnionGates, sp.Oracles, sp.Reviewers
	return pp, nil
}

// forPath resolves everything about a path except the stack's obligations,
// which it returns as the shared stack data.
func (p *Policy) forPath(path string, b *workBudget) (PathPolicy, *stackData, error) {
	if err := pathglob.ValidatePath(path); err != nil {
		return PathPolicy{}, nil, fmt.Errorf("resolve path: %w", err)
	}
	forms, err := newPathForms(path)
	if err != nil {
		return PathPolicy{}, nil, fmt.Errorf("resolve path: %w", err)
	}
	stack := p.tree.stack(forms)
	pp := PathPolicy{Path: path, Covered: len(stack) > 0}
	data := p.root
	if len(stack) > 0 {
		data = stack[len(stack)-1].data
		pp.Stack = slices.Clone(data.files)
	}
	p.resolveAccess(&pp, stack, forms, b)
	p.resolveOverrides(&pp, stack, b, forms)
	pp.LightsOnSources = slices.Clone(data.lightsOn)
	pp.LightsOn = len(data.lightsOn) > 0
	if b.over() {
		return PathPolicy{}, nil, fmt.Errorf("resolve path %s: %w", quote(path), ErrTooComplex)
	}
	return pp, data, nil
}

// localAccess is the verdict of one contract for a path, and whether it has one.
//
// Forbidden matches in any form. ReadOnly matching the path as written gives
// ReadOnly. A readOnly match in a folded form only caps the level's own
// verdict at ReadOnly: it must never lift a path the level would call None, so
// "API/x" is None, not read-only, when writable is ["src/**"] and readOnly is ["api/**"].
func localAccess(l *level, path string, forms pathForms, b *workBudget) (Access, bool) {
	if anyDenies(l.forbidden, forms, b) {
		return AccessForbidden, true
	}
	if exactDenies(l.readOnly, forms, b) {
		return AccessReadOnly, true
	}
	readOnlyForm := otherDenies(l.readOnly, forms, b)
	if !l.hasWrite {
		if readOnlyForm {
			return AccessReadOnly, true
		}
		return AccessNone, false
	}
	for i := range l.writable {
		if l.writable[i].matchExact(path, forms, b) {
			if readOnlyForm {
				return AccessReadOnly, true
			}
			return AccessWritable, true
		}
	}
	return AccessNone, true
}

func (p *Policy) resolveAccess(pp *PathPolicy, stack []*level, forms pathForms, b *workBudget) {
	pp.Access = AccessNone
	have := false
	for _, l := range stack {
		if anyDenies(l.sensitive, forms, b) {
			pp.Sensitive = true
			pp.SensitiveSources = append(pp.SensitiveSources, l.file)
		}
		// A strict comparison keeps the shallowest contract among equal verdicts.
		if a, ok := localAccess(l, pp.Path, forms, b); ok && (!have || a < pp.Access) {
			pp.Access, pp.AccessSource, have = a, l.file, true
		}
	}
	if !have {
		// Unreachable for a validated Policy: the topmost contract declares writable.
		pp.Access, pp.AccessSource = AccessNone, ""
	}
	if anyDenies(p.protected, forms, b) {
		pp.Protected = true
		pp.Access, pp.AccessSource = AccessForbidden, SourceProtected
	}
}

func (p *Policy) resolveOverrides(pp *PathPolicy, stack []*level, b *workBudget, forms pathForms) {
	pp.Generated = Valued[bool]{Source: SourceInstallDefault}
	pp.SwitchStaleDays = Valued[int]{Value: p.defaults.SwitchStaleDays, Source: SourceInstallDefault}
	pp.SwitchAbandonedDays = Valued[int]{Value: p.defaults.SwitchAbandonedDays, Source: SourceInstallDefault}
	pp.ReviewBudgetLines = Valued[int]{Value: p.defaults.ReviewBudgetLines, Source: SourceInstallDefault}
	// Root to leaf, so a later (lower) declaration overwrites an earlier one.
	for _, l := range stack {
		if l.hasGen {
			pp.Generated = Valued[bool]{Source: l.file}
			for i := range l.generated {
				if l.generated[i].matchExact(pp.Path, forms, b) {
					pp.Generated.Value = true
				}
			}
		}
		if v := l.overrides.SwitchStaleDays; v != nil {
			pp.SwitchStaleDays = Valued[int]{Value: *v, Source: l.file}
		}
		if v := l.overrides.SwitchAbandonedDays; v != nil {
			pp.SwitchAbandonedDays = Valued[int]{Value: *v, Source: l.file}
		}
		if v := l.overrides.ReviewBudgetLines; v != nil {
			pp.ReviewBudgetLines = Valued[int]{Value: *v, Source: l.file}
		}
	}
}

// Resolve resolves the effective contract for a change touching paths. It returns an
// error if paths is empty or any path is invalid. The result does not depend on the order
// of paths or on duplicates.
func (p *Policy) Resolve(paths []string) (*Effective, error) {
	if len(paths) == 0 {
		return nil, errors.New("resolve change: no paths")
	}
	if len(paths) > MaxResolvePaths {
		return nil, fmt.Errorf("resolve change: %d paths, the limit is %d: %w", len(paths), MaxResolvePaths, ErrTooComplex)
	}
	total := &workBudget{limit: p.resolveBudget}
	tooComplex := func() error { return fmt.Errorf("resolve change: %w", ErrTooComplex) }
	uniq := slices.Clone(paths)
	slices.Sort(uniq)
	uniq = slices.Compact(uniq)
	eff := &Effective{Revision: p.revision, SecurityReviewer: p.base.SecurityReviewer, Paths: make([]PathPolicy, 0, len(uniq))}
	datas := make([]*stackData, 0, len(uniq))
	distinct := map[*stackData]bool{}
	for _, path := range uniq {
		per := &workBudget{limit: p.forPathBudget}
		pp, data, err := p.forPath(path, per)
		if err != nil {
			return nil, err
		}
		if total.spent += per.spent; total.over() {
			return nil, tooComplex()
		}
		eff.Paths = append(eff.Paths, pp)
		datas = append(datas, data)
		distinct[data] = true
		if !pp.Covered {
			eff.Uncovered = append(eff.Uncovered, path)
		}
		if pp.Sensitive {
			eff.SensitivePaths = append(eff.SensitivePaths, path)
		}
	}
	// Every path on a stack shares the stack's obligations, so the change-level
	// union costs per distinct stack, not per path.
	stacks := make([]*stackData, 0, len(distinct))
	for d := range distinct {
		stacks = append(stacks, d)
	}
	slices.SortFunc(stacks, func(a, b *stackData) int {
		if c := len(a.files) - len(b.files); c != 0 {
			return c
		}
		return slices.Compare(a.files, b.files)
	})
	index := make(map[*stackData]int, len(stacks))
	var verify, union []Obligation
	var oracles []OracleObligation
	var reviewers []Requirement
	var lightsOn []string
	for i, d := range stacks {
		index[d] = i
		if total.spent += d.size(); total.over() {
			return nil, tooComplex()
		}
		sp := d.stackPolicy()
		eff.Stacks = append(eff.Stacks, sp)
		verify = append(verify, sp.VerifyGates...)
		union = append(union, sp.UnionGates...)
		oracles = append(oracles, sp.Oracles...)
		reviewers = append(reviewers, sp.Reviewers...)
		lightsOn = append(lightsOn, d.lightsOn...)
	}
	for i := range eff.Paths {
		eff.Paths[i].StackIndex = index[datas[i]]
	}
	if total.spent += workUnits(len(verify)) + workUnits(len(union)) + workUnits(len(oracles)) + workUnits(len(reviewers)); total.over() {
		return nil, tooComplex()
	}
	eff.VerifyGates = mergeObligations(verify)
	eff.UnionGates = mergeObligations(union)
	eff.Oracles = mergeOracles(oracles)
	eff.Reviewers = mergeRequirements(reviewers)
	eff.SecuritySignoffRequired = len(eff.SensitivePaths) > 0
	eff.LightsOnSources = sortSources(lightsOn)
	eff.LightsOn = len(eff.LightsOnSources) > 0
	eff.Conflicts = conflicts(eff)
	return eff, nil
}

// sourceRank orders sources root to leaf: the baseline, then the install
// default, then contract files by depth.
func sourceRank(s string) int {
	switch s {
	case SourceBaseline:
		return -2
	case SourceInstallDefault:
		return -1
	}
	return strings.Count(s, "/")
}

func compareSources(a, b string) int {
	return cmp.Or(cmp.Compare(sourceRank(a), sourceRank(b)), strings.Compare(a, b))
}

// sortSources returns a sorted, deduplicated copy of s. It returns nil for an empty s.
func sortSources(s []string) []string {
	if len(s) == 0 {
		return nil
	}
	out := slices.Clone(s)
	slices.SortFunc(out, compareSources)
	return slices.Compact(out)
}

func compareKeys(a, b GateKey) int {
	return cmp.Or(
		strings.Compare(a.ProducerID, b.ProducerID),
		strings.Compare(string(a.WorkflowID), string(b.WorkflowID)),
		strings.Compare(a.CheckID, b.CheckID),
	)
}

func firstSource(s []string) string {
	if len(s) == 0 {
		return ""
	}
	return s[0]
}

// identity is a gate obligation key: identity plus pinned revision.
type identity struct {
	key GateKey
	rev string
}

// mergeObligations merges obligations with the same identity and revision. The display
// name comes from the declaration whose first source sorts earliest, so the result does
// not depend on input order. The output is sorted by identity and revision.
func mergeObligations(in []Obligation) []Obligation {
	in = slices.Clone(in)
	slices.SortStableFunc(in, func(a, b Obligation) int {
		return cmp.Or(compareSources(firstSource(a.Sources), firstSource(b.Sources)), strings.Compare(a.Gate.Name, b.Gate.Name))
	})
	idx := map[identity]int{}
	var out []Obligation
	for i := range in {
		o := in[i]
		id := identity{o.Gate.Key(), o.Gate.WorkflowRevision}
		i, ok := idx[id]
		if !ok {
			idx[id] = len(out)
			o.Sources = sortSources(o.Sources)
			out = append(out, o)
			continue
		}
		m := &out[i]
		m.Gate.Mandatory = m.Gate.Mandatory || o.Gate.Mandatory
		// The first declaration's owner stands: inputs are sorted by source, and the
		// baseline sorts before every contract file, so a factory declaration is
		// always the first.
		m.Sources = sortSources(append(m.Sources, o.Sources...))
	}
	slices.SortFunc(out, func(a, b Obligation) int {
		return cmp.Or(compareKeys(a.Gate.Key(), b.Gate.Key()), strings.Compare(a.Gate.WorkflowRevision, b.Gate.WorkflowRevision))
	})
	return out
}

// mergeOracles merges oracles like [mergeObligations]. Oracles are always mandatory.
func mergeOracles(in []OracleObligation) []OracleObligation {
	in = slices.Clone(in)
	slices.SortStableFunc(in, func(a, b OracleObligation) int {
		return cmp.Or(compareSources(firstSource(a.Sources), firstSource(b.Sources)), strings.Compare(a.Oracle.Name, b.Oracle.Name))
	})
	idx := map[identity]int{}
	var out []OracleObligation
	for i := range in {
		o := in[i]
		id := identity{o.Oracle.Key(), o.Oracle.WorkflowRevision}
		i, ok := idx[id]
		if !ok {
			idx[id] = len(out)
			o.Sources = sortSources(o.Sources)
			o.Oracle.Observables = sortedObservables(o.Oracle.Observables)
			out = append(out, o)
			continue
		}
		m := &out[i]
		m.Oracle.Observables = sortedObservables(append(slices.Clone(m.Oracle.Observables), o.Oracle.Observables...))
		m.Sources = sortSources(append(m.Sources, o.Sources...))
	}
	slices.SortFunc(out, func(a, b OracleObligation) int {
		return cmp.Or(compareKeys(a.Oracle.Key(), b.Oracle.Key()), strings.Compare(a.Oracle.WorkflowRevision, b.Oracle.WorkflowRevision))
	})
	return out
}

func sortedObservables(o []Observable) []Observable {
	out := slices.Clone(o)
	slices.Sort(out)
	return slices.Compact(out)
}

func mergeRequirements(in []Requirement) []Requirement {
	idx := map[string]int{}
	var out []Requirement
	for _, r := range in {
		i, ok := idx[r.Role]
		if !ok {
			idx[r.Role] = len(out)
			out = append(out, Requirement{Role: r.Role, Sources: sortSources(r.Sources)})
			continue
		}
		out[i].Sources = sortSources(append(out[i].Sources, r.Sources...))
	}
	slices.SortFunc(out, func(a, b Requirement) int { return strings.Compare(a.Role, b.Role) })
	return out
}

// pin is one identity pinned at one revision by some sources.
type pin struct {
	key     GateKey
	rev     string
	sources []string
}

// conflicts finds identities pinned at more than one revision in the same change.
func conflicts(eff *Effective) []Conflict {
	var verify, union, oracles []pin
	for i := range eff.VerifyGates {
		o := &eff.VerifyGates[i]
		verify = append(verify, pin{o.Gate.Key(), o.Gate.WorkflowRevision, o.Sources})
	}
	for i := range eff.UnionGates {
		o := &eff.UnionGates[i]
		union = append(union, pin{o.Gate.Key(), o.Gate.WorkflowRevision, o.Sources})
	}
	for i := range eff.Oracles {
		o := &eff.Oracles[i]
		oracles = append(oracles, pin{o.Oracle.Key(), o.Oracle.WorkflowRevision, o.Sources})
	}
	var out []Conflict
	out = append(out, stageConflicts("verify", verify)...)
	out = append(out, stageConflicts("union", union)...)
	out = append(out, stageConflicts("darkMergeOracle", oracles)...)
	slices.SortFunc(out, func(a, b Conflict) int {
		return cmp.Or(strings.Compare(a.Stage, b.Stage), compareKeys(a.Key, b.Key))
	})
	return out
}

func stageConflicts(stage string, pins []pin) []Conflict {
	type entry struct {
		revs    []string
		sources []string
	}
	byKey := map[GateKey]*entry{}
	for _, r := range pins {
		e := byKey[r.key]
		if e == nil {
			e = &entry{}
			byKey[r.key] = e
		}
		e.revs = append(e.revs, r.rev)
		e.sources = append(e.sources, r.sources...)
	}
	var out []Conflict
	for k, e := range byKey {
		slices.Sort(e.revs)
		if revs := slices.Compact(e.revs); len(revs) > 1 {
			out = append(out, Conflict{Stage: stage, Key: k, Revisions: revs, Sources: sortSources(e.sources)})
		}
	}
	return out
}
