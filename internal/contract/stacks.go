// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

package contract

import (
	"cmp"
	"fmt"
	"math/bits"
	"slices"
	"strings"
)

// MaxStackGates is the most gate obligations one stage (verify or union) may
// have on any stack, counting the baseline's. Compile rejects a deeper
// accumulation (CodeTooMany) so the merged data can never be huge.
const MaxStackGates = 512

// stackData is everything a stack contributes that does not depend on the
// path: the contracts on it and the merged obligations of their declarations
// and the baseline. Stacks are chains, so each contract has exactly one,
// built once at Compile from its parent's. It is immutable after Compile, and
// shared by every path on that stack: callers get copies.
type stackData struct {
	files     []string // contract files, root to leaf; nil for the baseline-only stack
	verify    []Obligation
	union     []Obligation
	oracles   []OracleObligation
	reviewers []Requirement
	lightsOn  []string // files that turn lights-on on

	// idx indexes verify and union by gate identity, for the relational checks
	// of the children. It is built only for a stack that has children.
	idx [2]map[GateKey]gateInfo
}

// gateInfo is what a stack says about one gate identity: the revision and
// who pinned it first, and who first made it mandatory.
type gateInfo struct {
	rev, revSource, mandSource string
}

// workUnits is the cost of sorting or merging n items: one unit per item
// plus n log n.
func workUnits(n int) int64 {
	if n <= 1 {
		return int64(n)
	}
	return int64(n) * int64(1+bits.Len(uint(n)))
}

// baselineStack is the stack of a path no contract covers: the baseline alone.
func baselineStack(b Baseline) *stackData {
	d := &stackData{}
	for _, g := range b.Verify {
		d.verify = append(d.verify, Obligation{Gate: g, Owner: OwnerFactory, Sources: []string{SourceBaseline}})
	}
	for _, g := range b.Union {
		d.union = append(d.union, Obligation{Gate: g, Owner: OwnerFactory, Sources: []string{SourceBaseline}})
	}
	for _, r := range b.Reviewers {
		d.reviewers = append(d.reviewers, Requirement{Role: r, Sources: []string{SourceBaseline}})
	}
	d.verify, d.union, d.reviewers = mergeObligations(d.verify), mergeObligations(d.union), mergeRequirements(d.reviewers)
	for i, gs := range [][]Gate{b.Verify, b.Union} {
		d.idx[i] = map[GateKey]gateInfo{}
		for _, g := range gs {
			d.idx[i][g.Key()] = gateInfo{rev: g.WorkflowRevision, revSource: SourceBaseline, mandSource: SourceBaseline}
		}
	}
	return d
}

func compareObligationID(a, b Obligation) int {
	return cmp.Or(compareKeys(a.Gate.Key(), b.Gate.Key()), strings.Compare(a.Gate.WorkflowRevision, b.Gate.WorkflowRevision))
}

// extendObligations adds a contract's own declarations to its parent's merged
// list in one linear pass. own is merged first (it is at most 64 gates). Where
// an identity is already in the parent's list, the parent's declaration stays
// first (it has the earlier source), mandatory is OR'd and the own source is
// appended, which keeps sources sorted because a contract's file is deeper
// than every ancestor's. The result is sorted by identity and revision. Sources
// the merge doesn't change are shared with the parent, which is safe because
// they are never modified.
func extendObligations(parent, own []Obligation) []Obligation {
	own = mergeObligations(own)
	out := make([]Obligation, 0, len(parent)+len(own))
	i, j := 0, 0
	for i < len(parent) || j < len(own) {
		switch {
		case j == len(own), i < len(parent) && compareObligationID(parent[i], own[j]) < 0:
			out = append(out, parent[i])
			i++
		case i == len(parent), compareObligationID(parent[i], own[j]) > 0:
			out = append(out, own[j])
			j++
		default:
			m := parent[i]
			m.Gate.Mandatory = m.Gate.Mandatory || own[j].Gate.Mandatory
			m.Sources = append(slices.Clone(m.Sources), own[j].Sources...)
			out = append(out, m)
			i++
			j++
		}
	}
	return out
}

// buildStacks computes the stack data of every compiled contract, root first,
// charging the work to c. A contract whose stack would hold more than
// MaxStackGates obligations in a stage is reported (when it is in scope) and
// gets no data, so neither do its descendants. It returns false if any
// problem was reported or the budget ran out.
func (p *Policy) buildStacks(c *collector, scope map[string]bool) bool {
	hasChild := map[*level]bool{}
	for _, dir := range p.tree.dirs {
		l := p.tree.levels[dir]
		if anc := p.tree.ancestors(l); len(anc) > 0 {
			hasChild[anc[len(anc)-1]] = true
		}
	}
	ok := true
	for _, dir := range p.tree.dirs {
		l := p.tree.levels[dir]
		if _, collides := p.tree.collide[dir]; collides {
			continue
		}
		anc := p.tree.ancestors(l)
		if len(anc) >= MaxStackDepth {
			continue
		}
		parent := p.root
		if len(anc) > 0 {
			parent = anc[len(anc)-1].data
		}
		l.up = parent
		if parent == nil {
			continue // an ancestor crossed the limit and was reported
		}
		if !c.spend(workUnits(len(parent.verify)+len(l.verify))+workUnits(len(parent.union)+len(l.union)), l.file) {
			return false
		}
		d := &stackData{
			files:     append(slices.Clone(parent.files), l.file),
			verify:    extendObligations(parent.verify, ownObligations(l.verify, l.file)),
			union:     extendObligations(parent.union, ownObligations(l.union, l.file)),
			reviewers: mergeRequirements(append(slices.Clone(parent.reviewers), ownRequirements(l)...)),
			lightsOn:  slices.Clone(parent.lightsOn),
		}
		oracles := slices.Clone(parent.oracles)
		if l.oracle != nil {
			oracles = append(oracles, OracleObligation{Oracle: *l.oracle, Sources: []string{l.file}})
		}
		d.oracles = mergeOracles(oracles)
		if l.lightsOn != nil && *l.lightsOn {
			d.lightsOn = append(d.lightsOn, l.file)
		}
		if len(d.verify) > MaxStackGates || len(d.union) > MaxStackGates {
			if scope[dir] {
				c.problems = append(c.problems, Problem{
					File: l.file, Code: CodeTooMany,
					Message: fmt.Sprintf("more than %d gates in one stage on the stack of this contract", MaxStackGates),
				})
			}
			ok = false
			continue
		}
		if hasChild[l] {
			d.idx[0] = extendIndex(parent.idx[0], l.verify, l.file)
			d.idx[1] = extendIndex(parent.idx[1], l.union, l.file)
		}
		l.data = d
	}
	return ok && !c.exhausted
}

func ownObligations(gs []Gate, file string) []Obligation {
	out := make([]Obligation, len(gs))
	for i, g := range gs {
		out[i] = Obligation{Gate: g, Owner: OwnerContract, Sources: []string{file}}
	}
	return out
}

func ownRequirements(l *level) []Requirement {
	out := make([]Requirement, len(l.agents))
	for i, a := range l.agents {
		out[i] = Requirement{Role: a, Sources: []string{l.file}}
	}
	return out
}

// extendIndex copies the parent's index and adds the contract's gates. The
// first revision and the first mandatory declaration stay.
func extendIndex(parent map[GateKey]gateInfo, own []Gate, file string) map[GateKey]gateInfo {
	out := make(map[GateKey]gateInfo, len(parent)+len(own))
	for k, v := range parent {
		out[k] = v
	}
	for _, g := range own {
		info, ok := out[g.Key()]
		if !ok {
			info = gateInfo{rev: g.WorkflowRevision, revSource: file}
		}
		if g.Mandatory && info.mandSource == "" {
			info.mandSource = file
		}
		out[g.Key()] = info
	}
	return out
}

// cloneObligations returns a deep copy of obs.
func cloneObligations(obs []Obligation) []Obligation {
	out := slices.Clone(obs)
	for i := range out {
		out[i].Sources = slices.Clone(out[i].Sources)
	}
	return out
}

func cloneOracles(os []OracleObligation) []OracleObligation {
	out := slices.Clone(os)
	for i := range out {
		out[i].Sources = slices.Clone(out[i].Sources)
		out[i].Oracle.Observables = slices.Clone(out[i].Oracle.Observables)
	}
	return out
}

func cloneRequirements(rs []Requirement) []Requirement {
	out := slices.Clone(rs)
	for i := range out {
		out[i].Sources = slices.Clone(out[i].Sources)
	}
	return out
}

// size is the work of copying the stack's lists.
func (d *stackData) size() int64 {
	return int64(len(d.verify) + len(d.union) + len(d.oracles) + len(d.reviewers) + len(d.files) + 1)
}

// stackPolicy returns a deep copy of the stack's data as a StackPolicy.
func (d *stackData) stackPolicy() StackPolicy {
	return StackPolicy{
		Stack:       slices.Clone(d.files),
		VerifyGates: cloneObligations(d.verify),
		UnionGates:  cloneObligations(d.union),
		Oracles:     cloneOracles(d.oracles),
		Reviewers:   cloneRequirements(d.reviewers),
	}
}
