// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

package contract

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
)

// CodeUnregisteredGate marks a gate whose identity or pinned revision the
// registry does not know (CON-4).
const CodeUnregisteredGate Code = "unregistered-gate"

// sourceBaselineFile is the File of a problem about a baseline gate, which no
// contract declares.
const sourceBaselineFile = "factory baseline"

// GateRegistry answers whether a gate identity and pinned revision are
// registered. The consumer defines it: install config backs it in v1, and the
// forge adapter backs it later.
type GateRegistry interface {
	Registered(ctx context.Context, ref GateRef) (bool, error)
}

// ErrUnknownContractDir is wrapped by the error CheckGates returns for a dirs
// entry that is not the directory of a contract in the policy: a file path, a
// differently cased or normalized spelling, or a directory with no contract.
// Skipping it silently would leave a gate unchecked.
var ErrUnknownContractDir = errors.New("contract: not the directory of a contract in this policy")

// CheckGates asks reg whether every gate the policy relies on is registered at
// its pinned revision (CON-4): the verify gates, union gates and dark-merge
// oracle declared by the contracts in dirs (nil means every contract), and
// every baseline gate.
//
// dirs are contract directories exactly as the Set spells them ("" for the
// root). An entry that is not one returns an error wrapping
// [ErrUnknownContractDir].
//
// An unregistered gate is a Problem with CodeUnregisteredGate; File and Field
// point at the declaration, and baseline gates have File "factory baseline". A
// gate declared in several contracts is reported at each declaration. All of
// them are returned in one *ValidationError. A registry error is never a
// problem and never means "registered": it is returned, wrapped, and the check
// stops (fail closed). A cancelled ctx stops the check with ctx's error.
func (p *Policy) CheckGates(ctx context.Context, reg GateRegistry, dirs []string) error {
	if dirs == nil {
		dirs = p.tree.dirs
	}
	for _, dir := range dirs {
		if _, ok := p.tree.levels[dir]; !ok {
			return fmt.Errorf("check gates: directory %s: %w", quote(dir), ErrUnknownContractDir)
		}
	}
	problems, err := p.gateProblems(ctx, reg, dirs)
	if err != nil {
		return err
	}
	if len(problems) > 0 {
		return newValidationError(problems)
	}
	return nil
}

// gateProblems is the lookup behind CheckGates. A dir without a compiled
// contract is skipped: it has no declarations here, and its own problems were
// reported when it failed to compile.
func (p *Policy) gateProblems(ctx context.Context, reg GateRegistry, dirs []string) ([]Problem, error) {
	if reg == nil {
		return nil, errors.New("check gates: nil registry")
	}
	dirs = slices.Compact(slices.Sorted(slices.Values(dirs)))
	gc := &gateCheck{reg: reg, known: map[GateRef]bool{}}
	if err := gc.all(ctx, sourceBaselineFile, "", p.base.Verify, p.base.Union, nil); err != nil {
		return nil, err
	}
	for _, dir := range dirs {
		if l, ok := p.tree.levels[dir]; ok {
			if err := gc.all(ctx, l.file, fieldGates, l.verify, l.union, l.oracle); err != nil {
				return nil, err
			}
		}
	}
	return gc.problems, nil
}

// gateCheck asks a registry about gates and collects the unregistered ones.
type gateCheck struct {
	reg      GateRegistry
	known    map[GateRef]bool // answers, so a gate repeated across contracts is asked once
	problems []Problem
}

// all checks the verify and union gates and the oracle of one declaration
// site. prefix is the pointer prefix of the lists: "gates" in a contract and
// "" for the baseline.
func (gc *gateCheck) all(ctx context.Context, file, prefix string, verify, union []Gate, oracle *Oracle) error {
	at := func(parts ...string) []string {
		if prefix == "" {
			return parts
		}
		return append([]string{prefix}, parts...)
	}
	for i := range verify {
		if err := gc.one(ctx, file, at(stageVerify, strconv.Itoa(i)), verify[i].GateRef); err != nil {
			return err
		}
	}
	for i := range union {
		if err := gc.one(ctx, file, at(stageUnion, strconv.Itoa(i)), union[i].GateRef); err != nil {
			return err
		}
	}
	if oracle != nil {
		return gc.one(ctx, file, at("darkMergeOracle"), oracle.GateRef)
	}
	return nil
}

func (gc *gateCheck) one(ctx context.Context, file string, field []string, ref GateRef) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("check gates: %w", err)
	}
	ok, seen := gc.known[ref]
	if !seen {
		var err error
		if ok, err = gc.reg.Registered(ctx, ref); err != nil {
			return fmt.Errorf("check gates: registry lookup for %s: %w", quote(ref.CheckID), err)
		}
		gc.known[ref] = ok
	}
	if !ok {
		gc.problems = append(gc.problems, Problem{
			File: file, Field: pointer(field), Code: CodeUnregisteredGate,
			Message: sanitize(fmt.Sprintf("gate %s (producer %s, workflow %s, revision %s) is not registered",
				quote(ref.CheckID), quote(ref.ProducerID), quote(string(ref.WorkflowID)), quote(ref.WorkflowRevision))),
		})
	}
	return nil
}
