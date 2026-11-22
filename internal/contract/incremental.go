// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

package contract

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/elliott-davis/lightsout/internal/pathglob"
)

// Scope reports exactly which contracts an incremental validation checked, so
// tests and callers can assert it. The file lists hold contract file paths,
// sorted.
type Scope struct {
	// Changed are the contract files of the changed directories, including a
	// contract that was deleted and so is absent from the set.
	Changed []string
	// Checked are the contract files that were validated.
	Checked []string
	// CheckedDirs are the directories of Checked, in the same order, spelled as
	// the Set spells them. They are what [Policy.CheckGates] takes.
	CheckedDirs []string
	// Full is true when the trusted baseline digest was missing or stale, so
	// every contract was validated and not only the changed ones.
	Full bool
}

// ChangeOptions are the inputs of [ValidateChanged] besides the contracts.
type ChangeOptions struct {
	// Changed are the directories whose contract was added, edited or deleted,
	// "" for the repository root. They are directories, never file paths: an
	// entry that names a contract file is rejected. [ChangedDirs] maps changed
	// file paths to these.
	Changed []string
	// Registry, when non-nil, makes ValidateChanged check every gate of every
	// compiled contract, in scope or not, and the baseline's, against it
	// (CON-4): a gate registered when a contract was last validated may have
	// been revoked since, and authorization comes from the current registry. nil skips
	// that check. The activation path (WI-11) must always pass one: without it
	// a changed contract can pin a gate that does not exist.
	Registry GateRegistry
	// TrustedDigest is [TrustDigest] of the baseline and defaults
	// the unchanged contracts were last validated under. WI-11 stores it with
	// each trusted revision. Empty means unknown, and so does a digest that
	// differs from the current one: the unchanged contracts were valid only
	// under the old baseline, so everything is validated (Scope.Full).
	TrustedDigest string
}

// ValidateChanged validates the contracts a change touched against the
// contracts above them and the baseline, without re-validating the rest of
// the set (CON-13).
//
// The scope is the changed contracts that exist, their dirKey ancestors, their
// dirKey descendants (a deleted contract's included), and any directory whose
// dirKey collides with a changed one. Each check reads only the contract under
// test, the contracts above it and the baseline, and the collision check reads
// its partner, so a loosening of a changed contract, or a child that conflicts
// with a changed parent, is found. Every contract in scope gets the full
// per-contract checks: schema and patterns, relational checks, the stack depth
// and gate caps, and collisions. Contracts outside the scope are not
// validated: they were validated at the revision the factory trusts, under the
// baseline and defaults whose digest opts.TrustedDigest names. If that
// digest is empty or not the current one, that premise does not hold and every
// contract is validated.
//
// With opts.Registry the gates of every compiled contract and of the baseline
// are checked in the same call, and their problems join the rest. A registry
// error is returned (wrapped) and never counts as registered.
//
// An empty opts.Changed validates no contract (unless Full is forced) and
// returns nil, though a registry still checks every gate.
//
// Problems return a *ValidationError with the Scope. A nil set, a bad baseline
// or defaults, a registry error, a cancelled ctx, or an invalid changed entry
// (one wrapping pathglob.ErrInvalidPath) return a plain error.
func ValidateChanged(ctx context.Context, set *Set, b Baseline, d Defaults, opts ChangeOptions) (Scope, error) {
	return validateChanged(ctx, set, b, d, opts, defaultBudgets())
}

func validateChanged(ctx context.Context, set *Set, b Baseline, d Defaults, opts ChangeOptions, limits budgets) (Scope, error) {
	if set == nil {
		return Scope{}, errors.New("validate changed: nil contract set")
	}
	if err := ctx.Err(); err != nil {
		return Scope{}, fmt.Errorf("validate changed: %w", err)
	}
	changedKeys := make(map[string]bool, len(opts.Changed))
	var sc Scope
	for _, dir := range opts.Changed {
		if err := checkChangedDir(dir); err != nil {
			return Scope{}, fmt.Errorf("validate changed: %w", err)
		}
		changedKeys[keyOf(dir)] = true
		sc.Changed = append(sc.Changed, filePath(dir))
	}
	slices.Sort(sc.Changed)
	sc.Changed = slices.Compact(sc.Changed)
	sc.Full = opts.TrustedDigest == "" || opts.TrustedDigest != TrustDigest(b, d)

	// Scope is decided on dirKeys alone: a changed contract may be gone, and a
	// contract that fails to compile has no level.
	checked := []string{}
	for _, dir := range set.Dirs() {
		if sc.Full || inScope(keyOf(dir), changedKeys) {
			checked = append(checked, dir)
		}
	}
	type entry struct{ dir, file string }
	entries := make([]entry, len(checked))
	for i, dir := range checked {
		entries[i] = entry{dir, filePath(dir)}
	}
	slices.SortFunc(entries, func(x, y entry) int { return strings.Compare(x.file, y.file) })
	for _, e := range entries {
		sc.Checked = append(sc.Checked, e.file)
		sc.CheckedDirs = append(sc.CheckedDirs, e.dir)
	}

	p, problems, err := analyze(set, b, d, limits, checked)
	if err != nil {
		return Scope{}, fmt.Errorf("validate changed: %w", err)
	}
	if opts.Registry != nil {
		gp, gerr := p.gateProblems(ctx, opts.Registry, p.tree.dirs)
		if gerr != nil {
			return Scope{}, gerr
		}
		problems = append(problems, gp...)
	}
	if len(problems) > 0 {
		return sc, newValidationError(problems)
	}
	return sc, nil
}

// isContractName reports whether a path segment is a contract file name once
// case, normalization and invisible characters are ignored.
func isContractName(seg string) bool {
	k := dirKey(seg)
	return k == dirKey(FileName) || k == dirKey(misnamedFile)
}

// checkChangedDir rejects an entry that is not a valid contract directory.
func checkChangedDir(dir string) error {
	if dir == "" {
		return nil
	}
	if err := pathglob.ValidatePath(dir); err != nil {
		return fmt.Errorf("changed directory %s: %w", quote(dir), err)
	}
	if isContractName(dir[strings.LastIndexByte(dir, '/')+1:]) {
		return fmt.Errorf("changed entry %s names a contract file, pass the contract's directory: %w",
			quote(dir), pathglob.ErrInvalidPath)
	}
	return nil
}

// ChangedDirs maps changed repository file paths to the contract directories
// they affect: the directory of every path whose last segment is a contract
// file name, in any case or spelling (so a rename to or from a look-alike is
// seen too). The result is sorted and has no duplicates; "" is the root.
func ChangedDirs(paths []string) []string {
	var out []string
	for _, path := range paths {
		i := strings.LastIndexByte(path, '/')
		if isContractName(path[i+1:]) {
			out = append(out, path[:max(i, 0)])
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// validatorVersion identifies the validation rules. Bump it whenever a
// validation rule changes (a new check, a changed message-independent
// condition, a new problem code that rejects what was accepted), so that every
// stored trust digest goes stale and the next change validates everything.
const validatorVersion = 3

// TrustDigest returns the hex SHA-256 of a canonical encoding of everything the
// validity of an unchanged contract depends on besides its own bytes: every
// Baseline and Defaults field, the contract schema, the validator version, the
// stack depth and gate caps and the default work budgets. The encoding is
// order-sensitive for lists, so a reordering changes the digest, which only
// ever forces a full validation. WI-11 stores it with each trusted revision so
// that ValidateChanged can tell whether the unchanged contracts were validated
// under the current baseline and the current validator. It does not cover gate
// registration: the registry changes over time, so it is checked on every run.
func TrustDigest(b Baseline, d Defaults) string {
	return trustDigest(b, d, validatorVersion, schemaJSON)
}

// trustDigest is TrustDigest with the validator inputs passed in, so tests can
// show that each of them is covered.
func trustDigest(b Baseline, d Defaults, version int, schema []byte) string {
	list := func(s []string) []string {
		if s == nil {
			return []string{}
		}
		return s
	}
	gates := func(gs []Gate) []Gate {
		if gs == nil {
			return []Gate{}
		}
		return gs
	}
	canon := struct {
		Verify              []Gate   `json:"verify"`
		Union               []Gate   `json:"union"`
		Reviewers           []string `json:"reviewers"`
		SecurityReviewer    string   `json:"securityReviewer"`
		PRReviewer          string   `json:"prReviewer"`
		Protected           []string `json:"protected"`
		KnownAgents         []string `json:"knownAgents"`
		InstallRevision     string   `json:"installRevision"`
		SwitchStaleDays     int      `json:"switchStaleDays"`
		SwitchAbandonedDays int      `json:"switchAbandonedDays"`
		ReviewBudgetLines   int      `json:"reviewBudgetLines"`
		Validator           struct {
			Version       int      `json:"version"`
			SchemaSHA256  string   `json:"schemaSha256"`
			MaxStackDepth int      `json:"maxStackDepth"`
			MaxStackGates int      `json:"maxStackGates"`
			Budgets       [3]int64 `json:"budgets"`
		} `json:"validator"`
	}{
		gates(b.Verify), gates(b.Union), list(b.Reviewers), b.SecurityReviewer, b.PRReviewer,
		list(b.Protected), list(b.KnownAgents), b.InstallRevision, d.SwitchStaleDays, d.SwitchAbandonedDays, d.ReviewBudgetLines,
		struct {
			Version       int      `json:"version"`
			SchemaSHA256  string   `json:"schemaSha256"`
			MaxStackDepth int      `json:"maxStackDepth"`
			MaxStackGates int      `json:"maxStackGates"`
			Budgets       [3]int64 `json:"budgets"`
		}{
			version, schemaHash(schema), MaxStackDepth, MaxStackGates,
			[3]int64{defaultCompileBudget, defaultForPathBudget, defaultResolveBudget},
		},
	}
	data, err := json.Marshal(canon)
	if err != nil {
		return "" // cannot happen; an empty digest never matches, so it forces a full validation
	}
	sum := sha256.Sum256(append([]byte("lightsout/trust-digest/v1\n"), data...))
	return hex.EncodeToString(sum[:])
}

func schemaHash(schema []byte) string {
	sum := sha256.Sum256(schema)
	return hex.EncodeToString(sum[:])
}

// keyOf is the canonical key of a directory: its segments' dirKeys joined.
func keyOf(dir string) string {
	if dir == "" {
		return ""
	}
	segs := strings.Split(dir, "/")
	for i, s := range segs {
		segs[i] = dirKey(s)
	}
	return strings.Join(segs, "/")
}

// inScope reports whether the directory with key k is a changed one, a key
// ancestor of one, or a key descendant of one.
func inScope(k string, changed map[string]bool) bool {
	if changed[k] {
		return true
	}
	for c := range changed {
		if isKeyAncestor(k, c) || isKeyAncestor(c, k) {
			return true
		}
	}
	return false
}

// isKeyAncestor reports whether a is a proper ancestor of b. The root key ""
// is an ancestor of every other key.
func isKeyAncestor(a, b string) bool {
	if a == b {
		return false
	}
	return a == "" || strings.HasPrefix(b, a+"/")
}
