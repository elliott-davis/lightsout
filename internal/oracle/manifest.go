// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

package oracle

import (
	"errors"
	"fmt"
	"regexp"
	"slices"

	"github.com/elliott-davis/lightsout/internal/contract"
	"github.com/elliott-davis/lightsout/internal/pathglob"
	"github.com/elliott-davis/lightsout/internal/yamlsafe"
)

var (
	idPattern      = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,127}$`)
	fixturePattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

// allObservables returns the five PIP-13 categories, sorted.
func allObservables() []contract.Observable {
	return []contract.Observable{
		contract.ObservableEvents, contract.ObservableQueuedJobs, contract.ObservableReads,
		contract.ObservableResponses, contract.ObservableWrites,
	}
}

// Case is one input of the oracle: an ID and the digest of its inputs and initial state.
type Case struct {
	ID, Fixture string
}

// Boundary is an external boundary the harness observes, and the category it belongs to.
type Boundary struct {
	Name       string
	Observable contract.Observable
}

// Manifest is a validated case manifest (schema lightsout.oracle-cases/v1). Every case runs against every boundary on
// both sides. Use [ValidateManifest] to make one.
type Manifest struct {
	Cases      []Case
	Boundaries []Boundary
	// CoverGlobs are the repo-root-anchored globs of the changed paths this oracle speaks for.
	CoverGlobs []string
	patterns   []pathglob.Pattern
}

// Covers reports whether the manifest speaks for the repo-relative path p. The zero Manifest covers nothing.
func (m Manifest) Covers(p string) bool {
	for _, pat := range m.patterns {
		if pat.Match(p) {
			return true
		}
	}
	return false
}

// Observables returns the sorted set of categories the manifest's boundaries observe.
func (m Manifest) Observables() []contract.Observable {
	var out []contract.Observable
	for _, b := range m.Boundaries {
		out = append(out, b.Observable)
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// ErrManifest is wrapped by every error from [ValidateManifest].
var ErrManifest = errors.New("oracle: invalid case manifest")

func manifestErr(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrManifest, fmt.Sprintf(format, args...))
}

// ValidateManifest parses and checks a case manifest (YAML or JSON) against the observables the contract declares.
// It rejects duplicate keys and unknown fields, over 4096 cases, over 64 boundaries, a matrix over 4096 entries, over
// 256 covers, bad IDs, fixtures or globs, and a set of boundary observables that is not exactly declared. WI-11
// calls it at activation so that an oversized matrix fails before CI. Errors wrap [ErrManifest]; text taken from the
// input is escaped.
func ValidateManifest(data []byte, declared []contract.Observable) (Manifest, error) {
	tree, derr := yamlsafe.Decode(data, yamlsafe.Limits{MaxBytes: MaxManifestSize, MaxDepth: 6, MaxNodes: 64 << 10, Name: "case manifest"})
	if derr != nil {
		return Manifest{}, fmt.Errorf("%w: %s", ErrManifest, derr.Error())
	}
	root, err := exactObject(tree, "schema", "cases", "boundaries", "covers")
	if err != nil {
		return Manifest{}, manifestErr("%v", err)
	}
	if s, ok := root["schema"].(string); !ok || s != ManifestSchema {
		return Manifest{}, manifestErr("schema must be %q", ManifestSchema)
	}
	var m Manifest
	rawCases, ok := root["cases"].([]any)
	if !ok || len(rawCases) < 1 || len(rawCases) > MaxCases {
		return Manifest{}, manifestErr("cases must be a list of 1 to %d entries", MaxCases)
	}
	seenCase := map[string]bool{}
	for i, rc := range rawCases {
		o, err := exactObject(rc, "id", "fixture")
		if err != nil {
			return Manifest{}, manifestErr("cases[%d]: %v", i, err)
		}
		id, _ := o["id"].(string)
		fx, _ := o["fixture"].(string)
		switch {
		case !idPattern.MatchString(id):
			return Manifest{}, manifestErr("cases[%d]: bad id %s", i, esc(id))
		case seenCase[id]:
			return Manifest{}, manifestErr("cases[%d]: duplicate id %s", i, esc(id))
		case !fixturePattern.MatchString(fx):
			return Manifest{}, manifestErr("cases[%d]: fixture must be sha256:<64 lowercase hex>", i)
		}
		seenCase[id] = true
		m.Cases = append(m.Cases, Case{ID: id, Fixture: fx})
	}
	rawBounds, ok := root["boundaries"].([]any)
	if !ok || len(rawBounds) < 1 || len(rawBounds) > MaxBoundaries {
		return Manifest{}, manifestErr("boundaries must be a list of 1 to %d entries", MaxBoundaries)
	}
	seenBound := map[string]bool{}
	for i, rb := range rawBounds {
		o, err := exactObject(rb, "name", "observable")
		if err != nil {
			return Manifest{}, manifestErr("boundaries[%d]: %v", i, err)
		}
		name, _ := o["name"].(string)
		obs, _ := o["observable"].(string)
		switch {
		case !idPattern.MatchString(name):
			return Manifest{}, manifestErr("boundaries[%d]: bad name %s", i, esc(name))
		case seenBound[name]:
			return Manifest{}, manifestErr("boundaries[%d]: duplicate name %s", i, esc(name))
		case !slices.Contains(allObservables(), contract.Observable(obs)):
			return Manifest{}, manifestErr("boundaries[%d]: unknown observable %s", i, esc(obs))
		}
		seenBound[name] = true
		m.Boundaries = append(m.Boundaries, Boundary{Name: name, Observable: contract.Observable(obs)})
	}
	if len(m.Cases)*len(m.Boundaries) > MaxMatrix {
		return Manifest{}, manifestErr("%d cases times %d boundaries is over %d", len(m.Cases), len(m.Boundaries), MaxMatrix)
	}
	want := slices.Clone(declared)
	slices.Sort(want)
	want = slices.Compact(want)
	if got := m.Observables(); !slices.Equal(got, want) {
		return Manifest{}, manifestErr("boundary observables %s are not the declared %s", esc(fmt.Sprint(got)), esc(fmt.Sprint(want)))
	}
	rawCovers, ok := root["covers"].([]any)
	if !ok || len(rawCovers) < 1 || len(rawCovers) > MaxCovers {
		return Manifest{}, manifestErr("covers must be a list of 1 to %d globs", MaxCovers)
	}
	for i, rc := range rawCovers {
		g, ok := rc.(string)
		if !ok {
			return Manifest{}, manifestErr("covers[%d]: not a string", i)
		}
		pat, err := pathglob.Compile(g)
		if err != nil {
			return Manifest{}, manifestErr("covers[%d]: %s", i, esc(err.Error()))
		}
		m.CoverGlobs = append(m.CoverGlobs, g)
		m.patterns = append(m.patterns, pat)
	}
	return m, nil
}

// exactObject returns v as an object with exactly the given keys: unknown and missing keys are errors.
func exactObject(v any, keys ...string) (map[string]any, error) {
	o, ok := v.(map[string]any)
	if !ok {
		return nil, errors.New("not an object")
	}
	var unknown []string
	for k := range o {
		if !slices.Contains(keys, k) {
			unknown = append(unknown, k)
		}
	}
	if len(unknown) > 0 {
		return nil, fmt.Errorf("unknown field %s", esc(slices.Min(unknown))) // the smallest, so the error is deterministic
	}
	for _, k := range keys {
		if _, ok := o[k]; !ok {
			return nil, fmt.Errorf("missing field %s", k)
		}
	}
	return o, nil
}

// esc makes untrusted text safe to print on one line.
func esc(s string) string { return yamlsafe.Escape(s, escapeLimit) }
