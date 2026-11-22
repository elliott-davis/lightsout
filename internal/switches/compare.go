// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

package switches

import (
	"cmp"
	"slices"
	"strings"
)

// Verdict is the FLG-2 outcome of comparing two revisions.
type Verdict string

// Verdicts.
const (
	// VerdictPass means nothing in the change can turn a switch on, and neither revision has a problem.
	VerdictPass Verdict = "pass"
	// VerdictBlocked means the change adds a switch that is not default-off, or changes a flagd definition in a
	// way that can activate a feature.
	VerdictBlocked Verdict = "blocked"
	// VerdictError means either revision has a [Problem], or a [Set] was not made by [Detect].
	VerdictError Verdict = "error"
)

// Reason says why a [Change] blocks. A change that does not block has no reason.
type Reason string

// Blocking reasons.
const (
	// ReasonNewNotOff is a new switch that is not [StatusDefaultOff].
	ReasonNewNotOff Reason = "new-not-default-off"
	// ReasonActivation is an existing flagd switch whose runtime definition changed (a flagd source, or the
	// $evaluators and metadata of its file) while the head is not default-off, or that was default-off and is not any
	// more. Releasing a feature is a separate human decision (P2), so a PR that flips a default, adds targeting,
	// disables the flag, makes its sources disagree, or changes a switch that is on or has targeting, is blocked.
	ReasonActivation Reason = "activation-in-pr"
	// ReasonRemoval is a removed flagd definition. Without it the SDK returns the code default, which may be on.
	// Cleanup is a later phase (FLG-7).
	ReasonRemoval Reason = "removal-in-pr"
)

// ReasonOpaque is the reason for a blocking [OpaqueEntry].
const ReasonOpaque Reason = "opaque-source"

// Change is one switch, or one flagd source of a switch, in a [Comparison].
type Change struct {
	Key string
	// Path is the escaped flagd source path that was removed, for a removal. It is empty otherwise.
	Path string
	// Status is the switch's status at the head, or at the base for a removed switch.
	Status Status
	// BaseStatus is the status at the base, set for a changed switch or a removed source of a kept switch.
	BaseStatus Status
	// Reason is set when the change blocks.
	Reason Reason
}

// Comparison is the result of [Compare]. Every list is sorted by key, then path.
type Comparison struct {
	// New switches have no flagd definition at the base. Manifest definitions do not count, as no SDK reads them.
	// A switch the manifest alone defines at both revisions is not new, and is reported in StatusChanged if it changed.
	New []Change
	// Removed lists each flagd source (key and path) at the base that is not at the head, which blocks. A switch the
	// manifest alone defined, removed, is listed once with no path and no reason.
	Removed []Change
	// StatusChanged are existing switches whose status, or whose state, targeting, variants, default, metadata or
	// file-level evaluators changed.
	StatusChanged []Change
	// Opaque are the opaque entries that block: new at the head, or changed in kind or target. Escaped paths.
	Opaque  []string
	Verdict Verdict
}

// Compare checks the head against the base (FLG-2). The verdict is [VerdictError] if either set has a problem or
// was not made by [Detect]. Otherwise it is [VerdictBlocked] if any of these holds, and [VerdictPass] if none does:
//   - a new switch (no flagd definition at the base) is not [StatusDefaultOff], including a switch only the
//     manifest defines;
//   - an existing flagd switch's runtime definition changed (its flagd sources, or the $evaluators and metadata of
//     their files) and the head is not default-off, or it was default-off and no longer is;
//   - a flagd source (key and path) at the base is not at the head, whether the switch was deleted, moved to another
//     file or lost one of several sources;
//   - an opaque entry at the head is new, or differs from the base in kind or target.
//
// P2 makes releasing a feature a separate human decision, and the PRD does not say whether a PR may change an
// existing switch, so the stricter reading is taken: it blocks every PR that changes a switch that is on or has
// targeting. It can be relaxed here.
func Compare(base, head Set) Comparison {
	var c Comparison
	if !base.complete || !head.complete || len(base.Problems)+len(head.Problems) > 0 {
		c.Verdict = VerdictError
		return c
	}
	blocked := false
	for _, key := range head.Keys() {
		b, existed := base.Switches[key]
		if c.compareKey(key, b, head.Switches[key], existed) {
			blocked = true
		}
	}
	for _, key := range base.Keys() {
		if _, ok := head.Switches[key]; !ok && c.deleted(key, base.Switches[key]) {
			blocked = true
		}
	}
	slices.SortStableFunc(c.Removed, func(a, b Change) int {
		return cmp.Or(cmp.Compare(a.Key, b.Key), cmp.Compare(a.Path, b.Path))
	})
	c.Opaque = changedOpaque(base, head)
	blocked = blocked || len(c.Opaque) > 0
	if blocked {
		c.Verdict = VerdictBlocked
	} else {
		c.Verdict = VerdictPass
	}
	return c
}

// removedSources lists the flagd sources of b that h does not have, as removals that block.
func removedSources(key string, b, h Switch) []Change {
	var out []Change
	for i := range b.Definitions {
		d := &b.Definitions[i]
		if d.Kind != KindFlagd {
			continue
		}
		if !slices.ContainsFunc(h.Definitions, func(x Definition) bool { return x.Kind == KindFlagd && x.Path == d.Path }) {
			out = append(out, Change{Key: key, Path: escape(d.Path), Status: h.Status(), BaseStatus: b.Status(), Reason: ReasonRemoval})
		}
	}
	return out
}

// changedOpaque returns the head's opaque entries that are not in the base, or whose kind or target changed. An
// entry unchanged from the base does not block. The tree does not expose a gitlink's commit, so a gitlink at the
// same path at both revisions is taken as unchanged.
func changedOpaque(base, head Set) []string {
	type key struct{ raw, kind, target string }
	known := make(map[key]struct{}, len(base.Opaque))
	for _, o := range base.Opaque {
		known[key{o.raw, o.Kind, o.target}] = struct{}{}
	}
	var out []string
	for _, o := range head.Opaque {
		if _, ok := known[key{o.raw, o.Kind, o.target}]; !ok {
			out = append(out, o.Path)
		}
	}
	return out
}

// stateSig is what a switch's definitions say, without their paths or descriptions, so a change in any state,
// targeting, variant, default, metadata or evaluators shows. With flagdOnly it leaves out the manifest, which no SDK
// reads.
func stateSig(s Switch, flagdOnly bool) string {
	parts := make([]string, 0, len(s.Definitions))
	for i := range s.Definitions {
		d := &s.Definitions[i]
		if flagdOnly && d.Kind != KindFlagd {
			continue
		}
		parts = append(parts, string(d.Kind)+"|"+d.sig+"|"+d.defSig)
	}
	slices.Sort(parts)
	return strings.Join(parts, ";")
}

// compareKey compares one switch of the head with the base, recording what it reports, and reports whether it
// blocks. existed is whether the base has the key at all.
func (c *Comparison) compareKey(key string, b, h Switch, existed bool) bool {
	switch {
	case !existed || (!b.hasFlagd() && h.hasFlagd()):
		ch := Change{Key: key, Status: h.Status()}
		if ch.Status != StatusDefaultOff {
			ch.Reason = ReasonNewNotOff
		}
		c.New = append(c.New, ch)
		return ch.Reason != ""
	case !b.hasFlagd():
		// Defined only in the manifest at both revisions: no SDK reads it, so a change is reported only.
		if stateSig(b, false) != stateSig(h, false) {
			c.StatusChanged = append(c.StatusChanged, Change{Key: key, Status: h.Status(), BaseStatus: b.Status()})
		}
		return false
	}
	removed := removedSources(key, b, h)
	c.Removed = append(c.Removed, removed...)
	blocked := len(removed) > 0
	if !h.hasFlagd() || stateSig(b, false) == stateSig(h, false) {
		return blocked
	}
	ch := Change{Key: key, Status: h.Status(), BaseStatus: b.Status()}
	if ch.Status != StatusDefaultOff && (stateSig(b, true) != stateSig(h, true) || ch.BaseStatus == StatusDefaultOff) {
		ch.Reason = ReasonActivation
		blocked = true
	}
	c.StatusChanged = append(c.StatusChanged, ch)
	return blocked
}

// deleted records a switch that is gone from the head, and reports whether that blocks: it does when the base had a
// flagd source of it.
func (c *Comparison) deleted(key string, b Switch) bool {
	if !b.hasFlagd() {
		c.Removed = append(c.Removed, Change{Key: key, Status: b.Status()})
		return false
	}
	for i := range b.Definitions {
		if d := &b.Definitions[i]; d.Kind == KindFlagd {
			c.Removed = append(c.Removed, Change{Key: key, Path: escape(d.Path), Status: b.Status(), Reason: ReasonRemoval})
		}
	}
	return true
}
