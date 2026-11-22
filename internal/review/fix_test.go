// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

package review_test

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/elliott-davis/lightsout/internal/authz"
	"github.com/elliott-davis/lightsout/internal/forge"
	"github.com/elliott-davis/lightsout/internal/gate"
	"github.com/elliott-davis/lightsout/internal/review"
)

var update = flag.Bool("update", false, "rewrite golden files")

func wantInvalid(t *testing.T, d review.Decision) {
	t.Helper()
	wantDisp(t, d, review.Error)
	if !slices.Equal(d.Reasons, []review.Reason{review.ReasonInvalidInput}) {
		t.Fatalf("reasons = %v, want invalid-input", d.Reasons)
	}
}

// rebind rewrites an assignment the way a compromised writer would: the manifest and its digest are recomputed too.
func rebind(e *env, f func(as *review.Assignment, m *review.Manifest)) {
	for i := range e.snap.Assignments {
		as := &e.snap.Assignments[i]
		m := e.snap.Manifests[as.ID]
		f(as, &m)
		e.snap.Manifests[as.ID] = m
		as.ManifestDigest = m.Digest()
	}
}

func TestEvaluate_SignatureBindsAssignment_Rewritten(t *testing.T) { // AGT-3, SEC-11
	t.Parallel()
	tests := []struct {
		name    string
		prepare func(e *env) // shapes the genuine change the roles approved
		rewrite func(e *env) // what the writer makes it look like
	}{
		{"head", func(e *env) { e.tgt.HeadSHA = head2 }, func(e *env) {
			e.tgt.HeadSHA = head1
			e.setRound("r1", 1, head1, review.RoundDispatched)
			rebind(e, func(as *review.Assignment, m *review.Manifest) { as.HeadSHA, m.HeadSHA = head1, head1 })
		}},
		{"PR", func(e *env) { e.tgt.PR = 99 }, func(e *env) {
			e.tgt.PR = 7
			rebind(e, func(as *review.Assignment, _ *review.Manifest) { as.PR = 7 })
		}},
		{"repo", func(e *env) { e.tgt.Repo = "acme/other" }, func(e *env) {
			e.tgt.Repo = repo
			rebind(e, func(as *review.Assignment, _ *review.Manifest) { as.Repo = repo })
		}},
		{"forge", func(e *env) { e.tgt.Forge = "gitlab" }, func(e *env) {
			e.tgt.Forge = "github"
			rebind(e, func(as *review.Assignment, _ *review.Manifest) { as.Forge = "github" })
		}},
		{"role", func(_ *env) {}, func(e *env) {
			rebind(e, func(as *review.Assignment, _ *review.Manifest) {
				if as.Role == roleGo {
					as.Role = "docs-reviewer"
				}
			})
			e.eff.Reviewers[2].Role = "docs-reviewer"
			for i := range e.snap.Rounds {
				e.snap.Rounds[i].Roles = append(e.snap.Rounds[i].Roles, "docs-reviewer")
			}
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			e := newEnv(t)
			tc.prepare(e)
			e.approveAll()
			wantDisp(t, e.eval(), review.Pass) // the genuine records pass for the genuine target
			tc.rewrite(e)
			d := e.eval()
			if d.Disposition == review.Pass {
				t.Fatalf("a rewritten assignment passed: %+v", d)
			}
			n := 0
			for _, r := range d.Rejected {
				if r.Kind == review.RecordAttestation && r.Reason == review.ReasonBadBinding {
					n++
				}
			}
			if n == 0 {
				t.Errorf("no bad-binding rejection: %+v", d.Rejected)
			}
		})
	}
}

func TestEvaluate_SignatureBindsSession(t *testing.T) { // AGT-3, AGD-3, SEC-11
	t.Parallel()
	t.Run("a key of another session", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t)
		e.review(rv{role: rolePR})
		e.review(rv{role: roleSec})
		e.addKey("k-other", "some-other-session")
		id := e.review(rv{role: roleGo, key: "k-other"})
		d := e.eval()
		wantRejected(t, d, review.RecordAttestation, id, review.ReasonBadBinding)
		wantInconsistent(t, d) // a key-verified record that doesn't fit its assignment is never silently dropped
	})
	t.Run("a coder's key", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t)
		e.review(rv{role: rolePR})
		e.review(rv{role: roleSec})
		e.addKey("k-coder", "coder-1")
		id := e.review(rv{role: roleGo, key: "k-coder"})
		d := e.eval()
		wantRejected(t, d, review.RecordAttestation, id, review.ReasonCoderSession)
		wantInconsistent(t, d) // a reviewer-kind key for a session the snapshot calls the coder's
	})
	t.Run("a coder's key on a coder's assignment", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t)
		e.review(rv{role: rolePR})
		e.review(rv{role: roleSec})
		id := e.review(rv{role: roleGo, session: "coder-1"})
		d := e.eval()
		wantRejected(t, d, review.RecordAttestation, id, review.ReasonCoderSession)
		wantInconsistent(t, d)
	})
	t.Run("a key with no session", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t)
		e.review(rv{role: rolePR})
		e.review(rv{role: roleSec})
		e.addKey("k-none", "")
		id := e.review(rv{role: roleGo, key: "k-none"})
		wantRejected(t, e.eval(), review.RecordAttestation, id, review.ReasonBadBinding)
	})
	t.Run("a resolution signed by another session's key", func(t *testing.T) {
		t.Parallel()
		e := withClaim(t)
		e.addKey("k-other", "elsewhere")
		e.verify(vf{id: "v1", claim: claimRef(), key: "k-other"})
		wantRejected(t, e.eval(), review.RecordResolution, "v1", review.ReasonBadBinding)
	})
	t.Run("a resolution signed by a coder's key", func(t *testing.T) {
		t.Parallel()
		e := withClaim(t)
		e.addKey("k-coder", "coder-1")
		e.verify(vf{id: "v1", claim: claimRef(), key: "k-coder"})
		wantRejected(t, e.eval(), review.RecordResolution, "v1", review.ReasonCoderSession)
	})
	t.Run("a rewritten verify assignment", func(t *testing.T) {
		t.Parallel()
		e := withClaim(t)
		e.verify(vf{id: "v1", claim: claimRef()})
		for i := range e.snap.Assignments {
			if e.snap.Assignments[i].ID == "v1" {
				e.snap.Assignments[i].HeadSHA = head2
			}
		}
		wantRejected(t, e.eval(), review.RecordResolution, "v1", review.ReasonBadBinding)
	})
}

func TestEvaluate_ManifestSwappedWithRecomputedDigest_Rejected(t *testing.T) { // AGT-3
	t.Parallel()
	e := newEnv(t)
	e.review(rv{role: rolePR})
	e.review(rv{role: roleSec})
	id := e.review(rv{role: roleGo})
	m := review.Manifest{HeadSHA: head1, Items: append(e.fullItems(), review.Item{Kind: review.KindHistory, Digest: "sha256:new"})}
	e.snap.Manifests[id] = m
	for i := range e.snap.Assignments {
		if e.snap.Assignments[i].ID == id {
			e.snap.Assignments[i].ManifestDigest = m.Digest()
		}
	}
	d := e.eval()
	wantRejected(t, d, review.RecordAttestation, id, review.ReasonBadBinding)
	wantInconsistent(t, d)
}

func TestEvaluate_ReraisedClaimIsNewInstance(t *testing.T) { // AGT-4
	t.Parallel()
	e := newEnv(t)
	e.review(rv{role: rolePR, verdict: review.VerdictBlock, claims: []review.Claim{claim("C1")}, at: time.Minute})
	e.verify(vf{claim: claimRef(), at: 5 * time.Minute}) // C1 is dismissed at head1
	e.tgt.HeadSHA = head2
	changed := claim("C1")
	changed.Invariant, changed.Consequence = "a different invariant", "a different consequence"
	e.review(rv{role: rolePR, round: "r2", head: head2, verdict: review.VerdictBlock, claims: []review.Claim{changed}, at: 10 * time.Minute, session: "pr-2"})
	e.review(rv{role: roleSec, round: "r2", head: head2, session: "sec-2"})
	e.review(rv{role: roleGo, round: "r2", head: head2, session: "go-2"})
	e.snap.Rounds[0].State = review.RoundSuperseded
	d := e.eval()
	wantDisp(t, d, review.Blocked)
	wantOb(t, d, cobl(rolePR, "C1"), review.Pass, review.ReasonSatisfied)
	wantOb(t, d, review.ClaimObligationID(review.ClaimRef{Role: rolePR, ID: "C1", Digest: changed.Digest()}), review.Blocked, review.ReasonClaimOpen)
}

func TestEvaluate_ResolutionBeforeClaimOrInEarlierRound_Rejected(t *testing.T) { // AGT-4
	t.Parallel()
	t.Run("dated before the claim", func(t *testing.T) {
		t.Parallel()
		e := withClaim(t) // raised at +1m
		e.verify(vf{id: "v1", claim: claimRef(), at: 30 * time.Second})
		reapprove(e)
		d := e.eval()
		wantRejected(t, d, review.RecordResolution, "v1", review.ReasonBeforeClaim)
		wantOb(t, d, cobl(rolePR, "C1"), review.Blocked, review.ReasonClaimOpen)
	})
	t.Run("dated at the claim", func(t *testing.T) {
		t.Parallel()
		e := withClaim(t)
		e.verify(vf{id: "v1", claim: claimRef(), at: time.Minute})
		wantRejected(t, e.eval(), review.RecordResolution, "v1", review.ReasonBeforeClaim)
	})
	t.Run("verify assignment from an earlier round than the claim", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t)
		e.setRound("r1", 1, head1, review.RoundCompleted)
		e.review(rv{role: rolePR, round: "r2", verdict: review.VerdictBlock, claims: []review.Claim{claim("C1")}, at: time.Minute})
		e.verify(vf{id: "v1", claim: claimRef(), round: "r1", at: 5 * time.Minute})
		wantRejected(t, e.eval(), review.RecordResolution, "v1", review.ReasonRoundBeforeClaim)
	})
	t.Run("verify assignment in an unknown round", func(t *testing.T) {
		t.Parallel()
		e := withClaim(t)
		e.verify(vf{id: "v1", claim: claimRef(), round: "nowhere"})
		wantInconsistent(t, e.eval())
	})
	t.Run("first seen is the earliest attestation", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t)
		e.setRound("r1", 1, head1, review.RoundCompleted)
		e.review(rv{role: rolePR, round: "r1", verdict: review.VerdictBlock, claims: []review.Claim{claim("C1")}, at: 20 * time.Minute})
		e.review(rv{role: rolePR, round: "r2", verdict: review.VerdictBlock, claims: []review.Claim{claim("C1")}, at: 5 * time.Minute, session: "pr-2"})
		e.verify(vf{id: "v1", claim: claimRef(), round: "r2", at: 10 * time.Minute})
		d := e.eval()
		if slices.ContainsFunc(d.Rejected, func(r review.Rejection) bool { return r.Kind == review.RecordResolution }) {
			t.Errorf("rejected = %+v", d.Rejected)
		}
		wantOb(t, d, cobl(rolePR, "C1"), review.Pass, review.ReasonSatisfied)
	})
}

func TestEvaluate_RejectedBlockStillBlocks(t *testing.T) { // AGT-4, SEC-11
	t.Parallel()
	blocks := []review.Claim{claim("C1")}
	tests := map[string]struct {
		rv     rv
		tamper func(e *env, id string)
	}{
		"missing manifest": {rv{role: rolePR, verdict: review.VerdictBlock, claims: blocks}, func(e *env, id string) {
			delete(e.snap.Manifests, id)
		}},
		"manifest digest mismatch": {rv{role: rolePR, verdict: review.VerdictBlock, claims: blocks}, func(e *env, id string) {
			m := e.snap.Manifests[id]
			m.Items = append(m.Items, review.Item{Kind: review.KindHistory, Digest: "sha256:z"})
			e.snap.Manifests[id] = m
		}},
		"forbidden context": {rv{
			role: rolePR, verdict: review.VerdictBlock, claims: blocks,
			extra: []review.Item{{Kind: "transcript", Digest: "sha256:t"}},
		}, nil},
		"round does not list the role": {rv{role: rolePR, verdict: review.VerdictBlock, claims: blocks}, func(e *env, _ string) {
			e.snap.Rounds[0].Roles = []string{roleSec, roleGo}
		}},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			e := newEnv(t)
			id := e.review(tc.rv)
			if tc.tamper != nil {
				tc.tamper(e, id)
			}
			d := e.eval()
			wantOb(t, d, cobl(rolePR, "C1"), review.Blocked, review.ReasonClaimOpen)
			wantOb(t, d, "role:"+rolePR, review.Blocked, review.ReasonInvalidVerdict) // the block itself never approves
			wantDisp(t, d, review.Blocked)
		})
	}
	t.Run("a block bound to another session's key is inconsistent evidence", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t)
		e.addKey("k-other", "other")
		e.review(rv{role: rolePR, verdict: review.VerdictBlock, claims: blocks, key: "k-other"})
		wantInconsistent(t, e.eval())
	})
	t.Run("a newer invalid verdict hides an older approval", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t)
		e.approveAll()
		e.review(rv{role: rolePR, round: "r2", session: "pr-2", verdict: review.VerdictBlock, claims: blocks, extra: []review.Item{{Kind: "transcript", Digest: "sha256:t"}}})
		d := e.eval()
		wantOb(t, d, "role:"+rolePR, review.Blocked, review.ReasonInvalidVerdict)
		wantDisp(t, d, review.Blocked)
	})
	t.Run("an older invalid verdict does not hide a newer approval", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t)
		e.review(rv{role: rolePR, verdict: review.VerdictBlock, claims: blocks, extra: []review.Item{{Kind: "transcript", Digest: "sha256:t"}}})
		e.review(rv{role: rolePR, round: "r2", session: "pr-2"})
		wantOb(t, e.eval(), "role:"+rolePR, review.Pass, review.ReasonSatisfied)
	})
}

func TestEvaluate_ChangedPaths_Validated(t *testing.T) { // SEC-5
	t.Parallel()
	tests := map[string][]review.ChangedPath{
		"zero status":                 {{Path: "a.go"}},
		"unknown status":              {{Path: "a.go", Status: forge.FileStatus(99)}},
		"renamed without an old path": {{Path: "a.go", Status: forge.FileRenamed}},
		"copied without an old path":  {{Path: "a.go", Status: forge.FileCopied}},
		"modified with an old path":   {{Path: "a.go", OldPath: "b.go", Status: forge.FileModified}},
		"invalid path":                {{Path: "../a.go", Status: forge.FileModified}},
		"invalid old path":            {{Path: "a.go", OldPath: "/b.go", Status: forge.FileRenamed}},
		"duplicate path":              {{Path: "a.go", Status: forge.FileModified}, {Path: "a.go", Status: forge.FileAdded}},
		"invalid UTF-8 in a path":     {{Path: "a\xff.go", Status: forge.FileModified}},
	}
	for name, cp := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			e := newEnv(t) // lights-on is off: the check is unconditional
			e.approveAll()
			e.snap.ChangedPaths = cp
			wantInvalid(t, e.eval())
		})
	}
	t.Run("all known statuses are accepted", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t)
		e.setChanged(
			review.ChangedPath{Path: "a.go", Status: forge.FileAdded},
			review.ChangedPath{Path: "b.go", Status: forge.FileModified},
			review.ChangedPath{Path: "c.go", Status: forge.FileRemoved},
			review.ChangedPath{Path: "d.go", OldPath: "e.go", Status: forge.FileRenamed},
			review.ChangedPath{Path: "f.go", OldPath: "g.go", Status: forge.FileCopied},
			review.ChangedPath{Path: "h.go", Status: forge.FileModeChanged},
		)
		e.approveAll()
		wantDisp(t, e.eval(), review.Pass)
	})
}

func TestEvaluate_SensitiveSignoff_RemovedAndCopied(t *testing.T) { // SEC-5
	t.Parallel()
	mk := func(t *testing.T, cp review.ChangedPath, sensitive string, signoff []string, drop func(review.Item) bool) review.Decision {
		t.Helper()
		e := newEnv(t)
		e.eff.SecuritySignoffRequired = true
		e.eff.SensitivePaths = []string{sensitive}
		e.setChanged(cp)
		items := e.fullItems()
		if drop != nil {
			items = without(items, drop)
		}
		return secChange(e, items, signoff)
	}
	base := func(it review.Item) bool { return it.Side == review.SideBase }
	t.Run("removed needs its base side", func(t *testing.T) {
		t.Parallel()
		cp := review.ChangedPath{Path: "auth/gone.go", Status: forge.FileRemoved}
		wantDisp(t, mk(t, cp, "auth/gone.go", []string{"auth/gone.go"}, nil), review.Pass)
		wantDisp(t, mk(t, cp, "auth/gone.go", []string{"auth/gone.go"}, base), review.Blocked)
	})
	t.Run("copied from a sensitive file needs the old side", func(t *testing.T) {
		t.Parallel()
		cp := review.ChangedPath{Path: "docs/copy.go", OldPath: "auth/src.go", Status: forge.FileCopied}
		wantDisp(t, mk(t, cp, "auth/src.go", []string{"auth/src.go"}, nil), review.Pass)
		wantDisp(t, mk(t, cp, "auth/src.go", []string{"auth/src.go"}, base), review.Blocked)
	})
	t.Run("copied into a sensitive path signs off the old path too", func(t *testing.T) {
		t.Parallel()
		cp := review.ChangedPath{Path: "auth/copy.go", OldPath: "lib/src.go", Status: forge.FileCopied}
		wantDisp(t, mk(t, cp, "auth/copy.go", []string{"auth/copy.go", "lib/src.go"}, nil), review.Pass)
		wantDisp(t, mk(t, cp, "auth/copy.go", []string{"auth/copy.go"}, nil), review.Blocked)
	})
	t.Run("renamed into a sensitive path signs off the old path too", func(t *testing.T) {
		t.Parallel()
		cp := review.ChangedPath{Path: "auth/new.go", OldPath: "lib/old.go", Status: forge.FileRenamed}
		wantDisp(t, mk(t, cp, "auth/new.go", []string{"auth/new.go", "lib/old.go"}, nil), review.Pass)
		wantDisp(t, mk(t, cp, "auth/new.go", []string{"auth/new.go"}, nil), review.Blocked)
	})
	t.Run("a modified file needs no base side", func(t *testing.T) {
		t.Parallel()
		cp := review.ChangedPath{Path: "auth/a.go", Status: forge.FileModified}
		wantDisp(t, mk(t, cp, "auth/a.go", []string{"auth/a.go"}, nil), review.Pass)
	})
}

func TestEvaluate_LightsOn_AreasCoverOldPaths(t *testing.T) { // CON-8
	t.Parallel()
	mk := func(areas [][]string) review.Decision {
		e := lightsOnFor(t, []review.ChangedPath{{Path: "public/x.go", OldPath: "payments/x.go", Status: forge.FileRenamed}}, areas)
		return e.eval()
	}
	wantInvalid(t, mk([][]string{{"public/x.go"}}))
	wantInvalid(t, mk([][]string{{"payments/x.go"}}))
	d := mk([][]string{{"public/x.go"}, {"payments/x.go"}})
	wantDisp(t, d, review.NeedsAuthorization)
	if len(d.RequiredApprovals) != 2 {
		t.Fatalf("targets = %+v", d.RequiredApprovals)
	}
	if !slices.ContainsFunc(d.RequiredApprovals, func(tg authz.Target) bool { return slices.Equal(tg.Paths, []string{"payments/x.go"}) }) {
		t.Errorf("no target covers the old path: %+v", d.RequiredApprovals)
	}
	d = mk([][]string{{"public/x.go", "payments/x.go"}})
	wantDisp(t, d, review.NeedsAuthorization)
}

func TestEvaluate_GateEvidenceBinds(t *testing.T) { // AGT-4, P4
	t.Parallel()
	gev := &review.GateEvidence{Gate: gref, RunID: "100", RunAttempt: "1", JobID: "200", CandidateSHA: cand}
	try := func(t *testing.T, outcome string, mutate func(e *env), head string) review.Decision {
		t.Helper()
		e := withClaim(t)
		if mutate != nil {
			mutate(e)
		}
		e.verify(vf{id: "v-g", claim: claimRef(), outcome: outcome, head: head, at: 20 * time.Minute, ev: &review.Evidence{Gate: gev}})
		return e.eval()
	}
	rejected := func(d review.Decision) bool {
		return slices.ContainsFunc(d.Rejected, func(r review.Rejection) bool { return r.ID == "v-g" && r.Reason == review.ReasonGateEvidenceMismatch })
	}
	failed := func(e *env) { e.snap.Gate.Obligations[0].Disposition = gate.Blocked }
	tests := []struct {
		name    string
		outcome string
		mutate  func(e *env)
		head    string
		reject  bool
	}{
		{"dismissal by a passing gate", review.OutcomeDismissed, nil, head1, false},
		{"confirmation by a failed gate", review.OutcomeConfirmed, failed, head1, false},
		{"confirmation citing a passing gate still stands", review.OutcomeConfirmed, nil, head1, false},
		{"confirmation citing a gate decision for another head still stands", review.OutcomeConfirmed, func(e *env) { e.snap.Gate.HeadSHA = head2 }, head1, false},
		{"confirmation citing no gate decision still stands", review.OutcomeConfirmed, func(e *env) { e.snap.Gate = nil }, head1, false},
		{"confirmation citing a gate outside the contract still stands", review.OutcomeConfirmed, func(e *env) { e.eff.VerifyGates = nil }, head1, false},
		{"dismissal citing a failed gate", review.OutcomeDismissed, failed, head1, true},
		{"gate decision for another head", review.OutcomeDismissed, func(e *env) { e.snap.Gate.HeadSHA = head2 }, head1, true},
		{"gate decision for another forge", review.OutcomeDismissed, func(e *env) { e.snap.Gate.Forge = "gitlab" }, head1, true},
		{"gate decision for another repo", review.OutcomeDismissed, func(e *env) { e.snap.Gate.Repo = "acme/other" }, head1, true},
		{"gate decision under another install revision", review.OutcomeDismissed, func(e *env) { e.snap.Gate.InstallRevision = "old" }, head1, true},
		{"gate obligation not mandatory", review.OutcomeDismissed, func(e *env) { e.snap.Gate.Obligations[0].Mandatory = false }, head1, true},
		{"gate not mandatory in the contract", review.OutcomeDismissed, func(e *env) { e.eff.VerifyGates[0].Gate.Mandatory = false }, head1, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := rejected(try(t, tc.outcome, tc.mutate, tc.head)); got != tc.reject {
				t.Errorf("rejected = %v, want %v", got, tc.reject)
			}
		})
	}
	t.Run("a proof digest serves either outcome", func(t *testing.T) {
		t.Parallel()
		for _, o := range []string{review.OutcomeConfirmed, review.OutcomeDismissed} {
			e := withClaim(t)
			e.verify(vf{id: "v-g", claim: claimRef(), outcome: o, at: 20 * time.Minute})
			if rejected(e.eval()) {
				t.Errorf("%s with a proof digest was rejected", o)
			}
		}
	})
}

func TestEvaluate_Repair_NeedsNewerHeadAndTime(t *testing.T) { // AGT-4
	t.Parallel()
	t.Run("a repair at the confirmed head is not a repair", func(t *testing.T) {
		t.Parallel()
		e := withClaim(t)
		e.verify(vf{claim: claimRef(), outcome: review.OutcomeConfirmed, at: 10 * time.Minute})
		e.review(rv{role: rolePR, round: "r2", repaired: []string{review.RepairedRef(cref("C1"))}, at: 20 * time.Minute, session: "pr-2"})
		e.verify(vf{claim: claimRef(), at: 30 * time.Minute})
		wantOb(t, e.eval(), cobl(rolePR, "C1"), review.Blocked, review.ReasonClaimConfirmed)
	})
	t.Run("a repair dated before the confirmation", func(t *testing.T) {
		t.Parallel()
		e := withClaim(t)
		e.verify(vf{claim: claimRef(), outcome: review.OutcomeConfirmed, at: 10 * time.Minute})
		e.tgt.HeadSHA = head2
		e.review(rv{role: rolePR, round: "r2", head: head2, repaired: []string{review.RepairedRef(cref("C1"))}, at: 5 * time.Minute, session: "pr-2"})
		e.verify(vf{claim: claimRef(), head: head2, at: 30 * time.Minute})
		wantOb(t, e.eval(), cobl(rolePR, "C1"), review.Blocked, review.ReasonClaimConfirmed)
	})
	t.Run("a repair in a superseded round", func(t *testing.T) {
		t.Parallel()
		e := withClaim(t)
		e.verify(vf{claim: claimRef(), outcome: review.OutcomeConfirmed, at: 10 * time.Minute})
		e.tgt.HeadSHA = head2
		e.review(rv{role: rolePR, round: "r2", head: head2, repaired: []string{review.RepairedRef(cref("C1"))}, at: 20 * time.Minute, session: "pr-2"})
		e.setRound("r2", 2, head2, review.RoundSuperseded)
		e.verify(vf{claim: claimRef(), head: head2, at: 30 * time.Minute})
		wantOb(t, e.eval(), cobl(rolePR, "C1"), review.Blocked, review.ReasonClaimConfirmed)
	})
}

func TestEvaluate_InvalidUTF8_Rejected(t *testing.T) { // SEC-11
	t.Parallel()
	bad := "x\xffy"
	t.Run("claim text", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t)
		c := claim("C1")
		c.Invariant = bad
		id := e.review(rv{role: rolePR, verdict: review.VerdictBlock, claims: []review.Claim{c}})
		d := e.eval()
		wantRejected(t, d, review.RecordAttestation, id, review.ReasonMalformed)
		wantInconsistent(t, d)
	})
	t.Run("manifest item path", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t)
		id := e.review(rv{role: rolePR, extra: []review.Item{{Kind: review.KindHistory, Path: bad, Digest: "sha256:h"}}})
		wantRejected(t, e.eval(), review.RecordAttestation, id, review.ReasonForbiddenContext)
	})
	t.Run("assignment profile", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t)
		e.review(rv{role: rolePR, id: "x"})
		e.snap.Assignments[0].Profile = bad
		d := e.eval()
		wantRejected(t, d, review.RecordAssignment, "x", review.ReasonBadAssignment)
		wantInconsistent(t, d) // the attestation for it can't be placed
	})
	t.Run("resolution procedure", func(t *testing.T) {
		t.Parallel()
		e := withClaim(t)
		e.verify(vf{id: "v1", claim: claimRef()})
		e.snap.Resolutions[0].Procedure = bad
		e.resignRes(0)
		d := e.eval()
		wantRejected(t, d, review.RecordResolution, "v1", review.ReasonMalformed)
		wantInconsistent(t, d)
	})
	t.Run("target and contract strings", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t)
		e.approveAll()
		e.tgt.Forge = bad
		wantInvalid(t, e.eval())
		e = newEnv(t)
		e.approveAll()
		e.eff.Revision = bad
		wantInvalid(t, e.eval())
	})
	t.Run("approval strings", func(t *testing.T) {
		t.Parallel()
		e := lightsOnEnv(t)
		e.snap.LightsOn.Callers = []string{bad}
		wantInvalid(t, e.eval())
	})
}

func TestEvaluate_ApprovalRevisionsAreDigests(t *testing.T) { // CON-8
	t.Parallel()
	for _, v := range []string{"", "imp-1", "sha256:abc", "sha256:" + strings.Repeat("A", 64)} {
		e := lightsOnEnv(t)
		e.snap.LightsOn.ImpactRevision = v
		wantInvalid(t, e.eval())
		e = lightsOnEnv(t)
		e.snap.LightsOn.RecoveryRevision = v
		wantInvalid(t, e.eval())
	}
}

func TestEvaluate_InconsistentInputs_Invalid(t *testing.T) { // SEC-5, CON-8
	t.Parallel()
	tests := map[string]func(e *env){
		"signoff required without sensitive paths": func(e *env) { e.eff.SecuritySignoffRequired = true },
		"sensitive paths without signoff required": func(e *env) { e.eff.SensitivePaths = []string{"auth/a.go"} },
		"zero now": func(e *env) { e.now = time.Time{} },
		"two different approval declarations": func(e *env) {
			e.eff.LightsOn = true
			e.snap.ChangedPaths = []review.ChangedPath{{Path: "a.go", Status: forge.FileModified}}
			e.snap.OwnerAreas = [][]string{{"a.go"}}
			e.snap.LightsOn = &review.Approval{Generation: 1, ImpactRevision: impRev, RecoveryRevision: recRev}
			e.snap.NonSwitchable = &review.Approval{Generation: 2, ImpactRevision: impRev, RecoveryRevision: recRev}
		},
		"PR reviewer not configured":           func(e *env) { e.cfg.PRReviewer = "" },
		"PR reviewer not required":             func(e *env) { e.cfg.PRReviewer = "ghost" },
		"PR reviewer is the security reviewer": func(e *env) { e.cfg.PRReviewer = roleSec },
		"invalid sensitive path": func(e *env) {
			e.eff.SecuritySignoffRequired, e.eff.SensitivePaths = true, []string{"../x"}
		},
	}
	for name, f := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			e := newEnv(t)
			e.approveAll()
			f(e)
			wantInvalid(t, e.eval())
		})
	}
	t.Run("equal declarations are accepted", func(t *testing.T) {
		t.Parallel()
		e := lightsOnEnv(t)
		cp := *e.snap.LightsOn
		e.snap.NonSwitchable = &cp
		wantDisp(t, e.eval(), review.NeedsAuthorization)
	})
}

func TestEvaluate_Rounds_CountOnlyFinished(t *testing.T) { // AGT-5
	t.Parallel()
	t.Run("two completed and one dispatched", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t)
		e.setRound("r1", 1, head1, review.RoundCompleted)
		e.setRound("r2", 2, head1, review.RoundCompleted)
		e.setRound("r3", 3, head1, review.RoundDispatched)
		wantDisp(t, e.eval(), review.Pending)
	})
	t.Run("cap of one with a dispatched round", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t)
		e.cfg.ReviewRounds = 1
		e.setRound("r1", 1, head1, review.RoundDispatched)
		wantDisp(t, e.eval(), review.Pending)
		e.setRound("r1", 1, head1, review.RoundCompleted)
		wantDisp(t, e.eval(), review.Escalated)
	})
}

func TestEvaluate_Rounds_Validated(t *testing.T) { // AGT-5
	t.Parallel()
	tests := map[string][]review.Round{
		"bad head":      {{ID: "r1", Seq: 1, HeadSHA: "abc", State: review.RoundCompleted}},
		"zero seq":      {{ID: "r1", Seq: 0, HeadSHA: head1, State: review.RoundCompleted}},
		"negative seq":  {{ID: "r1", Seq: -1, HeadSHA: head1, State: review.RoundCompleted}},
		"empty ID":      {{ID: "", Seq: 1, HeadSHA: head1, State: review.RoundCompleted}},
		"unknown state": {{ID: "r1", Seq: 1, HeadSHA: head1, State: "weird"}},
		"shared seq": {
			{ID: "r1", Seq: 1, HeadSHA: head1, State: review.RoundCompleted}, {ID: "r2", Seq: 1, HeadSHA: head1, State: review.RoundCompleted},
		},
		"same ID, different roles": {
			{ID: "r1", Seq: 1, HeadSHA: head1, State: review.RoundCompleted, Roles: []string{"a"}},
			{ID: "r1", Seq: 1, HeadSHA: head1, State: review.RoundCompleted, Roles: []string{"b"}},
		},
		"same ID, different head": {
			{ID: "r1", Seq: 1, HeadSHA: head1, State: review.RoundCompleted}, {ID: "r1", Seq: 1, HeadSHA: head2, State: review.RoundCompleted},
		},
	}
	for name, rounds := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			e := newEnv(t)
			e.snap.Rounds = rounds
			wantInvalid(t, e.eval())
		})
	}
	t.Run("identical redelivery of a round is fine", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t)
		e.setRound("r1", 1, head1, review.RoundCompleted)
		e.snap.Rounds = append(e.snap.Rounds, e.snap.Rounds[0])
		wantDisp(t, e.eval(), review.Pending)
	})
}

func TestEvaluate_RoleMustBeInRound(t *testing.T) { // AGT-5
	t.Parallel()
	e := newEnv(t)
	e.review(rv{role: rolePR})
	e.review(rv{role: roleSec})
	id := e.review(rv{role: roleGo})
	e.snap.Rounds[0].Roles = []string{rolePR, roleSec}
	d := e.eval()
	wantRejected(t, d, review.RecordAttestation, id, review.ReasonRoleNotInRound)
	wantOb(t, d, "role:"+roleGo, review.Blocked, review.ReasonInvalidVerdict)
}

func TestEvaluate_ManifestContent(t *testing.T) { // AGT-3
	t.Parallel()
	t.Run("an approval without a spec", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t)
		id := e.review(rv{role: rolePR, items: []review.Item{{Kind: review.KindDiff, Path: "a", Digest: "sha256:d"}}})
		wantRejected(t, e.eval(), review.RecordAttestation, id, review.ReasonManifestIncomplete)
	})
	t.Run("an approval without a diff", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t)
		id := e.review(rv{role: rolePR, items: []review.Item{{Kind: review.KindSpec, Digest: "sha256:s"}}})
		wantRejected(t, e.eval(), review.RecordAttestation, id, review.ReasonManifestIncomplete)
	})
	t.Run("an empty manifest", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t)
		id := e.review(rv{role: rolePR, items: []review.Item{}})
		wantRejected(t, e.eval(), review.RecordAttestation, id, review.ReasonManifestIncomplete)
	})
	t.Run("a claim must point into the manifest", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t)
		c := claim("C1")
		c.Path = "unseen/file.go"
		id := e.review(rv{role: rolePR, verdict: review.VerdictBlock, claims: []review.Claim{c}})
		wantRejected(t, e.eval(), review.RecordAttestation, id, review.ReasonBadClaim)
	})
	t.Run("a claim in a repo-file the reviewer read", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t)
		c := claim("C1")
		c.Path = "lib/caller.go"
		e.review(rv{
			role: rolePR, verdict: review.VerdictBlock, claims: []review.Claim{c},
			extra: []review.Item{{Kind: review.KindRepoFile, Path: "lib/caller.go", Digest: "sha256:r"}},
		})
		d := e.eval()
		wantOb(t, d, review.ClaimObligationID(review.ClaimRef{Role: rolePR, ID: "C1", Digest: c.Digest()}), review.Blocked, review.ReasonClaimOpen)
		wantOb(t, d, "role:"+rolePR, review.Blocked, review.ReasonReviewerBlocked) // a valid block, not an invalid verdict
		if len(d.Rejected) != 0 {
			t.Errorf("rejected = %+v", d.Rejected)
		}
	})
	t.Run("a claim in a path only listed as history", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t)
		c := claim("C1")
		c.Path = "lib/old.go"
		id := e.review(rv{
			role: rolePR, verdict: review.VerdictBlock, claims: []review.Claim{c},
			extra: []review.Item{{Kind: review.KindHistory, Path: "lib/old.go", Digest: "sha256:r"}},
		})
		wantRejected(t, e.eval(), review.RecordAttestation, id, review.ReasonBadClaim)
	})
	t.Run("an item with an empty digest", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t)
		id := e.review(rv{role: rolePR, extra: []review.Item{{Kind: review.KindHistory}}})
		wantRejected(t, e.eval(), review.RecordAttestation, id, review.ReasonForbiddenContext)
	})
}

func TestEvaluate_Split_CurrentVerdictOnly(t *testing.T) { // INT-20
	t.Parallel()
	t.Run("a split request with claims is invalid", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t)
		id := e.review(rv{role: rolePR, verdict: review.VerdictRequestSplit, split: sizeGate, claims: []review.Claim{claim("C1")}})
		d := e.eval()
		wantRejected(t, d, review.RecordAttestation, id, review.ReasonBadClaim)
		if _, ok := find(d, "split"); ok {
			t.Error("replan from an invalid split")
		}
	})
	t.Run("a later approval by the same role withdraws it", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t)
		e.review(rv{role: rolePR, verdict: review.VerdictRequestSplit, split: sizeGate})
		e.review(rv{role: rolePR, round: "r2", session: "pr-2"})
		d := e.eval()
		if _, ok := find(d, "split"); ok {
			t.Error("a withdrawn split request still asks for a replan")
		}
		wantOb(t, d, "role:"+rolePR, review.Pass, review.ReasonSatisfied)
	})
	t.Run("a superseded round hides only approvals, so its split still asks", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t)
		e.approveAll()
		e.review(rv{role: rolePR, round: "r2", verdict: review.VerdictRequestSplit, split: sizeGate, session: "pr-2"})
		e.snap.Rounds[1].State = review.RoundSuperseded
		d := e.eval()
		wantOb(t, d, "split", review.Replan, review.ReasonSplitRequested)
		wantDisp(t, d, review.Replan)
	})
}

func TestEvaluate_ClaimIDForm(t *testing.T) { // AGT-4
	t.Parallel()
	for _, id := range []string{"has space", "bad/slash", "", strings.Repeat("a", 65), "ünï", "x\n"} {
		t.Run(fmt.Sprintf("%q", id), func(t *testing.T) {
			t.Parallel()
			e := newEnv(t)
			c := claim("C1")
			c.ID = id
			att := e.review(rv{role: rolePR, verdict: review.VerdictBlock, claims: []review.Claim{c}})
			wantRejected(t, e.eval(), review.RecordAttestation, att, review.ReasonBadClaim)
		})
	}
	e := newEnv(t)
	e.review(rv{role: rolePR, verdict: review.VerdictBlock, claims: []review.Claim{claim("A.b_c-1"), claim(strings.Repeat("a", 64))}})
	if _, ok := find(e.eval(), review.ClaimObligationID(review.ClaimRef{Role: rolePR, ID: "A.b_c-1", Digest: claim("A.b_c-1").Digest()})); !ok {
		t.Error("a valid claim ID was refused")
	}
}

func TestEvaluate_SizeCaps(t *testing.T) { // SEC-1
	t.Parallel()
	t.Run("records per kind", func(t *testing.T) {
		t.Parallel()
		for name, f := range map[string]func(s *review.Snapshot){
			"assignments":  func(s *review.Snapshot) { s.Assignments = make([]review.Assignment, 10001) },
			"attestations": func(s *review.Snapshot) { s.Attestations = make([]review.Attestation, 10001) },
			"resolutions":  func(s *review.Snapshot) { s.Resolutions = make([]review.Resolution, 10001) },
			"rounds":       func(s *review.Snapshot) { s.Rounds = make([]review.Round, 10001) },
			"changed":      func(s *review.Snapshot) { s.ChangedPaths = make([]review.ChangedPath, 10001) },
			"areas":        func(s *review.Snapshot) { s.OwnerAreas = make([][]string, 10001) },
			"coders":       func(s *review.Snapshot) { s.CoderSessions = make([]string, 10001) },
		} {
			e := newEnv(t)
			f(&e.snap)
			if d := e.eval(); d.Disposition != review.Error {
				t.Errorf("%s: disposition = %s", name, d.Disposition)
			}
		}
	})
	t.Run("claims in one attestation", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t)
		e.review(rv{role: rolePR})
		e.snap.Attestations[0].Claims = make([]review.Claim, 101)
		wantInvalid(t, e.eval())
	})
	t.Run("items in one manifest", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t)
		id := e.review(rv{role: rolePR})
		e.snap.Manifests[id] = review.Manifest{HeadSHA: head1, Items: make([]review.Item, 10001)}
		wantInvalid(t, e.eval())
	})
	t.Run("at the caps", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t)
		e.snap.Assignments = make([]review.Assignment, 10000)
		wantDisp(t, e.eval(), review.Pending)
	})
}

func TestEvaluate_Ordering(t *testing.T) { // AGT-5
	t.Parallel()
	t.Run("a later round beats a later timestamp", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t)
		e.setRound("r1", 1, head1, review.RoundCompleted)
		e.review(rv{role: roleGo, round: "r1", verdict: review.VerdictBlock, claims: []review.Claim{claim("C1")}, at: 50 * time.Minute})
		e.review(rv{role: roleGo, round: "r2", at: 10 * time.Minute, session: "go-2"})
		wantOb(t, e.eval(), "role:"+roleGo, review.Pass, review.ReasonSatisfied)
	})
	t.Run("an earlier round loses to a later timestamp only within its round", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t)
		e.review(rv{role: roleGo, verdict: review.VerdictBlock, claims: []review.Claim{claim("C1")}, at: 10 * time.Minute})
		e.review(rv{role: roleGo, at: 20 * time.Minute, session: "go-2"})
		wantOb(t, e.eval(), "role:"+roleGo, review.Pass, review.ReasonSatisfied)
	})
	t.Run("block wins a tie", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t)
		e.review(rv{role: roleGo, at: 10 * time.Minute})
		e.review(rv{role: roleGo, verdict: review.VerdictBlock, claims: []review.Claim{claim("C1")}, at: 10 * time.Minute, session: "go-2"})
		wantOb(t, e.eval(), "role:"+roleGo, review.Blocked, review.ReasonReviewerBlocked)
	})
}

func TestEvaluate_RecordChecks(t *testing.T) { // AGT-3, SEC-11
	t.Parallel()
	t.Run("another forge or repo in the assignment", func(t *testing.T) {
		t.Parallel()
		for name, r := range map[string]rv{
			"forge": {role: roleGo, forgeName: "gitlab"},
			"repo":  {role: roleGo, repo: "acme/other"},
		} {
			t.Run(name, func(t *testing.T) {
				t.Parallel()
				e := newEnv(t)
				e.review(rv{role: rolePR})
				e.review(rv{role: roleSec})
				id := e.review(r)
				d := e.eval()
				wantRejected(t, d, review.RecordAttestation, id, review.ReasonWrongTarget)
				wantInconsistent(t, d)
			})
		}
	})
	t.Run("a head the round doesn't have", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t)
		id := e.review(rv{role: roleGo})
		e.snap.Assignments[0].HeadSHA = "abc"
		e.snap.Attestations[0].AssignmentDigest = e.snap.Assignments[0].Digest()
		e.resignAtt(0)
		d := e.eval()
		wantRejected(t, d, review.RecordAttestation, id, review.ReasonRoundMismatch)
		wantInconsistent(t, d)
	})
	t.Run("an empty role on the assignment", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t)
		id := e.review(rv{role: roleGo})
		e.snap.Assignments[0].Role = ""
		e.snap.Attestations[0].AssignmentDigest = e.snap.Assignments[0].Digest()
		e.resignAtt(0)
		wantRejected(t, e.eval(), review.RecordAttestation, id, review.ReasonRoleNotInRound)
	})
	t.Run("a zero timestamp", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t)
		id := e.review(rv{role: roleGo})
		e.snap.Attestations[0].At = time.Time{}
		e.resignAtt(0)
		wantRejected(t, e.eval(), review.RecordAttestation, id, review.ReasonMalformed)
	})

	t.Run("an ambiguous verify assignment", func(t *testing.T) {
		t.Parallel()
		e := withClaim(t)
		e.verify(vf{id: "v1", claim: claimRef()})
		dup := e.snap.Assignments[len(e.snap.Assignments)-1]
		dup.Profile = "another"
		e.snap.Assignments = append(e.snap.Assignments, dup)
		wantRejected(t, e.eval(), review.RecordResolution, "v1", review.ReasonUnknownAssignment)
	})
	t.Run("a verify assignment for another forge is not an attempt", func(t *testing.T) {
		t.Parallel()
		e := withClaim(t)
		for range 4 {
			e.verify(vf{claim: claimRef(), none: true})
		}
		for i := range e.snap.Assignments {
			if e.snap.Assignments[i].Purpose == review.PurposeVerify {
				e.snap.Assignments[i].Forge = "gitlab"
			}
		}
		wantOb(t, e.eval(), cobl(rolePR, "C1"), review.Blocked, review.ReasonClaimOpen)
	})
	t.Run("a short public key", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t)
		e.review(rv{role: rolePR})
		e.review(rv{role: roleSec})
		id := e.review(rv{role: roleGo})
		k := e.keys["k-"+roleGo+"-s"]
		k.Pub = k.Pub[:10]
		e.keys["k-"+roleGo+"-s"] = k
		wantRejected(t, e.eval(), review.RecordAttestation, id, review.ReasonBadSignature)
	})
	t.Run("a short signature", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t)
		id := e.review(rv{role: roleGo})
		e.snap.Attestations[0].Signature = e.snap.Attestations[0].Signature[:10]
		wantRejected(t, e.eval(), review.RecordAttestation, id, review.ReasonBadSignature)
	})
}

func TestEvaluate_ApprovalManifestData_BindsRevision(t *testing.T) { // CON-8, PIP-9
	t.Parallel()
	rev := func(f func(e *env)) string {
		e := lightsOnEnv(t)
		f(e)
		return e.eval().RequiredApprovals[0].Revision
	}
	same := rev(func(*env) {})
	ns := rev(func(e *env) {
		e.snap.NonSwitchable = &review.Approval{Generation: 1, ImpactRevision: impRev, RecoveryRevision: recRev}
	})
	if ns != same {
		t.Error("a non-switchable declaration with the same data changes the revision")
	}
	if ns2 := rev(func(e *env) {
		e.snap.LightsOn = nil
		e.snap.NonSwitchable = &review.Approval{Generation: 2, ImpactRevision: impRev, RecoveryRevision: recRev}
	}); ns2 == same {
		t.Error("non-switchable data does not bind into the revision")
	}
	for name, f := range map[string]func(e *env){
		"forge": func(e *env) { e.tgt.Forge = "gitlab"; e.snap.Attestations = nil },
		"repo":  func(e *env) { e.tgt.Repo = "acme/other"; e.snap.Attestations = nil },
	} {
		if rev(f) == same {
			t.Errorf("%s does not bind into the revision", name)
		}
	}
}

func TestEncodings_CoverEveryField(t *testing.T) { //nolint:gocognit // one table per encoding, each field changed in turn
	t.Parallel()
	t.Run("attestation", func(t *testing.T) {
		t.Parallel()
		base := review.Attestation{
			AssignmentID: "a", AssignmentDigest: "d", Verdict: "block", Claims: []review.Claim{claim("A")}, SplitGateID: "g",
			SensitiveSignoff: []string{"x"}, Repaired: []string{"r"}, At: time.Unix(5, 0), KeyID: "k",
		}
		muts := map[string]func(a *review.Attestation){
			"AssignmentID":      func(a *review.Attestation) { a.AssignmentID = "b" },
			"AssignmentDigest":  func(a *review.Attestation) { a.AssignmentDigest = "e" },
			"Verdict":           func(a *review.Attestation) { a.Verdict = "approve" },
			"Claims":            func(a *review.Attestation) { a.Claims = nil },
			"claim ID":          func(a *review.Attestation) { a.Claims = []review.Claim{claim("B")} },
			"claim path":        func(a *review.Attestation) { a.Claims[0].Path = "other.go" },
			"claim start":       func(a *review.Attestation) { a.Claims[0].StartLine++ },
			"claim end":         func(a *review.Attestation) { a.Claims[0].EndLine++ },
			"claim invariant":   func(a *review.Attestation) { a.Claims[0].Invariant = "z" },
			"claim consequence": func(a *review.Attestation) { a.Claims[0].Consequence = "z" },
			"claim plan":        func(a *review.Attestation) { a.Claims[0].VerificationPlan = "z" },
			"SplitGateID":       func(a *review.Attestation) { a.SplitGateID = "h" },
			"SensitiveSignoff":  func(a *review.Attestation) { a.SensitiveSignoff = []string{"y"} },
			"Repaired":          func(a *review.Attestation) { a.Repaired = []string{"s"} },
			"At":                func(a *review.Attestation) { a.At = a.At.Add(time.Second) },
			"KeyID":             func(a *review.Attestation) { a.KeyID = "l" },
		}
		for name, f := range muts {
			m := base
			m.Claims = slices.Clone(base.Claims)
			f(&m)
			if bytes.Equal(base.SigningPayload(), m.SigningPayload()) {
				t.Errorf("%s is not covered", name)
			}
		}
	})
	t.Run("claims sorted on every field", func(t *testing.T) {
		t.Parallel()
		a, b := claim("A"), claim("A")
		b.Path = "z.go"
		x := review.Attestation{Claims: []review.Claim{a, b}}
		y := review.Attestation{Claims: []review.Claim{b, a}}
		if !bytes.Equal(x.SigningPayload(), y.SigningPayload()) {
			t.Error("claim order changes the payload")
		}
	})
	t.Run("resolution", func(t *testing.T) {
		t.Parallel()
		g := &review.GateEvidence{Gate: gref, RunID: "1", RunAttempt: "2", JobID: "3", CandidateSHA: cand}
		base := review.Resolution{
			AssignmentID: "a", AssignmentDigest: "d", Claim: cref("C1"), ReviewedRevision: head1, Procedure: "p", Expected: "e",
			Outcome: "confirmed", Evidence: review.Evidence{ProofDigest: "sha256:p", Gate: g}, At: time.Unix(5, 0), KeyID: "k",
		}
		muts := map[string]func(r *review.Resolution){
			"AssignmentID":     func(r *review.Resolution) { r.AssignmentID = "b" },
			"AssignmentDigest": func(r *review.Resolution) { r.AssignmentDigest = "e" },
			"claim role":       func(r *review.Resolution) { r.Claim.Role = "x" },
			"claim ID":         func(r *review.Resolution) { r.Claim.ID = "x" },
			"claim digest":     func(r *review.Resolution) { r.Claim.Digest = "x" },
			"ReviewedRevision": func(r *review.Resolution) { r.ReviewedRevision = head2 },
			"Procedure":        func(r *review.Resolution) { r.Procedure = "q" },
			"Expected":         func(r *review.Resolution) { r.Expected = "q" },
			"Outcome":          func(r *review.Resolution) { r.Outcome = "dismissed" },
			"ProofDigest":      func(r *review.Resolution) { r.Evidence.ProofDigest = "sha256:q" },
			"no gate":          func(r *review.Resolution) { r.Evidence.Gate = nil },
			"gate producer":    func(r *review.Resolution) { r.Evidence.Gate.Gate.ProducerID = "x" },
			"gate workflow":    func(r *review.Resolution) { r.Evidence.Gate.Gate.WorkflowID = "x" },
			"gate revision":    func(r *review.Resolution) { r.Evidence.Gate.Gate.WorkflowRevision = "x" },
			"gate check":       func(r *review.Resolution) { r.Evidence.Gate.Gate.CheckID = "x" },
			"gate run":         func(r *review.Resolution) { r.Evidence.Gate.RunID = "x" },
			"gate attempt":     func(r *review.Resolution) { r.Evidence.Gate.RunAttempt = "x" },
			"gate job":         func(r *review.Resolution) { r.Evidence.Gate.JobID = "x" },
			"gate candidate":   func(r *review.Resolution) { r.Evidence.Gate.CandidateSHA = head2 },
			"At":               func(r *review.Resolution) { r.At = r.At.Add(time.Second) },
			"KeyID":            func(r *review.Resolution) { r.KeyID = "l" },
		}
		for name, f := range muts {
			m := base
			cp := *g
			m.Evidence.Gate = &cp
			f(&m)
			if bytes.Equal(base.SigningPayload(), m.SigningPayload()) {
				t.Errorf("%s is not covered", name)
			}
		}
	})
	t.Run("assignment", func(t *testing.T) {
		t.Parallel()
		base := review.Assignment{
			ID: "a", Forge: "f", Repo: "r", PR: 1, HeadSHA: head1, RoundID: "r1", Role: "role", Profile: "p",
			ManifestDigest: "m", Purpose: review.PurposeVerify, ClaimRef: cref("C1"), Session: "s",
		}
		muts := map[string]func(a *review.Assignment){
			"ID": func(a *review.Assignment) { a.ID = "b" }, "Forge": func(a *review.Assignment) { a.Forge = "g" },
			"Repo": func(a *review.Assignment) { a.Repo = "s" }, "PR": func(a *review.Assignment) { a.PR = 2 },
			"HeadSHA": func(a *review.Assignment) { a.HeadSHA = head2 }, "RoundID": func(a *review.Assignment) { a.RoundID = "r2" },
			"Role": func(a *review.Assignment) { a.Role = "x" }, "Profile": func(a *review.Assignment) { a.Profile = "q" },
			"ManifestDigest": func(a *review.Assignment) { a.ManifestDigest = "n" },
			"Purpose":        func(a *review.Assignment) { a.Purpose = review.PurposeReview },
			"claim role":     func(a *review.Assignment) { a.ClaimRef.Role = "x" },
			"claim ID":       func(a *review.Assignment) { a.ClaimRef.ID = "x" },
			"claim digest":   func(a *review.Assignment) { a.ClaimRef.Digest = "x" },
			"Session":        func(a *review.Assignment) { a.Session = "t" },
		}
		for name, f := range muts {
			m := base
			f(&m)
			if base.Digest() == m.Digest() {
				t.Errorf("%s is not covered", name)
			}
		}
	})
	t.Run("claim", func(t *testing.T) {
		t.Parallel()
		base := claim("A")
		muts := map[string]func(c *review.Claim){
			"Path": func(c *review.Claim) { c.Path = "z.go" }, "StartLine": func(c *review.Claim) { c.StartLine++ },
			"EndLine": func(c *review.Claim) { c.EndLine++ }, "Invariant": func(c *review.Claim) { c.Invariant = "z" },
			"Consequence": func(c *review.Claim) { c.Consequence = "z" }, "VerificationPlan": func(c *review.Claim) { c.VerificationPlan = "z" },
		}
		for name, f := range muts {
			m := base
			f(&m)
			if base.Digest() == m.Digest() {
				t.Errorf("%s is not covered", name)
			}
		}
		other := base
		other.ID = "B"
		if base.Digest() != other.Digest() {
			t.Error("the claim ID is part of the content digest, but the instance key carries it")
		}
	})
	t.Run("manifest", func(t *testing.T) {
		t.Parallel()
		base := review.Manifest{HeadSHA: head1, Items: []review.Item{{Kind: "diff", Path: "p", Side: "base", Digest: "d"}}}
		muts := map[string]func(m *review.Manifest){
			"HeadSHA": func(m *review.Manifest) { m.HeadSHA = head2 }, "Kind": func(m *review.Manifest) { m.Items[0].Kind = "spec" },
			"Path": func(m *review.Manifest) { m.Items[0].Path = "q" }, "Side": func(m *review.Manifest) { m.Items[0].Side = "head" },
			"Digest": func(m *review.Manifest) { m.Items[0].Digest = "e" }, "Items": func(m *review.Manifest) { m.Items = nil },
		}
		for name, f := range muts {
			m := review.Manifest{HeadSHA: base.HeadSHA, Items: slices.Clone(base.Items)}
			f(&m)
			if base.Digest() == m.Digest() {
				t.Errorf("%s is not covered", name)
			}
		}
	})
	t.Run("approval manifest", func(t *testing.T) {
		t.Parallel()
		base := review.ApprovalManifest{
			Forge: "f", Repo: "r", PR: 1, Generation: 1, HeadSHA: head1, ImpactRevision: impRev, RecoveryRevision: recRev,
			Callers: []string{"a"}, RolloutOrder: []string{"a", "b"},
		}
		muts := map[string]func(m *review.ApprovalManifest){
			"Forge": func(m *review.ApprovalManifest) { m.Forge = "g" }, "Repo": func(m *review.ApprovalManifest) { m.Repo = "s" },
			"PR": func(m *review.ApprovalManifest) { m.PR = 2 }, "Generation": func(m *review.ApprovalManifest) { m.Generation = 2 },
			"HeadSHA":          func(m *review.ApprovalManifest) { m.HeadSHA = head2 },
			"ImpactRevision":   func(m *review.ApprovalManifest) { m.ImpactRevision = impRev2 },
			"RecoveryRevision": func(m *review.ApprovalManifest) { m.RecoveryRevision = recRev2 },
			"Callers":          func(m *review.ApprovalManifest) { m.Callers = []string{"b"} },
			"RolloutOrder":     func(m *review.ApprovalManifest) { m.RolloutOrder = []string{"b", "a"} },
		}
		for name, f := range muts {
			m := base
			f(&m)
			if base.Digest() == m.Digest() {
				t.Errorf("%s is not covered", name)
			}
		}
	})
	t.Run("domains differ on identical bodies", func(t *testing.T) {
		t.Parallel()
		a := review.Attestation{}.SigningPayload()
		r := review.Resolution{}.SigningPayload()
		pa, pr := bytes.IndexByte(a, '\n'), bytes.IndexByte(r, '\n')
		if bytes.Equal(a[:pa], r[:pr]) {
			t.Error("attestation and resolution share a domain")
		}
		domains := map[string]bool{}
		for _, d := range []string{string(a[:pa]), string(r[:pr])} {
			domains[d] = true
		}
		if len(domains) != 2 {
			t.Error("domains not distinct")
		}
		// The digests of distinct record types over zero values must differ too.
		seen := map[string]string{
			"assignment": review.Assignment{}.Digest(), "claim": review.Claim{}.Digest(),
			"manifest": review.Manifest{}.Digest(), "approval": "sha256:" + review.ApprovalManifest{}.Digest(),
		}
		uniq := map[string]bool{}
		for _, v := range seen {
			uniq[v] = true
		}
		if len(uniq) != len(seen) {
			t.Error("two encodings share a digest")
		}
	})
}

func TestApprovalManifest_Digest_Golden(t *testing.T) { // CON-8
	// WI-17 builds the same manifest from the proposal: this digest is a shared contract.
	m := review.ApprovalManifest{
		Forge: "github", Repo: "acme/app", PR: 7, Generation: 3, HeadSHA: head1,
		ImpactRevision: impRev, RecoveryRevision: recRev,
		Callers: []string{"svc-b", "svc-a"}, RolloutOrder: []string{"svc-a", "svc-b"},
	}
	got := []byte(m.Digest() + "\n")
	const path = "testdata/approval_manifest.golden"
	if *update {
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("digest = %s, want %s (run with -update after a deliberate change)", got, want)
	}
}
