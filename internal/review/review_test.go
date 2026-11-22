// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

package review_test

import (
	"bytes"
	"math/rand/v2"
	"slices"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/elliott-davis/lightsout/internal/audit"
	"github.com/elliott-davis/lightsout/internal/authz"
	"github.com/elliott-davis/lightsout/internal/contract"
	"github.com/elliott-davis/lightsout/internal/forge"
	"github.com/elliott-davis/lightsout/internal/review"
)

func TestEvaluate_AllRolesApprove_Pass(t *testing.T) { // AGT-3, AGD-3
	e := newEnv(t)
	e.approveAll()
	d := e.eval()
	wantDisp(t, d, review.Pass)
	if d.PolicyRevision != "pol-1" || d.InstallRevision != "inst-1" || d.StateVersion != "sv-1" || d.HeadSHA != head1 {
		t.Errorf("decision does not bind its inputs: %+v", d)
	}
	for _, r := range []string{rolePR, roleSec, roleGo} {
		wantOb(t, d, "role:"+r, review.Pass, review.ReasonSatisfied)
	}
}

func TestEvaluate_MissingRole_Pending(t *testing.T) { // AGD-3
	e := newEnv(t)
	e.review(rv{role: rolePR})
	e.review(rv{role: roleSec})
	d := e.eval()
	wantDisp(t, d, review.Pending)
	wantOb(t, d, "role:"+roleGo, review.Pending, review.ReasonNoApproval)
}

func TestEvaluate_ApprovalAtOlderHead_DoesNotCount(t *testing.T) { // AGT-3
	e := newEnv(t)
	e.tgt.HeadSHA = head2 // the change was pushed after the pr-reviewer approved head1
	e.review(rv{role: rolePR, head: head1})
	e.review(rv{role: roleSec, head: head2, round: "r2"})
	e.review(rv{role: roleGo, head: head2, round: "r2"})
	d := e.eval()
	wantDisp(t, d, review.Pending)
	wantOb(t, d, "role:"+rolePR, review.Pending, review.ReasonNoApproval)
	wantOb(t, d, "role:"+roleSec, review.Pass, review.ReasonSatisfied)
}

func TestEvaluate_CoderSessionAsReviewer_Rejected(t *testing.T) { // AGD-3, SEC-11
	e := newEnv(t)
	e.review(rv{role: rolePR})
	e.review(rv{role: roleSec})
	id := e.review(rv{role: roleGo, session: "coder-1"})
	d := e.eval()
	// CoderSessions comes from the snapshot, so it can't silently drop a signed record: the evidence is inconsistent.
	wantInconsistent(t, d)
	wantRejected(t, d, review.RecordAttestation, id, review.ReasonCoderSession)
}

func TestEvaluate_OneSessionTwoRoles_Rejected(t *testing.T) { // AGD-3
	e := newEnv(t)
	e.review(rv{role: rolePR, session: "shared"})
	e.review(rv{role: roleSec})
	e.review(rv{role: roleGo, session: "shared"})
	d := e.eval()
	wantDisp(t, d, review.Blocked)
	wantOb(t, d, "role:"+rolePR, review.Blocked, review.ReasonSessionReuse)
	wantOb(t, d, "role:"+roleGo, review.Blocked, review.ReasonSessionReuse)
	wantOb(t, d, "role:"+roleSec, review.Pass, review.ReasonSatisfied)
}

func TestEvaluate_ForgedAttestation_Rejected(t *testing.T) { // AGT-3, SEC-11
	t.Parallel()
	tests := []struct {
		name   string
		tamper func(e *env, a *review.Attestation)
	}{
		{"flipped signature byte", func(_ *env, a *review.Attestation) { a.Signature[0] ^= 0xff }},
		{"unknown key ID", func(_ *env, a *review.Attestation) { a.KeyID = "rt-unknown" }},
		{"valid signature by a different key", func(e *env, a *review.Attestation) {
			a.Signature = e.sign("k-fallback", a.SigningPayload()) // KeyID still names the session key
		}},
		{"empty signature", func(_ *env, a *review.Attestation) { a.Signature = nil }},
		{"later timestamp", func(_ *env, a *review.Attestation) { a.At = a.At.Add(time.Second) }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			e := newEnv(t)
			e.review(rv{role: rolePR})
			e.review(rv{role: roleSec})
			id := e.review(rv{role: roleGo})
			tc.tamper(e, &e.snap.Attestations[2])
			d := e.eval()
			wantDisp(t, d, review.Pending)
			wantRejected(t, d, review.RecordAttestation, id, review.ReasonBadSignature)
		})
	}
}

func TestEvaluate_BlockAlteredToApprove_Rejected(t *testing.T) { // AGT-3, AGT-4
	e := newEnv(t)
	e.approveAll()
	id := e.review(rv{role: rolePR, round: "r2", verdict: review.VerdictBlock, claims: []review.Claim{claim("C1")}})
	last := &e.snap.Attestations[len(e.snap.Attestations)-1]
	last.Verdict, last.Claims = review.VerdictApprove, nil
	d := e.eval()
	wantRejected(t, d, review.RecordAttestation, id, review.ReasonBadSignature)
	// The forged approve is dropped, and so is the honest block it replaced: the earlier approval stands.
	wantDisp(t, d, review.Pass)
}

func TestEvaluate_AttestationMoved_Rejected(t *testing.T) { // AGT-3, SEC-11
	t.Parallel()
	t.Run("to another PR's assignment", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t)
		e.review(rv{role: rolePR})
		e.review(rv{role: roleSec})
		id := e.review(rv{role: roleGo, pr: 99})
		d := e.eval()
		wantRejected(t, d, review.RecordAttestation, id, review.ReasonWrongTarget)
		wantInconsistent(t, d)
	})
	t.Run("to another assignment", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t)
		e.review(rv{role: rolePR})
		e.review(rv{role: roleSec})
		e.review(rv{role: roleGo, noAttest: true})
		moved := e.snap.Attestations[0] // pr-reviewer's approval, re-pointed
		moved.AssignmentID = e.snap.Assignments[2].ID
		e.snap.Attestations = append(e.snap.Attestations[:0:0], e.snap.Attestations[1:]...)
		e.snap.Attestations = append(e.snap.Attestations, moved)
		d := e.eval()
		wantRejected(t, d, review.RecordAttestation, moved.AssignmentID, review.ReasonBadSignature)
		wantDisp(t, d, review.Pending)
	})
	t.Run("to a nonexistent assignment", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t)
		e.approveAll()
		e.snap.Assignments = e.snap.Assignments[:2]
		d := e.eval()
		wantRejected(t, d, review.RecordAttestation, "a3", review.ReasonUnknownAssignment)
		wantInconsistent(t, d) // a signed record we can't place: the snapshot is inconsistent
	})
}

func TestEvaluate_ManifestSwapped_Rejected(t *testing.T) { // AGT-3
	e := newEnv(t)
	e.review(rv{role: rolePR})
	e.review(rv{role: roleSec})
	id := e.review(rv{role: roleGo})
	// The writer swaps in a manifest the reviewer was not shown.
	e.snap.Manifests[id] = review.Manifest{HeadSHA: head1, Items: []review.Item{{Kind: review.KindSpec, Digest: "sha256:other"}}}
	d := e.eval()
	wantRejected(t, d, review.RecordAttestation, id, review.ReasonManifestMismatch)
	wantOb(t, d, "role:"+roleGo, review.Blocked, review.ReasonInvalidVerdict)
	wantDisp(t, d, review.Blocked)
}

func TestEvaluate_MissingManifest_Rejected(t *testing.T) { // AGT-3
	e := newEnv(t)
	e.approveAll()
	delete(e.snap.Manifests, "a3")
	d := e.eval()
	wantRejected(t, d, review.RecordAttestation, "a3", review.ReasonManifestMissing)
	wantOb(t, d, "role:"+roleGo, review.Blocked, review.ReasonInvalidVerdict)
	wantDisp(t, d, review.Blocked)
}

func TestEvaluate_DuplicateAttestations(t *testing.T) { // AGT-3
	t.Parallel()
	t.Run("identical redelivery counts once", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t)
		e.approveAll()
		e.snap.Attestations = append(e.snap.Attestations, e.snap.Attestations...)
		d := e.eval()
		wantDisp(t, d, review.Pass)
		if len(d.Rejected) != 0 {
			t.Errorf("rejected = %+v", d.Rejected)
		}
	})
	t.Run("two differing attestations invalidate the assignment", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t)
		e.approveAll()
		other := e.snap.Attestations[2]
		other.Verdict, other.Claims = review.VerdictBlock, []review.Claim{claim("C1")}
		e.snap.Attestations = append(e.snap.Attestations, other)
		e.resignAtt(3)
		d := e.eval()
		wantRejected(t, d, review.RecordAttestation, "a3", review.ReasonConflictingRecords)
		wantOb(t, d, "role:"+roleGo, review.Blocked, review.ReasonInvalidVerdict)
		// The block of the conflicting pair still blocks: nobody can shed a claim by sending a second version.
		wantOb(t, d, cobl(roleGo, "C1"), review.Blocked, review.ReasonClaimOpen)
		wantDisp(t, d, review.Blocked)
	})
	t.Run("a forged duplicate cannot invalidate a genuine attestation", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t)
		e.approveAll()
		forged := e.snap.Attestations[2]
		forged.Verdict, forged.Claims = review.VerdictBlock, []review.Claim{claim("C1")}
		e.snap.Attestations = append(e.snap.Attestations, forged) // old signature
		d := e.eval()
		wantRejected(t, d, review.RecordAttestation, "a3", review.ReasonBadSignature)
		wantDisp(t, d, review.Pass)
	})
	t.Run("two differing assignments with one ID", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t)
		e.approveAll()
		dup := e.snap.Assignments[2]
		dup.Session = "another"
		e.snap.Assignments = append(e.snap.Assignments, dup)
		d := e.eval()
		wantRejected(t, d, review.RecordAssignment, "a3", review.ReasonDuplicateAssignment)
		wantDisp(t, d, review.Error) // the signed attestation can't be placed
	})
}

func TestEvaluate_ReviewerContext(t *testing.T) { // AGT-3
	t.Parallel()
	forbidden := []string{"coder-reasoning", "transcript", "private-holdout", "unknown-kind", ""}
	for _, kind := range forbidden {
		t.Run("kind "+kind, func(t *testing.T) {
			t.Parallel()
			e := newEnv(t)
			e.review(rv{role: rolePR})
			e.review(rv{role: roleSec})
			id := e.review(rv{role: roleGo, extra: []review.Item{{Kind: kind, Digest: "sha256:x"}}})
			d := e.eval()
			wantRejected(t, d, review.RecordAttestation, id, review.ReasonForbiddenContext)
			wantOb(t, d, "role:"+roleGo, review.Blocked, review.ReasonInvalidVerdict)
			wantDisp(t, d, review.Blocked)
		})
	}
	t.Run("bad side", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t)
		id := e.review(rv{role: roleGo, items: []review.Item{{Kind: review.KindDiff, Side: "middle", Digest: "sha256:x"}}})
		wantRejected(t, e.eval(), review.RecordAttestation, id, review.ReasonForbiddenContext)
	})
	t.Run("manifest head differs from the assignment", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t)
		id := e.review(rv{role: roleGo, mhead: head2})
		wantRejected(t, e.eval(), review.RecordAttestation, id, review.ReasonManifestHead)
	})
	t.Run("all allowed kinds", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t)
		items := e.fullItems()
		for _, k := range []string{"spec", "diff", "repo-file", "caller", "contract", "history", "public-test"} {
			items = append(items, review.Item{Kind: k, Path: "p", Side: review.SideBase, Digest: "sha256:x"})
		}
		e.review(rv{role: rolePR, items: items})
		e.review(rv{role: roleSec})
		e.review(rv{role: roleGo})
		wantDisp(t, e.eval(), review.Pass)
	})
}

func TestEvaluate_MalformedClaims_InvalidAttestation(t *testing.T) { // AGT-4
	t.Parallel()
	mod := func(f func(*review.Claim)) review.Claim { c := claim("C1"); f(&c); return c }
	tests := []struct {
		name   string
		claims []review.Claim
		verdic string
	}{
		{"no ID", []review.Claim{mod(func(c *review.Claim) { c.ID = "" })}, review.VerdictBlock},
		{"no location", []review.Claim{mod(func(c *review.Claim) { c.Path = "" })}, review.VerdictBlock},
		{"no invariant", []review.Claim{mod(func(c *review.Claim) { c.Invariant = " " })}, review.VerdictBlock},
		{"no consequence", []review.Claim{mod(func(c *review.Claim) { c.Consequence = "" })}, review.VerdictBlock},
		{"no verification plan", []review.Claim{mod(func(c *review.Claim) { c.VerificationPlan = "" })}, review.VerdictBlock},
		{"start line zero", []review.Claim{mod(func(c *review.Claim) { c.StartLine = 0 })}, review.VerdictBlock},
		{"end before start", []review.Claim{mod(func(c *review.Claim) { c.StartLine, c.EndLine = 9, 3 })}, review.VerdictBlock},
		{"invalid path", []review.Claim{mod(func(c *review.Claim) { c.Path = "../etc/passwd" })}, review.VerdictBlock},
		{"repeated claim ID", []review.Claim{claim("C1"), claim("C1")}, review.VerdictBlock},
		{"block without claims", nil, review.VerdictBlock},
		{"approve with claims", []review.Claim{claim("C1")}, review.VerdictApprove},
		{"unknown verdict", nil, "lgtm"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			e := newEnv(t)
			e.review(rv{role: rolePR})
			e.review(rv{role: roleSec})
			id := e.review(rv{role: roleGo, verdict: tc.verdic, claims: tc.claims})
			d := e.eval()
			if tc.verdic == "lgtm" {
				wantRejected(t, d, review.RecordAttestation, id, review.ReasonBadVerdict)
			} else {
				wantRejected(t, d, review.RecordAttestation, id, review.ReasonBadClaim)
			}
			// The invalid verdict is the role's newest: it never approves, and it hides nothing older.
			wantOb(t, d, "role:"+roleGo, review.Blocked, review.ReasonInvalidVerdict)
			wantDisp(t, d, review.Blocked)
		})
	}
}

func TestEvaluate_InvalidVerdict_WellFormedClaimsStillContribute(t *testing.T) { // AGT-4
	t.Parallel()
	bad := claim("C2")
	bad.Invariant = ""
	tests := map[string]rv{
		"block with one bad claim":   {role: roleGo, verdict: review.VerdictBlock, claims: []review.Claim{claim("C1"), bad}},
		"approve with a claim":       {role: roleGo, claims: []review.Claim{claim("C1")}},
		"split with a claim":         {role: roleGo, verdict: review.VerdictRequestSplit, split: sizeGate, claims: []review.Claim{claim("C1")}},
		"unknown verdict with claim": {role: roleGo, verdict: "lgtm", claims: []review.Claim{claim("C1")}},
		"claim ID repeated":          {role: roleGo, verdict: review.VerdictBlock, claims: []review.Claim{claim("C1"), claim("C1")}},
	}
	for name, r := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			e := newEnv(t)
			e.review(r)
			d := e.eval()
			wantOb(t, d, cobl(roleGo, "C1"), review.Blocked, review.ReasonClaimOpen)
			if _, ok := find(d, cobl(roleGo, "C2")); ok {
				t.Error("a malformed claim contributed")
			}
		})
	}
}

func TestEvaluate_ClaimStaysOpenWithGatesGreen_Blocked(t *testing.T) { // AGT-4, P4
	e := newEnv(t)
	e.review(rv{role: rolePR, verdict: review.VerdictBlock, claims: []review.Claim{claim("C1")}})
	e.review(rv{role: roleSec})
	e.review(rv{role: roleGo})
	d := e.eval() // the gate decision in the snapshot is green
	wantDisp(t, d, review.Blocked)
	wantOb(t, d, cobl(rolePR, "C1"), review.Blocked, review.ReasonClaimOpen)
	wantOb(t, d, "role:"+rolePR, review.Blocked, review.ReasonReviewerBlocked)
}

func cref(id string) review.ClaimRef {
	return review.ClaimRef{Role: rolePR, ID: id, Digest: claim(id).Digest()}
}

func claimRef() review.ClaimRef { return cref("C1") }

// withClaim returns an env where the pr-reviewer raised C1 and the other roles approve.
func withClaim(t *testing.T) *env {
	t.Helper()
	e := newEnv(t)
	e.review(rv{role: rolePR, verdict: review.VerdictBlock, claims: []review.Claim{claim("C1")}, at: time.Minute})
	e.review(rv{role: roleSec})
	e.review(rv{role: roleGo})
	return e
}

// reapprove adds a follow-up round where the claimant role approves again.
func reapprove(e *env) {
	e.review(rv{role: rolePR, round: "r2", at: 30 * time.Minute, session: "pr-follow-up"})
}

func TestEvaluate_ClaimResolutionRejected(t *testing.T) { // AGT-4, SEC-11
	t.Parallel()
	green := func(g *review.GateEvidence) *review.Evidence { return &review.Evidence{Gate: g} }
	gev := review.GateEvidence{Gate: gref, RunID: "100", RunAttempt: "1", JobID: "200", CandidateSHA: cand}
	tests := []struct {
		name   string
		setup  func(e *env)
		reason review.Reason
		v      vf
	}{
		{"claimant session", nil, review.ReasonVerifierNotIndep, vf{session: rolePR + "-s"}},
		{"session that attested the claim in another round", func(e *env) {
			e.review(rv{role: rolePR, round: "r2", verdict: review.VerdictBlock, claims: []review.Claim{claim("C1")}, session: "pr-2"})
		}, review.ReasonVerifierNotIndep, vf{session: "pr-2"}},
		{"signed by an untrusted key", nil, review.ReasonBadSignature, vf{key: "rt-nope"}},
		{"gate evidence without a gate decision", func(e *env) { e.snap.Gate = nil }, review.ReasonGateEvidenceMismatch, vf{ev: green(&gev)}},
		{"unrelated green job", nil, review.ReasonGateEvidenceMismatch, vf{ev: green(&review.GateEvidence{
			Gate: gref, RunID: "100", RunAttempt: "1", JobID: "999", CandidateSHA: cand,
		})}},
		{"wrong run", nil, review.ReasonGateEvidenceMismatch, vf{ev: green(&review.GateEvidence{
			Gate: gref, RunID: "101", RunAttempt: "1", JobID: "200", CandidateSHA: cand,
		})}},
		{"wrong attempt", nil, review.ReasonGateEvidenceMismatch, vf{ev: green(&review.GateEvidence{
			Gate: gref, RunID: "100", RunAttempt: "2", JobID: "200", CandidateSHA: cand,
		})}},
		{"wrong candidate", nil, review.ReasonGateEvidenceMismatch, vf{ev: green(&review.GateEvidence{
			Gate: gref, RunID: "100", RunAttempt: "1", JobID: "200", CandidateSHA: head2,
		})}},
		{"gate not mandatory in this change", func(e *env) { e.eff.VerifyGates = nil }, review.ReasonGateEvidenceMismatch, vf{ev: green(&gev)}},
		{"obligation not mandatory in the gate decision", func(e *env) { e.snap.Gate.Obligations[0].Mandatory = false }, review.ReasonGateEvidenceMismatch, vf{ev: green(&gev)}},
		{"dismissal by a gate that did not pass", func(e *env) { e.snap.Gate.Obligations[0].Disposition = "blocked" }, review.ReasonGateEvidenceMismatch, vf{ev: green(&gev)}},
		{"gate decision for another PR", func(e *env) { e.snap.Gate.PR = 8 }, review.ReasonGateEvidenceMismatch, vf{ev: green(&gev)}},
		{"gate decision under another policy revision", func(e *env) { e.snap.Gate.PolicyRevision = "old" }, review.ReasonGateEvidenceMismatch, vf{ev: green(&gev)}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			e := withClaim(t)
			if tc.setup != nil {
				tc.setup(e)
			}
			tc.v.claim = claimRef()
			tc.v.id = "v-test"
			e.verify(tc.v)
			reapprove(e)
			d := e.eval()
			wantRejected(t, d, review.RecordResolution, "v-test", tc.reason)
			wantDisp(t, d, review.Blocked)
			wantOb(t, d, cobl(rolePR, "C1"), review.Blocked, review.ReasonClaimOpen)
		})
	}
}

func TestEvaluate_ClaimResolution_WrongAssignment(t *testing.T) { // AGT-4, SEC-11
	t.Parallel()
	res := func(claim review.ClaimRef) review.Resolution {
		return review.Resolution{
			Claim: claim, ReviewedRevision: head1, Procedure: "p", Expected: "x",
			Outcome: review.OutcomeDismissed, Evidence: proof, At: base.Add(time.Hour),
		}
	}
	t.Run("a review assignment cannot resolve", func(t *testing.T) {
		t.Parallel()
		e := withClaim(t)
		e.resolve("a2", res(claimRef()))
		wantRejected(t, e.eval(), review.RecordResolution, "a2", review.ReasonWrongPurpose)
	})
	t.Run("an assignment for another claim cannot resolve this one", func(t *testing.T) {
		t.Parallel()
		e := withClaim(t)
		e.verify(vf{id: "v1", claim: cref("C2"), none: true})
		e.resolve("v1", res(claimRef()))
		wantRejected(t, e.eval(), review.RecordResolution, "v1", review.ReasonUnknownClaim)
	})
	t.Run("a resolution of a claim nobody raised", func(t *testing.T) {
		t.Parallel()
		e := withClaim(t)
		e.verify(vf{id: "v1", claim: cref("C9")})
		wantRejected(t, e.eval(), review.RecordResolution, "v1", review.ReasonUnknownClaim)
	})
	t.Run("reviewed revision differs from the assignment", func(t *testing.T) {
		t.Parallel()
		e := withClaim(t)
		e.verify(vf{id: "v1", claim: claimRef()})
		e.snap.Resolutions[0].ReviewedRevision = head2
		e.resignRes(0)
		wantRejected(t, e.eval(), review.RecordResolution, "v1", review.ReasonMalformed)
	})
	t.Run("two differing resolutions for one assignment", func(t *testing.T) {
		t.Parallel()
		e := withClaim(t)
		e.verify(vf{id: "v1", claim: claimRef()})
		other := e.snap.Resolutions[0]
		other.Outcome = review.OutcomeConfirmed
		e.snap.Resolutions = append(e.snap.Resolutions, other)
		e.resignRes(1)
		wantRejected(t, e.eval(), review.RecordResolution, "v1", review.ReasonConflictingRecords)
	})
}

func TestEvaluate_ValidDismissal_ClosesClaim(t *testing.T) { // AGT-4
	t.Parallel()
	t.Run("with a proof digest", func(t *testing.T) {
		t.Parallel()
		e := withClaim(t)
		e.verify(vf{claim: claimRef(), at: 20 * time.Minute})
		reapprove(e)
		d := e.eval()
		wantOb(t, d, cobl(rolePR, "C1"), review.Pass, review.ReasonSatisfied)
		wantDisp(t, d, review.Pass)
	})
	t.Run("with a mandatory gate's passing job", func(t *testing.T) {
		t.Parallel()
		e := withClaim(t)
		ev := &review.Evidence{Gate: &review.GateEvidence{Gate: gref, RunID: "100", RunAttempt: "1", JobID: "200", CandidateSHA: cand}}
		e.verify(vf{claim: claimRef(), at: 20 * time.Minute, ev: ev})
		reapprove(e)
		wantDisp(t, e.eval(), review.Pass)
	})
	t.Run("the claimant role must still approve again", func(t *testing.T) {
		t.Parallel()
		e := withClaim(t)
		e.verify(vf{claim: claimRef(), at: 20 * time.Minute})
		d := e.eval()
		wantOb(t, d, cobl(rolePR, "C1"), review.Pass, review.ReasonSatisfied)
		wantOb(t, d, "role:"+rolePR, review.Blocked, review.ReasonReviewerBlocked)
		wantDisp(t, d, review.Blocked)
	})
}

func TestEvaluate_ConfirmedClaim_NeedsRepairAndFreshDismissal(t *testing.T) { // AGT-4
	t.Parallel()
	// head1: the claim is raised and confirmed. The coder pushes head2 and the roles review it again.
	setup := func(t *testing.T, repairedAt time.Duration, repaired []string) *env {
		t.Helper()
		e := withClaim(t)
		e.verify(vf{id: "v-confirm", claim: claimRef(), outcome: review.OutcomeConfirmed, at: 10 * time.Minute})
		e.tgt.HeadSHA = head2
		e.review(rv{role: rolePR, round: "r2", head: head2, at: repairedAt, repaired: repaired, session: "pr-2"})
		e.review(rv{role: roleSec, round: "r2", head: head2, session: "sec-2"})
		e.review(rv{role: roleGo, round: "r2", head: head2, session: "go-2"})
		e.snap.Rounds[0].State = review.RoundSuperseded
		return e
	}
	t.Run("confirmed and not repaired stays blocked", func(t *testing.T) {
		t.Parallel()
		e := setup(t, 20*time.Minute, nil)
		d := e.eval()
		wantDisp(t, d, review.Blocked)
		wantOb(t, d, cobl(rolePR, "C1"), review.Blocked, review.ReasonClaimConfirmed)
	})
	t.Run("repaired at the new head without a fresh dismissal is still blocked", func(t *testing.T) {
		t.Parallel()
		e := setup(t, 20*time.Minute, []string{review.RepairedRef(cref("C1"))})
		d := e.eval()
		wantDisp(t, d, review.Blocked)
		wantOb(t, d, cobl(rolePR, "C1"), review.Blocked, review.ReasonClaimReverify)
	})
	t.Run("a dismissal reviewed at the old head is not fresh", func(t *testing.T) {
		t.Parallel()
		e := setup(t, 20*time.Minute, []string{review.RepairedRef(cref("C1"))})
		e.verify(vf{claim: claimRef(), head: head1, at: 30 * time.Minute})
		wantOb(t, e.eval(), cobl(rolePR, "C1"), review.Blocked, review.ReasonClaimReverify)
	})
	t.Run("a dismissal before the repair is not fresh", func(t *testing.T) {
		t.Parallel()
		e := setup(t, 20*time.Minute, []string{review.RepairedRef(cref("C1"))})
		e.verify(vf{claim: claimRef(), head: head2, at: 15 * time.Minute})
		wantOb(t, e.eval(), cobl(rolePR, "C1"), review.Blocked, review.ReasonClaimReverify)
	})
	t.Run("a dismissal by another verifier does not clear a confirmation without repair", func(t *testing.T) {
		t.Parallel()
		e := setup(t, 20*time.Minute, nil)
		e.verify(vf{claim: claimRef(), head: head2, at: 30 * time.Minute})
		wantOb(t, e.eval(), cobl(rolePR, "C1"), review.Blocked, review.ReasonClaimConfirmed)
	})
	t.Run("repair plus a fresh dismissal at the new head closes it", func(t *testing.T) {
		t.Parallel()
		e := setup(t, 20*time.Minute, []string{review.RepairedRef(cref("C1"))})
		e.verify(vf{claim: claimRef(), head: head2, at: 30 * time.Minute})
		d := e.eval()
		wantOb(t, d, cobl(rolePR, "C1"), review.Pass, review.ReasonSatisfied)
		wantDisp(t, d, review.Pass)
	})
	t.Run("a repair claimed by another role does not count", func(t *testing.T) {
		t.Parallel()
		e := setup(t, 20*time.Minute, nil)
		e.snap.Attestations = e.snap.Attestations[:len(e.snap.Attestations)-1]
		e.snap.Attestations = e.snap.Attestations[:len(e.snap.Attestations)-1]
		e.review(rv{role: roleSec, round: "r2", head: head2, repaired: []string{review.RepairedRef(cref("C1"))}, session: "sec-3", at: 21 * time.Minute})
		e.review(rv{role: roleGo, round: "r2", head: head2, session: "go-3"})
		e.verify(vf{claim: claimRef(), head: head2, at: 30 * time.Minute})
		wantOb(t, e.eval(), cobl(rolePR, "C1"), review.Blocked, review.ReasonClaimConfirmed)
	})
}

func TestEvaluate_OpenClaimCarriesAcrossPush(t *testing.T) { // AGT-4
	e := withClaim(t)
	e.tgt.HeadSHA = head2
	e.review(rv{role: rolePR, round: "r2", head: head2, session: "pr-2"})
	e.review(rv{role: roleSec, round: "r2", head: head2, session: "sec-2"})
	e.review(rv{role: roleGo, round: "r2", head: head2, session: "go-2"})
	e.snap.Rounds[0].State = review.RoundSuperseded
	d := e.eval()
	wantDisp(t, d, review.Blocked)
	wantOb(t, d, cobl(rolePR, "C1"), review.Blocked, review.ReasonClaimOpen)
	for _, r := range []string{rolePR, roleSec, roleGo} {
		wantOb(t, d, "role:"+r, review.Pass, review.ReasonSatisfied)
	}
}

func TestEvaluate_ClaimEscalation(t *testing.T) { // AGT-4, AGT-5
	t.Parallel()
	t.Run("more verify attempts than the cap", func(t *testing.T) {
		t.Parallel()
		e := withClaim(t)
		for range 3 {
			e.verify(vf{claim: claimRef(), none: true})
		}
		wantOb(t, e.eval(), cobl(rolePR, "C1"), review.Blocked, review.ReasonClaimOpen) // at the cap
		e.verify(vf{claim: claimRef(), none: true})
		d := e.eval()
		wantDisp(t, d, review.Escalated)
		wantOb(t, d, cobl(rolePR, "C1"), review.Escalated, review.ReasonClaimEscalated)
		if o, _ := find(d, cobl(rolePR, "C1")); o.Action != review.ActionAssignOwner {
			t.Errorf("action = %q", o.Action)
		}
	})
	t.Run("timeout with an injected clock", func(t *testing.T) {
		t.Parallel()
		e := withClaim(t)
		e.now = base.Add(time.Minute + 24*time.Hour) // exactly the timeout since the claim was first seen
		wantOb(t, e.eval(), cobl(rolePR, "C1"), review.Blocked, review.ReasonClaimOpen)
		e.now = e.now.Add(time.Nanosecond)
		d := e.eval()
		wantDisp(t, d, review.Escalated)
		wantOb(t, d, cobl(rolePR, "C1"), review.Escalated, review.ReasonClaimEscalated)
	})
	t.Run("a confirmed claim escalates too", func(t *testing.T) {
		t.Parallel()
		e := withClaim(t)
		e.verify(vf{claim: claimRef(), outcome: review.OutcomeConfirmed, at: 10 * time.Minute})
		e.now = base.Add(48 * time.Hour)
		wantOb(t, e.eval(), cobl(rolePR, "C1"), review.Escalated, review.ReasonClaimEscalated)
	})
	t.Run("a closed claim never escalates", func(t *testing.T) {
		t.Parallel()
		e := withClaim(t)
		e.verify(vf{claim: claimRef(), at: 20 * time.Minute})
		reapprove(e)
		e.now = base.Add(48 * time.Hour)
		wantDisp(t, e.eval(), review.Pass)
	})
}

func TestEvaluate_Rounds_CapEscalates(t *testing.T) { // AGT-5
	t.Parallel()
	t.Run("three rounds without convergence", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t)
		e.setRound("r1", 1, head2, review.RoundSuperseded) // superseded mid-review, still counts
		e.setRound("r2", 2, head1, review.RoundCompleted)
		e.review(rv{role: rolePR, round: "r2"})
		e.review(rv{role: roleSec, round: "r2"})
		e.review(rv{role: roleGo, round: "r2", verdict: review.VerdictBlock, claims: []review.Claim{claim("C1")}})
		e.setRound("r3", 3, head1, review.RoundCompleted) // a one-role follow-up
		e.review(rv{role: roleGo, round: "r3", verdict: review.VerdictBlock, claims: []review.Claim{claim("C2")}, session: "go-2"})
		d := e.eval()
		wantDisp(t, d, review.Escalated)
		wantOb(t, d, "rounds", review.Escalated, review.ReasonRoundsExhausted)
		if o, _ := find(d, "rounds"); o.Action != review.ActionAssignOwner {
			t.Errorf("action = %q", o.Action)
		}
	})
	t.Run("two rounds do not escalate", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t)
		e.setRound("r1", 1, head2, review.RoundSuperseded)
		e.setRound("r2", 2, head1, review.RoundCompleted)
		e.review(rv{role: rolePR, round: "r2"})
		wantDisp(t, e.eval(), review.Pending)
	})
	t.Run("a retry inside a round does not count", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t)
		e.setRound("r1", 1, head2, review.RoundSuperseded)
		e.setRound("r2", 2, head1, review.RoundCompleted)
		e.snap.Rounds = append(e.snap.Rounds, e.snap.Rounds[1], e.snap.Rounds[1]) // redelivered round records
		e.review(rv{role: rolePR, round: "r2"})
		e.review(rv{role: rolePR, round: "r2", session: "retry"})
		wantDisp(t, e.eval(), review.Pending)
	})
	t.Run("converged in the last round passes", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t)
		e.setRound("x1", 1, head2, review.RoundSuperseded)
		e.setRound("x2", 2, head2, review.RoundSuperseded)
		e.approveAll()
		wantDisp(t, e.eval(), review.Pass)
	})
	t.Run("escalated with only a confirmed claim outstanding is not a pass", func(t *testing.T) {
		t.Parallel()
		e := withClaim(t)
		e.verify(vf{claim: claimRef(), outcome: review.OutcomeConfirmed, at: 10 * time.Minute})
		reapprove(e)
		e.setRound("r1", 1, head1, review.RoundCompleted)
		e.setRound("r2", 2, head1, review.RoundCompleted)
		e.setRound("r3", 3, head1, review.RoundCompleted)
		d := e.eval()
		wantDisp(t, d, review.Escalated)
		wantOb(t, d, cobl(rolePR, "C1"), review.Blocked, review.ReasonClaimConfirmed)
		for _, r := range []string{rolePR, roleSec, roleGo} {
			wantOb(t, d, "role:"+r, review.Pass, review.ReasonSatisfied)
		}
	})
	t.Run("a round with conflicting records is invalid input", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t)
		e.setRound("r1", 1, head1, review.RoundCompleted)
		e.snap.Rounds = append(e.snap.Rounds, review.Round{ID: "r1", Seq: 2, HeadSHA: head1, State: review.RoundCompleted})
		d := e.eval()
		wantDisp(t, d, review.Error)
	})
}

func TestEvaluate_SupersededRoundApproval_DoesNotCount(t *testing.T) { // AGT-5
	e := newEnv(t)
	e.approveAll()
	e.setRound("r1", 1, head1, review.RoundSuperseded)
	d := e.eval()
	wantDisp(t, d, review.Pending)
}

func TestEvaluate_NewerBlockOverridesApprove(t *testing.T) { // AGT-4
	e := newEnv(t)
	e.approveAll()
	e.review(rv{role: roleGo, round: "r2", verdict: review.VerdictBlock, claims: []review.Claim{claim("C1")}, session: "go-2"})
	d := e.eval()
	wantDisp(t, d, review.Blocked)
	wantOb(t, d, "role:"+roleGo, review.Blocked, review.ReasonReviewerBlocked)
}

func TestEvaluate_SameRoundBlockAtLaterTimeOverridesApprove(t *testing.T) { // AGT-4
	e := newEnv(t)
	e.approveAll()
	e.review(rv{role: roleGo, verdict: review.VerdictBlock, claims: []review.Claim{claim("C1")}, session: "go-2", at: time.Hour})
	wantOb(t, e.eval(), "role:"+roleGo, review.Blocked, review.ReasonReviewerBlocked)
}

func sensitiveEnv(t *testing.T) *env {
	t.Helper()
	e := newEnv(t)
	e.eff.SecuritySignoffRequired = true
	e.eff.SensitivePaths = []string{"auth/a.go"}
	// a.go left the sensitive directory.
	e.setChanged(
		review.ChangedPath{Path: "docs/a.go", OldPath: "auth/a.go", Status: forge.FileRenamed},
		review.ChangedPath{Path: "main.go", Status: forge.FileModified},
	)
	return e
}

// without returns items minus those that match drop.
func without(items []review.Item, drop func(review.Item) bool) []review.Item {
	return slices.DeleteFunc(slices.Clone(items), drop)
}

func atPath(p string) func(review.Item) bool {
	return func(it review.Item) bool { return it.Path == p && it.Kind == review.KindDiff }
}

// secChange runs the three roles over e, the security reviewer showing items and signing off signoff.
func secChange(e *env, items []review.Item, signoff []string) review.Decision {
	e.review(rv{role: rolePR})
	e.review(rv{role: roleSec, items: items, signoff: signoff})
	e.review(rv{role: roleGo})
	return e.eval()
}

func TestEvaluate_SensitiveSignoff(t *testing.T) { // SEC-5
	t.Parallel()
	tests := []struct {
		name    string
		signoff []string
		want    review.Disposition
	}{
		{"renamed out of the sensitive directory with the exact sign-off", []string{"auth/a.go"}, review.Pass},
		{"plain approval without a sign-off", nil, review.Blocked},
		{"sign-off naming a wrong path", []string{"other.go"}, review.Blocked},
		{"sign-off with an extra path", []string{"auth/a.go", "main.go"}, review.Blocked},
		{"sign-off lacking the sensitive path", []string{}, review.Blocked},
		{"sign-off repeating the path", []string{"auth/a.go", "auth/a.go"}, review.Pass},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			e := sensitiveEnv(t)
			d := secChange(e, e.fullItems(), tc.signoff)
			wantDisp(t, d, tc.want)
			if tc.want == review.Blocked {
				wantOb(t, d, "signoff:sensitive", review.Blocked, review.ReasonSignoffMissing)
			} else {
				wantOb(t, d, "signoff:sensitive", review.Pass, review.ReasonSatisfied)
			}
		})
	}
	t.Run("the old side omitted from the manifest invalidates the verdict", func(t *testing.T) {
		t.Parallel()
		e := sensitiveEnv(t)
		items := without(e.fullItems(), func(it review.Item) bool { return it.Side == review.SideBase })
		d := secChange(e, items, []string{"auth/a.go"})
		wantDisp(t, d, review.Blocked)
		wantOb(t, d, "role:"+roleSec, review.Blocked, review.ReasonInvalidVerdict)
	})
	t.Run("a sensitive path that isn't changed needs its head side", func(t *testing.T) {
		t.Parallel()
		mk := func(side, kind string) review.Decision {
			e := newEnv(t)
			e.eff.SecuritySignoffRequired = true
			e.eff.SensitivePaths = []string{"auth/unchanged.go"}
			items := append(e.fullItems(), review.Item{Kind: kind, Path: "auth/unchanged.go", Side: side, Digest: "sha256:x"})
			return secChange(e, items, []string{"auth/unchanged.go"})
		}
		wantDisp(t, mk(review.SideHead, review.KindDiff), review.Pass)
		wantDisp(t, mk("", review.KindDiff), review.Pass)
		wantDisp(t, mk(review.SideBase, review.KindDiff), review.Blocked) // a base-only item
		wantDisp(t, mk(review.SideHead, review.KindRepoFile), review.Blocked)
	})
	t.Run("another role's sign-off does not satisfy it", func(t *testing.T) {
		t.Parallel()
		e := sensitiveEnv(t)
		e.review(rv{role: rolePR, signoff: []string{"auth/a.go"}})
		e.review(rv{role: roleSec})
		e.review(rv{role: roleGo})
		wantOb(t, e.eval(), "signoff:sensitive", review.Blocked, review.ReasonSignoffMissing)
	})
	t.Run("no security approval yet is pending", func(t *testing.T) {
		t.Parallel()
		e := sensitiveEnv(t)
		e.review(rv{role: rolePR})
		e.review(rv{role: roleGo})
		d := e.eval()
		wantDisp(t, d, review.Pending)
		wantOb(t, d, "signoff:sensitive", review.Pending, review.ReasonSignoffMissing)
	})
	t.Run("not required when no path is sensitive", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t)
		e.approveAll()
		if _, ok := find(e.eval(), "signoff:sensitive"); ok {
			t.Error("unexpected sign-off obligation")
		}
	})
}

// lightsOnFor is a lights-on change of the given files, approved by every role.
func lightsOnFor(t *testing.T, changed []review.ChangedPath, areas [][]string) *env {
	t.Helper()
	e := newEnv(t)
	e.eff.LightsOn = true
	e.snap.LightsOn = &review.Approval{Generation: 1, ImpactRevision: impRev, RecoveryRevision: recRev}
	e.setChanged(changed...)
	e.snap.OwnerAreas = areas
	e.approveAll()
	return e
}

func lightsOnEnv(t *testing.T) *env {
	t.Helper()
	return lightsOnFor(t, []review.ChangedPath{
		{Path: "a/x.go", Status: forge.FileModified},
		{Path: "a/y.go", Status: forge.FileAdded},
		{Path: "b/z.go", Status: forge.FileModified},
	}, [][]string{{"a/x.go", "a/y.go"}, {"b/z.go"}})
}

func TestEvaluate_LightsOn_RequiresAuthorization(t *testing.T) { // CON-8
	e := lightsOnEnv(t)
	d := e.eval()
	wantDisp(t, d, review.NeedsAuthorization) // never Pass: only a human decision can satisfy it
	if len(d.RequiredApprovals) != 2 {
		t.Fatalf("required approvals = %+v", d.RequiredApprovals)
	}
	var paths [][]string
	for _, tg := range d.RequiredApprovals {
		paths = append(paths, tg.Paths)
		want := authz.Target{
			Operation: authz.OpApproveLightsOn,
			Scope:     authz.Scope{Kind: authz.ScopeRepo, ID: "acme/app"},
			Subject:   audit.Subject{Kind: audit.SubjectChange, Repo: "acme/app", ID: "7"},
			Revision:  tg.Revision, Paths: tg.Paths,
		}
		if diff := cmp.Diff(want, tg); diff != "" {
			t.Errorf("target: %s", diff)
		}
		if len(tg.Revision) != 64 {
			t.Errorf("revision %q is not a digest", tg.Revision)
		}
	}
	slices.SortFunc(paths, func(a, b []string) int { return len(b) - len(a) })
	if diff := cmp.Diff([][]string{{"a/x.go", "a/y.go"}, {"b/z.go"}}, paths); diff != "" {
		t.Errorf("paths: %s", diff)
	}
	n := 0
	for _, o := range d.Obligations {
		if o.Kind == review.KindApproval {
			n++
			if o.Disposition != review.NeedsAuthorization || o.Action != review.ActionAuthorize {
				t.Errorf("obligation = %+v", o)
			}
		}
	}
	if n != 2 {
		t.Errorf("lights-on obligations = %d, want one per area", n)
	}
}

func TestEvaluate_LightsOn_OtherObligationsWin(t *testing.T) { // CON-8
	e := lightsOnEnv(t)
	e.snap.Attestations = e.snap.Attestations[:2] // the go-reviewer has not reviewed
	d := e.eval()
	wantDisp(t, d, review.Pending)
	if len(d.RequiredApprovals) != 2 {
		t.Errorf("required approvals must still be listed: %+v", d.RequiredApprovals)
	}
}

func TestEvaluate_LightsOn_RevisionBindsEveryInput(t *testing.T) { // CON-8, PIP-9
	rev := func(f func(e *env)) string {
		e := lightsOnEnv(t)
		f(e)
		return e.eval().RequiredApprovals[0].Revision
	}
	same := rev(func(*env) {})
	if same != rev(func(*env) {}) {
		t.Fatal("revision is not deterministic")
	}
	changes := map[string]func(e *env){
		"generation (edit then restore)": func(e *env) { e.snap.LightsOn.Generation = 3 },
		"impact revision":                func(e *env) { e.snap.LightsOn.ImpactRevision = impRev2 },
		"recovery revision":              func(e *env) { e.snap.LightsOn.RecoveryRevision = recRev2 },
		"callers":                        func(e *env) { e.snap.LightsOn.Callers = []string{"svc-a"} },
		"rollout order":                  func(e *env) { e.snap.LightsOn.RolloutOrder = []string{"svc-a"} },
		"PR":                             func(e *env) { e.tgt.PR = 8 },
		"head":                           func(e *env) { e.tgt.HeadSHA = head2 },
	}
	for name, f := range changes {
		got := rev(func(e *env) {
			f(e)
			if name == "head" || name == "PR" {
				e.snap.Attestations = nil // reviews are not the subject here
			}
		})
		if got == same {
			t.Errorf("changing %s does not change the revision", name)
		}
	}
	a := rev(func(e *env) {
		e.snap.LightsOn.Callers = []string{"x", "y"}
		e.snap.LightsOn.RolloutOrder = []string{"x", "y"}
	})
	if b := rev(func(e *env) {
		e.snap.LightsOn.Callers = []string{"y", "x"}
		e.snap.LightsOn.RolloutOrder = []string{"x", "y"}
	}); a != b {
		t.Error("caller order must not matter")
	}
	if b := rev(func(e *env) {
		e.snap.LightsOn.Callers = []string{"x", "y"}
		e.snap.LightsOn.RolloutOrder = []string{"y", "x"}
	}); a == b {
		t.Error("rollout order must matter")
	}
}

func TestEvaluate_NonSwitchable_RequiresAuthorization(t *testing.T) { // PIP-9
	e := newEnv(t)
	e.setChanged(review.ChangedPath{Path: "a.go", Status: forge.FileModified})
	e.approveAll()
	e.snap.NonSwitchable = &review.Approval{
		Generation: 1, ImpactRevision: impRev, RecoveryRevision: recRev,
		Callers: []string{"svc-a"}, RolloutOrder: []string{"svc-a"},
	}
	e.snap.OwnerAreas = [][]string{{"a.go"}}
	d := e.eval()
	wantDisp(t, d, review.NeedsAuthorization)
	if len(d.RequiredApprovals) != 1 || d.RequiredApprovals[0].Operation != authz.OpApproveLightsOn {
		t.Errorf("required = %+v", d.RequiredApprovals)
	}
}

func TestEvaluate_LightsOnOffAndSwitchable_NoApprovals(t *testing.T) { // CON-8
	e := newEnv(t)
	e.approveAll()
	e.snap.OwnerAreas = [][]string{{"nonsense"}} // ignored when lights-on does not apply
	d := e.eval()
	wantDisp(t, d, review.Pass)
	if len(d.RequiredApprovals) != 0 {
		t.Errorf("required = %+v", d.RequiredApprovals)
	}
}

func TestEvaluate_LightsOn_InvalidInput(t *testing.T) { // CON-8
	t.Parallel()
	tests := map[string]func(e *env){
		"area missing a changed path":   func(e *env) { e.snap.OwnerAreas = [][]string{{"a/x.go", "a/y.go"}} },
		"area with an extra path":       func(e *env) { e.snap.OwnerAreas[1] = []string{"b/z.go", "c/w.go"} },
		"path in two areas":             func(e *env) { e.snap.OwnerAreas[1] = []string{"b/z.go", "a/x.go"} },
		"path twice in one area":        func(e *env) { e.snap.OwnerAreas[0] = []string{"a/x.go", "a/x.go", "a/y.go"} },
		"empty area":                    func(e *env) { e.snap.OwnerAreas = append(e.snap.OwnerAreas, nil) },
		"no areas":                      func(e *env) { e.snap.OwnerAreas = nil },
		"no changed paths":              func(e *env) { e.snap.ChangedPaths = nil; e.snap.OwnerAreas = nil },
		"duplicate changed path":        func(e *env) { e.snap.ChangedPaths = append(e.snap.ChangedPaths, e.snap.ChangedPaths[0]) },
		"no approval data":              func(e *env) { e.snap.LightsOn = nil },
		"missing impact revision":       func(e *env) { e.snap.LightsOn.ImpactRevision = "" },
		"missing recovery revision":     func(e *env) { e.snap.LightsOn.RecoveryRevision = "" },
		"negative generation":           func(e *env) { e.snap.LightsOn.Generation = -1 },
		"non-switchable without impact": func(e *env) { e.snap.NonSwitchable = &review.Approval{RecoveryRevision: "r"} },
	}
	for name, f := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			e := lightsOnEnv(t)
			f(e)
			d := e.eval()
			wantDisp(t, d, review.Error)
			if !slices.Equal(d.Reasons, []review.Reason{review.ReasonInvalidInput}) {
				t.Errorf("reasons = %v", d.Reasons)
			}
			if len(d.RequiredApprovals) != 0 {
				t.Errorf("required = %+v", d.RequiredApprovals)
			}
		})
	}
}

func TestEvaluate_SplitRequest(t *testing.T) { // INT-20
	t.Parallel()
	t.Run("citing the wrong gate is invalid", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t)
		e.review(rv{role: rolePR, verdict: review.VerdictRequestSplit, split: "shape/other"})
		e.review(rv{role: roleSec})
		id := e.review(rv{role: roleGo, verdict: review.VerdictRequestSplit, split: ""})
		d := e.eval()
		wantRejected(t, d, review.RecordAttestation, "a1", review.ReasonWrongSplitGate)
		wantRejected(t, d, review.RecordAttestation, id, review.ReasonWrongSplitGate)
		if _, ok := find(d, "split"); ok {
			t.Error("an invalid split request created a replan")
		}
	})
	t.Run("a split gate cited by a non-split verdict is invalid", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t)
		id := e.review(rv{role: rolePR, split: sizeGate})
		wantRejected(t, e.eval(), review.RecordAttestation, id, review.ReasonWrongSplitGate)
	})
	t.Run("the right gate gives replan and no approval", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t)
		e.review(rv{role: rolePR, verdict: review.VerdictRequestSplit, split: sizeGate})
		e.review(rv{role: roleSec})
		e.review(rv{role: roleGo})
		d := e.eval()
		wantDisp(t, d, review.Replan)
		wantOb(t, d, "split", review.Replan, review.ReasonSplitRequested)
		if o, _ := find(d, "split"); o.Action != review.ActionReplan {
			t.Errorf("action = %q", o.Action)
		}
		if o, _ := find(d, "role:"+rolePR); o.Disposition == review.Pass {
			t.Error("a split request counted as an approval")
		}
	})
	t.Run("coexists with a security block", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t)
		e.review(rv{role: rolePR, verdict: review.VerdictRequestSplit, split: sizeGate})
		e.review(rv{role: roleSec, verdict: review.VerdictBlock, claims: []review.Claim{claim("S1")}})
		e.review(rv{role: roleGo})
		d := e.eval()
		wantDisp(t, d, review.Blocked)
		wantOb(t, d, "split", review.Replan, review.ReasonSplitRequested)
		wantOb(t, d, cobl(roleSec, "S1"), review.Blocked, review.ReasonClaimOpen)
		wantOb(t, d, "role:"+roleSec, review.Blocked, review.ReasonReviewerBlocked)
	})
	t.Run("a split request at an old head is not outstanding", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t)
		e.review(rv{role: rolePR, verdict: review.VerdictRequestSplit, split: sizeGate, head: head2, round: "r0"})
		if _, ok := find(e.eval(), "split"); ok {
			t.Error("stale split request")
		}
	})
}

func TestEvaluate_IncompleteSnapshot_Error(t *testing.T) { // SEC-1
	e := newEnv(t)
	e.approveAll()
	e.snap.Complete = false
	d := e.eval()
	wantDisp(t, d, review.Error)
	if !slices.Equal(d.Reasons, []review.Reason{review.ReasonIncompleteEvidence}) {
		t.Errorf("reasons = %v", d.Reasons)
	}
	if len(d.Obligations) != 0 {
		t.Errorf("obligations = %+v", d.Obligations)
	}
}

func TestEvaluate_InvalidInput_Error(t *testing.T) { // SEC-1
	t.Parallel()
	tests := map[string]func(e *env){
		"nil contract":                  func(e *env) { e.eff = nil },
		"empty revision":                func(e *env) { e.eff.Revision = "" },
		"empty install revision":        func(e *env) { e.eff.InstallRevision = "" },
		"empty forge":                   func(e *env) { e.tgt.Forge = "" },
		"empty repo":                    func(e *env) { e.tgt.Repo = "" },
		"zero PR":                       func(e *env) { e.tgt.PR = 0 },
		"short head":                    func(e *env) { e.tgt.HeadSHA = "abc" },
		"uppercase head":                func(e *env) { e.tgt.HeadSHA = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" },
		"empty head":                    func(e *env) { e.tgt.HeadSHA = "" },
		"zero config":                   func(e *env) { e.cfg = review.Config{} },
		"zero rounds":                   func(e *env) { e.cfg.ReviewRounds = 0 },
		"zero verify attempts":          func(e *env) { e.cfg.VerifyAttempts = 0 },
		"zero verify timeout":           func(e *env) { e.cfg.VerifyTimeout = 0 },
		"empty size gate":               func(e *env) { e.cfg.SizeGateID = "" },
		"nil keys":                      func(e *env) { e.keys = nil },
		"empty keys":                    func(e *env) { e.keys = review.Keys{} },
		"no reviewers":                  func(e *env) { e.eff.Reviewers = nil },
		"no security reviewer":          func(e *env) { e.eff.SecurityReviewer = "" },
		"security reviewer not present": func(e *env) { e.eff.SecurityReviewer = "ghost" },
		"only the security reviewer":    func(e *env) { e.eff.Reviewers = []contract.Requirement{{Role: roleSec}} },
		"empty reviewer role":           func(e *env) { e.eff.Reviewers = append(e.eff.Reviewers, contract.Requirement{}) },
		"unknown round state":           func(e *env) { e.snap.Rounds = append(e.snap.Rounds, review.Round{ID: "rx", State: "weird"}) },
	}
	for name, f := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			e := newEnv(t)
			e.approveAll()
			f(e)
			d := e.eval()
			wantDisp(t, d, review.Error)
			if !slices.Equal(d.Reasons, []review.Reason{review.ReasonInvalidInput}) {
				t.Errorf("reasons = %v", d.Reasons)
			}
		})
	}
}

func TestEvaluate_AttestationBoundToRoundAndAssignment(t *testing.T) { // AGT-5
	t.Parallel()
	t.Run("assignment in an unknown round", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t)
		id := e.review(rv{role: rolePR})
		e.snap.Rounds = nil
		d := e.eval()
		wantRejected(t, d, review.RecordAttestation, id, review.ReasonRoundMismatch)
		wantInconsistent(t, d)
	})
	t.Run("round head differs from the assignment head", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t)
		id := e.review(rv{role: rolePR})
		e.setRound("r1", 1, head2, review.RoundDispatched)
		d := e.eval()
		wantRejected(t, d, review.RecordAttestation, id, review.ReasonRoundMismatch)
		wantInconsistent(t, d)
	})
	t.Run("verify assignment cannot carry an attestation", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t)
		e.review(rv{role: rolePR, id: "x"})
		e.snap.Assignments[0].Purpose = review.PurposeVerify
		e.snap.Attestations[0].AssignmentDigest = e.snap.Assignments[0].Digest()
		e.addKeyKind("kv-x", e.snap.Assignments[0].Session, review.KeyVerifier)
		e.snap.Attestations[0].KeyID = "kv-x"
		e.resignAtt(0)
		wantRejected(t, e.eval(), review.RecordAttestation, "x", review.ReasonWrongPurpose)
	})
}

func TestSigningPayload_Canonical(t *testing.T) { // AGT-3
	a := review.Attestation{
		AssignmentID: "a1", Verdict: review.VerdictBlock, Claims: []review.Claim{claim("B"), claim("A")},
		SensitiveSignoff: []string{"y", "x"}, Repaired: []string{"2", "1"}, At: base, KeyID: "k",
	}
	b := a
	b.Claims = []review.Claim{claim("A"), claim("B")}
	b.SensitiveSignoff, b.Repaired = []string{"x", "y"}, []string{"1", "2"}
	b.Signature = []byte("not covered")
	if !bytes.Equal(a.SigningPayload(), b.SigningPayload()) {
		t.Error("list order or the signature changed the payload")
	}
	if p := string(a.SigningPayload()); p[:len("lightsout/review-attestation/v1\n")] != "lightsout/review-attestation/v1\n" {
		t.Errorf("payload = %q", p)
	}
	c := a
	c.Verdict = review.VerdictApprove
	if bytes.Equal(a.SigningPayload(), c.SigningPayload()) {
		t.Error("verdict not covered")
	}
	for name, f := range map[string]func(*review.Attestation){
		"assignment": func(x *review.Attestation) { x.AssignmentID = "a2" },
		"split gate": func(x *review.Attestation) { x.SplitGateID = "g" },
		"signoff":    func(x *review.Attestation) { x.SensitiveSignoff = []string{"x"} },
		"repaired":   func(x *review.Attestation) { x.Repaired = nil },
		"time":       func(x *review.Attestation) { x.At = x.At.Add(time.Nanosecond) },
		"key":        func(x *review.Attestation) { x.KeyID = "k2" },
		"claim":      func(x *review.Attestation) { x.Claims = []review.Claim{claim("A")} },
	} {
		d := a
		f(&d)
		if bytes.Equal(a.SigningPayload(), d.SigningPayload()) {
			t.Errorf("%s is not covered by the signature", name)
		}
	}
	r := review.Resolution{AssignmentID: "a1", At: base}
	if bytes.Equal(r.SigningPayload(), a.SigningPayload()) {
		t.Error("domains are not separated")
	}
}

func TestManifestDigest_Canonical(t *testing.T) { // AGT-3
	m1 := review.Manifest{HeadSHA: head1, Items: []review.Item{
		{Kind: "diff", Path: "b", Digest: "d"}, {Kind: "diff", Path: "a", Side: "head", Digest: "d"}, {Kind: "spec", Digest: "s"},
	}}
	m2 := review.Manifest{HeadSHA: head1, Items: []review.Item{m1.Items[2], m1.Items[1], m1.Items[0]}}
	if m1.Digest() != m2.Digest() {
		t.Error("item order changed the digest")
	}
	m3 := m1
	m3.HeadSHA = head2
	if m1.Digest() == m3.Digest() {
		t.Error("head not covered")
	}
	m4 := review.Manifest{HeadSHA: head1, Items: m1.Items[:2]}
	if m1.Digest() == m4.Digest() {
		t.Error("items not covered")
	}
}

func TestEvaluate_Deterministic_UnderShuffling(t *testing.T) { // NFR-3
	build := func() *env {
		e := lightsOnEnv(t)
		e.eff.SecuritySignoffRequired = true
		e.eff.SensitivePaths = []string{"a/x.go"}
		e.snap.Attestations = nil
		e.snap.Assignments = nil
		e.snap.Rounds = nil
		e.snap.Manifests = map[string]review.Manifest{}
		items := append(e.fullItems(), review.Item{Kind: review.KindDiff, Path: "a/x.go", Digest: "sha256:x"})
		e.review(rv{role: rolePR, verdict: review.VerdictBlock, claims: []review.Claim{claim("C1"), claim("C2")}})
		e.review(rv{role: roleSec, items: items, signoff: []string{"a/x.go"}})
		e.review(rv{role: roleGo, verdict: review.VerdictRequestSplit, split: sizeGate})
		e.addKeyKind("k-bad", "bad-s", review.KeyCoder)
		e.review(rv{role: roleGo, id: "bad", session: "bad-s", key: "k-bad"})
		e.verify(vf{claim: claimRef(), outcome: review.OutcomeConfirmed, at: 10 * time.Minute})
		e.verify(vf{claim: cref("C2"), at: 12 * time.Minute})
		e.verify(vf{claim: cref("C2"), none: true})
		e.setRound("r0", 7, head2, review.RoundSuperseded)
		e.setRound("r8", 8, head1, review.RoundCompleted)
		e.setRound("r9", 9, head1, review.RoundCompleted)
		e.snap.Attestations = append(e.snap.Attestations, e.snap.Attestations[0])
		e.snap.OwnerAreas = [][]string{{"b/z.go"}, {"a/y.go", "a/x.go"}}
		return e
	}
	want := build().eval()
	if want.Disposition != review.Escalated {
		t.Fatalf("setup: disposition = %s\n%+v", want.Disposition, want)
	}
	shuffle := func(seed uint64, e *env) {
		rng := rand.New(rand.NewPCG(seed, seed))
		sh := func(n int, swap func(i, j int)) { rng.Shuffle(n, swap) }
		s := &e.snap
		sh(len(s.Assignments), func(i, j int) { s.Assignments[i], s.Assignments[j] = s.Assignments[j], s.Assignments[i] })
		sh(len(s.Attestations), func(i, j int) { s.Attestations[i], s.Attestations[j] = s.Attestations[j], s.Attestations[i] })
		sh(len(s.Resolutions), func(i, j int) { s.Resolutions[i], s.Resolutions[j] = s.Resolutions[j], s.Resolutions[i] })
		sh(len(s.Rounds), func(i, j int) { s.Rounds[i], s.Rounds[j] = s.Rounds[j], s.Rounds[i] })
		sh(len(s.ChangedPaths), func(i, j int) { s.ChangedPaths[i], s.ChangedPaths[j] = s.ChangedPaths[j], s.ChangedPaths[i] })
		sh(len(s.OwnerAreas), func(i, j int) { s.OwnerAreas[i], s.OwnerAreas[j] = s.OwnerAreas[j], s.OwnerAreas[i] })
		for _, a := range s.OwnerAreas {
			sh(len(a), func(i, j int) { a[i], a[j] = a[j], a[i] })
		}
		for i := range s.Attestations {
			a := &s.Attestations[i]
			sh(len(a.Claims), func(x, y int) { a.Claims[x], a.Claims[y] = a.Claims[y], a.Claims[x] })
		}
		sh(len(e.eff.Reviewers), func(i, j int) { e.eff.Reviewers[i], e.eff.Reviewers[j] = e.eff.Reviewers[j], e.eff.Reviewers[i] })
	}
	for seed := range uint64(30) {
		e := build()
		shuffle(seed+1, e)
		if diff := cmp.Diff(want, e.eval()); diff != "" {
			t.Fatalf("seed %d: %s", seed, diff)
		}
	}
}

func TestEvaluate_DoesNotModifyInputs(t *testing.T) { // NFR-3
	e := withClaim(t)
	e.verify(vf{claim: claimRef()})
	before := cmp.Diff(review.Snapshot{}, e.snap)
	e.eval()
	if after := cmp.Diff(review.Snapshot{}, e.snap); after != before {
		t.Error("snapshot modified")
	}
}
