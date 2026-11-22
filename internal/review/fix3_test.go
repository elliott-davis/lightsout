// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

package review_test

import (
	"strconv"
	"testing"
	"time"

	"github.com/elliott-davis/lightsout/internal/contract"
	"github.com/elliott-davis/lightsout/internal/gate"
	"github.com/elliott-davis/lightsout/internal/review"
)

const head3 = "3333333333333333333333333333333333333333"

// More signed negative evidence must never produce a pass: confirmations only ever add to a claim's state.
func TestEvaluate_Confirmations_AreMonotonic(t *testing.T) { // AGT-4
	t.Parallel()
	ref := review.RepairedRef(cref("C1"))
	// at is the order of the two confirmations, one at the old head and one at the target head.
	for name, ats := range map[string][2]time.Duration{
		"the target-head confirmation is the later":   {10 * time.Minute, 15 * time.Minute},
		"the target-head confirmation is the earlier": {15 * time.Minute, 10 * time.Minute},
	} {
		t.Run("confirmed at the target head can't close: "+name, func(t *testing.T) {
			t.Parallel()
			e := withClaim(t)
			e.verify(vf{claim: claimRef(), outcome: review.OutcomeConfirmed, at: ats[0]})
			e.tgt.HeadSHA = head2
			e.review(rv{role: rolePR, round: "r2", head: head2, repaired: []string{ref}, at: 20 * time.Minute, session: "pr-2"})
			e.verify(vf{claim: claimRef(), outcome: review.OutcomeConfirmed, head: head2, at: ats[1]})
			e.verify(vf{claim: claimRef(), head: head2, at: 30 * time.Minute}) // a fresh dismissal
			wantOb(t, e.eval(), cobl(rolePR, "C1"), review.Blocked, review.ReasonClaimConfirmed)
		})
	}
	t.Run("a repair must be after the latest confirmation, whichever head it was at", func(t *testing.T) {
		t.Parallel()
		e := withClaim(t)
		e.verify(vf{claim: claimRef(), outcome: review.OutcomeConfirmed, at: 10 * time.Minute})
		e.verify(vf{claim: claimRef(), outcome: review.OutcomeConfirmed, head: head2, at: 40 * time.Minute})
		e.tgt.HeadSHA = head3
		e.review(rv{role: rolePR, round: "r3", head: head3, repaired: []string{ref}, at: 20 * time.Minute, session: "pr-3"})
		e.verify(vf{claim: claimRef(), head: head3, at: 50 * time.Minute})
		wantOb(t, e.eval(), cobl(rolePR, "C1"), review.Blocked, review.ReasonClaimConfirmed)
	})
	t.Run("a repair must be at a head no confirmation was at", func(t *testing.T) {
		t.Parallel()
		e := withClaim(t)
		e.verify(vf{claim: claimRef(), outcome: review.OutcomeConfirmed, head: head2, at: 10 * time.Minute})
		e.verify(vf{claim: claimRef(), outcome: review.OutcomeConfirmed, at: 12 * time.Minute})
		e.tgt.HeadSHA = head2 // confirmed at the target by the first one
		e.review(rv{role: rolePR, round: "r2", head: head2, repaired: []string{ref}, at: 20 * time.Minute, session: "pr-2"})
		e.verify(vf{claim: claimRef(), head: head2, at: 30 * time.Minute})
		wantOb(t, e.eval(), cobl(rolePR, "C1"), review.Blocked, review.ReasonClaimConfirmed)
	})
	t.Run("one confirmation, a newer head and a fresh dismissal still close it", func(t *testing.T) {
		t.Parallel()
		e := withClaim(t)
		e.verify(vf{claim: claimRef(), outcome: review.OutcomeConfirmed, at: 10 * time.Minute})
		e.tgt.HeadSHA = head3
		e.review(rv{role: rolePR, round: "r3", head: head3, repaired: []string{ref}, at: 20 * time.Minute, session: "pr-3"})
		e.verify(vf{claim: claimRef(), head: head3, at: 30 * time.Minute})
		wantOb(t, e.eval(), cobl(rolePR, "C1"), review.Pass, review.ReasonSatisfied)
	})
}

func TestEvaluate_Repair_UsesTheEarliestRepairTime(t *testing.T) { // AGT-4
	t.Parallel()
	ref := review.RepairedRef(cref("C1"))
	e := withClaim(t)
	e.verify(vf{claim: claimRef(), outcome: review.OutcomeConfirmed, at: 10 * time.Minute})
	e.tgt.HeadSHA = head2
	e.review(rv{role: rolePR, round: "r2", head: head2, repaired: []string{ref}, at: 20 * time.Minute, session: "pr-2"})
	e.setRound("r3", 3, head2, review.RoundDispatched)
	e.review(rv{role: rolePR, round: "r3", head: head2, repaired: []string{ref}, at: 40 * time.Minute, session: "pr-3"})
	e.verify(vf{claim: claimRef(), head: head2, at: 30 * time.Minute}) // after the first repair, before the second
	wantOb(t, e.eval(), cobl(rolePR, "C1"), review.Pass, review.ReasonSatisfied)
}

func TestEvaluate_SnapshotCoderSessions_NeverDropARecord(t *testing.T) { // SEC-11
	t.Parallel()
	t.Run("a block", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t)
		e.approveAll()
		e.review(rv{role: rolePR, round: "r2", verdict: review.VerdictBlock, claims: []review.Claim{claim("C1")}, session: "pr-2"})
		wantDisp(t, e.eval(), review.Blocked)
		e.snap.CoderSessions = append(e.snap.CoderSessions, "pr-2") // the writer relabels the session
		wantInconsistent(t, e.eval())
	})
	t.Run("a confirmation", func(t *testing.T) {
		t.Parallel()
		e := withClaim(t)
		e.verify(vf{claim: claimRef(), outcome: review.OutcomeConfirmed, at: 20 * time.Minute, session: "verifier-x"})
		wantOb(t, e.eval(), cobl(rolePR, "C1"), review.Blocked, review.ReasonClaimConfirmed)
		e.snap.CoderSessions = append(e.snap.CoderSessions, "verifier-x")
		wantInconsistent(t, e.eval())
	})
	t.Run("only a trusted coder-kind key rejects outright", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t)
		e.approveAll()
		e.addKeyKind("k-ck", "coder-1", review.KeyCoder)
		e.review(rv{role: roleGo, id: "x", round: "r2", session: "coder-1", key: "k-ck", verdict: review.VerdictBlock, claims: []review.Claim{claim("C1")}})
		d := e.eval()
		wantRejected(t, d, review.RecordAttestation, "x", review.ReasonCoderSession)
		wantDisp(t, d, review.Pass)
	})
}

func TestEvaluate_SupersededRound_HidesOnlyApprovals(t *testing.T) { // AGT-5
	t.Parallel()
	t.Run("a block in a superseded round still blocks", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t)
		e.approveAll()
		e.review(rv{role: roleGo, round: "r2", verdict: review.VerdictBlock, claims: []review.Claim{claim("C1")}, session: "go-2"})
		e.snap.Rounds[1].State = review.RoundSuperseded
		d := e.eval()
		wantOb(t, d, "role:"+roleGo, review.Blocked, review.ReasonReviewerBlocked)
		wantDisp(t, d, review.Blocked)
	})
	t.Run("a split in a superseded round still asks to replan", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t)
		e.approveAll()
		e.review(rv{role: roleGo, round: "r2", verdict: review.VerdictRequestSplit, split: sizeGate, session: "go-2"})
		e.snap.Rounds[1].State = review.RoundSuperseded
		wantDisp(t, e.eval(), review.Replan)
	})
	t.Run("an invalid verdict in a superseded round still blocks", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t)
		e.approveAll()
		e.review(rv{role: roleGo, round: "r2", session: "go-2", extra: []review.Item{{Kind: "transcript", Digest: "sha256:t"}}})
		e.snap.Rounds[1].State = review.RoundSuperseded
		wantOb(t, e.eval(), "role:"+roleGo, review.Blocked, review.ReasonInvalidVerdict)
	})
	t.Run("an approval in a superseded round is hidden", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t)
		e.approveAll()
		e.snap.Rounds[0].State = review.RoundSuperseded
		wantDisp(t, e.eval(), review.Pending)
	})
}

// Round.State is a trusted, unsigned input: the signed records don't say whether a round was superseded, so WI-18 takes
// it from the audited store.
func TestEvaluate_RoundState_IsATrustedInput(t *testing.T) { // AGT-5
	t.Parallel()
	e := newEnv(t)
	e.approveAll()
	wantDisp(t, e.eval(), review.Pass)
	e.snap.Rounds[0].State = review.RoundSuperseded
	wantDisp(t, e.eval(), review.Pending)
}

func TestEvaluate_ConfirmationForUnknownClaim_Inconsistent(t *testing.T) { // AGT-4
	t.Parallel()
	e := withClaim(t)
	e.verify(vf{claim: claimRef(), outcome: review.OutcomeConfirmed, at: 20 * time.Minute})
	// The writer drops the block but keeps the assignment: the verifier's signed ClaimRef proves the claim existed.
	e.snap.Attestations = e.snap.Attestations[1:]
	wantInconsistent(t, e.eval())
}

func TestEvaluate_MalformedResolution_CountsAsConfirmation(t *testing.T) { // AGT-4
	t.Parallel()
	variants := map[string]func(r *review.Resolution){
		"no evidence":       func(r *review.Resolution) { r.Evidence = review.Evidence{} },
		"blank procedure":   func(r *review.Resolution) { r.Procedure = "  " },
		"blank expectation": func(r *review.Resolution) { r.Expected = "" },
		"zero time":         func(r *review.Resolution) { r.At = time.Time{} },
		"unknown outcome":   func(r *review.Resolution) { r.Outcome = "waived" },
	}
	for name, f := range variants {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			e := withClaim(t)
			e.verify(vf{id: "v1", claim: claimRef(), at: 20 * time.Minute}) // a valid dismissal
			e.verify(vf{id: "v2", claim: claimRef(), at: 25 * time.Minute})
			f(&e.snap.Resolutions[1])
			e.resignRes(1)
			wantOb(t, e.eval(), cobl(rolePR, "C1"), review.Blocked, review.ReasonClaimConfirmed)
		})
	}
	t.Run("a malformed resolution for an unknown claim is inconsistent evidence", func(t *testing.T) {
		t.Parallel()
		e := withClaim(t)
		e.verify(vf{id: "v1", claim: cref("C9"), at: 20 * time.Minute})
		e.snap.Resolutions[0].Procedure = ""
		e.resignRes(0)
		wantInconsistent(t, e.eval())
	})
	t.Run("a well-formed dismissal for an unknown claim is only rejected", func(t *testing.T) {
		t.Parallel()
		e := withClaim(t)
		e.verify(vf{id: "v1", claim: cref("C9"), at: 20 * time.Minute})
		wantRejected(t, e.eval(), review.RecordResolution, "v1", review.ReasonUnknownClaim)
	})
}

func TestEvaluate_RoundSeqIsSigned(t *testing.T) { // AGT-5
	t.Parallel()
	e := newEnv(t)
	e.approveAll()
	for i := range e.snap.Assignments {
		e.snap.Assignments[i].RoundSeq = 9
	}
	e.snap.Rounds[0].Seq = 9 // the writer rewrites the order on both sides
	d := e.eval()
	wantRejected(t, d, review.RecordAttestation, "a1", review.ReasonBadBinding)
	wantInconsistent(t, d)
}

func TestEvaluate_Dismissal_CitingAPendingGate_Rejected(t *testing.T) { // AGT-4
	t.Parallel()
	e := withClaim(t)
	e.snap.Gate.Obligations[0].Disposition = gate.Pending
	gev := &review.GateEvidence{Gate: gref, RunID: "100", RunAttempt: "1", JobID: "200", CandidateSHA: cand}
	e.verify(vf{id: "v1", claim: claimRef(), at: 20 * time.Minute, ev: &review.Evidence{Gate: gev}})
	wantRejected(t, e.eval(), review.RecordResolution, "v1", review.ReasonGateEvidenceMismatch)
}

func TestEvaluate_Dismissal_GateEvidenceFieldsAreRequired(t *testing.T) { // AGT-4
	t.Parallel()
	for name, f := range map[string]func(g *review.GateEvidence){
		"run":       func(g *review.GateEvidence) { g.RunID = "" },
		"attempt":   func(g *review.GateEvidence) { g.RunAttempt = "" },
		"job":       func(g *review.GateEvidence) { g.JobID = "" },
		"candidate": func(g *review.GateEvidence) { g.CandidateSHA = "" },
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			e := withClaim(t)
			// A decision with the same empty field would otherwise match.
			e.snap.Gate.Obligations[0].RunID, e.snap.Gate.Obligations[0].RunAttempt, e.snap.Gate.Obligations[0].JobID = "", "", ""
			e.snap.Gate.CandidateSHA = ""
			gev := &review.GateEvidence{Gate: gref}
			e.verify(vf{id: "v1", claim: claimRef(), at: 20 * time.Minute, ev: &review.Evidence{Gate: gev}})
			f(gev)
			e.snap.Resolutions[0].Evidence.Gate = gev
			e.resignRes(0)
			wantRejected(t, e.eval(), review.RecordResolution, "v1", review.ReasonGateEvidenceMismatch)
		})
	}
}

func TestEvaluate_ManifestDiffKind(t *testing.T) { // AGT-3
	t.Parallel()
	e := newEnv(t)
	items := e.fullItems()
	for i := range items {
		if items[i].Kind == review.KindDiff {
			items[i].Kind = review.KindRepoFile // read, but not the change itself
		}
	}
	id := e.review(rv{role: roleGo, items: items})
	wantRejected(t, e.eval(), review.RecordAttestation, id, review.ReasonManifestIncomplete)
}

func TestEvaluate_ReviewersCap(t *testing.T) { // SEC-1
	t.Parallel()
	mk := func(n int) *env {
		e := newEnv(t)
		e.approveAll()
		e.eff.Reviewers = []contract.Requirement{{Role: rolePR}, {Role: roleSec}, {Role: roleGo}}
		for i := range n - 3 {
			e.eff.Reviewers = append(e.eff.Reviewers, contract.Requirement{Role: "role-" + strconv.Itoa(i)})
		}
		return e
	}
	wantInvalid(t, mk(10001).eval())
	if d := mk(10000).eval(); d.Disposition == review.Error {
		t.Errorf("at the cap: %+v", d.Reasons)
	}
}

func TestEvaluate_ResolutionRedelivery_CountsOnce(t *testing.T) { // AGT-4
	t.Parallel()
	e := withClaim(t)
	e.verify(vf{claim: claimRef(), at: 20 * time.Minute})
	e.snap.Resolutions = append(e.snap.Resolutions, e.snap.Resolutions[0])
	reapprove(e)
	d := e.eval()
	wantOb(t, d, cobl(rolePR, "C1"), review.Pass, review.ReasonSatisfied)
	if len(d.Rejected) != 0 {
		t.Errorf("rejected = %+v", d.Rejected)
	}
}

func TestEvaluate_VerifyAttempts_CountDistinctUnambiguousAssignments(t *testing.T) { // AGT-4
	t.Parallel()
	e := withClaim(t)
	for range 3 {
		e.verify(vf{claim: claimRef(), none: true})
	}
	// A redelivered assignment and an ambiguous one aren't attempts.
	e.snap.Assignments = append(e.snap.Assignments, e.snap.Assignments[len(e.snap.Assignments)-1])
	e.verify(vf{id: "amb", claim: claimRef(), none: true})
	dup := e.snap.Assignments[len(e.snap.Assignments)-1]
	dup.Profile = "other"
	e.snap.Assignments = append(e.snap.Assignments, dup)
	wantOb(t, e.eval(), cobl(rolePR, "C1"), review.Blocked, review.ReasonClaimOpen)
}

func TestEvaluate_ClaimsWithinOneAttestation(t *testing.T) { // AGT-4
	t.Parallel()
	first, second := claim("C1"), claim("C1")
	second.Consequence = "a second claim with the same ID"
	e := newEnv(t)
	e.review(rv{role: rolePR, verdict: review.VerdictBlock, claims: []review.Claim{first, second}})
	d := e.eval()
	wantOb(t, d, cobl(rolePR, "C1"), review.Blocked, review.ReasonClaimOpen)
	if _, ok := find(d, review.ClaimObligationID(review.ClaimRef{Role: rolePR, ID: "C1", Digest: second.Digest()})); ok {
		t.Error("the repeated ID contributed a second instance")
	}
}

func TestEvaluate_Ordering_TieBreakIsTheLargerAssignmentID(t *testing.T) { // AGT-5
	t.Parallel()
	for name, tc := range map[string]struct {
		approve, split string
		want           review.Disposition
	}{
		"the split has the larger ID":    {"a", "b", review.Pending},
		"the approval has the larger ID": {"b", "a", review.Pass},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			e := newEnv(t)
			e.review(rv{role: rolePR})
			e.review(rv{role: roleSec})
			e.review(rv{id: tc.approve, role: roleGo, at: 10 * time.Minute})
			e.review(rv{id: tc.split, role: roleGo, verdict: review.VerdictRequestSplit, split: sizeGate, at: 10 * time.Minute, session: "go-2"})
			d := e.eval()
			o, _ := find(d, "role:"+roleGo)
			if o.Disposition != tc.want {
				t.Errorf("role = %s/%s, want %s", o.Disposition, o.Reason, tc.want)
			}
		})
	}
}

func TestEvaluate_InvalidVerdict_IsNotSessionReuse(t *testing.T) { // AGD-3
	t.Parallel()
	e := newEnv(t)
	e.review(rv{role: rolePR, session: "shared", extra: []review.Item{{Kind: "transcript", Digest: "sha256:t"}}})
	e.review(rv{role: roleSec})
	e.review(rv{role: roleGo, session: "shared"})
	d := e.eval()
	wantOb(t, d, "role:"+rolePR, review.Blocked, review.ReasonInvalidVerdict)
	wantOb(t, d, "role:"+roleGo, review.Pass, review.ReasonSatisfied)
}

func TestEvaluate_InvalidInput_Strings_AndRoundRoles(t *testing.T) { // SEC-11
	t.Parallel()
	bad := "x\xffy"
	tests := map[string]func(e *env){
		"coder session": func(e *env) { e.snap.CoderSessions = []string{bad} },
		"round ID": func(e *env) {
			e.snap.Rounds = []review.Round{{ID: bad, Seq: 1, HeadSHA: head1, State: review.RoundCompleted}}
		},
		"round role":           func(e *env) { e.snap.Rounds[0].Roles = []string{bad} },
		"empty round role":     func(e *env) { e.snap.Rounds[0].Roles = []string{rolePR, ""} },
		"reviewer role":        func(e *env) { e.eff.Reviewers = append(e.eff.Reviewers, contract.Requirement{Role: bad}) },
		"sensitive path count": func(e *env) { e.eff.SensitivePaths = make([]string, 10001) },
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
}
