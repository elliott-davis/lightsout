// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

package review_test

import (
	"bytes"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/elliott-davis/lightsout/internal/contract"
	"github.com/elliott-davis/lightsout/internal/forge"
	"github.com/elliott-davis/lightsout/internal/review"
)

// A signed record is never silently dropped: a record whose signature verifies under a trusted key but that doesn't
// fit the snapshot makes the evidence inconsistent.
func TestEvaluate_KeyVerifiedRecordNeverDropped_Inconsistent(t *testing.T) { // SEC-11
	t.Parallel()
	t.Run("a block whose assignment was removed", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t)
		e.approveAll()
		e.review(rv{role: rolePR, round: "r2", verdict: review.VerdictBlock, claims: []review.Claim{claim("C1")}, session: "pr-2"})
		e.snap.Assignments = e.snap.Assignments[:len(e.snap.Assignments)-1]
		wantInconsistent(t, e.eval())
	})
	t.Run("a block whose assignment was rewritten to another PR", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t)
		e.approveAll()
		e.review(rv{role: rolePR, round: "r2", verdict: review.VerdictBlock, claims: []review.Claim{claim("C1")}, session: "pr-2"})
		e.snap.Assignments[len(e.snap.Assignments)-1].PR = 99
		wantInconsistent(t, e.eval())
	})
	t.Run("invalid UTF-8 swapped in after the runtime signed the replacement character", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t)
		c := claim("C1")
		c.Invariant = "x�y"
		e.review(rv{role: rolePR, verdict: review.VerdictBlock, claims: []review.Claim{c}})
		wantDisp(t, e.eval(), review.Blocked)
		// The signature is over the lossy JSON, so the swapped string still verifies.
		e.snap.Attestations[0].Claims[0].Invariant = "x\xffy"
		wantInconsistent(t, e.eval())
	})
	t.Run("a timestamp from the future", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t)
		e.review(rv{role: rolePR, at: 2*time.Hour + 5*time.Minute}) // exactly five minutes ahead of now
		wantDisp(t, e.eval(), review.Pending)
		e = newEnv(t)
		e.review(rv{role: rolePR, at: 2*time.Hour + 5*time.Minute + time.Second})
		wantInconsistent(t, e.eval())
	})
	t.Run("a future-dated resolution", func(t *testing.T) {
		t.Parallel()
		e := withClaim(t)
		e.verify(vf{claim: claimRef(), at: 3 * time.Hour})
		wantInconsistent(t, e.eval())
	})
	t.Run("a resolution for another PR, repo or forge", func(t *testing.T) {
		t.Parallel()
		for name, f := range map[string]func(as *review.Assignment){
			"PR":    func(as *review.Assignment) { as.PR = 99 },
			"repo":  func(as *review.Assignment) { as.Repo = "acme/other" },
			"forge": func(as *review.Assignment) { as.Forge = "gitlab" },
		} {
			t.Run(name, func(t *testing.T) {
				t.Parallel()
				e := withClaim(t)
				e.verify(vf{id: "v1", claim: claimRef(), none: true})
				as := &e.snap.Assignments[len(e.snap.Assignments)-1]
				f(as)
				e.resolve("v1", review.Resolution{
					Claim: claimRef(), ReviewedRevision: head1, Procedure: "p", Expected: "x",
					Outcome: review.OutcomeDismissed, Evidence: proof, At: base.Add(time.Hour),
				})
				d := e.eval()
				wantRejected(t, d, review.RecordResolution, "v1", review.ReasonWrongTarget)
				wantInconsistent(t, d)
			})
		}
	})
	t.Run("an ambiguous verify assignment", func(t *testing.T) {
		t.Parallel()
		e := withClaim(t)
		e.verify(vf{id: "v1", claim: claimRef()})
		dup := e.snap.Assignments[len(e.snap.Assignments)-1]
		dup.Profile = "another"
		e.snap.Assignments = append(e.snap.Assignments, dup)
		wantInconsistent(t, e.eval())
	})
	t.Run("an empty session on the assignment and the key", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t)
		e.addKey("k-none", "")
		id := e.review(rv{role: roleGo, session: "tmp", key: "k-none"})
		e.snap.Assignments[len(e.snap.Assignments)-1].Session = ""
		e.snap.Attestations[len(e.snap.Attestations)-1].AssignmentDigest = e.snap.Assignments[len(e.snap.Assignments)-1].Digest()
		e.resignAtt(len(e.snap.Attestations) - 1)
		d := e.eval()
		wantRejected(t, d, review.RecordAttestation, id, review.ReasonBadBinding)
		wantInconsistent(t, d)
	})
	t.Run("a coder's key can't force an error", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t)
		e.approveAll()
		e.addKeyKind("k-coder", "coder-1", review.KeyCoder)
		a := review.Attestation{AssignmentID: "nowhere", Verdict: review.VerdictApprove, At: base, KeyID: "k-coder"}
		a.Signature = e.sign("k-coder", a.SigningPayload())
		e.snap.Attestations = append(e.snap.Attestations, a)
		r := review.Resolution{AssignmentID: "nowhere", At: base, KeyID: "k-coder"}
		r.Signature = e.sign("k-coder", r.SigningPayload())
		e.snap.Resolutions = append(e.snap.Resolutions, r)
		d := e.eval()
		wantRejected(t, d, review.RecordAttestation, "nowhere", review.ReasonCoderSession)
		wantRejected(t, d, review.RecordResolution, "nowhere", review.ReasonCoderSession)
		wantDisp(t, d, review.Pass)
	})
	t.Run("a record with a bad signature can't force an error", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t)
		e.approveAll()
		a := review.Attestation{AssignmentID: "nowhere", Verdict: review.VerdictApprove, At: base, KeyID: "k-fallback"}
		a.Signature = make([]byte, 64)
		e.snap.Attestations = append(e.snap.Attestations, a)
		wantDisp(t, e.eval(), review.Pass)
	})
}

func TestEvaluate_RoundIdentityIsSigned(t *testing.T) { // AGT-5
	t.Parallel()
	t.Run("the snapshot's round has another Seq", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t)
		e.approveAll()
		e.snap.Rounds[0].Seq = 7
		wantInconsistent(t, e.eval())
	})
	t.Run("the snapshot's round has another head", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t)
		e.approveAll()
		e.snap.Rounds[0].HeadSHA = head2
		wantInconsistent(t, e.eval())
	})
	t.Run("a round with the signed Seq is accepted", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t)
		e.approveAll()
		wantDisp(t, e.eval(), review.Pass)
	})
}

func TestEvaluate_VerifyAssignmentRound(t *testing.T) { // AGT-4
	t.Parallel()
	t.Run("a dismissal in a round superseded at the current head", func(t *testing.T) {
		t.Parallel()
		e := withClaim(t)
		e.setRound("rv", 5, head1, review.RoundSuperseded)
		e.verify(vf{id: "v1", claim: claimRef(), round: "rv", at: 20 * time.Minute})
		wantRejected(t, e.eval(), review.RecordResolution, "v1", review.ReasonRoundSuperseded)
	})
	t.Run("a dismissal in a round superseded by a later push still stands", func(t *testing.T) {
		t.Parallel()
		e := withClaim(t)
		e.verify(vf{id: "v1", claim: claimRef(), at: 20 * time.Minute})
		e.snap.Rounds[0].State = review.RoundSuperseded
		e.tgt.HeadSHA = head2
		d := e.eval()
		wantOb(t, d, cobl(rolePR, "C1"), review.Pass, review.ReasonSatisfied)
	})
	t.Run("a verify round whose head differs from the assignment is inconsistent", func(t *testing.T) {
		t.Parallel()
		e := withClaim(t)
		e.verify(vf{id: "v1", claim: claimRef(), head: head2, round: "r1"})
		wantInconsistent(t, e.eval())
	})
}

func TestEvaluate_KeyKinds(t *testing.T) { // AGD-3, SEC-11
	t.Parallel()
	t.Run("a verifier key on a review assignment", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t)
		e.addKeyKind("kv-x", "go-reviewer-s", review.KeyVerifier)
		id := e.review(rv{role: roleGo, key: "kv-x"})
		d := e.eval()
		wantRejected(t, d, review.RecordAttestation, id, review.ReasonBadBinding)
		wantInconsistent(t, d)
	})
	t.Run("a reviewer key on a verify assignment", func(t *testing.T) {
		t.Parallel()
		e := withClaim(t)
		e.addKey("k-wrong", "verifier-v1")
		e.verify(vf{id: "v1", session: "verifier-v1", claim: claimRef(), key: "k-wrong"})
		d := e.eval()
		wantRejected(t, d, review.RecordResolution, "v1", review.ReasonBadBinding)
		wantInconsistent(t, d)
	})
	t.Run("a coder-kind key never counts", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t)
		e.review(rv{role: rolePR})
		e.review(rv{role: roleSec})
		e.addKeyKind("k-ck", "go-reviewer-s", review.KeyCoder)
		id := e.review(rv{role: roleGo, key: "k-ck"})
		d := e.eval()
		wantRejected(t, d, review.RecordAttestation, id, review.ReasonCoderSession)
		wantDisp(t, d, review.Pending)
	})
	t.Run("a key of no kind is invalid input", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t)
		e.approveAll()
		k := e.keys["k-fallback"]
		k.Kind = 0
		e.keys["k-fallback"] = k
		wantInvalid(t, e.eval())
		k.Kind = 99
		e.keys["k-fallback"] = k
		wantInvalid(t, e.eval())
	})
}

func TestEvaluate_EffectiveMustCoverTheChange(t *testing.T) { // CON-3
	t.Parallel()
	tests := map[string]func(e *env){
		"a changed path effective doesn't cover": func(e *env) { e.eff.Paths = nil },
		"an old path effective doesn't cover": func(e *env) {
			e.setChanged(review.ChangedPath{Path: "b.go", OldPath: "a.go", Status: forge.FileRenamed})
			e.eff.Paths = []contract.PathPolicy{{Path: "b.go"}}
		},
		"no changed paths": func(e *env) { e.snap.ChangedPaths = nil },
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

func TestEvaluate_ApprovalNeedsTheWholeDiff(t *testing.T) { // AGT-3
	t.Parallel()
	e0 := func(t *testing.T) *env {
		t.Helper()
		e := newEnv(t)
		e.setChanged(
			review.ChangedPath{Path: "a.go", Status: forge.FileModified},
			review.ChangedPath{Path: "gone.go", Status: forge.FileRemoved},
			review.ChangedPath{Path: "new.go", OldPath: "old.go", Status: forge.FileRenamed},
		)
		return e
	}
	tests := map[string]func(it review.Item) bool{
		"the diff of a modified path":     atPath("a.go"),
		"the base side of a removed path": atPath("gone.go"),
		"the head side of a renamed path": atPath("new.go"),
		"the base side of a rename's old": atPath("old.go"),
		"the spec":                        func(it review.Item) bool { return it.Kind == review.KindSpec },
	}
	for name, drop := range tests {
		t.Run("without "+name, func(t *testing.T) {
			t.Parallel()
			e := e0(t)
			id := e.review(rv{role: roleGo, items: without(e.fullItems(), drop)})
			d := e.eval()
			wantRejected(t, d, review.RecordAttestation, id, review.ReasonManifestIncomplete)
			wantOb(t, d, "role:"+roleGo, review.Blocked, review.ReasonInvalidVerdict)
		})
	}
	for name, tc := range map[string]struct{ path, side string }{
		"a base-only diff of a modified path": {"a.go", review.SideBase},
		"a head diff of a removed path":       {"gone.go", review.SideHead},
	} {
		t.Run("the wrong side doesn't count: "+name, func(t *testing.T) {
			t.Parallel()
			e := e0(t)
			items := e.fullItems()
			for i := range items {
				if items[i].Path == tc.path {
					items[i].Side = tc.side
				}
			}
			id := e.review(rv{role: roleGo, items: items})
			wantRejected(t, e.eval(), review.RecordAttestation, id, review.ReasonManifestIncomplete)
		})
	}
	t.Run("a full diff approves", func(t *testing.T) {
		t.Parallel()
		e := e0(t)
		e.approveAll()
		wantDisp(t, e.eval(), review.Pass)
	})
}

func TestEvaluate_ConfirmationsAreSticky(t *testing.T) { // AGT-4
	t.Parallel()
	t.Run("a confirmation whose gate evidence can't be rechecked still blocks", func(t *testing.T) {
		t.Parallel()
		e := withClaim(t)
		e.verify(vf{claim: claimRef(), at: 10 * time.Minute}) // dismissed
		gev := &review.GateEvidence{Gate: gref, RunID: "1", RunAttempt: "1", JobID: "1", CandidateSHA: head2}
		e.verify(vf{claim: claimRef(), outcome: review.OutcomeConfirmed, at: 20 * time.Minute, ev: &review.Evidence{Gate: gev}})
		e.snap.Gate = nil
		wantOb(t, e.eval(), cobl(rolePR, "C1"), review.Blocked, review.ReasonClaimConfirmed)
	})
	t.Run("a confirmation by the claimant's own session still blocks", func(t *testing.T) {
		t.Parallel()
		e := withClaim(t)
		e.verify(vf{claim: claimRef(), outcome: review.OutcomeConfirmed, at: 20 * time.Minute, session: rolePR + "-s"})
		wantOb(t, e.eval(), cobl(rolePR, "C1"), review.Blocked, review.ReasonClaimConfirmed)
	})
	t.Run("a malformed confirmation counts as a confirmation", func(t *testing.T) {
		t.Parallel()
		e := withClaim(t)
		e.verify(vf{id: "v1", claim: claimRef(), outcome: review.OutcomeConfirmed, at: 20 * time.Minute, ev: &review.Evidence{}})
		wantOb(t, e.eval(), cobl(rolePR, "C1"), review.Blocked, review.ReasonClaimConfirmed)
	})
	t.Run("of two differing resolutions for one assignment only the confirmation counts", func(t *testing.T) {
		t.Parallel()
		e := withClaim(t)
		e.verify(vf{id: "v1", claim: claimRef(), at: 20 * time.Minute})
		other := e.snap.Resolutions[0]
		other.Outcome = review.OutcomeConfirmed
		e.snap.Resolutions = append(e.snap.Resolutions, other)
		e.resignRes(1)
		d := e.eval()
		wantOb(t, d, cobl(rolePR, "C1"), review.Blocked, review.ReasonClaimConfirmed)
	})
	t.Run("re-confirmed at the new head stays confirmed", func(t *testing.T) {
		t.Parallel()
		e := withClaim(t)
		e.verify(vf{id: "v1", claim: claimRef(), outcome: review.OutcomeConfirmed, at: 10 * time.Minute})
		e.tgt.HeadSHA = head2
		e.review(rv{role: rolePR, round: "r2", head: head2, repaired: []string{review.RepairedRef(cref("C1"))}, at: 20 * time.Minute, session: "pr-2"})
		e.verify(vf{id: "v2", claim: claimRef(), outcome: review.OutcomeConfirmed, head: head2, at: 30 * time.Minute})
		e.verify(vf{id: "v3", claim: claimRef(), head: head2, at: 40 * time.Minute})
		wantOb(t, e.eval(), cobl(rolePR, "C1"), review.Blocked, review.ReasonClaimConfirmed)
	})
}

func TestEvaluate_Repaired_NamesOneInstance(t *testing.T) { // AGT-4
	t.Parallel()
	changed := claim("C1")
	changed.Consequence = "something else"
	setup := func(t *testing.T, repaired []string) *env {
		t.Helper()
		e := withClaim(t)
		e.verify(vf{claim: claimRef(), outcome: review.OutcomeConfirmed, at: 10 * time.Minute})
		e.tgt.HeadSHA = head2
		e.review(rv{role: rolePR, round: "r2", head: head2, repaired: repaired, at: 20 * time.Minute, session: "pr-2"})
		e.verify(vf{claim: claimRef(), head: head2, at: 30 * time.Minute})
		return e
	}
	t.Run("the instance's own ref repairs it", func(t *testing.T) {
		t.Parallel()
		wantOb(t, setup(t, []string{review.RepairedRef(cref("C1"))}).eval(), cobl(rolePR, "C1"), review.Pass, review.ReasonSatisfied)
	})
	for name, repaired := range map[string][]string{
		"a bare ID":                  {"C1"},
		"another instance of the ID": {review.RepairedRef(review.ClaimRef{Role: rolePR, ID: "C1", Digest: changed.Digest()})},
		"another ID":                 {review.RepairedRef(cref("C2"))},
	} {
		t.Run(name+" doesn't", func(t *testing.T) {
			t.Parallel()
			wantOb(t, setup(t, repaired).eval(), cobl(rolePR, "C1"), review.Blocked, review.ReasonClaimConfirmed)
		})
	}
	t.Run("a repair at a head that isn't the target", func(t *testing.T) {
		t.Parallel()
		e := withClaim(t)
		e.verify(vf{claim: claimRef(), outcome: review.OutcomeConfirmed, at: 10 * time.Minute})
		e.review(rv{role: rolePR, round: "r2", head: head2, repaired: []string{review.RepairedRef(cref("C1"))}, at: 20 * time.Minute, session: "pr-2"})
		e.tgt.HeadSHA = "3333333333333333333333333333333333333333"
		e.setRound("r3", 3, e.tgt.HeadSHA, review.RoundDispatched)
		e.verify(vf{claim: claimRef(), head: e.tgt.HeadSHA, at: 30 * time.Minute})
		wantOb(t, e.eval(), cobl(rolePR, "C1"), review.Blocked, review.ReasonClaimConfirmed)
	})
}

func TestClaimObligationID_Stable(t *testing.T) { // AGT-4
	t.Parallel()
	k := review.ClaimRef{Role: "r", ID: "C1", Digest: claim("C1").Digest()}
	want := "claim:r/C1#" + strings.TrimPrefix(k.Digest, "sha256:")
	if got := review.ClaimObligationID(k); got != want {
		t.Errorf("id = %s, want %s", got, want)
	}
	if review.ClaimObligationID(review.ClaimRef{Role: "r", ID: "C1", Digest: "x"}) != "claim:r/C1#x" {
		t.Error("short digest")
	}
	e := newEnv(t)
	e.review(rv{role: rolePR, verdict: review.VerdictBlock, claims: []review.Claim{claim("C1")}})
	if _, ok := find(e.eval(), review.ClaimObligationID(review.ClaimRef{Role: rolePR, ID: "C1", Digest: claim("C1").Digest()})); !ok {
		t.Error("the claim obligation doesn't have the documented ID")
	}
}

func TestEvaluate_Callers_NoDuplicates(t *testing.T) { // PIP-9
	t.Parallel()
	e := lightsOnEnv(t)
	e.snap.LightsOn.Callers = []string{"svc-a", "svc-a"}
	wantInvalid(t, e.eval())
}

func TestEvaluate_Equality_AndRoundState(t *testing.T) { // CON-8, AGT-5
	t.Parallel()
	t.Run("approval declarations differing only in rollout order", func(t *testing.T) {
		t.Parallel()
		e := lightsOnEnv(t)
		e.snap.LightsOn.RolloutOrder = []string{"a", "b"}
		e.snap.NonSwitchable = &review.Approval{Generation: 1, ImpactRevision: impRev, RecoveryRevision: recRev, RolloutOrder: []string{"b", "a"}}
		wantInvalid(t, e.eval())
	})
	t.Run("approval declarations differing only in caller order are equal", func(t *testing.T) {
		t.Parallel()
		e := lightsOnEnv(t)
		e.snap.LightsOn.Callers = []string{"a", "b"}
		e.snap.NonSwitchable = &review.Approval{Generation: 1, ImpactRevision: impRev, RecoveryRevision: recRev, Callers: []string{"b", "a"}}
		wantDisp(t, e.eval(), review.NeedsAuthorization)
	})
	t.Run("a round with the same ID and another state", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t)
		e.setRound("r1", 1, head1, review.RoundCompleted)
		e.snap.Rounds = append(e.snap.Rounds, review.Round{ID: "r1", Seq: 1, HeadSHA: head1, State: review.RoundSuperseded, Roles: e.snap.Rounds[0].Roles})
		wantInvalid(t, e.eval())
	})
}

func TestEvaluate_SizeCaps_MoreLists(t *testing.T) { // SEC-1
	t.Parallel()
	t.Run("manifests", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t)
		for i := range 10001 {
			e.snap.Manifests[strconv.Itoa(i)] = review.Manifest{}
		}
		wantInvalid(t, e.eval())
	})
	t.Run("sign-off paths, repaired refs and round roles", func(t *testing.T) {
		t.Parallel()
		long := make([]string, 10001)
		e := newEnv(t)
		e.review(rv{role: rolePR})
		e.snap.Attestations[0].SensitiveSignoff = long
		wantInvalid(t, e.eval())
		e = newEnv(t)
		e.review(rv{role: rolePR})
		e.snap.Attestations[0].Repaired = long
		wantInvalid(t, e.eval())
		e = newEnv(t)
		e.snap.Rounds = []review.Round{{ID: "r1", Seq: 1, HeadSHA: head1, State: review.RoundCompleted, Roles: long}}
		wantInvalid(t, e.eval())
	})
	t.Run("callers, rollout order and reviewers", func(t *testing.T) {
		t.Parallel()
		long := make([]string, 10001)
		for i := range long {
			long[i] = strconv.Itoa(i)
		}
		e := lightsOnEnv(t)
		e.snap.LightsOn.Callers = long
		wantInvalid(t, e.eval())
		e = lightsOnEnv(t)
		e.snap.LightsOn.RolloutOrder = long
		wantInvalid(t, e.eval())
		e = newEnv(t)
		e.approveAll()
		e.eff.Reviewers = make([]contract.Requirement, 10001)
		wantInvalid(t, e.eval())
	})
	t.Run("at the caps", func(t *testing.T) {
		t.Parallel()
		long := make([]string, 10000)
		for i := range long {
			long[i] = strconv.Itoa(i)
		}
		e := lightsOnEnv(t)
		e.snap.LightsOn.Callers = long
		wantDisp(t, e.eval(), review.NeedsAuthorization)
	})
}

func TestEvaluate_FirstSeen_IsTheEarliest(t *testing.T) { // AGT-4
	t.Parallel()
	t.Run("a tie goes to the smaller assignment ID", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t)
		e.setRound("r1", 1, head1, review.RoundCompleted)
		e.review(rv{id: "z", role: rolePR, round: "r1", verdict: review.VerdictBlock, claims: []review.Claim{claim("C1")}, at: 10 * time.Minute})
		e.review(rv{id: "a", role: rolePR, round: "r2", verdict: review.VerdictBlock, claims: []review.Claim{claim("C1")}, at: 10 * time.Minute, session: "pr-2"})
		// The tie goes to "a", in round r2 (Seq 2), so a verify round of Seq 1 is too early.
		e.verify(vf{id: "v1", claim: claimRef(), round: "r1", at: 20 * time.Minute})
		wantRejected(t, e.eval(), review.RecordResolution, "v1", review.ReasonRoundBeforeClaim)
	})
	t.Run("a tie with the smaller ID in the earlier round", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t)
		e.setRound("r1", 1, head1, review.RoundCompleted)
		e.review(rv{id: "a", role: rolePR, round: "r1", verdict: review.VerdictBlock, claims: []review.Claim{claim("C1")}, at: 10 * time.Minute})
		e.review(rv{id: "z", role: rolePR, round: "r2", verdict: review.VerdictBlock, claims: []review.Claim{claim("C1")}, at: 10 * time.Minute, session: "pr-2"})
		e.verify(vf{id: "v1", claim: claimRef(), round: "r1", at: 20 * time.Minute})
		d := e.eval()
		if slices.ContainsFunc(d.Rejected, func(r review.Rejection) bool { return r.Kind == review.RecordResolution }) {
			t.Errorf("rejected = %+v", d.Rejected)
		}
	})
}

func TestEvaluate_BlockWinsATie_ByID(t *testing.T) { // AGT-4
	t.Parallel()
	e := newEnv(t)
	e.review(rv{id: "z-approve", role: roleGo, at: 10 * time.Minute})
	e.review(rv{id: "a-block", role: roleGo, verdict: review.VerdictBlock, claims: []review.Claim{claim("C1")}, at: 10 * time.Minute, session: "go-2"})
	wantOb(t, e.eval(), "role:"+roleGo, review.Blocked, review.ReasonReviewerBlocked)
}

func TestEvaluate_GateEvidence_InvalidUTF8(t *testing.T) { // SEC-11
	t.Parallel()
	e := withClaim(t)
	gev := &review.GateEvidence{Gate: gref, RunID: "10\xff0", RunAttempt: "1", JobID: "200", CandidateSHA: cand}
	e.verify(vf{id: "v1", claim: claimRef(), at: 20 * time.Minute, ev: &review.Evidence{Gate: gev}})
	wantInconsistent(t, e.eval())
}

func TestEvaluate_ClaimSort_EveryField(t *testing.T) { // AGT-3
	t.Parallel()
	a := claim("A")
	muts := map[string]func(c *review.Claim){
		"path":        func(c *review.Claim) { c.Path = "z.go" },
		"start":       func(c *review.Claim) { c.StartLine = 99 },
		"end":         func(c *review.Claim) { c.EndLine = 99 },
		"invariant":   func(c *review.Claim) { c.Invariant = "zzz" },
		"consequence": func(c *review.Claim) { c.Consequence = "zzz" },
		"plan":        func(c *review.Claim) { c.VerificationPlan = "zzz" },
	}
	for name, f := range muts {
		b := a
		f(&b)
		x := review.Attestation{Claims: []review.Claim{a, b}}
		y := review.Attestation{Claims: []review.Claim{b, a}}
		if !bytes.Equal(x.SigningPayload(), y.SigningPayload()) {
			t.Errorf("claims differing only in %s sort by order of arrival", name)
		}
	}
}

func TestEvaluate_Confirmation_UsesTheAssignmentsHead(t *testing.T) { // AGT-4
	t.Parallel()
	e := withClaim(t)
	e.verify(vf{id: "v1", claim: claimRef(), outcome: review.OutcomeConfirmed, at: 10 * time.Minute})
	// The verifier signed a ReviewedRevision that isn't its assignment's head. The assignment is what's bound.
	e.snap.Resolutions[0].ReviewedRevision = head2
	e.resignRes(0)
	e.tgt.HeadSHA = head2
	e.review(rv{role: rolePR, round: "r2", head: head2, repaired: []string{review.RepairedRef(cref("C1"))}, at: 20 * time.Minute, session: "pr-2"})
	e.verify(vf{id: "v2", claim: claimRef(), head: head2, at: 30 * time.Minute})
	wantOb(t, e.eval(), cobl(rolePR, "C1"), review.Pass, review.ReasonSatisfied)
}
