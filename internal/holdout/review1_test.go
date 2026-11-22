// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

package holdout_test

import (
	"context"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/elliott-davis/lightsout/internal/audit"
	"github.com/elliott-davis/lightsout/internal/holdout"
)

// failRun grants, opens and records a failure for SC-1.
func (e *env) failRun(rev holdout.Revision, runID, asg string, cred holdout.Credential) {
	e.t.Helper()
	g := e.grant(rev, runID, asg)
	if _, err := e.store.Open(e.ctx(), cred, runID, g.Attempt); err != nil {
		e.t.Fatalf("open: %v", err)
	}
	if err := e.store.RecordOutcome(e.ctx(), cred, runID, g.Attempt, holdout.Outcome{FailedScenarios: []string{"SC-1"}}); err != nil {
		e.t.Fatalf("record: %v", err)
	}
}

func (e *env) entries() []audit.Entry {
	e.t.Helper()
	en, err := e.mem.Read(e.ctx(), 1, audit.MaxReadLimit)
	if err != nil {
		e.t.Fatal(err)
	}
	return en
}

func (e *env) successor(parent holdout.Revision, content string) holdout.Bundle {
	return e.successor2(parent, intentV1, content)
}

func (e *env) successor2(parent holdout.Revision, intent, content string) holdout.Bundle {
	b := bundle(parent, intent)
	b.Files[0].Bytes = []byte(content)
	return b
}

func (e *env) reject(rev holdout.Revision) {
	e.t.Helper()
	_, err := e.store.Review(e.ctx(), "reviewer", holdout.ReviewRequest{
		Suite: suite, Revision: rev, IntentRevision: intentV1, Verdict: holdout.VerdictReject,
		Mismatched: []string{"SC-1"}, Reason: "unblock",
	})
	if err != nil {
		e.t.Fatal(err)
	}
}

// Freeze bypass 1 (item 1): a plain successor proposed before the failure must not be approved after it.
func TestFreezeBypass_PreProposedSuccessor(t *testing.T) { // INT-9, PIP-15
	t.Parallel()
	e := newEnv(t)
	a := e.active()
	b := e.propose(e.successor(a, "weakened assertion"))
	e.failRun(a, "run-1", "asg-1", "runner-a")

	if err := e.review("reviewer", b, intentV1); !errors.Is(err, holdout.ErrFrozen) {
		t.Fatalf("approve plain successor of frozen revision: %v, want ErrFrozen", err)
	}
	rb, _ := e.store.Read(e.ctx(), "qe", suite, b)
	if rb.Status != holdout.StatusProposed {
		t.Fatalf("successor status %q", rb.Status)
	}
	// The way out: reject the stuck proposal, then a correction citing the failed run.
	e.reject(b)
	corr := e.successor(a, "corrected")
	corr.Correction = &holdout.Correction{Replaces: a, FailedRun: "run-1", Reason: "assertion was wrong"}
	c := e.propose(corr)
	if err := e.review("reviewer", c, intentV1); err != nil {
		t.Fatalf("approve correction: %v", err)
	}
}

// A correction proposed against an unfrozen parent and approved later is also refused if its citation no longer
// holds: the gate re-runs failedRunRecorded at approval.
func TestFreezeBypass_FailureAfterSupersedeAttempt(t *testing.T) { // INT-9, PIP-15
	t.Parallel()
	e := newEnv(t)
	a := e.active()
	e.grant(a, "run-1", "asg-1")
	if _, err := e.store.Open(e.ctx(), "runner-a", "run-1", 1); err != nil {
		t.Fatal(err)
	}
	b := e.propose(e.successor(a, "weakened"))
	// The opened attempt could still fail, so the successor cannot be approved yet.
	if err := e.review("reviewer", b, intentV1); !errors.Is(err, holdout.ErrState) {
		t.Fatalf("approve while an attempt is in flight: %v, want ErrState", err)
	}
	if err := e.store.RecordOutcome(e.ctx(), "runner-a", "run-1", 1, holdout.Outcome{FailedScenarios: []string{"SC-1"}}); err != nil {
		t.Fatal(err)
	}
	if err := e.review("reviewer", b, intentV1); !errors.Is(err, holdout.ErrFrozen) {
		t.Fatalf("approve after the failure: %v, want ErrFrozen", err)
	}
	ra, _ := e.store.Read(e.ctx(), "qe", suite, a)
	if ra.Status != holdout.StatusFrozen {
		t.Fatalf("a status %q", ra.Status)
	}
}

// The wedge: a runner opens an attempt and dies. The attempt blocks a successor until its report deadline, then it
// is abandoned, audited once, and no longer blocks.
func TestWedgedAttemptUnblocksAfterReportDeadline(t *testing.T) { // INT-9, PIP-15
	t.Parallel()
	e := newEnv(t)
	a := e.active()
	e.grant(a, "run-1", "asg-1")
	if _, err := e.store.Open(e.ctx(), "runner-a", "run-1", 1); err != nil {
		t.Fatal(err)
	}
	e.intents.set(approved(intentV2)) // the revision is stale, so no new grant can be issued to replace the runner
	next := e.propose(e.successor2(a, intentV2, "for the new intent"))
	if err := e.review("reviewer", next, intentV2); !errors.Is(err, holdout.ErrState) {
		t.Fatalf("while the attempt could still report: %v", err)
	}
	*e.now = e.now.Add(29 * time.Minute)
	if err := e.review("reviewer", next, intentV2); !errors.Is(err, holdout.ErrState) {
		t.Fatalf("just before the deadline: %v", err)
	}
	*e.now = e.now.Add(time.Minute) // exactly at ReportBy
	if err := e.review("reviewer", next, intentV2); err != nil {
		t.Fatalf("after the deadline: %v", err)
	}
	n := 0
	for _, en := range e.entries() {
		if en.Target == "holdout.abandoned" {
			n++
		}
	}
	if n != 1 {
		t.Errorf("%d abandoned audit entries, want 1", n)
	}
}

// A fenced attempt's failure still lands and freezes the revision; it cannot report a pass; and nothing is reported
// after the deadline.
func TestFencedAttemptMayStillReportAFailure(t *testing.T) { // INT-9, PIP-15
	t.Parallel()
	e := newEnv(t)
	a := e.active()
	e.grant(a, "run-1", "asg-1")
	if _, err := e.store.Open(e.ctx(), "runner-a", "run-1", 1); err != nil {
		t.Fatal(err)
	}
	e.grant(a, "run-1", "asg-2") // fences attempt 1, which is still opened
	next := e.propose(e.successor(a, "weakened"))
	if err := e.review("reviewer", next, intentV1); !errors.Is(err, holdout.ErrState) {
		t.Fatalf("fencing must not unblock: %v", err)
	}
	if err := e.store.RecordOutcome(e.ctx(), "runner-a", "run-1", 1, holdout.Outcome{Passed: true}); !errors.Is(err, holdout.ErrDenied) {
		t.Fatalf("fenced pass: %v", err)
	}
	if err := e.store.RecordOutcome(e.ctx(), "runner-a", "run-1", 1, holdout.Outcome{FailedScenarios: []string{"SC-1"}}); err != nil {
		t.Fatalf("fenced failure: %v", err)
	}
	if err := e.review("reviewer", next, intentV1); !errors.Is(err, holdout.ErrFrozen) {
		t.Fatalf("approve after the fenced failure: %v, want ErrFrozen", err)
	}
	if ra, _ := e.store.Read(e.ctx(), "qe", suite, a); ra.Status != holdout.StatusFrozen {
		t.Fatalf("status %q", ra.Status)
	}
	txt := e.auditText()
	if !strings.Contains(txt, "fenced-pass") {
		t.Error("fenced pass reason not audited")
	}
}

func TestLateOutcomeRefused(t *testing.T) { // PIP-15
	t.Parallel()
	e := newEnv(t)
	a := e.active()
	e.grant(a, "run-1", "asg-1")
	if _, err := e.store.Open(e.ctx(), "runner-a", "run-1", 1); err != nil {
		t.Fatal(err)
	}
	*e.now = e.now.Add(30 * time.Minute) // exactly the report deadline
	if err := e.store.RecordOutcome(e.ctx(), "runner-a", "run-1", 1, holdout.Outcome{FailedScenarios: []string{"SC-1"}}); !errors.Is(err, holdout.ErrDenied) {
		t.Fatalf("late failure: %v", err)
	}
	if !strings.Contains(e.auditText(), "late") {
		t.Error("late reason not audited")
	}
	next := e.propose(e.successor(a, "next"))
	if err := e.review("reviewer", next, intentV1); err != nil {
		t.Fatalf("an abandoned attempt blocks nothing: %v", err)
	}
}

func TestPassedAttemptDoesNotBlock(t *testing.T) { // INT-9
	t.Parallel()
	e := newEnv(t)
	a := e.active()
	e.grant(a, "run-1", "asg-1")
	if _, err := e.store.Open(e.ctx(), "runner-a", "run-1", 1); err != nil {
		t.Fatal(err)
	}
	if err := e.store.RecordOutcome(e.ctx(), "runner-a", "run-1", 1, holdout.Outcome{Passed: true}); err != nil {
		t.Fatal(err)
	}
	next := e.propose(e.successor(a, "next"))
	if err := e.review("reviewer", next, intentV1); err != nil {
		t.Fatal(err)
	}
}

func TestMaxRunDurationRequired(t *testing.T) { // PIP-15
	t.Parallel()
	e := newEnv(t)
	_, err := holdout.New(holdout.Config{
		Backend: e.backend, Verifier: fakeVerifier{m: workloads}, Intents: e.intents, Audit: e.audit,
		Clock: func() time.Time { return *e.now },
	})
	if err == nil {
		t.Fatal("a store without a report deadline was accepted")
	}
}

// Assignment reuse (item 2).
func TestAssignmentReuseDefeatedAndRunnersAreBound(t *testing.T) { // INT-6, SEC-11
	t.Parallel()
	e := newEnv(t)
	rev := e.active()
	e.grant(rev, "run-1", "asg-1")
	if _, err := e.store.Open(e.ctx(), "runner-a", "run-1", 1); err != nil {
		t.Fatal(err)
	}
	// The scheduler cannot reuse an assignment for a replacement attempt or for another run.
	if _, err := e.store.IssueGrant(e.ctx(), "scheduler", runRecord(rev, "run-1", "asg-1")); !errors.Is(err, holdout.ErrConflict) {
		t.Errorf("reused assignment for a replacement: %v", err)
	}
	if _, err := e.store.IssueGrant(e.ctx(), "scheduler", runRecord(rev, "run-9", "asg-1")); !errors.Is(err, holdout.ErrConflict) {
		t.Errorf("reused assignment for another run: %v", err)
	}
	g2 := e.grant(rev, "run-1", "asg-2")
	// The fenced credential cannot open the new attempt, with a different assignment or with the same session.
	if _, err := e.store.Open(e.ctx(), "runner-a", "run-1", g2.Attempt); !errors.Is(err, holdout.ErrDenied) {
		t.Errorf("fenced credential opened the next attempt: %v", err)
	}
	if _, err := e.store.Open(e.ctx(), "runner-s1", "run-1", g2.Attempt); !errors.Is(err, holdout.ErrDenied) {
		t.Errorf("session that opened attempt 1 opened attempt 2: %v", err)
	}
	if !strings.Contains(e.auditText(), "session") {
		t.Error("session denial reason not audited")
	}
	if _, err := e.store.Open(e.ctx(), "runner-b", "run-1", g2.Attempt); err != nil {
		t.Errorf("the right runner: %v", err)
	}
	// The attempt is bound to the session that opened it: the same assignment with another session cannot record.
	other := holdout.Credential("runner:asg-2")
	if err := e.store.RecordOutcome(e.ctx(), other, "run-1", g2.Attempt, holdout.Outcome{Passed: true}); !errors.Is(err, holdout.ErrDenied) {
		t.Errorf("another session recorded the outcome: %v", err)
	}
}

// Public IDs only (item 3).
func TestRejectAcceptsOnlyApprovedPublicIDs(t *testing.T) { // INT-9, AGT-2
	t.Parallel()
	e := newEnv(t)
	rev := e.propose(bundle("", intentV1))
	req := holdout.ReviewRequest{
		Suite: suite, Revision: rev, IntentRevision: intentV1, Verdict: holdout.VerdictReject,
		Mismatched: []string{"SC-1"}, Reason: "assertion does not match",
	}
	for name, mut := range map[string]func(*holdout.ReviewRequest){
		"private case id": func(r *holdout.ReviewRequest) { r.Mismatched = []string{"case-a2"} },
		"unknown id":      func(r *holdout.ReviewRequest) { r.Mismatched = []string{"rejects-qty-over-9999"} },
		"no reason":       func(r *holdout.ReviewRequest) { r.Reason = "" },
		"control reason":  func(r *holdout.ReviewRequest) { r.Reason = "a\x00b" },
		"long reason":     func(r *holdout.ReviewRequest) { r.Reason = strings.Repeat("x", 3000) },
		"too many ids": func(r *holdout.ReviewRequest) {
			r.Mismatched = make([]string, holdout.MaxScenarios+1)
		},
	} {
		r := req
		mut(&r)
		if _, err := e.store.Review(e.ctx(), "reviewer", r); !errors.Is(err, holdout.ErrInvalid) {
			t.Errorf("%s: %v, want ErrInvalid", name, err)
		}
	}
	res, err := e.store.Review(e.ctx(), "reviewer", req)
	if err != nil || strings.Join(res.Mismatched, ",") != "SC-1" {
		t.Fatalf("%v %+v", err, res)
	}
	if strings.Contains(e.auditText(), "case-a2") {
		t.Error("private case id reached the audit log")
	}
}

func TestMismatchErrorDoesNotEchoBundleOnlyIDs(t *testing.T) { // INT-9, AGT-2
	t.Parallel()
	e := newEnv(t)
	b := bundle("", intentV1)
	b.Scenarios[0].ScenarioID = "hidden-negative-qty-case" // not an approved scenario
	rev := e.propose(b)
	err := e.review("reviewer", rev, intentV1)
	var mm *holdout.MismatchError
	if !errors.As(err, &mm) {
		t.Fatalf("got %v", err)
	}
	if strings.Contains(err.Error(), "hidden-negative-qty-case") {
		t.Errorf("error echoes a bundle-only id: %v", err)
	}
	if mm.Extra != 1 || strings.Join(mm.ScenarioIDs, ",") != "SC-2" {
		t.Errorf("mismatch %+v", mm)
	}
}

// Attestation rules (items 4, 8, 17).
func TestAttestationIndependentMonotonicAndCarriedForward(t *testing.T) { // INT-7
	t.Parallel()
	e := newEnv(t)
	rev := e.active()
	req := holdout.CoverageRequest{Suite: suite, Revision: rev, Disclosed: []string{"case-a"}}
	for _, cred := range []holdout.Credential{"rev-sameP", "rev-sameS"} {
		if err := e.store.AttestCoverage(e.ctx(), cred, req); !errors.Is(err, holdout.ErrNotIndependent) {
			t.Errorf("%s self-attest: %v", cred, err)
		}
	}
	if err := e.store.AttestCoverage(e.ctx(), "reviewer", req); err != nil {
		t.Fatal(err)
	}
	req.Disclosed = nil
	if err := e.store.AttestCoverage(e.ctx(), "reviewer", req); !errors.Is(err, holdout.ErrDisclosureRegression) {
		t.Errorf("overwrite with fewer disclosures: %v", err)
	}
	req.Disclosed = []string{"case-b"}
	if err := e.store.AttestCoverage(e.ctx(), "reviewer", req); !errors.Is(err, holdout.ErrDisclosureRegression) {
		t.Errorf("replacing the disclosure set: %v", err)
	}

	// Requalification: the successor needs an attestation covering the suite's disclosures.
	next := e.propose(e.successor(rev, "successor"))
	if err := e.review("reviewer", next, intentV1); err != nil {
		t.Fatal(err)
	}
	if _, err := e.store.IssueGrant(e.ctx(), "scheduler", runRecord(next, "run-1", "asg-1")); !errors.Is(err, holdout.ErrNotAttested) {
		t.Fatalf("grant without attestation: %v, want ErrNotAttested", err)
	}
	if err := e.store.AttestCoverage(e.ctx(), "reviewer", holdout.CoverageRequest{Suite: suite, Revision: next}); !errors.Is(err, holdout.ErrDisclosureRegression) {
		t.Errorf("successor attestation dropping case-a: %v", err)
	}
	if err := e.store.AttestCoverage(e.ctx(), "reviewer", holdout.CoverageRequest{Suite: suite, Revision: next, Disclosed: []string{"case-a"}}); err != nil {
		t.Fatal(err)
	}
	e.grant(next, "run-1", "asg-1")
}

func TestAttestCoverageOnUnusableRevisionRefused(t *testing.T) { // INT-7
	t.Parallel()
	e := newEnv(t)
	rev := e.propose(bundle("", intentV1)) // proposed, not approved
	err := e.store.AttestCoverage(e.ctx(), "reviewer", holdout.CoverageRequest{Suite: suite, Revision: rev})
	if !errors.Is(err, holdout.ErrState) {
		t.Fatalf("got %v", err)
	}
}

func TestAttestationBounds(t *testing.T) { // INT-7
	t.Parallel()
	e := newEnv(t)
	rev := e.active()
	for name, d := range map[string][]string{
		"long id":  {strings.Repeat("x", 300)},
		"bad char": {"case a"},
		"too many": slices.Repeat([]string{"a"}, holdout.MaxScenarios*(holdout.MaxPrivateCases+1)+1),
	} {
		err := e.store.AttestCoverage(e.ctx(), "reviewer", holdout.CoverageRequest{Suite: suite, Revision: rev, Disclosed: d})
		if !errors.Is(err, holdout.ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// Retry after outcome (item 5).
func TestNoReplacementAttemptAfterAnOutcome(t *testing.T) { // INT-7, PIP-15
	t.Parallel()
	for name, out := range map[string]holdout.Outcome{
		"pass": {Passed: true},
		"fail": {FailedScenarios: []string{"SC-1"}},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			e := newEnv(t)
			rev := e.active()
			e.grant(rev, "run-1", "asg-1")
			if _, err := e.store.Open(e.ctx(), "runner-a", "run-1", 1); err != nil {
				t.Fatal(err)
			}
			if err := e.store.RecordOutcome(e.ctx(), "runner-a", "run-1", 1, out); err != nil {
				t.Fatal(err)
			}
			if _, err := e.store.IssueGrant(e.ctx(), "scheduler", runRecord(rev, "run-1", "asg-2")); !errors.Is(err, holdout.ErrConflict) {
				t.Fatalf("replacement after %s: %v", name, err)
			}
			e.grant(rev, "run-2", "asg-3") // a rerun is a new run
		})
	}
}

// Audit accuracy and global uniqueness (item 6).
type startGate struct {
	holdout.Backend
	wg *sync.WaitGroup
}

func (g startGate) Update(ctx context.Context, s holdout.SuiteID, fn func(*holdout.State, holdout.WriteTx) error) error {
	g.wg.Done()
	g.wg.Wait() // both writers are inside Update before either commits
	return g.Backend.Update(ctx, s, fn)
}

func TestGrantAuditMatchesWhatIsStored(t *testing.T) { // INT-7, NFR-4
	t.Parallel()
	t.Run("same run id", func(t *testing.T) {
		t.Parallel()
		grantRace(t, func(int) string { return "run-dup" }, func(i int) string { return []string{"asg-p", "asg-q"}[i] })
	})
	t.Run("same assignment", func(t *testing.T) {
		t.Parallel()
		grantRace(t, func(i int) string { return []string{"run-x", "run-y"}[i] }, func(int) string { return "asg-same" })
	})
}

// approveIn proposes and approves a first revision of s with the matching QE and reviewer credentials.
func (e *env) approveIn(s holdout.SuiteID, qe, rev holdout.Credential) holdout.Revision {
	e.t.Helper()
	b := bundle("", intentV1)
	b.Suite = s
	r, err := e.store.Propose(e.ctx(), qe, b)
	if err != nil {
		e.t.Fatal(err)
	}
	req := holdout.ReviewRequest{Suite: s, Revision: r, IntentRevision: intentV1, Verdict: holdout.VerdictApprove}
	if _, err = e.store.Review(e.ctx(), rev, req); err != nil {
		e.t.Fatal(err)
	}
	return r
}

// grantRace issues two grants for two suites at the same time and checks that exactly one is stored and audited.
func grantRace(t *testing.T, runID, assignment func(i int) string) {
	t.Helper()
	e := newEnv(t)
	suites := []holdout.SuiteID{suite, suite8}
	revs := []holdout.Revision{e.approveIn(suite, "qe", "reviewer"), e.approveIn(suite8, "qe-8", "reviewer-8")}
	var wg sync.WaitGroup
	wg.Add(2)
	st := e.storeOn(startGate{Backend: e.backend, wg: &wg})
	errs := make([]error, 2)
	var done sync.WaitGroup
	for i := range suites {
		done.Add(1)
		go func() {
			defer done.Done()
			rr := runRecord(revs[i], runID(i), assignment(i))
			rr.Suite = suites[i]
			_, errs[i] = st.IssueGrant(e.ctx(), "scheduler", rr)
		}()
	}
	done.Wait()
	oks, stored := 0, 0
	entries := e.entries()
	for i := range entries {
		if en := &entries[i]; en.Target == "holdout.issue-grant" && en.Outcome == "ok" {
			oks++
		}
	}
	for _, gerr := range errs {
		if gerr == nil {
			stored++
		} else if !errors.Is(gerr, holdout.ErrConflict) {
			t.Errorf("loser: %v", gerr)
		}
	}
	if stored != 1 || oks != 1 {
		t.Fatalf("stored grants %d, ok audit entries %d, errors %v; want 1 and 1", stored, oks, errs)
	}
}

// Suite-scoped assignments (item 7).
func TestQEAndReviewerNeedThisSuitesAssignment(t *testing.T) { // INT-6, SEC-11
	t.Parallel()
	e := newEnv(t)
	rev := e.active()
	before := e.backend.calls.Load()
	for _, cred := range []holdout.Credential{"qe-8", "qe-sibling", "reviewer-8"} {
		if _, err := e.store.Read(e.ctx(), cred, suite, rev); !errors.Is(err, holdout.ErrDenied) {
			t.Errorf("%s read: %v", cred, err)
		}
		if _, err := e.store.Status(e.ctx(), cred, suite); !errors.Is(err, holdout.ErrDenied) {
			t.Errorf("%s status: %v", cred, err)
		}
		if _, err := e.store.LeakCheck(e.ctx(), cred, holdout.LeakRequest{Suite: suite, Revision: rev}); !errors.Is(err, holdout.ErrDenied) {
			t.Errorf("%s leak: %v", cred, err)
		}
	}
	if _, err := e.store.Propose(e.ctx(), "qe-8", bundle("", intentV1)); !errors.Is(err, holdout.ErrDenied) {
		t.Errorf("propose: %v", err)
	}
	if _, err := e.store.Review(e.ctx(), "reviewer-8", holdout.ReviewRequest{Suite: suite, Revision: rev, IntentRevision: intentV1, Verdict: holdout.VerdictApprove}); !errors.Is(err, holdout.ErrDenied) {
		t.Errorf("review: %v", err)
	}
	if err := e.store.AttestCoverage(e.ctx(), "reviewer-8", holdout.CoverageRequest{Suite: suite, Revision: rev}); !errors.Is(err, holdout.ErrDenied) {
		t.Errorf("attest: %v", err)
	}
	if n := e.backend.calls.Load() - before; n != 0 {
		t.Errorf("denials read the backend %d times", n)
	}
	if got := suite.Assignment(); got != "suite:github:1#7" {
		t.Errorf("canonical assignment %q", got)
	}
}

func TestLeakCheckByReviewer(t *testing.T) { // INT-7
	t.Parallel()
	e := newEnv(t)
	rev := e.active()
	got, _ := e.store.Read(e.ctx(), "qe", suite, rev)
	rep, err := e.store.LeakCheck(e.ctx(), "reviewer", holdout.LeakRequest{
		Suite: suite, Revision: rev,
		Files: []holdout.PublicFile{{Path: "x_test.go", Bytes: got.Bundle.Files[0].Bytes}},
	})
	if err != nil || len(rep.Findings) != 1 {
		t.Fatalf("%v %+v", err, rep)
	}
}

// Status for the hand-off gate (item 10, 14).
func TestStatus(t *testing.T) { // INT-9
	t.Parallel()
	e := newEnv(t)
	st, err := e.store.Status(e.ctx(), "scheduler", suite)
	if err != nil || st.Head != "" || st.Eligible {
		t.Fatalf("empty suite: %v %+v", err, st)
	}
	rev := e.propose(bundle("", intentV1))
	st, _ = e.store.Status(e.ctx(), "scheduler", suite)
	if st.Head != rev || st.Status != holdout.StatusProposed || st.Eligible {
		t.Fatalf("proposed: %+v", st)
	}
	e.reject(rev)
	st, _ = e.store.Status(e.ctx(), "scheduler", suite)
	if st.Head != "" || strings.Join(st.Blocking, ",") != "SC-1" {
		t.Fatalf("after reject: %+v", st)
	}
	n := bundle("", intentV1)
	n.Files[0].Bytes = []byte("second")
	rev2 := e.propose(n)
	if err := e.review("reviewer", rev2, intentV1); err != nil {
		t.Fatal(err)
	}
	st, _ = e.store.Status(e.ctx(), "qe", suite)
	if st.Head != rev2 || st.Status != holdout.StatusActive || !st.Eligible || len(st.Blocking) != 0 {
		t.Fatalf("active: %+v", st)
	}
	// Staleness is reported at read time, without any call having marked the revision.
	e.intents.set(approved(intentV2))
	st, _ = e.store.Status(e.ctx(), "reviewer", suite)
	if st.Status != holdout.StatusStale || st.Eligible {
		t.Fatalf("stale: %+v", st)
	}
	if got, _ := e.store.Read(e.ctx(), "qe", suite, rev2); got.Status != holdout.StatusStale {
		t.Fatalf("read reports %q", got.Status)
	}
	e.intents.set(holdout.IntentState{Approved: intentV1, Pending: true, ScenarioIDs: []string{"SC-1", "SC-2"}})
	if st, _ = e.store.Status(e.ctx(), "scheduler", suite); st.Eligible || st.Status != holdout.StatusActive {
		t.Fatalf("pending: %+v", st)
	}
}

func TestStatusDeniedUniformly(t *testing.T) { // SEC-11, INT-9
	t.Parallel()
	e := newEnv(t)
	e.active()
	before := e.backend.calls.Load()
	for _, cred := range []holdout.Credential{"coder", "pr-review", "ci", "human", "runner-a", "unknown", "qe-other", "qe-8"} {
		if _, err := e.store.Status(e.ctx(), cred, suite); err != holdout.ErrDenied { //nolint:errorlint // the very same sentinel
			t.Errorf("%s: %v", cred, err)
		}
	}
	if n := e.backend.calls.Load() - before; n != 0 {
		t.Errorf("%d backend calls", n)
	}
}

// Runner denial reasons, backend errors, no existence oracle (items 11, 12, 17).
func TestRunnerDenialReasonsAreAudited(t *testing.T) { // SEC-11
	t.Parallel()
	e := newEnv(t)
	rev := e.active()
	e.grant(rev, "run-1", "asg-1")
	e.grant(rev, "run-2", "asg-2")
	denied := func(cred holdout.Credential, run string, attempt int) {
		t.Helper()
		if _, err := e.store.Open(e.ctx(), cred, run, attempt); err != holdout.ErrDenied { //nolint:errorlint // the very same sentinel
			t.Fatalf("%s %s %d: %v", cred, run, attempt, err)
		}
	}
	denied("runner-a", "nope", 1)  // unknown
	denied("runner-a", "run-1", 0) // unknown (attempt out of range)
	denied("runner-a", "run-1", 2) // unknown
	denied("runner-b", "run-1", 1) // assignment
	if _, err := e.store.Open(e.ctx(), "runner-a", "run-1", 1); err != nil {
		t.Fatal(err)
	}
	denied("runner-a", "run-1", 1) // reused
	e.grant(rev, "run-1", "asg-3") // fences attempt 1... but attempt 1 has no outcome yet
	denied("runner-a", "run-1", 1) // fenced
	// unusable: supersede the revision while run-2 is unopened. run-1's opened attempt must pass its report deadline.
	*e.now = e.now.Add(31 * time.Minute)
	next := e.propose(e.successor(rev, "next"))
	if err := e.review("reviewer", next, intentV1); err != nil {
		t.Fatal(err)
	}
	denied("runner-b", "run-2", 1) // unusable
	e.grant(next, "run-3", "asg-4")
	e.intents.set(holdout.IntentState{Approved: intentV1, Pending: true, ScenarioIDs: []string{"SC-1", "SC-2"}})
	denied("runner:asg-4", "run-3", 1) // pending
	e.intents.set(approved(intentV2))
	denied("runner:asg-4", "run-3", 1) // stale
	*e.now = e.now.Add(3 * time.Hour)
	denied("runner:asg-4", "run-3", 1) // expired (revision is stale too, but the earlier check wins)

	txt := e.auditText()
	for _, want := range []string{"unknown", "assignment", "reused", "fenced", "unusable", "pending", "stale", "expired"} {
		if !strings.Contains(txt, want) {
			t.Errorf("audit lacks reason %q", want)
		}
	}
}

func TestExpiryBoundary(t *testing.T) { // INT-6
	t.Parallel()
	e := newEnv(t)
	rev := e.active()
	g := e.grant(rev, "run-1", "asg-1")
	e.grant(rev, "run-2", "asg-2")
	*e.now = g.ExpiresAt.Add(-time.Nanosecond)
	if _, err := e.store.Open(e.ctx(), "runner-a", "run-1", 1); err != nil {
		t.Fatalf("just before expiry: %v", err)
	}
	*e.now = g.ExpiresAt
	if _, err := e.store.Open(e.ctx(), "runner-b", "run-2", 1); !errors.Is(err, holdout.ErrDenied) {
		t.Fatalf("exactly at expiry: %v", err)
	}
}

type failingRunIndex struct{ holdout.Backend }

func (failingRunIndex) SuiteOfRun(context.Context, string) (holdout.SuiteID, bool, error) {
	return holdout.SuiteID{}, false, errors.New("database down")
}

func TestBackendErrorsAreNotDenials(t *testing.T) { // SEC-11
	t.Parallel()
	e := newEnv(t)
	st := e.storeOn(failingRunIndex{e.backend})
	if _, err := st.Open(e.ctx(), "runner-a", "run-1", 1); err == nil || errors.Is(err, holdout.ErrDenied) {
		t.Errorf("open: %v", err)
	}
	if err := st.RecordOutcome(e.ctx(), "runner-a", "run-1", 1, holdout.Outcome{}); err == nil || errors.Is(err, holdout.ErrDenied) {
		t.Errorf("record: %v", err)
	}
}

func TestRunnerLookupHasNoExistenceOracle(t *testing.T) { // SEC-11, INT-6
	t.Parallel()
	e := newEnv(t)
	rev := e.active()
	e.grant(rev, "run-2", "asg-2")
	count := func(cred holdout.Credential, run string) (total, suites int64, err error) {
		t0, s0 := e.backend.calls.Load(), e.backend.suites.Load()
		_, err = e.store.Open(e.ctx(), cred, run, 1)
		return e.backend.calls.Load() - t0, e.backend.suites.Load() - s0, err
	}
	nCross, sCross, err1 := count("runner-o", "run-2") // exists, another repo
	nNone, sNone, err2 := count("runner-o", "run-none")
	if err1 != holdout.ErrDenied || err2 != holdout.ErrDenied { //nolint:errorlint // the very same sentinel
		t.Fatalf("errors %v %v", err1, err2)
	}
	if sCross != 0 || sNone != 0 {
		t.Errorf("cross-repo or unknown runner read suite state: %d %d", sCross, sNone)
	}
	if nCross != nNone || nCross != 1 {
		t.Errorf("lookup cost differs: existing %d, unknown %d", nCross, nNone)
	}
	en := e.entries()
	last, prev := en[len(en)-1], en[len(en)-2]
	if last.Subject != prev.Subject {
		t.Errorf("audit subjects differ: %+v vs %+v", prev.Subject, last.Subject)
	}
}

func TestRefusalForInvalidSuiteIsAudited(t *testing.T) { // NFR-4
	t.Parallel()
	e := newEnv(t)
	e.active()
	before := len(e.entries())
	bad := holdout.SuiteID{Repo: repo, Issue: 0}
	if _, err := e.store.Read(e.ctx(), "qe-bad", bad, "sha256:"+holdout.Revision(strings.Repeat("1", 64))); !errors.Is(err, holdout.ErrInvalid) {
		t.Fatalf("got %v", err)
	}
	en := e.entries()
	if len(en) != before+1 || !strings.Contains(en[len(en)-1].Target, "holdout.read") {
		t.Fatalf("refusal not audited: %d -> %d", before, len(en))
	}
}

func TestRefusalsAreAudited(t *testing.T) { // NFR-4
	t.Parallel()
	e := newEnv(t)
	rev := e.active()
	b := bundle("", intentV1) // wrong parent
	b.Files[0].Bytes = []byte("again")
	if _, err := e.store.Propose(e.ctx(), "qe", b); !errors.Is(err, holdout.ErrConflict) {
		t.Fatal(err)
	}
	_ = rev
	txt := e.auditText()
	if !strings.Contains(txt, "refused") || !strings.Contains(txt, "conflict") {
		t.Error("refusal not audited")
	}
}

// Outcome bounds (item 15).
func TestOutcomeBounds(t *testing.T) { // PIP-15
	t.Parallel()
	e := newEnv(t)
	rev := e.active()
	e.grant(rev, "run-1", "asg-1")
	if _, err := e.store.Open(e.ctx(), "runner-a", "run-1", 1); err != nil {
		t.Fatal(err)
	}
	big := make([]string, 200000)
	for i := range big {
		big[i] = "SC-1"
	}
	if err := e.store.RecordOutcome(e.ctx(), "runner-a", "run-1", 1, holdout.Outcome{FailedScenarios: big}); !errors.Is(err, holdout.ErrDenied) {
		t.Fatalf("huge list: %v", err)
	}
	if err := e.store.RecordOutcome(e.ctx(), "runner-a", "run-1", 1, holdout.Outcome{FailedScenarios: []string{"SC-2", "SC-1", "SC-2"}}); err != nil {
		t.Fatal(err)
	}
	_ = e.backend.View(e.ctx(), suite, func(st *holdout.State, _ holdout.ReadTx) error {
		got := st.Runs["run-1"].Attempts[0].Outcome.FailedScenarios
		if !slices.Equal(got, []string{"SC-1", "SC-2"}) {
			t.Errorf("stored %v", got)
		}
		return nil
	})
}

// Path rules (item 15).
func TestProposeRejectsCollidingPaths(t *testing.T) { // INT-6
	t.Parallel()
	for name, paths := range map[string][2]string{
		"file vs dir":   {"tests", "tests/x.go"},
		"case fold":     {"tests/A.go", "tests/a.go"},
		"nfc vs nfd":    {"tests/é.go", "tests/é.go"},
		"git dir":       {".git/hooks/pre-commit", "ok.go"},
		"nested git":    {"a/.git/config", "ok.go"},
		"git case":      {".GIT/config", "ok.go"},
		"git file":      {"sub/.git", "ok.go"},
		"nfd alone":     {"tests/é.go", "ok.go"},
		"dir case fold": {"Tests/x.go", "tests"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			e := newEnv(t)
			b := bundle("", intentV1)
			b.Files[0].Path, b.Files[1].Path = paths[0], paths[1]
			if _, err := e.store.Propose(e.ctx(), "qe", b); !errors.Is(err, holdout.ErrInvalid) {
				t.Fatalf("got %v, want ErrInvalid", err)
			}
		})
	}
	e := newEnv(t)
	b := bundle("", intentV1)
	b.Files[1].Mode = 0o755 // a fixture must not be executable
	if _, err := e.store.Propose(e.ctx(), "qe", b); !errors.Is(err, holdout.ErrInvalid) {
		t.Errorf("executable fixture: %v", err)
	}
	b = bundle("", intentV1)
	b.Files[0].Mode = 0o755 // a test may be
	if _, err := e.store.Propose(e.ctx(), "qe", b); err != nil {
		t.Errorf("executable test: %v", err)
	}
	if !utf8.ValidString("é") {
		t.Fatal("unreachable")
	}
}

func TestProposeBounds(t *testing.T) { // INT-6
	t.Parallel()
	e := newEnv(t)
	b := bundle("", intentV1)
	for i := range 257 {
		b.Scenarios[0].Private = append(b.Scenarios[0].Private, "pc-"+strings.Repeat("x", 1)+string(rune('a'+i%26))+string(rune('a'+i/26)))
	}
	if _, err := e.store.Propose(e.ctx(), "qe", b); !errors.Is(err, holdout.ErrInvalid) {
		t.Errorf("MaxPrivateCases: %v", err)
	}
	big := bundle("", intentV1)
	big.Files = nil
	for i := range 16 {
		big.Files = append(big.Files, holdout.File{Path: "f/" + string(rune('a'+i)), Mode: 0o644, Kind: holdout.KindFixture, Bytes: make([]byte, holdout.MaxFileBytes)})
	}
	big.Files = append(big.Files, holdout.File{Path: "f/z", Mode: 0o644, Kind: holdout.KindFixture, Bytes: []byte{1}})
	if _, err := e.store.Propose(e.ctx(), "qe", big); !errors.Is(err, holdout.ErrInvalid) {
		t.Errorf("MaxBundleBytes: %v", err)
	}
	many := bundle("", intentV1)
	many.Scenarios = nil
	for i := range holdout.MaxScenarios + 1 {
		many.Scenarios = append(many.Scenarios, holdout.Binding{
			ScenarioID: "S" + string(rune('a'+i%26)) + string(rune('a'+i/26)), Layer: "go", Entry: "e" + string(rune('a'+i%26)) + string(rune('a'+i/26)),
		})
	}
	if _, err := e.store.Propose(e.ctx(), "qe", many); !errors.Is(err, holdout.ErrInvalid) {
		t.Errorf("MaxScenarios: %v", err)
	}
}

// Canonical encoding adjacency (item 17).
func TestCanonicalEncodingFieldBoundaries(t *testing.T) { // INT-7
	t.Parallel()
	base := func() holdout.Bundle { return bundle("", intentV1) }
	pairs := map[string][2]func(*holdout.Bundle){
		"layer/entry": {
			func(b *holdout.Bundle) { b.Scenarios[0].Layer, b.Scenarios[0].Entry = "ab", "c" },
			func(b *holdout.Bundle) { b.Scenarios[0].Layer, b.Scenarios[0].Entry = "a", "bc" },
		},
		"scenario id/layer": {
			func(b *holdout.Bundle) { b.Scenarios[0].ScenarioID, b.Scenarios[0].Layer = "ab", "c" },
			func(b *holdout.Bundle) { b.Scenarios[0].ScenarioID, b.Scenarios[0].Layer = "a", "bc" },
		},
		"repo/intent": {
			func(b *holdout.Bundle) { b.Suite.Repo, b.IntentRevision = "ab", "c" },
			func(b *holdout.Bundle) { b.Suite.Repo, b.IntentRevision = "a", "bc" },
		},
	}
	for name, p := range pairs {
		x, y := base(), base()
		p[0](&x)
		p[1](&y)
		if x.Revision() == y.Revision() {
			t.Errorf("%s: boundary ambiguity", name)
		}
	}
	a, c := base(), base()
	a.Correction = &holdout.Correction{Replaces: "r", FailedRun: "f", Reason: "one"}
	c.Correction = &holdout.Correction{Replaces: "r", FailedRun: "f", Reason: "two"}
	if a.Revision() == c.Revision() {
		t.Error("correction reason does not change the revision")
	}
	d := base()
	d.Suite.Repo = "github:9"
	if d.Revision() == base().Revision() {
		t.Error("repo does not change the revision")
	}
}

// Corrections citing the wrong failure (item 17).
func TestCorrectionMustCiteThisRevisionsFailedRun(t *testing.T) { // INT-9
	t.Parallel()
	e := newEnv(t)
	a := e.active()
	e.failRun(a, "run-1", "asg-1", "runner-a")
	c1 := bundle(a, intentV1)
	c1.Files[0].Bytes = []byte("c1")
	c1.Correction = &holdout.Correction{Replaces: a, FailedRun: "run-1", Reason: "fix"}
	rev1 := e.propose(c1)
	if err := e.review("reviewer", rev1, intentV1); err != nil {
		t.Fatal(err)
	}
	// A passed run of the new revision does not unfreeze anything and cannot be cited.
	g := e.grant(rev1, "run-2", "asg-2")
	if _, err := e.store.Open(e.ctx(), "runner-b", "run-2", g.Attempt); err != nil {
		t.Fatal(err)
	}
	if err := e.store.RecordOutcome(e.ctx(), "runner-b", "run-2", g.Attempt, holdout.Outcome{Passed: true}); err != nil {
		t.Fatal(err)
	}
	e.failRun(rev1, "run-3", "asg-3", "runner:asg-3")
	for name, run := range map[string]string{"older revision's failure": "run-1", "a passed run": "run-2"} {
		c2 := bundle(rev1, intentV1)
		c2.Files[0].Bytes = []byte("c2-" + name)
		c2.Correction = &holdout.Correction{Replaces: rev1, FailedRun: run, Reason: "fix"}
		if _, err := e.store.Propose(e.ctx(), "qe", c2); !errors.Is(err, holdout.ErrBadCorrection) {
			t.Errorf("%s: %v", name, err)
		}
	}
	good := bundle(rev1, intentV1)
	good.Files[0].Bytes = []byte("c2-good")
	good.Correction = &holdout.Correction{Replaces: rev1, FailedRun: "run-3", Reason: "fix"}
	e.propose(good)
}

func TestOpenAfterSupersedeDenied(t *testing.T) { // INT-9
	t.Parallel()
	e := newEnv(t)
	a := e.active()
	e.grant(a, "run-1", "asg-1")
	b := e.propose(e.successor(a, "n"))
	if err := e.review("reviewer", b, intentV1); err != nil {
		t.Fatal(err)
	}
	if _, err := e.store.Open(e.ctx(), "runner-a", "run-1", 1); !errors.Is(err, holdout.ErrDenied) {
		t.Fatalf("opened a superseded revision: %v", err)
	}
}

// Blobs (item 16): file bytes are not in the transaction state, and tampering releases nothing.
type tamperBackend struct{ holdout.Backend }

func (b tamperBackend) View(ctx context.Context, s holdout.SuiteID, fn func(*holdout.State, holdout.ReadTx) error) error {
	return b.Backend.View(ctx, s, func(st *holdout.State, tx holdout.ReadTx) error { return fn(st, tamperTx{tx}) })
}

type tamperTx struct{ holdout.ReadTx }

func (t tamperTx) Files(rev holdout.Revision) ([]holdout.File, bool) {
	f, ok := t.ReadTx.Files(rev)
	if ok {
		f = slices.Clone(f)
		f[0].Bytes = []byte("tampered")
	}
	return f, ok
}

func TestFileBlobsAreSeparateAndChecked(t *testing.T) { // INT-6
	t.Parallel()
	e := newEnv(t)
	rev := e.active()
	_ = e.backend.View(e.ctx(), suite, func(st *holdout.State, _ holdout.ReadTx) error {
		rec := st.Revisions[rev]
		if len(rec.Bundle.Files) != 0 || len(rec.Files) != 2 || rec.Files[0].SHA256 == "" {
			t.Errorf("state holds file bytes or lacks metadata: %+v", rec.Files)
		}
		return nil
	})
	st := e.storeOn(tamperBackend{e.backend})
	got, err := st.Read(e.ctx(), "qe", suite, rev)
	if err == nil || got.Bundle.Files != nil {
		t.Fatalf("tampered blob released: %v", err)
	}
}

func TestReplacementMustKeepThePinnedInputs(t *testing.T) { // INT-7
	t.Parallel()
	e := newEnv(t)
	rev := e.active()
	e.grant(rev, "run-1", "asg-1")
	for name, mut := range map[string]func(*holdout.RunRecord){
		"candidate": func(r *holdout.RunRecord) { r.CandidateSHA = strings.Repeat("d", 40) },
		"artifact":  func(r *holdout.RunRecord) { r.ArtifactDigest = "sha256:" + strings.Repeat("e", 64) },
		"switches":  func(r *holdout.RunRecord) { r.SwitchConfigDigest = "sha256:" + strings.Repeat("f", 64) },
	} {
		rr := runRecord(rev, "run-1", "asg-"+name)
		mut(&rr)
		if _, err := e.store.IssueGrant(e.ctx(), "scheduler", rr); !errors.Is(err, holdout.ErrConflict) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if g := e.grant(rev, "run-1", "asg-2"); g.Attempt != 2 {
		t.Errorf("same pins: attempt %d", g.Attempt)
	}
}

func TestRejectedBundleCannotBeProposedAgain(t *testing.T) { // INT-9
	t.Parallel()
	e := newEnv(t)
	b := bundle("", intentV1)
	rev := e.propose(b)
	e.reject(rev)
	if _, err := e.store.Propose(e.ctx(), "qe", b); !errors.Is(err, holdout.ErrConflict) {
		t.Fatalf("re-proposing a rejected revision: %v", err)
	}
	if n := e.okCount("holdout.propose"); n != 1 {
		t.Fatalf("%d ok propose entries, want 1: a refused proposal must leave no ok entry", n)
	}
}
