// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

package gate_test

import (
	"math/rand/v2"
	"slices"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/elliott-davis/lightsout/internal/contract"
	"github.com/elliott-davis/lightsout/internal/forge"
	"github.com/elliott-davis/lightsout/internal/gate"
)

const (
	repo      = forge.RepoID("acme/app")
	wfRepo    = forge.RepoID("4242")
	wfPath    = ".github/workflows/verify.yml"
	pin       = "111111111111111111111111111111111111111a"
	candA     = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	candB     = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	producer  = "15368" // the forge's app ID, as in JobExecution.ProducerAppID
	otherProd = "99999"
)

func gateRef(check string) contract.GateRef {
	return contract.GateRef{
		ProducerID:       "github-app:" + producer,
		WorkflowID:       contract.WorkflowID(string(wfRepo) + "/" + wfPath),
		WorkflowRevision: pin,
		CheckID:          check,
	}
}

func obligation(check string, mandatory bool) contract.Obligation {
	return contract.Obligation{
		Gate:    contract.Gate{Name: check, GateRef: gateRef(check), Mandatory: mandatory},
		Owner:   contract.OwnerContract,
		Sources: []string{"contract.json"},
	}
}

func eff(obs ...contract.Obligation) *contract.Effective {
	return &contract.Effective{Revision: "pol1", InstallRevision: "inst1", VerifyGates: obs}
}

var t0 = time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)

func exec(check string, mod ...func(*forge.JobExecution)) forge.JobExecution {
	e := forge.JobExecution{
		Repo: repo, CandidateSHA: candA, Event: "merge_group", ProducerAppID: producer,
		WorkflowRepo: wfRepo, WorkflowPath: wfPath, WorkflowCommit: pin,
		JobKey: check, RunID: "run1", RunAttempt: "1", JobID: "job-" + check,
		Started: t0, Completed: t0.Add(time.Minute), Conclusion: forge.ConclusionSuccess,
		Provenance: forge.ProvenanceComplete,
	}
	for _, m := range mod {
		m(&e)
	}
	return e
}

func target() gate.Target {
	return gate.Target{Forge: "github", Repo: repo, PR: 7, HeadSHA: "head", CandidateSHA: candA}
}

func evid(execs ...forge.JobExecution) gate.Evidence {
	return gate.Evidence{Executions: execs, Complete: true}
}

func run(t *testing.T, e *contract.Effective, ev gate.Evidence) gate.Decision {
	t.Helper()
	return gate.Evaluate(e, target(), ev)
}

func wantObl(t *testing.T, d gate.Decision, disp gate.Disposition, reason gate.Reason, evidence ...gate.Reason) gate.ObligationResult {
	t.Helper()
	if len(d.Obligations) == 0 {
		t.Fatal("no obligations")
	}
	o := d.Obligations[0]
	if len(d.Reasons) == 0 && d.Disposition != disp {
		t.Fatalf("change disposition = %s, want %s", d.Disposition, disp)
	}
	if o.Disposition != disp || o.Reason != reason {
		t.Fatalf("obligation = %s/%q, want %s/%q", o.Disposition, o.Reason, disp, reason)
	}
	if diff := cmp.Diff(evidence, o.Evidence, cmpopts.EquateEmpty()); diff != "" {
		t.Fatalf("evidence mismatch (-want +got):\n%s", diff)
	}
	return o
}

func TestEvaluate_Pass(t *testing.T) { // PIP-2, CON-4
	e := eff(obligation("verify", true))
	d := run(t, e, evid(exec("verify")))
	if d.Disposition != gate.Pass {
		t.Fatalf("disposition = %s", d.Disposition)
	}
	o := wantObl(t, d, gate.Pass, gate.ReasonNone)
	if o.RunID != "run1" || o.RunAttempt != "1" || o.JobID != "job-verify" || o.Owner != contract.OwnerContract ||
		!o.Mandatory || len(o.Sources) != 1 {
		t.Errorf("result fields = %+v", o)
	}
	if d.PolicyRevision != "pol1" || d.InstallRevision != "inst1" || d.CandidateSHA != candA {
		t.Errorf("binding = %+v", d)
	}
}

func TestEvaluate_SameNameForeignCheck(t *testing.T) { // SEC-11, CON-4
	e := eff(obligation("verify", true))
	foreign := exec("verify", func(x *forge.JobExecution) { x.ProducerAppID = otherProd })
	d := run(t, e, evid(foreign))
	wantObl(t, d, gate.Blocked, gate.ReasonMissing, gate.ReasonForeign)
	if d.Disposition != gate.Blocked {
		t.Fatalf("disposition = %s", d.Disposition)
	}
}

func TestEvaluate_ForeignDoesNotSupersedeReal(t *testing.T) { // SEC-11
	e := eff(obligation("verify", true))
	foreign := exec("verify", func(x *forge.JobExecution) {
		x.ProducerAppID = otherProd
		x.RunAttempt = "9"
		x.Conclusion = forge.ConclusionFailure
	})
	d := run(t, e, evid(exec("verify"), foreign))
	wantObl(t, d, gate.Pass, gate.ReasonNone)
	// And a foreign success next to a real failure never rescues it.
	d = run(t, e, evid(exec("verify", func(x *forge.JobExecution) { x.Conclusion = forge.ConclusionFailure }),
		exec("verify", func(x *forge.JobExecution) { x.ProducerAppID = otherProd })))
	wantObl(t, d, gate.Blocked, gate.ReasonFailed)
}

func TestEvaluate_OverallGreenWithSkippedJob(t *testing.T) { // SEC-11
	e := eff(obligation("build", true), obligation("lint", true), obligation("verify", true))
	d := run(t, e, evid(exec("build"), exec("lint"), exec("verify", func(x *forge.JobExecution) { x.Conclusion = forge.ConclusionSkipped })))
	if d.Disposition != gate.Blocked {
		t.Fatalf("disposition = %s", d.Disposition)
	}
	for i, want := range []gate.Disposition{gate.Pass, gate.Pass, gate.Blocked} {
		if d.Obligations[i].Disposition != want {
			t.Errorf("obligation %d = %s, want %s", i, d.Obligations[i].Disposition, want)
		}
	}
	if d.Obligations[2].Reason != gate.ReasonNotRun {
		t.Errorf("reason = %q", d.Obligations[2].Reason)
	}
}

func TestEvaluate_NotRunConclusions(t *testing.T) { // SEC-11
	t.Parallel()
	tests := map[string]func(*forge.JobExecution){
		"neutral":           func(x *forge.JobExecution) { x.Conclusion = forge.ConclusionNeutral },
		"cancelled":         func(x *forge.JobExecution) { x.Conclusion = forge.ConclusionCancelled },
		"timed out":         func(x *forge.JobExecution) { x.Conclusion = forge.ConclusionTimedOut },
		"action required":   func(x *forge.JobExecution) { x.Conclusion = forge.CheckConclusion(99) },
		"success no start":  func(x *forge.JobExecution) { x.Started = time.Time{} },
		"success no end":    func(x *forge.JobExecution) { x.Completed = time.Time{} },
		"ends before start": func(x *forge.JobExecution) { x.Completed = x.Started.Add(-time.Second) },
	}
	for name, m := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			d := run(t, eff(obligation("verify", true)), evid(exec("verify", m)))
			wantObl(t, d, gate.Blocked, gate.ReasonNotRun)
			if d.Disposition != gate.Blocked {
				t.Errorf("disposition = %s", d.Disposition)
			}
		})
	}
}

func TestEvaluate_Failed(t *testing.T) { // PIP-2
	d := run(t, eff(obligation("verify", true)), evid(exec("verify", func(x *forge.JobExecution) { x.Conclusion = forge.ConclusionFailure })))
	wantObl(t, d, gate.Blocked, gate.ReasonFailed)
}

func TestEvaluate_Missing(t *testing.T) { // PIP-2
	d := run(t, eff(obligation("verify", true)), evid())
	wantObl(t, d, gate.Blocked, gate.ReasonMissing)
	if d.Disposition != gate.Blocked {
		t.Fatalf("disposition = %s", d.Disposition)
	}
}

func TestEvaluate_SupersededSuccessThenNewerAttempt(t *testing.T) { // SEC-11, PIP-2
	t.Parallel()
	first := exec("verify", func(x *forge.JobExecution) { x.SupersededBy = "attempt:2" })
	tests := []struct {
		name  string
		newer func(*forge.JobExecution)
		disp  gate.Disposition
		why   gate.Reason
	}{
		{"failed", func(x *forge.JobExecution) { x.Conclusion = forge.ConclusionFailure }, gate.Blocked, gate.ReasonFailed},
		{"pending", func(x *forge.JobExecution) {
			x.Conclusion = forge.ConclusionNone
			x.Completed = time.Time{}
		}, gate.Pending, gate.ReasonPending},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			newer := exec("verify", tc.newer, func(x *forge.JobExecution) { x.RunAttempt = "2" })
			d := run(t, eff(obligation("verify", true)), evid(first, newer))
			o := wantObl(t, d, tc.disp, tc.why)
			if o.RunAttempt != "2" {
				t.Errorf("attempt = %s", o.RunAttempt)
			}
		})
	}
}

func TestEvaluate_SupersededNewestAttemptNeverPasses(t *testing.T) { // SEC-11
	// The newer attempt is not in the snapshot: the lone superseded success must not pass.
	d := run(t, eff(obligation("verify", true)), evid(exec("verify", func(x *forge.JobExecution) { x.SupersededBy = "attempt:2" })))
	wantObl(t, d, gate.Blocked, gate.ReasonIncomplete)
}

func TestEvaluate_PartialRerun(t *testing.T) { // PIP-2
	e := eff(obligation("test (a)", true), obligation("test (b)", true))
	legA := exec("test (a)")
	legB1 := exec("test (b)", func(x *forge.JobExecution) { x.Conclusion = forge.ConclusionFailure; x.SupersededBy = "attempt:2" })
	legB2 := exec("test (b)", func(x *forge.JobExecution) {
		x.RunAttempt = "2"
		x.Conclusion = forge.ConclusionNone
		x.Completed = time.Time{}
	})
	d := run(t, e, evid(legA, legB1, legB2))
	if d.Disposition != gate.Pending {
		t.Fatalf("disposition = %s", d.Disposition)
	}
	if d.Obligations[0].Gate.CheckID != "test (a)" || d.Obligations[0].Disposition != gate.Pass {
		t.Errorf("leg a = %+v", d.Obligations[0])
	}
	if d.Obligations[1].Disposition != gate.Pending {
		t.Errorf("leg b = %+v", d.Obligations[1])
	}
	// Once the rerun leg succeeds the change passes.
	legB2.Conclusion, legB2.Completed = forge.ConclusionSuccess, t0.Add(time.Hour)
	if d = run(t, e, evid(legA, legB1, legB2)); d.Disposition != gate.Pass {
		t.Errorf("after rerun disposition = %s", d.Disposition)
	}
}

func TestEvaluate_Ambiguous(t *testing.T) { // PIP-2
	other := exec("verify", func(x *forge.JobExecution) { x.RunID = "run2"; x.JobID = "job-other" })
	d := run(t, eff(obligation("verify", true)), evid(exec("verify"), other))
	o := wantObl(t, d, gate.Blocked, gate.ReasonAmbiguous)
	if o.RunID != "" {
		t.Errorf("ambiguous result names a run: %+v", o)
	}
	// Two records of the same attempt are ambiguous too.
	dup := exec("verify", func(x *forge.JobExecution) { x.JobID = "dup" })
	wantObl(t, run(t, eff(obligation("verify", true)), evid(exec("verify"), dup)), gate.Blocked, gate.ReasonAmbiguous)
}

func TestEvaluate_StaleCandidateSHA(t *testing.T) { // SEC-11
	d := run(t, eff(obligation("verify", true)), evid(exec("verify", func(x *forge.JobExecution) { x.CandidateSHA = candB })))
	wantObl(t, d, gate.Blocked, gate.ReasonMissing, gate.ReasonStaleCandidate)
}

func TestEvaluate_WorkflowDispatchSameSHADoesNotCount(t *testing.T) { // SEC-11
	d := run(t, eff(obligation("verify", true)), evid(exec("verify", func(x *forge.JobExecution) { x.Event = "workflow_dispatch" })))
	wantObl(t, d, gate.Blocked, gate.ReasonMissing, gate.ReasonStaleCandidate)
	d = run(t, eff(obligation("verify", true)), evid(exec("verify", func(x *forge.JobExecution) { x.Event = "pull_request" })))
	wantObl(t, d, gate.Blocked, gate.ReasonMissing, gate.ReasonStaleCandidate)
}

func TestEvaluate_InRepoWorkflowAtCandidateIsUnpinned(t *testing.T) { // CON-4, SEC-11
	d := run(t, eff(obligation("verify", true)), evid(exec("verify", func(x *forge.JobExecution) {
		x.WorkflowRepo = "9999" // the candidate's own repo, not the registered workflow repo
		x.WorkflowCommit = candA
	})))
	wantObl(t, d, gate.Blocked, gate.ReasonMissing, gate.ReasonUnpinned)
}

func TestEvaluate_ReusableWorkflowAtOtherCommitIsUnpinned(t *testing.T) { // CON-4, SEC-11
	d := run(t, eff(obligation("verify", true)), evid(exec("verify", func(x *forge.JobExecution) {
		x.WorkflowCommit = "222222222222222222222222222222222222222b"
	})))
	wantObl(t, d, gate.Blocked, gate.ReasonMissing, gate.ReasonUnpinned)
	d = run(t, eff(obligation("verify", true)), evid(exec("verify", func(x *forge.JobExecution) { x.WorkflowPath = "other.yml" })))
	wantObl(t, d, gate.Blocked, gate.ReasonMissing, gate.ReasonUnpinned)
}

func TestEvaluate_IncompleteProvenance(t *testing.T) { // PIP-2, SEC-11
	d := run(t, eff(obligation("verify", true)), evid(exec("verify", func(x *forge.JobExecution) { x.Provenance = forge.ProvenanceIncomplete })))
	wantObl(t, d, gate.Blocked, gate.ReasonIncomplete)
	// An unparsable attempt number is not trusted either.
	d = run(t, eff(obligation("verify", true)), evid(exec("verify", func(x *forge.JobExecution) { x.RunAttempt = "x" })))
	wantObl(t, d, gate.Blocked, gate.ReasonIncomplete)
}

func TestEvaluate_ExecutionFromAnotherRepo(t *testing.T) { // SEC-11
	d := run(t, eff(obligation("verify", true)), evid(exec("verify", func(x *forge.JobExecution) { x.Repo = "evil/app" })))
	wantObl(t, d, gate.Blocked, gate.ReasonMissing)
	// The stray record can't be attributed, so the change as a whole errors.
	if d.Disposition != gate.Error || !slices.Contains(d.Reasons, gate.ReasonMalformedEvidence) {
		t.Errorf("change = %s %v", d.Disposition, d.Reasons)
	}
}

func TestEvaluate_IncompleteEvidenceIsError(t *testing.T) { // PIP-2
	d := run(t, eff(obligation("verify", true)), gate.Evidence{Executions: []forge.JobExecution{exec("verify")}})
	if d.Disposition != gate.Error {
		t.Fatalf("disposition = %s", d.Disposition)
	}
	wantObl(t, d, gate.Error, gate.ReasonIncompleteEvidence)
	if diff := cmp.Diff([]gate.Reason{gate.ReasonIncompleteEvidence}, d.Reasons); diff != "" {
		t.Error(diff)
	}
	// Error wins over a conflict, and an advisory-only contract still errors.
	e := eff(obligation("verify", false))
	e.Conflicts = []contract.Conflict{{Stage: "verify"}}
	if d = run(t, e, gate.Evidence{}); d.Disposition != gate.Error {
		t.Errorf("disposition = %s", d.Disposition)
	}
}

func TestEvaluate_ConflictsBlock(t *testing.T) { // CON-4
	e := eff(obligation("verify", true))
	e.Conflicts = []contract.Conflict{{Stage: "verify"}}
	d := run(t, e, evid(exec("verify")))
	if d.Disposition != gate.Blocked {
		t.Fatalf("disposition = %s", d.Disposition)
	}
	if diff := cmp.Diff([]gate.Reason{gate.ReasonConflict}, d.Reasons); diff != "" {
		t.Error(diff)
	}
	wantObl(t, d, gate.Pass, gate.ReasonNone)
}

func TestEvaluate_AdvisoryFailureStillPasses(t *testing.T) { // PIP-2
	e := eff(obligation("lint", false), obligation("verify", true))
	d := run(t, e, evid(exec("verify"), exec("lint", func(x *forge.JobExecution) { x.Conclusion = forge.ConclusionFailure })))
	if d.Disposition != gate.Pass {
		t.Fatalf("disposition = %s", d.Disposition)
	}
	if o := d.Obligations[0]; o.Mandatory || o.Disposition != gate.Blocked || o.Reason != gate.ReasonFailed {
		t.Errorf("advisory result = %+v", o)
	}
	// With no mandatory gate at all, nothing is proven and the change blocks.
	d = run(t, eff(obligation("lint", false)), evid(exec("lint")))
	if d.Disposition != gate.Blocked || !slices.Contains(d.Reasons, gate.ReasonNoMandatoryGates) {
		t.Errorf("no mandatory gates: %s %v", d.Disposition, d.Reasons)
	}
}

func TestEvaluate_Severity(t *testing.T) { // PIP-2
	e := eff(obligation("a", true), obligation("b", true))
	pending := exec("a", func(x *forge.JobExecution) { x.Conclusion = forge.ConclusionNone; x.Completed = time.Time{} })
	if d := run(t, e, evid(pending)); d.Disposition != gate.Blocked { // b is missing
		t.Errorf("pending+missing = %s", d.Disposition)
	}
	if d := run(t, e, evid(pending, exec("b"))); d.Disposition != gate.Pending {
		t.Errorf("pending+pass = %s", d.Disposition)
	}
}

func TestEvaluate_Deterministic(t *testing.T) { // PIP-2
	e := eff(obligation("c", true), obligation("a", true), obligation("b", false))
	execs := []forge.JobExecution{
		exec("a"), exec("b"), exec("c"),
		exec("c", func(x *forge.JobExecution) {
			x.RunID = "run2"
			x.RunAttempt = "2"
			x.Conclusion = forge.ConclusionFailure
		}),
		exec("a", func(x *forge.JobExecution) { x.ProducerAppID = otherProd }),
		exec("b", func(x *forge.JobExecution) { x.CandidateSHA = candB }),
	}
	want := run(t, e, evid(execs...))
	rng := rand.New(rand.NewPCG(1, 2))
	for range 50 {
		shuffled := append([]forge.JobExecution(nil), execs...)
		rng.Shuffle(len(shuffled), func(i, j int) { shuffled[i], shuffled[j] = shuffled[j], shuffled[i] })
		gates := append([]contract.Obligation(nil), e.VerifyGates...)
		rng.Shuffle(len(gates), func(i, j int) { gates[i], gates[j] = gates[j], gates[i] })
		e2 := *e
		e2.VerifyGates = gates
		if diff := cmp.Diff(want, run(t, &e2, evid(shuffled...))); diff != "" {
			t.Fatalf("decision changed with input order (-want +got):\n%s", diff)
		}
	}
}

func TestEvaluate_QueueTipDoesNotSatisfyOtherCandidate(t *testing.T) { // SEC-11, PIP-2
	// A and B are queued. B's candidate contains A, and its pass must not pass A.
	e := eff(obligation("verify", true))
	passForB := exec("verify", func(x *forge.JobExecution) { x.CandidateSHA = candB })
	targetA := gate.Target{Forge: "github", Repo: repo, PR: 1, CandidateSHA: candA}
	d := gate.Evaluate(e, targetA, evid(passForB))
	if d.Disposition != gate.Blocked {
		t.Fatalf("disposition = %s", d.Disposition)
	}
	wantObl(t, d, gate.Blocked, gate.ReasonMissing, gate.ReasonStaleCandidate)
	targetB := gate.Target{Forge: "github", Repo: repo, PR: 2, CandidateSHA: candB}
	if d = gate.Evaluate(e, targetB, evid(passForB)); d.Disposition != gate.Pass {
		t.Errorf("B disposition = %s", d.Disposition)
	}
}

func TestEvaluate_DoesNotMutateInputs(t *testing.T) { // PIP-2
	e := eff(obligation("b", true), obligation("a", true))
	run(t, e, evid())
	if e.VerifyGates[0].Gate.CheckID != "b" {
		t.Error("VerifyGates reordered in place")
	}
}
