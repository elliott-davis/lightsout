// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

package gate_test

import (
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/elliott-davis/lightsout/internal/contract"
	"github.com/elliott-davis/lightsout/internal/forge"
	"github.com/elliott-davis/lightsout/internal/forge/fake"
	"github.com/elliott-davis/lightsout/internal/gate"
)

func running(x *forge.JobExecution) {
	x.Conclusion = forge.ConclusionNone
	x.Completed = time.Time{}
}

func attempt(n string, mod ...func(*forge.JobExecution)) func(*forge.JobExecution) {
	return func(x *forge.JobExecution) {
		x.RunAttempt = n
		for _, m := range mod {
			m(x)
		}
	}
}

func TestEvaluate_TwoRunsAtDifferentAttemptsAreAmbiguous(t *testing.T) { // PIP-2
	t.Parallel()
	a := exec("verify")
	b := exec("verify", func(x *forge.JobExecution) { x.RunID, x.JobID, x.RunAttempt = "run2", "j2", "2" })
	d := run(t, eff(obligation("verify", true)), evid(a, b))
	wantObl(t, d, gate.Blocked, gate.ReasonAmbiguous)
}

func TestEvaluate_AttemptsCompareNumerically(t *testing.T) { // PIP-2
	t.Parallel()
	nine := exec("verify", attempt("9"))
	ten := exec("verify", attempt("10", func(x *forge.JobExecution) { x.Conclusion = forge.ConclusionFailure }))
	d := run(t, eff(obligation("verify", true)), evid(nine, ten))
	o := wantObl(t, d, gate.Blocked, gate.ReasonFailed)
	if o.RunAttempt != "10" {
		t.Errorf("attempt = %q", o.RunAttempt)
	}
}

func TestEvaluate_WorkflowRepoOnlyIsUnpinned(t *testing.T) { // CON-4, SEC-11
	t.Parallel()
	d := run(t, eff(obligation("verify", true)), evid(exec("verify", func(x *forge.JobExecution) { x.WorkflowRepo = "7777" })))
	wantObl(t, d, gate.Blocked, gate.ReasonMissing, gate.ReasonUnpinned)
}

func TestEvaluate_NearMissEvidence(t *testing.T) { // SEC-11
	t.Parallel()
	foreign := exec("verify", func(x *forge.JobExecution) { x.ProducerAppID = otherProd })
	unpinned := exec("verify", func(x *forge.JobExecution) { x.RunID = "r2"; x.WorkflowCommit = strings.Repeat("2", 40) })
	stale := exec("verify", func(x *forge.JobExecution) { x.RunID = "r3"; x.CandidateSHA = candB })
	e := eff(obligation("verify", true))
	wantObl(t, run(t, e, evid(foreign, stale)), gate.Blocked, gate.ReasonMissing, gate.ReasonForeign)
	wantObl(t, run(t, e, evid(unpinned, stale)), gate.Blocked, gate.ReasonMissing, gate.ReasonUnpinned)
	wantObl(t, run(t, e, evid(foreign, unpinned)), gate.Blocked, gate.ReasonMissing, gate.ReasonForeign, gate.ReasonUnpinned)
	wantObl(t, run(t, e, evid(stale)), gate.Blocked, gate.ReasonMissing, gate.ReasonStaleCandidate)
}

func TestEvaluate_CopiesTargetAndObligationFields(t *testing.T) { // PIP-2
	t.Parallel()
	o := obligation("verify", true)
	o.Sources = []string{"a.json", "b.json"}
	e := eff(o)
	d := run(t, e, evid(exec("verify")))
	if d.PR != 7 || d.HeadSHA != "head" || d.Repo != repo || d.Forge != "github" {
		t.Errorf("target = %+v", d.Target)
	}
	got := d.Obligations[0]
	if got.Name != "verify" || got.Gate != gateRef("verify") {
		t.Errorf("result = %+v", got)
	}
	got.Sources[0] = "mutated"
	if e.VerifyGates[0].Sources[0] != "a.json" {
		t.Error("Sources shares memory with the contract")
	}
}

func TestEvaluate_FactoryOwnedFailureBlocks(t *testing.T) { // CON-5, PIP-2
	t.Parallel()
	o := obligation("secret-scan", true)
	o.Owner = contract.OwnerFactory
	d := run(t, eff(o), evid(exec("secret-scan", func(x *forge.JobExecution) { x.Conclusion = forge.ConclusionFailure })))
	got := wantObl(t, d, gate.Blocked, gate.ReasonFailed)
	if got.Owner != contract.OwnerFactory {
		t.Errorf("owner = %q", got.Owner)
	}
}

func TestEvaluate_EjectedCandidateHasNoEvidence(t *testing.T) { // PIP-2, SEC-11
	t.Parallel()
	// B was ejected and requeued as a new candidate: nothing ran on it yet.
	e := eff(obligation("verify", true))
	d := gate.Evaluate(e, gate.Target{Forge: "github", Repo: repo, CandidateSHA: strings.Repeat("c", 40)}, evid(exec("verify")))
	wantObl(t, d, gate.Blocked, gate.ReasonMissing, gate.ReasonStaleCandidate)
}

func TestEvaluate_RunningWithIncompleteProvenanceIsPending(t *testing.T) { // PIP-2
	t.Parallel()
	d := run(t, eff(obligation("verify", true)), evid(exec("verify", running, func(x *forge.JobExecution) { x.Provenance = forge.ProvenanceIncomplete })))
	wantObl(t, d, gate.Pending, gate.ReasonPending)
}

func TestEvaluate_CompletedWithIncompleteProvenanceBlocks(t *testing.T) { // PIP-2, SEC-11
	t.Parallel()
	for _, c := range []forge.CheckConclusion{forge.ConclusionFailure, forge.ConclusionSuccess, forge.ConclusionSkipped} {
		d := run(t, eff(obligation("verify", true)), evid(exec("verify", func(x *forge.JobExecution) {
			x.Provenance = forge.ProvenanceIncomplete
			x.Conclusion = c
		})))
		wantObl(t, d, gate.Blocked, gate.ReasonIncomplete)
	}
}

func TestEvaluate_SharedJobKeyPartialRerunIsAmbiguous(t *testing.T) { // PIP-2
	t.Parallel()
	a := exec("verify", func(x *forge.JobExecution) { x.JobID = "legA" })
	b := exec("verify", func(x *forge.JobExecution) { x.JobID = "legB"; x.Conclusion = forge.ConclusionFailure })
	rerun := exec("verify", attempt("2"), func(x *forge.JobExecution) { x.JobID = "legB2" })
	d := run(t, eff(obligation("verify", true)), evid(a, b, rerun))
	wantObl(t, d, gate.Blocked, gate.ReasonAmbiguous)
}

// untrustedRecords are records that must never be ignored: a hidden newer attempt or missing identity.
func untrustedRecords() map[string]func(*forge.JobExecution) {
	failed := func(x *forge.JobExecution) { x.Conclusion = forge.ConclusionFailure }
	bad := func(n string) func(*forge.JobExecution) {
		return func(x *forge.JobExecution) { failed(x); x.RunAttempt = n }
	}
	blank := func(f func(*forge.JobExecution)) func(*forge.JobExecution) {
		return func(x *forge.JobExecution) { failed(x); x.RunAttempt = "2"; f(x) }
	}
	return map[string]func(*forge.JobExecution){
		"empty attempt":      bad(""),
		"zero attempt":       bad("0"),
		"plus attempt":       bad("+2"),
		"padded attempt":     bad("02"),
		"negative attempt":   bad("-3"),
		"fractional attempt": bad("2.0"),
		"spaced attempt":     bad(" 2"),
		"overflow attempt":   bad("99999999999999999999"),
		"ten digit attempt":  bad("9999999999"),
		"no producer":        blank(func(x *forge.JobExecution) { x.ProducerAppID = "" }),
		"no workflow repo":   blank(func(x *forge.JobExecution) { x.WorkflowRepo = "" }),
		"no workflow path":   blank(func(x *forge.JobExecution) { x.WorkflowPath = "" }),
		"no workflow commit": blank(func(x *forge.JobExecution) { x.WorkflowCommit = "" }),
		"no event":           blank(func(x *forge.JobExecution) { x.Event = "" }),
		"no candidate":       blank(func(x *forge.JobExecution) { x.CandidateSHA = "" }),
		"slash in repo id":   blank(func(x *forge.JobExecution) { x.WorkflowRepo = "acme/gates" }),
		"incomplete failure": blank(func(x *forge.JobExecution) { x.Provenance = forge.ProvenanceIncomplete }),
	}
}

func TestEvaluate_UntrustedRecordBlocksOlderSuccess(t *testing.T) { // PIP-2, SEC-11
	t.Parallel()
	for name, m := range untrustedRecords() {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			hidden := exec("verify", m, func(x *forge.JobExecution) { x.JobID = "hidden" })
			d := run(t, eff(obligation("verify", true)), evid(exec("verify"), hidden))
			wantObl(t, d, gate.Blocked, gate.ReasonIncomplete)
		})
	}
}

func TestEvaluate_ForeignCompleteRecordCannotBlockOrSupersede(t *testing.T) { // SEC-11
	t.Parallel()
	foreign := exec("verify", attempt("5", func(x *forge.JobExecution) {
		x.ProducerAppID = otherProd
		x.Conclusion = forge.ConclusionFailure
	}))
	wantObl(t, run(t, eff(obligation("verify", true)), evid(exec("verify"), foreign)), gate.Pass, gate.ReasonNone)
}

// fakeEvidence stores recs in a fresh fake forge, lists them back and returns the target and evidence.
func fakeEvidence(t *testing.T, recs ...forge.JobExecution) (gate.Target, gate.Evidence) {
	t.Helper()
	ctx := t.Context()
	f := fake.New(func() time.Time { return t0 })
	rid, err := f.AddRepo(ctx, "app", false)
	if err != nil {
		t.Fatalf("AddRepo: %v", err)
	}
	sha, err := f.CommitTree(ctx, rid, nil, "candidate", nil)
	if err != nil {
		t.Fatalf("CommitTree: %v", err)
	}
	for i := range recs {
		r := recs[i]
		r.Repo, r.CandidateSHA = rid, sha
		if err = f.AddJobExecution(ctx, r); err != nil {
			t.Fatalf("AddJobExecution: %v", err)
		}
	}
	listed, err := f.ListJobExecutions(ctx, rid, sha)
	if err != nil {
		t.Fatalf("ListJobExecutions: %v", err)
	}
	return gate.Target{Forge: "github", Repo: rid, PR: 1, CandidateSHA: sha}, gate.Evidence{Executions: listed, Complete: true}
}

func TestEvaluate_UntrustedRecordsThroughFakeForge(t *testing.T) { // PIP-2, SEC-11
	t.Parallel()
	e := eff(obligation("verify", true))
	check := func(name string, wantDisp gate.Disposition, wantReason gate.Reason, recs ...forge.JobExecution) {
		t.Helper()
		tg, ev := fakeEvidence(t, recs...)
		d := gate.Evaluate(e, tg, ev)
		if d.Disposition != wantDisp || d.Obligations[0].Reason != wantReason {
			t.Errorf("%s: %s/%q, want %s/%q", name, d.Disposition, d.Obligations[0].Reason, wantDisp, wantReason)
		}
	}
	good := exec("verify")
	failed := func(x *forge.JobExecution) { x.Conclusion = forge.ConclusionFailure; x.JobID = "hidden" }
	check("clean pass", gate.Pass, gate.ReasonNone, good)
	for _, n := range []string{"", "0", "x", " 2", "2.0", "-3"} {
		check("incomplete attempt "+n, gate.Blocked, gate.ReasonIncomplete, good,
			exec("verify", failed, func(x *forge.JobExecution) { x.RunAttempt = n; x.Provenance = forge.ProvenanceIncomplete }))
	}
	// The fake accepts these as complete, since strconv parses them, but the gate does not.
	for _, n := range []string{"+2", "02", "9999999999"} {
		check("complete attempt "+n, gate.Blocked, gate.ReasonIncomplete, good, exec("verify", failed, attempt(n)))
	}
	check("missing field", gate.Blocked, gate.ReasonIncomplete, good,
		exec("verify", failed, attempt("2"), func(x *forge.JobExecution) { x.Event = ""; x.Provenance = forge.ProvenanceIncomplete }))
	check("superseded success", gate.Blocked, gate.ReasonFailed, good, exec("verify", failed, attempt("2")))
}

func TestEvaluate_UnattributableRecords(t *testing.T) { // PIP-2, SEC-11
	t.Parallel()
	e := eff(obligation("verify", true))
	noKey := func(x *forge.JobExecution) {
		x.JobKey = ""
		x.JobID = "hidden"
		x.Provenance = forge.ProvenanceIncomplete
	}
	failed := func(x *forge.JobExecution) { x.Conclusion = forge.ConclusionFailure }
	tests := []struct {
		name string
		mod  []func(*forge.JobExecution)
		want gate.Disposition
		why  gate.Reason
		// viaFake also runs the case through the fake forge, which accepts these records.
		viaFake bool
	}{
		{"empty job key, failed", []func(*forge.JobExecution){noKey, failed, attempt("2")}, gate.Error, gate.ReasonMalformedEvidence, true},
		{"empty job key, running", []func(*forge.JobExecution){noKey, running, attempt("2")}, gate.Pending, gate.ReasonUnattributedRun, true},
		{"empty run id", []func(*forge.JobExecution){func(x *forge.JobExecution) { x.RunID = "" }, failed}, gate.Error, gate.ReasonMalformedEvidence, false},
		{"empty job id", []func(*forge.JobExecution){func(x *forge.JobExecution) { x.JobID = "" }, failed}, gate.Error, gate.ReasonMalformedEvidence, false},
		{"empty repo", []func(*forge.JobExecution){func(x *forge.JobExecution) { x.Repo = "" }, failed}, gate.Error, gate.ReasonMalformedEvidence, false},
		{"other repo", []func(*forge.JobExecution){func(x *forge.JobExecution) { x.Repo = "evil/app" }, failed}, gate.Error, gate.ReasonMalformedEvidence, false},
		{"other repo, running", []func(*forge.JobExecution){func(x *forge.JobExecution) { x.Repo = "evil/app" }, running}, gate.Pending, gate.ReasonUnattributedRun, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			d := run(t, e, evid(exec("verify"), exec("verify", tc.mod...)))
			if d.Disposition != tc.want || !slices.Contains(d.Reasons, tc.why) {
				t.Errorf("got %s %v, want %s with %q", d.Disposition, d.Reasons, tc.want, tc.why)
			}
		})
	}
	t.Run("through the fake forge", func(t *testing.T) {
		t.Parallel()
		for _, tc := range tests {
			if !tc.viaFake {
				continue
			}
			tg, ev := fakeEvidence(t, exec("verify"), exec("verify", tc.mod...))
			d := gate.Evaluate(e, tg, ev)
			if d.Disposition != tc.want || !slices.Contains(d.Reasons, tc.why) {
				t.Errorf("%s: got %s %v", tc.name, d.Disposition, d.Reasons)
			}
		}
	})
}

// TestEvaluate_RenamedNewerAttemptIsNotInferred pins current behaviour. A newer attempt under a different, non-empty
// JobKey is indistinguishable from a sibling job here. The WI-12 adapter must mark SupersededBy on every job of an
// older attempt that a newer attempt re-ran, and registered gate jobs must have static rendered names.
func TestEvaluate_RenamedNewerAttemptIsNotInferred(t *testing.T) { // PIP-2
	t.Parallel()
	renamed := exec("verify-renamed", attempt("2", func(x *forge.JobExecution) { x.Conclusion = forge.ConclusionFailure }))
	d := run(t, eff(obligation("verify", true)), evid(exec("verify"), renamed))
	wantObl(t, d, gate.Pass, gate.ReasonNone)
}

func TestEvaluate_RunningRecordsShadowOlderSuccess(t *testing.T) { // PIP-2, SEC-11
	t.Parallel()
	unvouched := func(m func(*forge.JobExecution)) forge.JobExecution {
		return exec("verify", attempt("2"), running, func(x *forge.JobExecution) { x.Provenance = forge.ProvenanceIncomplete }, m)
	}
	tests := map[string]func(*forge.JobExecution){
		"empty workflow commit": func(x *forge.JobExecution) { x.WorkflowCommit = "" },
		"empty workflow path":   func(x *forge.JobExecution) { x.WorkflowPath = "" },
		"other producer":        func(x *forge.JobExecution) { x.ProducerAppID = otherProd },
		"empty producer":        func(x *forge.JobExecution) { x.ProducerAppID = "" },
		"bad attempt":           func(x *forge.JobExecution) { x.RunAttempt = "x" },
		"empty attempt":         func(x *forge.JobExecution) { x.RunAttempt = "" },
	}
	for name, m := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			d := run(t, eff(obligation("verify", true)), evid(exec("verify"), unvouched(m)))
			wantObl(t, d, gate.Pending, gate.ReasonPending)
		})
	}
}

func TestEvaluate_ForeignRecordAttribution(t *testing.T) { // SEC-11
	t.Parallel()
	e := eff(obligation("verify", true))
	// A complete foreign record that is still running is excluded, so the real success stands.
	foreignRunning := exec("verify", attempt("2"), running, func(x *forge.JobExecution) { x.ProducerAppID = otherProd })
	wantObl(t, run(t, e, evid(exec("verify"), foreignRunning)), gate.Pass, gate.ReasonNone)
	// A completed foreign record without full provenance is not vouched for, so it blocks.
	foreignIncomplete := exec("verify", attempt("2"), func(x *forge.JobExecution) {
		x.ProducerAppID = otherProd
		x.Provenance = forge.ProvenanceIncomplete
	})
	wantObl(t, run(t, e, evid(exec("verify"), foreignIncomplete)), gate.Blocked, gate.ReasonIncomplete)
}

func TestEvaluate_DuplicateRecordsAreOne(t *testing.T) { // PIP-2
	t.Parallel()
	d := run(t, eff(obligation("verify", true)), evid(exec("verify"), exec("verify")))
	wantObl(t, d, gate.Pass, gate.ReasonNone)
}

func TestEvaluate_UntrustedBeatsAmbiguous(t *testing.T) { // PIP-2
	t.Parallel()
	e := eff(obligation("verify", true))
	twin := exec("verify", func(x *forge.JobExecution) { x.JobID = "twin" })
	bad := exec("verify", attempt("0"), func(x *forge.JobExecution) { x.RunID = "run9"; x.JobID = "j9" })
	wantObl(t, run(t, e, evid(exec("verify"), twin, bad)), gate.Blocked, gate.ReasonIncomplete)
	// Without the bad record it is ambiguous.
	wantObl(t, run(t, e, evid(exec("verify"), twin)), gate.Blocked, gate.ReasonAmbiguous)
}

func TestEvaluate_SupersededRunningIsIncomplete(t *testing.T) { // PIP-2
	t.Parallel()
	d := run(t, eff(obligation("verify", true)), evid(exec("verify", running, func(x *forge.JobExecution) { x.SupersededBy = "attempt:3" })))
	wantObl(t, d, gate.Blocked, gate.ReasonIncomplete)
}

func TestEvaluate_InstantJobPasses(t *testing.T) { // PIP-2
	t.Parallel()
	d := run(t, eff(obligation("verify", true)), evid(exec("verify", func(x *forge.JobExecution) { x.Completed = x.Started })))
	wantObl(t, d, gate.Pass, gate.ReasonNone)
}

func TestEvaluate_AdvisoryGateFieldsAreNotValidated(t *testing.T) { // PIP-2
	t.Parallel()
	adv := obligation("lint", false)
	adv.Gate.CheckID = ""
	d := run(t, eff(obligation("verify", true), adv), evid(exec("verify")))
	if d.Disposition != gate.Pass || slices.Contains(d.Reasons, gate.ReasonInvalidInput) {
		t.Fatalf("change = %s %v", d.Disposition, d.Reasons)
	}
	if o := d.Obligations[0]; o.Gate.CheckID != "" || o.Disposition != gate.Blocked || o.Reason != gate.ReasonMissing {
		t.Errorf("advisory = %+v", o)
	}
}

func TestEvaluate_InvalidInputIsError(t *testing.T) { // SEC-1
	t.Parallel()
	good := func() *contract.Effective { return eff(obligation("verify", true)) }
	tests := map[string]func(*contract.Effective, *gate.Target) *contract.Effective{
		"nil contract":      func(*contract.Effective, *gate.Target) *contract.Effective { return nil },
		"empty revision":    func(e *contract.Effective, _ *gate.Target) *contract.Effective { e.Revision = ""; return e },
		"empty install rev": func(e *contract.Effective, _ *gate.Target) *contract.Effective { e.InstallRevision = ""; return e },
		"empty repo":        func(e *contract.Effective, g *gate.Target) *contract.Effective { g.Repo = ""; return e },
		"empty forge":       func(e *contract.Effective, g *gate.Target) *contract.Effective { g.Forge = ""; return e },
		"empty candidate":   func(e *contract.Effective, g *gate.Target) *contract.Effective { g.CandidateSHA = ""; return e },
		"short candidate":   func(e *contract.Effective, g *gate.Target) *contract.Effective { g.CandidateSHA = "abc123"; return e },
		"upper candidate": func(e *contract.Effective, g *gate.Target) *contract.Effective {
			g.CandidateSHA = strings.ToUpper(candA)
			return e
		},
		"empty producer": func(e *contract.Effective, _ *gate.Target) *contract.Effective {
			e.VerifyGates[0].Gate.ProducerID = ""
			return e
		},
		"empty workflow": func(e *contract.Effective, _ *gate.Target) *contract.Effective {
			e.VerifyGates[0].Gate.WorkflowID = ""
			return e
		},
		"empty pin": func(e *contract.Effective, _ *gate.Target) *contract.Effective {
			e.VerifyGates[0].Gate.WorkflowRevision = ""
			return e
		},
		"empty check": func(e *contract.Effective, _ *gate.Target) *contract.Effective {
			e.VerifyGates[0].Gate.CheckID = ""
			return e
		},
	}
	for name, mut := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			tg := target()
			e := mut(good(), &tg)
			d := gate.Evaluate(e, tg, evid(exec("verify")))
			if d.Disposition != gate.Error || !cmp.Equal(d.Reasons, []gate.Reason{gate.ReasonInvalidInput}) {
				t.Errorf("got %s %v", d.Disposition, d.Reasons)
			}
		})
	}
}

func TestEvaluate_SHA256CandidateAccepted(t *testing.T) { // PIP-2
	t.Parallel()
	sha := strings.Repeat("d", 64)
	d := gate.Evaluate(eff(obligation("verify", true)), gate.Target{Forge: "github", Repo: repo, CandidateSHA: sha},
		evid(exec("verify", func(x *forge.JobExecution) { x.CandidateSHA = sha })))
	if d.Disposition != gate.Pass {
		t.Errorf("disposition = %s", d.Disposition)
	}
}

// TestEvaluate_RealContractEndToEnd parses, compiles and resolves a real contract, then evaluates the canonical
// identity forms against it (CON-4).
func TestEvaluate_RealContractEndToEnd(t *testing.T) { // CON-4, PIP-2
	t.Parallel()
	const (
		prod = "github-app:15368"
		wfID = "4242/.github/workflows/verify.yml"
	)
	yaml := "apiVersion: factory/v1alpha1\nkind: Contract\npaths:\n  writable: ['**']\ngates:\n  verify:\n" +
		"    - name: build\n      producerId: " + prod + "\n      workflowId: " + wfID + "\n      workflowRevision: " + pin +
		"\n      checkId: build\n      mandatory: true\n"
	parser, err := contract.NewParser()
	if err != nil {
		t.Fatal(err)
	}
	c, err := parser.Parse("", []byte(yaml))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	set, err := contract.NewSet(pin, c)
	if err != nil {
		t.Fatal(err)
	}
	baseGate := func(check string) contract.Gate {
		return contract.Gate{Name: check, GateRef: contract.GateRef{
			ProducerID: prod, WorkflowID: contract.WorkflowID(wfID), WorkflowRevision: pin, CheckID: check,
		}, Mandatory: true}
	}
	policy, err := contract.Compile(set, contract.Baseline{
		Verify:           []contract.Gate{baseGate("secret-scan")},
		Union:            []contract.Gate{baseGate("smoke")},
		Reviewers:        []string{"pr-reviewer", "security-reviewer"},
		SecurityReviewer: "security-reviewer",
		PRReviewer:       "pr-reviewer",
		InstallRevision:  strings.Repeat("c", 40),
	}, contract.Defaults{SwitchStaleDays: 45, SwitchAbandonedDays: 90, ReviewBudgetLines: 400})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	eff, err := policy.Resolve([]string{"src/main.go"})
	if err != nil {
		t.Fatal(err)
	}
	good := exec
	pass := gate.Evaluate(eff, target(), evid(good("build"), good("secret-scan")))
	if pass.Disposition != gate.Pass || len(pass.Obligations) != 2 {
		t.Fatalf("canonical forms: %s, %d obligations: %+v", pass.Disposition, len(pass.Obligations), pass.Obligations)
	}
	nearMiss := map[string]func(*forge.JobExecution){
		"producer":        func(x *forge.JobExecution) { x.ProducerAppID = "15369" },
		"workflow repo":   func(x *forge.JobExecution) { x.WorkflowRepo = "4243" },
		"workflow path":   func(x *forge.JobExecution) { x.WorkflowPath = ".github/workflows/verify.yaml" },
		"workflow commit": func(x *forge.JobExecution) { x.WorkflowCommit = strings.Repeat("1", 39) + "2" },
		"job key":         func(x *forge.JobExecution) { x.JobKey = "build2" },
		"candidate":       func(x *forge.JobExecution) { x.CandidateSHA = candB },
		"event":           func(x *forge.JobExecution) { x.Event = "push" },
		"repo":            func(x *forge.JobExecution) { x.Repo = "acme/other" },
	}
	for name, m := range nearMiss {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			d := gate.Evaluate(eff, target(), evid(good("build", m), good("secret-scan")))
			want := gate.Blocked
			if name == "repo" {
				want = gate.Error // a record of another repo is malformed evidence for the whole change
			}
			if d.Disposition != want {
				t.Fatalf("disposition = %s, want %s", d.Disposition, want)
			}
			for _, o := range d.Obligations {
				if o.Gate.CheckID == "build" && o.Disposition != gate.Blocked {
					t.Errorf("build = %s", o.Disposition)
				}
			}
		})
	}
	// The factory-owned baseline gate keeps its owner.
	for _, o := range pass.Obligations {
		if o.Gate.CheckID == "secret-scan" && o.Owner != contract.OwnerFactory {
			t.Errorf("owner = %q", o.Owner)
		}
	}
}

func TestEvaluate_UnvouchedRunningLiveness(t *testing.T) { // PIP-2
	t.Parallel()
	e := eff(obligation("verify", true))
	unvouched := func(run string, mod ...func(*forge.JobExecution)) forge.JobExecution {
		return exec("verify", append([]func(*forge.JobExecution){
			running,
			func(x *forge.JobExecution) {
				x.RunID, x.JobID, x.Provenance = run, "j-"+run, forge.ProvenanceIncomplete
			},
		}, mod...)...)
	}
	// A: a complete success in run1 and an unvouched running record in run2.
	a := run(t, e, evid(exec("verify"), unvouched("run2")))
	wantObl(t, a, gate.Pending, gate.ReasonPending)
	// ... and once run2 completes as unpinned, run1's success stands.
	done := exec("verify", func(x *forge.JobExecution) {
		x.RunID, x.JobID, x.WorkflowCommit = "run2", "j-run2", strings.Repeat("3", 40)
	})
	wantObl(t, run(t, e, evid(exec("verify"), done)), gate.Pass, gate.ReasonNone)
	// A block stays a block.
	failed := exec("verify", func(x *forge.JobExecution) { x.Conclusion = forge.ConclusionFailure })
	wantObl(t, run(t, e, evid(failed, unvouched("run2"))), gate.Blocked, gate.ReasonFailed)
	// B: both runs running and unvouched.
	wantObl(t, run(t, e, evid(unvouched("run1"), unvouched("run2"))), gate.Pending, gate.ReasonPending)
	// Two vouched matches are still ambiguous.
	other := exec("verify", func(x *forge.JobExecution) { x.RunID, x.JobID = "run3", "j3" })
	wantObl(t, run(t, e, evid(exec("verify"), other, unvouched("run2"))), gate.Blocked, gate.ReasonAmbiguous)
	// Two records in one attempt are ambiguous even when they're unvouched and running.
	twin := unvouched("run2", func(x *forge.JobExecution) { x.JobID = "twin" })
	wantObl(t, run(t, e, evid(unvouched("run2"), twin)), gate.Blocked, gate.ReasonAmbiguous)
}

// An unvouched running twin in the same attempt never exempts that attempt from the ambiguity rule, so it can't
// hide a vouched failure or a second leg, in either input order.
func TestEvaluate_UnvouchedTwinNeverMasksAmbiguity(t *testing.T) { // PIP-2, SEC-11
	t.Parallel()
	e := eff(obligation("verify", true))
	twin := func(producer string) forge.JobExecution {
		return exec("verify", func(x *forge.JobExecution) {
			x.JobID, x.Conclusion, x.Provenance = "twin", forge.ConclusionNone, forge.ProvenanceIncomplete
			if producer != "" {
				x.ProducerAppID = producer
			}
		})
	}
	failure := exec("verify", func(x *forge.JobExecution) { x.JobID, x.Conclusion = "j2", forge.ConclusionFailure })
	leg := exec("verify", func(x *forge.JobExecution) { x.JobID = "leg2" })
	unpinned := exec("verify", func(x *forge.JobExecution) {
		x.JobID, x.Conclusion, x.WorkflowCommit = "j3", forge.ConclusionFailure, strings.Repeat("e", 40)
	})
	attempt2 := func(x *forge.JobExecution) { x.RunAttempt = "2" }
	cases := map[string][]forge.JobExecution{
		"success and twin":                   {exec("verify"), twin("")},
		"success, failure and twin":          {exec("verify"), failure, twin("")},
		"success, unpinned failure and twin": {exec("verify"), unpinned, twin("")},
		"two leg successes and twin":         {exec("verify"), leg, twin("")},
		"success and foreign twin":           {exec("verify"), twin("999")},
		"attempt-2 success and twin":         {exec("verify", attempt2), func() forge.JobExecution { x := twin(""); attempt2(&x); return x }()},
	}
	for name, recs := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			for _, order := range [][]forge.JobExecution{recs, reversed(recs)} {
				d := run(t, e, evid(order...))
				if d.Disposition == gate.Pass {
					t.Fatalf("Disposition = pass for %v, want a block", order)
				}
				wantObl(t, d, gate.Blocked, gate.ReasonAmbiguous)
			}
		})
	}
}

func reversed(in []forge.JobExecution) []forge.JobExecution {
	out := slices.Clone(in)
	slices.Reverse(out)
	return out
}

func TestEvaluate_RunningRecordWithEmptyRunIDIsNotGrouped(t *testing.T) { // PIP-2
	t.Parallel()
	stray := exec("verify", running, func(x *forge.JobExecution) { x.RunID = "" })
	d := run(t, eff(obligation("verify", true)), evid(exec("verify"), stray))
	if d.Disposition != gate.Pending || !slices.Contains(d.Reasons, gate.ReasonUnattributedRun) {
		t.Fatalf("change = %s %v", d.Disposition, d.Reasons)
	}
	if o := d.Obligations[0]; o.Disposition != gate.Pass {
		t.Errorf("obligation = %s/%q", o.Disposition, o.Reason)
	}
}

func TestEvaluate_BlockedObligationBeatsUnattributedRunning(t *testing.T) { // PIP-2
	t.Parallel()
	failed := exec("verify", func(x *forge.JobExecution) { x.Conclusion = forge.ConclusionFailure })
	stray := exec("verify", attempt("2"), running, func(x *forge.JobExecution) { x.JobKey = ""; x.JobID = "x" })
	d := run(t, eff(obligation("verify", true)), evid(failed, stray))
	if d.Disposition != gate.Blocked || !slices.Contains(d.Reasons, gate.ReasonUnattributedRun) {
		t.Errorf("change = %s %v", d.Disposition, d.Reasons)
	}
}

func TestEvaluate_OlderUntrustedRecordsDoNotBlockForever(t *testing.T) { // PIP-2
	t.Parallel()
	e := eff(obligation("verify", true))
	oldIncomplete := exec("verify", func(x *forge.JobExecution) {
		x.Conclusion = forge.ConclusionFailure
		x.Provenance = forge.ProvenanceIncomplete
		x.JobID = "old"
	})
	newer := exec("verify", attempt("2"))
	wantObl(t, run(t, e, evid(oldIncomplete, newer)), gate.Pass, gate.ReasonNone)
	// Without the newer complete attempt it blocks.
	wantObl(t, run(t, e, evid(oldIncomplete)), gate.Blocked, gate.ReasonIncomplete)
	// An old running unvouched record is out too.
	oldRunning := exec("verify", running, func(x *forge.JobExecution) { x.Provenance = forge.ProvenanceIncomplete; x.JobID = "old" })
	wantObl(t, run(t, e, evid(oldRunning, newer)), gate.Pass, gate.ReasonNone)
	// A newer untrusted record still blocks, and so does one that can't be ordered.
	newerBad := exec("verify", attempt("3", func(x *forge.JobExecution) {
		x.Provenance = forge.ProvenanceIncomplete
		x.Conclusion = forge.ConclusionFailure
		x.JobID = "n3"
	}))
	wantObl(t, run(t, e, evid(oldIncomplete, newer, newerBad)), gate.Blocked, gate.ReasonIncomplete)
	unordered := exec("verify", attempt("x", func(x *forge.JobExecution) { x.Conclusion = forge.ConclusionFailure; x.JobID = "u" }))
	wantObl(t, run(t, e, evid(oldIncomplete, newer, unordered)), gate.Blocked, gate.ReasonIncomplete)
}
