// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

// Package backendtest is the conformance suite for [holdout.Backend]. Every backend, the in-memory one and the
// durable one that follows it (WI-21a), must pass [Run]. It checks the contract documented on the interface:
// atomic updates, blobs written once, global run and assignment uniqueness and serialized writers.
package backendtest

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/elliott-davis/lightsout/internal/holdout"
)

const (
	repoID  = "github:1"
	intent1 = "intent-1"
	sc1     = "SC-1"
	caseA2  = "case-a2"
	run1    = "run-1"
	mutated = "mutated"
)

var (
	suiteA = holdout.SuiteID{Repo: repoID, Issue: 1}
	suiteB = holdout.SuiteID{Repo: repoID, Issue: 2}
)

func rev(c string) holdout.Revision {
	return holdout.Revision("sha256:" + strings.Repeat(c, 64))
}

func file(content string) []holdout.File {
	return []holdout.File{{Path: "a_test.go", Mode: 0o644, Kind: holdout.KindTest, Bytes: []byte(content)}}
}

// withRun adds a run with one attempt bound to assignment.
func withRun(st *holdout.State, id string, attempt int, assignment string) {
	if st.Runs == nil {
		st.Runs = map[string]*holdout.RunState{}
	}
	r := st.Runs[id]
	if r == nil {
		r = &holdout.RunState{}
		st.Runs[id] = r
	}
	r.Attempts = append(r.Attempts, holdout.AttemptState{Number: attempt, Assignment: assignment})
}

// Run runs the conformance tests against backends made by newBackend, which must return a fresh empty backend.
// reopen returns a backend over the same storage after a restart: a durable backend closes its connections and
// opens new ones, and the in-memory backend returns the instance it was given. Everything committed before the
// reopen must be there after it, field for field.
func Run(t *testing.T, newBackend func(t *testing.T) holdout.Backend, reopen func(t *testing.T, b holdout.Backend) holdout.Backend) {
	t.Helper()
	withReopen := func(fn func(*testing.T, holdout.Backend, func() holdout.Backend)) func(*testing.T, holdout.Backend) {
		return func(t *testing.T, b holdout.Backend) {
			t.Helper()
			fn(t, b, func() holdout.Backend { return reopen(t, b) })
		}
	}
	tests := map[string]func(*testing.T, holdout.Backend){
		"RoundTripKeepsEveryField":       withReopen(roundTrip),
		"CancelledContextStoresNothing":  cancelledContext,
		"RollbackFromExistingState":      rollbackFromExisting,
		"PutFilesCopiesItsInput":         withReopen(putFilesCopies),
		"CrossSuiteRunIDRace":            crossSuiteRunIDRace,
		"CrossSuiteAssignmentRace":       crossSuiteAssignmentRace,
		"UpdateThenErrorStoresNothing":   updateErrorStoresNothing,
		"CommitIsVisible":                commitIsVisible,
		"BlobsAreWrittenOnce":            blobsWrittenOnce,
		"RunIDsAreGloballyUnique":        runIDsUnique,
		"AssignmentsAreGloballyUnique":   assignmentsUnique,
		"SuiteOfRunUnknownIsNotAnError":  suiteOfRunUnknown,
		"ConcurrentUpdatesAreSerialized": concurrentUpdates,
		"BlobsAreScopedToTheirSuite":     blobsScoped,
	}
	for name, fn := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			fn(t, newBackend(t))
		})
	}
}

// fullState populates every field of State, RevisionRecord, AttemptState, FileMeta and the nested records, so a
// backend that drops a column fails the round trip.
func fullState() holdout.State {
	at := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	author := holdout.Author{Principal: "qe-agent", Session: "s-qe"}
	reviewer := holdout.Author{Principal: "rev-agent", Session: "s-rev"}
	bundle := holdout.Bundle{
		Suite: suiteA, Parent: rev("0"), IntentRevision: intent1,
		Scenarios:  []holdout.Binding{{ScenarioID: sc1, Layer: "go", Entry: "case-a", Private: []string{caseA2}}},
		Correction: &holdout.Correction{Replaces: rev("0"), FailedRun: run1, Reason: "fix"},
	}
	return holdout.State{
		Head: rev("1"),
		Revisions: map[holdout.Revision]*holdout.RevisionRecord{
			rev("0"): {
				Revision: rev("0"), Bundle: holdout.Bundle{
					Suite: suiteA, IntentRevision: intent1,
					Scenarios: []holdout.Binding{{ScenarioID: sc1, Layer: "go", Entry: "case-a"}},
				},
				Status: holdout.StatusSuperseded, Author: author, ProposedAt: at,
			},
			rev("1"): {
				Revision: rev("1"), Bundle: bundle, Status: holdout.StatusFrozen, Author: author, ProposedAt: at.Add(time.Minute),
				Files: []holdout.FileMeta{{Path: "a_test.go", Mode: 0o755, Kind: holdout.KindTest, Size: 5, SHA256: strings.Repeat("ab", 32)}},
				Review: &holdout.ReviewRecord{
					Reviewer: reviewer, Verdict: holdout.VerdictApprove, IntentRevision: intent1,
					Mismatched: []string{sc1}, Reason: "because", At: at.Add(2 * time.Minute),
				},
				Attestation: &holdout.Attestation{Reviewer: reviewer, Disclosed: map[string]bool{caseA2: true}, At: at.Add(3 * time.Minute)},
			},
		},
		Runs: map[string]*holdout.RunState{run1: {
			Record: holdout.RunRecord{
				RunID: run1, Suite: suiteA, SuiteRevision: rev("1"), IntentRevision: intent1,
				CandidateSHA: strings.Repeat("a", 40), ArtifactDigest: "sha256:" + strings.Repeat("b", 64),
				SwitchConfigDigest: "sha256:" + strings.Repeat("c", 64), Assignment: "asg-1",
			},
			Attempts: []holdout.AttemptState{
				{
					Number: 1, Assignment: "asg-1", Session: "s-r1", ExpiresAt: at.Add(time.Hour), Opened: true,
					ReportBy: at.Add(30 * time.Minute), Abandoned: true,
				},
				{
					Number: 2, Assignment: "asg-2", Session: "s-r2", ExpiresAt: at.Add(2 * time.Hour), Opened: true,
					ReportBy: at.Add(90 * time.Minute), Outcome: &holdout.Outcome{FailedScenarios: []string{sc1}},
				},
			},
		}},
		Disclosed:  map[string]bool{caseA2: true, "case-z": true},
		LastReject: []string{sc1, "SC-2"},
	}
}

func commitFull(t *testing.T, b holdout.Backend) {
	t.Helper()
	err := b.Update(t.Context(), suiteA, func(st *holdout.State, tx holdout.WriteTx) error {
		*st = fullState()
		return tx.PutFiles(rev("1"), file("hello"))
	})
	if err != nil {
		t.Fatal(err)
	}
}

func roundTrip(t *testing.T, b holdout.Backend, reopen func() holdout.Backend) {
	t.Helper()
	commitFull(t, b)
	b = reopen()
	err := b.View(t.Context(), suiteA, func(st *holdout.State, tx holdout.ReadTx) error {
		if d := cmp.Diff(fullState(), *st, cmpopts.EquateEmpty()); d != "" {
			t.Errorf("state changed across commit and reopen (-want +got):\n%s", d)
		}
		files, ok := tx.Files(rev("1"))
		want := file("hello")
		if d := cmp.Diff(want, files, cmpopts.EquateEmpty()); !ok || d != "" {
			t.Errorf("blobs changed (-want +got) ok=%v:\n%s", ok, d)
		}
		if got, ok := tx.RunSuite(run1); !ok || got != suiteA {
			t.Errorf("run index lost: %v %v", got, ok)
		}
		if !tx.AssignmentBound("asg-1") || !tx.AssignmentBound("asg-2") {
			t.Error("assignment index lost")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if s, ok, err := b.SuiteOfRun(t.Context(), run1); err != nil || !ok || s != suiteA {
		t.Errorf("SuiteOfRun after reopen: %v %v %v", s, ok, err)
	}
}

func cancelledContext(t *testing.T, b holdout.Backend) {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	err := b.Update(ctx, suiteA, func(st *holdout.State, tx holdout.WriteTx) error {
		*st = fullState()
		return tx.PutFiles(rev("1"), file("x"))
	})
	if err == nil {
		t.Error("an update with a cancelled context succeeded")
	}
	if err := b.View(t.Context(), suiteA, func(st *holdout.State, tx holdout.ReadTx) error {
		if st.Head != "" || len(st.Revisions) != 0 || len(st.Runs) != 0 {
			t.Errorf("a cancelled update stored state: %+v", st)
		}
		if _, ok := tx.Files(rev("1")); ok || tx.AssignmentBound("asg-1") {
			t.Error("a cancelled update stored blobs or indexes")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func rollbackFromExisting(t *testing.T, b holdout.Backend) {
	t.Helper()
	commitFull(t, b)
	stored := false
	_ = b.View(t.Context(), suiteA, func(st *holdout.State, _ holdout.ReadTx) error {
		stored = cmp.Diff(fullState(), *st, cmpopts.EquateEmpty()) == ""
		return nil
	})
	if !stored {
		t.Fatal("the committed state is not what was written (see RoundTripKeepsEveryField)")
	}
	boom := errors.New("boom")
	err := b.Update(t.Context(), suiteA, func(st *holdout.State, _ holdout.WriteTx) error {
		rec := st.Revisions[rev("1")]
		rec.Status = holdout.StatusRejected
		rec.Review.Verdict = holdout.VerdictReject
		rec.Review.Mismatched[0] = mutated
		rec.Attestation.Disclosed["new"] = true
		rec.Files[0].SHA256 = mutated
		rec.Bundle.Scenarios[0].Private[0] = mutated
		run := st.Runs[run1]
		run.Attempts[1].Outcome.Passed = true
		run.Attempts[1].Outcome.FailedScenarios[0] = mutated
		run.Attempts[0].Abandoned = false
		delete(st.Runs, run1)
		delete(st.Revisions, rev("0"))
		st.Disclosed["new"] = true
		st.LastReject[0] = mutated
		st.Head = ""
		return boom
	})
	if !errors.Is(err, boom) {
		t.Fatalf("got %v", err)
	}
	if err := b.View(t.Context(), suiteA, func(st *holdout.State, _ holdout.ReadTx) error {
		if d := cmp.Diff(fullState(), *st, cmpopts.EquateEmpty()); d != "" {
			t.Errorf("a failed update changed stored state (-want +got):\n%s", d)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := b.SuiteOfRun(t.Context(), run1); !ok {
		t.Error("the run index lost the run in a rolled-back update")
	}
}

func putFilesCopies(t *testing.T, b holdout.Backend, reopen func() holdout.Backend) {
	t.Helper()
	in := file("original")
	err := b.Update(t.Context(), suiteA, func(_ *holdout.State, tx holdout.WriteTx) error {
		if err := tx.PutFiles(rev("1"), in); err != nil {
			return err
		}
		in[0].Bytes[0] = 'X' // the caller reuses its buffer after the call
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	in[0].Bytes[1] = 'Y'
	b = reopen()
	_ = b.View(t.Context(), suiteA, func(_ *holdout.State, tx holdout.ReadTx) error {
		if f, _ := tx.Files(rev("1")); string(f[0].Bytes) != "original" {
			t.Errorf("PutFiles kept the caller's buffer: %q", f[0].Bytes)
		}
		return nil
	})
	err = b.Update(t.Context(), suiteA, func(_ *holdout.State, tx holdout.WriteTx) error {
		return tx.PutFiles(rev("1"), file("again"))
	})
	if !errors.Is(err, holdout.ErrConflict) {
		t.Errorf("second write: %v, want ErrConflict", err)
	}
}

func crossSuiteRunIDRace(t *testing.T, b holdout.Backend) {
	t.Helper()
	race(t, b, func(st *holdout.State, i int) { withRun(st, "run-same", 1, fmt.Sprintf("asg-%d", i)) })
}

func crossSuiteAssignmentRace(t *testing.T, b holdout.Backend) {
	t.Helper()
	race(t, b, func(st *holdout.State, i int) { withRun(st, fmt.Sprintf("run-%d", i), 1, "asg-same") })
}

// race has one writer per suite claim the same global key at once. Exactly one commits and the rest get ErrConflict.
func race(t *testing.T, b holdout.Backend, claim func(*holdout.State, int)) {
	t.Helper()
	const n = 8
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- b.Update(t.Context(), holdout.SuiteID{Repo: repoID, Issue: 100 + i}, func(st *holdout.State, _ holdout.WriteTx) error {
				claim(st, i)
				return nil
			})
		}()
	}
	wg.Wait()
	close(errs)
	won := 0
	for err := range errs {
		switch {
		case err == nil:
			won++
		case !errors.Is(err, holdout.ErrConflict):
			t.Errorf("loser got %v, want ErrConflict", err)
		}
	}
	if won != 1 {
		t.Fatalf("%d writers won, want 1", won)
	}
}

func updateErrorStoresNothing(t *testing.T, b holdout.Backend) {
	t.Helper()
	boom := errors.New("boom")
	err := b.Update(t.Context(), suiteA, func(st *holdout.State, tx holdout.WriteTx) error {
		st.Head = rev("1")
		withRun(st, run1, 1, "asg-1")
		if err := tx.PutFiles(rev("1"), file("x")); err != nil {
			return err
		}
		return boom
	})
	if !errors.Is(err, boom) {
		t.Fatalf("got %v, want the function's error", err)
	}
	if s, ok, err := b.SuiteOfRun(t.Context(), run1); ok || err != nil {
		t.Fatalf("run index kept after rollback: %v %v %v", s, ok, err)
	}
	if err := b.View(t.Context(), suiteA, func(st *holdout.State, tx holdout.ReadTx) error {
		if st.Head != "" || len(st.Runs) != 0 {
			t.Errorf("state kept after rollback: %+v", st)
		}
		if tx.AssignmentBound("asg-1") {
			t.Error("assignment index kept after rollback")
		}
		if _, ok := tx.Files(rev("1")); ok {
			t.Error("blob kept after rollback")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func commitIsVisible(t *testing.T, b holdout.Backend) {
	t.Helper()
	err := b.Update(t.Context(), suiteA, func(st *holdout.State, tx holdout.WriteTx) error {
		st.Head = rev("1")
		withRun(st, run1, 1, "asg-1")
		return tx.PutFiles(rev("1"), file("hello"))
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := b.View(t.Context(), suiteA, func(st *holdout.State, tx holdout.ReadTx) error {
		if st.Head != rev("1") || st.Runs[run1] == nil {
			t.Errorf("state lost: %+v", st)
		}
		files, ok := tx.Files(rev("1"))
		if !ok || string(files[0].Bytes) != "hello" {
			t.Errorf("blob lost: %v %v", files, ok)
		}
		if got, ok := tx.RunSuite(run1); !ok || got != suiteA {
			t.Errorf("run index: %v %v", got, ok)
		}
		if !tx.AssignmentBound("asg-1") {
			t.Error("assignment index lost")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	// A view of another suite sees an empty state.
	_ = b.View(t.Context(), suiteB, func(st *holdout.State, _ holdout.ReadTx) error {
		if st.Head != "" || len(st.Runs) != 0 {
			t.Errorf("other suite not empty: %+v", st)
		}
		return nil
	})
}

func blobsWrittenOnce(t *testing.T, b holdout.Backend) {
	t.Helper()
	put := func(content string) error {
		return b.Update(t.Context(), suiteA, func(_ *holdout.State, tx holdout.WriteTx) error {
			return tx.PutFiles(rev("1"), file(content))
		})
	}
	if err := put("first"); err != nil {
		t.Fatal(err)
	}
	if err := put("second"); !errors.Is(err, holdout.ErrConflict) {
		t.Fatalf("second write of the same revision's blobs: %v, want ErrConflict", err)
	}
	_ = b.View(t.Context(), suiteA, func(_ *holdout.State, tx holdout.ReadTx) error {
		if f, _ := tx.Files(rev("1")); string(f[0].Bytes) != "first" {
			t.Errorf("blob overwritten: %q", f[0].Bytes)
		}
		return nil
	})
}

func blobsScoped(t *testing.T, b holdout.Backend) {
	t.Helper()
	if err := b.Update(t.Context(), suiteA, func(_ *holdout.State, tx holdout.WriteTx) error {
		return tx.PutFiles(rev("1"), file("x"))
	}); err != nil {
		t.Fatal(err)
	}
	_ = b.View(t.Context(), suiteB, func(_ *holdout.State, tx holdout.ReadTx) error {
		if _, ok := tx.Files(rev("1")); ok {
			t.Error("another suite can read the blobs")
		}
		return nil
	})
}

func runIDsUnique(t *testing.T, b holdout.Backend) {
	t.Helper()
	if err := b.Update(t.Context(), suiteA, func(st *holdout.State, _ holdout.WriteTx) error {
		withRun(st, run1, 1, "asg-1")
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	err := b.Update(t.Context(), suiteB, func(st *holdout.State, tx holdout.WriteTx) error {
		if _, taken := tx.RunSuite(run1); !taken {
			t.Error("the function cannot see the run ID owner")
		}
		withRun(st, run1, 1, "asg-2")
		return nil
	})
	if !errors.Is(err, holdout.ErrConflict) {
		t.Fatalf("got %v, want ErrConflict", err)
	}
	if s, _, _ := b.SuiteOfRun(t.Context(), run1); s != suiteA {
		t.Errorf("owner changed to %v", s)
	}
	if b.View(t.Context(), suiteB, func(st *holdout.State, tx holdout.ReadTx) error {
		if len(st.Runs) != 0 || tx.AssignmentBound("asg-2") {
			t.Error("conflicting update stored something")
		}
		return nil
	}) != nil {
		t.Fatal("view failed")
	}
	// The owner suite can keep updating its own run.
	if err := b.Update(t.Context(), suiteA, func(st *holdout.State, _ holdout.WriteTx) error {
		withRun(st, run1, 2, "asg-3")
		return nil
	}); err != nil {
		t.Fatalf("owner update: %v", err)
	}
}

func assignmentsUnique(t *testing.T, b holdout.Backend) {
	t.Helper()
	if err := b.Update(t.Context(), suiteA, func(st *holdout.State, _ holdout.WriteTx) error {
		withRun(st, run1, 1, "asg-1")
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for name, fn := range map[string]func(*holdout.State){
		"another run, another suite": func(st *holdout.State) { withRun(st, "run-9", 1, "asg-1") },
	} {
		if err := b.Update(t.Context(), suiteB, func(st *holdout.State, _ holdout.WriteTx) error {
			fn(st)
			return nil
		}); !errors.Is(err, holdout.ErrConflict) {
			t.Errorf("%s: got %v, want ErrConflict", name, err)
		}
	}
	// The same assignment on a second attempt of the same suite's run, and twice in one update, conflict too.
	if err := b.Update(t.Context(), suiteA, func(st *holdout.State, _ holdout.WriteTx) error {
		withRun(st, run1, 2, "asg-1")
		return nil
	}); !errors.Is(err, holdout.ErrConflict) {
		t.Errorf("reused by a later attempt: got %v", err)
	}
	if err := b.Update(t.Context(), suiteA, func(st *holdout.State, _ holdout.WriteTx) error {
		withRun(st, "run-2", 1, "asg-5")
		withRun(st, "run-3", 1, "asg-5")
		return nil
	}); !errors.Is(err, holdout.ErrConflict) {
		t.Errorf("bound twice in one update: got %v", err)
	}
	// An update that rewrites an existing attempt unchanged is fine.
	if err := b.Update(t.Context(), suiteA, func(st *holdout.State, _ holdout.WriteTx) error {
		st.Head = rev("2")
		return nil
	}); err != nil {
		t.Errorf("unrelated update: %v", err)
	}
}

func suiteOfRunUnknown(t *testing.T, b holdout.Backend) {
	t.Helper()
	if _, ok, err := b.SuiteOfRun(t.Context(), "nope"); ok || err != nil {
		t.Fatalf("unknown run: ok=%v err=%v", ok, err)
	}
}

func concurrentUpdates(t *testing.T, b holdout.Backend) {
	t.Helper()
	const n = 16
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- b.Update(t.Context(), suiteA, func(st *holdout.State, _ holdout.WriteTx) error {
				if st.Disclosed == nil {
					st.Disclosed = map[string]bool{}
				}
				st.Disclosed[fmt.Sprintf("case-%d", i)] = true
				withRun(st, fmt.Sprintf("run-%d", i), 1, fmt.Sprintf("asg-%d", i))
				return nil
			})
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	_ = b.View(t.Context(), suiteA, func(st *holdout.State, _ holdout.ReadTx) error {
		if len(st.Disclosed) != n || len(st.Runs) != n {
			t.Errorf("lost updates: %d disclosed, %d runs, want %d", len(st.Disclosed), len(st.Runs), n)
		}
		return nil
	})
}
