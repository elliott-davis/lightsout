// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

package holdout_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/elliott-davis/lightsout/internal/holdout"
)

// faultBackend injects storage faults: it can change the state a transaction sees and the blobs it reads.
// View runs on a copy of the state, so a tampering hook never changes what is stored.
type faultBackend struct {
	holdout.Backend
	state func(*holdout.State)
	files func(rev holdout.Revision, files []holdout.File, ok bool) ([]holdout.File, bool)
}

type faultTx struct {
	holdout.ReadTx
	f faultBackend
}

func (t faultTx) Files(rev holdout.Revision) ([]holdout.File, bool) {
	files, ok := t.ReadTx.Files(rev)
	if t.f.files == nil {
		return files, ok
	}
	cp := make([]holdout.File, len(files))
	for i, f := range files {
		f.Bytes = slices.Clone(f.Bytes)
		cp[i] = f
	}
	return t.f.files(rev, cp, ok)
}

type faultWriteTx struct {
	holdout.WriteTx
	f faultBackend
}

func (t faultWriteTx) Files(rev holdout.Revision) ([]holdout.File, bool) {
	return faultTx{t.WriteTx, t.f}.Files(rev)
}

func (f faultBackend) View(ctx context.Context, s holdout.SuiteID, fn func(*holdout.State, holdout.ReadTx) error) error {
	return f.Backend.View(ctx, s, func(st *holdout.State, tx holdout.ReadTx) error {
		cp := st.Clone()
		if f.state != nil {
			f.state(&cp)
		}
		return fn(&cp, faultTx{tx, f})
	})
}

func (f faultBackend) Update(ctx context.Context, s holdout.SuiteID, fn func(*holdout.State, holdout.WriteTx) error) error {
	return f.Backend.Update(ctx, s, func(st *holdout.State, tx holdout.WriteTx) error {
		if f.state != nil {
			f.state(st)
		}
		return fn(st, faultWriteTx{tx, f})
	})
}

func (e *env) okCount(target string) int {
	n := 0
	entries := e.entries()
	for i := range entries {
		if entries[i].Target == target && entries[i].Outcome == "ok" {
			n++
		}
	}
	return n
}

// Blob faults on Read and Open (items 5, 7): nothing is released, nothing is recorded, no "ok" audit entry.
func TestBadBlobsReleaseNothing(t *testing.T) { // INT-6, AGT-2
	t.Parallel()
	faults := map[string]func(rev holdout.Revision, files []holdout.File, ok bool) ([]holdout.File, bool){
		"missing":  func(_ holdout.Revision, _ []holdout.File, _ bool) ([]holdout.File, bool) { return nil, false },
		"too few":  func(_ holdout.Revision, f []holdout.File, ok bool) ([]holdout.File, bool) { return f[:1], ok },
		"too many": func(_ holdout.Revision, f []holdout.File, ok bool) ([]holdout.File, bool) { return append(f, f[0]), ok },
		"none": func(_ holdout.Revision, _ []holdout.File, ok bool) ([]holdout.File, bool) {
			return []holdout.File{}, ok
		},
		"tampered": func(_ holdout.Revision, f []holdout.File, ok bool) ([]holdout.File, bool) {
			f[0].Bytes[0] ^= 1
			return f, ok
		},
		"truncated": func(_ holdout.Revision, f []holdout.File, ok bool) ([]holdout.File, bool) {
			f[1].Bytes = f[1].Bytes[:3]
			return f, ok
		},
	}
	for name, fault := range faults {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			e := newEnv(t)
			rev := e.active()
			e.grant(rev, "run-1", "asg-1")
			bad := e.storeOn(faultBackend{Backend: e.backend, files: fault})
			if got, err := bad.Read(e.ctx(), "qe", suite, rev); err == nil || got.Bundle.Files != nil {
				t.Errorf("read released data: %v", err)
			}
			rd, err := bad.Open(e.ctx(), "runner-a", "run-1", 1)
			if err == nil || rd != nil || errors.Is(err, holdout.ErrDenied) {
				t.Errorf("open: %v %v", rd, err)
			}
			if e.okCount("holdout.open")+e.okCount("holdout.read") != 0 {
				t.Error("an ok audit entry was written for a failed release")
			}
			// Nothing was recorded: the grant was not consumed.
			if _, err := e.store.Open(e.ctx(), "runner-a", "run-1", 1); err != nil {
				t.Errorf("grant consumed by the failed open: %v", err)
			}
			if e.okCount("holdout.open") != 1 {
				t.Errorf("%d open entries", e.okCount("holdout.open"))
			}
		})
	}
}

func TestReturnedFilesComeFromMetadataAndTheAddressIsChecked(t *testing.T) { // INT-6
	t.Parallel()
	t.Run("blob path is ignored", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t)
		rev := e.active()
		evil := e.storeOn(faultBackend{Backend: e.backend, files: func(_ holdout.Revision, f []holdout.File, ok bool) ([]holdout.File, bool) {
			f[0].Path, f[0].Mode = "../evil", 0o777
			return f, ok
		}})
		got, err := evil.Read(e.ctx(), "qe", suite, rev)
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range got.Bundle.Files {
			if strings.Contains(f.Path, "evil") || f.Mode == 0o777 {
				t.Errorf("tampered blob metadata reached the caller: %+v", f)
			}
		}
	})
	t.Run("metadata only", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t)
		rev := e.active()
		bad := e.storeOn(faultBackend{Backend: e.backend, state: func(st *holdout.State) { st.Revisions[rev].Files[0].Mode = 0o755 }})
		if _, err := bad.Read(e.ctx(), "qe", suite, rev); err == nil {
			t.Error("changed mode accepted")
		}
	})
	t.Run("coordinated metadata and blob", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t)
		rev := e.active()
		e.grant(rev, "run-1", "asg-1")
		tampered := []byte("package b // swapped")
		bad := e.storeOn(faultBackend{
			Backend: e.backend,
			state: func(st *holdout.State) {
				m := &st.Revisions[rev].Files[1]
				m.Size, m.SHA256 = len(tampered), sha256Hex(tampered)
			},
			files: func(_ holdout.Revision, f []holdout.File, ok bool) ([]holdout.File, bool) {
				f[1].Bytes = tampered
				return f, ok
			},
		})
		if _, err := bad.Read(e.ctx(), "qe", suite, rev); err == nil {
			t.Error("coordinated tampering accepted by Read")
		}
		if rd, err := bad.Open(e.ctx(), "runner-a", "run-1", 1); err == nil || rd != nil {
			t.Errorf("coordinated tampering accepted by Open: %v", err)
		}
	})
}

func TestEligibleNeedsCurrentIntentAndAttestation(t *testing.T) { // INT-9, INT-7
	t.Parallel()
	t.Run("frozen revision with moved intent", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t)
		a := e.active()
		e.failRun(a, "run-1", "asg-1", "runner-a")
		st, _ := e.store.Status(e.ctx(), "scheduler", suite)
		if st.Status != holdout.StatusFrozen || !st.Eligible {
			t.Fatalf("frozen at the current intent: %+v", st)
		}
		e.intents.set(approved(intentV2))
		st, _ = e.store.Status(e.ctx(), "scheduler", suite)
		if st.Status != holdout.StatusFrozen || st.Eligible {
			t.Fatalf("frozen after the intent moved: %+v", st)
		}
	})
	t.Run("disclosures need an attestation on the head", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t)
		a := e.active()
		if err := e.store.AttestCoverage(e.ctx(), "reviewer", holdout.CoverageRequest{Suite: suite, Revision: a, Disclosed: []string{"case-a"}}); err != nil {
			t.Fatal(err)
		}
		next := e.propose(e.successor(a, "successor"))
		if err := e.review("reviewer", next, intentV1); err != nil {
			t.Fatal(err)
		}
		if st, _ := e.store.Status(e.ctx(), "scheduler", suite); st.Head != next || st.Eligible {
			t.Fatalf("no attestation yet: %+v", st)
		}
		if err := e.store.AttestCoverage(e.ctx(), "reviewer", holdout.CoverageRequest{Suite: suite, Revision: next, Disclosed: []string{"case-a"}}); err != nil {
			t.Fatal(err)
		}
		if st, _ := e.store.Status(e.ctx(), "scheduler", suite); !st.Eligible {
			t.Fatalf("attested: %+v", st)
		}
	})
}

func TestBlockingClearsWhenTheHeadIsEligible(t *testing.T) { // INT-9
	t.Parallel()
	e := newEnv(t)
	a := e.active()
	b := e.propose(e.successor(a, "worse"))
	e.reject(b) // head reverts to a, which is eligible
	st, _ := e.store.Status(e.ctx(), "scheduler", suite)
	if st.Head != a || !st.Eligible || len(st.Blocking) != 0 {
		t.Fatalf("%+v", st)
	}
	// With no usable head, the rejection still blocks.
	e2 := newEnv(t)
	rev := e2.propose(bundle("", intentV1))
	e2.reject(rev)
	if st, _ := e2.store.Status(e2.ctx(), "scheduler", suite); st.Eligible || strings.Join(st.Blocking, ",") != "SC-1" {
		t.Fatalf("%+v", st)
	}
}

func TestApprovalWithBundleOnlyScenarios(t *testing.T) { // INT-9
	t.Parallel()
	e := newEnv(t)
	b := bundle("", intentV1)
	b.Scenarios = append(b.Scenarios, holdout.Binding{ScenarioID: "SC-9", Layer: "go", Entry: "case-9"})
	rev := e.propose(b)
	err := e.review("reviewer", rev, intentV1)
	var mm *holdout.MismatchError
	if !errors.As(err, &mm) || mm.Extra != 1 || len(mm.ScenarioIDs) != 0 {
		t.Fatalf("got %v", err)
	}
	if strings.Contains(err.Error(), "SC-9") {
		t.Error("bundle-only id echoed")
	}
}

func TestMissingRecordsFailClosed(t *testing.T) { // INT-9
	t.Parallel()
	e := newEnv(t)
	a := e.active()
	b := e.propose(e.successor(a, "next"))
	gone := e.storeOn(faultBackend{Backend: e.backend, state: func(st *holdout.State) { delete(st.Revisions, a) }})
	if err := func() error {
		_, err := gone.Review(e.ctx(), "reviewer", holdout.ReviewRequest{Suite: suite, Revision: b, IntentRevision: intentV1, Verdict: holdout.VerdictApprove})
		return err
	}(); !errors.Is(err, holdout.ErrConflict) {
		t.Errorf("approve with the parent record missing: %v", err)
	}
	// A head that names a missing revision refuses a proposal on top of it.
	e2 := newEnv(t)
	a2 := e2.active()
	gone2 := e2.storeOn(faultBackend{Backend: e2.backend, state: func(st *holdout.State) { delete(st.Revisions, a2) }})
	if _, err := gone2.Propose(e2.ctx(), "qe", e2.successor(a2, "next")); !errors.Is(err, holdout.ErrConflict) {
		t.Errorf("propose on a missing head: %v", err)
	}
}

func TestRejectReasonStaysOutOfTheAuditLog(t *testing.T) { // INT-9, AGT-2
	t.Parallel()
	e := newEnv(t)
	rev := e.propose(bundle("", intentV1))
	const reason = "REASON-MARKER: asserts qty<=9999"
	_, err := e.store.Review(e.ctx(), "reviewer", holdout.ReviewRequest{
		Suite: suite, Revision: rev, IntentRevision: intentV1, Verdict: holdout.VerdictReject,
		Mismatched: []string{"SC-1"}, Reason: reason,
	})
	if err != nil {
		t.Fatal(err)
	}
	txt := e.auditText()
	if strings.Contains(txt, "REASON-MARKER") || strings.Contains(txt, "9999") {
		t.Error("the reason reached the audit log")
	}
	if !strings.Contains(txt, sha256Hex([]byte(reason))) {
		t.Error("the reason's digest is not audited")
	}
	_ = e.backend.View(e.ctx(), suite, func(st *holdout.State, _ holdout.ReadTx) error {
		if st.Revisions[rev].Review.Reason != reason {
			t.Error("the reason is not stored privately")
		}
		return nil
	})
}

func TestBuffersAreNotAliased(t *testing.T) { // INT-6
	t.Parallel()
	e := newEnv(t)
	b := bundle("", intentV1)
	rev := e.propose(b)
	b.Files[0].Bytes[0] ^= 0xff // the caller reuses its buffer after Propose
	got, err := e.store.Read(e.ctx(), "qe", suite, rev)
	if err != nil {
		t.Fatal(err)
	}
	want := slices.Clone(got.Bundle.Files[0].Bytes)
	if !strings.Contains(string(want), secret) {
		t.Fatal("stored bytes follow the caller's buffer")
	}
	got.Bundle.Files[0].Bytes[1] ^= 0xff // and the caller changes what Read returned
	again, _ := e.store.Read(e.ctx(), "qe", suite, rev)
	if !bytes.Equal(again.Bundle.Files[0].Bytes, want) {
		t.Fatal("a returned buffer aliases the stored one")
	}
	if rerr := e.review("reviewer", rev, intentV1); rerr != nil {
		t.Fatal(rerr)
	}
	e.grant(rev, "run-1", "asg-1")
	rd, err := e.store.Open(e.ctx(), "runner-a", "run-1", 1)
	if err != nil {
		t.Fatal(err)
	}
	f, _ := rd.File(rd.Paths()[0])
	f.Bytes[0] ^= 0xff
	if f2, _ := rd.File(rd.Paths()[0]); f2.Bytes[0] == f.Bytes[0] {
		t.Fatal("reader returns its own buffer")
	}
	last, _ := e.store.Read(e.ctx(), "qe", suite, rev)
	if !bytes.Equal(last.Bundle.Files[0].Bytes, want) {
		t.Fatal("the runner's reader aliases the store")
	}
}

func TestLeakCheckEmptyFiles(t *testing.T) { // INT-7
	t.Parallel()
	e := newEnv(t)
	b := bundle("", intentV1)
	b.Files = append(b.Files, holdout.File{Path: "fixtures/empty", Mode: 0o644, Kind: holdout.KindFixture})
	rev := e.propose(b)
	empty := sha256Hex(nil)
	rep, err := e.store.LeakCheck(e.ctx(), "qe", holdout.LeakRequest{
		Suite: suite, Revision: rev,
		Files:   []holdout.PublicFile{{Path: "pub/empty"}},
		Digests: []holdout.PublicDigest{{Path: "pub/empty.bin", SHA256: empty}},
	})
	if err != nil || !rep.Clean() {
		t.Fatalf("an empty file is not a leak: %v %+v", err, rep)
	}
}

func TestAttestationCarriesDisclosedCasesIntoRenamedSuccessor(t *testing.T) { // INT-7
	t.Parallel()
	e := newEnv(t)
	a := e.active()
	if err := e.store.AttestCoverage(e.ctx(), "reviewer", holdout.CoverageRequest{Suite: suite, Revision: a, Disclosed: []string{"case-a"}}); err != nil {
		t.Fatal(err)
	}
	b := e.successor(a, "renamed")
	b.Scenarios[1].Entry = "case-a-v2" // the disclosed case no longer exists in this revision
	next := e.propose(b)
	if err := e.review("reviewer", next, intentV1); err != nil {
		t.Fatal(err)
	}
	if err := e.store.AttestCoverage(e.ctx(), "reviewer", holdout.CoverageRequest{Suite: suite, Revision: next, Disclosed: []string{"case-a"}}); err != nil {
		t.Fatalf("a carried-forward disclosure is not a bundle case: %v", err)
	}
	if err := e.store.AttestCoverage(e.ctx(), "reviewer", holdout.CoverageRequest{Suite: suite, Revision: next, Disclosed: []string{"case-a", "never-existed"}}); !errors.Is(err, holdout.ErrInvalid) {
		t.Fatalf("a new unknown case: %v", err)
	}
}

// Hostile path spellings (item 10). The Go escapes are asserted on raw bytes so a tool that unescaped them would fail
// here instead of silently weakening the test.
func TestHostilePathSpellingsRefused(t *testing.T) { // INT-6
	t.Parallel()
	cases := map[string]struct {
		path string
		r    rune // a code point the path must contain, 0 if none
	}{
		"zero width non-joiner": {".g\u200cit/config", 0x200c},
		"zero width space":      {"tests/a\u200bb_test.go", 0x200b},
		"soft hyphen":           {"tests/a\u00adb.go", 0xad},
		"variation selector":    {"tests/a\ufe0fb.go", 0xfe0f},
		"combining grapheme":    {"tests/a\u034fb.go", 0x34f},
		"hangul filler":         {"tests/a\u3164b.go", 0x3164},
		"git trailing dot":      {".git./config", 0},
		"git trailing space":    {".git /config", 0},
		"git short name":        {"GIT~1/config", 0},
		"short name":            {"tests/LONGNA~2.go", 0},
		"trailing dot":          {"tests/a.", 0},
		"stream":                {"tests/a:stream", 0},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if c.r != 0 && !strings.ContainsRune(c.path, c.r) {
				t.Fatalf("the hostile path lost its code point U+%04X: %q", c.r, c.path)
			}
			e := newEnv(t)
			b := bundle("", intentV1)
			b.Files[0].Path = c.path
			if _, err := e.store.Propose(e.ctx(), "qe", b); !errors.Is(err, holdout.ErrInvalid) {
				t.Fatalf("got %v, want ErrInvalid", err)
			}
		})
	}
}

func TestAbandonmentIsAuditedOnceAndOnlyForOpenedAttempts(t *testing.T) { // PIP-15
	t.Parallel()
	e := newEnv(t)
	a := e.active()
	e.grant(a, "run-1", "asg-1")
	if _, err := e.store.Open(e.ctx(), "runner-a", "run-1", 1); err != nil {
		t.Fatal(err)
	}
	e.grant(a, "run-2", "asg-2") // granted, never opened: nothing to abandon
	b := e.successor(a, "with an unapproved extra scenario")
	b.Scenarios = append(b.Scenarios, holdout.Binding{ScenarioID: "SC-9", Layer: "go", Entry: "case-9"})
	next := e.propose(b)
	*e.now = e.now.Add(30 * time.Minute)
	for range 2 { // refused for the extra scenario, after the abandonment was observed
		var mm *holdout.MismatchError
		if err := e.review("reviewer", next, intentV1); !errors.As(err, &mm) {
			t.Fatalf("got %v", err)
		}
	}
	n := 0
	for _, en := range e.entries() {
		if en.Target == "holdout.abandoned" {
			n++
			if !strings.Contains(fmt.Sprintf("%+v", en), "run-1") {
				t.Errorf("abandoned entry names the wrong run: %+v", en)
			}
		}
	}
	if n != 1 {
		t.Fatalf("%d abandoned entries, want 1 (one opened attempt, observed twice)", n)
	}
}

func TestRejectNamesAtMostMaxScenarios(t *testing.T) { // INT-9
	t.Parallel()
	e := newEnv(t)
	var ids []string
	for i := range holdout.MaxScenarios + 44 {
		ids = append(ids, fmt.Sprintf("S%03d", i))
	}
	e.intents.set(holdout.IntentState{Approved: intentV1, ScenarioIDs: ids})
	rev := e.propose(bundle("", intentV1))
	_, err := e.store.Review(e.ctx(), "reviewer", holdout.ReviewRequest{
		Suite: suite, Revision: rev, IntentRevision: intentV1, Verdict: holdout.VerdictReject, Mismatched: ids, Reason: "everything",
	})
	if !errors.Is(err, holdout.ErrInvalid) {
		t.Fatalf("got %v", err)
	}
}

func TestApprovalClearsTheLastRejection(t *testing.T) { // INT-9
	t.Parallel()
	e := newEnv(t)
	first := e.propose(bundle("", intentV1))
	e.reject(first)
	n := bundle("", intentV1)
	n.Files[0].Bytes = []byte("second")
	second := e.propose(n)
	if err := e.review("reviewer", second, intentV1); err != nil {
		t.Fatal(err)
	}
	e.intents.set(approved(intentV2)) // the head is no longer eligible, so Blocking would show what is stored
	st, _ := e.store.Status(e.ctx(), "scheduler", suite)
	if st.Eligible || len(st.Blocking) != 0 {
		t.Fatalf("%+v", st)
	}
}

func TestStatusRefusesAnInvalidSuite(t *testing.T) { // NFR-4
	t.Parallel()
	e := newEnv(t)
	if _, err := e.store.Status(e.ctx(), "qe-bad", holdout.SuiteID{Repo: repo}); !errors.Is(err, holdout.ErrInvalid) {
		t.Fatalf("got %v", err)
	}
}

// An attempt that an approval treated as abandoned can never record, even if a caller's clock reads earlier than
// its deadline (an NTP step back, or a replica with a slower clock).
func TestAbandonedAttemptNeverRecordsAfterAClockStep(t *testing.T) { // PIP-15, INT-9
	t.Parallel()
	e := newEnv(t)
	a := e.active()
	e.grant(a, "run-1", "asg-1")
	if _, err := e.store.Open(e.ctx(), "runner-a", "run-1", 1); err != nil {
		t.Fatal(err)
	}
	b := e.propose(e.successor(a, "weakened"))
	t0 := *e.now
	*e.now = t0.Add(31 * time.Minute) // past ReportBy (MaxRunDuration is 30m)
	if err := e.review("reviewer", b, intentV1); err != nil {
		t.Fatal(err)
	}
	*e.now = t0.Add(29 * time.Minute) // the clock steps back before ReportBy
	err := e.store.RecordOutcome(e.ctx(), "runner-a", "run-1", 1, holdout.Outcome{FailedScenarios: []string{"SC-1"}})
	if !errors.Is(err, holdout.ErrDenied) {
		t.Fatalf("failure on an abandoned attempt after a clock step: %v, want ErrDenied", err)
	}
	rb, err := e.store.Read(e.ctx(), "qe", suite, b)
	if err != nil {
		t.Fatal(err)
	}
	if rb.Status != holdout.StatusActive {
		t.Fatalf("successor status %q, want active", rb.Status)
	}
}
