// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

package holdout_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/elliott-davis/lightsout/internal/audit"
	"github.com/elliott-davis/lightsout/internal/forge"
	"github.com/elliott-davis/lightsout/internal/holdout"
	"github.com/elliott-davis/lightsout/internal/holdout/memholdout"
)

const (
	repo      = forge.RepoID("github:1")
	otherRepo = forge.RepoID("github:2")
	intentV1  = "intent-1"
	intentV2  = "intent-2"
	secret    = "SECRET-ASSERTION-BODY-do-not-leak"
)

var (
	suite  = holdout.SuiteID{Repo: repo, Issue: 7}
	suite8 = holdout.SuiteID{Repo: repo, Issue: 8}
)

// fakeVerifier maps credentials to workloads. An unknown credential is unverified.
type fakeVerifier struct {
	m map[holdout.Credential]holdout.Workload
}

func (f fakeVerifier) Verify(_ context.Context, c holdout.Credential) (holdout.Workload, error) {
	if asg, ok := strings.CutPrefix(string(c), "runner:"); ok { // a runner for any assignment
		return holdout.Workload{Role: holdout.RoleAcceptanceRunner, Repo: repo, Principal: "runner", Session: "s-" + asg, Assignment: asg}, nil
	}
	w, ok := f.m[c]
	if !ok {
		return holdout.Workload{}, errors.New("unverified")
	}
	return w, nil
}

type fakeIntents struct {
	mu sync.Mutex
	st holdout.IntentState
}

func (f *fakeIntents) Current(context.Context, holdout.SuiteID) (holdout.IntentState, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.st, nil
}

func (f *fakeIntents) set(st holdout.IntentState) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.st = st
}

// countingBackend counts every backend call.
type countingBackend struct {
	holdout.Backend
	calls  atomic.Int64
	suites atomic.Int64 // View and Update calls: reads or writes of suite state
}

func (c *countingBackend) View(ctx context.Context, s holdout.SuiteID, fn func(*holdout.State, holdout.ReadTx) error) error {
	c.calls.Add(1)
	c.suites.Add(1)
	return c.Backend.View(ctx, s, fn)
}

func (c *countingBackend) Update(ctx context.Context, s holdout.SuiteID, fn func(*holdout.State, holdout.WriteTx) error) error {
	c.calls.Add(1)
	c.suites.Add(1)
	return c.Backend.Update(ctx, s, fn)
}

func (c *countingBackend) SuiteOfRun(ctx context.Context, id string) (holdout.SuiteID, bool, error) {
	c.calls.Add(1)
	return c.Backend.SuiteOfRun(ctx, id)
}

// failAudit fails every append while armed.
type failAudit struct {
	inner holdout.Auditor
	fail  atomic.Bool
}

func (f *failAudit) Append(ctx context.Context, r audit.Record) (audit.Entry, error) {
	if f.fail.Load() {
		return audit.Entry{}, errors.New("disk full")
	}
	return f.inner.Append(ctx, r)
}

type env struct {
	t       *testing.T
	store   *holdout.Store
	backend *countingBackend
	intents *fakeIntents
	audit   *failAudit
	mem     *audit.Memory
	now     *time.Time
}

var workloads = map[holdout.Credential]holdout.Workload{
	"qe":          {Role: holdout.RoleQE, Repo: repo, Assignment: suite.Assignment(), Principal: "qe-agent", Session: "s-qe"},
	"qe2":         {Role: holdout.RoleQE, Repo: repo, Assignment: suite.Assignment(), Principal: "qe-agent", Session: "s-qe-2"},
	"qe-other":    {Role: holdout.RoleQE, Repo: otherRepo, Principal: "qe-agent", Session: "s-qe-o"},
	"reviewer":    {Role: holdout.RoleScenarioReviewer, Repo: repo, Assignment: suite.Assignment(), Principal: "rev-agent", Session: "s-rev"},
	"rev-sameP":   {Role: holdout.RoleScenarioReviewer, Repo: repo, Assignment: suite.Assignment(), Principal: "qe-agent", Session: "s-rev"},
	"rev-sameS":   {Role: holdout.RoleScenarioReviewer, Repo: repo, Assignment: suite.Assignment(), Principal: "rev-agent", Session: "s-qe"},
	"rev-other":   {Role: holdout.RoleScenarioReviewer, Repo: otherRepo, Principal: "rev-agent", Session: "s-rev-o"},
	"scheduler":   {Role: holdout.RoleAcceptanceScheduler, Repo: repo, Principal: "sched", Session: "s-sch"},
	"runner-a":    {Role: holdout.RoleAcceptanceRunner, Repo: repo, Principal: "runner", Session: "s-r1", Assignment: "asg-1"},
	"runner-b":    {Role: holdout.RoleAcceptanceRunner, Repo: repo, Principal: "runner", Session: "s-r2", Assignment: "asg-2"},
	"sched-other": {Role: holdout.RoleAcceptanceScheduler, Repo: otherRepo, Principal: "sched", Session: "s-sch-o"},
	"runner-s1":   {Role: holdout.RoleAcceptanceRunner, Repo: repo, Principal: "runner", Session: "s-r1", Assignment: "asg-2"},
	"qe-bad":      {Role: holdout.RoleQE, Repo: repo, Assignment: holdout.SuiteID{Repo: repo}.Assignment(), Principal: "qe-agent", Session: "s-qe-bad"},
	"runner-o":    {Role: holdout.RoleAcceptanceRunner, Repo: otherRepo, Principal: "runner", Session: "s-r3", Assignment: "asg-1"},
	"qe-8":        {Role: holdout.RoleQE, Repo: repo, Assignment: suite8.Assignment(), Principal: "qe-agent", Session: "s-qe-8"},
	"reviewer-8":  {Role: holdout.RoleScenarioReviewer, Repo: repo, Assignment: suite8.Assignment(), Principal: "rev-agent", Session: "s-rev-8"},
	"qe-sibling":  {Role: holdout.RoleQE, Repo: repo, Assignment: suite8.Assignment(), Principal: "qe-agent", Session: "s-qe-sib"},
	"coder":       {Role: "coder", Repo: repo, Principal: "coder", Session: "s-c"},
	"pr-review":   {Role: "pr-reviewer", Repo: repo, Principal: "prr", Session: "s-p"},
	"spec":        {Role: "spec-writer", Repo: repo, Principal: "spec", Session: "s-s"},
	"ci":          {Role: "ci", Repo: repo, Principal: "ci", Session: "s-ci"},
	"human":       {Role: "human", Repo: repo, Principal: "github:1", Session: "s-h"},
	"no-session":  {Role: holdout.RoleQE, Repo: repo, Assignment: suite.Assignment(), Principal: "qe-agent"},
}

func newEnv(t *testing.T) *env {
	t.Helper()
	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	e := &env{t: t, now: &now}
	e.mem = audit.NewMemory()
	log, err := audit.New(e.mem, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	e.audit = &failAudit{inner: log}
	e.backend = &countingBackend{Backend: memholdout.New()}
	e.intents = &fakeIntents{st: approved(intentV1)}
	e.store, err = holdout.New(holdout.Config{
		Backend: e.backend, Verifier: fakeVerifier{m: workloads}, Intents: e.intents, Audit: e.audit,
		Clock: func() time.Time { return now }, GrantTTL: time.Hour, MaxRunDuration: 30 * time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func approved(intent string) holdout.IntentState {
	return holdout.IntentState{Approved: intent, ScenarioIDs: []string{"SC-1", "SC-2"}}
}

func bundle(parent holdout.Revision, intent string) holdout.Bundle {
	return holdout.Bundle{
		Suite: suite, Parent: parent, IntentRevision: intent,
		Scenarios: []holdout.Binding{
			{ScenarioID: "SC-2", Layer: "cypress", Entry: "case-b", Private: []string{"case-b2"}},
			{ScenarioID: "SC-1", Layer: "go-integration", Entry: "case-a", Private: []string{"case-a2", "case-a3"}},
		},
		Files: []holdout.File{
			{Path: "tests/b_test.go", Mode: 0o644, Kind: holdout.KindTest, Bytes: []byte("package b // " + secret)},
			{Path: "fixtures/data.json", Mode: 0o644, Kind: holdout.KindFixture, Bytes: []byte(`{"k":"` + secret + `"}`)},
		},
	}
}

// storeOn returns a store over the same collaborators with another backend (a wrapper), for fault injection.
func (e *env) storeOn(b holdout.Backend) *holdout.Store {
	e.t.Helper()
	st, err := holdout.New(holdout.Config{
		Backend: b, Verifier: fakeVerifier{m: workloads}, Intents: e.intents, Audit: e.audit,
		Clock: func() time.Time { return *e.now }, GrantTTL: time.Hour, MaxRunDuration: 30 * time.Minute,
	})
	if err != nil {
		e.t.Fatal(err)
	}
	return st
}

func (e *env) ctx() context.Context { return e.t.Context() }

func (e *env) propose(b holdout.Bundle) holdout.Revision {
	e.t.Helper()
	r, err := e.store.Propose(e.ctx(), "qe", b)
	if err != nil {
		e.t.Fatalf("propose: %v", err)
	}
	return r
}

func (e *env) review(cred holdout.Credential, rev holdout.Revision, intent string) error {
	_, err := e.store.Review(e.ctx(), cred, holdout.ReviewRequest{
		Suite: suite, Revision: rev, IntentRevision: intent, Verdict: holdout.VerdictApprove,
	})
	return err
}

// active proposes and approves a first revision.
func (e *env) active() holdout.Revision {
	e.t.Helper()
	rev := e.propose(bundle("", intentV1))
	if err := e.review("reviewer", rev, intentV1); err != nil {
		e.t.Fatalf("review: %v", err)
	}
	return rev
}

func runRecord(rev holdout.Revision, runID, assignment string) holdout.RunRecord {
	return holdout.RunRecord{
		RunID: runID, Suite: suite, SuiteRevision: rev, IntentRevision: intentV1,
		CandidateSHA:       strings.Repeat("a", 40),
		ArtifactDigest:     "sha256:" + strings.Repeat("b", 64),
		SwitchConfigDigest: "sha256:" + strings.Repeat("c", 64),
		Assignment:         assignment,
	}
}

func (e *env) grant(rev holdout.Revision, runID, assignment string) holdout.Grant {
	e.t.Helper()
	g, err := e.store.IssueGrant(e.ctx(), "scheduler", runRecord(rev, runID, assignment))
	if err != nil {
		e.t.Fatalf("issue grant: %v", err)
	}
	return g
}

func (e *env) auditText() string {
	e.t.Helper()
	entries, err := e.mem.Read(e.ctx(), 1, audit.MaxReadLimit)
	if err != nil {
		e.t.Fatal(err)
	}
	var sb strings.Builder
	for i := range entries {
		fmt.Fprintf(&sb, "%+v\n", entries[i])
	}
	return sb.String()
}

func TestRevisionDeterminism(t *testing.T) { // INT-7
	t.Parallel()
	a := bundle("", intentV1)
	b := bundle("", intentV1)
	b.Scenarios[0], b.Scenarios[1] = b.Scenarios[1], b.Scenarios[0] // order must not matter
	b.Files[0], b.Files[1] = b.Files[1], b.Files[0]
	if a.Revision() != b.Revision() {
		t.Fatal("same bundle, different revision")
	}
	if !strings.HasPrefix(string(a.Revision()), "sha256:") || len(a.Revision()) != len("sha256:")+64 {
		t.Fatalf("bad revision %q", a.Revision())
	}
	mutations := map[string]func(*holdout.Bundle){
		"intent":      func(b *holdout.Bundle) { b.IntentRevision = "intent-9" },
		"parent":      func(b *holdout.Bundle) { b.Parent = holdout.Revision("sha256:" + strings.Repeat("1", 64)) },
		"file byte":   func(b *holdout.Bundle) { b.Files[0].Bytes[0] ^= 1 },
		"file path":   func(b *holdout.Bundle) { b.Files[0].Path = "tests/c_test.go" },
		"file mode":   func(b *holdout.Bundle) { b.Files[0].Mode = 0o755 },
		"file kind":   func(b *holdout.Bundle) { b.Files[0].Kind = holdout.KindAssertion },
		"layer":       func(b *holdout.Bundle) { b.Scenarios[0].Layer = "other" },
		"entry":       func(b *holdout.Bundle) { b.Scenarios[0].Entry = "case-z" },
		"private":     func(b *holdout.Bundle) { b.Scenarios[0].Private = nil },
		"suite issue": func(b *holdout.Bundle) { b.Suite.Issue++ },
		"correction": func(b *holdout.Bundle) {
			b.Correction = &holdout.Correction{Replaces: "r", FailedRun: "run", Reason: "x"}
		},
	}
	for name, mut := range mutations {
		c := bundle("", intentV1)
		mut(&c)
		if c.Revision() == a.Revision() {
			t.Errorf("%s: change did not change the revision", name)
		}
	}
	// Length prefixing: moving a byte between adjacent fields must change the address.
	x, y := bundle("", intentV1), bundle("", intentV1)
	x.Files[0].Path, x.Files[0].Bytes = "ab", []byte("c")
	y.Files[0].Path, y.Files[0].Bytes = "a", []byte("bc")
	if x.Revision() == y.Revision() {
		t.Error("field boundary ambiguity")
	}
}

func TestLifecycle(t *testing.T) { // INT-6, INT-7, INT-9, PIP-15
	t.Parallel()
	e := newEnv(t)
	rev := e.active()

	got, err := e.store.Read(e.ctx(), "qe", suite, rev)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != holdout.StatusActive || got.Author.Principal != "qe-agent" || len(got.Bundle.Files) != 2 {
		t.Fatalf("read: %+v", got)
	}
	if _, ierr := e.store.Read(e.ctx(), "reviewer", suite, rev); ierr != nil {
		t.Fatalf("reviewer read: %v", ierr)
	}

	g := e.grant(rev, "run-1", "asg-1")
	if g.Attempt != 1 || !g.ExpiresAt.Equal(e.now.Add(time.Hour)) {
		t.Fatalf("grant: %+v", g)
	}
	rd, err := e.store.Open(e.ctx(), "runner-a", "run-1", 1)
	if err != nil {
		t.Fatal(err)
	}
	if rd.Revision() != rev || len(rd.Paths()) != 2 {
		t.Fatalf("reader: %v", rd.Paths())
	}
	f, ok := rd.File("tests/b_test.go")
	if !ok || !strings.Contains(string(f.Bytes), secret) {
		t.Fatal("reader lost file")
	}
	f.Bytes[0] = 'X' // a returned copy must not alias the store
	if f2, _ := rd.File("tests/b_test.go"); f2.Bytes[0] == 'X' {
		t.Fatal("reader aliases bytes")
	}
	if err := e.store.RecordOutcome(e.ctx(), "runner-a", "run-1", 1, holdout.Outcome{Passed: true}); err != nil {
		t.Fatal(err)
	}

	// Failure -> freeze -> correction -> review -> new grant.
	g2 := e.grant(rev, "run-2", "asg-2")
	if _, err := e.store.Open(e.ctx(), "runner-b", "run-2", g2.Attempt); err != nil {
		t.Fatal(err)
	}
	fail := holdout.Outcome{FailedScenarios: []string{"SC-1"}}
	if err := e.store.RecordOutcome(e.ctx(), "runner-b", "run-2", 1, fail); err != nil {
		t.Fatal(err)
	}
	frozen, _ := e.store.Read(e.ctx(), "qe", suite, rev)
	if frozen.Status != holdout.StatusFrozen {
		t.Fatalf("status %q, want frozen", frozen.Status)
	}
	// A frozen revision can be rerun (PIP-15).
	e.grant(rev, "run-3", "asg-3")

	corr := bundle(rev, intentV1)
	corr.Files[0].Bytes = []byte("package b // fixed " + secret)
	corr.Correction = &holdout.Correction{Replaces: rev, FailedRun: "run-2", Reason: "assertion was wrong"}
	rev2 := e.propose(corr)
	if _, err := e.store.IssueGrant(e.ctx(), "scheduler", runRecord(rev2, "run-4", "asg-1")); !errors.Is(err, holdout.ErrState) {
		t.Fatalf("grant on unreviewed correction: %v", err)
	}
	if err := e.review("reviewer", rev2, intentV1); err != nil {
		t.Fatal(err)
	}
	old, _ := e.store.Read(e.ctx(), "qe", suite, rev)
	if old.Status != holdout.StatusSuperseded {
		t.Fatalf("old status %q", old.Status)
	}
	e.grant(rev2, "run-5", "asg-5")

	if txt := e.auditText(); strings.Contains(txt, secret) {
		t.Fatal("audit log holds private bytes")
	}
}

func TestSEC11_DeniedCallersUniformAndNoBackendRead(t *testing.T) { // SEC-11, INT-6, AGT-2
	// Not parallel: the subtests share a backend call counter.
	e := newEnv(t)
	rev := e.active()
	e.grant(rev, "run-1", "asg-1")
	missing := holdout.Revision("sha256:" + strings.Repeat("9", 64))

	type call struct {
		name string
		fn   func(cred holdout.Credential, r holdout.Revision) error
		// roles that may make the call; every other cred must be denied.
		allowed map[holdout.Credential]bool
	}
	calls := []call{
		{"propose", func(c holdout.Credential, _ holdout.Revision) error {
			_, err := e.store.Propose(e.ctx(), c, bundle(rev, intentV2))
			return err
		}, map[holdout.Credential]bool{"qe": true, "qe2": true}},
		{"read", func(c holdout.Credential, r holdout.Revision) error {
			_, err := e.store.Read(e.ctx(), c, suite, r)
			return err
		}, map[holdout.Credential]bool{"qe": true, "qe2": true, "reviewer": true, "rev-sameP": true, "rev-sameS": true}},
		{"review", func(c holdout.Credential, r holdout.Revision) error {
			_, err := e.store.Review(e.ctx(), c, holdout.ReviewRequest{Suite: suite, Revision: r, IntentRevision: intentV1, Verdict: holdout.VerdictApprove})
			return err
		}, map[holdout.Credential]bool{"reviewer": true, "rev-sameP": true, "rev-sameS": true}},
		{"leak-check", func(c holdout.Credential, r holdout.Revision) error {
			_, err := e.store.LeakCheck(e.ctx(), c, holdout.LeakRequest{Suite: suite, Revision: r})
			return err
		}, map[holdout.Credential]bool{"qe": true, "qe2": true, "reviewer": true, "rev-sameP": true, "rev-sameS": true}},
		{"attest", func(c holdout.Credential, r holdout.Revision) error {
			return e.store.AttestCoverage(e.ctx(), c, holdout.CoverageRequest{Suite: suite, Revision: r})
		}, map[holdout.Credential]bool{"reviewer": true, "rev-sameP": true, "rev-sameS": true}},
		{"status", func(c holdout.Credential, _ holdout.Revision) error {
			_, err := e.store.Status(e.ctx(), c, suite)
			return err
		}, map[holdout.Credential]bool{"qe": true, "qe2": true, "reviewer": true, "rev-sameP": true, "rev-sameS": true, "scheduler": true}},
		{"issue-grant", func(c holdout.Credential, r holdout.Revision) error {
			_, err := e.store.IssueGrant(e.ctx(), c, runRecord(r, "run-x", "asg-1"))
			return err
		}, map[holdout.Credential]bool{"scheduler": true}},
		{"open", func(c holdout.Credential, _ holdout.Revision) error {
			_, err := e.store.Open(e.ctx(), c, "run-1", 1)
			return err
		}, map[holdout.Credential]bool{"runner-a": true, "runner-b": true, "runner-o": true}},
		{"record-outcome", func(c holdout.Credential, _ holdout.Revision) error {
			return e.store.RecordOutcome(e.ctx(), c, "run-1", 1, holdout.Outcome{Passed: true})
		}, map[holdout.Credential]bool{"runner-a": true, "runner-b": true, "runner-o": true}},
	}
	creds := []holdout.Credential{
		"coder", "pr-review", "spec", "ci", "human", "no-session", "unknown-credential", "",
		"qe-other", "rev-other", "sched-other", "qe-8", "reviewer-8", "qe-sibling", "scheduler", "runner-a", "runner-b", "runner-o", "qe", "qe2", "reviewer",
	}
	for _, c := range calls {
		for _, cred := range creds {
			// Denied by role or repo alone must be identical for existing and missing revisions, and read nothing.
			if c.allowed[cred] {
				continue
			}
			t.Run(c.name+"/"+string(cred), func(t *testing.T) {
				before := e.backend.calls.Load()
				errExisting := c.fn(cred, rev)
				errMissing := c.fn(cred, missing)
				if !errors.Is(errExisting, holdout.ErrDenied) {
					t.Fatalf("existing: got %v, want ErrDenied", errExisting)
				}
				if errExisting != errMissing { //nolint:errorlint // identity is the point: the very same sentinel
					t.Fatalf("errors differ: %v vs %v", errExisting, errMissing)
				}
				if errExisting.Error() != holdout.ErrDenied.Error() {
					t.Fatalf("denial carries detail: %q", errExisting)
				}
				if n := e.backend.calls.Load() - before; n != 0 {
					t.Fatalf("denied caller caused %d backend calls", n)
				}
			})
		}
	}
}

func TestSEC11_RolesNotListedAreDeniedEverywhere(t *testing.T) { // SEC-11
	t.Parallel()
	e := newEnv(t)
	rev := e.active()
	// Wrong-but-known roles (qe cannot review, reviewer cannot propose, ...).
	if _, err := e.store.Review(e.ctx(), "qe", holdout.ReviewRequest{Suite: suite, Revision: rev, IntentRevision: intentV1, Verdict: holdout.VerdictApprove}); !errors.Is(err, holdout.ErrDenied) {
		t.Errorf("QE review: %v", err)
	}
	if _, err := e.store.Propose(e.ctx(), "reviewer", bundle(rev, intentV1)); !errors.Is(err, holdout.ErrDenied) {
		t.Errorf("reviewer propose: %v", err)
	}
	if _, err := e.store.IssueGrant(e.ctx(), "qe", runRecord(rev, "r", "asg-1")); !errors.Is(err, holdout.ErrDenied) {
		t.Errorf("QE issue grant: %v", err)
	}
	if _, err := e.store.Open(e.ctx(), "qe", "r", 1); !errors.Is(err, holdout.ErrDenied) {
		t.Errorf("QE open: %v", err)
	}
	if _, err := e.store.Read(e.ctx(), "scheduler", suite, rev); !errors.Is(err, holdout.ErrDenied) {
		t.Errorf("scheduler read: %v", err)
	}
	if _, err := e.store.Read(e.ctx(), "runner-a", suite, rev); !errors.Is(err, holdout.ErrDenied) {
		t.Errorf("runner read: %v", err)
	}
}

func TestDenialsAreAudited(t *testing.T) { // SEC-11
	t.Parallel()
	e := newEnv(t)
	rev := e.active()
	_, _ = e.store.Read(e.ctx(), "coder", suite, rev)
	_, _ = e.store.Read(e.ctx(), "bogus", suite, rev)
	txt := e.auditText()
	for _, want := range []string{"holdout.read", "denied", "role", "unverified"} {
		if !strings.Contains(txt, want) {
			t.Errorf("audit lacks %q", want)
		}
	}
}

func TestRunnerGrantAbuse(t *testing.T) { // INT-6, SEC-11
	t.Parallel()
	e := newEnv(t)
	rev := e.active()
	e.grant(rev, "run-1", "asg-1")
	e.grant(rev, "run-2", "asg-2")

	denied := func(name string, cred holdout.Credential, run string, attempt int) {
		t.Helper()
		if _, err := e.store.Open(e.ctx(), cred, run, attempt); !errors.Is(err, holdout.ErrDenied) {
			t.Errorf("%s: got %v, want ErrDenied", name, err)
		}
	}
	denied("grant for another run (assignment mismatch)", "runner-b", "run-1", 1)
	denied("another run, other assignment", "runner-a", "run-2", 1)
	denied("unknown run", "runner-a", "nope", 1)
	denied("runner of another repo", "runner-o", "run-1", 1)
	denied("wrong attempt number", "runner-a", "run-1", 2)

	if _, err := e.store.Open(e.ctx(), "runner-a", "run-1", 1); err != nil {
		t.Fatal(err)
	}
	denied("reused", "runner-a", "run-1", 1) // once per attempt

	// Expired.
	*e.now = e.now.Add(2 * time.Hour)
	denied("expired", "runner-b", "run-2", 1)
}

func TestFencedAttempts(t *testing.T) { // INT-6, SEC-11
	t.Parallel()
	e := newEnv(t)
	rev := e.active()
	e.grant(rev, "run-1", "asg-1")
	if _, err := e.store.Open(e.ctx(), "runner-a", "run-1", 1); err != nil {
		t.Fatal(err)
	}
	g2 := e.grant(rev, "run-1", "asg-2") // replacement attempt fences attempt 1
	if g2.Attempt != 2 {
		t.Fatalf("attempt %d", g2.Attempt)
	}
	if err := e.store.RecordOutcome(e.ctx(), "runner-a", "run-1", 1, holdout.Outcome{Passed: true}); !errors.Is(err, holdout.ErrDenied) {
		t.Errorf("fenced outcome: %v", err)
	}
	if _, err := e.store.Open(e.ctx(), "runner-a", "run-1", 1); !errors.Is(err, holdout.ErrDenied) {
		t.Errorf("fenced open: %v", err)
	}
	if err := e.store.RecordOutcome(e.ctx(), "runner-b", "run-1", 2, holdout.Outcome{Passed: true}); !errors.Is(err, holdout.ErrDenied) {
		t.Errorf("outcome before open: %v", err)
	}
	if _, err := e.store.Open(e.ctx(), "runner-b", "run-1", 2); err != nil {
		t.Fatal(err)
	}
	if err := e.store.RecordOutcome(e.ctx(), "runner-b", "run-1", 2, holdout.Outcome{FailedScenarios: []string{"SC-1"}}); err != nil {
		t.Fatal(err)
	}
	if err := e.store.RecordOutcome(e.ctx(), "runner-b", "run-1", 2, holdout.Outcome{Passed: true}); !errors.Is(err, holdout.ErrDenied) {
		t.Errorf("second outcome: %v", err)
	}
	// A pinned run cannot change inputs for a replacement attempt.
	rr := runRecord(rev, "run-1", "asg-3")
	rr.CandidateSHA = strings.Repeat("d", 40)
	if _, err := e.store.IssueGrant(e.ctx(), "scheduler", rr); !errors.Is(err, holdout.ErrConflict) {
		t.Errorf("changed pin: %v", err)
	}
}

func TestOutcomeValidation(t *testing.T) { // PIP-15
	t.Parallel()
	e := newEnv(t)
	rev := e.active()
	e.grant(rev, "run-1", "asg-1")
	if _, err := e.store.Open(e.ctx(), "runner-a", "run-1", 1); err != nil {
		t.Fatal(err)
	}
	for name, o := range map[string]holdout.Outcome{
		"passed with failures": {Passed: true, FailedScenarios: []string{"SC-1"}},
		"unknown scenario":     {FailedScenarios: []string{"SC-99"}},
	} {
		if err := e.store.RecordOutcome(e.ctx(), "runner-a", "run-1", 1, o); !errors.Is(err, holdout.ErrDenied) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestReviewIndependenceAndAuthority(t *testing.T) { // INT-9
	t.Parallel()
	e := newEnv(t)
	rev := e.propose(bundle("", intentV1))
	for _, cred := range []holdout.Credential{"rev-sameP", "rev-sameS"} {
		if err := e.review(cred, rev, intentV1); !errors.Is(err, holdout.ErrNotIndependent) {
			t.Errorf("%s: got %v, want ErrNotIndependent", cred, err)
		}
	}
	if err := e.review("reviewer", rev, "intent-other"); !errors.Is(err, holdout.ErrIntentMismatch) {
		t.Errorf("wrong named intent: %v", err)
	}
	if err := e.review("reviewer", rev, intentV1); err != nil {
		t.Fatal(err)
	}
	if err := e.review("reviewer", rev, intentV1); !errors.Is(err, holdout.ErrState) {
		t.Errorf("second review: %v", err)
	}
}

func TestReviewRejectReturnsMismatchedIDs(t *testing.T) { // INT-9
	t.Parallel()
	e := newEnv(t)
	rev := e.propose(bundle("", intentV1))
	res, err := e.store.Review(e.ctx(), "reviewer", holdout.ReviewRequest{
		Suite: suite, Revision: rev, IntentRevision: intentV1, Verdict: holdout.VerdictReject, Mismatched: []string{"SC-2", "SC-1", "SC-2"}, Reason: "coverage gap",
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != holdout.StatusRejected || strings.Join(res.Mismatched, ",") != "SC-1,SC-2" {
		t.Fatalf("result %+v", res)
	}
	// A rejected revision reverts the head, so the next proposal starts from the same parent again.
	next := bundle("", intentV1)
	next.Files[0].Bytes = []byte("second try")
	e.propose(next)
}

func TestReviewRejectNeedsIDs(t *testing.T) { // INT-9
	t.Parallel()
	e := newEnv(t)
	rev := e.propose(bundle("", intentV1))
	_, err := e.store.Review(e.ctx(), "reviewer", holdout.ReviewRequest{Suite: suite, Revision: rev, IntentRevision: intentV1, Verdict: holdout.VerdictReject})
	if !errors.Is(err, holdout.ErrInvalid) {
		t.Fatalf("got %v", err)
	}
}

func TestReviewChecksBoundScenariosAgainstApproved(t *testing.T) { // INT-9
	t.Parallel()
	e := newEnv(t)
	e.intents.set(holdout.IntentState{Approved: intentV1, ScenarioIDs: []string{"SC-1", "SC-2", "SC-3"}})
	rev := e.propose(bundle("", intentV1))
	err := e.review("reviewer", rev, intentV1)
	var mm *holdout.MismatchError
	if !errors.As(err, &mm) || strings.Join(mm.ScenarioIDs, ",") != "SC-3" {
		t.Fatalf("got %v", err)
	}
}

func TestStaleAndPendingIntentBlock(t *testing.T) { // INT-9, SEC-10
	t.Parallel()
	t.Run("review", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t)
		rev := e.propose(bundle("", intentV1))
		e.intents.set(holdout.IntentState{Approved: intentV1, Pending: true, ScenarioIDs: []string{"SC-1", "SC-2"}})
		if err := e.review("reviewer", rev, intentV1); !errors.Is(err, holdout.ErrIntentPending) {
			t.Errorf("pending: %v", err)
		}
		e.intents.set(approved(intentV2))
		if err := e.review("reviewer", rev, intentV1); !errors.Is(err, holdout.ErrStaleIntent) {
			t.Errorf("stale: %v", err)
		}
	})
	t.Run("issue grant and open", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t)
		rev := e.active()
		e.grant(rev, "run-1", "asg-1")
		e.intents.set(holdout.IntentState{Approved: intentV1, Pending: true, ScenarioIDs: []string{"SC-1", "SC-2"}})
		if _, err := e.store.IssueGrant(e.ctx(), "scheduler", runRecord(rev, "run-2", "asg-1")); !errors.Is(err, holdout.ErrIntentPending) {
			t.Errorf("pending grant: %v", err)
		}
		if _, err := e.store.Open(e.ctx(), "runner-a", "run-1", 1); !errors.Is(err, holdout.ErrDenied) {
			t.Errorf("pending open: %v", err)
		}
		// The pending edit is withdrawn: the grant works again (not consumed by the refusal).
		e.intents.set(approved(intentV1))
		if _, err := e.store.Open(e.ctx(), "runner-a", "run-1", 1); err != nil {
			t.Errorf("open after withdrawal: %v", err)
		}
	})
	t.Run("stale revision", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t)
		rev := e.active()
		e.grant(rev, "run-1", "asg-1")
		e.intents.set(approved(intentV2))
		if _, err := e.store.IssueGrant(e.ctx(), "scheduler", runRecord(rev, "run-2", "asg-1")); !errors.Is(err, holdout.ErrStaleIntent) {
			t.Errorf("stale grant: %v", err)
		}
		if _, err := e.store.Open(e.ctx(), "runner-a", "run-1", 1); !errors.Is(err, holdout.ErrDenied) {
			t.Errorf("stale open: %v", err)
		}
		got, _ := e.store.Read(e.ctx(), "qe", suite, rev)
		if got.Status != holdout.StatusStale {
			t.Errorf("status %q, want stale", got.Status)
		}
		// Even if the old intent is somehow re-approved, a stale revision stays ineligible.
		e.intents.set(approved(intentV1))
		if _, err := e.store.IssueGrant(e.ctx(), "scheduler", runRecord(rev, "run-3", "asg-1")); !errors.Is(err, holdout.ErrState) {
			t.Errorf("stale stays stale: %v", err)
		}
		// A new revision for the new intent restores progress.
		e.intents.set(approved(intentV2))
		n := e.propose(bundle(rev, intentV2))
		if err := e.review("reviewer", n, intentV2); err != nil {
			t.Fatal(err)
		}
	})
}

func TestIssueGrantValidation(t *testing.T) { // INT-7
	t.Parallel()
	e := newEnv(t)
	rev := e.active()
	unreviewed := e.propose(bundle(rev, intentV1)) // proposed, not active
	bad := runRecord(rev, "run-1", "asg-1")
	bad.CandidateSHA = "main"
	if _, err := e.store.IssueGrant(e.ctx(), "scheduler", bad); !errors.Is(err, holdout.ErrInvalid) {
		t.Errorf("bad sha: %v", err)
	}
	if _, err := e.store.IssueGrant(e.ctx(), "scheduler", runRecord(unreviewed, "run-2", "asg-1")); !errors.Is(err, holdout.ErrState) {
		t.Errorf("unreviewed: %v", err)
	}
	wrongIntent := runRecord(rev, "run-3", "asg-1")
	wrongIntent.IntentRevision = intentV2
	if _, err := e.store.IssueGrant(e.ctx(), "scheduler", wrongIntent); !errors.Is(err, holdout.ErrIntentMismatch) {
		t.Errorf("wrong intent: %v", err)
	}
	// Open of a revision that was never made active is impossible: no grant exists.
	if _, err := e.store.Open(e.ctx(), "runner-a", "run-2", 1); !errors.Is(err, holdout.ErrDenied) {
		t.Errorf("open without grant: %v", err)
	}
}

func TestProposeCAS(t *testing.T) { // INT-7
	t.Parallel()
	e := newEnv(t)
	rev := e.active()
	b := bundle(rev, intentV1)
	b.Files[0].Bytes = []byte("v2")
	e.propose(b)
	c := bundle(rev, intentV1) // old parent, different content
	c.Files[0].Bytes = []byte("v3")
	if _, err := e.store.Propose(e.ctx(), "qe2", c); !errors.Is(err, holdout.ErrConflict) {
		t.Errorf("old parent: %v", err)
	}
	if _, err := e.store.Propose(e.ctx(), "qe", b); !errors.Is(err, holdout.ErrConflict) {
		t.Errorf("duplicate: %v", err)
	}
	// The head awaits review, so a proposal on top of it is refused too.
	d := bundle(b.Revision(), intentV1)
	d.Files[0].Bytes = []byte("v4")
	if _, err := e.store.Propose(e.ctx(), "qe", d); !errors.Is(err, holdout.ErrState) {
		t.Errorf("on top of pending head: %v", err)
	}
}

func TestProposeValidation(t *testing.T) { // INT-6
	t.Parallel()
	e := newEnv(t)
	tests := map[string]func(*holdout.Bundle){
		"no scenarios":       func(b *holdout.Bundle) { b.Scenarios = nil },
		"duplicate scenario": func(b *holdout.Bundle) { b.Scenarios[1].ScenarioID = b.Scenarios[0].ScenarioID },
		"duplicate case":     func(b *holdout.Bundle) { b.Scenarios[0].Private = []string{b.Scenarios[0].Entry} },
		"path traversal":     func(b *holdout.Bundle) { b.Files[0].Path = "../x" },
		"absolute path":      func(b *holdout.Bundle) { b.Files[0].Path = "/etc/x" },
		"wildcard path":      func(b *holdout.Bundle) { b.Files[0].Path = "a/*.go" },
		"duplicate path":     func(b *holdout.Bundle) { b.Files[1].Path = b.Files[0].Path },
		"bad mode":           func(b *holdout.Bundle) { b.Files[0].Mode = 0o777 },
		"bad kind":           func(b *holdout.Bundle) { b.Files[0].Kind = "x" },
		"file too large":     func(b *holdout.Bundle) { b.Files[0].Bytes = make([]byte, holdout.MaxFileBytes+1) },
		"too many files":     func(b *holdout.Bundle) { b.Files = make([]holdout.File, holdout.MaxFiles+1) },
		"empty intent":       func(b *holdout.Bundle) { b.IntentRevision = "" },
		"correction no parent": func(b *holdout.Bundle) {
			b.Correction = &holdout.Correction{Replaces: holdout.Revision("sha256:" + strings.Repeat("1", 64)), FailedRun: "r", Reason: "x"}
		},
	}
	for name, mut := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			b := bundle("", intentV1)
			mut(&b)
			if _, err := e.store.Propose(e.ctx(), "qe", b); !errors.Is(err, holdout.ErrInvalid) {
				t.Fatalf("got %v, want ErrInvalid", err)
			}
		})
	}
	// Bundles for another repo are denied, not invalid.
	b := bundle("", intentV1)
	b.Suite.Repo = otherRepo
	if _, err := e.store.Propose(e.ctx(), "qe", b); !errors.Is(err, holdout.ErrDenied) {
		t.Errorf("foreign repo: %v", err)
	}
}

func TestFreezeAndCorrection(t *testing.T) { // INT-9, PIP-15
	t.Parallel()
	e := newEnv(t)
	rev := e.active()
	e.grant(rev, "run-1", "asg-1")
	if _, err := e.store.Open(e.ctx(), "runner-a", "run-1", 1); err != nil {
		t.Fatal(err)
	}
	if err := e.store.RecordOutcome(e.ctx(), "runner-a", "run-1", 1, holdout.Outcome{FailedScenarios: []string{"SC-2"}}); err != nil {
		t.Fatal(err)
	}

	plain := bundle(rev, intentV1)
	plain.Files[0].Bytes = []byte("tweak")
	if _, err := e.store.Propose(e.ctx(), "qe", plain); !errors.Is(err, holdout.ErrFrozen) {
		t.Fatalf("plain successor of frozen: %v", err)
	}

	// Another suite's failed run, and an unknown run, are refused.
	otherSuite := holdout.SuiteID{Repo: repo, Issue: 8}
	foreign := bundle("", intentV1)
	foreign.Suite = otherSuite
	foreignRev, perr := e.store.Propose(e.ctx(), "qe-8", foreign)
	if perr != nil {
		t.Fatal(perr)
	}
	if _, err := e.store.Review(e.ctx(), "reviewer-8", holdout.ReviewRequest{Suite: otherSuite, Revision: foreignRev, IntentRevision: intentV1, Verdict: holdout.VerdictApprove}); err != nil {
		t.Fatal(err)
	}
	rr := runRecord(foreignRev, "run-foreign", "asg-9")
	rr.Suite = otherSuite
	if _, err := e.store.IssueGrant(e.ctx(), "scheduler", rr); err != nil {
		t.Fatal(err)
	}
	if _, err := e.store.Open(e.ctx(), "runner:asg-9", "run-foreign", 1); err != nil {
		t.Fatal(err)
	}
	if err := e.store.RecordOutcome(e.ctx(), "runner:asg-9", "run-foreign", 1, holdout.Outcome{FailedScenarios: []string{"SC-1"}}); err != nil {
		t.Fatal(err)
	}
	for name, failedRun := range map[string]string{"another suite's run": "run-foreign", "unknown run": "run-none"} {
		c := plain
		c.Correction = &holdout.Correction{Replaces: rev, FailedRun: failedRun, Reason: "fix"}
		if _, err := e.store.Propose(e.ctx(), "qe", c); !errors.Is(err, holdout.ErrBadCorrection) {
			t.Errorf("%s: %v", name, err)
		}
	}

	// Another revision's failure: run on a second revision of this suite cannot unlock the first.
	// (Simulated by citing a revision that is not the frozen head.)
	c := plain
	c.Correction = &holdout.Correction{Replaces: holdout.Revision("sha256:" + strings.Repeat("7", 64)), FailedRun: "run-1", Reason: "fix"}
	if _, err := e.store.Propose(e.ctx(), "qe", c); !errors.Is(err, holdout.ErrInvalid) {
		t.Errorf("replaces non-parent: %v", err)
	}

	// A correction of a revision that never failed is refused.
	// The good correction goes through but needs its own review.
	good := plain
	good.Correction = &holdout.Correction{Replaces: rev, FailedRun: "run-1", Reason: "fix"}
	grev, err := e.store.Propose(e.ctx(), "qe", good)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.review("rev-sameP", grev, intentV1); !errors.Is(err, holdout.ErrNotIndependent) {
		t.Errorf("author principal reviewing own correction: %v", err)
	}
}

func TestCorrectionOfUnfrozenRevisionRefused(t *testing.T) { // INT-9
	t.Parallel()
	e := newEnv(t)
	rev := e.active()
	c := bundle(rev, intentV1)
	c.Files[0].Bytes = []byte("tweak")
	c.Correction = &holdout.Correction{Replaces: rev, FailedRun: "run-1", Reason: "fix"}
	if _, err := e.store.Propose(e.ctx(), "qe", c); !errors.Is(err, holdout.ErrBadCorrection) {
		t.Fatalf("got %v", err)
	}
}

func TestFrozenStaysFrozenAfterIntentChange(t *testing.T) { // INT-9, PIP-15
	t.Parallel()
	e := newEnv(t)
	rev := e.active()
	e.grant(rev, "run-1", "asg-1")
	if _, err := e.store.Open(e.ctx(), "runner-a", "run-1", 1); err != nil {
		t.Fatal(err)
	}
	if err := e.store.RecordOutcome(e.ctx(), "runner-a", "run-1", 1, holdout.Outcome{FailedScenarios: []string{"SC-1"}}); err != nil {
		t.Fatal(err)
	}
	e.intents.set(approved(intentV2))
	next := bundle(rev, intentV2)
	if _, err := e.store.Propose(e.ctx(), "qe", next); !errors.Is(err, holdout.ErrFrozen) {
		t.Fatalf("got %v", err)
	}
}

func TestLeakCheck(t *testing.T) { // INT-7
	t.Parallel()
	e := newEnv(t)
	rev := e.active()
	got, err := e.store.Read(e.ctx(), "qe", suite, rev)
	if err != nil {
		t.Fatal(err)
	}
	var fixture holdout.File
	for i := range got.Bundle.Files {
		if f := got.Bundle.Files[i]; f.Kind == holdout.KindFixture {
			fixture = f
		}
	}
	digest := sha256Hex(fixture.Bytes)
	rep, err := e.store.LeakCheck(e.ctx(), "qe", holdout.LeakRequest{
		Suite: suite, Revision: rev,
		Files: []holdout.PublicFile{
			{Path: "e2e/copied_test.go", Bytes: got.Bundle.Files[1].Bytes},
			{Path: "e2e/ok_test.go", Bytes: []byte("package e2e // public")},
			{Path: "e2e/empty.txt"},
		},
		Digests: []holdout.PublicDigest{{Path: "e2e/data.bin", SHA256: digest}, {Path: "e2e/other.bin", SHA256: strings.Repeat("0", 64)}},
	})
	if err != nil {
		t.Fatal(err)
	}
	var paths []string
	for _, f := range rep.Findings {
		paths = append(paths, f.Path+":"+string(f.Kind))
	}
	want := "e2e/copied_test.go:file-copy,e2e/data.bin:fixture-digest"
	if strings.Join(paths, ",") != want {
		t.Fatalf("findings %v, want %s", paths, want)
	}
	if strings.Contains(fmt.Sprintf("%+v", rep), secret) {
		t.Fatal("report contains private text")
	}
	clean, err := e.store.LeakCheck(e.ctx(), "qe", holdout.LeakRequest{
		Suite: suite, Revision: rev,
		Files: []holdout.PublicFile{{Path: "a.go", Bytes: []byte("package a")}},
	})
	if err != nil || !clean.Clean() {
		t.Fatalf("clean: %v %+v", err, clean)
	}
	if _, err := e.store.LeakCheck(e.ctx(), "qe", holdout.LeakRequest{
		Suite: suite, Revision: rev,
		Files: []holdout.PublicFile{{Path: "../x"}},
	}); !errors.Is(err, holdout.ErrInvalid) {
		t.Errorf("bad path: %v", err)
	}
	if _, err := e.store.LeakCheck(e.ctx(), "qe", holdout.LeakRequest{Suite: suite, Revision: holdout.Revision("sha256:" + strings.Repeat("9", 64))}); !errors.Is(err, holdout.ErrNotFound) {
		t.Errorf("missing: %v", err)
	}
}

func TestAttestCoverage(t *testing.T) { // INT-7
	t.Parallel()
	e := newEnv(t)
	rev := e.active()
	req := holdout.CoverageRequest{Suite: suite, Revision: rev, Disclosed: []string{"case-a"}}
	if err := e.store.AttestCoverage(e.ctx(), "reviewer", req); err != nil {
		t.Fatal(err)
	}
	req.Disclosed = []string{"case-a", "case-b", "case-b2"} // SC-2 has nothing left
	var ce *holdout.CoverageError
	if err := e.store.AttestCoverage(e.ctx(), "reviewer", req); !errors.As(err, &ce) || strings.Join(ce.ScenarioIDs, ",") != "SC-2" {
		t.Errorf("got %v", err)
	}
	req.Disclosed = []string{"case-a", "nonexistent"}
	if err := e.store.AttestCoverage(e.ctx(), "reviewer", req); !errors.Is(err, holdout.ErrInvalid) {
		t.Errorf("unknown case: %v", err)
	}
	req.Disclosed = []string{"case-a", "case-a2"}
	if err := e.store.AttestCoverage(e.ctx(), "reviewer", req); err != nil {
		t.Errorf("superset: %v", err)
	}
	e.intents.set(approved(intentV2))
	if err := e.store.AttestCoverage(e.ctx(), "reviewer", req); !errors.Is(err, holdout.ErrStaleIntent) {
		t.Errorf("stale: %v", err)
	}
}

func TestFailedAuditReleasesNothing(t *testing.T) { // AGT-2, INT-6
	t.Parallel()
	e := newEnv(t)
	rev := e.active()
	e.grant(rev, "run-1", "asg-1")
	e.audit.fail.Store(true)

	got, err := e.store.Read(e.ctx(), "qe", suite, rev)
	if !errors.Is(err, holdout.ErrAudit) || got.Bundle.Files != nil || got.Revision != "" {
		t.Errorf("read released data: %v %+v", err, got)
	}
	rd, err := e.store.Open(e.ctx(), "runner-a", "run-1", 1)
	if !errors.Is(err, holdout.ErrAudit) || rd != nil {
		t.Errorf("open released a reader: %v", err)
	}
	if rep, err := e.store.LeakCheck(e.ctx(), "qe", holdout.LeakRequest{Suite: suite, Revision: rev}); !errors.Is(err, holdout.ErrAudit) || len(rep.Findings) != 0 {
		t.Errorf("leak check: %v", err)
	}
	if _, err := e.store.Propose(e.ctx(), "qe", bundle(rev, intentV1)); !errors.Is(err, holdout.ErrAudit) {
		t.Errorf("propose: %v", err)
	}

	// Nothing changed: the grant was not consumed, and no revision was stored.
	e.audit.fail.Store(false)
	if _, err := e.store.Open(e.ctx(), "runner-a", "run-1", 1); err != nil {
		t.Errorf("grant consumed by failed audit: %v", err)
	}
	if _, err := e.store.Propose(e.ctx(), "qe", bundle(rev, intentV1)); err != nil {
		t.Errorf("head moved by failed propose: %v", err)
	}
}

func TestAuditEntriesHoldNoPrivateBytes(t *testing.T) { // AGT-2
	t.Parallel()
	e := newEnv(t)
	rev := e.active()
	e.grant(rev, "run-1", "asg-1")
	_, _ = e.store.Open(e.ctx(), "runner-a", "run-1", 1)
	_, _ = e.store.LeakCheck(e.ctx(), "qe", holdout.LeakRequest{Suite: suite, Revision: rev, Files: []holdout.PublicFile{{Path: "a.go", Bytes: []byte(secret)}}})
	txt := e.auditText()
	if strings.Contains(txt, secret) || strings.Contains(txt, "b_test.go") {
		t.Fatal("audit log holds private data")
	}
	for _, want := range []string{"holdout.propose", "holdout.review", "holdout.issue-grant", "holdout.open", "holdout.leak-check"} {
		if !strings.Contains(txt, want) {
			t.Errorf("audit lacks %s", want)
		}
	}
}

func TestConcurrentOpenSucceedsOnce(t *testing.T) { // INT-6
	t.Parallel()
	e := newEnv(t)
	rev := e.active()
	e.grant(rev, "run-1", "asg-1")
	var ok atomic.Int64
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := e.store.Open(e.ctx(), "runner-a", "run-1", 1); err == nil {
				ok.Add(1)
			}
		}()
	}
	wg.Wait()
	if ok.Load() != 1 {
		t.Fatalf("%d opens succeeded, want 1", ok.Load())
	}
}

func TestConcurrentProposeForksNothing(t *testing.T) { // INT-7
	t.Parallel()
	e := newEnv(t)
	rev := e.active()
	var ok atomic.Int64
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			b := bundle(rev, intentV1)
			b.Files[0].Bytes = fmt.Appendf(nil, "v%d", i)
			if _, err := e.store.Propose(e.ctx(), "qe", b); err == nil {
				ok.Add(1)
			}
		}()
	}
	wg.Wait()
	if ok.Load() != 1 {
		t.Fatalf("%d proposals won, want 1", ok.Load())
	}
}

func TestNewRequiresCollaborators(t *testing.T) {
	t.Parallel()
	if _, err := holdout.New(holdout.Config{}); err == nil {
		t.Fatal("empty config accepted")
	}
}
