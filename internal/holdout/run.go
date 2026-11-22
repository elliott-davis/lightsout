// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

package holdout

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"strconv"
)

// IssueGrant records an Acceptance run attempt and returns its grant. Only the acceptance scheduler may call it
// (WI-24). The run record must name an active (or frozen) suite revision whose bundle intent equals the record's
// and the current approved intent. When the suite has disclosed private cases (INT-7), the revision must carry an
// attestation covering all of them.
//
// Run IDs and assignments are globally unique: an assignment is bound to exactly one attempt, ever, so a fenced
// runner credential cannot open a later attempt and one credential cannot open two runs. A second call for the
// same run ID with the same pinned inputs issues a replacement attempt that fences every earlier one, but only
// while no attempt of the run has recorded an outcome (pass or fail); a rerun after an outcome needs a new run ID.
func (s *Store) IssueGrant(ctx context.Context, cred Credential, rr RunRecord) (Grant, error) { // INT-7
	const op = "issue-grant"
	w, err := s.authorize(ctx, cred, op, &rr.Suite, RoleAcceptanceScheduler)
	if err != nil {
		return Grant{}, err
	}
	if cerr := s.checkSuite(ctx, w, op, rr.Suite); cerr != nil {
		return Grant{}, cerr
	}
	if err = rr.validate(); err != nil {
		s.refused(ctx, w, op, rr.Suite, err)
		return Grant{}, err
	}
	var g Grant
	err = s.run(ctx, w, op, rr.Suite, func(st *State, tx WriteTx) error {
		rec := st.Revisions[rr.SuiteRevision]
		switch {
		case rec == nil:
			return ErrNotFound
		case !rec.Status.usable():
			return ErrState
		case rec.Bundle.IntentRevision != rr.IntentRevision:
			return ErrIntentMismatch
		}
		if _, ierr := s.intentCheck(ctx, rec); ierr != nil {
			return ierr
		}
		if !attestationCovers(st, rec) {
			return ErrNotAttested
		}
		run := st.Runs[rr.RunID]
		if owner, taken := tx.RunSuite(rr.RunID); taken && (run == nil || owner != rr.Suite) {
			return ErrConflict
		}
		if run != nil && (!run.Record.samePin(rr) || slices.ContainsFunc(run.Attempts, hasOutcome)) {
			return ErrConflict
		}
		if tx.AssignmentBound(rr.Assignment) {
			return ErrConflict
		}
		attempt := 1
		if run != nil {
			attempt = len(run.Attempts) + 1
		}
		attrs := map[string]string{
			attrRevision: string(rr.SuiteRevision), attrRunID: clean(rr.RunID), attrAttempt: strconv.Itoa(attempt),
			"candidate": rr.CandidateSHA, "artifact": rr.ArtifactDigest, "switch_config": rr.SwitchConfigDigest,
			"intent_revision": clean(rr.IntentRevision), "assignment": clean(rr.Assignment),
		}
		if ierr := s.commitAudit(ctx, w, op, rr.Suite, attrs); ierr != nil {
			return abort(ierr)
		}
		if run == nil {
			run = &RunState{Record: rr}
			st.Runs[rr.RunID] = run
		}
		run.Attempts = append(run.Attempts, AttemptState{
			Number: attempt, Assignment: rr.Assignment, ExpiresAt: s.cfg.Clock().Add(s.cfg.GrantTTL),
		})
		g = Grant{RunID: rr.RunID, Attempt: attempt, ExpiresAt: run.Attempts[len(run.Attempts)-1].ExpiresAt}
		return nil
	})
	if err != nil {
		return Grant{}, err
	}
	return g, nil
}

func hasOutcome(a AttemptState) bool { return a.Outcome != nil }

// attestationCovers reports whether the suite has no disclosures, or rec carries an attestation that includes all of
// them (INT-7 requalification).
func attestationCovers(st *State, rec *RevisionRecord) bool {
	if len(st.Disclosed) == 0 {
		return true
	}
	if rec.Attestation == nil {
		return false
	}
	for id := range st.Disclosed {
		if !rec.Attestation.Disclosed[id] {
			return false
		}
	}
	return true
}

// Reader is a read-only view of one revision's private files, handed to the acceptance runner. It holds private
// bytes and must stay outside the candidate's sandbox (WI-24).
type Reader struct {
	suite SuiteID
	rev   Revision
	files map[string]File
	paths []string
}

// Suite returns the suite the reader belongs to.
func (r *Reader) Suite() SuiteID { return r.suite }

// Revision returns the revision the reader is scoped to.
func (r *Reader) Revision() Revision { return r.rev }

// Paths returns the file paths in order.
func (r *Reader) Paths() []string { return slices.Clone(r.paths) }

// File returns a copy of the file at path.
func (r *Reader) File(path string) (File, bool) {
	f, ok := r.files[path]
	f.Bytes = bytes.Clone(f.Bytes)
	return f, ok
}

// Runner denial reasons for the audit log. The caller always sees the bare [ErrDenied].
const (
	reasonUnknown      = "unknown"
	reasonFenced       = "fenced"
	reasonExpired      = "expired"
	reasonReused       = "reused"
	reasonUnusable     = "unusable"
	reasonStale        = "stale"
	reasonPending      = "pending"
	reasonIntentFailed = "intent-unavailable"
	reasonSession      = "session"
	reasonNotOpened    = "not-opened"
	reasonRecorded     = "recorded"
	reasonOutcome      = "bad-outcome"
	reasonLate         = "late"
	reasonFencedPass   = "fenced-pass"
)

// reasonError is a runner refusal: it becomes a denial with this audit reason.
type reasonError string

func (r reasonError) Error() string { return string(r) }

// Open lets the acceptance runner bound to a run's current attempt read that run's suite revision, once. Every
// failure is [ErrDenied] with no detail: an unknown run, another run's or assignment's credential, another repo,
// an expired, reused or fenced attempt, a revision no longer usable and stale or pending intent. A specific reason
// code goes to the audit log only. A backend failure is returned as an error, never as a denial. The attempt is
// bound to the runner's session on first open, and a session that opened an earlier attempt of the run cannot open
// a later one.
func (s *Store) Open(ctx context.Context, cred Credential, runID string, attempt int) (*Reader, error) { // INT-6
	const op = "open"
	w, err := s.authorize(ctx, cred, op, nil, RoleAcceptanceRunner)
	if err != nil {
		return nil, err
	}
	suite, ok, err := s.runSuite(ctx, w, op, runID)
	if !ok {
		return nil, err
	}
	var rd *Reader
	err = s.runnerStep(ctx, w, op, suite, runID, attempt, true, func(run *RunState, tx WriteTx, rec *RevisionRecord, at *AttemptState) error {
		switch {
		case at.Opened:
			return reasonError(reasonReused)
		case !s.cfg.Clock().Before(at.ExpiresAt):
			return reasonError(reasonExpired)
		case !rec.Status.usable():
			return reasonError(reasonUnusable)
		case slices.ContainsFunc(run.Attempts, func(a AttemptState) bool { return a.Session == w.Session }):
			return reasonError(reasonSession)
		}
		if _, ierr := s.intentCheck(ctx, rec); ierr != nil {
			return reasonError(intentReason(ierr))
		}
		files, ierr := loadFiles(tx, rec)
		if ierr != nil {
			return abort(ierr)
		}
		attrs := map[string]string{attrRevision: string(rec.Revision), attrRunID: clean(runID), attrAttempt: strconv.Itoa(attempt)}
		if ierr = s.commitAudit(ctx, w, op, suite, attrs); ierr != nil {
			return abort(ierr)
		}
		at.Opened = true
		at.Session = w.Session
		at.ReportBy = s.cfg.Clock().Add(s.cfg.MaxRunDuration)
		rd = newReader(suite, rec.Revision, files)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return rd, nil
}

func intentReason(err error) string {
	switch {
	case errors.Is(err, ErrIntentPending):
		return reasonPending
	case errors.Is(err, ErrStaleIntent):
		return reasonStale
	}
	return reasonIntentFailed
}

func newReader(suite SuiteID, rev Revision, files []File) *Reader {
	rd := &Reader{suite: suite, rev: rev, files: make(map[string]File, len(files))}
	for _, f := range files {
		rd.files[f.Path] = f
		rd.paths = append(rd.paths, f.Path)
	}
	return rd
}

// RecordOutcome stores the result of an attempt, which must have been opened by the calling session and not yet
// recorded, before its report deadline (MaxRunDuration after it opened). A fenced (older) attempt may still record a
// failure until its deadline, and that failure freezes the revision like any other, but it can never record a pass. A failure freezes the suite revision (PIP-15): a plain successor is refused afterwards, and only
// a correction citing this run may replace it (INT-9). An outcome is recorded
// even if the revision was superseded or went stale meanwhile, because the failure is evidence; approval of a
// successor waits for opened attempts to record, so a recorded failure always lands on the head of the lineage.
func (s *Store) RecordOutcome(ctx context.Context, cred Credential, runID string, attempt int, out Outcome) error { // PIP-15, INT-9
	const op = "record-outcome"
	w, err := s.authorize(ctx, cred, op, nil, RoleAcceptanceRunner)
	if err != nil {
		return err
	}
	suite, ok, err := s.runSuite(ctx, w, op, runID)
	if !ok {
		return err
	}
	return s.runnerStep(ctx, w, op, suite, runID, attempt, false, func(run *RunState, _ WriteTx, rec *RevisionRecord, at *AttemptState) error {
		switch {
		case !at.Opened:
			return reasonError(reasonNotOpened)
		case at.Session != w.Session:
			return reasonError(reasonSession)
		case at.Outcome != nil:
			return reasonError(reasonRecorded)
		case at.Abandoned, !s.cfg.Clock().Before(at.ReportBy):
			// Once an approval has treated the attempt as abandoned it can never record, whatever this caller's
			// clock says: a stepped-back clock or a slower replica must not land a failure on a superseded revision.
			return reasonError(reasonLate)
		case at.Number != len(run.Attempts) && out.Passed:
			return reasonError(reasonFencedPass) // a fenced attempt may still report a failure, never a pass
		}
		failed, valid := cleanOutcome(out, rec.Bundle)
		if !valid {
			return reasonError(reasonOutcome)
		}
		attrs := map[string]string{
			attrRevision: string(rec.Revision), attrRunID: clean(runID), attrAttempt: strconv.Itoa(attempt),
			"passed": strconv.FormatBool(out.Passed),
		}
		if ierr := s.commitAudit(ctx, w, op, suite, attrs); ierr != nil {
			return abort(ierr)
		}
		at.Outcome = &Outcome{Passed: out.Passed, FailedScenarios: failed}
		if !out.Passed && rec.Status == StatusActive {
			rec.Status = StatusFrozen
		}
		return nil
	})
}

// cleanOutcome validates an outcome against the bundle's public scenario IDs and returns the sorted, de-duplicated
// failed IDs.
func cleanOutcome(o Outcome, b Bundle) ([]string, bool) {
	if o.Passed && len(o.FailedScenarios) > 0 || len(o.FailedScenarios) > MaxScenarios {
		return nil, false
	}
	failed := slices.Compact(slices.Sorted(slices.Values(o.FailedScenarios)))
	ids := b.ScenarioIDs()
	for _, id := range failed {
		if !slices.Contains(ids, id) {
			return nil, false
		}
	}
	return failed, true
}

// runSuite resolves a run's suite after authorization with one index lookup that costs the same whether or not
// the run exists, and checks the runner's repo before any suite is read. An unknown run and another repo's run are
// the same denial, audited with the same subject. A backend failure is an error, not a denial.
func (s *Store) runSuite(ctx context.Context, w Workload, op, runID string) (suite SuiteID, ok bool, err error) {
	suite, found, err := s.cfg.Backend.SuiteOfRun(ctx, runID)
	if err != nil {
		return SuiteID{}, false, wrapOp(op, err)
	}
	if !found || suite.Repo != w.Repo {
		s.deny(ctx, &w, op, nil, reasonUnknown)
		return SuiteID{}, false, ErrDenied
	}
	return suite, true, nil
}

// runnerStep loads the run, revision and attempt for a runner call and checks the run's current attempt and the
// runner's assignment before calling fn. With currentOnly false an older, fenced attempt is selected too. fn returns a reasonError for a refusal (committed as a no-op apart from
// stale marking), an [abort] error for a real failure, or nil. A refusal is a denial.
func (s *Store) runnerStep(ctx context.Context, w Workload, op string, suite SuiteID, runID string, attempt int, currentOnly bool,
	fn func(*RunState, WriteTx, *RevisionRecord, *AttemptState) error,
) error {
	var reason string
	err := s.cfg.Backend.Update(ctx, suite, func(st *State, tx WriteTx) error {
		initState(st)
		run := st.Runs[runID]
		if run == nil || run.Record.Suite != suite || len(run.Attempts) == 0 {
			reason = reasonUnknown
			return nil
		}
		if attempt < 1 || attempt > len(run.Attempts) {
			reason = reasonUnknown
			return nil
		}
		at := &run.Attempts[attempt-1]
		rec := st.Revisions[run.Record.SuiteRevision]
		switch {
		case rec == nil:
			reason = reasonUnknown
		case currentOnly && attempt != len(run.Attempts):
			reason = reasonFenced
		case at.Assignment != w.Assignment:
			reason = reasonAssignment
		}
		if reason != "" {
			return nil
		}
		r := fn(run, tx, rec, at)
		var a *abortError
		var rr reasonError
		switch {
		case errors.As(r, &a):
			return a.err
		case errors.As(r, &rr):
			reason = string(rr)
		case r != nil:
			reason = reasonUnknown
		}
		return nil
	})
	if err != nil {
		return wrapOp(op, err)
	}
	if reason != "" {
		s.deny(ctx, &w, op, &suite, reason)
		return ErrDenied
	}
	return nil
}
