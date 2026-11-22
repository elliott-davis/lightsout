// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

package holdout

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/elliott-davis/lightsout/internal/audit"
)

// DefaultGrantTTL is how long a grant can be opened after it is issued.
const DefaultGrantTTL = time.Hour

// Config holds a [Store]'s collaborators. All are injected; nothing is global.
type Config struct {
	Backend  Backend
	Verifier Verifier
	Intents  IntentSource
	Audit    Auditor
	Clock    func() time.Time
	// GrantTTL is the lifetime of a grant. Zero means [DefaultGrantTTL].
	GrantTTL time.Duration
	// MaxRunDuration bounds how long an opened attempt may take to report. It is required and must be positive.
	// An opened attempt blocks the approval of a successor revision until it records an outcome or this deadline
	// passes, so a dead runner cannot wedge a suite forever, and cannot report a pass after the deadline.
	MaxRunDuration time.Duration
}

// Store is the holdout store. It is safe for concurrent use if its backend is.
type Store struct {
	cfg Config
}

// New returns a store. Every collaborator is required.
func New(cfg Config) (*Store, error) {
	switch {
	case cfg.Backend == nil:
		return nil, errors.New("holdout: nil backend")
	case cfg.Verifier == nil:
		return nil, errors.New("holdout: nil verifier")
	case cfg.Intents == nil:
		return nil, errors.New("holdout: nil intent source")
	case cfg.Audit == nil:
		return nil, errors.New("holdout: nil auditor")
	case cfg.Clock == nil:
		return nil, errors.New("holdout: nil clock")
	case cfg.GrantTTL < 0:
		return nil, errors.New("holdout: negative grant ttl")
	case cfg.MaxRunDuration <= 0:
		return nil, errors.New("holdout: max run duration must be positive")
	}
	if cfg.GrantTTL == 0 {
		cfg.GrantTTL = DefaultGrantTTL
	}
	return &Store{cfg: cfg}, nil
}

// Audit attribute keys.
const (
	attrRole     = "role"
	attrSession  = "session"
	attrRevision = "revision"
	attrRunID    = "run_id"
	attrAttempt  = "attempt"
)

// Reason codes written to the audit log for denials. They never reveal whether a suite, revision or grant exists.
const (
	reasonUnverified = "unverified"
	reasonRole       = "role"
	reasonRepo       = "repo"
	reasonAssignment = "assignment"
)

// checkSuite refuses a malformed suite ID from an authorized caller, and audits the refusal.
func (s *Store) checkSuite(ctx context.Context, w Workload, op string, suite SuiteID) error {
	if suite.valid() {
		return nil
	}
	err := invalidf("suite")
	s.refused(ctx, w, op, suite, err)
	return err
}

// authorize verifies the credential and checks role and repo scope. It touches no backend. A denial is audited and
// returned as [ErrDenied] with no further detail.
func (s *Store) authorize(ctx context.Context, cred Credential, op string, suite *SuiteID, roles ...Role) (Workload, error) {
	w, err := s.cfg.Verifier.Verify(ctx, cred)
	if err != nil || !w.valid() {
		s.deny(ctx, nil, op, suite, reasonUnverified)
		return Workload{}, ErrDenied
	}
	if !hasRole(roles, w.Role) {
		s.deny(ctx, &w, op, suite, reasonRole)
		return Workload{}, ErrDenied
	}
	if suite != nil && w.Repo != suite.Repo {
		s.deny(ctx, &w, op, suite, reasonRepo)
		return Workload{}, ErrDenied
	}
	// QE and the scenario reviewer work on one suite: repo scope alone is not enough (INT-6).
	if suite != nil && (w.Role == RoleQE || w.Role == RoleScenarioReviewer) && w.Assignment != suite.Assignment() {
		s.deny(ctx, &w, op, suite, reasonAssignment)
		return Workload{}, ErrDenied
	}
	return w, nil
}

func hasRole(roles []Role, r Role) bool {
	for _, x := range roles {
		if x == r {
			return true
		}
	}
	return false
}

// valid reports whether a verified workload carries what the store needs. A workload that does not is unverified.
func (w Workload) valid() bool {
	if !validText(string(w.Role), maxFieldBytes) || w.Repo == "" || len(w.Repo) > maxFieldBytes {
		return false
	}
	if !validText(w.Principal, maxFieldBytes) || !validText(w.Session, maxFieldBytes) {
		return false
	}
	return w.Role != RoleAcceptanceRunner || validText(w.Assignment, maxFieldBytes)
}

func (w Workload) author() Author { return Author{Principal: w.Principal, Session: w.Session} }

func (w Workload) actor() audit.Actor { return audit.Actor{Kind: audit.ActorAgent, ID: w.Principal} }

func (w Workload) templateVersion() string {
	if w.TemplateVersion == "" {
		return "unknown"
	}
	return w.TemplateVersion
}

func subjectOf(suite *SuiteID) audit.Subject {
	if suite == nil || !suite.valid() {
		return audit.Subject{Kind: audit.SubjectInstall, ID: "holdout"}
	}
	return audit.Subject{Kind: audit.SubjectIssue, Repo: string(suite.Repo), ID: strconv.Itoa(suite.Issue)}
}

// deny appends a denial entry. It is best effort: the caller is denied whether or not the append works, and the
// denial itself must not depend on the log.
func (s *Store) deny(ctx context.Context, w *Workload, op string, suite *SuiteID, reason string) {
	rec := audit.Record{
		Actor:   audit.Actor{Kind: audit.ActorExternal, ID: "unverified"},
		Subject: subjectOf(suite),
		Action:  audit.ActionDecision,
		Target:  "holdout." + op,
		Outcome: string(audit.VerdictDenied),
		Decision: &audit.Decision{
			Operation: "holdout." + op,
			Verdict:   audit.VerdictDenied,
			Reason:    reason,
		},
	}
	if w != nil {
		rec.Actor = w.actor()
		rec.TemplateVersion = w.templateVersion()
		rec.Decision.Role = string(w.Role)
		rec.Attrs = map[string]string{attrSession: clean(w.Session)}
	}
	_, _ = s.cfg.Audit.Append(ctx, rec)
}

// refused appends an entry for an authorized call that was refused. Best effort, like [Store.deny]. An entry that
// has no valid suite to name uses the decision form with the install-level subject, which the audit log accepts.
func (s *Store) refused(ctx context.Context, w Workload, op string, suite SuiteID, err error) {
	rec := audit.Record{
		Actor:           w.actor(),
		TemplateVersion: w.templateVersion(),
		Subject:         subjectOf(&suite),
		Action:          audit.ActionToolCall,
		Target:          "holdout." + op,
		Outcome:         "refused",
		Attrs:           map[string]string{attrSession: clean(w.Session), "reason": refusalCode(err)},
	}
	if rec.Subject.Kind == audit.SubjectInstall {
		rec.Action = audit.ActionDecision
		rec.Outcome = string(audit.VerdictDenied)
		rec.Decision = &audit.Decision{
			Operation: "holdout." + op, Role: string(w.Role), Verdict: audit.VerdictDenied, Reason: refusalCode(err),
		}
	}
	_, _ = s.cfg.Audit.Append(ctx, rec)
}

func refusalCode(err error) string {
	for _, c := range []struct {
		err  error
		code string
	}{
		{ErrInvalid, "invalid"},
		{ErrNotFound, "not-found"},
		{ErrConflict, "conflict"},
		{ErrState, "state"},
		{ErrFrozen, "frozen"},
		{ErrBadCorrection, "bad-correction"},
		{ErrNotIndependent, "not-independent"},
		{ErrIntentMismatch, "intent-mismatch"},
		{ErrStaleIntent, "stale-intent"},
		{ErrIntentPending, "intent-pending"},
		{ErrIntentUnavailable, "intent-unavailable"},
		{ErrDenied, "denied"},
	} {
		if errors.Is(err, c.err) {
			return c.code
		}
	}
	var mm *MismatchError
	if errors.As(err, &mm) {
		return "scenario-mismatch"
	}
	var cv *CoverageError
	if errors.As(err, &cv) {
		return "coverage"
	}
	return "error"
}

// commitAudit appends the success entry. Callers do it before returning private bytes or committing state, and
// release nothing when it fails.
func (s *Store) commitAudit(ctx context.Context, w Workload, op string, suite SuiteID, attrs map[string]string) error {
	return s.appendOutcome(ctx, w, op, "ok", suite, attrs)
}

// appendOK appends an "abandoned"-style state entry; see [Store.appendOutcome].
func (s *Store) appendOK(ctx context.Context, w Workload, op string, suite SuiteID, attrs map[string]string) error {
	return s.appendOutcome(ctx, w, op, op, suite, attrs)
}

func (s *Store) appendOutcome(ctx context.Context, w Workload, op, outcome string, suite SuiteID, attrs map[string]string) error {
	a := map[string]string{attrRole: string(w.Role), attrSession: clean(w.Session)}
	for k, v := range attrs {
		a[k] = v
	}
	_, err := s.cfg.Audit.Append(ctx, audit.Record{
		Actor:           w.actor(),
		TemplateVersion: w.templateVersion(),
		Subject:         subjectOf(&suite),
		Action:          audit.ActionToolCall,
		Target:          "holdout." + op,
		Outcome:         outcome,
		Attrs:           a,
	})
	if err != nil {
		return fmt.Errorf("%w: %w", ErrAudit, err)
	}
	return nil
}

// clean makes caller-supplied text safe and short for the audit log.
func clean(s string) string {
	const limit = 128
	if len(s) > limit {
		s = s[:limit]
	}
	return strconv.QuoteToASCII(s)
}

// intentCheck confirms, inside a backend transaction, that the current intent is approved, has no pending edit
// and equals the bundle's. If the approved intent has moved on it marks an active revision stale, which the
// caller commits by returning nil from the transaction.
func (s *Store) intentCheck(ctx context.Context, rec *RevisionRecord) (IntentState, error) {
	st, err := s.cfg.Intents.Current(ctx, rec.Bundle.Suite)
	if err != nil {
		return IntentState{}, wrapUnavailable(err)
	}
	switch {
	case st.Pending:
		return st, ErrIntentPending
	case st.Approved == "" || st.Approved != rec.Bundle.IntentRevision:
		if rec.Status == StatusActive {
			rec.Status = StatusStale
		}
		return st, ErrStaleIntent
	}
	return st, nil
}

// abortError marks a real failure (an audit or backend error) inside a transaction step, as opposed to a refusal.
type abortError struct{ err error }

func (e *abortError) Error() string { return e.err.Error() }

func abort(err error) error { return &abortError{err: err} }

// run executes a transactional step. A plain error returned by fn is a refusal: it commits whatever fn changed so
// far (only stale marking) and is returned after the refusal is audited. An [abort] error aborts the transaction.
func (s *Store) run(ctx context.Context, w Workload, op string, suite SuiteID, fn func(*State, WriteTx) error) error {
	var refusal error
	err := s.cfg.Backend.Update(ctx, suite, func(st *State, tx WriteTx) error {
		initState(st)
		r := fn(st, tx)
		var a *abortError
		if errors.As(r, &a) {
			return a.err
		}
		refusal = r
		return nil
	})
	if err != nil {
		return wrapOp(op, err)
	}
	if refusal != nil {
		s.refused(ctx, w, op, suite, refusal)
	}
	return refusal
}

// effective returns what a reader should see: an active revision whose intent was superseded is reported stale
// even if no call has marked it yet, and eligible says whether the revision may be used for a run right now: it is
// usable, the current approved intent equals its own with no pending edit, and it carries the attestation that
// the suite's disclosures require.
// Failures of the intent source report the stored status and not-eligible.
func (s *Store) effective(ctx context.Context, st *State, rec *RevisionRecord) (status Status, eligible bool) {
	in, err := s.cfg.Intents.Current(ctx, rec.Bundle.Suite)
	if err != nil {
		return rec.Status, false
	}
	status = rec.Status
	if status == StatusActive && in.Approved != rec.Bundle.IntentRevision {
		status = StatusStale
	}
	current := !in.Pending && in.Approved == rec.Bundle.IntentRevision
	return status, status.usable() && current && attestationCovers(st, rec)
}

func wrapUnavailable(err error) error { return fmt.Errorf("%w: %w", ErrIntentUnavailable, err) }

func wrapOp(op string, err error) error { return fmt.Errorf("holdout %s: %w", op, err) }

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}
