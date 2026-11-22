// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

package holdout

import (
	"context"
	"maps"
	"slices"
	"time"

	"github.com/elliott-davis/lightsout/internal/audit"
)

// Verifier turns a credential into the workload it authenticates (WI-30 supplies the implementation). Any error
// means the credential is not verified. Service access is separate from internal/authz, which serves human
// decisions.
type Verifier interface {
	Verify(ctx context.Context, cred Credential) (Workload, error)
}

// IntentState is the current approval state of a suite's public scenario intent.
type IntentState struct {
	// Approved is the ideator-approved intent revision, or "" if none is approved.
	Approved string
	// Pending is true while an edit to the intent awaits approval. A pending edit blocks use of the previous
	// approval.
	Pending bool
	// ScenarioIDs are the public scenario IDs of the approved revision.
	ScenarioIDs []string
}

// IntentSource reports the intent state of a suite from the system of record (WI-19, WI-20). The store never takes
// the intent from a caller.
type IntentSource interface {
	Current(ctx context.Context, suite SuiteID) (IntentState, error)
}

// Auditor appends to the audit log. *audit.Log implements it.
type Auditor interface {
	Append(ctx context.Context, r audit.Record) (audit.Entry, error)
}

// ReadTx is what a backend exposes inside a [Backend.View] or [Backend.Update] call besides the suite state. The
// indexes are global (across suites) and are read in the same serialized step as the state, so a check made in the
// function cannot be invalidated before the function's changes commit.
type ReadTx interface {
	// RunSuite returns the suite that owns a run ID anywhere in the store.
	RunSuite(runID string) (SuiteID, bool)
	// AssignmentBound reports whether an assignment is bound to an attempt anywhere in the store. An assignment is
	// bound to exactly one attempt, ever.
	AssignmentBound(assignment string) bool
	// Files returns the immutable file blobs stored for a revision of this suite. The caller must not modify them.
	Files(rev Revision) ([]File, bool)
}

// WriteTx adds blob writes to [ReadTx].
type WriteTx interface {
	ReadTx
	// PutFiles stores a revision's file blobs. Blobs are written once: a second write for the same revision is an
	// error. They commit or roll back with the state.
	PutFiles(rev Revision, files []File) error
}

// Backend stores suites. The memory implementation (package memholdout) is for tests and development only; a
// durable one must pass the conformance suite in package backendtest.
//
// Contract:
//   - [Backend.Update] is atomic and serialized per suite, and serialized against every other writer for the
//     global indexes: if fn returns an error nothing it changed (state or blobs) is stored.
//   - Run IDs are globally unique: a run ID belongs to the first suite that stored it. Assignments are globally
//     unique: each is bound to exactly one attempt. A commit that would break either returns [ErrConflict] and
//     stores nothing. Callers still check through [ReadTx] first so the refusal happens before the audit append.
//   - fn may call the audit log and the intent source but must not call back into the backend.
type Backend interface {
	// View calls fn with the suite's state, or an empty state if the suite has none. fn must not modify or retain it.
	View(ctx context.Context, suite SuiteID, fn func(*State, ReadTx) error) error
	// Update calls fn with a mutable copy of the suite's state and stores it if fn returns nil.
	Update(ctx context.Context, suite SuiteID, fn func(*State, WriteTx) error) error
	// SuiteOfRun returns the suite that owns a run ID. A missing run is ok=false with a nil error, at the same cost
	// as a present one; any other failure is an error.
	SuiteOfRun(ctx context.Context, runID string) (suite SuiteID, ok bool, err error)
}

// Author identifies who proposed a revision. It comes from the verified workload.
type Author struct{ Principal, Session string }

// ReviewRecord is the scenario reviewer's decision on a revision.
type ReviewRecord struct {
	Reviewer       Author
	Verdict        Verdict
	IntentRevision string
	Mismatched     []string
	Reason         string // reviewer's free-text evidence; never shown to coders (P4)
	At             time.Time
}

// Attestation records that a reviewer confirmed retained private coverage (INT-7).
type Attestation struct {
	Reviewer  Author
	Disclosed map[string]bool // every case disclosed so far, a superset of earlier attestations
	At        time.Time
}

// RevisionRecord is everything stored for one revision.
type RevisionRecord struct {
	Revision    Revision
	Bundle      Bundle     // without file bytes: see Files and [ReadTx.Files]
	Files       []FileMeta // sorted by path
	Status      Status
	Author      Author
	ProposedAt  time.Time
	Review      *ReviewRecord
	Attestation *Attestation
}

// AttemptState is one attempt of a run.
type AttemptState struct {
	Number     int
	Assignment string
	Session    string // the runner session that opened the attempt
	ExpiresAt  time.Time
	Opened     bool
	// ReportBy is the report deadline of an opened attempt: OpenedAt + MaxRunDuration. Until then the attempt may
	// record a failure even if a replacement fenced it. After it the attempt is abandoned.
	ReportBy time.Time
	// Abandoned is set the first time a call observes an opened attempt past ReportBy with no outcome.
	Abandoned bool
	Outcome   *Outcome
}

// RunState is a run and its attempts, oldest first. The last attempt is the only current one.
type RunState struct {
	Record   RunRecord
	Attempts []AttemptState
}

// State is the whole state of one suite.
type State struct {
	Head      Revision
	Revisions map[Revision]*RevisionRecord
	Runs      map[string]*RunState
	// Disclosed is the append-only set of private case IDs published as public regression tests (INT-7). It
	// carries forward to every successor revision.
	Disclosed map[string]bool
	// LastReject holds the public scenario IDs of the latest rejection, cleared on approval, for the hand-off gate.
	LastReject []string
}

// Clone returns a deep copy of s.
func (s State) Clone() State {
	c := State{Head: s.Head, Disclosed: maps.Clone(s.Disclosed), LastReject: slices.Clone(s.LastReject)}
	if s.Revisions != nil {
		c.Revisions = make(map[Revision]*RevisionRecord, len(s.Revisions))
		for k, r := range s.Revisions {
			rc := *r
			rc.Bundle = r.Bundle.normalized()
			rc.Files = slices.Clone(r.Files)
			if r.Review != nil {
				v := *r.Review
				v.Mismatched = slices.Clone(v.Mismatched)
				rc.Review = &v
			}
			if r.Attestation != nil {
				v := *r.Attestation
				v.Disclosed = maps.Clone(v.Disclosed)
				rc.Attestation = &v
			}
			c.Revisions[k] = &rc
		}
	}
	if s.Runs != nil {
		c.Runs = make(map[string]*RunState, len(s.Runs))
		for k, r := range s.Runs {
			rc := RunState{Record: r.Record, Attempts: make([]AttemptState, len(r.Attempts))}
			for i, a := range r.Attempts {
				if a.Outcome != nil {
					o := *a.Outcome
					o.FailedScenarios = slices.Clone(o.FailedScenarios)
					a.Outcome = &o
				}
				rc.Attempts[i] = a
			}
			c.Runs[k] = &rc
		}
	}
	return c
}

// initState makes the maps non-nil.
func initState(s *State) {
	if s.Revisions == nil {
		s.Revisions = map[Revision]*RevisionRecord{}
	}
	if s.Runs == nil {
		s.Runs = map[string]*RunState{}
	}
	if s.Disclosed == nil {
		s.Disclosed = map[string]bool{}
	}
}
