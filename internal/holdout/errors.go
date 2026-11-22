// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

package holdout

import (
	"errors"
	"fmt"
	"strings"
)

// Errors. A denied caller only ever sees [ErrDenied]; the others go to callers already authorized for the call.
var (
	// ErrDenied is returned to every caller that is not allowed to make the call, whatever the reason. It carries
	// no detail: the reason code goes to the audit log only, and never depends on whether anything exists.
	ErrDenied = errors.New("holdout: access denied")
	// ErrInvalid wraps every malformed request or bundle.
	ErrInvalid = errors.New("holdout: invalid request")
	// ErrNotFound means an authorized caller named a revision that does not exist.
	ErrNotFound = errors.New("holdout: not found")
	// ErrConflict means a compare-and-swap failed: the parent is not the suite's head, or the revision or run exists.
	ErrConflict = errors.New("holdout: conflict")
	// ErrState means the revision is not in a state that allows the call.
	ErrState = errors.New("holdout: revision state does not allow this call")
	// ErrFrozen means the parent revision recorded an Acceptance failure, so only a correction may replace it
	// (INT-9, PIP-15).
	ErrFrozen = errors.New("holdout: revision is frozen after a failure; only a correction may replace it")
	// ErrBadCorrection means a correction does not replace the frozen head or does not cite a failed run recorded
	// for the same suite and revision.
	ErrBadCorrection = errors.New("holdout: invalid correction")
	// ErrNotIndependent means the reviewer shares a principal or session with the author.
	ErrNotIndependent = errors.New("holdout: reviewer is not independent of the author")
	// ErrIntentMismatch means the intent revision the reviewer named differs from the bundle's.
	ErrIntentMismatch = errors.New("holdout: intent revision does not match the bundle")
	// ErrStaleIntent means the approved intent is not the revision the bundle was written for.
	ErrStaleIntent = errors.New("holdout: bundle intent revision is not the current approved intent")
	// ErrIntentPending means an unapproved intent edit is pending, which blocks the previous approval.
	ErrIntentPending = errors.New("holdout: an unapproved intent edit is pending")
	// ErrIntentUnavailable means the intent source failed; the store fails closed.
	ErrIntentUnavailable = errors.New("holdout: intent source unavailable")
	// ErrAudit means the audit append failed, so nothing was released or changed.
	ErrAudit = errors.New("holdout: audit append failed")
)

// ErrNotAttested means disclosed private cases exist for the suite and the revision has no attestation that
// covers all of them (INT-7).
var ErrNotAttested = errors.New("holdout: revision lacks an attestation covering the disclosed cases")

// ErrDisclosureRegression means an attestation omits a case an earlier attestation disclosed. Disclosures only grow.
var ErrDisclosureRegression = errors.New("holdout: attestation must include every earlier disclosure")

// MismatchError lists the approved public scenario IDs the bundle does not bind (INT-9), and how many bound
// scenarios are not approved. Bundle-only IDs are private information, so they are only counted.
type MismatchError struct {
	ScenarioIDs []string
	Extra       int
}

func (e *MismatchError) Error() string {
	return fmt.Sprintf("holdout: bundle does not match approved scenarios: unbound [%s], %d extra",
		strings.Join(e.ScenarioIDs, ", "), e.Extra)
}

// CoverageError lists public scenario IDs that keep no undisclosed private case.
type CoverageError struct{ ScenarioIDs []string }

func (e *CoverageError) Error() string {
	return "holdout: no undisclosed private case retained for: " + strings.Join(e.ScenarioIDs, ", ")
}

func invalidf(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, args...))
}
