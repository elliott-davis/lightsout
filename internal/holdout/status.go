// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

package holdout

import (
	"context"
	"slices"
)

// SuiteStatus is the public hand-off view of a suite (INT-9). It holds no private data.
type SuiteStatus struct {
	// Head is the suite's head revision, or "" if the suite has none.
	Head Revision
	// Status is the head's effective state: an active revision whose intent was superseded is reported stale.
	Status Status
	// Eligible is true when the head may be used for a run now: it is usable, the current approved intent, with
	// no pending edit, equals the bundle's, and any attestation the suite's disclosures require is present.
	Eligible bool
	// Blocking lists the approved public scenario IDs of the latest rejection while the head is not eligible. It is
	// empty once the head is eligible, because a rejected proposal no longer blocks anything then.
	Blocking []string
}

// Status reports the hand-off state of a suite to the acceptance scheduler, QE and the scenario reviewer (INT-9).
// It returns public data only. Everyone else is denied before any backend read.
func (s *Store) Status(ctx context.Context, cred Credential, suite SuiteID) (SuiteStatus, error) { // INT-9
	const op = "status"
	w, err := s.authorize(ctx, cred, op, &suite, RoleAcceptanceScheduler, RoleQE, RoleScenarioReviewer)
	if err != nil {
		return SuiteStatus{}, err
	}
	if cerr := s.checkSuite(ctx, w, op, suite); cerr != nil {
		return SuiteStatus{}, cerr
	}
	var out SuiteStatus
	err = s.cfg.Backend.View(ctx, suite, func(st *State, _ ReadTx) error {
		if ierr := s.commitAudit(ctx, w, op, suite, nil); ierr != nil {
			return ierr
		}
		out = SuiteStatus{Head: st.Head, Blocking: slices.Clone(st.LastReject)}
		if rec := st.Revisions[st.Head]; rec != nil {
			out.Status, out.Eligible = s.effective(ctx, st, rec)
		}
		if out.Eligible {
			out.Blocking = nil // a usable head means hand-off is not blocked, whatever an earlier proposal's rejection said
		}
		return nil
	})
	if err != nil {
		return SuiteStatus{}, wrapOp(op, err)
	}
	return out, nil
}
