// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

package holdout

import (
	"context"
)

// RevisionView is the private view of a revision returned to QE and the scenario reviewer. It holds private bytes.
type RevisionView struct {
	Revision Revision
	Status   Status
	Author   Author
	Bundle   Bundle
}

// Read returns a revision's private bundle to QE or the scenario reviewer of the suite's repo (INT-6).
func (s *Store) Read(ctx context.Context, cred Credential, suite SuiteID, rev Revision) (RevisionView, error) { // INT-6
	const op = "read"
	w, err := s.authorize(ctx, cred, op, &suite, RoleQE, RoleScenarioReviewer)
	if err != nil {
		return RevisionView{}, err
	}
	if cerr := s.checkSuite(ctx, w, op, suite); cerr != nil {
		return RevisionView{}, cerr
	}
	var out RevisionView
	var refusal error
	err = s.cfg.Backend.View(ctx, suite, func(st *State, tx ReadTx) error {
		rec := st.Revisions[rev]
		if rec == nil {
			refusal = ErrNotFound
			return nil
		}
		files, ierr := loadFiles(tx, rec)
		if ierr != nil {
			return ierr
		}
		// The audit entry is committed before any private byte leaves the store.
		if ierr := s.commitAudit(ctx, w, op, suite, map[string]string{attrRevision: string(rev)}); ierr != nil {
			return ierr
		}
		status, _ := s.effective(ctx, st, rec)
		b := rec.Bundle.normalized()
		b.Files = files
		out = RevisionView{Revision: rec.Revision, Status: status, Author: rec.Author, Bundle: b}
		return nil
	})
	if err != nil {
		return RevisionView{}, wrapOp(op, err)
	}
	if refusal != nil {
		s.refused(ctx, w, op, suite, refusal)
		return RevisionView{}, refusal
	}
	return out, nil
}
