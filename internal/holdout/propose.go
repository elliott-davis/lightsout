// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

package holdout

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"slices"
)

// Propose stores b as a new proposed revision and returns its address. Only QE of b's suite may call it. The
// author is the verified workload, never a field of b.
//
// b.Parent must be the suite's current head (compare-and-swap), so concurrent proposals cannot fork the suite; a
// head still awaiting review also blocks. If the head recorded a failure, only a Correction that replaces it and
// cites a failed run recorded for the same suite and revision is accepted; a plain successor gets [ErrFrozen]
// (INT-9, PIP-15). Either way the revision needs its own independent review before any run uses it.
func (s *Store) Propose(ctx context.Context, cred Credential, b Bundle) (Revision, error) { // INT-6, INT-7, INT-9
	const op = "propose"
	w, err := s.authorize(ctx, cred, op, &b.Suite, RoleQE)
	if err != nil {
		return "", err
	}
	if cerr := s.checkSuite(ctx, w, op, b.Suite); cerr != nil {
		return "", cerr
	}
	n := b.normalized()
	if ierr := n.validate(); ierr != nil {
		s.refused(ctx, w, op, b.Suite, ierr)
		return "", ierr
	}
	rev := n.Revision()
	err = s.run(ctx, w, op, n.Suite, func(st *State, tx WriteTx) error {
		if refusal := proposeChecks(st, n, rev); refusal != nil {
			return refusal
		}
		// The blobs go first, so a refused write leaves no "ok" audit entry for a revision that was not stored.
		if ierr := tx.PutFiles(rev, n.Files); ierr != nil {
			return abort(ierr)
		}
		attrs := map[string]string{attrRevision: string(rev), "parent": string(n.Parent)}
		if ierr := s.commitAudit(ctx, w, op, n.Suite, attrs); ierr != nil {
			return abort(ierr)
		}
		meta := fileMetas(n.Files)
		n.Files = nil // the bytes live in the blob store
		st.Revisions[rev] = &RevisionRecord{
			Revision: rev, Bundle: n, Files: meta, Status: StatusProposed, Author: w.author(), ProposedAt: s.cfg.Clock(),
		}
		st.Head = rev
		return nil
	})
	if err != nil {
		return "", err
	}
	return rev, nil
}

func proposeChecks(st *State, n Bundle, rev Revision) error {
	if _, dup := st.Revisions[rev]; dup || n.Parent != st.Head {
		return ErrConflict
	}
	if n.Parent == "" {
		if n.Correction != nil {
			return ErrBadCorrection
		}
		return nil
	}
	parent := st.Revisions[n.Parent]
	if parent == nil { // a head that names no revision means a corrupt backend: fail closed
		return ErrConflict
	}
	if parent.Status == StatusProposed {
		return ErrState
	}
	return freezeGate(st, parent, n)
}

// frozen reports whether a failure was recorded against rec. It is derived from the recorded outcomes, so a
// frozen revision stays frozen even after its status changes to stale.
func frozen(st *State, rec *RevisionRecord) bool {
	if rec.Status == StatusFrozen {
		return true
	}
	for _, r := range st.Runs {
		if r.Record.SuiteRevision == rec.Revision && runFailed(r) {
			return true
		}
	}
	return false
}

func runFailed(r *RunState) bool {
	return slices.ContainsFunc(r.Attempts, func(a AttemptState) bool { return a.Outcome != nil && !a.Outcome.Passed })
}

// failedRunRecorded reports whether c cites a run of this suite and replaced revision with a recorded failure.
func failedRunRecorded(st *State, suite SuiteID, c *Correction) bool {
	r, ok := st.Runs[c.FailedRun]
	return ok && r.Record.Suite == suite && r.Record.SuiteRevision == c.Replaces && runFailed(r)
}

// fileMetas returns the metadata of files, which must be sorted by path.
func fileMetas(files []File) []FileMeta {
	out := make([]FileMeta, len(files))
	for i, f := range files {
		sum := sha256.Sum256(f.Bytes)
		out[i] = FileMeta{Path: f.Path, Mode: f.Mode, Kind: f.Kind, Size: len(f.Bytes), SHA256: hex.EncodeToString(sum[:])}
	}
	return out
}

// loadFiles returns the files of rec. Each File is built from the recorded metadata (path, mode, kind) plus the
// blob bytes, which must match the recorded size and SHA-256. The content address of the whole bundle is then
// recomputed and compared with the revision ID, so tampering with the metadata and the blob together is caught too.
// Any mismatch, including a different blob count, releases nothing.
func loadFiles(tx ReadTx, rec *RevisionRecord) ([]File, error) {
	blobs, ok := tx.Files(rec.Revision)
	if !ok || len(blobs) != len(rec.Files) {
		return nil, errors.New("holdout: stored files are missing")
	}
	out := make([]File, len(blobs))
	for i, m := range rec.Files {
		sum := sha256.Sum256(blobs[i].Bytes)
		if len(blobs[i].Bytes) != m.Size || hex.EncodeToString(sum[:]) != m.SHA256 {
			return nil, errors.New("holdout: stored files fail their digest")
		}
		out[i] = File{Path: m.Path, Mode: m.Mode, Kind: m.Kind, Bytes: bytes.Clone(blobs[i].Bytes)}
	}
	b := rec.Bundle.normalized()
	b.Files = out
	if b.Revision() != rec.Revision {
		return nil, errors.New("holdout: stored revision fails its content address")
	}
	return out, nil
}
