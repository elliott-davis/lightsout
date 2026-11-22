// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

package holdout

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"maps"
	"slices"
	"strconv"
)

// PublicFile is a file of a proposed public regression PR (INT-7).
type PublicFile struct {
	Path  string
	Bytes []byte
}

// PublicDigest is a public file the caller only has by digest, for example a large binary fixture.
type PublicDigest struct {
	Path   string
	SHA256 string // lowercase hex
}

// LeakRequest asks whether a public change copies private material from a suite revision.
type LeakRequest struct {
	Suite    SuiteID
	Revision Revision
	Files    []PublicFile
	Digests  []PublicDigest
}

// LeakKind says how a public file matched.
type LeakKind string

// Leak kinds.
const (
	LeakFileCopy      LeakKind = "file-copy"      // the bytes equal a whole private file
	LeakFixtureDigest LeakKind = "fixture-digest" // the digest equals a private file's digest
)

// LeakFinding names a public path that matched. It never carries private text.
type LeakFinding struct {
	Path string
	Kind LeakKind
}

// LeakReport is the result of [Store.LeakCheck]. It holds public paths only.
type LeakReport struct{ Findings []LeakFinding }

// Clean reports whether nothing matched.
func (r LeakReport) Clean() bool { return len(r.Findings) == 0 }

// LeakCheck is a backstop for exact copies only: whole private files and file digests (INT-7). Empty private files
// are ignored. It does not look for partial or near copies; the disclosure review of the public diff is the
// primary control. QE and the scenario reviewer of the suite may call it, and the report names only the caller's own paths.
func (s *Store) LeakCheck(ctx context.Context, cred Credential, req LeakRequest) (LeakReport, error) { // INT-7
	const op = "leak-check"
	w, err := s.authorize(ctx, cred, op, &req.Suite, RoleQE, RoleScenarioReviewer)
	if err != nil {
		return LeakReport{}, err
	}
	if ierr := req.validate(); ierr != nil {
		s.refused(ctx, w, op, req.Suite, ierr)
		return LeakReport{}, ierr
	}
	var rep LeakReport
	var refusal error
	err = s.cfg.Backend.View(ctx, req.Suite, func(st *State, _ ReadTx) error {
		rec := st.Revisions[req.Revision]
		if rec == nil {
			refusal = ErrNotFound
			return nil
		}
		attrs := map[string]string{attrRevision: string(req.Revision)}
		if ierr := s.commitAudit(ctx, w, op, req.Suite, attrs); ierr != nil {
			return ierr
		}
		rep = leakReport(rec.Files, req)
		return nil
	})
	if err != nil {
		return LeakReport{}, wrapOp(op, err)
	}
	if refusal != nil {
		s.refused(ctx, w, op, req.Suite, refusal)
		return LeakReport{}, refusal
	}
	return rep, nil
}

func (r LeakRequest) validate() error {
	if !validRevision(r.Revision) {
		return invalidf("revision")
	}
	if len(r.Files)+len(r.Digests) > MaxFiles {
		return invalidf("more than %d public files", MaxFiles)
	}
	total := 0
	for _, f := range r.Files {
		if err := validFilePath(f.Path); err != nil {
			return invalidf("public file path")
		}
		total += len(f.Bytes)
	}
	if total > MaxBundleBytes {
		return invalidf("public files larger than %d bytes", MaxBundleBytes)
	}
	for _, d := range r.Digests {
		if err := validFilePath(d.Path); err != nil || !validHex(d.SHA256, 64) {
			return invalidf("public digest")
		}
	}
	return nil
}

func leakReport(files []FileMeta, req LeakRequest) LeakReport {
	private := map[string]bool{}
	for _, f := range files {
		if f.Size > 0 {
			private[f.SHA256] = true
		}
	}
	var out []LeakFinding
	for _, f := range req.Files {
		sum := sha256.Sum256(f.Bytes)
		if len(f.Bytes) > 0 && private[hex.EncodeToString(sum[:])] {
			out = append(out, LeakFinding{Path: f.Path, Kind: LeakFileCopy})
		}
	}
	for _, d := range req.Digests {
		if private[d.SHA256] {
			out = append(out, LeakFinding{Path: d.Path, Kind: LeakFixtureDigest})
		}
	}
	slices.SortFunc(out, func(a, b LeakFinding) int {
		if c := compareStr(a.Path, b.Path); c != 0 {
			return c
		}
		return compareStr(string(a.Kind), string(b.Kind))
	})
	return LeakReport{Findings: out}
}

// CoverageRequest is the scenario reviewer's attestation that a revision retains private coverage after some of
// its cases were published as public regression tests.
type CoverageRequest struct {
	Suite    SuiteID
	Revision Revision
	// Disclosed lists the private case IDs now public. It must include every case disclosed by an earlier
	// attestation of the suite, and every scenario must keep at least one other case.
	Disclosed []string
}

// AttestCoverage records, for a pinned revision, that every scenario keeps at least one undisclosed private case
// (INT-7: QE retains or adds fresh private coverage before requalification). Only the scenario reviewer may call
// it, independent of the revision's author (different principal and session), and the revision must be usable with a
// current approved intent. Disclosures are append-only for the suite and carry forward to successor revisions: an
// attestation that omits an earlier disclosure is [ErrDisclosureRegression]. A scenario with nothing left returns a
// [*CoverageError].
func (s *Store) AttestCoverage(ctx context.Context, cred Credential, req CoverageRequest) error { // INT-7
	const op = "attest-coverage"
	w, err := s.authorize(ctx, cred, op, &req.Suite, RoleScenarioReviewer)
	if err != nil {
		return err
	}
	if cerr := s.checkSuite(ctx, w, op, req.Suite); cerr != nil {
		return cerr
	}
	disclosed, err := cleanDisclosed(req.Disclosed)
	if err != nil {
		s.refused(ctx, w, op, req.Suite, err)
		return err
	}
	return s.run(ctx, w, op, req.Suite, func(st *State, _ WriteTx) error {
		rec := st.Revisions[req.Revision]
		switch {
		case rec == nil:
			return ErrNotFound
		case !rec.Status.usable():
			return ErrState
		case rec.Author.Principal == w.Principal || rec.Author.Session == w.Session:
			return ErrNotIndependent
		}
		if _, ierr := s.intentCheck(ctx, rec); ierr != nil {
			return ierr
		}
		if cerr := checkDisclosure(st, rec.Bundle, disclosed); cerr != nil {
			return cerr
		}
		attrs := map[string]string{attrRevision: string(req.Revision), "disclosed": strconv.Itoa(len(disclosed))}
		if ierr := s.commitAudit(ctx, w, op, req.Suite, attrs); ierr != nil {
			return abort(ierr)
		}
		for id := range disclosed {
			st.Disclosed[id] = true
		}
		rec.Attestation = &Attestation{Reviewer: w.author(), Disclosed: maps.Clone(disclosed), At: s.cfg.Clock()}
		return nil
	})
}

func cleanDisclosed(ids []string) (map[string]bool, error) {
	if len(ids) > MaxScenarios*(MaxPrivateCases+1) {
		return nil, invalidf("too many disclosed cases")
	}
	out := make(map[string]bool, len(ids))
	for _, id := range ids {
		if !validToken(id, maxFieldBytes) {
			return nil, invalidf("disclosed case id")
		}
		out[id] = true
	}
	return out, nil
}

// checkDisclosure applies the monotonic and coverage rules. Cases disclosed earlier count as disclosed in this
// revision too, whether or not it still has a case of that name.
func checkDisclosure(st *State, b Bundle, disclosed map[string]bool) error {
	for id := range st.Disclosed {
		if !disclosed[id] {
			return ErrDisclosureRegression
		}
	}
	known := map[string]bool{}
	for _, sc := range b.Scenarios {
		known[sc.Entry] = true
		for _, p := range sc.Private {
			known[p] = true
		}
	}
	for id := range disclosed {
		if !known[id] && !st.Disclosed[id] {
			return invalidf("disclosed case is not in the revision")
		}
	}
	var bad []string
	for _, sc := range b.Scenarios {
		left := 0
		for _, c := range append([]string{sc.Entry}, sc.Private...) {
			if !disclosed[c] {
				left++
			}
		}
		if left == 0 {
			bad = append(bad, sc.ScenarioID)
		}
	}
	if len(bad) > 0 {
		return &CoverageError{ScenarioIDs: bad}
	}
	return nil
}
