// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

package holdout

import (
	"context"
	"maps"
	"slices"
	"strconv"
)

// ReviewRequest is a scenario reviewer's decision on a proposed revision.
type ReviewRequest struct {
	Suite    SuiteID
	Revision Revision
	// IntentRevision is the exact approved intent revision the reviewer checked the bundle against. It must equal
	// the bundle's.
	IntentRevision string
	Verdict        Verdict
	// Mismatched lists the approved public scenario IDs the reviewer found uncovered or wrong. Required to reject,
	// and every ID must be one of the approved public scenario IDs from the [IntentSource]: a private case ID or a
	// bundle-only ID is refused, so a rejection can never carry private information to the coder.
	Mismatched []string
	// Reason is the reviewer's free-text evidence for a rejection (P4). It is stored escaped in the audit trail
	// and is never shown to coders. Required to reject.
	Reason string
}

// ReviewResult is the outcome of a review. It holds public data only.
type ReviewResult struct {
	Status     Status
	Mismatched []string // on reject: the mismatched public scenario IDs that block hand-off (INT-9)
}

// Review records the scenario reviewer's verdict (INT-9). Approval requires the reviewer to differ from the author
// in both principal and session, the intent revision named to equal the bundle's, the current intent from the
// [IntentSource] to be approved, not pending and equal to it, and the bundle to bind exactly the approved public
// scenarios. It also re-checks the freeze in the same transaction: a revision whose parent recorded a failure is
// approved only as a correction citing a failed run of that parent, and nothing is approved while the parent has an
// opened attempt that has neither recorded an outcome nor passed its report deadline (its failure could still land). Approval makes the revision active and
// supersedes its parent. A mismatch returns a [*MismatchError] naming approved public scenario IDs.
func (s *Store) Review(ctx context.Context, cred Credential, req ReviewRequest) (ReviewResult, error) { // INT-9, PIP-15
	const op = "review"
	w, err := s.authorize(ctx, cred, op, &req.Suite, RoleScenarioReviewer)
	if err != nil {
		return ReviewResult{}, err
	}
	if cerr := s.checkSuite(ctx, w, op, req.Suite); cerr != nil {
		return ReviewResult{}, cerr
	}
	if req.Verdict != VerdictApprove && req.Verdict != VerdictReject {
		err = invalidf("verdict")
		s.refused(ctx, w, op, req.Suite, err)
		return ReviewResult{}, err
	}
	var res ReviewResult
	err = s.run(ctx, w, op, req.Suite, func(st *State, _ WriteTx) error {
		rec := st.Revisions[req.Revision]
		switch {
		case rec == nil:
			return ErrNotFound
		case rec.Status != StatusProposed:
			return ErrState
		case rec.Author.Principal == w.Principal || rec.Author.Session == w.Session:
			return ErrNotIndependent
		case req.IntentRevision != rec.Bundle.IntentRevision:
			return ErrIntentMismatch
		}
		if req.Verdict == VerdictReject {
			return s.reject(ctx, w, st, rec, req, &res)
		}
		return s.approve(ctx, w, st, rec, req, &res)
	})
	if err != nil {
		return ReviewResult{}, err
	}
	return res, nil
}

func (s *Store) reject(ctx context.Context, w Workload, st *State, rec *RevisionRecord, req ReviewRequest, res *ReviewResult) error {
	if !validText(req.Reason, maxReasonBytes) {
		return invalidf("reject must carry a reason")
	}
	if len(req.Mismatched) == 0 || len(req.Mismatched) > MaxScenarios {
		return invalidf("reject must name 1..%d mismatched scenario ids", MaxScenarios)
	}
	intent, err := s.cfg.Intents.Current(ctx, rec.Bundle.Suite)
	if err != nil {
		return wrapUnavailable(err)
	}
	approved := slices.Compact(slices.Sorted(slices.Values(intent.ScenarioIDs)))
	mm := slices.Compact(slices.Sorted(slices.Values(req.Mismatched)))
	for _, id := range mm {
		if !validToken(id, 64) || !slices.Contains(approved, id) {
			return invalidf("mismatched ids must be approved public scenario ids")
		}
	}
	attrs := map[string]string{
		attrRevision: string(rec.Revision), "verdict": string(VerdictReject),
		"reason_len": strconv.Itoa(len(req.Reason)), "reason_sha256": sha256Hex(req.Reason),
	}
	if err = s.commitAudit(ctx, w, "review", rec.Bundle.Suite, attrs); err != nil {
		return abort(err)
	}
	rec.Status = StatusRejected
	rec.Review = &ReviewRecord{
		Reviewer: w.author(), Verdict: VerdictReject, IntentRevision: req.IntentRevision, Mismatched: mm,
		Reason: req.Reason, At: s.cfg.Clock(),
	}
	st.LastReject = slices.Clone(mm)
	if st.Head == rec.Revision {
		st.Head = rec.Bundle.Parent
	}
	*res = ReviewResult{Status: StatusRejected, Mismatched: slices.Clone(mm)}
	return nil
}

func (s *Store) approve(ctx context.Context, w Workload, st *State, rec *RevisionRecord, req ReviewRequest, res *ReviewResult) error {
	parent := st.Revisions[rec.Bundle.Parent]
	if rec.Bundle.Parent != "" && parent == nil { // a successor whose parent is gone means a corrupt backend: fail closed
		return ErrConflict
	}
	if parent != nil {
		if blocked, err := s.abandonedOrBlocked(ctx, w, st, parent); err != nil || blocked {
			if err != nil {
				return abort(err)
			}
			return ErrState
		}
		if err := freezeGate(st, parent, rec.Bundle); err != nil {
			return err
		}
	}
	intent, err := s.intentCheck(ctx, rec)
	if err != nil {
		return err
	}
	if missing, extra := scenarioMismatch(rec.Bundle.ScenarioIDs(), intent.ScenarioIDs); len(missing) > 0 || extra > 0 {
		return &MismatchError{ScenarioIDs: missing, Extra: extra}
	}
	attrs := map[string]string{attrRevision: string(rec.Revision), "verdict": string(VerdictApprove)}
	if err = s.commitAudit(ctx, w, "review", rec.Bundle.Suite, attrs); err != nil {
		return abort(err)
	}
	rec.Status = StatusActive
	rec.Review = &ReviewRecord{Reviewer: w.author(), Verdict: VerdictApprove, IntentRevision: req.IntentRevision, At: s.cfg.Clock()}
	if parent != nil && parent.Status != StatusRejected {
		parent.Status = StatusSuperseded
	}
	st.LastReject = nil
	*res = ReviewResult{Status: StatusActive}
	return nil
}

// freezeGate is the successor rule (INT-9, PIP-15), applied at proposal and again at approval, because a failure can
// land between the two. A parent with a recorded failure is replaced only by a correction citing a failed run of that
// parent, and a correction is only for a parent with a recorded failure.
func freezeGate(st *State, parent *RevisionRecord, b Bundle) error {
	if !frozen(st, parent) {
		if b.Correction != nil {
			return ErrBadCorrection
		}
		return nil
	}
	if b.Correction == nil {
		return ErrFrozen
	}
	if !failedRunRecorded(st, b.Suite, b.Correction) {
		return ErrBadCorrection
	}
	return nil
}

// abandonedOrBlocked applies the report deadline to the parent's opened attempts. An opened attempt with no outcome
// whose deadline has not passed could still record a failure, so it blocks the approval of a successor (blocked).
// One past its deadline is abandoned: it no longer blocks, and the first call that observes it appends an
// "abandoned" audit entry and marks it, so the abandonment is on record. Fencing is not an unblock mechanism, since
// a fenced attempt may still report a failure until its own deadline.
func (s *Store) abandonedOrBlocked(ctx context.Context, w Workload, st *State, parent *RevisionRecord) (blocked bool, err error) {
	now := s.cfg.Clock()
	for _, id := range slices.Sorted(maps.Keys(st.Runs)) {
		run := st.Runs[id]
		if run.Record.SuiteRevision != parent.Revision {
			continue
		}
		for i := range run.Attempts {
			at := &run.Attempts[i]
			if !at.Opened || at.Outcome != nil || at.Abandoned {
				continue
			}
			if now.Before(at.ReportBy) {
				blocked = true
				continue
			}
			attrs := map[string]string{attrRevision: string(parent.Revision), attrRunID: clean(id), attrAttempt: strconv.Itoa(at.Number)}
			if aerr := s.appendOK(ctx, w, "abandoned", parent.Bundle.Suite, attrs); aerr != nil {
				return false, aerr
			}
			at.Abandoned = true
		}
	}
	return blocked, nil
}

// scenarioMismatch compares the bound scenario IDs with the approved ones. It returns the approved IDs that are not
// bound, sorted, and the number of bound IDs that are not approved. An empty approved list is a mismatch for every
// bound scenario (fail closed). Extra IDs are only counted: they come from the private bundle.
func scenarioMismatch(bound, approved []string) (missing []string, extra int) {
	approved = slices.Compact(slices.Sorted(slices.Values(approved)))
	for _, id := range approved {
		if !slices.Contains(bound, id) {
			missing = append(missing, id)
		}
	}
	for _, id := range bound {
		if !slices.Contains(approved, id) {
			extra++
		}
	}
	return missing, extra
}
