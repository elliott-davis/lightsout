// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

// Package gate decides whether the gates of record passed for one merge-group candidate (PIP-2, CON-4, SEC-11).
//
// Evaluate is pure: it takes the effective contract and a snapshot of job executions and does no I/O. The caller
// fetches the snapshot and re-evaluates right before it publishes a verdict. See docs/design/gates.md.
package gate

import (
	"cmp"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/elliott-davis/lightsout/internal/contract"
	"github.com/elliott-davis/lightsout/internal/forge"
)

// canonicalAttempt is a positive decimal integer without sign, padding or leading zeros, small enough for an int.
var canonicalAttempt = regexp.MustCompile(`^[1-9]\d{0,8}$`)

// fullSHA is a full commit ID, SHA-1 or SHA-256, in lowercase hex.
var fullSHA = regexp.MustCompile(`^([0-9a-f]{40}|[0-9a-f]{64})$`)

// mergeGroupEvent is the only event whose executions count as gate evidence.
const mergeGroupEvent = "merge_group"

// Disposition is the outcome of an obligation or of the whole change. The values are ordered by severity in
// [Evaluate]: error over blocked over pending over pass.
type Disposition string

// Dispositions.
const (
	// Pass means every mandatory obligation has exactly one successful matching execution.
	Pass Disposition = "pass"
	// Pending means the evidence may still turn into a pass once a running job completes. Retry later.
	Pending Disposition = "pending"
	// Blocked is terminal for this evidence: repair the cause or run the gate again.
	Blocked Disposition = "blocked"
	// Error means the evidence could not be collected, so nothing can be said about the gates.
	Error Disposition = "error"
)

func (d Disposition) rank() int {
	switch d {
	case Pass:
		return 0
	case Pending:
		return 1
	case Blocked:
		return 2
	case Error:
		return 3
	default:
		return 3 // an unknown disposition is as bad as an error
	}
}

// Reason says why an obligation or a change did not pass. Foreign, Unpinned and StaleCandidate are also used as
// evidence next to ReasonMissing.
type Reason string

// Reasons.
const (
	ReasonNone               Reason = ""
	ReasonPending            Reason = "pending"
	ReasonMissing            Reason = "missing"
	ReasonAmbiguous          Reason = "ambiguous"
	ReasonForeign            Reason = "foreign"
	ReasonNotRun             Reason = "not-run"
	ReasonFailed             Reason = "failed"
	ReasonUnpinned           Reason = "unpinned"
	ReasonIncomplete         Reason = "incomplete"
	ReasonStaleCandidate     Reason = "stale-candidate"
	ReasonConflict           Reason = "conflict"
	ReasonIncompleteEvidence Reason = "incomplete-evidence"
	ReasonInvalidInput       Reason = "invalid-input"
	ReasonNoMandatoryGates   Reason = "no-mandatory-gates"
	ReasonUnattributedRun    Reason = "unattributed-running"
	ReasonMalformedEvidence  Reason = "malformed-evidence"
)

// Target is the change a decision is for. CandidateSHA is the only SHA evidence may come from.
type Target struct {
	// Forge names the forge, such as "github". A contract's producer ID must be Forge + "-app:" + the execution's
	// ProducerAppID.
	Forge        string
	Repo         forge.RepoID
	PR           int
	HeadSHA      string
	CandidateSHA string
}

// Evidence is a snapshot of job executions for the target repo. Complete is false when collection failed or was
// truncated, and then nothing passes.
type Evidence struct {
	Executions []forge.JobExecution
	Complete   bool
}

// ObligationResult is the verdict for one gate obligation.
type ObligationResult struct {
	Gate        contract.GateRef
	Name        string
	Owner       contract.Owner
	Sources     []string
	Mandatory   bool
	Disposition Disposition
	// Reason is the primary reason, empty on a pass.
	Reason Reason
	// Evidence holds extra reasons found next to Reason (foreign, unpinned, stale-candidate), sorted.
	Evidence []Reason
	// RunID, RunAttempt and JobID identify the execution the verdict is based on. They are empty when there was none
	// or when it was ambiguous.
	RunID, RunAttempt, JobID string
}

// Decision is the result of [Evaluate]. It binds to the policy revision, install revision and candidate SHA.
type Decision struct {
	Target
	PolicyRevision  string
	InstallRevision string
	Disposition     Disposition
	// Reasons are change-level reasons: invalid-input, conflict, no-mandatory-gates, unattributed-running,
	// malformed-evidence and incomplete-evidence.
	Reasons []Reason
	// Obligations are the verify gates sorted by identity and revision. Advisory ones are reported but never
	// affect Disposition.
	Obligations []ObligationResult
}

// Evaluate decides the gates of record for t from ev. It is deterministic and does not modify its inputs.
//
// Identity forms. A contract's producerId must equal t.Forge + "-app:" + ProducerAppID, such as "github-app:15368".
// Its workflowId must equal WorkflowRepo + "/" + WorkflowPath, where WorkflowRepo is the forge's stable repo ID
// without a slash, such as "123456/.github/workflows/gate.yml". The adapter (WI-12) and the gate registry use exactly
// these forms, and a numeric workflow ID is rejected at registration.
//
// Evaluate fails closed. It returns Error with ReasonInvalidInput for a nil contract, an empty revision or install
// revision, an empty forge or repo, a candidate that isn't a full lowercase SHA, or a mandatory gate with an empty field. It blocks a
// contract with no mandatory gate. A record that can't be attributed to a job (another repo, or an empty RunID,
// JobKey or JobID) is never ignored: while running it holds the change at pending or worse (ReasonUnattributedRun), and a blocked
// obligation still wins over it. Once completed it makes the change an error (ReasonMalformedEvidence). PR and HeadSHA are echoed from the caller and are not verified here.
func Evaluate(eff *contract.Effective, t Target, ev Evidence) Decision {
	d := Decision{Target: t, Disposition: Pass}
	if !validInput(eff, t) {
		d.Disposition = Error
		d.Reasons = []Reason{ReasonInvalidInput}
		if eff != nil {
			d.PolicyRevision, d.InstallRevision = eff.Revision, eff.InstallRevision
		}
		return d
	}
	d.PolicyRevision, d.InstallRevision = eff.Revision, eff.InstallRevision

	gates := slices.Clone(eff.VerifyGates)
	slices.SortFunc(gates, func(a, b contract.Obligation) int {
		return cmp.Or(
			cmp.Compare(a.Gate.ProducerID, b.Gate.ProducerID),
			cmp.Compare(a.Gate.WorkflowID, b.Gate.WorkflowID),
			cmp.Compare(a.Gate.CheckID, b.Gate.CheckID),
			cmp.Compare(a.Gate.WorkflowRevision, b.Gate.WorkflowRevision),
			cmp.Compare(a.Gate.Name, b.Gate.Name),
			cmp.Compare(boolInt(a.Gate.Mandatory), boolInt(b.Gate.Mandatory)),
			cmp.Compare(a.Owner, b.Owner),
			slices.Compare(a.Sources, b.Sources),
		)
	})

	mandatory := 0
	for i := range gates {
		o := &gates[i]
		r := ObligationResult{
			Gate:      o.Gate.GateRef,
			Name:      o.Gate.Name,
			Owner:     o.Owner,
			Sources:   slices.Clone(o.Sources),
			Mandatory: o.Gate.Mandatory,
		}
		if ev.Complete {
			evaluateGate(&r, t, ev.Executions)
		} else {
			r.Disposition, r.Reason = Error, ReasonIncompleteEvidence
		}
		d.Obligations = append(d.Obligations, r)
		if r.Mandatory {
			mandatory++
			d.raise(r.Disposition)
		}
	}

	running, malformed := unattributed(t, ev.Executions)
	if len(eff.Conflicts) > 0 {
		d.Reasons = append(d.Reasons, ReasonConflict)
		d.raise(Blocked)
	}
	if mandatory == 0 {
		d.Reasons = append(d.Reasons, ReasonNoMandatoryGates)
		d.raise(Blocked)
	}
	if running {
		d.Reasons = append(d.Reasons, ReasonUnattributedRun)
		d.raise(Pending)
	}
	if malformed {
		d.Reasons = append(d.Reasons, ReasonMalformedEvidence)
		d.raise(Error)
	}
	if !ev.Complete {
		d.Reasons = append(d.Reasons, ReasonIncompleteEvidence)
		d.raise(Error)
	}
	return d
}

// unattributed reports records that can't be tied to a (run, job) group, so no per-gate grouping can see them: a
// repo other than the target's, or an empty RunID, JobKey or JobID. A running one might still turn into a newer
// attempt of a gate job. A completed one is evidence the snapshot is wrong.
func unattributed(t Target, execs []forge.JobExecution) (running, malformed bool) {
	for i := range execs {
		e := &execs[i]
		if attributable(t, e) {
			continue
		}
		if e.Conclusion == forge.ConclusionNone {
			running = true
		} else {
			malformed = true
		}
	}
	return running, malformed
}

// attributable reports whether e can be tied to a (run, job) group of the target repo. Every grouping uses this one
// predicate, so a record [unattributed] flags never forms a group.
func attributable(t Target, e *forge.JobExecution) bool {
	return e.Repo == t.Repo && e.RunID != "" && e.JobKey != "" && e.JobID != ""
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func validInput(eff *contract.Effective, t Target) bool {
	if eff == nil || eff.Revision == "" || eff.InstallRevision == "" ||
		t.Forge == "" || t.Repo == "" || !fullSHA.MatchString(t.CandidateSHA) {
		return false
	}
	for i := range eff.VerifyGates {
		g := eff.VerifyGates[i].Gate
		if g.Mandatory && (g.ProducerID == "" || g.WorkflowID == "" || g.WorkflowRevision == "" || g.CheckID == "") {
			return false
		}
	}
	return true
}

func (d *Decision) raise(to Disposition) {
	if to.rank() > d.Disposition.rank() {
		d.Disposition = to
	}
}

// structurallyBad reports whether e lacks a field the matcher relies on, or has an attempt that is not canonical.
// Such a record cannot be ordered or attributed, so it is never ignored.
func structurallyBad(e *forge.JobExecution) bool {
	return e.ProducerAppID == "" || e.WorkflowRepo == "" || e.WorkflowPath == "" || e.WorkflowCommit == "" ||
		e.CandidateSHA == "" || e.Event == "" || e.RunID == "" || e.JobID == "" ||
		strings.Contains(string(e.WorkflowRepo), "/") || !canonicalAttempt.MatchString(e.RunAttempt)
}

// runOutcome is what one run's records say about a gate.
type runOutcome int

const (
	runForeign runOutcome = iota // only records of another producer
	runUnpinned
	runStale
	runMatched   // the newest attempt matches and is vouched for: judge it
	runUnvouched // the newest attempt is running and nobody vouched for it: pending
	runUntrusted
	runAmbiguous
)

// producerMatches reports whether e was produced by the contract's producer, in the canonical form
// <forge>-app:<app id>.
func producerMatches(g contract.GateRef, t Target, e *forge.JobExecution) bool {
	return g.ProducerID == t.Forge+"-app:"+e.ProducerAppID
}

// pendingAttempt orders a running record whose attempt can't be parsed above every real attempt, so it shadows them.
const pendingAttempt = int(^uint(0) >> 1)

func unvouchedRunning(e *forge.JobExecution) bool {
	return e.Conclusion == forge.ConclusionNone && e.Provenance != forge.ProvenanceComplete
}

// newestVouched is the highest canonical attempt among complete, well-formed records of the contract's producer.
// Older canonical attempts can no longer be the newest, so their gaps don't block.
func newestVouched(g contract.GateRef, t Target, run []forge.JobExecution) int {
	newest := 0
	for i := range run {
		e := &run[i]
		if e.Provenance == forge.ProvenanceComplete && !structurallyBad(e) && producerMatches(g, t, e) {
			n, _ := strconv.Atoi(e.RunAttempt) // canonical, as structurallyBad checked
			newest = max(newest, n)
		}
	}
	return newest
}

// evaluateRun judges the records of one (run, job key) group. Records are grouped before any identity filter, so
// an attempt that does not match still counts as the newest attempt and shadows an older success.
func evaluateRun(g contract.GateRef, t Target, run []forge.JobExecution) (runOutcome, forge.JobExecution) {
	var live []forge.JobExecution
	vouched := newestVouched(g, t, run)
	for i := range run {
		e := &run[i]
		// A canonical attempt below a vouched one can't be the newest. A non-canonical one can't be ordered.
		older := canonicalAttempt.MatchString(e.RunAttempt) && attemptNumber(e) < vouched
		switch {
		case unvouchedRunning(e):
			// A running job that nobody vouched for is pending whatever its fields say: the adapter binds them late.
			if older {
				continue
			}
		case structurallyBad(e) || e.Provenance != forge.ProvenanceComplete:
			// A bad record blocks even when its producer differs: it can't be vouched for as foreign.
			if older {
				continue
			}
			return runUntrusted, forge.JobExecution{}
		case !producerMatches(g, t, e):
			// A complete record of a known other producer neither blocks nor supersedes the real one.
			continue
		}
		if !slices.Contains(live, *e) {
			live = append(live, *e)
		}
	}
	if len(live) == 0 {
		// Invariant: runs are never empty, and every record is either live, skipped as older than a live vouched
		// record, or foreign. So a run with no live record held only foreign ones.
		return runForeign, forge.JobExecution{}
	}

	perAttempt := map[int][]forge.JobExecution{}
	newest := 0
	for i := range live {
		n := attemptNumber(&live[i])
		perAttempt[n] = append(perAttempt[n], live[i])
		newest = max(newest, n)
	}
	for _, recs := range perAttempt {
		// Legs that share a rendered name, or conflicting records of one job, vouched or not. An unvouched running
		// record never exempts its attempt: it could hide a vouched failure or a second leg.
		if len(recs) > 1 {
			return runAmbiguous, forge.JobExecution{}
		}
	}
	cur := perAttempt[newest][0]
	if unvouchedRunning(&cur) {
		return runUnvouched, cur
	}
	switch {
	case string(g.WorkflowID) != string(cur.WorkflowRepo)+"/"+cur.WorkflowPath || cur.WorkflowCommit != g.WorkflowRevision:
		return runUnpinned, cur
	case cur.CandidateSHA != t.CandidateSHA || cur.Event != mergeGroupEvent:
		return runStale, cur
	}
	return runMatched, cur
}

func attemptNumber(e *forge.JobExecution) int {
	if !canonicalAttempt.MatchString(e.RunAttempt) {
		return pendingAttempt // only running, unvouched records get here
	}
	n, _ := strconv.Atoi(e.RunAttempt)
	return n
}

// evaluateGate fills r for one obligation. Across runs, two or more vouched current matches are ambiguous. One
// vouched match is judged on its own, except that a pass becomes pending while an unvouched running record is
// around. With no vouched match, an unvouched running record makes the obligation pending.
func evaluateGate(r *ObligationResult, t Target, execs []forge.JobExecution) {
	g := r.Gate
	runs := map[string][]forge.JobExecution{}
	for i := range execs {
		if e := &execs[i]; attributable(t, e) && e.JobKey == g.CheckID {
			runs[e.RunID] = append(runs[e.RunID], *e)
		}
	}

	seen := map[runOutcome]bool{}
	var matched, unvouched []forge.JobExecution
	for _, run := range runs {
		out, cur := evaluateRun(g, t, run)
		seen[out] = true
		switch out {
		case runMatched:
			matched = append(matched, cur)
		case runUnvouched:
			unvouched = append(unvouched, cur)
		case runForeign, runUnpinned, runStale, runUntrusted, runAmbiguous:
		}
	}

	switch {
	case seen[runUntrusted]:
		r.Disposition, r.Reason = Blocked, ReasonIncomplete
	case seen[runAmbiguous] || len(matched) > 1:
		r.Disposition, r.Reason = Blocked, ReasonAmbiguous
	case len(matched) == 1:
		judge(r, &matched[0])
		if r.Disposition == Pass && len(unvouched) > 0 {
			r.Disposition, r.Reason = Pending, ReasonPending
		}
	case len(unvouched) == 1:
		judge(r, &unvouched[0])
	case len(unvouched) > 1:
		r.Disposition, r.Reason = Pending, ReasonPending
	default:
		r.Disposition, r.Reason = Blocked, ReasonMissing
		if seen[runForeign] {
			r.Evidence = append(r.Evidence, ReasonForeign)
		}
		if seen[runUnpinned] {
			r.Evidence = append(r.Evidence, ReasonUnpinned)
		}
		if seen[runStale] && !seen[runForeign] && !seen[runUnpinned] { // only when it is the sole near-match
			r.Evidence = append(r.Evidence, ReasonStaleCandidate)
		}
		slices.Sort(r.Evidence)
	}
}

// judge sets the verdict for the one current matching execution.
func judge(r *ObligationResult, e *forge.JobExecution) {
	r.RunID, r.RunAttempt, r.JobID = e.RunID, e.RunAttempt, e.JobID
	switch {
	case e.SupersededBy != "":
		// A newest attempt that is already superseded means a newer attempt is missing from the snapshot.
		r.Disposition, r.Reason = Blocked, ReasonIncomplete
	case e.Conclusion == forge.ConclusionNone:
		r.Disposition, r.Reason = Pending, ReasonPending
	case e.Conclusion == forge.ConclusionFailure:
		r.Disposition, r.Reason = Blocked, ReasonFailed
	case e.Conclusion == forge.ConclusionSuccess && !e.Started.IsZero() && !e.Completed.IsZero() && !e.Completed.Before(e.Started):
		r.Disposition = Pass
	default:
		// skipped, neutral, cancelled, timed out, an unknown conclusion, or a success without sane times.
		r.Disposition, r.Reason = Blocked, ReasonNotRun
	}
}
