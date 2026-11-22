// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

// Package review decides whether a change's reviews are complete (AGT-3, AGT-4, AGT-5, SEC-5, AGD-3, CON-8, INT-20).
//
// [Evaluate] is pure: it takes the effective contract, a complete snapshot of the factory's review evidence and the
// trusted runtime keys, and does no I/O. It authorizes nothing and waives nothing: escalation hands the change to a
// person but never passes it. See docs/design/review.md.
package review

import (
	"crypto/ed25519"
	"time"

	"github.com/elliott-davis/lightsout/internal/authz"
	"github.com/elliott-davis/lightsout/internal/contract"
	"github.com/elliott-davis/lightsout/internal/forge"
	"github.com/elliott-davis/lightsout/internal/gate"
)

// Target is the change a decision is for. HeadSHA is the only head whose approvals count.
type Target struct {
	Forge   string
	Repo    forge.RepoID
	PR      int
	HeadSHA string // 40 or 64 lowercase hex characters
}

// Purpose says what an assignment is for.
type Purpose string

// Purposes.
const (
	PurposeReview Purpose = "review"
	PurposeVerify Purpose = "verify" // verifies one claim
)

// ClaimRef names a claim instance: the role that raised it, its ID and the digest of its content ([Claim.Digest]).
// Raising the same ID again with different content is a new instance, and it starts open.
type ClaimRef struct {
	Role   string
	ID     string
	Digest string
}

// Assignment is issued by the control plane for one reviewer or verifier session. It is not signed: it is part of
// the snapshot, and the signed records bind to it by its ID and its digest ([Assignment.Digest]). ManifestDigest pins what the session was shown.
type Assignment struct {
	ID             string
	Forge          string
	Repo           forge.RepoID
	PR             int
	HeadSHA        string
	RoundID        string
	RoundSeq       int // the round's sequence number: the snapshot's round must agree
	Role           string
	Profile        string // the pinned agent profile digest (AGT-7)
	ManifestDigest string
	Purpose        Purpose
	ClaimRef       ClaimRef // verify assignments only
	Session        string
}

// Item kinds a reviewer may be shown (AGT-3). Anything else is forbidden, including coder reasoning, transcripts
// and private holdouts.
const (
	KindSpec       = "spec"
	KindDiff       = "diff"
	KindRepoFile   = "repo-file"
	KindCaller     = "caller"
	KindContract   = "contract"
	KindHistory    = "history"
	KindPublicTest = "public-test"
)

// Item sides.
const (
	SideBase = "base"
	SideHead = "head"
)

// Item is one piece of reviewer context. Side is "base", "head" or empty.
type Item struct {
	Kind   string
	Path   string
	Side   string
	Digest string
}

// Manifest is everything a reviewer session was shown.
type Manifest struct {
	HeadSHA string
	Items   []Item
}

// Verdicts.
const (
	VerdictApprove      = "approve"
	VerdictBlock        = "block"
	VerdictRequestSplit = "request-split"
)

// Claim is a provisional block (AGT-4). Every field is required. It is keyed by the claimant role and ID.
type Claim struct {
	ID               string
	Path             string
	StartLine        int
	EndLine          int
	Invariant        string
	Consequence      string
	VerificationPlan string
}

// Attestation is a reviewer's complete verdict, signed by the agent runtime with the session's workload identity.
// Everything except Signature is covered by [Attestation.SigningPayload].
type Attestation struct {
	AssignmentID string
	// AssignmentDigest is [Assignment.Digest] of the assignment the runtime saw. A signature over it binds the verdict
	// to the head, the PR, the manifest and the session, so a writer can't move or rewrite an assignment.
	AssignmentDigest string
	Verdict          string
	Claims           []Claim
	// SplitGateID is the size gate a request-split cites (INT-20).
	SplitGateID string
	// SensitiveSignoff is the exact set of sensitive paths (and old paths of renames) the security reviewer signs off
	// (SEC-5).
	SensitiveSignoff []string
	// Repaired lists claim instances of this role the coder has since repaired, each as "<id>#<claim digest>"
	// ([RepairedRef]).
	Repaired  []string
	At        time.Time
	KeyID     string
	Signature []byte
}

// Resolution outcomes.
const (
	OutcomeConfirmed = "confirmed"
	OutcomeDismissed = "dismissed"
)

// GateEvidence cites one job of a trusted gate. It must match a mandatory obligation of the change.
type GateEvidence struct {
	Gate         contract.GateRef
	RunID        string
	RunAttempt   string
	JobID        string
	CandidateSHA string
}

// Evidence is what a verifier observed: either the digest of a reproducible proof, or a trusted gate's job.
// Exactly one is set.
type Evidence struct {
	ProofDigest string // "sha256:" and 64 hex characters
	Gate        *GateEvidence
}

// Resolution is an independent verifier's signed finding on one claim (AGT-4).
type Resolution struct {
	AssignmentID     string // a verify assignment for Claim
	AssignmentDigest string // [Assignment.Digest], as in [Attestation]
	// Claim is the claim instance resolved. Its Digest is the signed claim digest.
	Claim            ClaimRef
	ReviewedRevision string // the head the verifier examined
	Procedure        string
	Expected         string
	Outcome          string
	Evidence         Evidence
	At               time.Time
	KeyID            string
	Signature        []byte
}

// Round states.
const (
	RoundDispatched = "dispatched"
	RoundCompleted  = "completed"
	RoundSuperseded = "superseded"
)

// Round is one factory-dispatched review pass (AGT-5). A head change mid-round supersedes it.
type Round struct {
	ID      string
	Seq     int
	HeadSHA string
	State   string
	Roles   []string
}

// ChangedPath is one changed file. OldPath is required for a rename or a copy and forbidden otherwise. For a removed
// file, Path is the old path.
type ChangedPath struct {
	Path    string
	OldPath string
	Status  forge.FileStatus
}

// Approval is the declared data of an approval manifest: what a human approves for CON-8 (lights-on) or PIP-9
// (non-switchable). Editing and restoring any of it needs a new Generation, so an earlier approval is invalidated.
type Approval struct {
	Generation       int
	ImpactRevision   string
	RecoveryRevision string
	Callers          []string
	RolloutOrder     []string
}

// Snapshot is the factory's review evidence for one change. When Complete is false nothing passes.
type Snapshot struct {
	Assignments  []Assignment
	Attestations []Attestation
	Resolutions  []Resolution
	Rounds       []Round
	// Manifests holds what each review assignment was shown, keyed by assignment ID.
	Manifests     map[string]Manifest
	CoderSessions []string
	// LightsOn is the approval data for a lights-on change (eff.LightsOn).
	LightsOn *Approval
	// NonSwitchable declares the change non-switchable even if LightsOn is false (PIP-9), and carries its approval
	// data. It is nil when the change is switchable. It wins over LightsOn when both are set.
	NonSwitchable *Approval
	ChangedPaths  []ChangedPath
	// OwnerAreas groups the changed paths by current owner area. WI-18 computes them with WI-09.
	OwnerAreas [][]string
	// Gate is the gate decision for the change, used to check gate evidence of a resolution.
	Gate         *gate.Decision
	StateVersion string
	Complete     bool
}

// Config is the install's review limits. A zero value is invalid input.
type Config struct {
	ReviewRounds   int           // AGT-5, default 3
	VerifyAttempts int           // verify assignments per claim, default 3
	VerifyTimeout  time.Duration // how long a claim may stay unresolved
	SizeGateID     string        // the review-budget gate a split request must cite (INT-20)
	// PRReviewer is the role that reviews every change (AGD-3). WI-18 fills it from Baseline.PRReviewer. It must be
	// one of the effective contract's reviewers and differ from its security reviewer.
	PRReviewer string
}

// Key is a trusted runtime key. Session is the one session it signs for: a signature counts only for an assignment
// with that session, and never when the session is the coder's.
type Key struct {
	Pub     ed25519.PublicKey
	Session string
	// Kind says what the runtime made the key for. WI-18 injects it from the runtime's own records. The zero value
	// is invalid.
	Kind KeyKind
}

// KeyKind says what a runtime key signs for.
type KeyKind int

// Key kinds. A review assignment needs a [KeyReviewer] key and a verify assignment needs a [KeyVerifier] key. A
// [KeyCoder] key never counts.
const (
	KeyReviewer KeyKind = iota + 1
	KeyVerifier
	KeyCoder
)

// Keys are the trusted runtime keys by key ID. They are injected, never read from the snapshot.
type Keys map[string]Key

// Disposition is the outcome of an obligation or of the whole change. [Evaluate] orders them
// error > escalated > blocked > replan > pending > needs-authorization > pass.
type Disposition string

// Dispositions.
const (
	// Pass means every obligation is met.
	Pass Disposition = "pass"
	// NeedsAuthorization means the reviews passed, but a human approval (CON-8, PIP-9) is still needed. It is never
	// Pass. WI-18 may merge only after it authorizes every Decision.RequiredApprovals target at execution time, in
	// the same state transition as the merge. Nothing in this package can satisfy it.
	NeedsAuthorization Disposition = "needs-authorization"
	// Pending means evidence is still to come.
	Pending Disposition = "pending"
	// Replan means a reviewer asked for a split (INT-20). The spec writer replans.
	Replan Disposition = "replan"
	// Blocked is terminal for this evidence: repair the cause.
	Blocked Disposition = "blocked"
	// Escalated means a cap was reached (AGT-5, AGT-4). A contract owner is assigned. It is never a pass.
	Escalated Disposition = "escalated"
	// Error means the input or evidence is unusable.
	Error Disposition = "error"
)

func (d Disposition) rank() int {
	switch d {
	case Pass:
		return 0
	case Error:
		return 6
	case NeedsAuthorization:
		return 1
	case Pending:
		return 2
	case Replan:
		return 3
	case Blocked:
		return 4
	case Escalated:
		return 5
	default:
		return 6 // an unknown disposition is as bad as an error
	}
}

// Reason says why an obligation, a record or the whole decision did not pass.
type Reason string

// Reasons for a decision or an obligation.
const (
	ReasonInvalidInput       Reason = "invalid-input"
	ReasonIncompleteEvidence Reason = "incomplete-evidence"
	// ReasonInconsistentEvidence means a key-verified record can't be placed in the snapshot: the snapshot's writer
	// dropped or altered something it signs for.
	ReasonInconsistentEvidence Reason = "inconsistent-evidence"
	ReasonInvalidVerdict       Reason = "invalid-verdict"
	ReasonNoApproval           Reason = "no-current-approval"
	ReasonReviewerBlocked      Reason = "reviewer-blocked"
	ReasonSplitRequested       Reason = "split-requested"
	ReasonSessionReuse         Reason = "session-not-independent"
	ReasonSignoffMissing       Reason = "sensitive-signoff-missing"
	ReasonClaimOpen            Reason = "claim-unresolved"
	ReasonClaimConfirmed       Reason = "claim-confirmed"
	ReasonClaimReverify        Reason = "claim-awaiting-reverification"
	ReasonClaimEscalated       Reason = "claim-escalated"
	ReasonRoundsExhausted      Reason = "review-rounds-exhausted"
	ReasonLightsOn             Reason = "authorization-required"
	ReasonSatisfied            Reason = "satisfied"
)

// Reasons a record is rejected. A rejected record never approves anything.
const (
	ReasonBadSignature         Reason = "bad-signature"
	ReasonUnknownAssignment    Reason = "unknown-assignment"
	ReasonDuplicateAssignment  Reason = "duplicate-assignment"
	ReasonWrongTarget          Reason = "wrong-target"
	ReasonWrongPurpose         Reason = "wrong-purpose"
	ReasonBadAssignment        Reason = "bad-assignment"
	ReasonCoderSession         Reason = "coder-session"
	ReasonManifestMissing      Reason = "manifest-missing"
	ReasonManifestMismatch     Reason = "manifest-digest-mismatch"
	ReasonManifestHead         Reason = "manifest-head-mismatch"
	ReasonForbiddenContext     Reason = "forbidden-context"
	ReasonMalformed            Reason = "malformed"
	ReasonBadVerdict           Reason = "bad-verdict"
	ReasonBadClaim             Reason = "malformed-claim"
	ReasonWrongSplitGate       Reason = "wrong-split-gate"
	ReasonConflictingRecords   Reason = "conflicting-records"
	ReasonUnknownClaim         Reason = "unknown-claim"
	ReasonVerifierNotIndep     Reason = "verifier-not-independent"
	ReasonBadEvidence          Reason = "bad-evidence"
	ReasonGateEvidenceMismatch Reason = "gate-evidence-mismatch"
	ReasonBadBinding           Reason = "bad-binding"
	ReasonFromFuture           Reason = "timestamp-in-future"
	ReasonRoundMismatch        Reason = "round-mismatch"
	ReasonRoundSuperseded      Reason = "round-superseded"
	ReasonRoleNotInRound       Reason = "role-not-in-round"
	ReasonManifestIncomplete   Reason = "manifest-incomplete"
	ReasonBeforeClaim          Reason = "resolution-before-claim"
	ReasonRoundBeforeClaim     Reason = "round-before-claim"
)

// RecordKind says what kind of record a [Rejection] is about.
type RecordKind string

// Record kinds.
const (
	RecordAssignment  RecordKind = "assignment"
	RecordAttestation RecordKind = "attestation"
	RecordResolution  RecordKind = "resolution"
)

// Rejection reports a record that was ignored, and why. ID is the assignment ID.
type Rejection struct {
	Kind   RecordKind
	ID     string
	Reason Reason
}

// Obligation kinds.
const (
	KindRole     = "role"
	KindSignoff  = "signoff"
	KindClaim    = "claim"
	KindSplit    = "split"
	KindRounds   = "rounds"
	KindApproval = "lights-on"
)

// Actions an obligation asks of its owner.
const (
	ActionDispatch    = "dispatch-reviewer"
	ActionReassign    = "reassign-reviewer"
	ActionRepair      = "repair-and-rereview"
	ActionSignoff     = "supply-sensitive-signoff"
	ActionVerify      = "verify-claim"
	ActionAssignOwner = "assign-owner"
	ActionReplan      = "replan"
	ActionAuthorize   = "authorize-lights-on"
)

// Obligation is one thing the change still needs, or has satisfied. IDs are stable: "role:<role>",
// "claim:<role>/<id>#<digest>", "signoff:sensitive", "lights-on:<area digest>", "split" and "rounds".
type Obligation struct {
	ID          string
	Kind        string
	Disposition Disposition
	Reason      Reason
	Evidence    []string // assignment IDs and similar references, sorted
	Action      string   // empty when satisfied
}

// Decision is the result of [Evaluate]. It binds to the contract revision, install revision, head and state version:
// WI-18 compares StateVersion right before it publishes, and checks that the PR and head belong to the current queue
// candidate.
type Decision struct {
	Target
	PolicyRevision  string
	InstallRevision string
	StateVersion    string
	Disposition     Disposition
	// Reasons are decision-level reasons: invalid-input or incomplete-evidence.
	Reasons     []Reason
	Obligations []Obligation // sorted by ID
	Rejected    []Rejection  // sorted
	// RequiredApprovals are the human approvals a lights-on or non-switchable change needs, one per owner area.
	// This package never authorizes them: see [NeedsAuthorization].
	RequiredApprovals []authz.Target
}
