// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

// Package authz authorizes human decisions at execution time (SEC-10, NFR-5).
//
// A decision binds one operation, one scope, one subject and one exact revision. The action handler computes a
// [Target] from authoritative state and calls [Authorizer.Authorize], which rechecks identity, role, scope and
// revision against current sources, consumes the decision ID and audits the outcome. Nothing is cached: a grant
// is evidence for the caller's records, never a reusable capability.
//
// Authorization is never inferred from comment text. The adapter that verified the event fills in [Decision],
// and everything in it other than the revision, choice and operation comes from the forge, not from the text.
package authz

import (
	"context"
	"slices"
	"time"

	"github.com/elliott-davis/lightsout/internal/audit"
)

// PrincipalKind says what sort of account authored an event.
type PrincipalKind string

// Principal kinds. Only a user can approve anything.
const (
	PrincipalUser PrincipalKind = "user"
	PrincipalBot  PrincipalKind = "bot"
	PrincipalApp  PrincipalKind = "app"
)

// Principal is the forge's authenticated author of an event.
type Principal struct {
	Forge string
	ID    string // the forge's stable ID
	Login string // display only, never used for identity
	Kind  PrincipalKind
}

// ScopeKind says whether a scope is one repository or the whole installation.
type ScopeKind string

// Scope kinds.
const (
	ScopeRepo    ScopeKind = "repo"
	ScopeInstall ScopeKind = "install"
)

// Scope is the repository or installation a decision applies to.
type Scope struct {
	Kind ScopeKind
	ID   string
}

// Operation is the closed set of privileged human operations.
type Operation string

// Operations.
//
// [OpActivateInstall] is one approver's decision. Activating an install revision needs the install's quorum of distinct
// granted decisions, each by a different member of the currently active revision, and each bound (Target.Revision) to the
// value of install.ActivationRevision: the installation, the active generation and the candidate commit. Authz checks one decision at a time and cannot count, so the caller (the activation path, WI-10 and
// WI-11) gathers the grants and counts distinct principals in the same transaction that compares and swaps the active
// generation.
const (
	OpConfirmClassification Operation = "confirm-classification" // INT-3
	OpDecideSplit           Operation = "decide-split"           // INT-11
	OpApproveScenarios      Operation = "approve-scenarios"      // INT-4
	OpRejectScenarios       Operation = "reject-scenarios"       // INT-4: returns the work to refinement
	OpApprovePathException  Operation = "approve-path-exception" // CON-7
	OpApproveLightsOn       Operation = "approve-lights-on"      // CON-8
	OpActivateContract      Operation = "activate-contract"      // CON-2
	OpActivateInstall       Operation = "activate-install"       // RUN-1: activates an install config revision
	OpHalt                  Operation = "halt"                   // SEC-6
	OpResume                Operation = "resume"                 // SEC-6
)

// Role is a role a principal must hold, now, to take part in an operation.
type Role string

// Roles.
const (
	RoleIdeator       Role = "ideator"
	RolePathOwner     Role = "path-owner"
	RoleCodeOwner     Role = "code-owner"
	RoleContractOwner Role = "contract-owner"
	RoleAdmin         Role = "admin"
	// RolePolicyApprover is held by the install's policy approvers (Enterprise IT), who activate install config
	// revisions. A decision proves one approver. Quorum is the caller's job: see [OpActivateInstall].
	RolePolicyApprover Role = "policy-approver"
)

// Channel is how the decision arrived.
type Channel string

// Channels.
const (
	ChannelIssueComment Channel = "issue-comment"
	ChannelReview       Channel = "review"
	ChannelAPI          Channel = "api"
	ChannelAdminCLI     Channel = "admin-cli"
)

// Integrity says whether the event still is what its author posted. Its zero value is not a pass, so an adapter
// that forgets to set it fails closed.
type Integrity int

// Integrity values. Only [IntegrityOriginal] passes.
const (
	IntegrityUnknown  Integrity = iota // not checked
	IntegrityOriginal                  // unedited and not quoted
	IntegrityEdited                    // edited after creation
	IntegrityQuoted                    // the command sat inside a quote
)

// Location is where the event was posted. It comes from the event itself, never from text.
type Location struct {
	Scope   Scope
	Subject audit.Subject
}

// Decision is what a forge or API adapter extracts from one authenticated event.
type Decision struct {
	// ID is the canonical, globally unique source ID (forge, event kind and event ID). It is the unit of replay
	// protection.
	ID            string
	Channel       Channel   // one of the four closed channels; anything else is malformed
	Principal     Principal // the event's authenticated author, as the forge reports it
	Authenticated bool      // set only by the adapter that verified the event
	Location      Location
	Operation     Operation // the operation the principal invoked
	// Revision is the revision the principal named in the structured command: a 40- or 64-digit lowercase hex
	// digest. Producers digest composed inputs (WI-19, WI-36).
	Revision string
	Choice   string // digest of the choice, required for operations that take one and forbidden for the rest
	// Integrity is set to [IntegrityOriginal] only after the adapter checked the forge's edit state at execution
	// time, not only when the event was captured (WI-10).
	Integrity Integrity
	Created   time.Time
}

// Target is what the action handler is about to do, computed fresh from authoritative state.
type Target struct {
	Operation Operation
	Scope     Scope
	Subject   audit.Subject
	// Revision is the current revision, a 40- or 64-digit lowercase hex digest. It must pin every approved input and be unique to the subject, so an
	// identical proposal on another issue, or an edit that is later reverted, has a different revision.
	Revision string
	Choice   string   // digest of the choice the handler is about to execute
	Paths    []string // the area; required (non-empty) for owner roles
}

// RoleSource answers whether a principal holds a role right now, for the target. Callers must not cache.
// Authorize clears Principal.Login before the call: resolve by Forge and ID together, because IDs are unique only
// within one forge and logins can be renamed or recycled. For an owner role the principal must own every path in
// Target.Paths.
type RoleSource interface {
	HasRole(ctx context.Context, p Principal, r Role, t Target) (bool, error)
}

// Tx is the caller's transaction. Consume and the grant's audit append run in it together with the caller's own
// state change, so all of them commit or roll back together.
type Tx interface {
	// Consume records the decision ID as used. It returns [ErrReplayed] if the ID was ever consumed.
	Consume(ctx context.Context, decisionID string) error
	// Append appends r to the audit log inside the transaction.
	Append(ctx context.Context, r audit.Record) (audit.Entry, error)
}

// Auditor records denials outside the caller's transaction, so a rollback cannot erase a denial. *audit.Log
// satisfies it.
type Auditor interface {
	Append(ctx context.Context, r audit.Record) (audit.Entry, error)
}

// Grant is the evidence of one granted decision. It is not a capability and must not be stored for reuse.
type Grant struct {
	DecisionID string
	Target     Target
	Seq        uint64 // the audit sequence number of the grant entry
}

// opPolicy is the required role, scope kind and allowed subject kinds of one operation.
type opPolicy struct {
	Role      Role
	ScopeKind ScopeKind
	Subjects  []audit.SubjectKind
	Choice    bool // the operation takes a choice, which must then be non-empty
	Area      bool // an owner role: the target must name the area (Paths)
}

// operations returns the policy table. It is a function, not a variable, so there is no mutable package state.
func operations() map[Operation]opPolicy {
	issue := []audit.SubjectKind{audit.SubjectIssue}
	change := []audit.SubjectKind{audit.SubjectChange}
	install := []audit.SubjectKind{audit.SubjectInstall}
	return map[Operation]opPolicy{
		OpConfirmClassification: {Role: RoleIdeator, ScopeKind: ScopeRepo, Subjects: issue},
		OpDecideSplit:           {Role: RoleIdeator, ScopeKind: ScopeRepo, Subjects: issue, Choice: true},
		OpApproveScenarios:      {Role: RoleIdeator, ScopeKind: ScopeRepo, Subjects: issue},
		OpRejectScenarios:       {Role: RoleIdeator, ScopeKind: ScopeRepo, Subjects: issue},
		OpApprovePathException:  {Role: RolePathOwner, ScopeKind: ScopeRepo, Subjects: change, Area: true},
		OpApproveLightsOn:       {Role: RoleCodeOwner, ScopeKind: ScopeRepo, Subjects: change, Area: true},
		OpActivateContract:      {Role: RoleContractOwner, ScopeKind: ScopeRepo, Subjects: change, Area: true},
		OpActivateInstall:       {Role: RolePolicyApprover, ScopeKind: ScopeInstall, Subjects: install},
		OpHalt:                  {Role: RoleAdmin, ScopeKind: ScopeInstall, Subjects: install},
		OpResume:                {Role: RoleAdmin, ScopeKind: ScopeInstall, Subjects: install},
	}
}

// Operations returns every operation, sorted. Install config validates its per-operation settings against it.
func Operations() []Operation {
	ops := operations()
	out := make([]Operation, 0, len(ops))
	for op := range ops {
		out = append(out, op)
	}
	slices.Sort(out)
	return out
}
