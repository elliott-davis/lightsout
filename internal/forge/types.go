// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

package forge

import (
	"io/fs"
	"strconv"
	"time"
)

const (
	nameUnknown = "unknown"
	nameMerged  = "merged"
)

// enumName returns names[i], or "unknown(i)" when i is out of range.
func enumName(names []string, i int) string {
	if i < 0 || i >= len(names) {
		return nameUnknown + "(" + strconv.Itoa(i) + ")"
	}
	return names[i]
}

// ActorKind says what sort of account an [Actor] is.
type ActorKind int

// Actor kinds. The zero value is unknown and never counts as a user.
const (
	ActorUnknown ActorKind = iota
	ActorUser
	ActorBot
	ActorApp
)

func (k ActorKind) String() string {
	return enumName([]string{nameUnknown, "user", "bot", "app"}, int(k))
}

// Actor is a forge account. ID is stable, and Login is for display only (SEC-10).
type Actor struct {
	Forge string
	ID    string
	Login string
	Kind  ActorKind
}

// RepoID is the forge's stable repository ID, not its name.
type RepoID string

// Repo describes a repository. Owner is the login of the owning organization or user, which a consumer compares
// ASCII case-insensitively with the org of a team before trusting that team's access.
type Repo struct {
	ID    RepoID
	Name  string
	Owner string
}

// Permission is the access level an account or team holds on one repository. The zero value is unknown and
// fails closed: it is never at least any level.
type Permission int

// Permissions, from least to most access.
const (
	PermUnknown Permission = iota
	PermNone
	PermRead
	PermTriage
	PermWrite
	PermMaintain
	PermAdmin
)

func (p Permission) String() string {
	return enumName([]string{nameUnknown, "none", "read", "triage", "write", "maintain", "admin"}, int(p))
}

// AtLeast reports whether p is known and grants at least the given level. A value outside the known range is unknown, so it is false on either side.
func (p Permission) AtLeast(least Permission) bool {
	return p > PermUnknown && p <= PermAdmin && least > PermUnknown && least <= PermAdmin && p >= least
}

// TeamPrivacy says who can see a team. The zero value is unknown and fails closed.
type TeamPrivacy int

// Team privacy values. GitHub ignores a secret team as a code owner.
const (
	PrivacyUnknown TeamPrivacy = iota
	PrivacyVisible
	PrivacySecret
)

func (p TeamPrivacy) String() string {
	return enumName([]string{nameUnknown, "visible", "secret"}, int(p))
}

// Team describes a team. Org and Slug are lowercase.
type Team struct {
	Org     string
	Slug    string
	Privacy TeamPrivacy
}

// EditState says whether a comment or review changed after it was created. The zero value fails closed.
type EditState int

// Edit states.
const (
	EditUnknown EditState = iota
	EditOriginal
	EditEdited
)

func (e EditState) String() string {
	return enumName([]string{nameUnknown, "original", "edited"}, int(e))
}

// IssueType is an issue's type, such as "bug" or "feature".
type IssueType string

// IssueState is open or closed.
type IssueState int

// Issue states.
const (
	IssueStateUnknown IssueState = iota
	IssueOpen
	IssueClosed
)

func (s IssueState) String() string {
	return enumName([]string{nameUnknown, "open", "closed"}, int(s))
}

// TypeMechanism says how SetIssueType recorded the type.
type TypeMechanism int

// Type mechanisms.
const (
	TypeMechanismUnknown TypeMechanism = iota
	TypeNative                         // the forge's issue-type field
	TypeLabel                          // the "type:<t>" label fallback
)

func (m TypeMechanism) String() string {
	return enumName([]string{nameUnknown, "native", "label"}, int(m))
}

// Issue is a forge issue. NodeID survives a transfer between repos, so it is the stable handle.
type Issue struct {
	Repo            RepoID
	Number          int
	NodeID          string
	Author          Actor
	Title, Body     string
	Type            IssueType
	Labels          []string
	State           IssueState
	Parent          int       // the parent issue's number in the same repo, or 0. Cross-repo sub-issues are not supported in v1.
	Edit            EditState // EditEdited once the body changed after creation, by anyone
	Created         time.Time
	Updated         time.Time
	TransferredFrom RepoID // set when the issue was transferred, to the repo it came from
}

// NewIssue is the input to CreateIssue. The author is always the factory identity. On a repo without native issue
// types, Type is recorded as a "type:<t>" label instead.
type NewIssue struct {
	Repo   RepoID
	Title  string
	Body   string
	Type   IssueType
	Labels []string
	Parent int
}

// Comment is an issue or pull request comment. A deleted comment does not exist: GetComment returns ErrNotFound
// and ListComments omits it.
type Comment struct {
	ID      string
	Repo    RepoID
	Issue   int
	Author  Actor
	Body    string
	Created time.Time
	Edit    EditState
}

// PRState is the state of a pull request.
type PRState int

// Pull request states.
const (
	PRStateUnknown PRState = iota
	PROpen
	PRClosed
	PRMerged
)

func (s PRState) String() string {
	return enumName([]string{nameUnknown, "open", "closed", nameMerged}, int(s))
}

// PullRequest is a forge pull request. HeadSHA and BaseSHA are full commit SHAs, and HeadSHA follows the head
// branch: a push moves it. HeadRef and BaseRef are short branch names (no refs/heads/ prefix). HeadRepo is the
// repo the head branch lives in, which is not Repo for a pull request from a fork, so a branch named
// factory/<id> in a fork is not a factory branch.
type PullRequest struct {
	Repo             RepoID
	Number           int
	Author           Actor
	HeadRepo         RepoID
	HeadRef, HeadSHA string
	BaseRef, BaseSHA string
	State            PRState
	Draft            bool
}

// ReviewState is the verdict of a review.
type ReviewState int

// Review states.
const (
	ReviewStateUnknown ReviewState = iota
	ReviewApproved
	ReviewChangesRequested
	ReviewCommented
	ReviewDismissed // the original verdict is gone, as on GitHub
)

func (s ReviewState) String() string {
	return enumName([]string{nameUnknown, "approved", "changes_requested", "commented", "dismissed"}, int(s))
}

// Review is a pull request review. CommitSHA is the commit that was reviewed, and stays the same when the pull
// request's head moves. Only the body of a review can be edited, never its verdict.
type Review struct {
	ID        string
	Repo      RepoID
	PR        int
	Author    Actor
	CommitSHA string
	State     ReviewState
	Submitted time.Time
	Edit      EditState
	Body      string
}

// CheckStatus is the progress of a check run.
type CheckStatus int

// Check statuses.
const (
	CheckStatusUnknown CheckStatus = iota
	CheckQueued
	CheckInProgress
	CheckCompleted
)

func (s CheckStatus) String() string {
	return enumName([]string{nameUnknown, "queued", "in_progress", "completed"}, int(s))
}

// CheckConclusion is the outcome of a completed check or job. The zero value means no conclusion.
type CheckConclusion int

// Check conclusions.
const (
	ConclusionNone CheckConclusion = iota
	ConclusionSuccess
	ConclusionFailure
	ConclusionNeutral
	ConclusionCancelled
	ConclusionSkipped
	ConclusionTimedOut
)

func (c CheckConclusion) String() string {
	return enumName([]string{"none", "success", "failure", "neutral", "cancelled", "skipped", "timed_out"}, int(c))
}

// ProducerAppID, here and in [JobExecution], is the integration (GitHub App) ID namespace. It is never an
// [Actor] ID: an app's bot account and the app itself have different IDs.

// CheckRun is the display and publication record of a check. It is never gate evidence on its own.
type CheckRun struct {
	ID            string
	Repo          RepoID
	HeadSHA, Name string
	ProducerAppID string
	Status        CheckStatus
	Conclusion    CheckConclusion
	Started       time.Time
	Completed     time.Time
}

// CheckRunInput is what the factory supplies to create a check run. The producer is the factory identity and is
// deliberately not a field.
type CheckRunInput struct {
	HeadSHA, Name string
	Status        CheckStatus
	Conclusion    CheckConclusion
}

// Provenance says whether every field of a [JobExecution] was established. The zero value is Incomplete, so a
// record nobody vouched for fails closed.
type Provenance int

// Provenance values.
const (
	ProvenanceIncomplete Provenance = iota
	ProvenanceComplete
)

func (p Provenance) String() string {
	return enumName([]string{"incomplete", "complete"}, int(p))
}

// JobExecution is the gate-of-record evidence (PIP-2, CON-4): a job that ran, with full provenance. Consumers
// block on Incomplete provenance. The forge layer never fills a missing field in. Consumers must still require
// exactly one non-superseded execution per job key: a superseded success is stale evidence.
type JobExecution struct {
	Repo           RepoID
	CandidateSHA   string // the commit or merge-group SHA the job ran on
	Event          string // merge_group, pull_request, push, ...
	ProducerAppID  string // the integration that ran it
	WorkflowRepo   RepoID // where the executed workflow file lives
	WorkflowPath   string
	WorkflowCommit string // the full SHA of the workflow file that actually executed
	JobKey         string // the job's rendered check name as the forge reports it, matrix values included, e.g. "test (ubuntu-latest, 1.22)"
	RunID          string
	RunAttempt     string
	JobID          string
	Started        time.Time
	Completed      time.Time
	Conclusion     CheckConclusion
	Provenance     Provenance
	SupersededBy   string // the JobID of a later attempt of the same job, or "attempt:<n>" when that attempt has no job ID
}

// FileStatus is how a file changed between two commits.
type FileStatus int

// File statuses.
const (
	FileStatusUnknown FileStatus = iota
	FileAdded
	FileModified
	FileRemoved
	FileRenamed
	FileCopied
	FileModeChanged
)

func (s FileStatus) String() string {
	return enumName([]string{nameUnknown, "added", "modified", "removed", "renamed", "copied", "mode_changed"}, int(s))
}

// ChangedFile is one entry of a comparison. A rename reports both paths.
type ChangedFile struct {
	Path         string
	PreviousPath string
	Status       FileStatus
	OldMode      fs.FileMode
	NewMode      fs.FileMode
}

// GitSignature is the name, email and time recorded in a git commit. It is not an account and is forgeable by
// whoever made the commit: never map it to an [Actor] or use it for authorization.
type GitSignature struct {
	Name  string
	Email string
	When  time.Time
}

// Commit is a commit with its full message. Verified is true only when the forge verified a signature on it. The
// zero value means unverified.
type Commit struct {
	SHA       string
	Parents   []string
	Author    GitSignature
	Committer GitSignature
	Message   string
	Verified  bool
}

// QueueState is the state of a merge-queue entry.
type QueueState int

// Queue states.
const (
	QueueStateUnknown QueueState = iota
	QueueQueued
	QueueInGroup
	QueueMerged
	QueueRemoved
)

func (s QueueState) String() string {
	return enumName([]string{nameUnknown, "queued", "in_group", nameMerged, "removed"}, int(s))
}

// QueueEntry is a pull request in the merge queue.
type QueueEntry struct {
	Repo    RepoID
	PR      int
	HeadSHA string
	State   QueueState
}

// QueueMember is a pull request in a merge group, at the head SHA it was enqueued with. CandidateSHA is the
// merge commit built for it: candidate_i is a two-parent merge of candidate_(i-1) (the base for the first member)
// and the member's head.
type QueueMember struct {
	PR           int
	HeadSHA      string
	CandidateSHA string
}

// GroupState is the state of a merge group.
type GroupState int

// Group states.
const (
	GroupStateUnknown GroupState = iota
	GroupActive
	GroupMerged
	GroupFailed // the group was dissolved, for example because a member was ejected
)

func (s GroupState) String() string {
	return enumName([]string{nameUnknown, "active", nameMerged, "failed"}, int(s))
}

// MergeGroup is a set of queued pull requests tested together at CandidateSHA, which is the last member's
// candidate commit: a chain of two-parent merges of the base and each member's head in turn.
type MergeGroup struct {
	Repo         RepoID
	CandidateSHA string
	BaseSHA      string
	Members      []QueueMember
	State        GroupState
}

// ObservedMerge is a merge the forge performed, as observed afterwards.
type ObservedMerge struct {
	Repo         RepoID
	PR           int
	HeadSHA      string
	MergedCommit string
	MergedBy     Actor
	At           time.Time
}

// RequiredCheck is a status check a branch requires, pinned to the app that must produce it. An empty AppID means
// the check is unpinned (any source may produce it), which WI-18 must reject.
type RequiredCheck struct {
	Context string
	AppID   string
}

// RuleEnforcement says whether a ruleset is enforced. The zero value is unknown.
type RuleEnforcement int

// Enforcement values.
const (
	EnforcementUnknown RuleEnforcement = iota
	EnforcementActive
	EnforcementEvaluate // reports violations without blocking
	EnforcementDisabled
)

func (e RuleEnforcement) String() string {
	return enumName([]string{nameUnknown, "active", "evaluate", "disabled"}, int(e))
}

// BranchRules are the effective rules on a branch. Complete is false when the forge could not establish them all:
// an adapter must set it false whenever it cannot map something it was shown. EnforceAdmins says administrators
// are held to the rules, Enforcement says whether the ruleset is active at all, and BypassOther is true when the
// bypass list holds entries that are not individual actors (roles, teams, deploy keys, apps), which BypassActors
// cannot represent.
// A branch with no rules reports an empty, complete set, which is what GitHub truly reports: a consumer that needs
// a required check (WI-18) must fail on an empty set.
type BranchRules struct {
	RequiredChecks     []RequiredCheck
	MergeQueueRequired bool
	BypassActors       []Actor
	BypassOther        bool
	EnforceAdmins      bool
	Enforcement        RuleEnforcement
	Complete           bool
}

// PushPolicy is what the control plane grants a pusher beyond its one ref. It is evaluated over every path that
// differs between the change's trusted base and the new commit, never over the paths a change lists.
type PushPolicy struct {
	// Workflows is GitHub's App "workflows" permission, the right to change files under .github/workflows/.
	// Coders never get it.
	Workflows bool
	// Deny reports factory-protected paths (the baseline protected list and contract files). A path it reports
	// may not differ from the trusted base. It is required: a nil Deny is invalid, so a caller that wants no extra
	// denies passes a function that returns false. Deny receives raw paths and must canonicalize them itself
	// (case, trailing dots and spaces, and the like). It is never called under the forge's locks, because it may
	// read the forge.
	Deny func(path string) bool
}

// FileWrite is one file written by a push. Executable selects mode 0o755.
type FileWrite struct {
	Path       string
	Data       []byte
	Executable bool
}

// Change is what a push applies to its parent commit's tree: writes and deletes of files.
type Change struct {
	Message string
	Writes  []FileWrite
	Deletes []string
}
