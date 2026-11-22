// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

// Package forgetest is the conformance suite every forge implementation must pass: the in-memory fake, and the
// GitHub adapter over recorded fixtures. It checks behavior the consumers rely on for security: stable
// identities, edit-state re-reads, idempotent creates, pusher scoping and compare-and-swap, tree modes and
// symlink refusal, and provenance passthrough.
//
// The suite must be passable by an honest adapter: it only asks for states a real forge can reach.
package forgetest

import (
	"context"

	"github.com/elliott-davis/lightsout/internal/forge"
	"github.com/elliott-davis/lightsout/internal/forge/gittree"
)

// Harness is a forge implementation plus the minimal setup a recorded-fixture adapter can provide. Setup methods take a context because an adapter does I/O there. Helpers store
// what they are given and never complete it. Behavior that needs the forge to mutate on demand lives in the
// optional interfaces below, and a subtest that needs one is skipped when the harness lacks it.
type Harness interface {
	forge.IdentityReader
	forge.IssueReader
	forge.IssueWriter
	forge.PRReader
	forge.DiffReader
	forge.CheckReader
	forge.CheckWriter
	forge.MergeQueue
	forge.RulesReader
	forge.TreeReader

	// Pusher binds a pusher for principal to one exact ref. It refuses a ref other than
	// refs/heads/factory/<change-id>, an unassigned change, and a principal the change is not assigned to, all
	// with ErrForbidden. The policy bounds what the branch may differ in from the trusted base, and its Deny is
	// required (a nil one is ErrInvalid).
	Pusher(ctx context.Context, principal forge.Actor, repo forge.RepoID, ref string, policy forge.PushPolicy) (forge.BranchPusher, error)

	// FactoryActor is the factory's bot account. FactoryAppID is its integration ID, a different namespace.
	FactoryActor() forge.Actor
	FactoryAppID() string

	AddRepo(ctx context.Context, name string, issueTypes bool) (forge.RepoID, error)
	// ForkRepo creates a repo that shares src's commits and branches.
	ForkRepo(ctx context.Context, src forge.RepoID, name string) (forge.RepoID, error)
	DefaultBranch(ctx context.Context, repo forge.RepoID) (string, error)
	AddActor(ctx context.Context, login string, kind forge.ActorKind) (forge.Actor, error)
	// AssignChange models the control plane issuing a change to one coder identity on a trusted base, which must be
	// an existing commit (ErrInvalid otherwise). Every push must descend from it.
	AssignChange(ctx context.Context, repo forge.RepoID, changeID string, owner forge.Actor, baseSHA string) error
	ProtectBranch(ctx context.Context, repo forge.RepoID, ref string) error
	// SetBranchRules sets what BranchRules returns for an existing branch, exactly as given.
	SetBranchRules(ctx context.Context, repo forge.RepoID, branch string, rules forge.BranchRules) error

	// AddIssue opens an issue authored by any actor, such as a human.
	AddIssue(ctx context.Context, repo forge.RepoID, author forge.Actor, title, body string) (forge.Issue, error)
	AddComment(ctx context.Context, repo forge.RepoID, issue int, author forge.Actor, body string) (forge.Comment, error)
	TransferIssue(ctx context.Context, repo forge.RepoID, number int, to forge.RepoID) (forge.Issue, error)

	// AddPullRequest opens a pull request from headRef in headRepo (the same repo, or a fork) to baseRef.
	AddPullRequest(ctx context.Context, repo forge.RepoID, author forge.Actor, headRepo forge.RepoID, headRef, baseRef string) (forge.PullRequest, error)
	AddReview(ctx context.Context, repo forge.RepoID, pr int, author forge.Actor, commitSHA string, state forge.ReviewState) (forge.Review, error)

	// CommitTree stores a commit whose whole tree is entries and returns its SHA. It moves no ref.
	CommitTree(ctx context.Context, repo forge.RepoID, parents []string, message string, entries []gittree.Entry) (string, error)
	SetRef(ctx context.Context, repo forge.RepoID, ref, sha string) error

	AddCheckRun(ctx context.Context, cr forge.CheckRun) (forge.CheckRun, error)
	AddJobExecution(ctx context.Context, je forge.JobExecution) error
}

// Editor changes content after it was read, so the suite can check that re-reads see the current state.
type Editor interface {
	EditComment(ctx context.Context, repo forge.RepoID, id, body string) error
	DeleteComment(ctx context.Context, repo forge.RepoID, id string) error
	EditReview(ctx context.Context, repo forge.RepoID, pr int, id, body string) error
	DismissReview(ctx context.Context, repo forge.RepoID, pr int, id string) error
	EditIssue(ctx context.Context, repo forge.RepoID, number int, body string) error
}

// Identities changes accounts and teams.
type Identities interface {
	RenameActor(ctx context.Context, id, login string) error
	RevokeActor(ctx context.Context, id string) error
	MarkReviewer(ctx context.Context, id string) error
	AddTeamMember(ctx context.Context, org, team, actorID string) error
	RemoveTeamMember(ctx context.Context, org, team, actorID string) error
}

// TreeSetup configures tree reads and comparisons.
type TreeSetup interface {
	SetTreeLimits(ctx context.Context, lim gittree.Limits) error
	DeclareRename(ctx context.Context, repo forge.RepoID, headSHA, from, to string) error
}

// QueueSetup drives the merge queue the way the forge itself would.
type QueueSetup interface {
	SetPullRequestHead(ctx context.Context, repo forge.RepoID, number int, sha string) error
	ClosePullRequest(ctx context.Context, repo forge.RepoID, number int) error
	SetPullRequestDraft(ctx context.Context, repo forge.RepoID, number int, draft bool) error
	RetargetPullRequest(ctx context.Context, repo forge.RepoID, number int, newBase string) error
	// FormGroup builds one candidate commit per member from the caller's cumulative trees.
	FormGroup(ctx context.Context, repo forge.RepoID, prs []int, trees [][]gittree.Entry) (forge.MergeGroup, error)
	// EjectMember rebuilds the members after the ejected one from suffixTrees.
	EjectMember(ctx context.Context, repo forge.RepoID, candidateSHA string, pr int, suffixTrees [][]gittree.Entry) (forge.MergeGroup, error)
	RecordMerge(ctx context.Context, repo forge.RepoID, m forge.ObservedMerge) error
}

// FaultInjector makes an operation fail the way a truncated forge answer does. The operations are the capability
// method names ListComments, ListReviews, Compare, Commits, ListJobExecutions and Tree.
type FaultInjector interface {
	InjectIncomplete(ctx context.Context, op string) error
}
