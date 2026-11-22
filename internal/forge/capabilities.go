// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

package forge

import (
	"context"
	"io/fs"
)

// The capability interfaces below are the full list the fake and the adapters implement. Consumers declare the
// subset they use, in their own package.

// IdentityReader reads accounts and team membership.
type IdentityReader interface {
	// GetActor returns the actor's current login. A revoked or unknown ID is ErrNotFound.
	GetActor(ctx context.Context, id string) (Actor, error)
	// IsTeamMember checks membership live, with no cache. Org and team are passed lowercase.
	IsTeamMember(ctx context.Context, org, team, actorID string) (bool, error)
}

// PermissionReader reads repository ownership and access, which GitHub requires before it honors a code owner:
// an owner without write access to the repository is ignored.
type PermissionReader interface {
	// GetRepo returns the repository's current description. An unknown repo is ErrNotFound.
	GetRepo(ctx context.Context, repo RepoID) (Repo, error)
	// RepoPermission returns the actor's effective permission on the repo, read live with no cache. A revoked or
	// deleted actor has PermNone. An unknown actor or repo is ErrNotFound.
	RepoPermission(ctx context.Context, repo RepoID, actorID string) (Permission, error)
	// GetTeam returns the team, with its privacy. An unknown team is ErrNotFound. Org and team are lowercase.
	GetTeam(ctx context.Context, org, team string) (Team, error)
	// TeamRepoPermission returns the team's permission on the repo, read live with no cache. A team with no access
	// has PermNone. An unknown repo is ErrNotFound. Org and team are lowercase.
	TeamRepoPermission(ctx context.Context, repo RepoID, org, team string) (Permission, error)
}

// IssueReader reads issues and comments.
type IssueReader interface {
	GetIssue(ctx context.Context, repo RepoID, number int) (Issue, error)
	// GetIssueByNodeID finds an issue by its stable node ID, wherever it lives now.
	GetIssueByNodeID(ctx context.Context, nodeID string) (Issue, error)
	// ListSubIssues returns the direct sub-issues of parent, by number.
	ListSubIssues(ctx context.Context, repo RepoID, parent int) ([]Issue, error)
	// ListComments returns every comment or ErrIncomplete. A deleted comment is omitted. A missing issue is ErrNotFound.
	ListComments(ctx context.Context, repo RepoID, issue int) ([]Comment, error)
	// GetComment re-reads one comment, including its current edit state. A deleted comment is ErrNotFound.
	GetComment(ctx context.Context, repo RepoID, id string) (Comment, error)
}

// IssueWriter changes issues.
type IssueWriter interface {
	// CreateIssue returns the existing issue when idempotencyKey was already used in the repo, wherever that issue
	// lives now: keys are per repo and follow the issue across a transfer. Callers check Repo.
	CreateIssue(ctx context.Context, in NewIssue, idempotencyKey string) (Issue, error)
	UpdateIssueBody(ctx context.Context, repo RepoID, number int, body string) error
	// SetIssueType falls back to a "type:<t>" label when the repo has no issue types, and says which it used.
	SetIssueType(ctx context.Context, repo RepoID, number int, t IssueType) (TypeMechanism, error)
	AddLabels(ctx context.Context, repo RepoID, number int, labels ...string) error
	RemoveLabel(ctx context.Context, repo RepoID, number int, label string) error
	CreateComment(ctx context.Context, repo RepoID, issue int, body string) (Comment, error)
	// AddSubIssue is idempotent and moves the child if it had another parent. It rejects self-parenting and cycles
	// with ErrInvalid. Both issues must be in the same repo.
	AddSubIssue(ctx context.Context, repo RepoID, parent, child int) error
}

// PRReader reads pull requests and reviews.
type PRReader interface {
	GetPullRequest(ctx context.Context, repo RepoID, number int) (PullRequest, error)
	ListReviews(ctx context.Context, repo RepoID, pr int) ([]Review, error)
	// GetReview re-reads one review, including its current edit and dismissal state.
	GetReview(ctx context.Context, repo RepoID, pr int, id string) (Review, error)
}

// DiffReader compares commits.
type DiffReader interface {
	// Compare returns the complete changed-file list of headSHA against the merge base of baseSHA and headSHA, as
	// GitHub's three-dot compare does, or ErrIncomplete. Two commits with no common ancestor are ErrNotFound.
	// Renames are best effort: a policy consumer must treat a rename as a removal of PreviousPath and an addition
	// of Path.
	Compare(ctx context.Context, repo RepoID, baseSHA, headSHA string) ([]ChangedFile, error)
	// Commits returns every commit reachable from headSHA and not from baseSHA, with its full message, oldest first
	// (parents before children). Two commits with no common ancestor are ErrNotFound, as for Compare.
	Commits(ctx context.Context, repo RepoID, baseSHA, headSHA string) ([]Commit, error)
}

// CheckReader reads check runs and job executions.
type CheckReader interface {
	ListCheckRuns(ctx context.Context, repo RepoID, sha string) ([]CheckRun, error)
	ListJobExecutions(ctx context.Context, repo RepoID, sha string) ([]JobExecution, error)
}

// CheckWriter publishes the factory's own checks. The producer is always the factory identity.
type CheckWriter interface {
	CreateCheckRun(ctx context.Context, repo RepoID, in CheckRunInput) (CheckRun, error)
	// UpdateCheckRun changes a check run the factory created. Another app's run is ErrForbidden.
	UpdateCheckRun(ctx context.Context, repo RepoID, id string, status CheckStatus, conclusion CheckConclusion) (CheckRun, error)
}

// MergeQueue reads and feeds the merge queue. Enqueue alone never starts any stage.
type MergeQueue interface {
	// Enqueue fails with ErrConflict unless the pull request is open and its head is expectedHeadSHA. A push to a
	// queued pull request removes it from the queue.
	Enqueue(ctx context.Context, repo RepoID, pr int, expectedHeadSHA string) (QueueEntry, error)
	Dequeue(ctx context.Context, repo RepoID, pr int) error
	QueueEntries(ctx context.Context, repo RepoID) ([]QueueEntry, error)
	MergeGroups(ctx context.Context, repo RepoID) ([]MergeGroup, error)
	ObservedMerges(ctx context.Context, repo RepoID) ([]ObservedMerge, error)
}

// RulesReader reads effective branch rules.
type RulesReader interface {
	BranchRules(ctx context.Context, repo RepoID, branch string) (BranchRules, error)
}

// TreeReader reads repository content at pinned commits.
type TreeReader interface {
	// ResolveRef resolves a ref once to a full commit SHA.
	ResolveRef(ctx context.Context, repo RepoID, ref string) (string, error)
	// Tree returns the tracked tree at a full 40- or 64-hex commit SHA. A short SHA or a ref is an error.
	Tree(ctx context.Context, repo RepoID, sha string) (fs.FS, error)
	ReadFile(ctx context.Context, repo RepoID, sha, path string) ([]byte, error)
}

// BranchPusher pushes to the one ref it was bound to at construction (SEC-2, SEC-3). It cannot merge or enqueue.
type BranchPusher interface {
	// Push applies change on top of expectedParentSHA as a compare-and-swap and returns the new commit SHA.
	// A stale parent is ErrConflict. A denied principal, branch or ref is ErrForbidden.
	Push(ctx context.Context, expectedParentSHA string, change Change) (string, error)
}
