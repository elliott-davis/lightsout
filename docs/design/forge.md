# Forge boundary (INTG-1 interface)

Status: accepted after a Codex review, 2026-11-21. Covers WI-08: the `internal/forge` domain types, the capability interfaces, a read-only `fs.FS` over a
git tree, the in-memory fake every later work item tests against, and a shared conformance suite. The GitHub adapter (WI-12) runs the
same suite against recorded fixtures. Webhook ingestion is WI-10. Credential scoping is WI-30.

## Principles

- **The forge is the source of record, and its content is untrusted.** Identities, edit state, check provenance and
  tree contents come from the forge API. Any text inside them is untrusted input (SEC-1).
- **Stable IDs, never names.** Actors are `(forge, numeric ID)`, and a login is display only (SEC-10). Issues carry a stable
  node ID that survives a transfer. Gate evidence is a job execution with full provenance, never a check name (CON-4, PIP-2).
- **Everything is pinned.** Content and diffs are read at full commit SHAs. A ref is resolved once.
- **Complete or an error.** A truncated tree, a capped file list, or missing provenance is an explicit error (`ErrIncomplete`), never a partial
  result. The fake must never produce evidence the GitHub adapter can't obtain, and the conformance suite keeps the two honest.
- **Small interfaces defined by consumers.** `internal/forge` defines the domain types and exports capability interfaces only so
  the fake and the adapters can be checked against one list. Consumers declare the subset they use.
- **Only `internal/forge/github` imports go-github** (depguard).

## Domain types (package `forge`)

```go
type Actor struct { Forge, ID, Login string; Kind ActorKind /* user | bot | app */ }
type RepoID string                      // stable forge repo ID
type EditState int                      // EditUnknown (zero: fail closed) | EditOriginal | EditEdited

type Issue struct {
    Repo RepoID; Number int; NodeID string   // NodeID survives a transfer
    Author Actor; Title, Body string; Type IssueType; Labels []string; State IssueState
    Parent int /* same repo only in v1 */; Edit EditState; Created, Updated time.Time; TransferredFrom RepoID
}
type Comment struct { ID string; Repo RepoID; Issue int; Author Actor; Body string; Created time.Time; Edit EditState }
type PullRequest struct { Repo, HeadRepo RepoID; Number int; Author Actor; HeadRef, HeadSHA, BaseRef, BaseSHA string /* refs are short branch names */; State PRState; Draft bool }
type Review struct { ID string; Repo RepoID; PR int; Author Actor; CommitSHA string /* the reviewed commit */; State ReviewState /* unknown (zero) | approved | changes_requested | commented | dismissed */; Submitted time.Time; Edit EditState; Body string }

// CheckRun is the display and publication record. It is never gate evidence on its own.
type CheckRun struct { ID string; Repo RepoID; HeadSHA, Name string; ProducerAppID string; Status CheckStatus; Conclusion CheckConclusion; Started, Completed time.Time }

// JobExecution is the gate-of-record evidence (PIP-2, CON-4). WI-13 decides. This is what WI-12 must be able to substantiate end to end.
type JobExecution struct {
    Repo          RepoID
    CandidateSHA  string   // the commit or merge-group SHA the job ran on
    Event         string   // merge_group | pull_request | push | ...
    ProducerAppID string   // the integration (App) ID that ran it, e.g. GitHub Actions. Never an Actor ID
    WorkflowRepo  RepoID   // where the executed workflow file lives (differs for reusable workflows)
    WorkflowPath  string
    WorkflowCommit string  // the commit of the workflow file that actually executed (full SHA)
    JobKey        string   // the job's rendered check name as the forge reports it, matrix values included: "test (ubuntu-latest, 1.22)"
    RunID, RunAttempt, JobID string
    Started, Completed time.Time
    Conclusion    CheckConclusion
    Provenance    Provenance // Complete | Incomplete. Incomplete means some field couldn't be established, and consumers block.
    SupersededBy  string     // the JobID of a later attempt of the same job, if any
}

type ChangedFile struct { Path, PreviousPath string; Status FileStatus /* added | modified | removed | renamed | copied | mode-changed */; OldMode, NewMode fs.FileMode }
type GitSignature struct { Name, Email string; When time.Time }   // forgeable, never an account
type Commit struct { SHA string; Parents []string; Author, Committer GitSignature; Message string; Verified bool /* zero: unverified */ }

type QueueEntry struct { Repo RepoID; PR int; HeadSHA string; State QueueState /* queued | in-group | merged | removed */ }
type MergeGroup struct { Repo RepoID; CandidateSHA /* a real commit */, BaseSHA string; Members []QueueMember /* {PR, HeadSHA, CandidateSHA} */; State GroupState }
type ObservedMerge struct { Repo RepoID; PR int; HeadSHA, MergedCommit string; MergedBy Actor; At time.Time }

// RequiredCheck.AppID "" means unpinned (any source), which WI-18 must reject. An adapter sets Complete=false whenever it can't map something.
type BranchRules struct { RequiredChecks []RequiredCheck /* {Context, AppID} */; MergeQueueRequired bool; BypassActors []Actor; BypassOther bool; EnforceAdmins bool; Enforcement RuleEnforcement /* unknown (zero) | active | evaluate | disabled */; Complete bool }
type PushPolicy struct { Workflows bool; Deny func(path string) bool }
```

`JobKey` is the *rendered* name, which is unique per matrix leg within a run attempt and is what GitHub's jobs API exposes (`name`, not the YAML key).
A contract's `checkId` must equal this rendered name at the pinned `WorkflowCommit`, and the name is trusted only because that workflow commit is pinned.
`Provenance: Complete` needs every field above set, `CandidateSHA` to be an existing commit of the repo, a numeric `RunAttempt`, full-SHA `CandidateSHA` and `WorkflowCommit`, and a non-empty `Event`.
Supersession is keyed on (`ProducerAppID`, `WorkflowRepo`, `WorkflowPath`, `RunID`, `JobKey`), so a foreign app can't supersede an Actions job: when two attempts exist, the older one carries `SupersededBy` (the later job ID, or `attempt:<n>` when it has none), whichever was added first.
A re-run of one matrix leg supersedes only that leg. The consumer rule is exactly one non-superseded execution per `JobKey`.

## Capabilities

- **IdentityReader:**
  - `GetActor(id)` returns the current login.
  - `IsTeamMember(org, team, actorID)` checks membership live, with no cache (WI-09). Org and team are passed lowercase. Only active membership counts: a pending invitation is not a member.
- **PermissionReader** (WI-09): GitHub ignores a code owner without write access, so ownership needs these reads, all live with no cache.
  - `GetRepo(repo)` returns `Repo{ID, Name, Owner}`, where `Owner` is the owning org or user login. A team counts as an owner only if its org is the repo's owner (ASCII case-insensitive).
  - `RepoPermission(repo, actorID)` returns the actor's effective `Permission`. A revoked actor has `PermNone`. An unknown actor or repo is `ErrNotFound`.
  - `TeamRepoPermission(repo, org, team)` returns the team's `Permission`, `PermNone` when it has no access.
  - `GetTeam(org, team)` returns `Team{Org, Slug, Privacy}`, where privacy is unknown (zero, fails closed), visible or secret. GitHub ignores a secret team as a code owner, so only a visible team can own. An unknown team is `ErrNotFound`.
  - `Permission` is unknown (zero), none, read, triage, write, maintain or admin. Unknown fails closed: `AtLeast` is false for it and for any value outside the known range.
- **IssueReader:**
  - `GetIssue`, `GetIssueByNodeID` and `ListSubIssues`.
  - `ListComments` is complete or ErrIncomplete. A missing issue or PR is ErrNotFound.
  - `GetComment` re-reads edit state at execution time. A deleted comment is ErrNotFound and is omitted from `ListComments`, as on GitHub, so a deleted approval fails as not found. There is no deleted edit state.
  - An issue carries `Edit` too, so an approval in an issue body that was edited after the fact is visible. `UpdateIssueBody` by the factory sets it as well.
- **IssueWriter:** `CreateIssue(..., idempotencyKey)`, `UpdateIssueBody`, `SetIssueType`, `AddLabels`, `RemoveLabel`, `CreateComment` and `AddSubIssue`.
  - `CreateIssue` returns the existing issue when the key was already used, so a retry after an ambiguous write doesn't duplicate.
    Keys are per repo and follow the issue across a transfer, so the retry returns it wherever it lives now. Callers check `Repo`.
    A suite-passing adapter may instead return a new issue in the original repo after a transfer, because it emulates keys with a repo-scoped marker.
  - `SetIssueType` falls back to a `type:<t>` label when the forge has no issue types, and reports which one it used. `CreateIssue` with a type does the same.
  - A pull request is also an issue of the same number, so `GetIssue`, `AddLabels` and `SetIssueType` work on PR numbers, as in GitHub's issues API. Transferring a PR, or an issue to its own repo, is `ErrInvalid`.
  - Sub-issues:
    - `AddSubIssue` is idempotent, moves a re-parented child, and rejects self-parenting and cycles with ErrInvalid.
    - Unknown issues are ErrNotFound.
    - A transfer removes sub-issue links in both directions.
    - Cross-repo sub-issues are not supported in v1.
- **PRReader:** `GetPullRequest`, `ListReviews` (a missing PR is ErrNotFound) and `GetReview`, which re-reads at execution time.
  - `HeadSHA` follows the head branch. A review's `CommitSHA` is pinned to what was reviewed, so an approval at X and a push to Y leaves the PR at Y and the approval at X.
  - Opening a PR whose head and base share no history is `ErrInvalid`, as GitHub's 422 (a fork shares its source's history). A closed or merged PR no longer follows its branch.
  - `HeadRepo` is the repo the head branch lives in. For a fork it is not `Repo`, so a fork branch named `factory/<id>` is not a factory branch.
  - `AddReview` needs a commit that was a head of the PR at some point, a state of approved, changes_requested or commented, and an author other than the PR's author for an approval (`ErrForbidden`). A commented review can't be dismissed (`ErrInvalid`).
  - Review states are approved, changes_requested, commented and dismissed, and the zero value is unknown. Dismissing replaces the verdict, as on GitHub.
    A review edit changes only `Body` and sets `Edit`, never the verdict.
- **DiffReader:**
  - `Compare(repo, baseSHA, headSHA)` returns the complete changed-file list, including both rename paths and mode changes, or ErrIncomplete. This replaces GitHub's PR file list, which is capped at 3000 files.
    - Like GitHub's three-dot compare, it diffs the merge base of the two commits against head. The merge base is git's best common ancestor: common ancestors minus any that is an ancestor of another, and if a criss-cross leaves several, the one whose SHA sorts first, so a base that moved on doesn't report its new files as removed. With a base that is an ancestor it equals a two-dot diff. With no common ancestor it is ErrNotFound.
    - Equality is decided by bytes and mode, never by a stored SHA, so a no-op rewrite isn't a modification.
    - Renames are best effort. A policy consumer must treat a rename as removing `PreviousPath` and adding `Path`.
  - `Commits(repo, baseSHA, headSHA)` returns every commit with its message, oldest first (parents before children), or ErrNotFound when the two share no ancestor. `Author` and `Committer` are git signatures. They are forgeable, so they are never mapped to an actor or used for authorization.
- **CheckReader:** `ListCheckRuns(repo, sha)` and `ListJobExecutions(repo, sha)`.
- **CheckWriter:** `CreateCheckRun` and `UpdateCheckRun`, for the factory's own checks only.
  - The producer is the factory's App ID and is not a parameter. The App ID (`ProducerAppID`) is a different namespace from the factory bot account's actor ID (`FactoryAppID()` vs `FactoryActor().ID`).
  - `HeadSHA` must be the full SHA of an existing commit, and a run has a conclusion exactly when it is completed.
  - Updating another app's run is ErrForbidden.
- **MergeQueue:** `Enqueue(repo, pr, expectedHeadSHA)`, `Dequeue`, `QueueEntries`, `MergeGroups` and `ObservedMerges`. Enqueue alone never starts any stage.
  - Enqueue needs an open PR whose head is the expected SHA, otherwise ErrConflict.
  - A push to a queued PR removes it from the queue, and `Dequeue` of a grouped PR does the same. Either fails the group it was in, and the other members go back to queued, as on GitHub.
  - A group's candidates are real commits shaped like GitHub's: a chain of two-parent merges, where candidate i merges candidate i-1 (the base for the first member) with member i's head.
    Each has a `refs/heads/gh-readonly-queue/<base>/pr-<n>-<headsha>` ref, `Tree` and `Compare` work at each, and the group's `CandidateSHA` is the last member's.
    The caller supplies one cumulative tree per member. All members share one base branch, taken from the PRs themselves.
  - Ejecting a member keeps the candidates before it and rebuilds the ones after it from new trees. Ejecting the last remaining member fails the group and makes no new one.
  - `Dequeue` of an entry that is already removed or merged is `ErrInvalid`. A draft PR can't be enqueued, and converting a queued PR to a draft or retargeting it removes it from the queue. Only an open PR can be closed.
  - A merge that lands a group's candidate lands every member up to it, and the recorded pull request must be one of them. The group is then merged when every member has merged, and otherwise it fails and the rest go back to queued.
    A merge is only recorded when it moves the base branch forward and contains the pull request's head, otherwise `ErrInvalid`.
  - A group's `gh-readonly-queue` refs are deleted when the group merges or fails.
    Moving a base branch by any other path (a ref update) fails every active group on it, and the group keeps its now-stale `BaseSHA`.
- **RulesReader:** `BranchRules(repo, branch)` returns the effective rules, so WI-18 can check that the factory's verdict is required before GitHub can merge.
  - An unknown branch is ErrNotFound, and `refs/heads/x` is the same as `x`.
  - An existing branch with no rules reports an empty, complete set, which is what GitHub reports. A consumer that needs a required check must fail on an empty set (WI-18).
  - `RequiredCheck.AppID` of `""` means the check is unpinned (any source may produce it), which WI-18 must reject.
  - `EnforceAdmins`, `Enforcement` (active, evaluate, disabled; zero is unknown) and `BypassOther` (bypass entries that aren't individual actors: roles, teams, deploy keys, apps) let WI-18 see how binding the rules are.
  - An adapter must set `Complete` false whenever it can't map something it was shown.
- **TreeReader:** `ResolveRef(repo, ref)`, `Tree(repo, sha)` returning an `fs.FS`, and `ReadFile(repo, sha, path)`.
- **BranchPusher:** `Push(ctx, expectedParentSHA, change)`, where change is a list of file writes and deletes. Binding one takes a ctx too, because WI-30 mints the credential there.

### Push authority (SEC-2, SEC-3)

A `BranchPusher` is bound at construction to one principal, one repo and one exact ref, `refs/heads/factory/<change-id>`, with a change ID of at most 100 characters.

The trusted base given to `AssignChange` must be the current head of the base branch, or reachable from it. The forge
can't tell a base-branch commit from one fetched through `refs/pull/N/head` (fork commits live in the same object store), so the
control plane checks this when it assigns, and WI-30 checks it on the real write path.

- **Change assignment:** the control plane issues a change to exactly one coder identity (the fake models this with `AssignChange`).
  Binding a pusher is ErrForbidden unless the ref is a factory ref, that change is assigned, and it is assigned to this principal, matching on forge and ID.
  Push re-checks the assignment, so a reassigned change takes the old pusher's right away. It also re-checks that the principal isn't revoked or a read-only reviewer.
- **Compare-and-swap:** Push is a compare-and-swap on the parent. A stale parent gives `ErrConflict`, and two racing pushes with the same parent give exactly one success.
- **Denials:** the fake models branch protection, so these are `ErrForbidden`:
  - a push to the default or a protected branch
  - a push to any other ref
  - a push to a change assigned to someone else, or to nobody
  - a push from a read-only (reviewer) or revoked identity
- **No merge:** no pusher can merge or enqueue. It has no such methods, and the suite asserts it doesn't implement `MergeQueue`.
- **Head follows:** a push, or any other move of a branch, updates the head of every open PR on that branch (in any repo, for forks), and takes a queued one out of the queue.
- **Trusted base:** assigning a change binds a trusted base, the base branch head the control plane chose. It must be an existing commit of the repo (ErrInvalid otherwise).
  - Every push must descend from it. A first push on an orphan commit, or on a parent that doesn't descend from the base (for example a fork PR head copied into the repo), is `ErrForbidden`, and the ref isn't created.
  - The policy is evaluated over every path that differs between the trusted base and the new commit's tree (added, removed, changed and mode-changed), never over the paths the change lists.
    A parent that already carries a forbidden change from an earlier commit is therefore refused whatever the push lists.
- **Push policy:** binding takes a `PushPolicy`, which the control plane builds.
  - `Workflows` is GitHub's App `workflows` permission. Any path under `.github/workflows/` that differs from the base is `ErrForbidden` unless it is set, and coders never get it.
    The prefix check uses the same equivalences as the `.git` check below.
  - `Deny(path)` is the control plane's list of factory-protected paths (the baseline protected list and contract files, such as `CODEOWNERS` and `.github/actions/**`). A path it reports may not differ from the base.
    It receives raw paths and must canonicalize them itself (case, trailing dots and spaces), and the control plane builds it from `internal/contract`'s folded protected matching.
  - `Deny` is required. A nil one is `ErrInvalid` at construction, so it fails closed. A caller that wants no extra denies passes a function that returns false.
  - The fake never calls `Deny` under its lock, since it may read the forge: it computes the diff paths under the lock, evaluates the policy outside it, then takes the lock again and re-checks that the parent is still the head (compare-and-swap) before writing.
  - A refused push doesn't move or create the ref.
  - WI-30 must do the same on the real write path: require descent from the trusted base, and evaluate the policy over the diff from that base, never over the listed paths.
  - WI-30 coder credentials must never carry the `workflows` scope, and WI-30 must apply the same deny paths.
    Workflows that run on a push to `factory/*` branches with secrets need CI-side controls, because `.github/actions/**` is reachable from existing workflows. That is a WI-30 and install requirement.
- **Factory identity:** `AssignChange` refuses the factory's own identity. The merger is never a coder.
- **Input:**
  - A path with a segment that is `.git` on any common file system is ErrForbidden in `Push` and `CommitTree`: any case, trailing dots and spaces, an NTFS stream suffix, the `git~1` 8.3 name, and HFS-ignorable code points (U+200C-U+200F, U+202A-U+202E, U+206A-U+206F, U+FEFF). `gittree.New` still allows one so `contract.Load` can detect a nested repo with CodeForeignTree.
  - `ErrInvalid` covers an empty change, a duplicate path, a delete of a missing file and a write below a non-directory. A write below a symlink is ErrSymlink.

WI-30 enforces the same scoping on the real write path through credentials and egress. A fake-only denial does not satisfy SEC-2/3 by itself.

### Tree as `fs.FS`

`Tree(repo, sha)` takes a full 40- or 64-hex SHA. A short SHA or a ref is an error.

- **Modes:**
  - A blob is a regular file, and an executable blob is a regular file with mode 0o755.
  - A symlink shows as `fs.ModeSymlink` in directory listings and `Stat`.
  - A gitlink (submodule) is `fs.ModeIrregular` and can't be opened or traversed.
- **Opening:**
  - `Open` and `ReadFile` reject any path that has a symlink in *any* component, including the last, with `ErrSymlink`. A symlinked CODEOWNERS therefore can't be parsed as policy.
  - `ReadLink` is available on symlinks, and `*FS` implements `fs.ReadLinkFS`. `Stat` behaves like `Lstat` and never follows.
- **Names and bytes:** names are preserved exactly, case-colliding names included. Bytes are raw blob bytes: `.gitattributes` and LFS pointers are just files.
  Consumers interpret attributes and decide collision policy.
- **Validation:** a name that fails `fs.ValidPath` or `pathglob.ValidatePath` is an error at walk time, not a silent skip.
- **Names:** names may contain bidirectional or zero-width characters, and lookups match them exactly, so consumers must escape paths on output. A name with a control character (C0, DEL, C1) or a backslash is an invalid entry, so the tree read fails closed.
- **Completeness:** directory enumeration is complete or `ErrIncomplete`. The adapter recovers truncated GitHub tree responses by fetching subtrees, or fails.
  `gittree.New` can't see truncation, so callers never build a tree from a truncated listing. The adapter returns `ErrIncomplete` instead.
- **Limits:**
  - file size (each blob and symlink target): default 10 MiB, then ErrTooLarge when the tree is built, so one oversized file fails the tree instead of leaving a partial one
  - total content bytes: default 1 GiB, then ErrTooLarge
  - node count, synthesized directories included: default 200k, then ErrTooLarge
  - total bytes of all node paths: default 64 MiB, then ErrTooLarge, so a few very deep paths can't multiply memory
- **Implementation:** the `fs.FS` lives in `internal/forge/gittree` and is built from a list of entries. The fake and the adapter both use it.

### Errors and guarantees

- `ErrNotFound`, `ErrForbidden`, `ErrConflict`, `ErrTooLarge`, `ErrIncomplete`, `ErrSymlink`, `ErrInvalid` and `ErrUnsupported` are sentinels.
- `*RateLimitError{RetryAfter}` wraps `ErrRateLimited`.
- Adapters `url.PathEscape` every identity value they put in an API path.
- Missing authorization or gate evidence must block in the consumer. The forge layer never fills in defaults.

## The fake (`internal/forge/fake`)

A mutex-protected, deterministic, in-memory forge with an injected clock and monotonic IDs. It implements every capability.

Test helpers:
- create repos, users, bots, apps and teams
- commit trees (content is deep-copied), assign changes to coders, and open issues as a human
- edit or delete comments and reviews
- transfer issues
- add check runs and job executions from any producer, including a foreign app with the same name, a modified workflow, a superseded attempt or incomplete provenance
  - A record can't claim complete provenance with a field missing, and the fake never completes an incomplete one.
  - Adding a later attempt of the same (run ID, job key) marks the older attempt superseded, so a stale success is always marked.
    Consumers must still require exactly one non-superseded execution per job key.
- form merge groups and eject members (with the new candidate tree, and ejecting the last member fails the group), and record observed merges
- fork repos (a fork shares its source's commits and branches), close, retarget and draft pull requests
- revoke identities and change team membership (a revoked actor is unknown, a non-member and can't push)
- inject truncated answers (`ErrIncomplete`) for the list, compare, commit and tree reads
- set branch rules

It enforces branch protection and pusher scoping exactly as described above. It never produces evidence, or reaches a state, that GitHub can't: the suite must be passable by an honest adapter.

## Conformance suite (`internal/forge/forgetest`)

`forgetest.Run(t, newForge func(t) Harness)` runs the behavior tests against any implementation. It covers completeness, edit-state re-reads,
idempotent creates, pusher CAS and scoping, tree modes and symlink refusal, and provenance passthrough.

`Harness` is a small core: the capabilities plus the setup a recorded-fixture adapter can provide (repos, actors, change assignment, issues, comments, PRs, reviews, commits, refs, check runs and job executions).
Setup that needs the forge to mutate on demand lives in optional interfaces: `Editor`, `Identities`, `TreeSetup`, `QueueSetup` and `FaultInjector`.
Every setup method takes a context as its first argument, because an adapter does I/O there. A subtest type-asserts the interface it needs and skips when the harness lacks it. The fake implements all of them, and WI-12 implements the core over recorded fixtures.

## WI-12 obligations from CODEOWNERS

Verify against real GitHub, and record the answers here, how it handles two kinds of line:

- a line with an inline `# comment` among the owners, and
- a line that names an unknown user or team.

Also map GitHub's membership `state: pending` (an invitation not yet accepted) to false in `IsTeamMember`.

If GitHub skips the whole line for either, we must skip it too, or we over-grant. Until that is verified, `internal/codeowners` does this: an inline `#` ends the owner list and the rest of the line is kept, and an owner token that is not a valid `@user`, `@org/team` or email makes the whole file invalid.
