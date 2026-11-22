# Authorization of human decisions (SEC-10, NFR-5)

Status: accepted after a Codex review, 2026-11-21. Covers WI-06, which is SEC-10 and the decision half of NFR-5. Service identities for
agents (SEC-2, SEC-3) are WI-30. WI-10 wires every channel (issue events, checks, callbacks, API, admin) through this package and
supplies the transactional store. CODEOWNERS resolution is WI-09, and the ideator binding is WI-19.

## Principles

- **Authorize at execution, never from a cache.** A decision is checked when the action it authorizes runs. No grant
  is stored and reused (SEC-10, NFR-5).
- **Identity comes from the forge, never from text.** A principal is the forge's authenticated author of the event
  that carries the decision. A name, mention or quote in comment text never identifies anyone.
- **A decision binds one thing.** That thing is the operation, the scope (repo or install), the subject (issue or change), and
  the exact revision. The action handler computes the target independently from authoritative state, and anything that
  doesn't match is denied.
- **Every decision is audited**, granted or denied, with typed evidence (`audit.Decision`).
- **Fail closed.** An unknown operation, a role-source error or a failed audit append is a denial or an error, never a grant.

## Package `internal/authz`

```go
type Principal struct { Forge, ID, Login string; Kind PrincipalKind } // ID is the forge's stable ID; Login is display only
type Scope struct { Kind ScopeKind /* repo | install */; ID string }

// Operation is a closed set. Each operation has a required role, a scope kind and an optional expiry (Policy).
//   confirm-classification (INT-3), decide-split (INT-11), approve-scenarios (INT-4),
//   reject-scenarios (INT-4, returns the work to refinement)                          role ideator         scope repo
//   approve-path-exception (CON-7)                                                    role path-owner      scope repo
//   approve-lights-on      (CON-8)                                                    role code-owner      scope repo
//   activate-contract      (CON-2)                                                    role contract-owner  scope repo
//   halt, resume           (SEC-6)                                                    role admin           scope install

// Decision is what a forge or API adapter extracts from one authenticated event.
type Decision struct {
    ID        string     // canonical, globally unique source ID (forge + event kind + event ID); the unit of replay protection
    Channel   Channel    // issue-comment | review | api | admin-cli
    Principal Principal  // the event's authenticated author, as the forge reports it
    Authenticated bool   // set only by the adapter that verified the event (webhook signature, API credential)
    Location  Location   // where the event was posted (scope + subject), taken from the event itself, never from text
    Operation Operation  // the operation the principal invoked
    Revision  string     // the revision the principal named in the structured command
    Choice    string     // digest of the choice; required for decide-split, forbidden for every other operation
    Integrity Integrity  // IntegrityUnknown (zero) | Original | Edited | Quoted; only Original passes
    Created   time.Time
}

// Target is what the action handler is about to do, computed fresh from authoritative state at execution.
type Target struct {
    Operation Operation   // the operation the handler is executing
    Scope     Scope
    Subject   audit.Subject
    Revision  string      // current revision, 40 or 64 lowercase hex; must pin every approved input (see below)
    Choice    string      // digest of the choice the handler is about to execute
    Paths     []string    // the area; required for owner roles (path-owner, code-owner, contract-owner)
}

// Authorize clears Principal.Login before calling it: resolve by Forge + ID together, because IDs are unique only within one forge
// and logins can be renamed or recycled. For an owner role the principal must own every path in Target.Paths.
type RoleSource interface { HasRole(ctx context.Context, p Principal, r Role, t Target) (bool, error) }

// Tx is the caller's transaction. Consume and the grant's audit append run in it, together with the caller's state
// change, so all three commit or roll back together. Consume fails with ErrReplayed if the ID was ever consumed.
type Tx interface {
    Consume(ctx context.Context, decisionID string) error
    Append(ctx context.Context, r audit.Record) (audit.Entry, error)
}

// Config carries Forge (required, [a-z][a-z0-9-]*; v1 has one forge per install and multi-forge later widens this to a set),
// InstallID (required), per-operation Expiry (zero or absent means none, WI-07 supplies it) and
// DenialAuditTimeout (default 5s).
type Authorizer struct { /* policy, roles RoleSource, denials Auditor (non-transactional), clock */ }
func (a *Authorizer) Authorize(ctx context.Context, tx Tx, d Decision, t Target) (Grant, error)
```

On any non-nil error from `Authorize`, including `ErrDenied`, the caller must not commit its state change. Callers must not echo
a denial's reason to an unauthorized principal, because "stale" versus "no-role" reveals whether a guessed revision was right.

Revisions have three rules.
- **A revision is a digest.** It is 40 or 64 lowercase hex digits (a git SHA or a SHA-256), on both the decision and the target. Anything
  else, such as a branch, a ref or uppercase hex, is `malformed`. Producers digest composed inputs (WI-19, WI-36).
- **A revision pins everything the human approved.** Approving scenarios binds the scenario revision. Approving lights-on binds the change SHA plus the
  declared impact and recovery plan revisions. A resume binds the halt generation. The handler composes these into one
  opaque string.
- **A revision is unique to its subject.** A bare content hash isn't enough, because two issues with identical proposals
  would share it. Every edit creates a new revision, including an edit that is later reverted. Producers (WI-19, WI-36) follow this.

### Checks

`Authorize` checks in this order. The first failure is a `*DeniedError{Reason}` that wraps `ErrDenied`, and it is
audited through the non-transactional denial auditor, so the caller's rollback can't erase it. The denial append is detached from the
caller's cancellation (`context.WithoutCancel`) and bounded by `Config.DenialAuditTimeout`, so a client that disconnects can't erase its probing.

1. **Unauthenticated:** `Authenticated` is false, or the principal's forge or ID is empty.
2. **Not a person:** the principal isn't a `user`. Bot and app approvals never advance work.
3. **Wrong operation:** the operation is unknown, `d.Operation != t.Operation`, or the scope kind doesn't fit the operation.
4. **Wrong place:** `d.Location` doesn't equal `(t.Scope, t.Subject)`, or the target is inconsistent. A repo scope needs
   `Subject.Repo == Scope.ID`. An install scope needs an install subject whose ID equals `Scope.ID` and whose repo is empty. `Scope.ID`, `Subject.ID` and a
   non-empty `Subject.Repo` must be 1 to 256 bytes of printable ASCII, because grants store them verbatim. The subject kind must suit the
   operation, owner operations need a non-empty `Paths` without empty, duplicate or non-printable elements (valid UTF-8, no control or format
   characters), and every other operation needs none. An install scope must be
   this installation (`Scope.ID == Config.InstallID`). The principal's forge must be the configured forge. This catches a cross-repo replay and a command copied to another issue.
5. **Malformed:** a decision ID that isn't 1 to 256 bytes of printable ASCII (checked before `Consume` ever sees it), a principal ID that isn't printable ASCII
   without `:`, a zero `Created`, a non-empty choice that isn't a 64-digit lowercase hex digest, a revision that isn't a 40- or 64-digit lowercase hex digest, a channel outside `issue-comment | review | api | admin-cli`, or
   `IntegrityUnknown`. Checks and callbacks carry service identities, never human decisions, so they have no channel here (NFR-5's other paths go through WI-30 and WI-10).
6. **Stale:** `d.Revision != t.Revision`. This catches an older revision, a proposal edited after approval, and a resume for an earlier halt.
7. **Wrong choice:** `decide-split` needs a non-empty choice (a digest) on both sides and they must be equal. Every other operation must carry no choice.
8. **Edited or quoted:** `Integrity` is `Edited` or `Quoted`. The adapter sets `IntegrityOriginal` only after checking the forge's edit state at execution time, not only
   when the event was captured (WI-10). The zero value fails closed.
9. **Expired or from the future:** a `Created` time more than a minute ahead of the clock is `malformed`. Expiry applies only to operations whose policy sets one.
10. **No role now:** `HasRole` is false (`no-role`) or returns an error (`role-error`). A revoked admin or owner is caught here. A decision denied for
    `no-role` stays unconsumed and can succeed later if the role is granted, as long as every binding still matches.
11. **Replayed:** `tx.Consume` fails with `ErrReplayed`. It runs only after every binding has passed, so a wrong-target attempt doesn't burn a valid approval.
    Any other `Consume` error isn't a denial: the caller rolls back.

After the checks pass, `Authorize` appends the grant entry through `tx` and returns a `Grant`: the decision ID, the target
and the audit seq. If the append fails, it returns an error and the caller rolls back, so the consumption is undone
too. The `Grant` is evidence for the caller's records. It is not a reusable capability.

### Audit evidence

The audit actor is the verified principal as `<forge>:<id>`: `ActorHuman` for an authenticated user, and `ActorExternal` for an authenticated bot or app,
whose identity was verified. A decision that isn't authenticated is never attributed to the claimed principal. Its actor is `external` / `unauthenticated` with no display name, and the claimed forge, ID and
login (sanitized, clipped) appear only in `attrs.claimed_principal`. The forge format and the principal ID rule make `<forge>:<id>` unambiguous. The audit log requires
a human actor for a granted decision, as defence in depth. The audit `Operation` and `Target` never come from client text: they are the target's
operation if known, else the decision's if known, else `unknown`. The client's raw operation goes only in `attrs.requested_operation`.

- **Grants are never clipped.** An oversized value makes the grant's append fail, which is an error and never a grant. Everything in a grant except the login
  was validated by the checks and is stored verbatim, including the decision ID and `choice`. The login is sanitized. A grant also records `choice` when present, and for owner operations `paths_digest` (hex SHA-256 over the sorted paths, each prefixed with its 8-byte big-endian length) and `paths_count`.
- **Denials clip** each client-supplied string to 1024 bytes (clip, sanitize, clip again). `Decision.Revision` holds the decision's revision only if it is a valid digest. Otherwise it is empty and the raw value
  is in `attrs.requested_revision`. A `stale` denial also records `target_revision`, and a `wrong-choice` denial records `requested_choice` and `target_choice`. A `wrong-place` denial also records the decision's location in attrs. If the target's subject
  can't be recorded (for example an empty ID), the denial is recorded against `install/<InstallID>` with the raw subject in attrs, so every denial is audited.
- **Role** is recorded only once the role check has run. Earlier denials leave it empty, as they do the revision when the request supplied none. The audit
  validator allows an empty `Role` and `Revision` on denials only. This is deliberate: a denial may lack evidence the request never supplied.
- **Sanitizing:** in every record, C0 and C1 controls, every format character (Unicode category Cf: bidi controls, zero-width characters, U+FEFF,
  soft hyphen, tags), line and paragraph separators (U+2028/9) and the Hangul fillers (U+115F, U+1160, U+3164, U+FFA0) in client-supplied strings
  (login, IDs, operation text, revision on denials) become U+FFFD.
- **Revision format in the log:** the audit validator also requires a granted decision's revision to be a 40- or 64-digit lowercase hex digest, so no
  other writer can record a branch name as an approval.

### Caller contract

- After a grant, the caller performs its action conditional on `Grant.Target.Revision`: a merge with the expected head SHA, or a compare-and-swap on the state row in
  the same `Tx`. A target that moved after the check must not be acted on (CON-8, "approval for the exact change").
- On any non-nil error from `Authorize`, don't commit.

### Notes for WI-10

- Retain the consumed set for as long as any decision could still be valid. With no expiry, that means forever. Never purge it.
- If the denial auditor and the transactional appends write one hash chain, they must not deadlock: serialize them in the store, or use separate chains.
- Rate-limit before `Authorize`, because every denial is a durable write of up to about 15 KB.

### Roles

The ideator is bound by WI-19. Authorship nominates the ideator, who must be a verified human still eligible under the repo's intake
policy. A bot-opened issue has no ideator until someone binds one. A transferred issue needs a fresh binding. Any delegation is an
audited, issue-scoped assignment.

The three owner roles (`path-owner`, `code-owner`, `contract-owner`) share one mechanism in `internal/codeowners` and differ only in the paths the
caller puts in `Target.Paths`: the read-only paths a change touches (CON-7), every changed path (CON-8), and the contract **file** paths being activated,
such as `svc/.factory.yaml` (CON-2), which are the files GitHub's own code-owner review covers. The principal must own every path. As on GitHub, an owner
counts only with write access to the repository: a `@user` owner needs the current login and write permission, and a `@org/team` owner needs the org to own the
repo, a visible team (GitHub ignores secret teams), write access for the team and live membership. The role source is bound to the repo the CODEOWNERS was loaded from, is built per execution from the
trusted base, and is never long-lived.

Owner roles are checked per area. An action that spans several owner areas, such as activating a contract that touches two areas, needs one granted decision
per area. WI-11 composes these and requires coverage of every affected area under the previously trusted ownership.

### Install activation

`OpActivateInstall` (`"activate-install"`) needs `RolePolicyApprover` (`"policy-approver"`), install scope and an install subject.
`Target.Revision` is `install.ActivationRevision(installID, generation, candidate)`, which binds the installation, the active generation
and the candidate commit (the encoding is in [install.md](install.md), "Activation operation"). A decision made for an earlier generation
has a different revision, so WI-10 must compute the value from the store's current generation and thereby deny it. Authz checks one
decision at a time and cannot count, so quorum is the caller's job (WI-10, WI-11): gather `quorum` granted decisions from distinct
principals who are policy approvers of the *active* revision (`Config.RoleSource()` of the active config), each carrying the same
`ActivationRevision`, and consume them with the compare-and-swap of the active generation in one transaction. A candidate's own
`policyApprovers` never count.

## Tests (SEC-11 negatives)

Fakes for RoleSource and Tx, and an in-memory audit log. Each check has a denial test, plus:

- a matching authorized approval succeeds, with exactly one grant entry
- a forged approval (unauthenticated, or a bot)
- a stale approval
- a proposal edited after approval with the comment unchanged
- a decision denied for no role that later succeeds once the role is granted
- every operation requires its own role, and denial when the principal holds every other role
- a denial survives a cancelled caller context, and an oversized value on a grant is an error, not a grant
- an edited comment, a quoted command, a copied command on a second issue with identical content, and a cross-repo replay
- a valid approval presented for a different operation on the same subject and revision
- a revoked owner or admin, where the role source changes between decision and execution
- a replayed decision ID, including a resume for halt H1 delivered after H2
- an audit failure on grant, where the decision stays unconsumed and a retry succeeds
- a role-source error, which denies
- an unknown operation, which is denied and audited without a role or revision
- two correct executions and one wrong-target execution racing, where exactly one grant wins
- expiry: with no expiry, a seven-day-old approval still succeeds; with expiry, the exact cutoff is tested
