# Review policy and evidence rule (WI-15)

Status: accepted after a Codex review, 2026-11-22. Covers WI-15: AGT-3, AGT-4, AGT-5, SEC-5, AGD-3, CON-8 and INT-20.

`internal/review` is a pure evaluation package, like `internal/gate`. It decides whether a change's reviews are
complete from three inputs:
- the effective contract
- a complete snapshot of the factory's review evidence for the change
- the install config

It does no I/O and authorizes nothing. WI-18 dispatches reviewers, stores evidence (WI-10) and authorizes human
approvals (WI-06) at execution time, in the state-transition transaction. A saved grant can't show that it was
later revoked, so this package never accepts grants.

## Trust boundary: assignments and attestations (AGT-3)
An agent's verdict is a **factory record**, never a forge review. A forge review authenticates an account, but it can't
show which isolated session saw which inputs.

### Assignment
An `Assignment` is issued by the control plane for one reviewer or verifier. It is single-use, and its fields are:
- `ID`, `Forge`, `Repo`, `PR`, `HeadSHA`
- `RoundID` and `RoundSeq`
- `Role`, `Profile`, the pinned agent profile digest (AGT-7)
- `ManifestDigest`
- `Purpose`: review or verify, plus the `ClaimRef` for verify: the claimant role, the claim ID and the claim digest
- `Session`

### Attestation
An `Attestation` is the complete verdict, signed by the agent runtime with the session's workload identity. The
signature is ed25519 over a canonical encoding of the assignment ID, the **assignment digest** and the verdict body.
The assignment digest (`Assignment.Digest()`) covers every assignment field: forge, repo, PR, head, round, role,
profile, manifest digest, purpose, claim reference (role, ID and digest) and session. The ID is covered too.

The trusted runtime keys are injected into `Evaluate`; they're not read from the snapshot. Each key
(`Key{Pub, Session, Kind}`) belongs to one session and has a kind (`KeyReviewer`, `KeyVerifier` or `KeyCoder`), which
WI-18 takes from the runtime's own records. A signature counts only when all of these hold:
- it verifies with the key named by `KeyID`
- the signed assignment digest equals the digest of the assignment in the snapshot
- the key's session equals the assignment's session
- the key's kind matches the assignment's purpose (reviewer for a review, verifier for a verify)
- the key is not a coder's: not of kind `KeyCoder`. A key of another kind whose session is in `CoderSessions` makes the
  evidence inconsistent (below), because `CoderSessions` comes from the snapshot and can't be allowed to drop a signed
  record
- the snapshot's round for the assignment has the same ID, `Seq` and head as the assignment signed

So a writer who rewrites an assignment (its head, PR, repo, forge, role, manifest digest or session) can't reuse an
existing signature, and a session can't sign for another session or for the coder.

The evaluator verifies the signature independently of whoever wrote the record:
- **A compromised writer** can't mint, alter or move a signed record: an approval, a block, a confirmation or a
  dismissal.
- **A compromised runtime signer** is the remaining trust root.

**Trusted inputs.** Some snapshot fields aren't signed. They are trusted inputs, and WI-18 takes them from the audited
store or from the forge at execution time, never from the writer of the snapshot: `Round.State`, `Round.Roles`,
`LightsOn`, `NonSwitchable`, `ChangedPaths`, `OwnerAreas`, `Gate`, `CoderSessions`, `Complete` and `StateVersion`.
Forging one of them isn't something this package can detect. `Round.State` shows why: a writer that marks a round
superseded hides its approvals.

**A signed record is never silently dropped.** The writer that builds the snapshot is untrusted, and a record that
silently vanished could be a block. A record is *key-verified* when its signature verifies under a trusted key. A
key-verified attestation or resolution makes the evidence **inconsistent** (`error` with `inconsistent-evidence`) when:
its assignment is unknown or ambiguous; its signed assignment digest, its key's session or its key's kind doesn't match
the assignment; its assignment targets another forge, repo or PR; the snapshot's round differs from the assignment's
round; any of its strings is invalid UTF-8 (a lossy JSON encoding would let a different string verify); or its time is
more than five minutes after `now`. A record signed by a coder's key is rejected outright and never forces an error.

Deleting a record, or corrupting its signature, is out of scope for this package: from here a deleted record and one
that was never sent look the same. That belongs to WI-10's audited store, which must prove the snapshot complete (WI-18
note: pass `Complete` only when the store proves that no signed record is missing).

Two rules make attestations count once:
- An identical redelivery of an attestation counts once.
- Two different attestations for one assignment make the assignment `invalid`.

## Who reviews (AGD-3, SEC-5)
**Required roles.** These come from `Effective.Reviewers`, which already includes the baseline core roles
(`PRReviewer`, `SecurityReviewer`) and every specialist from each touched stack.

**Independence.** Each required role is filled by its own assignment. Its session must be distinct from:
- the coder's sessions (`Snapshot.CoderSessions`)
- every other role's session on this change

**SEC-5.** When `Effective.SecuritySignoffRequired` is set, the `Effective.SecurityReviewer` role's manifest must hold the
complete sensitive diff for every path in `Effective.SensitivePaths`. That includes the base side of deletions and
renames: a file renamed out of a sensitive directory still needs its old side shown. Its attestation must also carry an
explicit `SensitiveSignoff` over exactly that path set. A plain approval doesn't satisfy SEC-5.

## Reviewer context (AGT-3)
The manifest is a list of items `{Kind, Path?, Side?, Digest}`.
- **Allowed kinds:** `spec`, `diff`, `repo-file` (read-only, base or head), `caller`, `contract`, `history` and
  `public-test`.
- **Forbidden kinds:** anything else, including `coder-reasoning`, `transcript` and `private-holdout`. The evaluator
  rejects a manifest that contains one.
- **Digest:** the evaluator recomputes the manifest digest from the items and compares it to the assignment.
- **HeadSHA:** the manifest's HeadSHA must equal the assignment's.

## Verdicts and claims (AGT-4, P4)
An attestation's verdict is one of `approve`, `block` or `request-split`, plus a list of `Claims`.

**Claims.** A claim (a provisional block) has five required fields:
- an ID that is stable across pushes
- a location: path and line range at the reviewed head
- the violated invariant
- the concrete consequence
- a verification plan

A claim with a missing field makes the attestation `invalid`. An invalid attestation never counts as approval.

**Verification.** Each claim is verified in one of two ways:
- **By an independent verifier.** The verifier is assigned by the factory with `Purpose: verify` and that claim's
  `ClaimRef`. Its
  session must be distinct from the claimant's and the coder's. Its signed `Resolution` binds:
  - the claim instance (role, ID and claim digest) and the reviewed revision
  - the procedure it ran, the expected outcome and the observed evidence digest
  - an outcome: `confirmed` or `dismissed`

  A proof digest on its own decides nothing.
- **By a trusted gate.** A gate result reference (a `gate.ObligationResult` identity: gate ref, run, attempt, job, and
  the candidate) plus a recorded explanation linking that check to the claim. The gate must be a mandatory obligation of
  this change.

**Claim lifecycle.**
- **Open claims carry across pushes.**
- **Dismissed** closes the claim.
- **Confirmed** keeps the change blocked until an attestation by the claimant's role records the claim as repaired. The
  attestation must be valid, at the target head, in a round that isn't superseded, dated after the **latest**
  confirmation, at a head that **no** confirmation was at, and list the instance as `<id>#<claim digest>`
  (`RepairedRef`). The claim then needs a fresh dismissal reviewed at the target head and dated after that attestation.
  Confirmations are monotonic: another confirmation can only keep a claim confirmed, and one at the target head can't
  be repaired at all.
- **Confirmations are sticky.** A key-verified, bound confirmation always counts, even if its gate evidence can't be
  rechecked against the current gate decision (another head, or none), or its gate isn't blocked: ignoring a
  confirmation would let a confirmed defect pass. A resolution that isn't a well-formed dismissal (no evidence, a blank
  procedure or expectation, no time, or an unknown outcome) counts as a confirmation of its assignment's claim. A
  confirmation for a claim instance that isn't in the snapshot is inconsistent evidence. Gate evidence is validated only for a dismissal: the contract's
  mandatory gate, passed, at the reviewed head (P4). A confirmation's head is its assignment's.
- **A claim is an instance.** It is the claimant role, the ID and a digest of its content (`Claim.Digest()`). Raising the
  same ID again with changed content is a new instance, and it starts open. A resolution signs the claim digest, must be
  dated after the instance was first seen. For a dismissal, its verify assignment's round must exist at the assignment's
  head and be no earlier than the one where the instance was first seen, and it must not be superseded while its head
  is the target's. A dismissal in a round superseded by a later push stands, for the same reason as one in a completed
  round at an old head: it was valid for the claim's content when it was made.
- **Unresolved claims block.** Verification attempts per claim are capped (`cfg.VerifyAttempts`, default 3). Past the cap,
  or once a claim has been open or confirmed-but-unrepaired longer than `cfg.VerifyTimeout` (from an injected clock), the
  claim escalates. These two limits are a fail-closed addition beyond the AGT-5 round cap, pending a PRD clarification.

## Rounds (AGT-5)
**What a round is.** A round is a factory-dispatched review pass with a persistent `RoundID`, which the snapshot lists
in order.
- **Superseded:** a head change mid-round closes that round as superseded. Its approvals are hidden, but its blocks,
  splits and invalid verdicts still count against their roles, so more negative evidence never makes an older approval
  current again. It still counts toward the cap.
- **Retries:** a retry with the same review inputs inside a round is free.
- **Follow-ups:** a deliberate follow-up dispatch for one role costs a round. It keeps other roles' approvals that are
  still current at the same head. WI-18 supersedes the round when the spec or the contract changes, which invalidates
  every approval in it.
- **Counting:** only completed and superseded rounds count toward the cap. A round that's merely dispatched hasn't used
  up a review yet.

**The cap.** Once `ReviewRounds` (install timers, default 3) is reached without convergence, the disposition is
`escalated`, and the action is to assign the change to a contract owner, once.
- **Convergence:** every required role approves the current head, and no claim is open or confirmed-but-unrepaired.
- **The owner's limits:** escalation gives the owner no waiver. Their approval alone can't pass the PR. They direct a
  repair or a replan, through other work items.

## Lights-on and non-switchable approval (CON-8, PIP-9)
**When it applies.** It applies when `Effective.LightsOn` is set, or when the snapshot declares the change non-switchable
(WI-17 sets this even when LightsOn is false).

**What WI-15 returns.** WI-15 returns the required `authz.Target`s for `OpApproveLightsOn`:
- `Target.Paths` covers **every changed path**. Across owner areas, one target is required per owner area, so together
  they cover the full set.
- `Target.Revision` is the digest of a canonical **approval manifest**, shared with WI-17. The manifest holds:
  - the change identity (forge, repo, PR) and the proposal generation
  - the HeadSHA
  - the declared impact revision and the recovery plan revision
  - for PIP-9, the affected callers and rollout order

Editing and then restoring any input changes the generation, so an earlier approval is invalidated.

WI-18 authorizes each target at execution time. Until those are authorized, the result is a `needs-authorization`
obligation, never a pass. When every other obligation passes, the overall disposition is `needs-authorization`. WI-18 may
merge only after it authorizes every `RequiredApprovals` target at execution time, in the same state transition as the
merge. This package can't satisfy the obligation, and nothing in the snapshot claims it was authorized.

## Split requests (INT-20)
A `request-split` must cite the **size** gate ID, the review-budget gate from WI-14 (for example
`shape/review-budget`). Any other ID makes the attestation invalid. A valid request adds a `replan` obligation for the
spec writer (INT-15).

## Output (for WI-18)
```
Evaluate(eff, target, snapshot, cfg, keys, now) Decision
```

**Inputs.**
- `target` is `{Forge, Repo, PR, HeadSHA}`.
- `snapshot` holds the following, and is `Complete` or not:
  - `Assignments`, `Attestations`, `Resolutions` and `Rounds`
  - `Manifests`, by review assignment ID
  - `CoderSessions`
  - `LightsOn` and `NonSwitchable`, the approval data (the non-switchable declaration wins; two that disagree are invalid)
  - `ChangedPaths` (status from `forge.FileStatus`) and `OwnerAreas`
  - `Gate`, the gate decision that gate evidence is checked against
  - `StateVersion`
  - `Complete`

**The Decision.**
- **Disposition:** an overall `pass`, `needs-authorization`, `pending`, `replan`, `blocked`, `escalated` or `error`,
  in increasing precedence (the highest outstanding one wins).
- **Obligations:** a complete list, each with a stable ID, a kind, a disposition, a reason, evidence references and a
  required action.
- **Several at once:** a split request and a security block can both be outstanding.
- **Binding:** the decision binds (Effective.Revision, InstallRevision, HeadSHA, StateVersion). WI-18 compares
  StateVersion right before publishing, and must also check that the reviewed PR and head belong to the current queue
  candidate.
- **Incomplete snapshot:** a snapshot that isn't `Complete` gives `error`, even when every visible verdict approves.

## Implementation decisions (WI-15)
Choices the design left open:
- **Round binding.** The assignment carries `RoundSeq`, and the snapshot's round must match its ID, `Seq` and head
  (inconsistent evidence otherwise). Rounds with the same ID but different content are invalid input. Rounds are
  counted by distinct ID.
- **PR reviewer.** `Effective` doesn't name the PR reviewer role, so `Config.PRReviewer` does. WI-18 fills it from
  `Baseline.PRReviewer`. It must be one of the required roles and differ from the security reviewer.
- **Latest verdict wins, and invalid verdicts count.** A role's current verdict is its latest at the target head
  (round sequence, then time, then block over other verdicts, then assignment ID). A key-verified, bound attestation
  that is invalid (a malformed claim, a block with no claims, a split with claims, a manifest that fails the content
  rules, a role not in its round) competes like any other: when it is the newest, the role is `blocked` with
  `invalid-verdict` and never falls back to an older approval. Each of its well-formed claims still contributes on its
  own. A dismissed claim doesn't make a blocking role approve:
  the role needs a follow-up approval, which costs a round.
- **Sign-off set.** The set is `Effective.SensitivePaths` plus the old path of every removed, renamed or copied entry in
  `ChangedPaths` that touches a sensitive path. A sensitive path needs a `diff` item at the head side (or with no side), unless it is only an
  old path or removed: a base-only item doesn't show what the change made of the file. A removed file's path is its old
  path.
- **Changed paths** are always validated: a known status, valid paths, an old path exactly for renames and copies, and no
  duplicates.
- **Lights-on data.** It's invalid input without an impact and recovery revision (each `sha256:` and 64 hex), without
  changed paths, or when `OwnerAreas` doesn't partition the changed paths **and their old paths**. WI-18 must resolve
  `Effective` over old paths too, so a rename out of a protected directory still reaches that directory's owners. The
  authz target revision is the 64-hex digest of the `ApprovalManifest`.
- **Context.** An approving manifest needs a `spec` item and a `diff` item. A claim's path must appear as a `diff` or
  `repo-file` item in the claimant's manifest. A `request-split` with claims is invalid, and it asks for a replan only
  while it is its role's current verdict. A role must be listed in its round's `Roles`. An approving manifest also needs a `diff` item for every changed path: the
  head side (or no side) of each path that isn't removed, and the base side of each removed path and each old path.
  `Effective.Paths` must cover every changed path and old path, and `ChangedPaths` can't be empty.
- **Canonical encodings.** Strings that are signed or digested must be valid UTF-8, and claim IDs match
  `^[A-Za-z0-9._-]{1,64}$`. Snapshot lists, an attestation's claims and a manifest's items are capped, and a snapshot
  over a cap is invalid input.
- **Claim obligation IDs** are always `claim:<role>/<id>#<claim digest in hex>`, so they're stable and can't collide.
- **Key kinds** are `KeyReviewer`, `KeyVerifier` and `KeyCoder`. The zero kind is invalid input. A key of the wrong kind
  for its assignment is inconsistent evidence.
- **Callers** can't repeat.
- **Rejections.** `Decision.Rejected` lists every record that was ignored and why. A record whose signature doesn't
  verify is only rejected: it can't invalidate a genuine one, because conflicts are only judged among key-verified
  records. Of two differing resolutions for one assignment, only a confirmation counts.
