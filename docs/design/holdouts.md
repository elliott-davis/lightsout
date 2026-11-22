# Holdout store (WI-21)

Status: proposed 2026-11-22, before implementation. Covers WI-21: INT-6, INT-7, INT-9 and AGT-2 (store side). The
Acceptance runner and its repair loop are WI-24, service identities are WI-30, and the scenario/intent records come
from WI-19 and WI-20.

## What it protects
QE binds each ideator-approved public scenario (Given/When/Then, readable on the issue) to **private** executable
material: test code, extra private cases, fixtures and assertions. If a coder, a PR reviewer or customer CI could read
that material, Acceptance would stop being an independent check (P4). The store is the only place private material
lives, and every read and write of it is authorized and audited.

## Principles
- **Closed access policy, checked per call.** A caller is a factory-verified workload identity (WI-30 supplies the
  verifier; WI-21 defines the interface). Access is decided by role and binding at the moment of the call, never cached.
- **Immutable, content-addressed revisions.** A suite revision is never edited. Its ID is the SHA-256 of its canonical
  encoding, so a run, review or regression PR can name exactly what it used (INT-7, PIP-3).
- **Public and private are separate types.** The public view (scenario IDs, intent revision, suite revision ID, counts)
  is a different Go type from the private bundle, so private data can't flow into an issue comment by accident.
- **Fail closed and audit both outcomes.** An unknown role, a lookup error or a failed audit append denies.

## Model (`internal/holdout`)
```go
type SuiteID struct { Repo forge.RepoID; Issue int }     // one suite per feature issue (or authorized fix)
type Revision string                                     // "sha256:<hex>" of the canonical bundle

type Bundle struct {                                     // private; never rendered
    Suite          SuiteID
    Parent         Revision                              // "" for the first revision
    IntentRevision string                                // exact ideator-approved scenario revision (WI-19/20)
    Scenarios      []Binding                             // one per public scenario ID, sorted
    Files          []File                                // test code, fixtures, assertions: {Path, Mode, Bytes}, sorted, bounded
    Correction     *Correction                           // set on a correction revision (INT-9)
    Author         Caller                                // QE session that proposed it
}
type Binding struct { ScenarioID string; Layer string /* e.g. go-integration, cypress */; Entry string; Private []string /* extra private case IDs */ }
type Correction struct { Replaces Revision; FailedRun string; Reason string } // preserves the original failure (INT-9)
```
Bounds: ≤ 1024 files, ≤ 4 MiB per file, ≤ 64 MiB per bundle, ≤ 256 scenarios; paths validated like repo paths.

## Lifecycle
1. **Propose** (QE only): `Propose(ctx, caller, Bundle) (Revision, error)`. Stored as `proposed`. `Parent` must be the
   suite's current head (compare-and-swap), so concurrent proposals can't silently fork. A correction must name the
   revision it replaces and the failed run, and carry a reason.
2. **Review** (scenario reviewer only, a session independent of the author): `Review(ctx, caller, rev, intentRevision,
   verdict)`. The reviewer must name the exact intent revision; it must equal the bundle's `IntentRevision` **and** the
   currently approved intent (looked up through an injected `IntentSource`, never from the caller). `approve` makes the
   revision `active`; `reject` lists mismatched public scenario IDs, which block hand-off (INT-9). The reviewer can't
   approve a revision whose author is the same session or principal.
3. **Run access** (Acceptance runner only): `Open(ctx, caller, RunGrant) (Reader, error)`. A `RunGrant` names one run
   ID, one suite and one active revision, and expires. The orchestrator (WI-24) issues it; the store records it, and
   `Open` succeeds only for the runner identity bound to that run, before expiry, at most once per grant. The `Reader` is
   read-only and scoped to that revision's files.
4. **Intent changes.** When the approved intent revision changes, every active revision bound to the old one becomes
   `stale` and can't be opened for a run until QE proposes and the reviewer approves a revision for the new intent.

## Access policy
| Role (WI-30 workload identity) | Read private | Propose | Review | Open for a run |
| --- | --- | --- | --- | --- |
| `qe` (for this repo) | yes | yes | no | no |
| `scenario-reviewer` (for this repo) | yes | no | yes | no |
| `acceptance-runner` | no | no | no | only with a matching, unexpired, unused grant |
| `coder`, `pr-reviewer`, `spec-writer`, customer CI, humans, anything else | **no** | no | no | no |

Every call names a caller; the store asks the `Verifier` (WI-30) to confirm it, then checks role and repo scope.

## Public regression tests (INT-7)
- After Acceptance succeeds, QE proposes a public regression test (a normal PR through Verify). `LeakCheck(ctx, caller,
  rev, publicFiles)` blocks the PR if it contains any private file's bytes, any private fixture's digest, or any private
  string literal of 16 or more bytes from the bundle (after whitespace normalization). It returns only file paths and
  counts, never the matched private text.
- Cases published that way are recorded as **disclosed**. Before the feature can requalify, the head revision must keep
  at least one undisclosed private case per scenario (QE "retains or adds fresh private coverage").

## Output hygiene (AGT-2, PIP-15)
The store exposes `Public(rev)`: scenario IDs, intent revision, revision ID and counts. Failure reporting to coders
(scenario ID, expected outcome, sanitized symptom, run reference) is WI-24; the store gives it no API that returns
private bytes to a non-runner caller.

## Storage
An interface with an in-memory implementation in WI-21. The PostgreSQL backend comes after WI-10d lands (follow-up),
in its own tables with the same exact-allowlist discipline. Content at rest is not encrypted in v1; the store database
is factory-owned and never reachable from coder or CI sandboxes (RUN, SEC-1).

## Audit
Every call appends an `audit` entry: actor (the verified caller), subject (the issue), action, revision and outcome.
Denials are audited too. No audit entry contains private bytes.

## Tests (SEC-11 negative tests are mandatory)
Coder, PR reviewer, customer CI and an unverified identity are denied every read. A runner with a grant for another
run, another revision, an expired grant or a reused grant is denied. QE can't review; the reviewer can't propose; the
author session can't approve its own revision. A stale intent blocks `Open`. A concurrent proposal from an old parent
conflicts. A regression PR containing a private fixture, a private literal or a whole private file is blocked, and the
result doesn't echo the private text.

## Revisions after the Codex review (2026-11-22; they replace the conflicting parts above)
1. **Callers and grants.**
   - `Verifier.Verify(ctx, credential) (Workload, error)` returns the authenticated workload: role, repo, principal,
     session and assignment. The store takes a `Workload` only from the verifier, never from the caller's arguments.
     Service access is separate from `internal/authz`, which serves human decisions.
   - Grants are minted only by the `acceptance-scheduler` role (WI-24), from a **run record** that pins the candidate SHA,
     artifact digest, switch-config digest, intent revision and suite revision: `IssueGrant(ctx, w, RunRecord)`.
   - A grant is redeemed **once per attempt**: `Open(ctx, w, grantID, attempt)`. Issuing a replacement attempt fences
     every earlier one, and only the current attempt may record an outcome: `RecordOutcome(ctx, w, grantID, attempt,
     outcome)`. Outcomes are stored, so a later correction can cite an authoritative failed run.
   - WI-24 requirement: the private reader and driver run outside the candidate's sandbox, and candidate code never sees
     the reader or its credentials.
2. **Freshness and independence.**
   - At review and at open, the store checks atomically that the revision is eligible and that the **current** intent
     revision (from `IntentSource`) is approved and equals the bundle's. A pending, unapproved intent edit blocks use of
     the previous approval.
   - `Author` comes from the verified workload. The reviewer must differ from the author in **both** principal and
     session; the same qualified model is fine.
   - **Freeze:** once a run on revision R records a failure, a plain successor of R is refused. Only a correction that
     replaces R and cites a failed run recorded for the same suite and revision may supersede it, and it needs its own
     independent review before a rerun (INT-9, PIP-15).
3. **Public regression.**
   - The disclosure review of the exact public diff happens before the first forge write (WI-24 and the regression flow
     own that; the QE session writing it gets only public intent and repo context).
   - `LeakCheck` stays as a backstop for exact copies only: whole private files and fixture digests. The 16-byte literal
     rule is dropped.
   - Retained coverage is an attestation, not a count: `AttestCoverage(ctx, w, rev, disclosed []string)` by the scenario
     reviewer, against pinned revisions. Requalification needs it.
4. **Storage.** Memory backend in WI-21, for tests and development only. The PostgreSQL backend (WI-21a, after WI-10d)
   is an explicit prerequisite for the first real Acceptance run, with no memory fallback in a production
   configuration. It must preserve suites, reviews, grant redemptions, outcomes and audit across restarts.
5. **No oracle for unauthorized callers.**
   - `Public(rev)` and match counts are cut; coders already see public intent on the issue.
   - Authorization happens **before** any lookup, so a denied caller gets the same status and bytes whether the revision
     exists or not, and the backend is never read (tested with a counting backend).
   - The success audit entry is committed before any private byte is returned; a failed audit append releases nothing.

## Revisions after review round 1 (2026-11-22; they replace the conflicting parts above)
1. **Freeze is re-checked at approval.** `Review` approve runs the successor rule in the same transaction: a parent
   with any recorded failure is replaced only by a correction (it replaces the parent and cites a failed run recorded
   for that suite and revision), otherwise `ErrFrozen`. While the parent's current attempt is opened with no
   recorded outcome, approval waits (`ErrState`), because the failure could still land. A fenced attempt never
   blocks (it cannot record), so the scheduler unblocks a dead runner by issuing a replacement attempt. A stuck
   plain successor is rejected, after which the correction path is open. `RecordOutcome` still records on a revision
   that went stale or superseded, because the failure is evidence.
2. **Assignments bind one attempt, ever.** Run IDs and assignments are globally unique (Backend contract). A runner
   is bound to the attempt whose assignment its credential carries, and the attempt is bound to the runner session
   on first `Open`: a session that opened an earlier attempt of the run cannot open a later one, and only that
   session may record the outcome.
3. **Public IDs only.** A rejection's `Mismatched` must be a non-empty subset (at most `MaxScenarios`) of the
   approved public scenario IDs from the `IntentSource`, with a bounded free-text `Reason` (P4 evidence, escaped in the
   audit entry, never shown to coders). `MismatchError` lists approved IDs the bundle does not bind and only counts
   bundle-only extras.
4. **Attestation.** `AttestCoverage` needs the same independence as `Review` (principal and session differ from the
   revision's author). Disclosures are an append-only suite-level set: each attestation must include every earlier
   disclosure (`ErrDisclosureRegression`), they carry forward to successors, and are bounded and held as maps.
5. **No retry after an outcome.** A replacement attempt is refused once any attempt of the run recorded an outcome
   (pass or fail). A rerun needs a new run ID and a new assignment.
6. **Audit accuracy.** The backend exposes the global run and assignment indexes to the transaction function
   (`ReadTx`), so uniqueness refusals happen before the success audit append. The backend still enforces the same
   rules at commit as defence in depth.
7. **Suite-scoped QE and reviewer.** A QE or scenario reviewer workload must carry `Assignment == SuiteID.Assignment()`
   (`suite:<repo>#<issue>`, issued by WI-30). Repo scope alone is denied (reason `assignment`).
8. **Requalification.** Once the suite has disclosed cases, `IssueGrant` needs the revision to carry an attestation
   covering all of them (`ErrNotAttested`).
9. **`LeakCheck`** may be called by the scenario reviewer as well as QE, so the disclosure review is independent of the
   author.
10. **`Status(ctx, cred, suite)`** for the scheduler, QE and the reviewer returns the head revision, its effective
    status, whether it is eligible for the current intent, and the public scenario IDs blocking since the last
    rejection. No private bytes. Others get the uniform denial before any backend read.
11. **Runner denials** are one `ErrDenied` to the caller, with a specific audit reason (`unknown`, `assignment`,
    `fenced`, `expired`, `reused`, `unusable`, `stale`, `pending`, `session`, `intent-unavailable`, ...). A backend
    error other than not-found propagates as an error.
12. **No existence oracle for runners.** The run to suite lookup is one index call (`SuiteOfRun`, missing is
    `ok=false`, not an error) that costs the same for unknown and existing runs. A run of another repo and an unknown
    run share the denial and audit subject, and neither reads suite state.
13. **Refusals with an invalid suite** are audited using the decision form with the install-level subject.
14. **Effective status at read time.** `Read` and `Status` report an active revision as stale when the approved intent
    moved on, without waiting for a call to mark it. Marking still happens on use and is permanent.
15. **Bounds and paths.** `FailedScenarios` is de-duplicated, at most `MaxScenarios`, and must be bound scenario IDs.
    Disclosed and mismatched lists and their strings are bounded. File paths must be NFC, have no `.git` component
    (any case), and may not collide by duplicate, case folding or file-versus-directory prefix. Only test files may be
    executable.
16. **Blobs.** File bytes live in immutable blobs keyed by revision, written once at `Propose` in the same `Update`
    (`WriteTx.PutFiles`) and read by `Read` and `Open` (`ReadTx.Files`). The transaction state holds file metadata
    (path, mode, kind, size, SHA-256), and every blob read is checked against its digest. `LeakCheck` uses the digests
    and reads no blobs. The conformance suite in `internal/holdout/backendtest` (run against `memholdout`) is what
    WI-21a must pass.

## Revisions after review round 2 (2026-11-22; they replace the conflicting parts above, including round 1 item 1)
1. **Report deadline instead of fencing as the unblock.** `Config.MaxRunDuration` is required and positive. `Open` sets
   the attempt's `ReportBy = OpenedAt + MaxRunDuration`. An opened attempt, even one a replacement fenced, may still
   `RecordOutcome` a **failure** (never a pass) from its bound session until `ReportBy`; the failure freezes the
   revision like any other. A late outcome is refused (audit reason `late`), a fenced pass is refused (`fenced-pass`).
   Approval of a successor waits (`ErrState`) while any opened attempt on the parent has neither an outcome nor passed
   its `ReportBy`. After `ReportBy` the attempt is abandoned: it no longer blocks, and the first call that observes it
   marks it and appends an `abandoned` audit entry. A dead runner therefore cannot wedge a suite for longer than
   `MaxRunDuration`, and fencing never hides a failure. Replacement attempts keep all their eligibility checks.
2. **The reject reason never enters the audit log.** It is stored only in the private `ReviewRecord`. The audit entry
   carries its length and SHA-256.
3. **Content address on every release.** `Read` and `Open` build each returned file from the recorded metadata (path,
   mode, kind) plus blob bytes that match the recorded size and SHA-256, then recompute the bundle's content address and
   compare it with the revision ID. A missing blob, a different blob count, a bad digest, or coordinated metadata and
   blob tampering releases nothing, records nothing and writes no `ok` audit entry. `Propose` writes the blobs before
   the audit append, so a refused write leaves no phantom `ok` entry.
4. **Status.** `Eligible` also requires the attestation that the suite's disclosures need. `Blocking` is reported only
   while the head is not eligible: once a usable head exists, a rejected proposal no longer blocks hand-off.
5. **Approval fails closed** when `Bundle.Parent` is set but the parent record is missing (`ErrConflict`).
6. **Paths** also refuse Default_Ignorable_Code_Point characters (format characters such as U+200C, variation selectors,
   and the other default-ignorables), components ending in a dot or space, 8.3 short names (`~` and a digit) and colons.
7. **Backend conformance** (`internal/holdout/backendtest`, the suite WI-21a must pass) now takes a `reopen` hook and
   deep-compares every field of the state, blobs and indexes after commit and reopen. It also checks cross-suite
   run-ID and assignment races, a cancelled context, rollback after mutating existing records, `PutFiles` copying its
   input and a second write returning `ErrConflict`.

### Residuals accepted for v1
- **Same-repo wrong-assignment runner oracle (low).** A runner of the right repo with the wrong assignment is denied
  after the run's suite is resolved, so a runner can tell "a run of my repo exists" from "no such run". Runner-only,
  and the caller still learns nothing about suites or revisions.
- **Re-approval of an identical intent revision revives a revision bound to it.** A revision marked stale stays
  stale in storage, but if the same intent revision ID is approved again, a new `effective` view and a new grant check
  treat it as current. That is intended: the intent revision ID is the exact text approved.
- **Disclosure is tracked by case ID.** A reviewer attesting renamed cases is making a judgement the store cannot
  check; WI-24's disclosure review owns it.
- **Regression PR to disclosure linkage** is WI-24's: the store records what the reviewer attests, not which PR
  published the cases.
- **The QE session that writes the public regression test must get no suite assignment from WI-30**, or it could read
  the private suite. The store trusts the assignment as issued.
