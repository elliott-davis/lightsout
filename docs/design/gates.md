# Gate-of-record evaluation (WI-13)

Status: accepted after a Codex review, 2026-11-21. Covers WI-13: PIP-2, the execution-match half of CON-4, and the SEC-11 "same-name foreign check"
negative. It is a pure evaluation package, `internal/gate`. It takes the effective contract (WI-03), the forge's job executions
(WI-08) and the merge-group candidate, and returns a verdict per mandatory obligation. It does no I/O itself. The caller (WI-18)
fetches the inputs.

## Inputs
- `contract.Effective` for the change. `VerifyGates`, `Conflicts`, `Revision` and `InstallRevision` are used.
- `forge.MergeGroup`, or the queue member, whose `CandidateSHA` is the only SHA evidence may come from.
- `[]forge.JobExecution` from `ListJobExecutions(repo, CandidateSHA)`, which is complete or an error.

## Identity matching
A contract gate is `{producerId, workflowId, workflowRevision, checkId}`. An execution matches a gate only if **all** of these hold, plus `Repo == target repo`:
1. `producerId == Target.Forge + "-app:" + ProducerAppID`. A foreign app with the same check name never matches.
2. The workflow identity matches `workflowId`: `workflowId == WorkflowRepo + "/" + WorkflowPath` (see "Canonical identity forms").
3. The workflow content that ran is pinned at `workflowRevision` (see "Pinning").
4. `JobKey == checkId`, the rendered job name (forge.md), so matrix legs are distinct.
5. `CandidateSHA == group.CandidateSHA` and `Event == "merge_group"`.
6. After matching, `Provenance == Complete` and `SupersededBy == ""` are block conditions rather than match conditions. They apply to completed records only: an unvouched running record is `pending` (see "Attempts" and "Verdicts").

## Canonical identity forms
The contract schema allows `producerId` as `kind:id` and `workflowId` as `[A-Za-z0-9._/-]` without a colon, so the forms are fixed:
- **Producer:** `<forge>-app:<app id>`, such as `github-app:15368`. `Target.Forge` is required, and the match is `producerId == Forge + "-app:" + ProducerAppID`.
- **Workflow:** `<repo id>/<workflow path>`, such as `123456/.github/workflows/gate.yml`. The repo ID is the forge's stable numeric or opaque ID
  and has no slash. A `WorkflowRepo` containing a slash makes the record structurally bad, so it blocks as `incomplete`.

The adapter (WI-12) and the gate registry use exactly these forms. Registration rejects an integer `workflowId`, and a `workflowId` whose repo part has more than one segment.

## Pinning (decided)
A mandatory gate in v1 names a **reviewed workflow pinned at a full commit SHA**. `workflowRevision` must equal
`JobExecution.WorkflowCommit`, the commit of the workflow file that actually executed. For a reusable or required workflow, that's
GitHub's `job_workflow_sha`, bound to the specific job, for example through verified job-scoped OIDC claims joined by check-run ID.
If the adapter can't bind the callee commit to the job, provenance is `Incomplete` and the gate blocks.

An in-repo workflow always executes at the candidate commit, so it can never match a pin. Pinning only the top-level YAML blob
isn't sound: a local composite action or a gate script loaded from the candidate can still change the verdict. That mode is
deferred until registration can establish every file that controls the verdict.

`workflowId` names `<repo-id>/<path>` of the registered workflow.

**Known limitation.** For a pinned reusable workflow, the in-repo caller job (its `with:` inputs and the name that feeds the JobKey) comes
from the candidate. Soundness depends on CON-6 protected workflow paths (WI-14) until WI-12 binds the caller, or registration allows
only org-required or input-free reusable gates.

Registration-time rules belong to the gate registry (install config) and the WI-12 adapter, not to this package:
- registered gate jobs have static rendered names: no expressions in the job or caller-job `name:`. A newer attempt re-run under a different
  non-empty JobKey can't be told from a sibling job here, so this package doesn't try
- the adapter sets `SupersededBy` on every job of an older attempt that a newer attempt of the same run re-ran, keyed by (RunID, JobKey)
  whatever the producer or attempt binding
- the adapter binds `CandidateSHA`, `RunID` and `RunAttempt` from the run at creation
- `ListJobExecutions` lists every job of every run on the candidate, including in-flight ones

The forge fake gets the same behaviour in WI-08a.
- mandatory legs have fixed, unique rendered names
- no `if:` can skip the gate-defining job
- no step- or job-level `continue-on-error` on gate-defining work

SEC-4's secret scanning and dependency scanning are factory-owned registered jobs of this kind, not GitHub's native features. Native
secret-scanning merge protection reports on the PR head, not on the queue candidate.

## Attempts
Executions for the target repo and JobKey are grouped per (run, JobKey) **before** any identity filtering. A newer attempt that doesn't
match still counts as the newest, so it shadows an older success. Only the newest attempt (numeric maximum) of each group counts. A record with a
canonical attempt below the newest complete, well-formed attempt of the real producer is out, so an old incomplete record can't block
forever. A non-canonical attempt can't be ordered, so it still blocks:
- A running job (no conclusion) without complete provenance is `pending` and shadows older attempts, whatever its identity fields say
  (empty workflow commit or path, another or empty producer, a non-canonical attempt). The adapter binds these late and none is vouched for.
- A record with `Provenance == Complete` and a different producer is `foreign` and can't block or supersede the real producer's group.
- Any other completed record that is incomplete, or structurally bad, blocks the obligation as `incomplete`. Structurally bad means a missing
  identity field (producer, workflow repo, path or commit, candidate, event, run or job ID), a slash in the workflow repo, or a `RunAttempt`
  that isn't `^[1-9][0-9]{0,8}$`. A structurally bad record blocks even when its producer differs, because it can't be vouched for as foreign.
  A completed foreign record without complete provenance is also `incomplete`.
- Records that can't be grouped at all (another repo, or an empty RunID, JobKey or JobID) are handled for the whole change: running holds the
  change at `pending` or worse (`unattributed-running`), and a blocked obligation still wins over it. Completed makes it an `error` (`malformed-evidence`).
- Across runs, two or more vouched current matches are `ambiguous`. One vouched match is judged on its own, except that a pass becomes `pending`
  while an unvouched running record exists. With no vouched match, an unvouched running record makes the obligation `pending`. Unvouched running
  records can stall a merge indefinitely. That is fail-closed and belongs to WI-18's pending-timeout policy.
- A newer attempt that is pending, failed, or plausibly matching but incomplete blocks an older success.
- An untouched matrix leg keeps its success across a partial rerun.
- Two or more records in one attempt of a group (legs sharing a rendered name), or current matches in different runs, are `ambiguous`.

## API (for WI-18)
```go
type Target struct { Forge string; Repo forge.RepoID; PR int; HeadSHA, CandidateSHA string }
type Evidence struct { Executions []forge.JobExecution; Complete bool }   // a snapshot; Complete=false means block
func Evaluate(eff *contract.Effective, t Target, ev Evidence) Decision
type Decision struct {
    Target; PolicyRevision, InstallRevision string
    Disposition Disposition // pass | pending | blocked | error
    Reasons []Reason // change-level: invalid-input, conflict, no-mandatory-gates, unattributed-running, malformed-evidence, incomplete-evidence
    Obligations []ObligationResult // per gate: full GateRef, owner, sources, mandatory, disposition, reason, and the RunID/RunAttempt/JobID used
}
```
Pending (still running; not a terminal block), blocked (terminal) and error (collection failed) stay distinct, so WI-18 can retry, repair or audit.
`PR` and `HeadSHA` are echoed from the caller and not checked here, so WI-18 must verify merge-group membership.
`Evaluate` returns `error` with `invalid-input` for a nil contract, an empty revision, install revision, forge or repo, a candidate that isn't
a full lowercase SHA-1 or SHA-256, or a mandatory gate with an empty field. A contract with no mandatory verify gate is `blocked`
(`no-mandatory-gates`). Change reasons: `invalid-input`, `conflict`, `no-mandatory-gates`, `unattributed-running`, `malformed-evidence`
and `incomplete-evidence`.
WI-18 re-evaluates right before publishing its verdict. A pass for B's cumulative candidate never satisfies A.

## Verdicts
For each mandatory obligation:
- **pass:** exactly one matching execution with conclusion `success`, actually started and completed.
- Every other case blocks, with a typed reason:
  - `pending`: a matching job is still running. Not a block: retry later.
  - `missing`: no match.
  - `ambiguous`: two or more current matches, including two distinct records in one attempt.
  - `foreign`: a same-name execution from another producer exists. Reported as evidence alongside missing.
  - `not-run`: conclusion skipped, neutral, cancelled, timed out or unknown, or no start time, or a completion time before the start.
  - `failed`.
  - `unpinned`: the workflow content doesn't match the pin.
  - `incomplete`: a completed record's provenance isn't complete, a record is structurally bad or has a non-canonical attempt, or the newest attempt is already superseded (a newer one is missing from the snapshot).
  - `stale-candidate`: the execution ran on another SHA or for another event. Reported as evidence only when it's the sole near-match.
- **Advisory obligations** are evaluated and reported with the same verdicts, but never affect the change disposition.
- **The change as a whole** is blocked if any mandatory obligation blocks. It is also blocked when `Effective.Conflicts` is non-empty, 
  or when the contract has no mandatory gate. An incomplete evidence list is an `error` (collection failed), which outranks a block.
- **Owner == factory** gates can't be waived, and nothing in this package offers a waiver.
- **The result binds to** `(Effective.Revision, Effective.InstallRevision, CandidateSHA)`. A new candidate invalidates it.

## Tests (SEC-11 negatives)
- **Same-name foreign check:** another producer with the same check name, which is never a pass.
- **Wrong evidence:** an overall-green workflow with one mandatory job skipped, a neutral conclusion, a missing job, and a superseded success with a later failure.
- **Wrong place or kind of run:** a stale group SHA, an Event that is a PR rather than a merge group, and incomplete provenance.
- **Matrix:** one leg failed.
- **Workflow changes:**
  - An in-repo workflow file edited in the candidate gives `unpinned`.
  - A reusable workflow at another commit gives `unpinned`.
- **Policy states:** conflicts present.
- **Queue movement:** a new candidate after an eject has no evidence.
- **The pass case:** all evidence matches.
