# V1 backlog

Generated from [PRD.md](../PRD.md) v0.1 on 2026-11-21. Each work item (WI) implements the `v1` phase of the
requirement IDs it lists. Items are in dependency order: an item depends only on items above it. Every one of the
95 v1 requirement IDs appears in at least one item. Where a requirement spans layers, each item that touches it
says which part it owns.

Status values: `todo`, `in progress`, `done`. Update the status, and the commit that finished the item, as work
lands. Design notes for larger items live in [docs/design/](design/).

## How the order was chosen

1. **Pure domain first.** Contracts, audit, decisions and install config have no I/O dependencies and everything
   else consumes them. They are testable offline without fakes.
2. **Then the forge boundary.** One interface (`internal/forge`) with an in-memory fake, then the GitHub adapter.
   Every gate and intake item is built against the fake.
3. **Then the stages in pipeline order**: Verify, Intake, Acceptance, Union, Recovery. Verify comes before Intake
   because Intake's hand-off and every later stage depend on PRs being able to pass Verify.
4. **Runtime, cost and operations last** among the code items, since they wrap stages that already work against
   fakes. Qualification (milestones A and B) closes v1.

## Phase 1: domain foundations

| WI | Work item | Requirement IDs | Depends on | Status |
| --- | --- | --- | --- | --- |
| WI-01 | Path globs | CON-7, CON-12 (support) | — | done (7966634) |
| WI-02 | Contract schema, parsing and discovery | CON-11, CON-4, CON-1 | — | done |
| WI-03 | Effective contract resolver and relational validation | CON-3, CON-5, CON-7, CON-9, CON-12, AGD-3, SEC-5 | WI-01, WI-02 | done |
| WI-02a | Accept numeric-looking gate pins as strings | CON-4 | WI-02 | todo |
| WI-03a | Bound cross-stack source merging in Resolve | CON-3 (availability), SEC-1 | WI-03 | todo |
| WI-04 | Incremental validation, explain, gate registry check, CLI | CON-13, CON-4 | WI-03 | done |
| WI-04a | Incremental scope versus the whole-set compile budget | CON-13 (availability) | WI-04 | todo |
| WI-05 | Append-only audit log | NFR-4, RUN-5, AGT-6 | — | done |
| WI-06 | Identities, roles and revision-bound decisions | SEC-10, NFR-5 | WI-05 | done |
| WI-07 | Install config, role profiles and admission | RUN-6, AGT-7, NFR-2, SEC-1, CON-9, CON-5 | WI-03 | done |
| WI-07a | Install validation hardening (forge hosts, floating versions, loopback aliases) | SEC-1, AGT-7 | WI-07 | todo |

- **WI-01** `internal/pathglob`: anchored globs (`*`, `?`, `**`), strict syntax, matching, and a conservative
  containment proof that fails closed. See [design/contracts.md](design/contracts.md).
- **WI-02** `internal/contract`: the embedded, versioned v1alpha1 JSON Schema, which rejects unknown fields (so a
  command field fails); hardened YAML parsing; strict decoding; gates identified by producer, workflow, pinned revision
  and check, never by name alone; discovery of `.factory.yaml` at any level (CON-1 coverage).
- **WI-03** The stack of contracts per path and per change (CON-3); merge rules per field (CON-12); lowest-level
  overrides over install defaults (CON-9); gate owner and mandatory/advisory with an unwaivable factory baseline (CON-5);
  path classification as writable, read-only or forbidden (CON-7 data, not Verify); core reviewers that can't be
  removed (AGD-3); sensitive paths that require the security reviewer (SEC-5 data).
  From the WI-01/02 review: deny lists match exactly, after case-folding and NFC normalization, or on any
  ancestor directory. A path that fails `ValidatePath` (including one over 256 segments) is an error, never
  "allowed", and gets a denial test. Re-validate any contract given to the resolver, since `NewSet` accepts
  hand-built ones. Document that `*.pem` is anchored and doesn't match `certs/key.pem`.
- **WI-02a** Found during WI-13. A contract `pin` written as bare digits, or as something YAML reads as a number (`1e5`-style digits), becomes a YAML number, so the schema rejects it. A real all-digit SHA is astronomically rare, but the schema should accept the string form: document "quote the pin" or coerce scalars for pin fields, and add a test.
- **WI-03a** The first WI-03 follow-up, which the user deferred from WI-03 on 2026-11-21. The change-level merge in `Resolve`
  (`mergeObligations`, `mergeOracles`, `mergeRequirements`) re-clones and re-sorts a shared identity's source list on every
  duplicate, and charges only the obligation count. With 1000 contracts sharing 64 gates per stage, and a change touching 969 paths,
  one Resolve takes 30 s to 3.5 min and never fails closed. The cost is quadratic in the number of stacks. Fix: gather each identity's sources
  across stacks and sort and dedupe once, charge Σ len(Sources) plus the final sort, and cache source ranks.
  Add a regression test for the shape and a mutant check. Its verification audits every loop in Compile and Resolve
  for an uncharged cost, not just this one. Security results are correct today; this is an availability issue only.
- **WI-04** Incremental validation of a contract with its ancestors and descendants; an explain command
  that shows each effective value and its source (CON-13); registered-identity and revision check against a consumer-defined registry (CON-4).
  From WI-03: `ValidateChanged` wraps `Policy.validate(dirs)`. The scope is the changed contracts, their dirKey ancestors and descendants, and any directory whose key collides with them (a parent re-pin makes descendants conflict). `Explain` surfaces `AccessSource`, `SensitiveSources`, `LightsOnSources`, `Obligation.Sources` and `Valued.Source`, all of which already exist, and must escape the raw repo path text they carry. `CheckGates` covers the baseline gates too. `buildStacks` sets no problem when a contract over the gate cap lies outside a partial scope: with incremental scopes, always record a problem or fail closed.
- **WI-04a** WI-04 follow-up (availability only). The compile work budget is shared across the whole set. Sibling contracts that each pass a scoped
  `ValidateChanged` can exceed it together, so the merged policy no longer compiles and the factory fails closed for the repo.
  Fix: per-contract budgets, or store the trusted spend with the trust digest and charge the scoped delta. Add a test where the siblings fit
  individually and fail together, and assert both paths agree. Until then, WI-11 runs a full Compile before activation.
- **WI-05** `internal/audit`: an append-only interface with no update or delete, and hash-chained entries. Every entry
  has an actor and a subject (change, issue or install). Agent and factory entries carry the template or build version
  (RUN-5). Every agent tool call, model call and repo write names a change or, before a PR exists, an issue (AGT-6). A
  `link` entry ties a change to the issue it came from. In-memory and file-backed stores first; PostgreSQL arrives with WI-10.
  The chain is unkeyed: a deliberate rewrite or truncation is caught only by `VerifyAgainst` with a checkpoint kept outside the log.
- **WI-06** `internal/authz`: forge identity, role, scope (repo or install) and the exact revision or digest a
  decision binds to. It rechecks at execution against a current role source, and rejects edited, copied, quoted, bot,
  stale, revoked and cross-repo decisions. Every decision, granted or denied, is audited. Negative tests per SEC-11.
  WI-05 already carries the evidence shape (`audit.Decision`, `ActorExternal` for bot and unverified principals); WI-06
  enforces that `Decision.Revision` is an immutable revision or digest.
- **WI-07** `internal/install`: install config with defaults for timers and caps (AGT-5, INT-15, PIP-15, REC-3, COST-2/3/4/7),
  the factory baseline gates (SEC-4 identities) and core reviewers, one pinned runtime, harness and model profile per enabled
  role (RUN-6, AGT-7), and a qualification record check that runs before admission (NFR-2 data). Validation fails any role
  that combines untrusted input, secrets and open egress (SEC-1).
  From WI-06: supply `authz.Config` (`Forge`, `InstallID`, per-operation `Expiry` with none as the default, `DenialAuditTimeout`). Define the install's admin principals by forge and stable ID, never by login, and who may change that list. Decide whether install-config changes go through authz (the PRD names "admin" in SEC-6 but only "Enterprise IT" in the roles table).
  From WI-03: supply `contract.Baseline` (mandatory gates, `Reviewers`, `PRReviewer` distinct from `SecurityReviewer`, `KnownAgents`, `Protected` patterns such as `.github/workflows/**` and `CODEOWNERS`) and `contract.Defaults` (each at least 1). `Compile` validates them, but install-time validation should report errors earlier and more clearly.
  From WI-04: back contract.GateRegistry from install config (registered {producerId, workflowId, workflowRevision, checkId}; no empty fields; 40/64 lowercase hex). Any change to the baseline, defaults, KnownAgents or the registry triggers a full Compile plus CheckGates across every managed repo and reports failures without silently deactivating. Replace the CLI's interim defaults in cmd/factory/contract.go (baseline(), defaults()) with --install so they can't drift.
- **WI-07a** WI-07 follow-up (no critical findings). Forge-host suffix matching (github.com, githubusercontent.com, githubcopilot.com, ghe.com, github.ai, ghcr.io, and forgeHosts with their subdomains); GitHub IP ranges, or a WI-30 note. More floating words (insiders, prerelease, pre, development, devel, unreleased, wip, newest, recent, previous, last, prod, production, live; glued forms like nightly2025; `/` in versions). Model-name false positives (qwen3-next-80b, flux.1-dev, stable-code-3b, …-preview-tts). More loopback aliases (host.containers.internal and similar).

## Phase 2: forge boundary and control-plane state

| WI | Work item | Requirement IDs | Depends on | Status |
| --- | --- | --- | --- | --- |
| WI-08 | Forge interface and in-memory fake | INTG-1 (interface) | WI-06 | done |
| WI-08a | Forge fake: remaining denial tests and fidelity | SEC-2, SEC-3, SEC-11 | WI-08 | todo |
| WI-09 | CODEOWNERS ownership resolution | CON-2 (ownership) | WI-08 | done |
| WI-10 | State store and event loop | NFR-5 (event paths), NFR-4 (durable store) | WI-05, WI-08 | todo |
| WI-11 | Contract activation and protected policy path | CON-2, CON-6, CON-10 (review path) | WI-04, WI-06, WI-09, WI-10 | todo |
| WI-12 | GitHub adapter | INTG-1 | WI-08 | todo |

- **WI-08** `internal/forge`: issues and comments with authenticated authors and edit state; issue types and
  `type:` labels; sub-issues; content and tree at a revision; check runs with producer and workflow identity; merge
  queue groups; and branch push scoped to one identity. The fake is the test double for everything below.
  Includes a read-only `fs.FS` over a git tree at a commit, which is the only input `contract.Load` may be given in
  production. Adapters must `url.PathEscape` gate identity values (`workflowId`, `checkId`) when building API paths.
- **WI-08a** WI-08 follow-up: forge fake gaps left after three fix rounds, found by the final verification.
  - **TOCTOU denial tests.** The re-plan after `Deny` (push.go) has no deterministic denial test. Add these cases:
    - Deny reassigns or revokes the change: ErrForbidden, ref unchanged.
    - Deny pushes on the same pusher: the outer push gets ErrConflict.
    - Deny re-bases to a different diff: ErrConflict.
  - **Pin these with tests that kill mutants:**
    - the RecordMerge member-index check, using stacked PRs;
    - the RecordMerge no-op clause;
    - mode-only diffs on workflow and denied paths;
    - `WorkflowRepo` in supersession;
    - deleting the ejected member's queue ref.
  - **Fidelity of RecordMerge outside a group.** Refuse drafts, octopus merges and another group's candidate, or mark every PR whose head landed as merged.
  - **Fidelity of AddCheckRun.** Reject a conclusion unless the status is completed, and reject an unknown head SHA.
  - **Symlinked .github.** Refuse a symlink or gitlink at a proper prefix of a workflow or denied path (`.github`, `.github/actions`).
  From WI-13: the fake lists only records whose CandidateSHA is bound, and supersedes only when the attempt parses and the producer and workflow match, so a newer unbound attempt can drop out and let an older success pass (impossible on real GitHub). Supersede on (RunID, JobKey) alone, with a fake-forge test.
- **WI-09** Parse CODEOWNERS (gitignore semantics) at a trusted revision and resolve each path's current owners.
  From WI-06: implement the owner roles of `authz.RoleSource` (`path-owner`, `code-owner`, `contract-owner`). Resolve by forge and stable ID, mapping the ID to its current login and team membership at execution time with no cache. Return true only when the principal owns every path in `Target.Paths`, and deny on any lookup error. Define how code-owner and contract-owner differ. Negative tests: a renamed login, a recycled login, and a team removal between decision and execution.
  From WI-08: use IdentityReader live with no cache. Read CODEOWNERS only via TreeReader.Tree at a full SHA. A symlinked CODEOWNERS (ErrSymlink) denies. A revoked actor (ErrNotFound) denies.
- **WI-10** PostgreSQL-backed state for issues, changes, features and trains; idempotent webhook ingestion with
  signature checks; one authorization path for issue events, checks, callbacks, API and admin actions (NFR-5).
  The PostgreSQL audit backend implements `audit.Backend` and serializes head selection and insert in the transaction
  that records the state change. Persist audit head checkpoints outside the log's storage and run `VerifyAgainst` at startup.
  The first HTTP surface: write its OpenAPI document first and serve it with chi (AGENTS.md, API first). Generate
  types and handler interfaces with oapi-codegen's chi strict-server output (tool pinned in `tools/go.mod`, plus its
  runtime module); justify both in the PR description.
  From WI-06 (see docs/design/authz.md, "Caller contract" and "Notes for WI-10"):
  - Route human decisions from `issue-comment`, `review`, `api` and `admin-cli` only through `Authorize`. Checks and callbacks use service identities (WI-30).
  - Set `Authenticated` only after the signature or credential check. Set `IntegrityOriginal` only after re-reading the forge's edit state at execution time.
  - Implement `authz.Tx`: `Consume` is a unique index that is never purged, and the grant append and the caller's state change share one transaction.
  - Act only through a compare-and-swap on `Grant.Target.Revision`.
  - Serialize the denial auditor's chain with the transactional one, or keep them on separate chains.
  - Rate-limit before `Authorize`, and never echo `DeniedError.Reason` back to the caller.
  From WI-08: map GetComment/GetReview re-reads to Integrity at execution time. EditUnknown, edited and deleted all deny. Check that Comment.Repo/Issue match the subject. Key issues by NodeID. ErrIncomplete and RateLimitError mean block and retry, never a partial result.
  From WI-07: implement install activation. It needs `quorum` granted OpActivateInstall decisions from distinct principals, taken only from the active revision's RoleSource, and consumed together with a compare-and-swap of the active generation in one transaction. Target.Revision = install.ActivationRevision(installID, activeGeneration, candidateCommit). Bootstrap happens once; refuse a second. Read the install config only via install.Load at a full SHA, refuse an empty InstallRevision on any production path, and store the install revision with every decision and evidence row. The quorum helper counts distinct principals, never grants; authz.Grant has no Principal field, so carry it alongside. Denial tests: the same approver twice; a member only of the candidate revision; a bot.
  From WI-15: review.Evaluate fails closed on any signed record inconsistent with the snapshot, but can't detect a record deleted outright or one whose signature was corrupted. Build the review snapshot from audited store records with a completeness proof (a per-change chain or sequence range), and set Snapshot.Complete only when that proof checks.
- **WI-11** Activation of a contract revision requires approval of that exact revision by a current owner,
  under the previously trusted ownership and gate rules. A product change can never supply the policy that
  authorizes it (CON-2). Protected paths (contracts, CI definitions, CODEOWNERS) fail a product PR, and a protected
  proposal is evaluated under the current trusted policy (CON-6). An onboarder draft goes through the same path (CON-10).
  Protected-path matching case-folds, so a product PR can't add `x/.Factory.yaml`. That would fail every later
  contract load closed.
  From WI-06: use `authz.OpActivateContract` with `Target.Revision` set to the contract proposal revision and `Paths` set to the area. Require one grant per affected owner area under the previously trusted CODEOWNERS. Test that a proposal whose own CODEOWNERS edit would make the approver an owner is denied.
  From WI-03: protected-path classification already exists (`PathPolicy.Protected`; contract files and `Baseline.Protected` are always Forbidden). Reuse it; don't build a second matcher. Bind activation to `Effective.Revision`.
  From WI-04: validate a contract proposal with ValidateChanged plus the registry in one call, bound to the proposal revision. Derive changedDirs from the forge diff between the trusted and proposal revisions, never from the PR text: added, edited, deleted and renamed contracts, both sides of a rename. Pass dirs, not file paths. Misnamed, case-variant and symlinked contract files block. Assert the diff covers every contract file that differs. Store Scope.Checked and the registry answers with the activation decision for audit. derive Changed by comparing each contract file's digest against the trusted set, not only from the forge file list, which can be truncated. Include the old path of every rename. Always run a full Compile (about 2 s worst case) before activating anything. Incremental validation is for PR feedback only (WI-04a).
  From WI-09: build the owner RoleSource from codeowners.Load at the previously trusted base SHA, never the proposal head. Take that SHA from the protected default ref, never from the PR payload's base (GitHub serves fork commits by SHA). A Load error (ParseError, ErrSymlink, ErrTooLarge, ErrIncomplete) denies; never fall back. Record File.Revision() and File.Path() in the activation audit. RoleContractOwner checks the contract file paths being activated, which matches what GitHub's own code-owner review enforces (authz.md). Use one Target per owner area. Tests: a proposal that edits or adds .github/CODEOWNERS to make the approver an owner is denied; a repo A RoleSource never authorizes in repo B.
  From WI-07: activating a new install revision runs a full Compile plus CheckGates across every managed repo and reports failures without deactivating anything. Bind contract activation evidence to Effective.Revision plus Effective.InstallRevision.
- **WI-12** `internal/forge/github`: go-github implementation of WI-08, GitHub App auth, issue types, Checks
  publishing and the merge queue. Contract tests run the same suite against the fake and against recorded fixtures.
  From WI-08: implement forgetest.Harness over recorded fixtures. Tests: url.PathEscape of identity values; an invalid tree name means Tree errors; modes 120000/160000; Compare beyond 3000 files and truncated trees are recovered or give ErrIncomplete. JobExecution.Provenance is Complete only when every field, including reusable-workflow repo/commit, came from the API.
  From WI-09: verify CODEOWNERS wildcard-last-segment descent (`*.js` vs `lib.js/x.ts`), inline `# comment` among owners, and unknown-owner lines against recorded GitHub behavior. IsTeamMember maps GitHub's `state: pending` to false (active membership only).
  From WI-13:
    - **Callee identity.** Fill JobExecution's WorkflowRepo (stable repo ID), WorkflowPath and WorkflowCommit with the executed (callee) workflow. Bind job_workflow_ref and job_workflow_sha to the specific job, for example through job-scoped OIDC claims joined by check-run ID; if that fails, Provenance is Incomplete.
    - **Caller binding.** Either add the caller's repo, path and commit plus an inputs digest, or allow only org-required, input-free reusable workflows as gates and reject other reusable gates at registration.
    - **Registration rules, at the pinned commit:** fixed, unique rendered names; no `if:` on gate-defining work; no continue-on-error. Resolve a numeric workflowId to `<repo-id>:<path>`, or reject it.
    - **Conclusions.** Map stale, action_required and startup_failure to a completed non-success value, never ConclusionNone. ListJobExecutions lists Actions jobs only. Set SupersededBy on every older attempt.
    - **Conformance:** an incomplete record's RunAttempt equals its run's attempt (gate's older-records skip relies on it). Fixtures: matrix names, a single-leg rerun, a reusable callee, a skipped job with started_at set, and the twin-ambiguity cases through the fake.

## Phase 3: Verify

| WI | Work item | Requirement IDs | Depends on | Status |
| --- | --- | --- | --- | --- |
| WI-13 | Gate-of-record evaluation | PIP-2, CON-4 (execution match), SEC-11 (foreign check) | WI-03, WI-08 | done |
| WI-14 | Path, protected-path and PR shape gates | CON-7, CON-6, INT-18, INT-19 | WI-11 | todo |
| WI-15 | Review policy and evidence rule | AGT-3, AGT-4, AGT-5, SEC-5, AGD-3, CON-8, INT-20 | WI-03, WI-06 | done |
| WI-15a | Review evidence: dismissals and cross-claim confirmations | AGT-4, SEC-11 | WI-15 | todo |
| WI-16 | Dark-merge oracle evaluation | PIP-13, PIP-4, INT-10 (comparison) | WI-13 | todo |
| WI-17 | Non-switchable changes | PIP-9 | WI-14, WI-15 | todo |
| WI-18 | Verify orchestrator and merge | PIP-1, PIP-2, SEC-2, SEC-4, NFR-6 | WI-13–WI-17, WI-10 | todo |

- **WI-13** Every mandatory gate needs an execution record with its trusted producer, workflow identity, pinned
  revision, job identity, merge-group SHA, actual execution and explicit success. Skipped, neutral, missing, stale,
  foreign and same-name results block. A new queue head invalidates earlier results.
  From WI-03: treat `Effective.Conflicts` as a block, bind results to `Effective.Revision`, and treat `Obligation.Owner == factory` as unwaivable.
  From WI-08: evidence comes only from ListJobExecutions at the merge-group CandidateSHA. Block on: incomplete provenance, SupersededBy, a mismatched producer/workflow/commit/job key, Event != merge_group, or a non-success conclusion. A new candidate after an eject has no evidence.
- **WI-14** A change outside writable paths fails unless it touches only read-only paths and a path owner approves (CON-7).
  A change that mixes writable and read-only paths fails.
  A product PR that touches a protected path fails (CON-6). Shape rules fail with their gate ID (INT-18). The soft
  review budget counts hand-written lines only, and detects generated files from linguist attributes, DO NOT EDIT
  headers and contract paths, and compares the total against the smallest budget that applies (INT-19). The shape
  rules don't trust contract-declared `generated` paths alone.
  From WI-03: `Effective` has no change-level verdict. Build "all writable, or all read-only plus owner approval; mixed fails" from `Paths[i].Access`. Uncovered, Protected, `ErrInvalidPath` and `ErrTooComplex` all fail. Use the smallest `ReviewBudgetLines` across paths. `Generated` is an override, so never trust it alone. Escape raw path text in any output.
  From WI-09: CON-7 path exceptions pass Paths = exactly the read-only paths touched, with CODEOWNERS at the trusted base. A CODEOWNERS Load error is a failed gate with its own ID. A product PR that adds, modifies, deletes or symlinks any codeowners.Locations() path, or a case or normalization variant of one, fails as protected (CON-6).
- **WI-15** Reviewer context excludes coder reasoning and holdouts (AGT-3). Provisional blocks carry location,
  invariant, consequence and verification plan, with confirmation or dismissal on evidence (AGT-4, P4). A round cap
  escalates to an owner (AGT-5). Sensitive paths need security signoff (SEC-5). Lights-on needs current owner
  approval of the exact change, impact and recovery plan (CON-8). A split request becomes a replan request (INT-20).
  From WI-03: when `SecuritySignoffRequired` is set, require explicit approval from `Effective.SecurityReviewer`. Every change needs both core reviewers plus the specialists from each stack (`Effective.Stacks[i].Reviewers`).
- **WI-15a** WI-15 follow-up (low; from the final security verification). (1) A key-verified, bound dismissal for an unknown claim is only rejected; make it inconsistent-evidence, as for confirmations, since its signed ClaimRef proves the claim existed (exploiting it needs a record deletion, which is WI-10's to prevent). (2) A verifier assigned to C1 who confirms naming C2 counts only against C1; also count it against the named claim when that claim is known.
- **WI-16** Compare baseline and merge-group candidate on responses, reads, writes, events and queued jobs. Dark
  features and Tasks require equivalence (PIP-4). An authorized Fix permits only its delta (INT-10). Record both
  SHAs, configs, the oracle revision and the result.
- **WI-17** Declared effects, affected callers, rollout order, recovery steps and owner approval of the exact revision.
  An errant flag-off side effect blocks. Expand and contract run as separate trains.
  From WI-15:
    - Build the approval with `review.ApprovalManifest` (internal/review/canon.go); don't define a second encoding.
    - Set `Snapshot.NonSwitchable` for every declared non-switchable change, even when LightsOn is false. It wins over LightsOn.
    - Bump `Generation` on every edit to impact, recovery, callers or rollout order, including an edit that is later restored. Never reuse a generation. ImpactRevision and RecoveryRevision are digests of the recorded effects and steps. Include the old paths of renames in OwnerAreas.
    - Still owned here: independent mandatory gate results, errant flag-off side effects (WI-16), isolation under INT-18 (WI-14), expand and contract trains, and "missing evidence requires coverage or replanning". Open decision: whether PIP-9 approvals need their own authz operation.
- **WI-18** The control plane alone merges, through the queue (SEC-2). Secret and dependency scans are mandatory
  baseline gates (SEC-4). Every agent commit carries the contract's trailer (NFR-6). Issues and Checks show the stage
  and disposition (PIP-1).
  From WI-08: BranchRules(default) must be Complete, require the merge queue, require the factory verdict by the factory App ID, and have no agent bypass actors. Empty rules mean a failing install. Read NFR-6 trailers from DiffReader.Commits. Add check output fields for PIP-1.
  From WI-13:
    - **Target and evidence.** Build gate.Target from the PR's own queue member (Members[i].CandidateSHA), never the group tip. Any fetch error means Evidence{Complete:false}.
    - **Before publishing:** check PolicyRevision and InstallRevision against the current trusted revisions, recheck gate registration, re-evaluate right before publishing, and publish on the CandidateSHA.
    - **Dispositions.** pending means retry; blocked means repair or rerun; error means retry, then audit. Unvouched running records hold a change at pending indefinitely, so add a pending-timeout policy with escalation and an audit entry.
    - **Merge** requires the gate plus WI-14 (CON-6 also stops caller-workflow tampering for reusable gates), WI-15 and WI-16. Audit the Decision; escape gate names and reasons in check output. SEC-4 scans are registered factory-owned baseline gates.
  From WI-15:
    - **Dispatch.** Assignments use unguessable IDs. Each role gets its own session, never a coder session. Rounds have a monotonic Seq and a RoundID is never reused; a one-role follow-up is a new round. A round is superseded when the head changes. On Escalated, assign a contract owner exactly once.
    - **Context manifest.** Spec, diff, callers of changed interfaces, contracts, history and public tests, all read-only; never coder reasoning, transcripts or holdouts. Acceptance test: a changed interface yields a caller item for an unchanged caller.
    - **Signing.** The runtime signs the full assignment digest; key IDs are bound to the runtime's workload identity; review.Keys comes from install config with Kind set from that identity, never from the snapshot.
    - **Inputs.** Resolve Effective over new paths, the old paths of renames and deleted paths, so SensitivePaths and LightsOn see all of them. Fill ChangedPaths from DiffReader, set Complete only when everything was read, and fill Snapshot.Gate from WI-13 at the current candidate.
    - **Config.** Timers.ReviewRounds maps to Config.ReviewRounds and Baseline.PRReviewer to Config.PRReviewer. VerifyAttempts and VerifyTimeout need install-config fields. SizeGateID must equal WI-14's review-budget gate ID.
    - **Lights-on.** On NeedsAuthorization, authorize every RequiredApprovals target at execution time, in the merge transaction. Never cache a grant.
    - **Before publishing or merging,** check StateVersion, PolicyRevision, InstallRevision, HeadSHA and PR against the current queue candidate in the same transaction. Route the replan obligation to the spec writer with who asked and why (INT-15). Audit the Decision and its Rejected records; escape claim text and paths in check output.

## Phase 4: Intake and holdouts

| WI | Work item | Requirement IDs | Depends on | Status |
| --- | --- | --- | --- | --- |
| WI-19 | Intake state machine on issues | INT-1, INT-2, INT-3, INT-8, INT-11, INT-12 | WI-06, WI-10, WI-03 | todo |
| WI-20 | Scenarios, spec and PR plan | INT-4, INT-5, INT-14, INT-15, INT-16, INT-21, FLG-1, COST-1 (estimate) | WI-19 | todo |
| WI-21 | Holdout store | INT-6, INT-7, INT-9, AGT-2 | WI-06, WI-05 | todo |
| WI-22 | Unflagged Fix authorization | INT-17, INT-10 | WI-03, WI-20 | todo |
| WI-23 | Switch convention detection and records | FLG-2, FLG-3 | WI-08 | todo |

- **WI-19** Intake state, versioned proposals and authenticated decisions recorded on the issue (INT-1). The refined idea's
  affected paths and duplicate or conflicting issues (INT-2). A proposed and confirmed type mapped to GitHub
  issue types or `type:` labels (INT-3). No owner gate at intake (INT-8). Splits become sub-issues (INT-11). Refusal reasons
  cover no covering contract, forbidden paths needed and multi-repo work (INT-12).
  From WI-06: implement the ideator `RoleSource`. The ideator must be a verified human who is eligible under the intake policy. A bot-opened issue has no ideator until one is bound, a transfer needs a fresh binding, and any delegation is audited. Proposal revisions are 40- or 64-hex digests, unique per subject and new on every edit, including reverts. The `decide-split` Choice is the digest of the kept set. Store the rejection comment with the state change. Decide whether submitting an idea is itself an audited decision.
  From WI-08: SetIssueType reports native or label; define precedence when a stray type: label exists. A transfer (TransferredFrom set) needs a fresh ideator binding. Splits use AddSubIssue/ListSubIssues.
- **WI-20** Ideator approval of the exact scenario revision before any spec (INT-4). Spec and plan committed under a
  factory path keyed by switch or issue ID (INT-5). The plan is a dependency graph whose first PR adds the switch, off (INT-14).
  Only the spec writer replans, every replan is logged, and replans are capped (INT-15). An explicit complete state (INT-16).
  Each scenario records its bound test layer (INT-21). Switch IDs are minted here (FLG-1). The cost estimate is recorded (COST-1).
- **WI-21** Only QE and the scenario reviewer can read a suite. The Acceptance runner gets read-only access scoped to
  one run and suite revision. Coder, PR reviewer and customer CI identities are denied (INT-6, AGT-2). Suite revisions
  are versioned separately from intent, and a public regression PR leaks nothing (INT-7). Scenario review against the exact
  intent revision, with QE-only corrections (INT-9).
- **WI-22** An owner-approved contract authorizes a narrow class of unflagged fixes, and QE records the report, callers,
  expected correction and the matching authorization. A visible reproducer must be red on the baseline and green on the
  candidate. Anything broader needs reclassification or a switch.
- **WI-23** Detect OpenFeature manifests and flagd config, and make new switches default off (FLG-2). Record switch
  identity, owner, age, default and qualification status, and show them on GitHub (FLG-3).

## Phase 5: Acceptance, Union and recovery

| WI | Work item | Requirement IDs | Depends on | Status |
| --- | --- | --- | --- | --- |
| WI-24 | Acceptance runner and repair loop | PIP-3, PIP-15, SEC-11 (leak test) | WI-18, WI-20, WI-21 | todo |
| WI-25 | Candidate manifest | PIP-14 | WI-03, WI-23 | todo |
| WI-26 | Train scheduling and configuration matrix | PIP-5, PIP-11, PIP-10 | WI-25, WI-18 | todo |
| WI-27 | Recovery and line stop | REC-1, REC-2, REC-3, REC-4 | WI-26 | todo |

- **WI-24** Runs only on a complete plan with every PR merged through Verify. It records the candidate SHA, artifact
  digest, switch config, suite and intent revisions and per-scenario results (PIP-3). A failure keeps the feature dark,
  returns only redacted feedback, freezes the suite revision and caps repairs (PIP-15).
- **WI-25** An immutable manifest pins the source commit, verified artifact digest, policy revision, release defaults,
  complete flag values and dependencies. Changing any pinned input invalidates qualification.
- **WI-26** Release defaults, all-on, all-off and the exact proposed configuration, with shared evidence for identical
  configurations (PIP-5). Daily cadence, root-contract override, a floor of twice the last run time, and skipping empty
  trains (PIP-11). Serialize overlapping hand-written files and shared non-switchable artifacts, both at plan time and per diff (PIP-10).
  From WI-07: add a train cadence field to the install schema (PIP-11).
- **WI-27** Qualify the replacement manifest before ejecting (REC-1). Unflagged work recovers through a verified
  inverse or an eligible source revision (REC-2). Inverse repairs are capped (REC-3). Stop the train and page the owner when
  recovery can't produce a passing candidate (REC-4).

## Phase 6: runtime and agents

| WI | Work item | Requirement IDs | Depends on | Status |
| --- | --- | --- | --- | --- |
| WI-28 | Runtime interface and kagent adapter | RUN-8, RUN-2, RUN-5 | WI-07, WI-05 | todo |
| WI-29 | Install manifest, pinning, BOM and preflight | RUN-1, RUN-9, NFR-8 | WI-07 | todo |
| WI-30 | Egress, credentials and least privilege | RUN-3, RUN-4, SEC-1, SEC-2, SEC-3 | WI-28, WI-12 | todo |
| WI-31 | Coding harness launcher and inner loop | SEC-9, AGT-1, AGT-8, RUN-10 (headless) | WI-28 | todo |
| WI-32 | Agent catalog and role qualification suite | AGD-1, AGD-3, AGT-7, NFR-2, INT-2, CON-10 (drafting) | WI-28, WI-31 | todo |

- **WI-28** `internal/runtime` interface. Only `internal/runtime/kagent` imports kagent (RUN-8, enforced by depguard).
  Sessions run in Agent Substrate sandboxes, never in plain containers (RUN-2). Workload identity reaches the audit log (RUN-5).
  AGT-6 completeness lives here and in WI-30/31: every tool call (MCP via agentgateway), model call and repo write emits
  one audit entry with the session's workload identity and its change subject once the change exists. Test it with a fake
  session that makes one of each and asserts exactly three entries.
  From WI-07: call Config.Admit right before scheduling every session, and treat any non-nil result as a denial. Audit role, tuple digest, record digest and install revision. Launch exactly the Role() profile, and refuse a running image that differs from it. Build a content-addressed QualificationStore over the offline bundle.
- **WI-29** Templates, harnesses and the install manifest live in git, pinned by digest. Validate against an
  offline mirror (RUN-1). Preflight names each unmet prerequisite (RUN-9). A BOM covers every component (NFR-8).
  From WI-07: resolve and verify deploymentManifest and every profile digest against the offline mirror. Preflight runs Admit for every enabled role (RUN-9). Put the install revision and qualification records in the BOM (NFR-8).
- **WI-30** agentgateway deny-by-default egress per role, with blocked calls logged (RUN-3). Credentials are injected at egress,
  and a secret scan of a running sandbox finds none (RUN-4). No agent token can merge or push to protected branches (SEC-2).
  Reviewers are read-only (SEC-3).
  From WI-08: enforce PushPolicy on the real write path. Coder credentials never carry the `workflows` scope. Evaluate the deny paths over the diff from the trusted base, never over the listed paths, and require descent from that base. The trusted base must be the base branch head or reachable from it. Push-triggered workflows on `factory/*` with secrets need CI-side controls.
  From WI-07: enforce egress exactly as Role().Egress.Hosts. Inject gateway credentials only for their exact host and METHOD /path, and never percent-decode. Deny at the gateway any hostname that resolves to link-local, loopback or unspecified addresses. Define a closed tool-permission vocabulary and reject write or merge permissions on reviewer roles (SEC-3) and on protected branches (SEC-2).
- **WI-31** Bare-mode Claude Code and factory-supplied Codex config. A fixture checkout plants hooks, MCP config and
  settings, and the test asserts none of them load (SEC-9). Inner-loop results are never gate results (AGT-1). A recipe is
  accepted only after it reproduces a green CI result, with CI as the fallback (AGT-8).
- **WI-32** Templates for the v1 roles (AGD-1). Pinned profiles per role (AGT-7). A qualification suite with
  positive and negative fixtures per role (NFR-2). Rubber-duck refinement (INT-2) and the onboarder's draft (CON-10).
  From WI-09: CODEOWNERS parsing fails closed, so one bad line removes every owner. The onboarder must report CODEOWNERS parse errors as a blocker.
  From WI-07: decide whether qualification records expire and which suiteRevisions are acceptable. Write positive and negative fixtures per role. Use installtest.NewSigner. When the catalog names the coding role, require the two baseline reviewer roles to be distinct from it (AGD-3 independence, AGT-2).

## Phase 7: cost, operations and security regression

| WI | Work item | Requirement IDs | Depends on | Status |
| --- | --- | --- | --- | --- |
| WI-33 | Quotas and CI rate limits | COST-2, COST-3 | WI-07, WI-10 | todo |
| WI-34 | Circuit and progress breakers | COST-4, COST-7 | WI-18 | todo |
| WI-35 | Cost accounting | COST-1, COST-5 | WI-20, WI-28 | todo |
| WI-36 | Halt and resume | SEC-6 | WI-06, WI-10 | todo |
| WI-37 | Security regression suite | SEC-11 | WI-06, WI-13, WI-21, WI-24, WI-36 | todo |

- **WI-33** Over-quota work queues and doesn't start (COST-2). A per-PR hourly cap on gate-of-record runs (COST-3).
  From WI-07: charge quotas by stable team ID, with DefaultTeam for unlisted teams and CI runs counted per (repo ID, PR). Define which team a change charges. Queue work over quota, and use an injected clock. Test with non-default parsed values.
- **WI-34** Stop after N consecutive failures of the same gate (COST-4). Stop after 5 iterations with no newly passing gate,
  or spend past 5× the estimate (COST-7).
  From WI-07 (applies to WI-15, WI-20, WI-24 and WI-27 too): read Timers() from a parsed config. Tests must use non-default values. SpendOverEstimateFactor is an integer.
- **WI-35** Estimated versus actual cost on the issue, notifying without pausing (COST-1). Tokens, GPU time and CI
  minutes per feature, including failed attempts. Team and train totals reconcile (COST-5).
- **WI-36** Only a current admin halts or resumes. A halt fences sessions, queued actions and merges. A resume
  binds to the halt revision, and replays are denied and logged.
  From WI-06: use `OpHalt` and `OpResume` (role admin, install scope, subject = InstallID). The halt generation is a unique digest, so a resume for H1 that arrives after H2 is stale. Define what a halt binds to. Tests: a revoked former admin is denied for both halt and resume, and a replayed resume is denied and logged.
  From WI-07: admins come only from the active revision's RoleSource, built per execution. "Revoked" means removed in a newly activated revision. Test: an admin halts at revision 1, is removed at revision 2, and their resume is denied.
- **WI-37** One integration suite on every control-plane change. It denies a forged approval, a stale owner
  approval, an unauthorized resume, a same-name foreign check and coder access to a private fixture, finds no leak
  in published Acceptance output, and lets a matching authorized approval succeed.
  From WI-06: lift the unit SEC-11 cases (forged approval, stale owner approval, unauthorized resume, matching approval succeeds) into this suite, run against the real forge fake, store and CODEOWNERS source.

## Phase 8: qualification

| WI | Work item | Requirement IDs | Depends on | Status |
| --- | --- | --- | --- | --- |
| WI-38 | Milestone A: hosted vertical slice on the OTel Demo fork | INTG-1, RUN-10, NFR-9, PIP-1 | all above | todo |
| WI-39 | Milestone B: `ghes-local-v1` disconnected qualification | NFR-1, NFR-3, NFR-8, RUN-10, NFR-2 | WI-38 | todo |
| —     | DCO and license | NFR-7 | — | done (56015e7) |

- **WI-38** The scripted scenarios from PRD "V1 scope", section A: flag-off guard, forced Acceptance failure and repair, a
  failed revert with a line stop, and the A-alone interaction refused and then repaired. Scale targets of 10 sessions and 20 PRs a day (NFR-9).
- **WI-39** A clean install with external routes denied, two full runs through Union, retained flow evidence and
  the BOM, and a role qualification record for each enabled role.

## Notes

- **NFR-7** was satisfied by the tooling commit: Apache-2.0 `LICENSE`, the DCO commit-msg hook and the CI check.
- **Infrastructure-bound items** (WI-28 to WI-32, WI-38, WI-39) need a Kubernetes cluster with kagent, Agent
  Substrate and agentgateway. Their code and unit tests can be written against fakes. Their acceptance evidence
  cannot be produced offline in this repo's `make check`.
- **Known limitation (WI-02):** `contract.Load` gathers every problem before applying the 100-problem cap. The
  worst case is 1000 files of 64 KiB, so memory is bounded but generous. Contract files are protected paths that
  only trusted committers can add (CON-6). Revisit if loading ever runs on untrusted trees.
- **Later-phase IDs** (RUN-7, AGD-2/4/5, INT-13/22, PIP-6/7/8/12, FLG-4–7, REC-5, SEC-7/8, COST-6, POR-*,
  INTG-2–4, NFR-10) are out of scope. Where v1 types should leave room for them (such as release stages in the
  manifest), the item notes it rather than building it.
