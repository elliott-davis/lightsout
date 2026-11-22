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
| WI-01 | Path globs | CON-7, CON-12 (support) | — | in progress |
| WI-02 | Contract schema, parsing and discovery | CON-11, CON-4, CON-1 | — | in progress |
| WI-03 | Effective contract resolver and relational validation | CON-3, CON-5, CON-7, CON-9, CON-12, AGD-3, SEC-5 | WI-01, WI-02 | todo |
| WI-04 | Incremental validation, explain, gate registry check, CLI | CON-13, CON-4 | WI-03 | todo |
| WI-05 | Append-only audit log | NFR-4, RUN-5, AGT-6 | — | todo |
| WI-06 | Identities, roles and revision-bound decisions | SEC-10, NFR-5 | WI-05 | todo |
| WI-07 | Install config, role profiles and admission | RUN-6, AGT-7, NFR-2, SEC-1, CON-9, CON-5 | WI-03 | todo |

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
- **WI-04** Incremental validation of a contract with its ancestors and descendants; an explain command
  that shows each effective value and its source (CON-13); registered-identity and revision check against a consumer-defined registry (CON-4).
- **WI-05** `internal/audit`: an append-only interface with no update or delete, hash-chained entries, and an actor workload
  identity, template version and change ID on every entry. In-memory and file-backed stores first; PostgreSQL arrives with WI-10.
- **WI-06** `internal/authz`: forge identity, role, scope (repo or install) and the exact revision or digest a
  decision binds to. It rechecks at execution against a current role source, and rejects edited, copied, quoted, bot,
  stale, revoked and cross-repo decisions. Every decision, granted or denied, is audited. Negative tests per SEC-11.
- **WI-07** `internal/install`: install config with defaults for timers and caps (AGT-5, INT-15, PIP-15, REC-3, COST-2/3/4/7),
  the factory baseline gates (SEC-4 identities) and core reviewers, one pinned runtime, harness and model profile per enabled
  role (RUN-6, AGT-7), and a qualification record check that runs before admission (NFR-2 data). Validation fails any role
  that combines untrusted input, secrets and open egress (SEC-1).

## Phase 2: forge boundary and control-plane state

| WI | Work item | Requirement IDs | Depends on | Status |
| --- | --- | --- | --- | --- |
| WI-08 | Forge interface and in-memory fake | INTG-1 (interface) | WI-06 | todo |
| WI-09 | CODEOWNERS ownership resolution | CON-2 (ownership) | WI-08 | todo |
| WI-10 | State store and event loop | NFR-5 (event paths), NFR-4 (durable store) | WI-05, WI-08 | todo |
| WI-11 | Contract activation and protected policy path | CON-2, CON-6, CON-10 (review path) | WI-04, WI-06, WI-09, WI-10 | todo |
| WI-12 | GitHub adapter | INTG-1 | WI-08 | todo |

- **WI-08** `internal/forge`: issues and comments with authenticated authors and edit state; issue types and
  `type:` labels; sub-issues; content and tree at a revision; check runs with producer and workflow identity; merge
  queue groups; and branch push scoped to one identity. The fake is the test double for everything below.
  Includes a read-only `fs.FS` over a git tree at a commit, which is the only input `contract.Load` may be given in
  production. Adapters must `url.PathEscape` gate identity values (`workflowId`, `checkId`) when building API paths.
- **WI-09** Parse CODEOWNERS (gitignore semantics) at a trusted revision and resolve each path's current owners.
- **WI-10** PostgreSQL-backed state for issues, changes, features and trains; idempotent webhook ingestion with
  signature checks; one authorization path for issue events, checks, callbacks, API and admin actions (NFR-5).
- **WI-11** Activation of a contract revision requires approval of that exact revision by a current owner,
  under the previously trusted ownership and gate rules. A product change can never supply the policy that
  authorizes it (CON-2). Protected paths (contracts, CI definitions, CODEOWNERS) fail a product PR, and a protected
  proposal is evaluated under the current trusted policy (CON-6). An onboarder draft goes through the same path (CON-10).
  Protected-path matching case-folds, so a product PR can't add `x/.Factory.yaml`. That would fail every later
  contract load closed.
- **WI-12** `internal/forge/github`: go-github implementation of WI-08, GitHub App auth, issue types, Checks
  publishing and the merge queue. Contract tests run the same suite against the fake and against recorded fixtures.

## Phase 3: Verify

| WI | Work item | Requirement IDs | Depends on | Status |
| --- | --- | --- | --- | --- |
| WI-13 | Gate-of-record evaluation | PIP-2, CON-4 (execution match), SEC-11 (foreign check) | WI-03, WI-08 | todo |
| WI-14 | Path, protected-path and PR shape gates | CON-7, CON-6, INT-18, INT-19 | WI-11 | todo |
| WI-15 | Review policy and evidence rule | AGT-3, AGT-4, AGT-5, SEC-5, AGD-3, CON-8, INT-20 | WI-03, WI-06 | todo |
| WI-16 | Dark-merge oracle evaluation | PIP-13, PIP-4, INT-10 (comparison) | WI-13 | todo |
| WI-17 | Non-switchable changes | PIP-9 | WI-14, WI-15 | todo |
| WI-18 | Verify orchestrator and merge | PIP-1, PIP-2, SEC-2, SEC-4, NFR-6 | WI-13–WI-17, WI-10 | todo |

- **WI-13** Every mandatory gate needs an execution record with its trusted producer, workflow identity, pinned
  revision, job identity, merge-group SHA, actual execution and explicit success. Skipped, neutral, missing, stale,
  foreign and same-name results block. A new queue head invalidates earlier results.
- **WI-14** A change outside writable paths fails unless it touches only read-only paths and a path owner approves (CON-7).
  A change that mixes writable and read-only paths fails.
  A product PR that touches a protected path fails (CON-6). Shape rules fail with their gate ID (INT-18). The soft
  review budget counts hand-written lines only, and detects generated files from linguist attributes, DO NOT EDIT
  headers and contract paths, and compares the total against the smallest budget that applies (INT-19). The shape
  rules don't trust contract-declared `generated` paths alone.
- **WI-15** Reviewer context excludes coder reasoning and holdouts (AGT-3). Provisional blocks carry location,
  invariant, consequence and verification plan, with confirmation or dismissal on evidence (AGT-4, P4). A round cap
  escalates to an owner (AGT-5). Sensitive paths need security signoff (SEC-5). Lights-on needs current owner
  approval of the exact change, impact and recovery plan (CON-8). A split request becomes a replan request (INT-20).
- **WI-16** Compare baseline and merge-group candidate on responses, reads, writes, events and queued jobs. Dark
  features and Tasks require equivalence (PIP-4). An authorized Fix permits only its delta (INT-10). Record both
  SHAs, configs, the oracle revision and the result.
- **WI-17** Declared effects, affected callers, rollout order, recovery steps and owner approval of the exact revision.
  An errant flag-off side effect blocks. Expand and contract run as separate trains.
- **WI-18** The control plane alone merges, through the queue (SEC-2). Secret and dependency scans are mandatory
  baseline gates (SEC-4). Every agent commit carries the contract's trailer (NFR-6). Issues and Checks show the stage
  and disposition (PIP-1).

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
- **WI-29** Templates, harnesses and the install manifest live in git, pinned by digest. Validate against an
  offline mirror (RUN-1). Preflight names each unmet prerequisite (RUN-9). A BOM covers every component (NFR-8).
- **WI-30** agentgateway deny-by-default egress per role, with blocked calls logged (RUN-3). Credentials are injected at egress,
  and a secret scan of a running sandbox finds none (RUN-4). No agent token can merge or push to protected branches (SEC-2).
  Reviewers are read-only (SEC-3).
- **WI-31** Bare-mode Claude Code and factory-supplied Codex config. A fixture checkout plants hooks, MCP config and
  settings, and the test asserts none of them load (SEC-9). Inner-loop results are never gate results (AGT-1). A recipe is
  accepted only after it reproduces a green CI result, with CI as the fallback (AGT-8).
- **WI-32** Templates for the v1 roles (AGD-1). Pinned profiles per role (AGT-7). A qualification suite with
  positive and negative fixtures per role (NFR-2). Rubber-duck refinement (INT-2) and the onboarder's draft (CON-10).

## Phase 7: cost, operations and security regression

| WI | Work item | Requirement IDs | Depends on | Status |
| --- | --- | --- | --- | --- |
| WI-33 | Quotas and CI rate limits | COST-2, COST-3 | WI-07, WI-10 | todo |
| WI-34 | Circuit and progress breakers | COST-4, COST-7 | WI-18 | todo |
| WI-35 | Cost accounting | COST-1, COST-5 | WI-20, WI-28 | todo |
| WI-36 | Halt and resume | SEC-6 | WI-06, WI-10 | todo |
| WI-37 | Security regression suite | SEC-11 | WI-06, WI-13, WI-21, WI-24, WI-36 | todo |

- **WI-33** Over-quota work queues and doesn't start (COST-2). A per-PR hourly cap on gate-of-record runs (COST-3).
- **WI-34** Stop after N consecutive failures of the same gate (COST-4). Stop after 5 iterations with no newly passing gate,
  or spend past 5× the estimate (COST-7).
- **WI-35** Estimated versus actual cost on the issue, notifying without pausing (COST-1). Tokens, GPU time and CI
  minutes per feature, including failed attempts. Team and train totals reconcile (COST-5).
- **WI-36** Only a current admin halts or resumes. A halt fences sessions, queued actions and merges. A resume
  binds to the halt revision, and replays are denied and logged.
- **WI-37** One integration suite on every control-plane change. It denies a forged approval, a stale owner
  approval, an unauthorized resume, a same-name foreign check and coder access to a private fixture, finds no leak
  in published Acceptance output, and lets a matching authorized approval succeed.

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
- **Later-phase IDs** (RUN-7, AGD-2/4/5, INT-13/22, PIP-6/7/8/12, FLG-4–7, REC-5, SEC-7/8, COST-6, POR-*,
  INTG-2–4, NFR-10) are out of scope. Where v1 types should leave room for them (such as release stages in the
  manifest), the item notes it rather than building it.
