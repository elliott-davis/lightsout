# Dark AI Software Factory — PRD v0.1

Nov 21, 2026 · @Elliott

## Overview

The factory turns an idea from a PM or engineer into merged, tested code using the enterprise's own repos, CI and processes. Features merge behind a switch that defaults to off. Humans approve intent, own exceptions and authorize release.

The factory is open source and designed for on-prem installations. V1 first proves one Feature from a GitHub issue through a green Union train on the OpenTelemetry Demo fork. GitHub Issues carry decisions and GitHub Checks report gates. A separate disconnected run qualifies the on-prem path before v1 is complete.

**Problems it solves**

1. **Engineers retrofit agents onto old process.** They bolt agentic tools onto existing workflows and get little out of them.
2. **PMs build misaligned prototypes.** With Claude or Codex they get a PoC that ignores the codebase at best, and at worst something functional enough to be dangerous that skips engineering best practice.
3. **Enterprises fear AI.** They restrict which tools and code models may touch, so they need something on-prem, inspectable and governed.

**Document conventions.** Requirement IDs (`CON-3`, `PIP-5`) are stable and meant to be parsed. Each requirement has testable acceptance criteria and a phase (`v1` or `later`), so the spec can be broken down into work items automatically.

## Goals and non-goals

**Goals**

| ID | Goal |
| --- | --- |
| G1 | An approved Feature can reach a green train without a human writing or reading code when the contract permits automated review. |
| G2 | Every change passes the team's existing gates plus the factory's mandatory gates. No agent can waive one. |
| G3 | An authorized PM or RM decides whether to release the exact candidate tested in Rehearsal. |
| G4 | Complete an on-prem run with external routes disabled and an install-qualified model and harness for each role. |
| G5 | Adapt to existing tools. V1 uses GitHub Issues, Actions and Checks. GitLab, Jenkins and Jira integrations come later. |

**Non-goals**

- Replacing the forge, the CI system or the issue tracker.
- Defining build commands or build pipelines. The factory owns promotion, the customer's CI owns builds (the lesson from Chef Delivery).
- Deploying to or operating production. For on-prem software, Delivered means a release artifact.
- Building test beds for repos that don't have one (v1).
- Contributing to upstream projects.

## Users and roles

From v1, the control plane verifies each human decision against the authenticated forge identity and the role authorized for that action. It records the actor, role, decision and exact revision approved. Editing the approved content requires fresh approval. A bot comment, a quoted approval or an approval for an older revision cannot advance the work.

| Role | Who | Responsibilities |
| --- | --- | --- |
| Ideator | PM or engineer | Submits ideas, confirms the classification (Feature, Task or Fix), decides splits, approves the revision of the public acceptance scenarios and watches progress. |
| PM / RM | Product or release manager | In later Rehearsal and Delivered, authorizes the tested release manifest or rejects it with a reason. |
| Contract owner | Team or sub-team, via CODEOWNERS | Approves contract revisions for its paths, chooses lights-on mode and handles escalations. |
| Enterprise IT | Platform or central IT team | Installs the factory, connects integrations, qualifies role profiles and sets install-wide defaults. |
| Agents | Factory | Refine ideas, plan, implement, review and recover changes. Product advice and post-Delivered cleanup come later. |

## Design principles

When two requirements conflict, these decide.

1. **P1 Adapt, don't replace.** The factory runs on top of the team's forge, CI, tracker and conventions. Chef Delivery failed because it forced every pipeline into Chef code.
2. **P2 Dark by default.** Verify compares a Feature's observable behavior with its switch off against the queue baseline. Releasing a feature is a separate, human decision.
3. **P3 Independence over inspection.** Publish the approved behavior. Keep executable holdouts and private cases, fixtures and assertions isolated from implementers and PR reviewers. Independent reviewers and mandatory gates enforce the contract.
4. **P4 Evidence for blockers.** A confirmed blocker cites a failing check or a violated gate with supporting evidence. A reviewer who spots a credible untested failure can block provisionally by naming the invariant, location, consequence and verification plan. An independent verifier records confirmation or dismissal with evidence. An unresolved blocker escalates at the review cap.
5. **P5 Ownership follows the code.** Contracts layer like CODEOWNERS. A lower level can tighten what's above it, never loosen it.
6. **P6 Bound recovery.** Retry within the recovery cap. If a failed revert leaves the candidate unsafe, stop promotion and page the owner with the failed checks and attempted repairs.
7. **P7 Open source first.** Enterprises that fear AI trust code they can inspect.

## Core concepts

Intake prepares the work. The promotion pipeline then tests successively larger units. The immutable Union candidate manifest pins the source commit, customer CI artifact digest, effective policy revision, release defaults, complete resolved flag values and dependencies. Changing any of these creates a new candidate that must pass its applicable checks.

1. **Intake** (idea) → approved behavior, spec, private executable scenarios and PR plan.
2. **Verify** (one PR) → independent review and gates against the merge-queue candidate, including comparison with the queue baseline under the same release defaults and the new switch off.
3. **Acceptance** (one complete Feature) → run private holdouts with its switch on. On failure, keep the switch off by default, return a redacted failure to the repair loop and rerun Verify and Acceptance on the revised candidate. Escalate to the owner at the recovery cap.
4. **Union** (scheduled train) → run smoke and contract gates on the CI artifact with release defaults, with all newly accepted switches on, with them all off, and with the exact proposed full configuration. Record results against each configuration. Bisect failures and eject a culprit only after verifying the recovered candidate.
5. **Rehearsal** (later, release candidate) → test the exact proposed release defaults. A PM or RM authorizes the tested manifest. A rejection records a reason and returns the feature to Intake.
6. **Delivered** (later, release artifact) → produce the release bound to the authorized manifest. A changed artifact or flag configuration requires new tests and authorization.

| Term | Meaning |
| --- | --- |
| Contract | Opt-in config at any directory level. It maps factory stages to existing CI checks, declares writable and forbidden paths, and sets overrides. It contains no build commands. |
| Effective contract | The stack of contracts along every path a change touches. Lower levels can only tighten. |
| Install config | Install-wide defaults owned by IT, including qualified runtime profiles, integrations and timers. |
| Gate of record | A required check from the trusted producer named in policy for that stage and candidate. Customer CI supplies the mapped repo checks. The factory-owned Acceptance runner supplies holdout results. |
| Inner loop | The coding agent's local build and test, worked out from the repo, best effort. It never counts as a gate. |
| Feature switch | A runtime flag. Its ID identifies the feature and every PR in the feature references it. |
| Change | One PR. The unit of Verify. |
| Feature | All the PRs behind one switch. The unit of Acceptance. |
| Task | An unflagged, behavior-preserving change. It skips Acceptance only when unchanged checks and queue-candidate comparisons support that claim. Non-switchable changes also follow PIP-9 and owner policy. |
| Fix | A narrowly scoped correction with a public reproducer. An unflagged Fix skips Acceptance only if policy permits it, the reproducer fails on the baseline and passes on the queue candidate, and comparisons bound the observable difference to the approved correction. |
| Train | A scheduled batch of accepted Features and verified Tasks and Fixes. The unit of Union. |
| Release candidate | The immutable candidate manifest and corresponding CI artifact tested in Rehearsal. |
| Lights-on mode | A per-contract setting that requires human PR review in that area. |

Work that cannot satisfy the unflagged criteria must be replanned as a switched Feature where possible. Schema, API, configuration, dependency and other changes a switch cannot hide require PIP-9 and the effective owner's policy regardless of classification.

## Agent runtime and definitions

The reference stack uses kagent resources, Agent Substrate sandboxes and agentgateway. The install records one qualified runtime, harness and model profile for each enabled role. Profiles may share components. Additional profiles require role-specific qualification.

- **kagent** defines a role's AgentTemplate and Harness. An Agent pairs them and a Session is one running conversation. [kagent](https://kagent.dev/)
- **Agent Substrate** runs each Session as an Actor in its own gVisor or microVM sandbox. Later, the factory can suspend idle sessions while CI runs. [Agent Substrate](https://docs.cloud.google.com/kubernetes-engine/ai-ml/about-agent-substrate)
- **agentgateway** brokers model, MCP and A2A traffic, enforces per-role egress and injects credentials at the boundary. The install must demonstrate isolation with its pinned versions. [kagent 1.0](https://www.solo.io/blog/announcing-kagent-1-0-ga) · [agentgateway](https://agentgateway.dev/docs/standalone/latest/faqs/)
- **Factory control plane** verifies decisions and requests merges through the queue. Its merge identity is unavailable to agent sessions.

**How factory concepts map onto the runtime**

| Factory concept | Runtime construct |
| --- | --- |
| Agent role, prompt, model, tools, skills | kagent AgentTemplate |
| Execution engine, image, worker pool | kagent Harness |
| One agent working on one change | kagent Agent and sandboxed Session on Agent Substrate |
| Access to forge, CI, tracker | MCP servers behind agentgateway |
| Allowed agent-to-agent messages | A2A through agentgateway with role-specific routing and context limits |
| Credentials | Injected at egress by agentgateway |
| Network limits per role | EgressPolicy, deny by default |
| Model choice per role | Pinned, qualified profile routed through agentgateway |

### Runtime (RUN)

| ID | Requirement | Acceptance criteria | Phase |
| --- | --- | --- | --- |
| RUN-1 | Version AgentTemplates, harnesses and the install manifest in git. Pin runtime dependencies, images, templates, tools and model revisions and mirror the inputs needed offline. | A fresh install resolves the recorded revisions and digests from the mirror. Missing or mismatched inputs fail validation. | v1 |
| RUN-2 | Agents run on Agent Substrate, each session in its own gVisor or microVM sandbox. | No agent session runs in a plain container. | v1 |
| RUN-3 | All model, MCP and A2A traffic goes through agentgateway, with deny-by-default egress per role. | A sandbox call to a host outside its policy is blocked and logged. | v1 |
| RUN-4 | Credentials are injected at egress. Sandboxes never hold integration or model credentials. | A secret scan of a running sandbox's filesystem and environment finds no integration or model credentials. | v1 |
| RUN-5 | Every agent action carries the actor's workload identity in the audit log. | Each audit entry names the actor identity and the template version. | v1 |
| RUN-6 | Enable one pinned runtime, harness and model profile per role per install. | Every enabled role passes its representative task with its assigned tools and permissions. An unqualified substitution is rejected. | v1 |
| RUN-7 | A coding session can be suspended while CI runs and resumed with its context when results arrive. | A resumed session continues the same change without re-reading the repo from scratch. | later |
| RUN-8 | The factory reaches the reference runtime through a thin adapter. A fallback implementation is later work. | No factory code outside the adapter depends on kagent types. | v1 |
| RUN-9 | Preflight checks the Kubernetes version and served APIs required by the pinned runtime, the configured sandbox pool, identity issuance and KVM where microVMs require it. | Installation stops with a named failure for each unmet prerequisite. The installed runtime starts an isolated session with a verifiable identity. | v1 |
| RUN-10 | Run the coding harness headlessly. Qualify the exact harness and endpoint using the fork's coding task, tool calls and gate handoff. Qualify the disconnected install with a local model and mirrored inputs before declaring v1 complete. | Record profile versions, task results and network evidence. With external routes disabled, the install completes the Feature through Union using local forge, CI, registry and model services. A hosted run counts only toward development qualification. | v1 |

### Agent definitions and catalog (AGD)

The v1 catalog provides the roles needed for the fork. The PR reviewer and security reviewer independently review every v1 PR in separate contexts. A change to a sensitive path requires explicit security signoff. The PM advisory, switch janitor and custom agents are later additions.

| Agent | Stage | What it does | Can block? |
| --- | --- | --- | --- |
| Rubber duck | Intake | Guides the ideator in the issue, sharpens the idea, surfaces duplicate and conflicting work, proposes splits and explains refusals. | No |
| Spec writer | Intake | Writes the spec and the PR plan against the approved scenarios. | No |
| Coder | Verify, repair | Implements one PR in a coding harness and repairs failures from bounded, redacted feedback. | No |
| PR reviewer | Verify | Reviews the spec and diff for correctness against approved behavior, test coverage and regression risk. | Yes, under P4 |
| Security reviewer | Verify | Reviews authorization, injection, secrets and unsafe dependencies, and triages SAST findings. Explicitly signs off on changes to sensitive paths. | Yes, under P4 |
| Product manager | Acceptance (later) | Checks the feature against the spec and approved behavior with the switch on. | No (advisory) |
| Train conductor | Union | Runs the train, isolates failing configurations and requests verified reverts for Tasks and Fixes. Stops promotion and pages on failed recovery. | Yes, stops the train |
| Switch janitor | After Delivered (later) | Removes stale switches and proposes removing abandoned features. | No |
| Contract onboarder | Onboarding | Reads a repo's CI and conventions and proposes its first contract to the owner. | No |
| QE agent | Intake, Acceptance | Authors public behavior for approval, binds it to private executable holdouts, and reports sanitized results. After Acceptance, writes a separate regression test from approved public behavior and publishes it following review for holdout disclosure. The executable holdout, private fixtures, cases and assertions stay in the holdout store. | No |
| Scenario reviewer | Intake | Checks private executable coverage against the exact approved behavior revision. | Yes, under P4 |

| ID | Requirement | Acceptance criteria | Phase |
| --- | --- | --- | --- |
| AGD-1 | Ship the v1 roles above as ready-made templates. | A fresh qualified install can take a fork issue through a green train with two independent reviewer roles on every PR using only catalog agents. | v1 |
| AGD-2 | Teams can define custom agents with their own prompts, skills and MCP tools. | A custom template registered in git appears in the catalog and can be used by a contract after qualification. | later |
| AGD-3 | Contracts can add checks or specialist reviews for sensitive paths. The PR reviewer and security reviewer form the minimum for every v1 PR. | A child contract can add a specialist. Policy validation rejects an attempt to remove either core review or waive security signoff on a sensitive path. | v1 |
| AGD-4 | Custom agents get the same guardrails as catalog agents. | No custom template can receive merge rights, contract write access, holdout access outside its assigned role, or a waiver of the evidence rule. | later |
| AGD-5 | Agent templates and skills are packaged as versioned OCI artifacts so air-gapped installs can mirror them through a registry such as Harbor. | A template can be installed from a private registry with no internet access. | later |

## Functional requirements

Agent runtime and definitions appear above. Each row gives a work item’s ID, requirement, testable criteria and phase.

### Intake and classification (INT)

Intake works like a factory's receiving dock. An idea arrives, agents unload and refine it, and the ideator approves the acceptance scenarios before any spec, plan or code exists. Tasks have no scenarios. A fix carries one visible scenario that reproduces the bug instead.

1. **Arrive.** The ideator opens a GitHub issue.
2. **Refine.** The rubber duck guides the ideator in the issue thread. It questions them, checks the idea against current code and in-flight and backlog issues, proposes a split if the idea is too big, and refuses with a reason if it can't be built.
3. **Classify.** The agent proposes Feature, Task or Fix; the ideator confirms.
4. **Approve scenarios (features only).** The QE agent writes plain-language acceptance scenarios, and the ideator approves them. A rejection goes back to Refine with the ideator's comment.
5. **Spec and plan.** The spec writer writes the spec and PR plan against the approved scenarios, and mints the switch ID for a feature.
6. **Hand off.** For features, the QE agent binds the approved intent to private executable tests in the holdout store, the scenario reviewer checks them against the approved text, the spec is committed, and the first coding run starts.

| ID | Requirement | Acceptance criteria | Phase |
| --- | --- | --- | --- |
| INT-1 | An ideator can submit and refine an idea in a GitHub issue. | An issue records the Intake state, versioned proposals and authenticated decisions. GitHub Checks link the subsequent gate results. | v1 |
| INT-2 | The rubber duck guides the ideator, refining the idea against the current code and the in-flight and backlog work. | The refined idea lists affected paths, plus any duplicate or conflicting issues with links. | v1 |
| INT-3 | Each idea is classified as Feature, Task or Fix and recorded as the issue's type. | The agent proposes a type and the ideator confirms it before work starts. GitHub's Feature, Task and Bug issue types map to Feature, Task and Fix; repos without issue types use a `type:` label. | v1 |
| INT-4 | For a feature, the QE agent writes plain-language acceptance scenarios right after refinement, and the ideator approves them before a spec or PR plan exists. | No spec or coding run starts on a feature without ideator-approved scenarios. Rejected scenarios return to refinement with the ideator's comment. | v1 |
| INT-5 | The spec writer commits the spec and PR plan under a factory path keyed by switch ID for features or issue ID for unflagged work. | Before coding, a feature spec links the exact approved scenario revision and each planned PR to the spec items it covers. | v1 |
| INT-6 | Approved Given/When/Then intent is readable on the issue. Executables, additional private cases, fixtures and assertions stay in a factory-owned holdout store. | Only QE and the scenario reviewer can inspect the suite. A noninteractive factory Acceptance runner gets read-only access scoped to one run and suite revision. Coder, PR reviewer and customer CI identities cannot read it. | v1 |
| INT-7 | QE versions the private suite separately from its approved intent. After success it proposes a separately reviewed public regression test through Verify. | The regression PR exposes no private cases or fixtures. Before requalification, QE retains or adds fresh private coverage. Its review and run reference immutable suite and intent revisions. | v1 |
| INT-8 | Intake has no human gate other than the ideator. Code owners shape what agents may do only through contracts, and are paged on escalation. | No intake step waits on a contract owner's approval. | v1 |
| INT-9 | The scenario reviewer checks each private suite revision against the exact ideator-approved intent. A mismatch blocks hand-off by public scenario ID. | Changing intent requires renewed ideator approval. Only QE may propose a private test correction, in a separate versioned change with independent scenario review. Preserve the original failure, link the reason for correction, and rerun Acceptance. Coding actors cannot write the suite. | v1 |
| INT-10 | An unflagged Fix skips Acceptance only for the correction explicitly authorized under INT-17. A contract can require a switch. | The visible regression test fails on the queue baseline and passes on the candidate. The PIP-13 comparison preserves behavior outside the authorized delta. A broader change requires reclassification or a switch before merge. | v1 |
| INT-11 | When an idea is too big for one switch, the rubber duck proposes a split, and the ideator decides. | Each child the ideator keeps becomes its own feature with its own switch, linked as a sub-issue of the original idea. | v1 |
| INT-12 | When an idea can't be built, the rubber duck refuses it with a reason on the issue and says what would unblock it. | Reasons cover at least: no contract covers the paths, it needs forbidden paths, or it spans more than one repo (v1). | v1 |
| INT-13 | At Acceptance the ideator can see additional sanitized evidence for each public scenario, such as a video or screenshots. | Evidence omits private inputs, assertions and fixtures. Looking at it is optional. | later |
| INT-14 | The feature PR plan is a dependency graph. Its first PR adds the switch, off, plus scaffolding. Each PR cites its spec items and passes PIP-13 or takes the PIP-9 exception. | Independent PRs can be coded in parallel in separate sessions within COST-2. No feature PR inherits dark-merge evidence from another. | v1 |
| INT-15 | Only the spec writer edits a plan. Coders and reviewers can ask it to split a PR or add work. | Every plan change is logged with who asked for it and why. After a capped number of replans (default 3) the feature escalates to a contract owner, as in AGT-5. | v1 |
| INT-16 | A plan is marked complete as an explicit state, set by the spec writer. | Acceptance never fires on a plan that is not marked complete, even if every PR listed so far has merged. | v1 |
| INT-17 | An owner-approved contract can authorize a narrow class of unflagged fixes. QE records the report, affected callers, expected correction and matching authorization. | Ambiguous intent returns to the ideator. A change beyond the authorized delta or to another relied-on behavior requires a flagged Feature or explicit owner-controlled handling under PIP-9. A report alone cannot authorize a behavior change. | v1 |
| INT-18 | PR shape rules are hard. A non-switchable change (PIP-9) is alone in its PR, generated output rides with its source, and a PR touches one contract owner's area unless the plan says it must cross. | A PR that breaks a shape rule fails Verify with the rule's gate ID. | v1 |
| INT-19 | Each PR has a soft review-surface budget: hand-written changed lines, excluding generated files, lockfiles and test fixtures. The budget is an install default a contract can override. | Generated files are detected from linguist-generated attributes, "DO NOT EDIT" headers and contract-declared paths. A PR over budget needs a justification in the plan; it does not fail on size alone. | v1 |
| INT-20 | A reviewer agent can ask for a PR to be split when it is too big to review with confidence. | The request cites the size gate ID (P4) and reaches the spec writer as a replan request (INT-15). | v1 |
| INT-21 | Scenarios are written for the ideator as plain Given/When/Then. The QE agent picks the test layer when it binds each one. | On the tinker repo, a frontend scenario binds to a Cypress spec and a service scenario to a Go integration test against the running service. | v1 |
| INT-22 | The interactive portal supports refinement, classification, splits and scenario approval using the same authenticated decisions as GitHub. | An ideator can reach approved scenarios without opening GitHub. The portal posts the refined idea, class and approved intent revision to the issue. | later |

### Contracts (CON)

| ID | Requirement | Acceptance criteria | Phase |
| --- | --- | --- | --- |
| CON-1 | Contract files can live at any directory level of a repo. | The factory does nothing to a path unless an approved contract covers it. | v1 |
| CON-2 | Contract ownership follows the repo’s CODEOWNERS. Contract proposals follow a separate, owner-controlled policy review path. | Activation requires approval of the exact revision by a current owner under the previously trusted ownership and gate rules. A product change cannot supply the policy used to authorize its own merge. | v1 |
| CON-3 | For any change, the effective contract is the stack of contracts along every path it touches. | A change that spans two owners' areas must satisfy both contracts. A lower level that removes a parent's mandatory gate fails validation. | v1 |
| CON-4 | Contracts reference existing CI gates by trusted producer, pinned workflow revision and job/check identity. Display names are for readers. Contracts contain no build commands. | Validation rejects commands, unregistered identities or revisions and a mandatory gate identified only by name. Verify accepts a matching execution under PIP-2. | v1 |
| CON-5 | Each gate declares its owner and whether it is mandatory or advisory. Factory baseline gates are mandatory and cannot be waived by an owner, contract or agent. | Contracts can add gates. A current owner may change a contract-added gate for future candidates through CON-2, subject to inherited minimums (CON-12). An in-flight change cannot waive a mandatory result. | v1 |
| CON-6 | Product-change agents cannot change contracts, CI definitions, ownership rules or other protected paths. | A product PR touching a protected path fails Verify. A separate owner-led protected proposal is evaluated under the currently trusted policy. Proposed rules and workflows cannot attest to their own adoption. | v1 |
| CON-7 | A contract declares writable, read-only and forbidden paths. Agents may propose changes to read-only paths (for example shared protos), but those PRs need a path owner's approval. | A change outside writable paths fails Verify, unless it touches only read-only paths and a path owner approves it. | v1 |
| CON-8 | A contract can turn on lights-on mode for its area. | Merge requires all mandatory gates plus current code-owner approval for the exact change, declared impact and recovery plan (SEC-10). | v1 |
| CON-9 | A contract can override install-wide defaults such as the switch timers. | The value used is the lowest level's override, else the install default. | v1 |
| CON-10 | The contract onboarder drafts a repo’s first contract from its CI configuration, CODEOWNERS and conventions. | A current owner sponsors the draft on the separate protected review path. The owner reviews the CI mappings and approves the pinned revision under pre-existing trust rules before it takes effect. | v1 |
| CON-11 | A contract is a .factory.yaml file, validated against a published, versioned JSON Schema that rejects unknown fields. | A contract with any unknown field, including a command field, fails validation (CON-4). | v1 |
| CON-12 | Every contract field is either a safety field, which only tightens down the tree, or an override field, where the lowest level wins (CON-9). | Gates, agents, forbidden and sensitive paths accumulate; writable paths only narrow; lights-on only turns on. A child that loosens a safety field fails validation. | v1 |
| CON-13 | Contract validation is incremental, and the effective contract for any path can be explained. | A contract PR validates only that contract, its ancestors and its descendants. An explain command shows each effective value for a path and which contract set it. | v1 |

A contract applies to its directory and everything below it. This example uses illustrative identities. The integration resolves them against its trusted CI registration.

```yaml
# .factory.yaml
apiVersion: factory/v1alpha1
kind: Contract
paths:
  writable: ["**"]
  readOnly: ["api/protos/**"]      # agents may propose; a path owner approves (CON-7)
  forbidden: ["deploy/**"]
  sensitive: ["src/checkout/payment/**"]  # security reviewer required (SEC-5)
  generated: ["gen/**"]            # excluded from the review budget (INT-19)
gates:
  verify:
    - name: build-and-test
      producerId: github-app:12345
      workflowId: 67890
      workflowRevision: 'a4ac7e7ccc7544f12d78ba75fd84289a903511f3'
      checkId: build-and-test      # job identity within the registered workflow
      mandatory: true
    - name: lint
      producerId: github-app:12345
      workflowId: 67890
      workflowRevision: 'a4ac7e7ccc7544f12d78ba75fd84289a903511f3'
      checkId: lint
      mandatory: false
  darkMergeOracle:                 # existing trusted CI comparison (PIP-13)
    producerId: github-app:12345
    workflowId: 67890
    workflowRevision: 'a4ac7e7ccc7544f12d78ba75fd84289a903511f3'
    checkId: checkout-contract
    observables: [responses, reads, writes, events, queued-jobs]
agents:
  verify: [security-reviewer]      # adds to the parent's list, never removes
lightsOn: false
overrides:                         # lowest level wins
  switchStaleDays: 45
  reviewBudgetLines: 300
```

### Pipeline and stages (PIP)

| ID | Requirement | Acceptance criteria | Phase |
| --- | --- | --- | --- |
| PIP-1 | The v1 pipeline covers Verify (change), Acceptance (feature) and Union (train). Later stages are Rehearsal (release candidate) and Delivered (release). | Issues and Checks show the current stage and disposition, including blocked, repairing, retrying and ejected. Verified repairs may re-enter earlier gates. A pilot train ends with a qualified or blocked manifest. | v1 |
| PIP-2 | Verify runs every mandatory gate on the exact merge-group SHA combining the PR with queued changes ahead of it. Merge also requires all applicable reviews. | Require a registered execution record for each mandatory job showing its trusted producer, workflow identity and pinned revision, job identity, merge-group SHA, actual execution and explicit success. An overall green workflow with a skipped job fails. Neutral, missing, stale or foreign results block merge. A changed queue head requires a new run. | v1 |
| PIP-3 | Acceptance runs the approved private suite with the feature enabled only when the plan is marked complete and all planned PRs have passed Verify and merged. | A noninteractive factory run records the candidate SHA and artifact digest, switch config, suite and intent revisions, and per-scenario pass/fail status. Only independent success qualifies the feature for Union. A PM opinion is optional later. | v1 |
| PIP-4 | Unflagged Tasks skip Acceptance only when the contract oracle demonstrates observable neutrality against the pre-change baseline. | An unchanged public API or green existing suite alone is insufficient. An unapproved difference or missing comparison blocks the Task. Reclassify behavioral work as a Feature or authorized Fix. Route inherently non-switchable work to PIP-9. | v1 |
| PIP-5 | At Union, run smoke and contract gates on the CI artifact with the release defaults, the accepted switches all on and all off, and the exact proposed complete configuration (PIP-14). Identical configurations can share evidence. | Include existing flag values, dependency constraints and prerequisite settings. A mixed proposal that fails with both extremes green is blocked. Record its failing configuration. The pilot qualifies a proposed manifest without activating it. | v1 |
| PIP-6 | In Rehearsal, an authorized PM or RM requests the qualified manifest. An authorized watcher can reject it. | Before activation, confirm the exact PIP-14 evidence and the actor’s current authority. A changed flag or dependency requires qualification. Log the actor, manifest and time. | later |
| PIP-7 | Delivered references the release artifact supplied by customer CI, such as a signed OCI bundle. | The delivery record links its digest and exact activated switch configuration to the qualified manifest. | later |
| PIP-8 | Company policy can request promotion manually, on a schedule or on a signal. | Every actual activation requires passing evidence for that exact manifest and current PM or RM authorization bound to it. A scheduled request with stale evidence or approval remains pending. Emergency halt remains available under SEC-6. | later |
| PIP-9 | Declare inherently non-switchable schema, data, proto, API, configuration or dependency changes before merge. Verify isolates each under INT-18 and requires an owner-controlled lights-on review. | Record effects, affected callers, rollout order, rollback or forward-recovery steps and independent mandatory gate results. An owner approves that exact revision and impact. An errant flag-off side effect blocks the change. Missing evidence for switchable work requires coverage or replanning. Migrations use separate expand and contract trains. | v1 |
| PIP-10 | At plan time and on each PR diff, serialize overlapping hand-written files and shared non-switchable artifacts. Record known cross-service or switch dependencies in the plan and manifest. | Later overlapping PRs wait, rebase and run Verify again. Disjoint files may interact through shared reads, events or services. An interaction between disjoint PRs still blocks their failing proposed configuration under PIP-5. | v1 |
| PIP-11 | Union's default cadence is one train per working day, set in install config and overridable in the repo's root contract. A train with nothing newly accepted is skipped. | The interval cannot be shorter than twice the last train's run time. The tinker repo runs a train every 2 hours to build its baseline faster. | v1 |
| PIP-12 | A train can also run one diagnostic pass per newly accepted switch, enabling it over the release defaults. Independent passes run in parallel. | The diagnostic identifies the failing switch set. The full proposed configuration must still pass PIP-5. | later |
| PIP-13 | The contract pins a trusted comparison, representative inputs, observable boundaries and allowed nondeterminism. Compare the pre-PR queue baseline with its merge-group candidate under the same inputs and release defaults. On first introduction, compare baseline behavior without the new flag to the candidate with it explicitly off. | Compare responses, observable reads and writes, emitted events and queued jobs. Dark features and unflagged Tasks require equivalence. An authorized Fix permits only the INT-10 delta. A switched-off checkout that still enqueues a new job fails even with an identical response. Record both SHAs, configurations, oracle revision and result. Missing coverage blocks automatic merge. | v1 |
| PIP-14 | A candidate manifest pins its source commit, customer CI artifact digest, effective policy revision, release defaults, complete resolved flag values and dependencies. Union records gate identities and results against the immutable manifest. | Reject an unverified source-to-digest mapping, missing flag value, unsatisfied dependency or failing exact configuration. A change to any pinned input invalidates qualification and requires a fresh result for the replacement manifest. | v1 |
| PIP-15 | Failed Acceptance keeps the feature dark and ineligible for Union. Return only the public scenario ID, expected observable outcome, sanitized symptom and run reference to the coder. | Freeze the failing suite revision across repair attempts. Each repair commit passes Verify before independent Acceptance reruns that suite. A suite defect follows INT-9. Logs, issues, artifacts and prompts disclose no executable, private input or assertion. After the repair limit (default 3 rounds), block and page the owner. | v1 |

### Agents and review (AGT)

| ID | Requirement | Acceptance criteria | Phase |
| --- | --- | --- | --- |
| AGT-1 | The coding agent works out the repo's local build and test steps for its inner loop. | Inner-loop results are never shown or counted as gate results. | v1 |
| AGT-2 | Coders can read approved scenario intent. Private Acceptance material stays outside all coding and PR review sessions (INT-6). | A coder can see a public scenario ID and its approved behavior after a failure. Attempts to fetch private runner output or fixtures are denied. | v1 |
| AGT-3 | At least two independent reviewers see the spec, diff and relevant repository context read-only, including callers, contracts, history and public tests. | A reviewer can trace a changed interface to an unchanged caller. Reviewer context excludes coder reasoning, transcripts and private holdouts. | v1 |
| AGT-4 | A reviewer may block provisionally by citing a source location, violated invariant, concrete consequence and verification plan, even when all gates pass. | An independent reviewer or trusted gate tests the claim or checks a reproducible proof. Record evidence for confirmation or dismissal. Confirmed issues require repair and re-review. Unresolved claims remain blocked and escalate under AGT-5. | v1 |
| AGT-5 | Reviews stop after a capped number of rounds and escalate. | After N rounds (default 3) without convergence, the PR is assigned to a contract owner. | v1 |
| AGT-6 | Agents run sandboxed, and every action is audited. | Every tool call, model call and repo write is in the audit log with the change ID. | v1 |
| AGT-7 | Pin a model and configuration profile per enabled role in install configuration. Profiles can use the same model. The PM role comes later. | A v1 run identifies the pinned profile and model revision used by each role. Changing the coding profile leaves the reviewer’s pinned profile intact. | v1 |
| AGT-8 | The contract onboarder records each repo's inner-loop recipe once, starting from the repo's devcontainer if it has one. Coding agents start from the recipe instead of rediscovering it. | A recipe is accepted only after it reproduces a recent green CI result. When a recipe fails, the coder falls back to gate-of-record CI within COST-3's limit, and the recipe is flagged for repair. | v1 |

### Feature switches (FLG)

| ID | Requirement | Acceptance criteria | Phase |
| --- | --- | --- | --- |
| FLG-1 | Every feature is guarded by one switch, and the switch ID is the feature's identity. | Every PR in a feature references its switch ID. Acceptance groups PRs by that ID. | v1 |
| FLG-2 | The factory follows the repo's existing switch convention. | Detects OpenFeature manifests and flagd config in the OTel Demo. New switches default to off. | v1 |
| FLG-3 | In v1, record switch identity, owner, age, default and qualification status through Union. | GitHub shows a new feature defaults off, whether Acceptance passed, and the manifest in which its proposed setting was tested. | v1 |
| FLG-4 | After release-stage integrations exist, track Rehearsal and Delivered activation. A release switch on in Delivered for N days (default 30) is stale. | The portal shows environment state and age. A stale release switch triggers a cleanup PR through the normal pipeline. | later |
| FLG-5 | A switch never turned on for N days (default 30) is abandoned. The factory proposes removing the feature code and notifies the ideator. | The proposal is created as a task in the tracker. | later |
| FLG-6 | Switches have a release or permanent kind. Only an authorized PM or RM may change the recorded kind. | Permanent operational controls are exempt from FLG-4. The portal lists them separately with their owners. | later |
| FLG-7 | The spec writer records the surviving path for release switches. The janitor uses a deterministic codemod where available and an agent for remaining edits. | Each cleanup PR identifies the surviving path and which edits came from the codemod or agent. | later |

### Recovery (REC)

| ID | Requirement | Acceptance criteria | Phase |
| --- | --- | --- | --- |
| REC-1 | When a train fails, test candidate switch configurations, respecting dependencies. Qualify the exact replacement manifest before ejecting a switched feature from the proposed activation. | Link the failed and passing manifests, check results and disabled feature to the intake issue. Disabling the switch leaves its source in the artifact. An inconclusive investigation leaves promotion blocked. | v1 |
| REC-2 | For suspect merged, unflagged work, submit an inverse through Verify or select an eligible source revision excluding that change. Customer CI supplies a replacement artifact with verified provenance. | Record evidence that the replacement source excludes the change or contains its verified inverse. Re-run mandatory qualification on the replacement manifest. Mark ejected only on success. Changing an issue or membership list cannot remove code from an artifact. | v1 |
| REC-3 | A conflicting inverse may be repaired within a configured retry cap (default 3). Each repaired inverse passes Verify before use. | Conflict at the cap, failed Verify, missing replacement artifact or failed replacement qualification stops promotion and pages the owner under REC-4. The original item remains unresolved. | v1 |
| REC-4 | Stop the train whenever recovery cannot establish a passing eligible candidate. | Page the current owner with attempted reversals or switch configurations, failing checks and last known eligible manifest. Promotion resumes only with evidence for a qualified replacement. | v1 |
| REC-5 | A Rehearsal rejection blocks the proposed activation, records a reason and opens a follow-up issue in intake. | A replacement or rollback activation uses a qualified safe configuration or the last known good manifest, with PIP-8 authorization. Emergency halt remains available immediately. After two rejection rounds assign the feature to a human engineer. | later |

### Security (SEC)

The factory is the most privileged actor in the repo, and every file, ticket and tool result it reads is untrusted input. These rules keep one hostile string from becoming merged code.

| ID | Requirement | Acceptance criteria | Phase |
| --- | --- | --- | --- |
| SEC-1 | All repo content, tickets, CI logs and tool results are treated as untrusted input. No agent that reads them may hold both access to secrets and open egress. | Each role's policy is checked at install; a role with all three of untrusted input, secrets and open egress fails validation. | v1 |
| SEC-2 | Agents never hold merge rights. Only the factory control plane merges, and only after the merge queue's gates and reviews pass. | No agent identity has a forge token that can merge or push to protected branches. | v1 |
| SEC-3 | Each role gets least privilege. Reviewers are read-only; coders can push only to their own change branch. | A reviewer's attempt to push is rejected by the forge. | v1 |
| SEC-4 | Every PR passes secret scanning and dependency scanning as mandatory factory gates. | A PR introducing a secret or a dependency with a known critical CVE cannot merge. | v1 |
| SEC-5 | The security reviewer agent is mandatory for paths a contract marks sensitive. | A PR touching a sensitive path cannot merge without the security reviewer's approval. | v1 |
| SEC-6 | Only a currently authorized admin can halt or resume the installation. Halt fences running sessions, queued actions and merges. | After halt, no session runs or PR merges until a current admin authorizes resume for that halt revision. A non-admin, revoked admin or replayed resume is denied and logged. | v1 |
| SEC-7 | A prompt-injection test suite runs against every factory release. | The release is blocked if a planted instruction in a repo file or ticket changes agent behavior. | later |
| SEC-8 | Rehearsal never uses raw production data. It uses synthetic data, or snapshots masked with the customer's existing masking tools (P1). | No agent identity can reach Rehearsal data stores. A Rehearsal environment without masked or synthetic data cannot start. | later |
| SEC-9 | Coding harnesses load only factory-supplied settings, tools and instructions, never ones found in the repo. Claude Code runs in bare mode; Codex reads provider config from the factory, not the project. | A hook, MCP config or harness settings file planted in the repo does not run or load during a coding session. | v1 |
| SEC-10 | Authenticate privileged human actions using verified forge identities and current role and ownership rules (NFR-5). Bind each decision to the actor, intended action, repository or installation, and exact proposal revision, commit or manifest digest. | At execution, recheck identity, role, scope and revision. Reject edited or copied issue comments, stale approvals, revoked owners and cross-repo replays. Audit approved and denied decisions, including intake, path exceptions, contract changes and halt/resume. | v1 |
| SEC-11 | The pilot runs integration regressions for the factory’s authorization, isolation and gate controls on every control-plane change. | Tests deny a forged approval, a stale owner approval, unauthorized resume, a same-name foreign check and coder access to a private fixture. A failed Acceptance case leaves no secret or private fixture in published logs or issue output. A matching authorized approval succeeds. | v1 |

### Cost and capacity (COST)

| ID | Requirement | Acceptance criteria | Phase |
| --- | --- | --- | --- |
| COST-1 | Token and GPU budgets per team and per feature are informational. The spec writer estimates each feature's cost when it writes the plan. | The issue links to estimated and actual cost. Going over budget notifies the ideator and owner but never pauses work. | v1 |
| COST-2 | Concurrency quotas per team for agent sessions and gate-of-record CI runs. | Work over quota waits in a queue instead of starting. | v1 |
| COST-3 | Gate-of-record CI runs are rate-limited per repo, so agents iterate in their inner loop first. | A coding agent cannot trigger the customer's CI more than the configured number of times per PR per hour. | v1 |
| COST-4 | A circuit breaker catches runaway loops. | An agent that fails the same gate N times in a row is stopped and its change escalated. | v1 |
| COST-5 | Cost is reported per feature, team and train. | The run record attributes tokens, GPU time and CI minutes to each feature, including failed attempts. Team and train totals reconcile to the run records. | v1 |
| COST-6 | Enforced budgets, set from the estimate-versus-actual data collected under COST-1. | A contract can turn a team's budget from informational to enforced. | later |
| COST-7 | A progress breaker stops a change that churns without progress. It is a safety stop, separate from budgets. | A change is stopped and escalated after 5 iterations with no newly passing gate, or once its spend passes 5 times its plan estimate. Both defaults are configurable. | v1 |

### Portal (POR)

| ID | Requirement | Acceptance criteria | Phase |
| --- | --- | --- | --- |
| POR-1 | The interactive portal reads idea status from the tracker. | Each idea shown links to its underlying issue and reflects the same stage. | later |
| POR-2 | Each change has a portal card with its stage, gate results, evidence and, when available, the PM agent's advisory verdict. | Every gate result links to its run. | later |
| POR-3 | PMs and RMs can turn switches on and off from the portal. | Switch changes are permission-checked and logged. | later |

### Integrations (INTG)

| ID | Requirement | Acceptance criteria | Phase |
| --- | --- | --- | --- |
| INTG-1 | GitHub Issues holds intake, decisions and status. GitHub Actions runs CI and GitHub Checks exposes gate results. | On the hosted fork and the qualified disconnected profile, an authenticated ideator can refine an idea and approve its exact revision on the issue. The control plane updates the issue, publishes revision-bound checks and admits passing PRs to merge under contract. | v1 |
| INTG-2 | Jira as the tracker. | The factory reads issues and issue types and creates follow-up tickets. | later |
| INTG-3 | GitLab and Jenkins adapters. | The same contract runs against GitLab CI or Jenkins jobs without changes. | later |
| INTG-4 | Adapters for additional customer Kubernetes and inference deployments. | A declared additional platform can create and tear down an Acceptance environment and pass its role qualification suite. | later |

## Non-functional requirements

| ID | Requirement | Acceptance criteria | Phase |
| --- | --- | --- | --- |
| NFR-1 | Support a named, qualified disconnected deployment. | Milestone B installs from scratch with external routes denied and completes two full v1 runs through Union under that restriction. Retain network policy, flow records and run evidence with the profile. A hosted GitHub run counts only toward milestone A. | v1 |
| NFR-2 | Admit each model and harness for a specific role on a pinned deployment profile. | Before scheduling a role, verify a passing qualification record for its exact model, harness, role definition, tools and endpoint configuration. Test required capabilities, representative behavior and negative cases for each role. Missing or failed qualification blocks admission. Changes to the qualified tuple require requalification. | v1 |
| NFR-3 | No telemetry or license phone-home. | During disconnected installation and both runs, traffic reaches only the named internal endpoints. Capture DNS, network flows and denied attempts, including startup and retries. Required external dependencies fail qualification. | v1 |
| NFR-4 | An append-only audit log. | Audit entries cannot be edited or deleted through any factory API. | v1 |
| NFR-5 | Enforce role and scope on every action in v1 using authenticated forge identities and scoped service identities. Federated SSO is later. | Apply the same checks to issue events, checks, callbacks, API and administrative paths. Verify current role and ownership at execution and bind decisions to the exact revision. Deny and audit unauthorized, revoked, replayed and stale approvals. | v1 |
| NFR-6 | Provenance on every agent commit. | Every commit carries the trailer set in the contract, e.g. `Assisted-by:`. | v1 |
| NFR-7 | Apache-2.0 license, with DCO sign-off for contributions. | Every commit to the project carries a Signed-off-by line, enforced by a DCO check. | v1 |
| NFR-8 | Install a pinned, versioned disconnected bundle. | The bill of materials identifies immutable digests or checksums for the forge and Actions runners, actions, charts, runtime and service images, Git dependencies, model weights, harnesses, tools, scanner databases and test fixtures. Install only from local media or services, including the registry, PostgreSQL and snapshot store. Archive the manifest with both runs. | v1 |
| NFR-9 | V1 scale targets on the tinker repo. Enterprise targets come later. | 10 concurrent agent sessions and 20 merged PRs a day, with no queued work waiting more than one train. | v1 |
| NFR-10 | Enterprise scale targets per repo, sized from a large monorepo that holds about 4,000 open PRs at any moment. | 4,000 open factory PRs, 500 active agent sessions with the rest suspended, and PIP-10 overlap checks and merge-queue admission each decided within 60 seconds. Throughput: 500 merged PRs a day in a monorepo and 10 a day in a side repo. | later |

## Success metrics

Use the first 20 scheduled tinker trains to establish engineering baselines from issue events, the audit log and run records. Record every train, including empty, aborted and failed trains. Publish counts with rates and mark a zero denominator as unavailable. Tag deliberate fault injections so operators can distinguish a successful safety drill from a spontaneous failure. The operating target for spontaneous line stops is zero. The adoption decision uses the team pilot below.

| ID | Metric | Definition |
| --- | --- | --- |
| MET-1 | Idea-to-Acceptance lead time | Elapsed time from intake to passing Acceptance. Report median and p90 among passes, and all submitted, failed and unfinished feature counts with age at cutoff. |
| MET-2 | Dark merge rate | Eligible PRs merged without human action divided by all submitted PRs outside lights-on areas. Report abandoned and pending PRs. |
| MET-3 | Ejection rate | Features ejected divided by features admitted to each train. |
| MET-4 | Revert rate | Tasks and unswitched fixes requiring revert divided by those admitted to each train. Report confirmed and failed reverts separately. |
| MET-5 | Rehearsal rejection rate | Once Rehearsal exists, features rejected divided by features evaluated there. Until then, record as unavailable. |
| MET-6 | Escalation rate | Changes hitting a cap and escalated to a human divided by all admitted changes. |
| MET-7 | Cost per accepted feature | Total compute and CI cost of all feature attempts, including failures and retries, divided by accepted features. Report tokens, GPU time and CI minutes alongside cost. |
| MET-8 | Line-stop count | Count all stops for an unrecoverable candidate, including trunk failure after ejection, an unconfirmed revert, an unresolved cause or unverified artifact recovery. Tag drills separately from spontaneous stops. Report cause and time to confirmed recovery. |
| MET-9 | Inner-loop agreement | Matching gate outcomes divided by comparable inner-loop and CI pairs for the same commit and gate. Report unpaired results separately. |

## V1 scope and tinker repo

Requirement row phases govern scope. Milestones A and B establish the v1 engineering claims. Milestone C tests whether adopting the factory improves a team's current workflow.

**A. Hosted vertical slice.** Use a public fork of the [OpenTelemetry Demo](https://github.com/open-telemetry/opentelemetry-demo) with GitHub Issues, Actions and Checks. Work only on the fork and use the required `Assisted-by:` trailer. Exercise the Go checkout and product-catalog services and the TypeScript frontend, using the fork's per-service OpenFeature manifests, generated code and flagd runtime state. Run the minimal Compose deployment and applicable Cypress tests at Union.

Use the core role catalog, pinned runtime and qualified role configurations. The ideator refines and approves public behavioral intent on the issue. QE keeps executable holdouts private. Independent review sessions receive the code context they need and can raise a provisional, testable blocker. Multiple independent reviewers may share a model if it qualifies for each assigned role. The issue and Checks link each decision, revision and gate run.

Demonstrate a feature from intake through Verify, Acceptance and Union. Exercise the flag-off guard with a change that alters existing behavior while disabled and retain the blocking check. Force an Acceptance failure, trace the repair through Verify and rerun the private holdout before train admission. Include a non-switchable change whose revert fails. Stop the candidate and page the owner until repository and gate evidence confirm recovery, even if the issue already says the work moved. For a passing candidate, record its commit SHA, immutable artifact digest, complete proposed flag manifest and policy revision. Seed an interaction where A alone fails while A+B (all on) and all off both pass. Refuse the untested A-alone proposal, then run Union on that exact manifest and record its failing check. Repair the interaction through Verify and rerun Union on the corrected candidate with the same A-alone flag values and a new manifest. Bind its passing verdict to the new SHA, artifact, policy and full manifest.

**B. Disconnected qualification.** The first proposed profile, `ghes-local-v1`, uses GitHub Enterprise Server and self-hosted Actions, a local registry and dependency mirrors, a local Kubernetes cluster with the pinned factory runtime and state stores, and local inference. Before claiming support, name the exact release or digest of every component and each role's model, harness and tool permissions in the profile. For example, the coder must repair an ordinary failing check while denied holdout access, the reviewer must catch a seeded behavioral regression with access to code context, and the scenario reviewer must reject a mismatched executable scenario. Apply positive and negative fixtures to every enabled role. Wire-format compatibility alone does not qualify a deployment.

Start with a clean installation and deny external routes at its network boundary before installing. Complete the v1 workflow twice, retain the bill of materials, role qualification results, endpoint inventory, flow or packet evidence and both candidate records, then mark only that exact profile supported. An unproven profile remains a qualification candidate. Optional runtime, forge and inference adapters require separate qualification before use.

**C. Representative team pilot.** Before assigning work, the team and an independent evaluator register the current workflow, entry and completion criteria, task sampling, assignment, exclusions, time and cost rates, observation window and decision thresholds. The proposed pilot policy below must be accepted or revised before results are seen.

- Enroll at least 40 eligible, consecutive items of real team work spanning features, tasks and fixes. Stratify by class, estimated size and risk, then randomize within strata to factory or current workflow (at least 20 per arm). Use the same repository, staffing window and completion criteria. Record all screened items, exclusions with reasons and deviations.
- Follow each assigned item for 30 calendar days from assignment. Use a common integration-ready checkpoint through Union or the team's equivalent. Count every assigned item once in its original arm, including retries, failures, escalations, withdrawals and unfinished work. For elapsed time credit unfinished items with the full 30 days. Report completion separately.
- Two evaluators outside implementation score the same anonymized artifacts against a preregistered rubric for intent, correctness, regression coverage and maintainability. Each independently scores readiness and whether pass, block or escalation decisions were warranted, then a third adjudicates disagreements. Preregister the decision sample (all gate decisions, or a fixed sampling rule for each stage) and count both false passes and unwarranted blocks. Evaluators observe ordinary decisions in both arms, including always-on factory checks, using read-only access. Their retrospective scores confer no merge authority and do not count as human intervention in MET-2. Count unfinished work as unready. Record attributable follow-up defects found in the window with severity and repair effort.
- Capture total human minutes for intake, approvals, authoring, reviews, escalations, administration, reruns and defect repair in both arms. Calculate all-in cost from those minutes at frozen labor rates, model/GPU consumption, CI, storage and allocated setup, licensing and operating overhead, including failed attempts and follow-up. Count a resource once. Report arm totals, cost per assigned item and cost per independently accepted item. Publish elapsed time, quality, decision accuracy, completion and defect counts with raw denominators.
- **Proposed go/no-go rule.** Proceed to a wider trial only if the factory cuts median elapsed time by at least 20% and total human minutes per assigned item by at least 25%, with all-in cost per independently accepted item at or below the comparison arm. If either arm has zero independently ready items, the cost gate is unmet. The factory’s independently ready share must be at least 85% and within 5 percentage points of or above the comparison arm. At least 90% of scored gate decisions must be warranted. Require zero critical attributable defects or unauthorized promotions and no more than one additional item with a high-severity defect versus the comparison arm. Report uncertainty and stratum mix. A missed threshold, insufficient enrollment or incomplete scoring withholds expansion until a fresh preregistered pilot.

**Later scope.** The full interactive portal, feature cards, advisory PM role, custom agents and optional infrastructure adapters follow the core slice. Rehearsal, actual activation, Delivered, post-release observation and switch cleanup require later release evidence and controls. A passing v1 Union record establishes readiness only for its bound candidate and configuration.

## Open questions

- [ ] RUN-10 spike: test Codex with a local model on the tinker repo. If qualifying Claude Code as an additional harness, test gateway-injected credentials with sandbox credential access denied. Both paths require their own qualification evidence.
- [ ] Record the exact component BOM and passing model/harness tuple for each core role in the first disconnected profile. Which candidates meet the role behavior and isolation fixtures within the team's hardware envelope?
- [ ] Before the team pilot, name the participating team and independent evaluators, confirm the representative work mix and lock the proposed thresholds and costing assumptions.

## Decision log

All decisions below were made on 2026-11-21.

| Decision | Why |
| --- | --- |
| Build open source first, on a public tinker repo. | Wider adoption, and no proprietary code in the project. |
| Tinker repo is a fork of the OTel Demo, Go and TypeScript slice, no Java. | It has multiple services, flagd switches built in, and Cypress end-to-end tests. |
| Sit on top of existing forge, CI and tracker. | Developers won't change tools; Delivery failed by imposing its own. |
| Contracts are layered by directory and owned through CODEOWNERS. | Monorepo teams and sub-teams each own their areas. |
| Contracts reference existing CI checks, never commands. | CI stays the source of record (P1). |
| AURD-style promotion pipeline, with Verify in front. | Builds on Chef Delivery's model, minus its pipeline-as-code mistake. |
| Stages are accumulators: change, feature, train, release candidate, release. | Matches how work grows as it moves toward release. |
| Every feature ships behind a switch; the switch ID is the feature's identity. | Merging dark separates code from release, and makes bisection cheap. |
| Tasks have no switch, must prove no behavior change, and can be auto-reverted. | Dependency bumps and refactors still need a fast path. |
| Union runs on a schedule, like a release train. | Predictable batches; features that miss a train wait for the next. |
| The later PM agent is advisory. | Release judgment stays with people. |
| Independent agents review changes in Verify. Each receives code context and may raise a testable provisional blocker. | Independent sessions and evidence can be evaluated even when qualified reviewers share a model. |
| Later, Rehearsal rejection records a reason and follow-up issue. Before activating any replacement, verify Union qualification for the exact safe configuration and obtain PM/RM authorization bound to its full manifest. | Optional or scheduled Rehearsal policies retain the same activation authorization. |
| Switch timers default to 30 days, overridable at install and contract level. | Teams need different clean-up cadences. |
| Automate recovery and page on a line stop or unconfirmed revert. | Moving an issue cannot establish that the candidate is safe. |
| Runtime is kagent on Agent Substrate, with agentgateway brokering all traffic. | On-prem and Kubernetes-native, with sandboxing, egress control and credential injection built in. |
| Ship the core role catalog in v1. Add custom agents and skills later. | Qualification and isolation can be tested against a bounded set of roles. |
| Verify merges through a merge queue. | With many agents in flight, PR bases go stale within minutes. |
| Agents never hold merge rights; only the control plane merges. | The factory is the most privileged actor in the repo. |
| Read-only paths accept agent proposals with an owner's approval. | Features that need a shared proto change otherwise have no path. |
| GitHub Issues is the v1 tracker, using GitHub issue types in place of Jira's; Jira becomes a later adapter. | Keeps v1 inside the GitHub fork, and keeps the tracker as the record of work (POR-1). |
| The ideator approves the acceptance scenarios early, before the spec and PR plan are written. | Nobody reliably reviews AI-written spec prose. Scenarios are short, testable, and carry the ideator's intent. |
| No code-owner approval at intake. Owners act through contracts and are paged on escalation. | The engineer's role is changing fast, and the factory avoids human roadblocks. Someone still gets paged. |
| The spec and approved behavior are visible in the repo or issue. Executable holdouts and private fixtures stay in the factory store. | Coders need approved intent to implement correctly. Independent tests retain their diagnostic value. |
| QE proposes separately reviewed public regression tests derived from approved behavior after Acceptance. | The private suite and fixtures stay in the holdout store. |
| QE owns the approved scenarios, their private bindings and execution, and the proposal for public regression coverage. | Independent review checks the public regression PR through Verify. |
| A scenario reviewer agent checks each executable scenario against its approved text. Evidence for the ideator at Acceptance is later. | Guards the step where intent can be lost unseen. Ideator-facing evidence is useful but could become a rabbit hole. |
| An unswitched Fix requires a narrow owner-approved fix policy, a red-before/green-after reproducer and an expected behavior delta bound to the change. | Only a bounded restoration of expected behavior qualifies for this path. |
| The rubber duck is a guide. It proposes splits and explains refusals; the ideator decides. | Intake should help an idea along, not block it. A refused idea gets a reason and a next step. |
| The PR plan is a dependency graph, and independent PRs in a feature are coded in parallel. | Parallel work is the point of the factory; moving serially gates it artificially. |
| Only the spec writer edits a plan, "complete" is an explicit state, and replanning is capped. | Plans will change mid-flight; one owner and an explicit end state tell Acceptance when to fire. |
| A Fix within the approved policy can proceed without routine ideator intervention. Reclassify broader behavior changes as Features and obtain approval of the intended behavior. | The reproducer and bound delta make the narrow exception reviewable. |
| PR size is bounded by hard shape rules, a soft budget on hand-written lines, and reviewer split requests. | Lines of code mislead for generated schema and proto changes; what matters is isolating the consequential pieces. |
| PIP-10 stays: overlapping features are serialized, and unrelated areas run in parallel. | Clearly overlapping changes can have serious consequences; parallelism comes from unrelated work. |
| Under PIP-10, only a later feature's overlapping PRs wait; overlap is a shared hand-written file or non-switchable artifact. | Keeps the safety of serializing overlaps without stalling the rest of the plan. |
| Scenarios are plain Given/When/Then; the QE agent picks the test layer. | Readable for the ideator, and not every scenario needs an end-to-end test. |
| GitHub Issues handles v1 intake and authenticated decisions. Checks exposes gate status. The interactive portal follows later. | The fork can exercise the whole v1 path with one system of record. |
| Budgets are informational in v1; enforced budgets come later. | There is no data yet to set budgets well. Estimate-versus-actual data will inform stricter budgets. |
| Apache-2.0 license with DCO sign-off; a personal project. | Matches kagent and Agent Substrate, both Apache-2.0 CNCF projects; DCO is lighter than a CLA. |
| Union runs a daily train by default, and every 2 hours on the tinker repo. | Small batches bisect cheaply; the tinker repo needs baseline data fast. |
| Union must pass on the exact proposed flag configuration as well as mandatory control configurations. Exhaustive or optional single-switch diagnostics are later. | All-on and all-off can both pass while a mixed configuration fails. |
| Contracts are .factory.yaml files with a strict schema. Each field is a safety field (tighten only) or an override field (lowest wins). | Makes "lower levels only tighten" checkable, while teams still tune timers and budgets freely. |
| The inner loop uses a recorded, CI-verified recipe per repo, with CI as the fallback. | Published benchmarks show agents set up an unfamiliar repo only about half the time. |
| Switches are release or permanent. The surviving path is recorded at plan time, and removal uses codemods first. | Teams that clean up well set exit criteria when a flag is created and automate removal. |
| A progress breaker is a safety stop, separate from budgets. | With informational budgets, a loop that fails differently each round would otherwise run unchecked. |
| Use a pinned kagent runtime behind a thin adapter. Evaluate alternative runtimes later. | A reproducible runtime is required for qualification. |
| A disconnected profile earns support after an externally isolated clean install and two successful through-Union runs. | Public GitHub, warmed caches and hosted inference cannot establish disconnected operation. |
| Rehearsal uses only synthetic or masked data. | Keeps PII away from agents, and reuses the customer's masking tools (P1). |
| Baseline engineering diagnostics over 20 tinker trains. Preregister adoption thresholds before team pilot results. | Train telemetry measures factory operation. A matched or randomized comparison measures team outcomes. |
| Enterprise targets assume about 4,000 open PRs per repo at any moment. | Taken from a real large monorepo. At that size, overlap detection and the merge queue are the parts that will strain first. |
| Throughput targets: 500 merged PRs a day in a monorepo, 10 in a side repo. | Hundreds of PRs merge daily in a large monorepo today; side repos see about 10. |
| Pin Agent Substrate and its runtime dependencies in the versioned BOM. Requalify affected profiles before upgrading. | The same configuration must be reproducible offline. |
| Admit only model/harness combinations qualified for the assigned role and deployment. | Tool behavior, isolation and task performance must hold beyond an endpoint format check. |
| Coding harnesses ignore repo-supplied hooks, MCP config and settings (SEC-9). | Repo content is untrusted (SEC-1). |
| The factory is written in Go; the portal frontend uses whatever framework fits best. | Go suits a Kubernetes control plane and matches kagent; the frontend choice matters less. |
