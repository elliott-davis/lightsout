# Dark-merge oracle evaluation (WI-16)

Status: draft revised after a Codex review, 2026-11-22. Implementation is **deferred** until WI-04 and WI-07 are committed, because WI-16 adds contract schema fields (contracts.md: "PIP-13 oracle inputs and nondeterminism ... are added by those items") and those packages have uncommitted layers. WI-23 comes first, since the first-introduction check needs its flag interpretation. Covers WI-16: PIP-13, PIP-4 and INT-10 (the comparison).

`internal/oracle` is a pure evaluation package, like `internal/gate` and `internal/review`. It answers whether a
change's dark-merge oracle shows that the change is observably neutral against the queue baseline, or that it differs
only by an authorized Fix delta. It does no I/O. WI-18 fetches the inputs.

## Inputs
- **The obligations:** `eff.Oracles`, the oracle obligations, each with its `GateRef` and its declared `Observables`.
- **The gate evaluation:** the oracle job is a gate-of-record execution. Its evidence comes from `gate.Evaluate`, using
  the same rules as the other gates (WI-13): the pinned workflow, the merge-group candidate, attempts and provenance.
  The oracle package takes the `gate.Decision` and requires a `Pass` for the oracle's GateRef.
- **The report:** the oracle job's report artifact, fetched by WI-18 from that job's artifacts. A digest binds it to the
  job (forge artifact metadata: run, attempt, job, name, sha256).
  - The report is **untrusted**: the job is pinned, but it executes candidate code. It is parsed strictly, against a
    versioned schema, with bounded size, and unknown fields are rejected.
- **The work kind:** from the issue type (INT-3). It is one of `feature-dark`, `task` or `fix`. Fix carries an
  `Authorization` from INT-17 (WI-22): the authorized delta.
- **The baseline:** the queue baseline SHA, which is the merge group's base, and the candidate SHA.
- **The release defaults:** a config digest.
- **First introduction:** if the change introduces a new switch, the switch's key.

## The report (schema `lightsout.oracle/v1`)
The report holds these top-level fields:
- `baselineSHA` and `candidateSHA`
- `baselineConfig` and `candidateConfig` (digests), plus `switchOverrides` (for first introduction: `{key: "off"}` on the candidate)
- `oracleRevision` (the pinned workflow commit)
- `inputs`: the representative input set's digest and count

It also holds `results`, with one entry per observable:
`{observable, compared: n, equal: n, differences: [{input, observable, detail digest}], uncovered: [...]}`

## Rules
1. **The gate must pass.** The oracle's GateRef must pass in the gate decision. Otherwise the result is blocked
   (`oracle-not-run`).
2. **The report must bind to the gate execution and this comparison:**
   - its artifact digest matches the job's artifact
   - `baselineSHA` equals the queue baseline
   - `candidateSHA` equals the gate's candidate
   - `oracleRevision` equals the GateRef's revision
   - `candidateConfig` and `baselineConfig` equal the release-defaults digest
     - Exception, on first introduction: the candidate config is the release defaults with the new switch explicitly
       off, and `switchOverrides` says exactly that.
3. **Every declared observable must be covered:**
   - each declared observable has a result with `compared > 0`
   - `uncovered` is empty
   - `compared` equals the input count

   Missing coverage blocks (PIP-13: "missing coverage blocks automatic merge").
4. **The allowed differences depend on the work kind:**
   - **feature-dark and task** need equivalence: zero differences on every observable.
     - An unapproved difference blocks (PIP-4).
     - An identical response alongside a new queued job still fails, because `queued-jobs` is its own observable and must
       be declared (PIP-13).
   - **fix** may differ only within the authorized delta. Each difference must match the `Authorization`'s (observable,
     input set) entries, and any difference outside them blocks (INT-10).
     - An authorization with an empty delta means equivalence.
5. **Declared observables:**
   - **Required for every work kind:** responses, writes, events and queued-jobs. A contract that omits any of them is a
     configuration error, so the change is blocked (`oracle-incomplete`).
   - **Reads** are required only when the contract declares them.
6. **The result binds to** (Effective.Revision, InstallRevision, baselineSHA, candidateSHA, oracleRevision, report
   digest). WI-18 records both SHAs, the configs, the oracle revision and the result (PIP-13 "Record").

## Output
`Evaluate(eff, gateDecision, in Input) Decision`. The Decision gives:
- one result per oracle obligation: pass or blocked, with a reason and evidence
- the overall disposition: `pass`, `blocked`, `pending` or `error`

Pending covers the case where the gate is pending. Error covers an incomplete input or a malformed report.

## Revisions from the Codex review (they replace the conflicting parts above)
1. **Baseline.** For a queue member, the baseline is the **previous member's candidate**, or the group base for the first member. It isn't the group base for everyone. Otherwise a later PR can silently undo an earlier PR's authorized correction. Ejecting a member invalidates the evidence that follows it.
2. **Gate evidence.** `gate.Evaluate` only evaluates `VerifyGates`. Oracle GateRefs are evaluated by calling it with an Effective whose VerifyGates are the oracle refs, all mandatory. This needs no gate change. Snapshot-wide failures are kept.
3. **Trust.** Signing a report the candidate wrote proves nothing. Registration (WI-12 plus the gate registry) qualifies the oracle harness, which must:
   - build and run each SHA in a fresh sandbox with equivalent initial state
   - observe effects at external boundaries, outside the candidate process
   - assemble the report outside both sandboxes

   WI-16 verifies the report's binding to the run, attempt and job and its digest, plus the expected comparison inputs. An omitted or failed collector never establishes "zero".
4. **Coverage.** Counts prove nothing.
   - **The case manifest:** the contract (a new field) pins a **case manifest**: case IDs plus fixture digests.
   - **Scenario mapping:** trusted policy maps changed paths to the scenarios they require.
   - **Observations:** the report has one completed observation per expected case and boundary on each side. Counts are derived from those records.
   - **Blocking:** a duplicated or substituted case blocks, and so does an unmapped affected boundary.
5. **Nondeterminism.** A contract pin (a new field) gives a comparison-policy digest: exact equality by default, plus versioned rules scoped to a boundary, a field and an operation (for example a bounded timestamp tolerance).
   - Multiplicity and identity relationships are kept.
   - The report records every rule it applied.
   - A changed rule digest blocks.
6. **Fix delta.** An (input, observable) pair would permit *any* change. WI-22 produces a revision-bound authorization that names:
   - the cases, the field or operation
   - the allowed before→after relation (a typed predicate)

   WI-16 matches structured differences against it. Anything else blocks, for example a correct 404→200 that also changes the account ID. WI-18 separately requires that the visible reproducer failed on the baseline and passes on the candidate.
7. **First introduction.** The expected configs come from WI-23's reading of the real baseline and candidate manifests. The checks:
   - the key is absent on the baseline
   - the candidate's shipped default and fallback resolve to off, with the flagd variants and targeting pinned
   - the observed run is explicitly off, with every other release setting preserved

   A candidate that defaults to on and passes only under the forced-off override blocks.
8. **Observables.** All five PIP-13 categories, reads included, must be accounted for across the affected scope. Contracts name concrete boundaries and may split coverage among several oracles. A boundary is inapplicable only when the trusted sandbox proves it, for example by denying queue access.
9. **Output.** The decision gives a typed disposition and reason per oracle, plus an overall verdict. It binds to:
   - repo and PR/head
   - both SHAs and both configs
   - the policy and install revisions
   - the work kind and authorization
   - the job attempt and the report and policy digests

   Empty required evidence never passes. A WI-16 pass establishes only the comparison: a dark Feature still needs Acceptance (PIP-3).
