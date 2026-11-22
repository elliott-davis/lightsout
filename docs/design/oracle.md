# Dark-merge oracle evaluation (WI-16)

Status: design revised after a Codex review, 2026-11-22; concrete v1 design at the end. Covers WI-16: PIP-13, PIP-4 and INT-10 (the comparison).

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

## Implementation design (v1)
Status: decided 2026-11-22 after a second Codex review of the first draft. This section turns the revisions above
into concrete types. It replaces the "Inputs", "The report" and "Rules" sections where they conflict.

### Contract field (`gates.darkMergeOracle`, schema v1alpha1)
One new **required** field, a digest pin, so the case list doesn't live in the contract and changing it is a
contract change that goes through activation (WI-11):
- `caseManifest: {path, sha256}`: the case manifest (below). `path` is repo-relative and validated like any contract
  path; `sha256` is 64 lowercase hex. Only the digest is identity; `path` says where to read it.

The resolver merges oracle declarations by (GateKey, workflowRevision, manifest digest, sorted declared observables)
and reports a `Conflict` (stage `darkMergeOracle`) when one GateKey appears with more than one such pin in a change,
in either path order. The observables are in the identity because one manifest can match only one observable set, so
declarations that differ there cannot both pass; observables no longer accumulate down a stack. Existing contracts without the field stop validating; none are deployed yet.

**Cut from v1: the comparison policy.** v1 compares exactly: no ignore rules, no tolerances, no wildcards. The report
declares `"comparison": "exact/v1"` and anything else blocks. A later `comparisonPolicy` pin is an optional field,
so adding it is not a breaking change. Timestamp noise must be removed by the harness's fixtures (frozen clocks)
until a real case needs a scoped tolerance.

### Case manifest (`lightsout.oracle-cases/v1`, YAML or JSON, strict)
```yaml
schema: lightsout.oracle-cases/v1
cases:                       # 1..4096, ids unique
  - id: checkout-happy       # ^[a-z0-9][a-z0-9._-]{0,127}$
    fixture: sha256:<hex>    # digest of the inputs and initial state
boundaries:                  # 1..64, names unique, same id pattern
  - name: http-api
    observable: responses    # one of the five PIP-13 categories
covers: ["src/checkout/**"]  # 1..256 repo-root-anchored globs (internal/pathglob): the changed paths this oracle speaks for
```
- Every case runs against every boundary on both sides. cases × boundaries ≤ 4096, so a complete report fits the
  report cap. `ValidateManifest` enforces this, and WI-11 calls it at activation so an oversized matrix fails before CI.
- The set of boundary observables must equal the contract's declared `observables` exactly.
- Globs are anchored at the repo root, not the contract directory, so identical bytes mean identical coverage
  whichever contract declares them. A manifest that claims paths off its own stack is harmless: coverage is only
  checked through each path's own stack.

### The report (`lightsout.oracle/v1`, JSON, strict, ≤ 8 MiB) and its signature
Assembled by the registered harness outside both sandboxes (Revision 3).

**Provenance.** Artifacts are per run, so any step of the oracle job can upload an artifact with the report's name,
and every binding field of a report is computable by it. The binding fields therefore prove nothing on their own. The
harness signs the report: the run attempt must hold exactly one `lightsout-oracle-report` and exactly one
`lightsout-oracle-report.sig` (none: `report-missing`; more than one: `report-ambiguous`). The signature artifact is
strict JSON `{"schema":"lightsout.oracle-sig/v1","keyId":"...","signature":"<base64 std>"}`. The signature is Ed25519
over `"lightsout.oracle-report/v1\x00" || sha256(report bytes)`. `Input.HarnessKeys` (key ID to `HarnessKey{Public, Repo, Oracle}`, from install
registration, WI-12) must be non-empty, and each key must have a repo and an oracle and pass `oracle.ValidHarnessKey`:
a small-order point (the identity and the other torsion points, canonical or not, with either sign bit) verifies a
forged signature for any message, so it is `invalid-input`. A key signs only for its own repo and oracle key;
a signature by another repo's or another oracle's key is `report-unsigned`. `SignReport` fails (never panics) for a
wrong-size private key or a key ID that is empty or over 1 KiB; an unknown key ID or a signature that does not verify is `report-unsigned`. The
report is authenticated before it is parsed. **WI-12 invariant: the harness private key never enters either sandbox
or any step of the oracle job that runs candidate code**; without it the signature is worth nothing. The key ID and
signature shape follow the review attestations' (`internal/review`: key ID to ed25519 key, domain-separated payload).

**A boundary with nothing to observe** (for example a queue the system doesn't have) is reported `completed` with the
digest of the empty observed record set, observed externally by the harness. `denied` means the harness could not
observe the boundary and always blocks.

**Parser bounds.** The parser counts values while it reads, so memory is bounded by construction: at most
`13 × 4096 + 6 × 16384 + 277` values (an observation is 13 values, a difference 6, the fixed part 277 including at
most 256 overrides), arrays of at most 4096 items, objects of at most 256 keys, at most 1024 differences per
observation and 16384 per report. NUL characters in any string are rejected. Parsed with duplicate keys and unknown fields
rejected and depth bounded. Every string from it is escaped before display.
```json
{
  "schema": "lightsout.oracle/v1",
  "repo": "<forge repo id>",
  "job": {"runId": "...", "runAttempt": "...", "jobId": "..."},
  "baselineSHA": "...", "candidateSHA": "...", "oracleRevision": "...",
  "comparison": "exact/v1",
  "caseManifest": "sha256:...",
  "switchOverrides": {"new-key": "off"},
  "configs": {"requested": {"baseline": "sha256:...", "candidate": "sha256:..."},
              "loaded":    {"baseline": "sha256:...", "candidate": "sha256:..."}},
  "observations": [
    {"case": "checkout-happy", "boundary": "http-api",
     "baseline":  {"status": "completed", "fixture": "sha256:...", "digest": "sha256:..."},
     "candidate": {"status": "completed", "fixture": "sha256:...", "digest": "sha256:..."},
     "differencesComplete": true,
     "differences": [{"record": "cart/1", "operation": "GET /cart", "field": "/status", "before": 404, "after": 200}]}
  ]
}
```
- `digest` is the SHA-256 of the canonical observed record set for that (case, boundary, side). `loaded` configs are
  what the harness measured each process actually loaded.
- `before` and `after` are JSON scalars or null, at most 1 KiB each.

### Package `internal/oracle`
```go
func Evaluate(eff *contract.Effective, in Input) Decision
func ValidateManifest(data []byte, declared []contract.Observable) (Manifest, error)
func DeriveConfig(releaseDefaults string, overrides map[string]string) string
```
`Input`:
- `Target gate.Target` (forge, repo, PR, head, candidate) and `Evidence gate.Evidence`: the job executions at the
  candidate. `BaselineSHA`: the previous queue member's candidate, or the group base, derived by WI-18.
- `Kind`: `feature-dark`, `task` or `fix`, and `Issue` (the issue number the change implements).
  `Fix *FixAuthorization` is required for `fix` and forbidden otherwise. `HarnessKeys` are the registered harness keys.
- `ReleaseDefaults`: the release-defaults config digest.
- `Switches switches.Comparison` of the sets `Detect` read at `BaselineSHA` and `CandidateSHA`.
- `Reports`: per oracle (by GateRef), the manifest bytes read at `eff.Revision` and every artifact of the oracle job's
  run attempt: `{Name, SHA256, Bytes}`.

`FixAuthorization` (produced and authz-bound by WI-22, consumed here): `ID`, `Repo`, `Issue`, `ContractRevision`
(must equal `eff.Revision`, otherwise `invalid-input`), `Oracle` (contract.GateKey), `OracleRevision` and
`CaseManifest` (the manifest's hex digest; another value is `unauthorized-difference`, so an authorization can't be
replayed after the oracle is re-pinned), and `Deltas`, each `{Case, Boundary, Record, Operation, Field, Before, After}` with exact JSON
scalar values. Each delta authorizes exactly one difference.

Rules, in order. The first failure per oracle is its reason. All block unless noted.
1. Invalid input (nil contract, empty revisions, non-full head, baseline or candidate SHAs, baseline equal to
   candidate, PR ≤ 0, issue ≤ 0, release defaults that aren't `sha256:<64 hex>`, no harness keys, unknown kind, fix
   without or non-fix with an authorization, an authorization for another repo, issue or contract revision, a delta
   with an empty case or boundary or an oversized or non-scalar value) → `error` (`invalid-input`).
2. **Per-path coverage.** For every changed path in `eff.Paths`, take the oracles on its stack
   (`eff.Stacks[p.StackIndex].Oracles`) whose manifest `covers` it. There must be at least one (`oracle-missing`), and
   their boundaries together must include all five categories (`oracle-incomplete`). An uncovered path of the
   contract set (`eff.Uncovered`) is `oracle-missing`. A protected path (`PathPolicy.Protected`) is `protected-path`:
   protected paths never ride the oracle. Every applicable reason is reported, sorted. WI-18 must include both sides of every rename in the change's
   paths.
3. **Gate.** Call `gate.Evaluate` with an Effective whose VerifyGates are the change's oracle refs, all mandatory.
   The **whole** decision must be `pass`, so snapshot-wide reasons (malformed or unattributed evidence) block.
   Pending → `pending`, Error → `error`; otherwise `oracle-not-run`.
4. **Manifest.** The bytes must match the pin and pass `ValidateManifest` → otherwise `error` (`manifest-invalid`).
5. **Report binding.** Exactly one artifact named `lightsout-oracle-report` and one `lightsout-oracle-report.sig` in the
   run attempt (`report-missing` / `report-ambiguous`). Each artifact's SHA-256 equals its bytes
   (`report-unbound`), and the signature verifies under a registered key (`report-unsigned`; a malformed signature
   artifact is `report-malformed`), before the report is parsed. Its `job` equals the gate result's run, attempt and job. Its
   `repo`, `baselineSHA`, `candidateSHA`, `oracleRevision` (the GateRef's revision), `caseManifest` (the pin) and
   `comparison` equal the expected values → otherwise `report-unbound`. A report that fails strict parsing → `error`
   (`report-malformed`).
6. **First introduction.** `Switches.Verdict` must be `pass` (not just "not error"): a removed source or a changed
   switch blocks here too. Every `Switches.New` entry must have status
   `default-off` (a pass verdict alone isn't trusted), and `switchOverrides` must be exactly `Switches.New`'s keys,
   each `off` → `first-introduction`.
7. **Configs.** `requested.baseline` = `ReleaseDefaults`; `requested.candidate` = `DeriveConfig(ReleaseDefaults,
   overrides)` (equal to `ReleaseDefaults` with no overrides). `loaded` must equal `requested` on each side
   → `config-mismatch`.
8. **Coverage.** Exactly one observation per (case, boundary) in the manifest: none missing, extra or duplicated.
   Both sides `completed`, and each side's `fixture` equals the manifest's → `coverage`. Any other status, including
   `denied` on one or both sides, blocks in v1: a denied boundary is not shown to be inapplicable.
9. **Diff integrity.** `differencesComplete` must be true. Equal digests with differences, or unequal digests with
   none, is `report-inconsistent`.
10. **Differences.** For `feature-dark` and `task`, any difference → `difference`. For `fix`, each difference must
    consume a distinct delta that matches it on every field, with `Fix.Oracle` equal to this oracle's key;
    otherwise `unauthorized-difference`. Unused deltas are fine (the comparison is no broader than authorized).
    WI-18 separately requires the reproducer to fail on the baseline and pass on the candidate.

`Decision` binding fields are **raw** (authorization ID, override keys and values, config digests): callers compare and
store them, and a renderer escapes them. Evidence lines are escaped for control, bidi and ANSI characters but not for
Markdown, so renderers show them in a code span or block. Overrides are sorted `{Key, Value}` pairs. `Decision`: overall `Disposition` (`pass`, `pending`, `blocked`, `error`, ordered as in `gate`), one result per oracle
(GateRef, disposition, reason, run/attempt/job, report digest, observation count), and the binding: repo, PR, head,
both SHAs, requested and loaded config digests, overrides, `eff.Revision`, `eff.InstallRevision`, kind, issue,
authorization ID and manifest digests. A pass needs at least one oracle and at least one observation; empty evidence
never passes. A pass establishes only the comparison: a dark Feature still needs Acceptance (PIP-3).

### Known limits (follow-ups)
- **SDK code fallback.** The forced-off run exercises flagd's value, not the call site's fallback when the key is
  missing (WI-23 can't see call-site defaults either). A candidate whose code falls back to on passes. Fix: a third
  run with the key absent from the candidate's flagd config, compared like the others.
- **Trust in the harness.** Digests, loaded configs and difference lists are the harness's word. Evaluate checks that
  they are consistent and bound; qualifying the harness (Revision 3) is WI-12 plus registration.

### Implementation notes (WI-16)
Where the code made a choice the design left open:
- **Conflict encoding.** For stage `darkMergeOracle`, `Conflict.Revisions` entries are
  `"<workflowRevision>@<manifest sha256>;<sorted observables, comma-joined>"`.
  The struct is unchanged. A child contract that re-pins an ancestor's oracle with another revision or manifest digest
  fails validation (`conflict`), as a different revision did before.
- **Rule order.** Rule 2 reads each manifest's `covers`, so manifests are loaded first. A manifest whose bytes miss the
  pin or fail validation covers nothing: its paths report `oracle-missing`, and the oracle itself reports
  `manifest-invalid` (rule 4). Rule 2 failures are change-level (`Decision.Reasons`) and do not stop the per-oracle rules.
- **Rule 3.** The synthetic Effective also copies `eff.Conflicts`, so a pin conflict blocks. A pending or error gate
  decision is the oracle's disposition, with reason `oracle-not-run`.
- **Report limits.** An oversized report and a report that fails strict parsing are both `error` / `report-malformed`.
  Keys match exactly (case-sensitively); every field of the schema is required.
- **Scalars.** `before`/`after` and delta values are null, bool, string or a plain decimal number (no exponent), each
  at most 1 KiB. Numbers compare by value (`404` equals `404.0`); a string never equals a number.
- **Names.** The exported types are `Report` and `Result`, not `OracleReport` and `OracleResult`, to avoid stutter.
  `oracle.SignReport` builds the signature artifact, so the harness and the tests share one encoding.
- **Validator version.** `contract.validatorVersion` is 3 (the pin now covers observables), so stored trust digests go stale.
- **Config encoding.** See `DeriveConfig`: SHA-256 over length-prefixed fields, `"sha256:"` plus lowercase hex.
