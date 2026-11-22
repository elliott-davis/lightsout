# Contract schema and resolver (CON-*)

Status: accepted after a Codex review, 2026-11-21. Covers CON-1, CON-3, CON-4 (static validation and the registry check), CON-5, CON-7
(path classification only), CON-9, CON-11, CON-12 and CON-13, plus the contract-side parts of AGD-3 and SEC-5.
Activation and ownership (CON-2, CON-6, CON-10) and the Verify-time enforcement (CON-7, CON-8) are separate work
items in [the backlog](../backlog.md). They consume the types defined here.

## Packages

| Package | Responsibility |
| --- | --- |
| `internal/pathglob` | Anchored path globs: compile, match, and a conservative containment proof (`A ⊆ B`). No dependencies. |
| `internal/contract` | The `.factory.yaml` v1alpha1 schema (embedded JSON Schema), safe parsing, tree loading, the effective-contract resolver, relational validation, incremental validation and explain. |
| `cmd/factory` | `factory contract schema`, `factory contract validate`, `factory contract explain`. |

## Parsing untrusted contract files

A contract is repo content and untrusted until activated (SEC-1). Parsing is staged so that each layer fails closed:

1. **Size and shape.** Reject files over 64 KiB, multiple YAML documents, anchors and aliases, custom tags,
   non-string mapping keys, duplicate keys and nesting deeper than 16.
2. **JSON Schema.** Convert the YAML node tree to plain JSON values and validate them against the embedded,
   versioned schema (`internal/contract/schema/v1alpha1.json`). Every object sets `additionalProperties: false`, so
   any unknown field, including `command`, `run`, `script` or `steps`, fails (CON-11, CON-4).
3. **Strict decode.** Decode the same JSON values into Go types with `DisallowUnknownFields`, so the schema and the
   Go types cannot silently drift. A test also asserts that every schema property has a merge rule (see below).

Discovery walks an `fs.FS` that must be the repository's **tracked tree at the policy revision** (a full commit
ID). In production that is a git-tree reader from the forge layer (WI-08), never a working tree. As defence in depth,
discovery skips any subtree containing a `.git` entry (submodules and nested repos are another trust domain),
rejects symlinked and non-regular contract files, and reports near-miss names (`.factory.yml`, `.Factory.yaml`) as
errors rather than skipping them silently. Every pattern is compiled during parsing, so a `Set` never holds a
pattern the resolver can't evaluate.

Text must be UTF-8 without a byte-order mark. Integers must be plain decimal; floats are rejected.

## Path globs

Patterns are anchored at the contract's directory and use `/` separators. Supported syntax: literal segments, `*`
and `?` within a segment, and `**` as a whole segment (zero or more segments). Rejected: leading `/`, `.` and `..`
segments, empty segments, `\`, `[`, `{` and NUL. The smaller syntax keeps containment provable.

Patterns are case-sensitive, like git paths. Patterns and gate names reject Unicode control and format characters
(bidi overrides, zero-width characters), so an approver sees what the matcher sees. Segments that come from a contract's directory, added when a pattern is
rebased to repository coordinates, are literal even if the directory name contains `*` or `?`.

`Contains(b, a)` returns true only when it can prove every path matched by `a` is matched by `b`. Anything it
cannot prove is reported as not contained, so loosening checks fail closed. `Witness(b, a)` tries a few concrete
paths, so an error can say "for example `svc/x/y.go`" when it finds a real counterexample and "could not prove"
when it doesn't. A proof against the *union* of several ancestor patterns is deferred: in v1 a child pattern must
fit inside a single ancestor pattern.

## The v1alpha1 contract

```yaml
apiVersion: factory/v1alpha1     # required, exact
kind: Contract                   # required, exact
paths:
  writable: ["**"]               # absent = no opinion; [] = nothing writable here or below
  readOnly: ["api/protos/**"]
  forbidden: ["deploy/**"]
  sensitive: ["src/checkout/payment/**"]
  generated: ["gen/**"]
gates:
  verify: [<gate>, ...]
  union: [<gate>, ...]           # smoke and contract gates at Union (PIP-5)
  darkMergeOracle:               # always mandatory; no `mandatory` field, `name` optional
    producerId/workflowId/workflowRevision/checkId: ...
    observables: [responses, reads, writes, events, queued-jobs]
agents:
  verify: [security-reviewer]
lightsOn: false
overrides:
  switchStaleDays: 45
  switchAbandonedDays: 30
  reviewBudgetLines: 300
```

A gate is `{name, producerId, workflowId, workflowRevision, checkId, mandatory}`, and every field is required.
`name` is display only. Gate identity is `(producerId, workflowId, checkId)`. A gate *obligation* is the identity
plus `workflowRevision`, a full 40- or 64-hex commit ID, because PIP-2 requires the execution to match the pin.
`workflowId` accepts a positive integer, kept exactly (no float64 round trip), or a string, so later forges fit
without a schema change.

Fields the PRD needs from contracts in later work items (INT-10 switch requirement, INT-17 fix authorizations,
NFR-6 provenance trailer, PIP-11 root-only train cadence, PIP-13 oracle inputs and nondeterminism) are added by
those items. v1alpha1 is an alpha version, so additions are backward compatible. Until a field exists, the
operation that needs it is blocked; it is never assumed.

## Merge rules (CON-12)

Every schema leaf has exactly one rule, held in a table in code. A test walks the schema and fails if a property has
no rule or a rule names a property that doesn't exist.

| Field | Class | Rule |
| --- | --- | --- |
| `paths.forbidden`, `paths.readOnly`, `paths.sensitive` | safety, accumulate | Union down the tree. |
| `paths.writable` | safety, narrow | A path is writable only if it matches the writable list at every level that declares one. |
| `gates.verify`, `gates.union`, `gates.darkMergeOracle` | safety, accumulate | Union of obligations. A redeclared identity on the same stack must keep the same revision (two pins on one stack can never both pass) and may only raise `mandatory`. |
| `agents.verify` | safety, accumulate | Union, always including the factory's core reviewers (`pr-reviewer`, `security-reviewer`). |
| `lightsOn` | safety, only on | OR down the tree. An explicit `false` under an ancestor's `true` is an error. |
| `overrides.*`, `paths.generated` | override | The lowest level that sets it wins, else the install default (CON-9). |

`paths.generated` is an override because it only tunes the soft review budget (INT-19), which is itself an override.
Hard rules (INT-18 "generated output rides with its source", PIP-10 overlap of hand-written files) must not trust
it alone. They need independent evidence such as linguist attributes and `DO NOT EDIT` headers.

### Path access

For a path `p`, each contract on its stack (the contracts in `p`'s ancestor directories) gives a local verdict:
`Forbidden` if a forbidden pattern matches, else `ReadOnly` if a read-only pattern matches, else `Writable` or
`None` if the level declares `writable`, else no opinion. The effective access is the minimum over the stack in the
order `Forbidden < None < ReadOnly < Writable`. An uncovered path is `None` and is reported as uncovered (CON-1).

The topmost contract on every stack (one with no ancestor contract) must declare `paths.writable`, even as `[]`.
Otherwise a gates-only parent followed by a child that grants `writable: ["**"]` would widen access from nothing to
everything. Below the top, an absent `writable` inherits.

The minimum makes loosening ineffective by construction. Validation still reports an attempted loosening (CON-12):

- A child `writable` pattern must be provably contained in some `writable` pattern of every ancestor that declares
  one.
- A child `readOnly` pattern must be provably contained in some `writable` or `readOnly` pattern of every ancestor
  that declares `writable`.
- A child `writable` or `readOnly` pattern provably inside an ancestor's `forbidden` pattern, or a child `writable`
  pattern provably inside an ancestor's `readOnly` pattern, is an error. Partial overlap is allowed, because the
  minimum already keeps the ancestor's restriction and globs can't express exclusions. These checks account for the
  descendant rule below.

Verify (WI-14) reads CON-7 literally: a change is admitted when every path is writable, or when every path is
read-only and a current path owner approves. A mixed change fails.

### Deny lists err towards blocking

`forbidden`, `readOnly` and `sensitive` use two extra rules that `writable` doesn't, decided after the security
review. Both only ever widen what's denied, so neither can loosen anything:

- **Descendants.** A deny pattern also covers everything below a path it matches, so `forbidden: [deploy]` covers
  `deploy/prod.yaml` the way CODEOWNERS readers expect.
- **Folded variants.** A path is also denied when its case-folded, NFC-normalized form matches the folded pattern.
  Otherwise `DEPLOY/x` would slip past `deploy/**` and land in `deploy/` on a case-insensitive checkout.

### Baseline

The resolver takes a `Baseline` from install config: the factory's mandatory gates (secret and dependency scanning,
SEC-4) and core reviewers (AGD-3). Baseline entries carry owner `factory`. A contract that redeclares a baseline
gate identity as advisory fails validation (CON-5).

## Resolving and explaining

- `Resolve(set, baseline, defaults, paths)` returns the effective contract for a change: per-path access, sensitive
  and generated flags and overrides, plus the union of gates and agents over every touched path's stack and the OR
  of `lightsOn` (CON-3). Each value records the contract directory that set it, or `install default` or
  `factory baseline`. The result carries the policy revision (the commit the contract set was read from), so later
  evidence binds to it. The same identity pinned at two revisions across different stacks is reported as a
  conflict, which Verify treats as a block. Change-level decisions such as the review budget (WI-14 uses the
  smallest applicable budget) belong to the consumer.
- `Explain(path)` lists each effective value for one path and its source (CON-13).
- `ValidateChanged(set, changedDirs)` validates the changed contracts, their ancestors and their descendants, and
  returns the set it checked so tests can assert the scope (CON-13).
- `CheckGates(ctx, eff, registry)` asks a consumer-defined `GateRegistry` whether each gate's producer, workflow and
  pinned revision are registered (CON-4). Install config backs it in v1; the forge adapter backs it later.

Problems are returned as a typed `*ValidationError` holding `Problem{File, Field, Code, Message}` values, so
callers and tests branch on `Code` with `errors.As`. All four fields are escaped and bounded: they carry untrusted
keys and path names, and they end up in CI logs and PR comments, where a raw newline could forge a line.

## Dependencies

- `go.yaml.in/yaml/v3`: the maintained successor to the archived `gopkg.in/yaml.v3`. Needed to parse YAML at the
  node level.
- `github.com/santhosh-tekuri/jsonschema/v6`: a draft 2020-12 validator. CON-11 requires validation against the
  published schema, not an approximation of it. The schema compiles from embedded bytes, and the loader refuses
  every external reference, so validation never touches the file system or the network.
