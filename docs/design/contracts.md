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

For a path `p`, each contract on its stack gives a local verdict: `Forbidden` if a forbidden pattern matches, else
`ReadOnly` if a read-only pattern matches, else `Writable` or `None` if the level declares `writable`, else no
opinion. The effective access is the minimum over the stack in the order `Forbidden < None < ReadOnly < Writable`.
An uncovered path is `None` and is reported as uncovered (CON-1).

Each directory segment has a canonical key, `dirKey`: NFC, upper then lower case, full case fold, NFD with combining
marks removed, default-ignorable code points removed (soft hyphen, zero-width characters, variation selectors and
so on), trailing dots and spaces trimmed (NTFS drops them), NFC. A contract at directory `d` is on `p`'s stack when
`d` is the root, or the first segments of `p` have the same keys as the segments of `d`. Membership is one lookup per
key prefix, so every stack is a chain and no two members are unrelated. `DEPLOY/prod.yaml`, `deploy./prod.yaml` and
`dep\u00adloy/prod.yaml` all get the rules of `deploy/.factory.yaml`, including its gates, reviewers, sensitive paths
and lights-on mode. The key over-conflates on purpose: that only adds contracts to a stack, which can only tighten.
The patterns of a `writable` list stay case-sensitive, so the child's `deploy/**` does not match `DEPLOY/x` and that
level says `None`. Two contract directories with the same key sequence, such as `deploy` and `DEPLOY`, are an error
(`conflict`, on the later one in sorted order), because a case-insensitive checkout would merge them. An incremental
validation scope must include a changed contract's key-ancestors, key-descendants and any directory whose key
collides with it.

Factory checkouts are case-sensitive Linux. The keys and folded forms defend against case-insensitive or normalizing
checkouts elsewhere. NTFS 8.3 short names are not modeled.

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
  descendant rule and the folded forms below.

Verify (WI-14) reads CON-7 literally: a change is admitted when every path is writable, or when every path is
read-only and a current path owner approves. A mixed change fails.

### Protected paths

Contract files never come back writable to an agent. A path whose last segment is `.factory.yaml` or `.factory.yml`,
in any form below, is `Forbidden` with the source `factory protected path`, and `PathPolicy.Protected` is true.
Contract changes go through their own review path (CON-2, CON-6). `Baseline.Protected` adds root-anchored patterns
from install config, such as `.github/workflows/**` and `CODEOWNERS`. They follow the deny rules and give the same
result.

### Deny lists err towards blocking

`forbidden`, `readOnly`, `sensitive` and protected paths use two extra rules that `writable` doesn't, decided after the
security review. Both only ever widen what's denied:

- **Descendants.** A deny pattern also covers everything below a path it matches, so `forbidden: [deploy]` covers
  `deploy/prod.yaml` the way CODEOWNERS readers expect. The matcher uses `pathglob.Pattern.WithDescendants`, which
  appends a `**` to the compiled pattern, so it works for a pattern of any length.
- **Folded forms.** A path is also checked in four other forms, so a case-insensitive or normalizing checkout can't
  slip past a pattern. Patterns are ASCII, so they are lower-cased and anchored under the same form of the
  contract's directory. Forms 1 to 3 first `clean` each segment: NFD, drop combining marks, drop default-ignorable
  code points, trim trailing dots and spaces, NFC (a precomposed letter is still one rune, so `?` still counts one).
  Then they apply one case step, so a name that is both a case variant and carries a trailing dot or an invisible
  character (`deploy./ß.yaml`) is still caught.
  - Clean, then full case fold: the Kelvin sign becomes `k`, `ß` becomes `ss`, `ﬁ` becomes `fi`.
  - Clean, then simple per-rune lower case, so `?` still counts one rune: `DEPLOY/ß.yaml` matches `deploy/?.yaml`.
  - Clean, then `lower(upper(p))`, so dotless `ı` behaves as it does on NTFS: `ınfra/x` matches `infra/**`.
  - The skeleton: `dirKey` of each segment, so `deploy./x` and a soft hyphen inside `deploy` still match, and
    accents are ignored (`café/x` matches `cafe/**`).

  Spellings a filesystem treats as one name can differ in rune count (`ß` and `ss`, `ﬁ` and `fi`, NFC and NFD), so in
  the four folded forms each `?` of a deny pattern widens to `*` within its segment. `deploy/?.yaml` also denies
  `deploy/ss.yaml`. This only widens what is denied. The exact form keeps `?` at one rune, and `writable` never uses
  folded forms.

If a folded form is not a valid path (folding can push it past the length limit, and the skeleton can empty a segment),
the path can't be checked in every form. `ForPath` and `Resolve` return an error wrapping `pathglob.ErrInvalidPath`
instead of a result.

A `readOnly` match that exists only in a folded form never raises a verdict. It caps the level's own verdict at
`ReadOnly`: with `writable: ["src/**"]` and `readOnly: ["api/**"]`, `API/x` is `None`, not `ReadOnly`. Forbidden,
sensitive and protected matches count in any form.

A path segment is at most 255 bytes (NAME_MAX), so a longer one is `ErrInvalidPath`. It can't exist on any supported
filesystem, and the cap bounds the work of matching one segment.

Work is bounded so a hostile tree can't stall the resolver. All limits fail closed. The budgets count units of
work, not segments: matching a pattern against a path costs `(pattern runes + 1) * (path runes + 1) + 16`, an
upper bound on the matcher's steps, and a containment proof costs `(outer runes + 1) * (inner runes + 1) + 16`
(`Pattern.Runes`). A witness search for an error message charges every match it makes, and is skipped quietly when
the budget can't cover it.

- A path may have at most `MaxStackDepth` (32) contracts on its stack. `Compile` checks this first, from the tree,
  before any proof runs, and reports `too-many`.
- A stack may carry at most `MaxStackGates` (512) obligations per stage (verify, union), counting the baseline's.
  The contract that crosses the limit gets `too-many`. This is the backstop that keeps the merged data small.
- `Compile` spends at most 650 million units on proofs, merges and gate lookups. Running out is a `too-many`
  problem and no policy.
- `ForPath` spends at most 16 million units, including one per obligation it copies. `Resolve` accepts at most
  `MaxResolvePaths` (20000) paths and spends at most 1.6 billion units in total, including the copy and the merge
  of each distinct stack. Exceeding a budget returns an error wrapping `ErrTooComplex`, which Verify treats as a
  block. A partial answer is never returned: a match that ran out of budget is not read as "no match".

The measured cost of a unit is 0.01 to 2.7 ns on the development machine (`BenchmarkUnitCost_*`), and the budgets
assume 3 ns, so the worst cases are about 2 s for `Compile`, 50 ms for `ForPath` and 5 s for `Resolve`. A realistic
tree (the PRD example plus three levels of about 20 short patterns per list, 10,000 paths of 3 to 8 segments)
uses about 0.1% of the `Compile` budget, 0.2% of the `ForPath` budget at worst and 1.4% of the `Resolve` budget.
Measured worst cases:

- 32 levels of 15 gates per stage (481 per stage), 20,000 paths under the deepest contract: `Resolve` takes about
  0.34 s and keeps about 11 MiB.
- 32 levels of 64 gates per stage, the shape that used to need 15.9 GB: `Compile` fails in about 30 ms with
  `too-many`.
- 1000 hand-built contracts (a 31-deep chain and 969 leaves with 64 verify and 64 union gates each): `Compile`
  takes about 1 s.

The budgets are unexported fields of `Policy`, so tests can lower them to prove the fail-closed paths.

`PathPolicy` and `Effective` carry raw repository path text. A consumer that writes it to a PR comment, check run or
log must escape it (WI-04 explain, WI-14).

### Baseline

The resolver takes a `Baseline` from install config: the factory's mandatory gates (secret and dependency scanning,
SEC-4), core reviewers (AGD-3) and protected paths. Baseline entries carry owner `factory`. A contract that redeclares
a baseline gate identity as advisory fails validation (CON-5). `Compile` checks the baseline itself and returns a plain
error for any of these:

- A baseline gate that isn't mandatory, or a duplicate identity in a stage.
- A gate that fails the contract schema: an empty producer, a non-hex revision, a name with a newline.
- A reviewer or known-agent name that isn't a valid agent name.
- `PRReviewer` or `SecurityReviewer` that isn't one of `Reviewers`, or the same role for both. They are the two
  independent core reviews, so every change gets both (AGD-1, AGD-3).
- An invalid protected pattern.

`SecurityReviewer` is the role whose sign-off a sensitive path needs (SEC-5), and the effective contract carries it
so the consumer knows whom to require.

A `Policy` copies everything it needs from the contracts, and `Compile` re-validates each contract against the schema,
so a hand-built contract is held to the same rules as a parsed one.

## Resolving and explaining

`Compile(set, baseline, defaults)` returns an immutable `Policy`, or a `*ValidationError` with every problem. Two
methods read it. Both are safe for concurrent use.

- `Policy.ForPath(path)` returns the effective contract for one path: access and its source, sensitive, generated
  and protected flags, overrides, and the gates and reviewers of its stack.
- `Policy.Resolve(paths)` returns the effective contract for a change (CON-3): per-path results plus the union of
  gates and reviewers over every touched path's stack and the OR of `lightsOn`. Each value records the contract file
  that set it, or `install default` or `factory baseline`. The result carries the policy revision (the commit the
  contract set was read from), so later evidence binds to it. The same identity pinned at two revisions across
  different stacks is reported as a conflict, which Verify treats as a block. Change-level decisions such as the review
  budget (WI-14 uses the smallest applicable budget) belong to the consumer.

Stacks are chains, so there is one distinct stack per contract (plus the baseline-only stack for paths no contract
covers). `Compile` merges each stack's gates, oracles, reviewers and lights-on sources once, from its parent's merged
result and its own declarations, and keeps them immutable in the `Policy`. `ForPath` returns a fresh copy of its
stack's merge. `Resolve` groups the touched paths by stack: `Effective.Stacks` holds each distinct stack's lists
once, each `PathPolicy.StackIndex` points into it, and the per-path gate, oracle and reviewer slices are nil. The
change-level lists are the union over the distinct stacks, so the cost is per stack and not per path.

The same per-stack index serves the relational gate checks: each stack indexes its gates by identity, with the
first pinned revision and the first mandatory declaration, so each gate of a contract is one lookup.

`Compile` also skips its schema pass for a contract the `Parser` built and nobody has changed. The parser stores the
SHA-256 of the contract's canonical JSON after validating it. Any later change to any field changes the JSON, so a
mutated or hand-built contract has no matching digest and is validated in full.

Not built yet (WI-04):

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
