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
   non-string mapping keys, duplicate keys and nesting deeper than 16. This stage is `internal/yamlsafe`, shared with
   the install config: `yamlsafe.Decode(data, Limits{MaxBytes, MaxDepth, MaxNodes, Name})` caps the byte size first,
   then checks the encoding (UTF-8, no byte-order mark, no NUL) and converts one YAML document to plain JSON values.
   Its `*Error{Code, Message, Path}` codes (`syntax`, `unsafe-yaml`, `too-large` and `schema` for an
   unrepresentable scalar) are the contract problem codes of the same name, and the messages and pointers are escaped
   the same way. Contract limits are 64 KiB, depth 16 and 10,000 nodes. A golden file
   (`testdata/yaml_pipeline.golden`) pins what the pipeline does to every fixture, recorded before the move.
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
    caseManifest: {path: ..., sha256: ...}   # the case manifest, pinned by digest (PIP-13)
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
| `gates.darkMergeOracle` (also) | safety, accumulate | A redeclared oracle identity must also keep the same `caseManifest` digest and the same `observables`, which must equal the manifest's boundary categories; they don't accumulate (PIP-13). A level that wants more coverage tightens by declaring another oracle, which accumulates. |
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
log must escape it (`WriteExplanation` does; WI-14).

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
- An `InstallRevision` that is not empty and not 40 or 64 lowercase hex digits.

`InstallRevision` is the commit of the install config the baseline came from (empty only in tests that build a
baseline by hand). `Effective.InstallRevision` carries it next to `Effective.Revision`, so evidence binds to both the
contract revision and the install revision, and the trust digest covers it. Changing a baseline gate therefore
cannot leave the policy identity of the evidence unchanged (RUN-1).

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

### Incremental validation (CON-13)

`ValidateChanged(ctx, set, baseline, defaults, ChangeOptions{Changed, Registry, TrustedDigest})` validates what
a change touched without re-validating the whole set. It returns a `Scope{Changed, Checked, CheckedDirs, Full}` so
tests and callers can assert exactly what ran.

- **Changed** are directories ("" is the root), never file paths. An entry that names a contract file, in any case or
  spelling (`svc/.factory.yaml`, `.FACTORY.YAML`, a look-alike with an invisible character), is rejected with an error
  wrapping `ErrInvalidPath` that says to pass the contract's directory. `ChangedDirs(paths)` maps changed repository
  file paths to the contract directories they affect.
- **Checked** are the changed contracts that exist, their dirKey ancestors, their dirKey descendants (a deleted
  contract's descendants too) and any directory whose dirKey collides with a changed one. Siblings are not checked.
  `CheckedDirs` are the same contracts as directories.
- Every Checked contract gets the full per-contract checks: schema re-validation and patterns, the relational checks,
  the stack-depth and gate caps, and collisions. Contracts outside Checked are not validated. Each check reads only the
  contract under test and the contracts above it, so a loosening in a changed contract, or a parent that re-pins a gate
  revision its descendant still pins to the old one, is found.
- **The trust premise.** Contracts outside the scope are valid only if they were validated at the trusted revision
  under the same baseline, defaults and validator. `TrustDigest(baseline, defaults)` (named for what it covers, which is
  more than the baseline) is a SHA-256 over a canonical encoding of every field of both (the baseline's
  `InstallRevision` included), the SHA-256 of the contract
  schema, a `validatorVersion` constant (2 since the install revision check) (bump it whenever a validation rule changes), `MaxStackDepth`, `MaxStackGates`
  and the default work budgets. WI-11 stores it with each trusted revision and passes it as `TrustedDigest`. If it is
  empty (unknown) or differs from the current digest, `ValidateChanged` validates every contract and sets `Scope.Full`.
- **CON-4.** With `Registry` set, the gates of *every* compiled contract, in scope or not, and of the baseline are
  checked in the same call (the same lookups as `CheckGates`), and their problems join the others in one
  `*ValidationError`. These are lookups, not relational proofs, so they are cheap, and authorization must come from the
  current registry and never from an earlier check: a gate registered when a contract was last validated may have been
  revoked since. The trust digest therefore does not cover registration. A registry error is returned wrapped and
  never counts as registered. A nil `Registry` skips the check; the activation path (WI-11) must always pass one.
- **Incremental validation is for PR feedback.** The relational work budget is shared across the whole set, so sibling
  contracts that each fit a scoped run can exceed it together in a full one. Activation (WI-11) must therefore run a
  full `Compile` (about 2 s in the worst case) before anything is activated, and not rely on a scoped result.
- An empty `Changed` validates no contract (unless `Full` is forced) and returns nil. A registry still checks every
  gate.
- `Compile` and `ValidateChanged` share one path: build the levels, then validate (which builds the stacks inside),
  with `Compile` passing every directory. `Compile` is as strict as ever and still reports a loosening in a contract
  nobody changed.
- Fail closed: the scope is closed under key-ancestors, so a contract in scope never sits under an unbuildable stack
  outside it. That closure is the primary guarantee; `validate` also reports, as defense in depth, any contract in
  scope whose stack could not be built. A stack that fails outside the scope is not reported and does not stop the
  checks inside it.
- Problems come back as a `*ValidationError`. A nil set, a bad baseline or defaults, a registry error, a cancelled
  context or an invalid changed entry is a plain error.

### Explain (CON-13)

`Policy.Explain(path)` returns an `Explanation{Revision, Effective PathPolicy}`: every effective value for the path and
the contract that set it. `ErrInvalidPath` and `ErrTooComplex` from `ForPath` pass through.

`WriteExplanation(w, e)` prints one line per value: access and its source, covered, the stack, protected, sensitive
and its sources, generated and its source, lightsOn and its sources, each override and its source, then every verify
and union gate (name, producer, workflow, check, revision, mandatory, owner, sources), each oracle and each reviewer
with its sources. Every string that came from the repository is escaped with the same helper as `Problem` text
(`display`). The escaped set is C0 and C1 controls, format characters (Cf: bidi overrides, tag characters), other
non-printable runes, invalid UTF-8, `\`, and `#` (as `\x23`, so a `##[command` cannot reach a CI log, where GitHub's
legacy runner parser finds it anywhere in a line). `quote` escapes `#` the same way, and so does the path-glob error text in `internal/pathglob`. `contract.EscapeText`
applies the same rules to any string; the CLI runs every error it prints through it, and `Load` never wraps a
`*fs.PathError`, which would print its path raw: an unreadable directory is a `invalid-path` problem and any other I/O
error carries the quoted name and only the underlying cause. The `flag` package's own error output is switched off for
the same reason. An escaped string is cut at about
4 KiB. Each is printed as one double-quoted token in which a
`"` is escaped as `\"`, so a hostile path or gate name cannot forge a line or close its quotes.

`Explanation.MarshalJSON` is the stable shape for `--json`: top-level keys `revision`, `path`, `covered`, `stack`,
`access`, `protected`, `sensitive`, `generated`, `lightsOn`, `switchStaleDays`, `switchAbandonedDays`,
`reviewBudgetLines`, `verifyGates`, `unionGates`, `oracles` and `reviewers`. Values that have a source are
`{"value", "source"}` (or `"sources"` for lists); empty lists are `[]`. Add fields, never rename one.
`encoding/json` escapes only the C0 controls (and `<`, `>`, `&`, U+2028, U+2029), so `MarshalJSON` also rewrites every
rune that `display` would escape (`#`, C1 controls such as U+0085 and U+009B, DEL, format characters such as U+202E
and tag characters outside the BMP) as `\uXXXX`.

### Registered gates (CON-4)

`GateRegistry` is defined here, by its consumer: `Registered(ctx, GateRef) (bool, error)`. Install config backs it in
v1 (WI-07), and the forge adapter backs it later. `Policy.CheckGates(ctx, reg, dirs)` asks it about:

- every verify gate, union gate and dark-merge oracle declared by the contracts in `dirs` (nil means all), and
- every baseline gate, always.

`dirs` entries are contract directories exactly as the set spells them. One that isn't (a file path, a case or NFC
variant, a directory with no contract) returns an error wrapping `ErrUnknownContractDir`; it is never skipped.

The answer is for the whole identity and pinned revision, so a registered identity at an unregistered revision, or a
foreign producer with the same check name, is unregistered. An unregistered gate is a `Problem` with code
`unregistered-gate`; `File` and `Field` point at the declaration (for example `/gates/verify/0`), and a baseline gate
has `File` "factory baseline" and a field like `/verify/0`. All are collected into one `*ValidationError`. A registry
error is returned wrapped, never as a problem and never as "registered", and stops the check. The check honors `ctx`
before every lookup. A gate repeated across contracts is asked about once but reported at every declaration.

### The `factory contract` CLI

`factory contract schema` prints the JSON Schema. `factory contract validate` and `factory contract explain` read the
contracts of a checkout with `os.DirFS(--root)`. In production the factory reads the tracked tree of a revision through
the forge; this command is for developers and CI checkouts, where the checkout is the tracked tree.

- `validate --revision <sha> (--gate-registry <file.json> | --no-gate-registry) [--root .] [--changed <dir>]...
  [--known-agent <name>]... [--trusted-digest <hex>]` prints one problem per line to stdout and exits non-zero
  on any. `--revision` (40 or 64 hex digits) is required; a missing or invalid one is a usage error. So is giving
  neither registry flag: skipping the CON-4 check must be explicit, and `--no-gate-registry` prints a note on stderr.
  `--gate-registry` is a JSON array of gate refs, decoded strictly: unknown, duplicate or case-variant keys, a missing
  or empty field, a revision that is not 40 or 64 lowercase hex digits, trailing data and a file over 1 MiB are errors.
  Without `--changed` the command is one full `ValidateChanged` call with the registry, so loosenings and unregistered
  gates are reported together. `--changed` (a directory, not a file path; a file path is a usage error) validates only
  the scope when `--trusted-digest` matches `trust-digest`, and everything otherwise, with a stderr note saying so.
  `--trusted-digest` without `--changed` is a usage error.
- `trust-digest (--install <file> --install-revision <sha> | --interim-defaults [defaults flags])` prints the trust digest of the
  baseline and defaults, so CI can pin it.
- `explain --revision <sha> [--root .] [--json] <path>` compiles the tree (a tree with problems prints them and fails)
  and prints the explanation. Flags come before the path.

`validate`, `explain` and `trust-digest` need a policy source: `--install <file>` with `--install-revision <sha>`, or `--interim-defaults`. The install config
(docs/design/install.md) then supplies the baseline, the defaults, the known agents and the gate registry, so none of
them can drift from what the factory uses. `--known-agent`, `--switch-stale-days`, `--switch-abandoned-days` and
`--review-budget-lines` are refused with it (a usage error, even at the default value), and so are `--gate-registry`
and `--no-gate-registry` on `validate`. An invalid install file prints its problems and fails before any contract is read.
`--install-revision` sets the policy identity (40 or 64 hex digits) and is required with `--install`; `--interim-defaults` can't be combined with `--install`. `factory install validate
<file>` checks an install file alone.

Without `--install` the command is a usage error unless `--interim-defaults` is given, because the interim policy has no secret-scan or dependency-scan gates (SEC-4) and must never apply silently. With `--interim-defaults` the interim CLI defaults apply and each command prints a stderr note saying so: `--switch-stale-days
30`, `--switch-abandoned-days 30`, `--review-budget-lines 300`; reviewers `pr-reviewer` and `security-reviewer` (PR
reviewer and security reviewer respectively); no baseline gates; protected `.github/workflows/**`, `.github/actions/**`
and every CODEOWNERS location (`install.DefaultProtected()`, seeded from `codeowners.Locations()`).

`Problem.String` renders `"file" "field": [code] message`, with File and Field quoted (a `"` escaped) so that a
directory named `::error title=x::y` cannot start a line and a `:` or `[` in a name cannot pass for the field or
the code.

Problems are returned as a typed `*ValidationError` holding `Problem{File, Field, Code, Message}` values, so
callers and tests branch on `Code` with `errors.As`. All four fields are escaped and bounded: they carry untrusted
keys and path names, and they end up in CI logs and PR comments, where a raw newline could forge a line.

## Dependencies

- `go.yaml.in/yaml/v3`: the maintained successor to the archived `gopkg.in/yaml.v3`. Needed to parse YAML at the
  node level. Used by `internal/yamlsafe`, which both contract and install parsing call.
- `github.com/santhosh-tekuri/jsonschema/v6`: a draft 2020-12 validator. CON-11 requires validation against the
  published schema, not an approximation of it. The schema compiles from embedded bytes, and the loader refuses
  every external reference, so validation never touches the file system or the network.
