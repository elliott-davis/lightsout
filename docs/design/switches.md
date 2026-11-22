# Switch detection and records (WI-23)

Status: accepted, 2026-11-22; revised after review (fix rounds 1 to 3). Covers WI-23: FLG-2 (follow the repo's switch
convention; new switches default off) and FLG-3 (record identity, owner, age, default and qualification status, and
show them on GitHub).

`internal/switches` is a pure package. It reads a repository tree at an exact revision (an `fs.FS`, as WI-08's git
tree provides) and produces the following:
- the detected switch definitions, and the entries it could not read
- a base→head comparison that blocks changes which can turn a feature on
- a `Record` type and a renderer for what GitHub shows

Storing records is left to WI-10 and WI-18, and publishing them to WI-12 and WI-18.

## Detection (FLG-2): judge what flagd would serve
Guessing at flagd's quirks does not work: flagd decodes leniently, matches field names case-insensitively, and splices
evaluators into the flag text by string replacement. So detection **ports flagd core v0.19.3's load pipeline** (in
`pipeline.go`, with each function citing its source and the Apache-2.0 attribution) and judges the **effective flag set**: the
flags flagd would serve. A **differential corpus** (`testdata/flagd-differential/`) pins the port to the real loader. Every
case is a file plus the flags flagd actually loaded from it, recorded by running flagd (see its README), and a test asserts the
port yields the recorded flags. This keeps the port honest without a flagd dependency.

### The pipeline
For one document:
1. **Extension** (`utils.ConvertToJSON`): everything in the extension that is not an ASCII letter or digit is removed (the class
   `[^a-zA-Z0-9]+`, so `é` and `ſ` go, and `.jsoné` is `json`), then lower-cased. It must be `json`, `yaml` or `yml`. A file
   with another extension, or none, is not loaded.
2. **YAML to JSON** (`utils.YAMLToJSON`): the **first document** is unmarshalled into a map, nested non-string keys are made
   strings with `%v`, and the map is marshalled. JSON goes through as it is.
3. **Transpose evaluators** (`evaluator.transposeEvaluators`): the text is normalized by a decode and re-marshal, and every
   `{"$ref":"name"}` is replaced by raw string replacement with the evaluator's text. flagd walks a map, so its order is random.
   The port walks the names in sorted order. The canonical form refuses every name that could matter, so the order is
   irrelevant to a canonical file.
4. **Decode** (`evaluator.configToFlagDefinition`): into flagd's flag model, whose tags match case-insensitively. `flags` may be
   an object or an array. A default variant must name a variant. A file flagd refuses at any step serves nothing.

### What is a source
A document is a **source** if any of these holds:
- the pipeline yields at least one flag with **non-empty variants**;
- its top level has any key that folds, under `encoding/json`'s rule, to `$evaluators` (the splice tripwire, which also catches a
  splice that lifts `flags` out of a nested object);
- it has the shape of an OpenFeature manifest (see below).

A flag without variants gives no value in flagd, so the SDK uses the code default. That is the same as a missing flag, a
documented residual. It also removes the false positives of any other tool's `flags:` key (Codecov, Helm, i18n, goreleaser).

Sources are looked for in:
- **Every candidate file.** The first YAML document is the file-level document, as flagd reads it.
- **Every string** of more than 16 bytes in any document of a candidate, including a top-level array and **every document of a
  multi-document YAML file**. It is decoded as JSON, and if that fails as YAML (first document), and the same test applies. A hit
  has the path `file#/pointer`, with the document number first for a multi-document file. The `#` is escaped like any text in a
  display, as `\x23`. This goes **one level deep**. Equal strings are decoded once.
- **FeatureFlag resources** in any document, at any of those places: `kind: FeatureFlag` with an `apiVersion` of
  `core.openfeature.dev/*`. Its `spec.flagSpec`, and the older `spec.featureFlagSpec`, are marshalled and go through the pipeline
  from step 3, as `kubernetes_sync.go marshallFeatureFlagSpec` does. The operator's typed conversion is not ported, and the
  canonical form refuses unknown keys. The path is `file#/spec/flagSpec`.

A symlink to a regular file in the tree is resolved one component at a time, and its target's bytes are probed under the link's
name and extension. `..` may not leave the tree, and no component may be a symlink, gitlink or other irregular entry. A link
that does not resolve is a problem if its name has a candidate extension, and an **opaque entry** otherwise.

### Canonical form
Every source is parsed strictly and must be canonical, and it must also be **equal to the effective set**. Anything else is a
problem, so the verdict is `error` and the check fails closed.
- **JSON** token by token: no duplicate key at any level, valid UTF-8, no byte-order mark, no trailing data, nesting within
  `MaxDepth`. **YAML** through `internal/yamlsafe`: one document, no anchors, aliases, merge keys, custom tags or duplicate
  keys, and string keys only. A YAML source with a later document is a problem. A YAML map whose keys collide after conversion
  (`1.0` and `'1'`) is a problem, as flagd keeps either at random. Floats are refused, so a YAML source with a decimal variant is a
  problem.
- **flagd file:** exact lower-case top-level keys from `$schema` (a string), `flags`, `$evaluators` and `metadata`. A key that
  folds to `flags` or `$evaluators` without being exactly that, such as `FLAGS`, is an unknown key. `$evaluators` without `flags` is
  a problem. `flags` is an **object** keyed by switch name, and the array form is a problem (`non-canonical-array`), as flagd
  accepts it and this check does not.
- **Each flag:** exact lower-case keys from `state` (`ENABLED` or `DISABLED`), `variants` (non-empty, every value one type of
  boolean, string, number or object, never an array or null), `defaultVariant` (a string or null), `targeting`, `metadata` and
  `description` (a string). The flagd schema omits `description`, but the OTel Demo uses it.
- **`$evaluators`:** an object. Each name matches `^[A-Za-z0-9_-]{1,64}$` and each value is a non-empty object. A name with quotes
  or braces rewrites other flags (confirmed against flagd).
- **`metadata`,** at the top level and per flag: an object of string, number and boolean values.
- **`$ref`** is allowed only inside a flag's `targeting`, as an object with exactly that one key whose string value names an
  evaluator of the same file. Any other `$ref`, anywhere, is a problem.
- **`defaultVariant: ""`** is an absent default (flagd treats it so), so the switch is `unproven-default`.
- **Equal to the effective set:** the canonical flags must equal what flagd serves from the source, for every key: state, default
  variant, variants and whether there is targeting. If they differ the problem is `non-canonical-effective`.
- **OpenFeature manifest:** top-level `$schema` and `flags` only. Each flag has `flagType` (`boolean`, `string`, `integer`, `float`
  or `object`), a `defaultValue` of that type, and an optional `description`. An integer is a JSON number with no fraction or
  exponent. A manifest never makes a flag in flagd, so its shape (an entry with `flagType` and no `state` or `variants`) is a
  third reason for a document to be a source. A file whose flags mix flagd and manifest entries is a problem.
- **Explicit manifest.** `.openfeature.json` or `.openfeature.yaml` (YAML read with `internal/yamlsafe`) may set `manifest`. The
  path must pass `pathglob.ValidatePath` and contain no wildcard. A config that is unparseable, not an object, symlinked or
  oversized, both files present, or an invalid path is a problem, and no manifest is read. Other config keys are ignored. A path
  that does not exist is a problem. The file at the path is read once, strictly, as a manifest, whatever it holds.
- A flag with a defect is kept as an `Invalid` definition, so its key is not mistaken for new. A defect that makes a whole file
  unreadable yields no definitions. `Definition.Path` is the file path, or `file#/pointer` for an embedded source.

### Limits
`DefaultLimits()` is the only source. The zero value is `ErrInvalidLimits`. Exceeding a budget is `ErrTooLarge` and returns
no Set, except where the table says it is a problem for one file.

| Limit | Default | Trade-off |
| --- | --- | --- |
| `MaxEntries` | 200,000 | Every tree entry visited. A larger tree is refused, not sampled. |
| `MaxFileBytes` | 16 MiB | The git tree serves at most 10 MiB, so every file it serves is probed in full. A larger candidate, or one the tree will not serve, is a `too-large` problem with no token shortcut. A repo with a JSON or YAML file that large gets an error until WI-23a adds an exclusion mechanism. |
| `MaxTotalBytes` | 512 MiB | Bytes read from candidates, plus the YAML-to-JSON and embedded-string decodes, charged before each read. Over is `ErrTooLarge`. |
| `MaxDepth` | 64 | Nesting of strictly parsed files and of the probe walk. Deeper is a `too-deep` problem for that file, so nothing can hide below the cap. |
| `MaxFlagsPerFile` | 10,000 | More is `ErrTooLarge`. |
| `MaxDefinitionsPerKey` | 64 | Bounds the work to compare the sources of one key. More is `ErrTooLarge`. |
| `MaxNodes` | 1,000,000 | Values visited in one pass over a file, counting every expansion of a YAML alias, and the bytes of text they hold (capped at `MaxFileBytes`). The conversion of a YAML document and the search for embedded sources are separate passes with a budget each. More is a `too-large` problem for that file. The walk checks the context every 1,024 nodes. |

A returned error never embeds a raw repository path: it is escaped, and the chain keeps the original for `errors.Is`.

## Status of a switch
The first rule that matches wins:
1. `invalid`: a definition had a problem.
2. `conflicting`: two sources disagree. flagd files must have the same signature: type, state, variants, default variant,
   targeting, flag metadata, and the file's `$evaluators` and top-level metadata (path and description are ignored). A manifest
   must have a compatible type (number, integer and float are compatible) and the same default as the first flagd file and the
   first manifest. Each is compared with the first of its kind only, because equality is transitive.
3. `not-boolean`: a source is not a boolean.
4. `default-on`: a source says on by default.
5. `unproven-default`: the flag is `DISABLED`, has no `defaultVariant` (absent, null or `""`), has any `targeting` key (even `{}`
   or `null`), or there is no flagd source. A manifest alone is unproven because no SDK reads it. Proving that a JsonLogic rule
   never returns the on variant is out of scope for v1.
6. `default-off`.

## Compare(base, head)
A key is **new** for FLG-2 when it has no flagd definition at the base. Manifest definitions do not count. A switch the
manifest alone defines at both revisions is not new, and a change to it is only reported (a manifest default flip is
reported, not blocked).

The verdict is `error` if either set has a problem or was not made by `Detect` (a zero `Set` is never a pass). Otherwise it is
`blocked` if any of these holds, and `pass` if none does:
- **new-not-default-off:** a new switch is not `default-off`. A new switch with no flagd definition is `unproven-default`.
- **activation-in-pr:** an existing flagd switch's runtime definition changed (any flagd source, or the `$evaluators` and
  top-level `metadata` of its file, which carries `flagSetId`) and the head is not `default-off`, whatever the base was. Or it
  was `default-off` and no longer is, such as a manifest that now disagrees. A change to a description only passes.
- **removal-in-pr:** a base (key, flagd path) pair is not at the head, whether the switch was deleted, moved to another
  file, or lost one of several sources. Without it the SDK returns the code default, which may be on. `Removed` lists one
  change per path. Cleanup is a later phase (FLG-7).
- **opaque-source:** an opaque entry at the head is new, or differs from the base in kind or target. The tree does not
  expose a gitlink's commit, so a gitlink at the same path at both revisions is taken as unchanged (WI-23a).

**Decision deferred ([#11](https://github.com/elliott-davis/lightsout/issues/11)).** P2 says releasing a feature is a separate
human decision, and the PRD does not say whether a PR may change an existing switch. Until #11 is decided, this takes the
stricter reading: **it blocks every PR that changes a switch that is
on or has targeting**, and every PR that activates or removes a default-off one. `Compare` reports every change in `New`,
`Removed` and `StatusChanged`, whether or not it blocks. Only a change with a `Reason` blocks.

## Records (FLG-3)
A `Record` is `{Key, Repo, Description, Sources, Owner, FirstSeenRevision, FirstSeenAt, Default, Qualification}`.
- `NewRecord(repo, sw, rev, at, owner)` sets `Default` from `sw.Status()`, so a switch that is not default-off cannot be
  recorded as off. It sets Sources (sorted, distinct) and Description (the first non-empty).
- **Owner** is an input: the feature's contract owner or ideator, resolved by WI-18. This package never infers it.
- **Qualification** is `none` (the zero value), `acceptance-passed` (needs a run reference), `union-qualified` or
  `union-blocked` (both need an Acceptance run and a Union manifest ID). `Validate()` checks it, and `Render` returns an error
  for an invalid one and writes nothing.
- **Age** is `now − FirstSeenAt`, with `now` injected: minutes, hours (under 48) or days, `under a minute` if negative, and
  `unknown` if the time is zero.

`Render(w, records, now)` writes a Markdown table for a GitHub check: whether the switch defaults off (the word `off` only for
`default-off`), the Acceptance status, the manifest that tested the proposed setting (shown for the union states only), the
owner and the age. Rows are sorted by every field. Every string is escaped for Markdown and CI annotations, as in WI-04 and
WI-09: control characters, backslash and `#`, then `@ < > & ` [ ] ( ) | * ~ !` and `::`, and autolinks are broken
(`://` becomes `:\/\/` and `www.` becomes `www\.`). The golden test is `testdata/render.golden`, updated with `-update`.

## Fixtures
`testdata/otel-fc7f2a68dcf9/` is the upstream OTel Demo `src/flagd/demo.flagd.json` at that commit, with its source and
Apache-2.0 attribution in its README. `testdata/handwritten-demo-shape/` is a small hand-written file in the demo's shape. It
is not the OTel Demo.

## Known gaps (WI-23b, [#8](https://github.com/elliott-davis/lightsout/issues/8))
The file-delivered path is verified against flagd (the differential corpus and 100k fuzzed files). The Kubernetes delivery
path still has four open HIGH findings, each of which lets an on switch pass or wedges the check:
- a YAML document that yaml.v3 cannot decode (duplicate keys, which kubectl accepts) is skipped with every source in it;
- FeatureFlag resources inside `kind: List` / `items` are not searched;
- FeatureFlag YAML is read as YAML 1.2, while kubectl and Helm deliver YAML 1.1 (`on`, `yes`, `true` keys collide);
- the canonical check's evaluator transposition has no output budget (denial of service).

## Residual risks (WI-23a, [#9](https://github.com/elliott-davis/lightsout/issues/9))
- **Differential corpus against new flagd versions.** Run `testdata/flagd-differential/` against each new flagd release, and add
  the cases a review finds. A change in a recorded result means the port and the canonical form must be reviewed. The corpus is
  recorded with `tools/fdump`, built from flagd core in its own module so it never joins the main module's bill of
  materials. Where it lives long term, and whether CI runs it, is open ([#10](https://github.com/elliott-davis/lightsout/issues/10)).
- **Exclusions.** A repo with a JSON or YAML file over 16 MiB gets an error. Keep an exclusion mechanism on the list.
- **Code defaults at call sites.** A flag without variants, a missing flag and a provider error all return the code default. This
  package reads the flag file and cannot see the call site, so a call site that defaults to `true` is not detected.
- **`--uri`.** flagd `--uri` references in compose, Kubernetes and Helm files are not resolved, and neither are mounts that
  **rename** files. Every candidate file and every embedded string is searched, so a source in the repo is found wherever it is
  named, but a source built at deploy time (a template, a remote URL) is not seen.
- **Base64 and `binaryData`.** A Kubernetes Secret's `data` and a ConfigMap's `binaryData` hold base64, which is not decoded.
- **Second-level embedding.** A source inside a string inside an embedded source is not found.
- **Gitlink commits.** The tree does not expose the commit of a gitlink (`gittree` gives no `Sys()`), so a submodule bump is not
  seen as a change.
- **Manifest code defaults.** A manifest default flip is reported only. Revisit it if generated OpenFeature code uses manifest
  defaults.
- **FeatureFlag typed conversion.** The operator's conversion of a FeatureFlag resource is not ported (its module is not
  available to flagd's own tests here), so its handling of fields it drops is judged by the canonical form's refusal of unknown
  keys.
