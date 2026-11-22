# Install config (WI-07)

Status: accepted after a Codex review, 2026-11-21. Implemented by WI-07 (`internal/install`, `internal/yamlsafe`, `factory install`, `--install`). The section "As built" at the end records what the code settled. The install config holds:

- defaults for timers and caps (AGT-5, INT-15, PIP-15, REC-3, COST-2/3/4/7)
- the factory baseline: SEC-4 gates, AGD-3 core reviewers, protected paths
- the gate registry (CON-4)
- the install policy approvers and the emergency admins (SEC-6)
- one pinned runtime, harness and model profile per enabled role (RUN-6, AGT-7)
- the inputs for the signed qualification check that runs before admission (NFR-2)

Install validation rejects any role that could combine untrusted input, secrets and open egress (SEC-1).

## Principles

- **IT-owned, versioned and pinned (RUN-1).** The config lives in git. The factory loads only an activated revision, and every
  decision and piece of evidence records that revision.
- **Parsed as strictly as a contract.** The bounded YAML-to-JSON conversion moves from `internal/contract` into a shared
  `internal/yamlsafe` package. It caps the byte size before decoding, rejects anchors, aliases, custom tags, duplicate keys and
  multiple documents, and caps depth and node count. Each consumer keeps its own embedded schema, typed decoder and semantic checks.
  The extraction must leave contract parsing byte-for-byte identical, including values, error codes and pointers, and the existing
  contract tests pin that.
- **One source for every default.** `internal/install` produces:
  - `contract.Baseline` and `contract.Defaults`
  - `authz.Config` and the admin and approver `authz.RoleSource`
  - a `contract.GateRegistry`
  - per-role profiles

  Nothing else hard-codes these values. The `factory contract` CLI gains `--install <file>`, which replaces its interim flags.
- **Identities are stable IDs.** People are `(forge, ID)`, never logins.

## Shape

```yaml
apiVersion: factory/v1alpha1
kind: Install
installation: { id: "inst-1", forge: github }
deploymentManifest: "sha256:…"            # WI-29 manifest digest that pins templates, sandboxes, tools and permissions
policyApprovers:                          # Enterprise IT. Activating a new install revision needs `quorum` distinct current approvers.
  quorum: 2                               # default 2, minimum 1, must be satisfiable by the listed members
  members: [{ forge: github, id: "111" }, { forge: github, id: "222" }]
admins:                                   # SEC-6 halt/resume only; a single current admin suffices
  - { forge: github, id: "12345" }
timers:                                   # PRD defaults where the PRD gives one; every value >= 1
  reviewRounds: 3                         # AGT-5
  replans: 3                              # INT-15
  acceptanceRepairs: 3                    # PIP-15
  inverseRetries: 3                       # REC-3
  sameGateFailures: 3                     # COST-4 (install choice; the PRD gives no number)
  noProgressIterations: 5                 # COST-7
  spendOverEstimateFactor: 5              # COST-7
quotas:                                   # COST-2, COST-3: install choices, the PRD gives no numbers
  teams: [{ teamId: "github:team:9876", agentSessions: 4, ciRuns: 8 }]   # stable forge team IDs
  defaultTeam: { agentSessions: 2, ciRuns: 4 }
  ciRunsPerPRPerHour: 6                   # counted per (repo ID, PR number)
contractDefaults: { switchStaleDays: 30, switchAbandonedDays: 30, reviewBudgetLines: 300 }   # CON-9
baseline:
  verify:
    - { purpose: secret-scan,     name: secret-scan, producerId: "…", workflowId: "…", workflowRevision: "<40-hex>", checkId: "…", mandatory: true }
    - { purpose: dependency-scan, name: dep-scan,    producerId: "…", workflowId: "…", workflowRevision: "<40-hex>", checkId: "…", mandatory: true }
  union: []
  reviewers: { pr: pr-reviewer, security: security-reviewer }
  knownAgents: [payments-specialist]
  protected:                              # default when absent; a list given here must cover every DefaultProtected() entry
    - ".github/workflows/**"
    - ".github/actions/**"
    - ".github/CODEOWNERS"                # all three locations: GitHub uses the first it finds, so a product PR
    - "CODEOWNERS"                        # that adds .github/CODEOWNERS would otherwise take precedence over the root file
    - "docs/CODEOWNERS"
gateRegistry:                             # CON-4. Every baseline gate and every gate a contract may reference.
  - { producerId: "…", workflowId: "…", workflowRevision: "<40-hex>", checkId: "…" }
decisions: { expiry: {}, denialAuditTimeoutSeconds: 5 }
qualifierKeys:                            # ed25519 public keys of IT-controlled qualification runners (WI-32)
  - { id: "q1", key: "<base64 ed25519 public key>" }
roles:
  coder:
    profile:
      template: { digest: "sha256:…" }    # the role definition (AgentTemplate)
      runtime:  { image: "registry/agent@sha256:…" }
      harness:  { name: claude-code, version: "x.y.z", digest: "sha256:…" }
      model:    { name: "…", revision: "…" }
      endpoint: { digest: "sha256:…" }    # canonical endpoint and gateway route config
      tools:    [{ name: git, version: "2.47.0", permissions: ["repo:read", "branch:push-own"] }]
    egress:   { hosts: ["models.internal:443"] }                  # literal host:port only, deny by default
    gatewayCredentials: [{ name: model-key, host: "models.internal:443", operations: ["POST /v1/messages"] }]
    sandboxSecrets: []                    # must be empty in v1 (RUN-4)
    qualification: "sha256:…"             # digest of the signed qualification record bytes
  pr-reviewer:   { … }
  security-reviewer: { … }
```

## Validation (fails closed, every problem reported with its JSON pointer)

1. **Schema.** The schema check runs first, then everything below.
2. **Timers and quotas.** Every value must be at least 1. Absent fields take the PRD defaults. Quota team IDs must be unique.
3. **Baseline:**
   - Both purposes, `secret-scan` and `dependency-scan`, are present as mandatory `verify` gates (SEC-4).
   - Every baseline gate is in the gate registry.
   - The two core reviewers are distinct, and **both resolve to enabled roles**.
   - The baseline passes `contract.Compile`'s baseline checks, by calling that code directly rather than duplicating it.
   - A `protected` list, if given, covers every `DefaultProtected()` entry (`.github/workflows/**`, `.github/actions/**` and every `codeowners.Locations()` path): some pattern, or a protected directory above it, contains it. The default list is seeded from that function.
4. **Gate registry.** Identities are unique and revisions are full SHAs.
5. **People.** `policyApprovers.members` and `admins` are non-empty and unique, and their forge is the installation's forge. The quorum must be at least 1 and at most the member count.
6. **Roles (SEC-1, RUN-4, RUN-6):**
   - Every agent role is treated as reading untrusted input in v1. That is never declared, it is assumed.
   - `sandboxSecrets` must be empty. Credentials exist only as gateway-injected credentials bound to an exact host and operation list.
   - `egress.hosts` are literal `host:port` values with no wildcards, and every gateway credential's host is in the role's egress list.
   - Together these make "untrusted input + secrets + open egress" impossible to declare. A role that tries any part of it fails.
   - Every profile field is pinned: the image is an `@sha256:` digest, and the template, harness and endpoint carry digests. The model carries a revision, and each tool carries a version and permissions.
   - Every enabled role has a qualification digest.
   - WI-30 enforces the same policy at runtime. Install validation can't prove what a sandbox can actually reach.
7. **Deployment manifest.** `deploymentManifest` is a well-formed digest. WI-29 resolves and verifies it.

## Admission (NFR-2)

`Admit(ctx, role, store QualificationStore) error` runs before scheduling a role:
1. Fetch the record bytes by the configured digest from a content-addressed store (offline bundle or local store), and re-hash them.
2. Decode the record strictly:
   `{tupleDigest, suiteRevision, result, evidence: [digests], qualifiedAt, keyId, signature}`.
   The signature is ed25519 over the canonical bytes of every field except the signature itself.
3. Verify the signature with a configured `qualifierKeys` entry matching `keyId`. An unknown key or a bad signature is denied.
4. Recompute the role's versioned (v2) tuple digest over the role name, the deployment manifest digest, template digest, runtime image,
   harness name, version and digest, model name and revision, endpoint digest, each tool's name, version and sorted permissions, the
   sorted egress hosts and the sorted gateway credentials. The canonical encoding is documented in "Admission as built" and covered by
   a golden test.
5. Require `result == pass` and an equal tuple digest. Anything else is a typed denial: unknown role, missing, digest mismatch,
   malformed, unsigned, unknown key, bad signature, failed, or a different tuple.

Changing any part of the tuple, such as one tool permission or the role template, invalidates a genuine pass.

## Policy identity

Evidence binds to both the contract revision and the install revision. `contract.Baseline` gets an `InstallRevision`, and
`Effective` reports both, so changing a baseline gate can never leave an evidence identifier unchanged.

## Activation (later work items)

A new install revision is activated through authz with a new operation, `activate-install`. Its role is `policy-approver` and its scope is install.
Activation needs `quorum` distinct granted decisions from members of the currently active revision, bound to the installation, the
active generation and the candidate commit. Approvals are consumed, audited, and compared-and-swapped against the active generation in one
transaction, so two activations racing from the same generation can't both commit.

A candidate can't approve itself. Only members of the active revision count, so a compromised approver plus a newly added member can't reach quorum.
The first revision is bootstrapped once, out of band, by IT with a local CLI. A second bootstrap is refused, and recovering lost credentials is a documented IT procedure.

WI-07 delivers the data, the validation, and the `activate-install` operation in authz. The transactional activation flow lands with the state
store (WI-10) and the policy review path (WI-11).

## As built (WI-07)

### Packages and API

- `internal/yamlsafe`: `Decode(data, Limits{MaxBytes, MaxDepth, MaxNodes, Name}) (any, *Error)`. It is the bounded
  YAML-to-JSON stage of `internal/contract` moved out unchanged, plus the escaping helpers (`Escape`, `Quote`, `Pointer`,
  `Sanitize`) that contract's `display`, `quote`, `pointer` and `sanitize` now call. `Error{Code, Message, Path}` uses the
  codes `syntax`, `unsafe-yaml`, `too-large` and `schema` (a value JSON cannot hold: a float, a bad boolean, a non-decimal
  integer, a top level that isn't a mapping). Install limits are 2 MiB, depth 16 and 100,000 nodes (a registry of 4,096 gates
  needs about 37,000).
- `internal/install`: `Parse(data) (*Config, error)` runs yamlsafe, the embedded schema
  (`internal/install/schema/v1alpha1.json`, every object closed), a strict decode and the semantic rules. Any problem
  returns a `*ValidationError` of `Problem{Field, Code, Message}` with escaped JSON pointers (at most 100, sorted, with a
  `too-many` note), and no `Config`. `Config` is immutable and every accessor returns copies:
  `WithRevision(sha)`, `Revision()`, `Installation()`, `DeploymentManifest()`, `Baseline()`, `Defaults()`, `GateRegistry()`,
  `AuthzConfig()`, `Admins()`, `PolicyApprovers()` (members and quorum), `RoleSource()`, `Timers()`, `Quotas()`, `Role(name)`,
  `Roles()` and `Admit(ctx, role, store)`. `DefaultProtected()` is the default protected list.
- `internal/install/installtest`: deterministic ed25519 `Signer`s (`NewSigner(keyID, seed)`), an in-memory
  `QualificationStore` and `Encode`, for tests of admission here and in WI-32.
- `factory install validate <file>` prints the problems or `ok`.

### Decisions the design left open

- **Roles.** A role is enabled if and only if it is a key of `roles`. There is no `enabled` flag. Role and tool names match
  `[a-z][a-z0-9-]{0,63}`. `sandboxSecrets` may be absent (empty); a non-empty list is `unsafe-role`. There is no field to
  declare `untrustedInput`, so a role that tries is an unknown field.
- **Egress.** A host is a lowercase DNS name or IPv4 address with a port (`host:port`), checked by the schema, and the port is
  checked to be 1 to 65535. A wildcard, scheme, path, CIDR or bracketed IPv6 literal does not parse. A gateway credential
  must name a host that appears in its role's `egress.hosts` exactly (host and port), and its operations are
  `METHOD /path` strings without wildcards. Credential names and tool names are unique within a role.
- **Defaults.** Where the PRD gives a number: `reviewRounds` 3, `replans` 3, `acceptanceRepairs` 3, `inverseRetries` 3,
  `noProgressIterations` 5, `spendOverEstimateFactor` 5. Two more defaults are install choices, not PRD numbers:
  `policyApprovers.quorum` 2 and `denialAuditTimeoutSeconds` 5 (which is authz's own default). Required
  because the PRD gives none: `sameGateFailures`, `quotas` (`defaultTeam`, `ciRunsPerPRPerHour`) and `contractDefaults`.
  Every number must be at least 1. With one listed approver and no `quorum`, the default 2 is unsatisfiable and fails.
- **Quota teams** are `<forge>:<id>` and the prefix must be the installation's forge.
- **Gate registry.** Identities are unique per `(producerId, workflowId, workflowRevision, checkId)`. The same identity at two
  pinned revisions is two registrations, because contracts pin revisions. `purpose` (`secret-scan` or `dependency-scan`) is
  allowed only on baseline verify gates, once each, and both must be present. A baseline gate counts as registered only at
  its own pinned revision.
- **Baseline check.** When no earlier rule reports a problem in the baseline or the defaults, `contract.Compile` runs on an
  empty contract set, so its rules (identity duplicates, agent names, protected patterns, defaults) are not copied. Its
  error is one `baseline` problem. `contract.Compile` is the only entry point: contract exports no separate baseline check.
- **People.** Admins and approvers are `(forge, id)` with the installation's forge. The same person may be both. `RoleSource()`
  grants `authz.RoleAdmin` and `authz.RolePolicyApprover` by `(forge, id)` and nothing else. It denies bots and apps, any
  scope other than this installation, and a cancelled context. Build it from the *active* revision at execution time.
- **Decisions.** `decisions.expiry` maps an operation name to seconds, and a name that `authz.Operations()` doesn't list is
  rejected. Absent means no expiry. A missing `decisions` section uses authz's own defaults.
- **Revision.** The config can't name its own commit, so `Parse` leaves the install revision empty and `WithRevision(sha)`
  (40 or 64 hex digits) sets it. `Baseline().InstallRevision` carries it, `contract.Effective.InstallRevision` reports it and
  `contract.TrustDigest` covers it (the validator version is 2). The CLI sets it from `--install-revision`.

### Admission as built

`Admit` returns nil or an error. A `*AdmissionError{Role, Reason, Detail}` wraps `ErrNotAdmitted`; any other non-nil error
(a store failure other than `ErrRecordNotFound`, a cancelled context) also means the role must not run.

| Reason | Cause |
| --- | --- |
| `unknown-role` | the role is not enabled |
| `missing` | the store returns `ErrRecordNotFound` for the configured digest |
| `digest-mismatch` | the bytes don't hash to the configured digest |
| `malformed` | not exactly one JSON object with exactly the seven fields (duplicate or unknown key, trailing data, over 64 KiB, bad digest, revision, result, time or key ID) |
| `unsigned` | `signature` is empty |
| `unknown-key` | `keyId` is not in `qualifierKeys` |
| `bad-signature` | not base64, not 64 bytes, or it doesn't verify |
| `failed` | `result` is not `pass` |
| `tuple-mismatch` | the record qualified another tuple |

Checks run in that order. `malformed` and `unknown-role` go beyond the seven reasons in the first design: a record that
can't be read, or a role that was never enabled, must still be a typed denial.

- **Record** (stored as JSON, addressed by `sha256:<hex of the bytes>`): `tupleDigest`, `suiteRevision` (40 or 64 hex),
  `result` (`pass` or `fail`), `evidence` (up to 64 `sha256:` digests), `qualifiedAt` (RFC 3339), `keyId`, `signature`
  (standard base64 of 64 bytes).
- **Signing bytes**: `"lightsout/qualification-record/v1\n"` followed by the compact JSON of every field except
  `signature`, in the order above. They are rebuilt from the decoded fields, so spelling in the store doesn't matter.
- **Tuple digest** (v2): `sha256:` and the hex of SHA-256 over `"lightsout/qualification-tuple/v2\n"` and the compact JSON
  `{"role","manifest","template","image","harness":{"name","version","digest"},"model":{"name","revision"},"endpoint","tools":[{"name","version","permissions"}],"egress":[…],"credentials":[{"host","name","operations"}]}`.
  `manifest` is the install's `deploymentManifest`. Tools are sorted by name, then version, then permissions; permissions,
  egress hosts and operations are sorted; credentials are sorted by host, then name, then operations. Only the qualification
  digest is outside the tuple, so re-pinning the network profile or the deployment manifest invalidates a pass (NFR-2 "pinned
  deployment profile"). A golden test pins the digest and a second test recomputes it from the written-out encoding. v1
  (without manifest, egress and credentials) was never released.
- A **qualifier key list** is required (at least one key); a config with none could never admit a role.

### Activation operation

`authz.OpActivateInstall` (`"activate-install"`) needs `authz.RolePolicyApprover` (`"policy-approver"`), install scope and an
install subject. `Target.Revision` (and the revision the approver names) is `install.ActivationRevision(installID,
generation, candidate) (string, error)`: the lowercase hex SHA-256 of `"lightsout/install-activation/v1\n"`, then `u64(len(installID))`
and the install ID bytes, then `u64(8)` and `u64(generation)`, then `u64(len(candidate))` and the candidate commit bytes, where
`u64` is 8 big-endian bytes. It returns an error for an empty install ID or one outside the schema's form, and for a candidate that
isn't 40 or 64 lowercase hex digits. A decision therefore binds the installation, the active generation
and the candidate. A decision made for an earlier generation has a different revision, and WI-10 must compute the value from
the store's current generation and so deny it. Authz checks one decision at a time and cannot
count, so quorum is the caller's job (WI-10 and WI-11): gather `quorum` granted decisions from distinct principals who are
policy approvers of the *active* revision (`Config.RoleSource()` of the active config), each carrying the same
`ActivationRevision`, and consume them with the compare-and-swap of the active generation in one
transaction. A candidate's own `policyApprovers` never count. [authz.md](authz.md), "Install activation", carries the caller contract.

### Open items

- Install validation can't prove what a sandbox can reach. WI-30 enforces the same policy at runtime.
- A record has no expiry. Whether a pass goes stale (a new suite revision, a time limit) is for WI-32.
- Any change to the baseline, defaults, known agents or registry must trigger a full `Compile` and `CheckGates` across the
  managed repos (WI-11); the trust digest already makes `ValidateChanged` validate everything.

### Review round 1 changes

- **Protected list.** A custom `baseline.protected` must cover every `DefaultProtected()` entry (workflows, actions and each
  CODEOWNERS location), by pathglob's containment proof. Each missing entry is a denial test.
- **Revision is required.** `Load(ctx, tr, repo, sha, path)` reads the install file through a forge tree at a full SHA (it needs
  `fs.ReadLinkFS`, refuses symlinks on the path, caps the size) and sets the revision from the SHA. `Parse` plus
  `WithRevision` remain for tests and the CLI. `Config.Baseline()` returns `ErrNoRevision` for a config without one.
- **Tool permissions** are a closed vocabulary: `repo:read`, `issues:read`, `issues:comment`, `pulls:read`, `pulls:review`,
  `checks:read`, `branch:push-own`. There is no merge permission and none that pushes to a protected branch (SEC-2). No reviewer
  may hold `branch:push-own` (SEC-3): a reviewer is a core reviewer or any `knownAgents` role (the specialist reviews of AGD-3). A
  role that holds `branch:push-own` may not also hold `pulls:review`, so a coder can't approve its own change (SEC-2).
- **Floating versions** are refused as `model.name`, `model.revision`, `harness.version` and a tool `version`. The value is
  split on `- _ . : / + @` and compared in any case. It floats if
  - it starts with `refs/` or `origin/`, or has a `heads` token, or has a `*`;
  - any token is always floating: `latest`, `stable`, `default`, `current`, `main`, `master`, `head`, `edge`, `nightly`, `x`,
    `lts`, `rolling`, `tip`, `release`, `trunk`, `develop`, `unstable` or `experimental`;
  - a pre-release token (`beta`, `canary`, `next`, `dev`, `preview`, `snapshot`, `alpha`, `rc`) has no numeric token after it;
  - for `harness.version` and a tool `version` only, it is a bare major version (`2`, `v1`). Model revisions are often plain
    numbers (`0613`, `20250929`), so that rule does not apply to them or to the model name.

  So `claude-3-5-sonnet-latest`, `chatgpt-4o-latest`, `llama3:latest`, `refs/heads/develop`, `2.x`, `canary` and `2.47-latest`
  float, and `claude-sonnet-4-5-20250929`, `2.47.0`, `2.0.0-beta.1`, `15.0.0-canary.12`, `o1-preview-2024-09-12`,
  `gemini-2.5-pro-preview-06-05` and a full SHA are pins. A model alias that moves upstream without changing its name can't be
  seen here: `endpoint.digest` must pin the upstream model ID route, and WI-29 and WI-30 verify it.
- **No forge credentials through the gateway** (SEC-2, SEC-3). A role's `egress.hosts` and `gatewayCredentials[].host` may not
  name the forge: for `installation.forge: github`, `github.com`, `api.github.com`, `uploads.github.com`, `codeload.github.com`,
  `raw.githubusercontent.com` and `objects.githubusercontent.com` (any port), plus every host in the optional
  `installation.forgeHosts` list (for GitHub Enterprise Server). In v1 a role reaches the forge only through its tool permissions:
  WI-30 mints a scoped forge token per role from the closed permission set. A reviewer with a `git-receive-pack`, merge or
  GraphQL credential, or a coder with a refs or reviews credential, is `unsafe-role`.
- **Qualifier keys** may not be small-order ed25519 points (the libsodium and RFC 8032 list of seven encodings, with either
  sign bit), including all zeros, the identity and the non-canonical encodings. Base64 must be canonical.
- **Egress hosts** may not be loopback (`127.0.0.0/8`), link-local (`169.254.0.0/16`), `0.0.0.0/8`, multicast (`224.0.0.0/4`), the
  broadcast address, the provider metadata addresses `100.100.100.200` and `168.63.129.16`, `localhost`, `*.localhost`,
  `localhost.localdomain`, `localhost4`, `localhost6`, `ip6-localhost`, `ip6-loopback`, `metadata`, `metadata.google.internal`,
  `metadata.goog`, `host.docker.internal`, `gateway.docker.internal`, `instance-data`, `instance-data.ec2.internal`, `kubernetes`, `kubernetes.default`, `kubernetes.default.svc` or
  anything under `.svc.cluster.local`. A port with a leading zero (`:0443`) is refused too. An IPv4 address must be canonical dotted decimal, so `127.1`, `2130706433`,
  `0x7f.0.0.1` and `0177.0.0.1` fail. This reads the literal text only: WI-30 must still deny a hostname that resolves to
  one of these addresses.
- **Gateway operations** have a path that equals its `path.Clean` form (no empty segment, trailing slash, `.` or `..`), every
  segment matching `[A-Za-z0-9._~-]+`, and no `%`, `;`, backslash or NUL anywhere, so there is no encoding to decode
  differently at the gateway and the origin.
- **Base64.** A qualifier key must match `^[A-Za-z0-9+/]{43}=$` and a signature `^[A-Za-z0-9+/]{86}==$` before decoding,
  which also refuses the CR and LF a decoder would skip.
- **Admission** checks the record size before hashing it.
- **`knownAgents`** must each be an enabled role. On GitHub a person's `id` is the numeric account ID
  (`^[1-9][0-9]{0,19}$`), never a login.
- **CLI.** `contract validate|explain|trust-digest` need either `--install <file> --install-revision <commit>` or
  `--interim-defaults` (which prints the interim note). `--interim-defaults` can't be combined with `--install`. `explain` prints
  `installRevision` in text and `--json`.
