# Control-plane state, ingestion and the first HTTP surface (WI-10)

Status: accepted after a Codex review, 2026-11-21. WI-10 lands as three sub-items, in order:

- **WI-10a store:** `internal/store` interfaces, PostgreSQL and in-memory implementations, the PostgreSQL `audit.Backend` (two chains), `authz.Tx`, checkpoints, and atomic delivery receipt with enqueue plus the lease contract.
- **WI-10b ingest:** webhook ingestion over an OpenAPI-first chi HTTP surface (webhook endpoint, health and readiness).
- **WI-10c loop:** the event loop. It runs one authorization path (NFR-5), routes decisions through `authz.Authorize`, fences leases, and reconciles forge writes.

## Principles

- **One transaction per state change.** These happen together in one `READ COMMITTED` transaction: the caller's state change, `authz.Tx.Consume`, the grant's audit append and the audit head advance.
  - **Invariants** come from explicit conditions, not from serializable isolation:
    - `Consume` is a unique key. Only that key's conflict maps to `ErrReplayed`.
    - A state update is conditional on both the observed row version **and** `Grant.Target.Revision` (CAS).
    - Each audit chain has a pre-existing head row, locked `FOR UPDATE`. `SealFunc` is called once, the successor is validated, and it is inserted while the head is advanced in the same transaction.
  - **No transparent retries.** `Authorize` does live lookups and writes denials independently, so a callback isn't pure. The caller retries the whole operation explicitly.
  - **Multi-row predicates** that come later (WI-33 quotas) get a lockable row or a narrowly scoped serializable transaction.
- **Two audit chains.** The *decision chain* is written in state transactions. The *denial chain* is written in its own short transactions over a **reserved connection pool**. A denial can therefore persist while every worker connection is busy, and a caller's rollback can't erase it. Example: one transaction holds the grant-chain head for the first owner's approval and must audit the second owner's denial before rolling back.
- **Checkpoints outside the log.** Each chain's committed head (chain ID, seq, hash) is checkpointed to an external sink every N entries and at shutdown. At startup, `VerifyAgainst` runs on both chains and refuses to start on a mismatch. Only the checkpointed prefix is protected against deliberate truncation (NFR-4). WI-10a ships a file sink.
- **Invariants live in columns, payloads in JSONB.** Columns with constraints hold:
  - the stable issue node ID and current repo
  - the CAS row version
  - the approved revision digest
  - replay keys
  - lease generation
  - the payload schema version

  The schema version, the CAS version and the approval digest are kept distinct. An evolving payload is versioned JSONB. A field is promoted to a column when SQL must enforce uniqueness, a relationship or a transition precondition.
- **Atomic receipt.** Recording a delivery `(forge, delivery ID, body digest)` and enqueuing its work item happen in **one** transaction, so a crash can't leave a delivery recorded with its only work item lost. Receipts are **keyed by the SHA-256 of the verified body** (receipt ID `sha256-<hex>`), not by the forge's delivery ID, because `X-GitHub-Delivery` and `X-GitHub-Event` are not signed:
  - A captured signed body replayed under fresh delivery IDs, or with a swapped event header, is an idempotent 2xx and enqueues once.
  - Squatting a real delivery's ID with other bytes cannot block the real delivery, and conflicts can't grow the audit log.
  - The GitHub GUID and event are kept as work-payload metadata only.
  - The unsigned event header picks the parser, so a replayed body can at most create a spurious re-read hint. A hint is never authority, and the loop re-reads and re-authorizes everything.
  - A conflict (the same receipt ID with a different digest) can only mean a SHA-256 collision. The 409 and audit path stays because the store contract allows it.
- **Events are hints, never authority.** A work item says only "re-read X". The loop re-reads the authoritative forge objects (WI-08) before acting:
  - For a comment or review: its author, location, edit state and the author's current role.
  - For an approving review: also its current verdict and reviewed SHA.
  - The decision ID consumed is the canonical forge object ID, never the delivery ID.
- **Webhook signatures.**
  - `X-Hub-Signature-256` is verified in constant time over the bounded raw bytes, *before* any decoding.
  - The cap is 25 MiB, GitHub's own payload limit. A larger delivery is refused and recovered via redelivery (WI-12).
  - Event and delivery headers are routing and deduplication inputs only.
  - The signed installation and repository must match the install config.
- **One authorization path (NFR-5).**
  - Comment and review decisions are re-read forge objects.
  - API and admin-CLI decisions need a credential-backed identity: the API client's authenticated principal.
  - Checks and callbacks are scoped service identities (WI-30) and never human decisions.
- **Never purge.** The consumed-decision and delivery tables are append-only for the life of the installation.
- **Testing.**
  - **One conformance suite** (`internal/store/storetest`) runs against both stores.
  - **The in-memory store** keeps `make check` fast and offline.
  - **The PostgreSQL store** runs the suite when `LIGHTSOUT_TEST_POSTGRES_URL` is set, plus engine-specific tests that use real concurrency: two connections with barriers, uniqueness waits, rollback, `SKIP LOCKED`, lease takeover, a terminated worker, and restart on migrated data.
  - **A passing real-PostgreSQL run is a merge condition for WI-10a.** Locally that's a pinned `postgres:16-alpine` container with no external network.
  - **In CI it needs a required job that fails when PostgreSQL is unavailable.** Today CI runs plain `make test`, where the env-gated suite would skip and stay green forever. That CI change needs human approval in this repo (`.github/workflows` edits prompt), so it's tracked separately.

## Store (WI-10a)

As built (`internal/store`, with `memstore`, `pgstore`, `checkpoint` and the `storetest` conformance suite):

```go
type Store interface {
    Tx(ctx, fn func(ctx, tx Txn) error) error   // READ COMMITTED; no automatic retry; a Txn is single-goroutine and dead after fn returns
    Denials() audit.Backend                     // denial chain, reserved pool, one transaction per append
    Decisions() audit.Backend                   // read-only view of the decision chain (AppendNext fails with ErrReadOnly)
    Lease(ctx, owner string, maxItems int, ttl time.Duration) ([]Lease, error) // SKIP LOCKED, oldest first, bumps generation
    Close() error
}
type Txn interface {
    RecordDelivery(ctx, forge, deliveryID string, digest Digest, work WorkItem) (new bool, err error) // receipt+enqueue, atomic
    Get(ctx, kind Kind, id string) (Row, error)                  // Kind: issue, change, feature, train
    Put(ctx, row Row, expect Version, expectRevision string) (Version, error)
    Enqueue(ctx, WorkItem) error
    Complete(ctx, Lease) error                                   // fenced
    Reschedule(ctx, Lease, notBefore time.Time) error            // fenced; clears the lease, attempts++
    DeadLetter(ctx, Lease, reason string) error                  // fenced; never leased again
    authz.Tx                                                     // Consume (unique, never purged) + Append (decision chain)
}
func VerifyChains(ctx, st Store, sink checkpoint.Sink, opts VerifyOptions) error
func WriteCheckpoints(ctx, st Store, sink checkpoint.Sink, opts VerifyOptions) error
```

- **Generic rows.** One `state_rows` table holds all four kinds (`Get`/`Put` over a `Kind`) instead of per-kind methods.
  A transfer is a `Put` that changes `Repo`: the node ID is the key and the version bumps.
- **Four distinct revision-ish columns:** the CAS `version`, the payload `schema_version`, `current_revision` and
  `approved_revision`.
  - `current_revision` is the subject's current proposal or head revision. The action handler resolves
    `authz.Target.Revision` from it **in the same `Txn`** that applies the grant, and `Put(row, expect,
    expectRevision)` compares `expectRevision` with the stored `current_revision`. A proposal that moved after the check
    is therefore an `ErrConflict`, so an approval binds to the exact current proposal (CON-8, SEC-10). The new current
    revision is whatever the caller sets on the row.
  - `approved_revision` records the last approved revision as evidence. It is not compared.
- **Payloads** are JSON objects. The store rejects, identically in both stores, what PostgreSQL's jsonb refuses:
  `\u0000`, unpaired surrogate escapes, invalid UTF-8 and numbers outside numeric's range (`ErrInvalid`). SQLSTATE
  22P05, 22P02, 22021 and 22003 map to `ErrInvalid` as a backstop. Numbers keep full precision.
- **Leases are fenced twice.** `Complete`, `Reschedule` and `DeadLetter` need the current generation **and** an unexpired
  lease by the store's clock, so a slow holder is fenced out as soon as `Expires` passes even if nobody re-leased
  the item. A rescheduled item waits until `notBefore`. `Lease.Attempts` counts reschedules. A dead-lettered item is
  parked for good. WI-10c owns retry policy, backoff and jitter.
- **Seal checks.** Both stores validate every sealed entry with `audit.CheckSuccessor` (the audit package's own
  link, record and hash rules) and call `seal` exactly once.
- **Multi-decision transactions.** A `Tx` that authorizes several decisions by itself (it `Consume`s IDs, then calls
  `Append`) must `Consume` every decision ID, in sorted order, before its first `Append`. `Append` holds the decision
  head lock until the transaction ends, so interleaving can deadlock. Two `authz.Authorize` calls in one `Tx` cannot
  follow that rule, because each consumes and then appends before it returns, so such a transaction can deadlock with
  another one. PostgreSQL then aborts one (40P01), the store maps it to `store.ErrRetry` (also 40001 and lock
  timeouts), nothing is committed, and the caller may rerun the whole operation, authorization included. Prefer one
  `Authorize` per `Tx`.
- **Operator flow: migrate as the owner, run as the runtime role.**
  - `pgstore.Migrate(ctx, ownerURL, runtimeRole)` is an explicit operator step. It takes the advisory lock, applies
    pending migrations in their own transactions, verifies every applied checksum and (re)grants the runtime role.
    The service never runs it.
  - `pgstore.Open` only checks, read-only, and creates nothing. It refuses (`ErrSchema`) a database that is
    unmigrated, newer than the binary, has an altered migration, or has any protective trigger missing or disabled. It
    refuses (`ErrPrivilege`) a runtime credential that is a superuser, that owns or is in the owner group of the
    schema, the database or their objects, or that holds any privilege beyond the allowlist below, unless `Config.AllowOwnerRuntime` is set, which needs a logger and warns on every `Open`. The opt-out is for
    tests and development.
  - Every pooled connection pins `search_path` to the migrated schema and sets `lock_timeout` (default 5s) and
    `idle_in_transaction_session_timeout` (default 60s), both configurable.
- **Roles and appends.**
  - The runtime role does not own the tables, the schema or the database, and is not in their owner group. It has SELECT on the audit entries and chain heads, SELECT and INSERT on
    the consumed set and the receipts, and read-write on state and work.
  - Appends go through two SECURITY DEFINER functions that run as the owner, with `search_path` pinned (`pg_temp` last)
    and EXECUTE granted to the runtime role only. `audit_lock_head` locks and returns the head. `audit_append` checks
    `seq = head.seq + 1` and `prev_hash = head.hash` under the head lock, then inserts the entry and advances the head in
    one step. The role therefore cannot move a head, plant an entry ahead of it or wedge a chain, and the Go backend also
    runs `audit.CheckSuccessor` before calling the function.
  - Triggers keep the audit entries, consumed decisions and receipts append-only, and a chain head can only advance by
    one and is never deleted. An owner or superuser can drop triggers, which is what `Open`'s trigger check and the
    checkpoints are for.
  - **Residual risk, stated plainly.** A holder of the runtime credential can still append a correctly hashed, forged
    entry of its own choosing, because the hash chain is unkeyed. Detecting that needs an external signer, which is a
    later work item. Checkpoints only protect the prefix they cover.
  - The same credential can also append a correctly linked but malformed entry (one that verification rejects). Startup
    verification then fails, and the service refuses to start. That fails closed, but it is a lasting denial of service
    until an operator repairs the chain, so treat the runtime credential as able to halt the factory.
  - **Threat model.** `Open` catches a misconfigured runtime role or schema, once, at startup. It cannot see a grant
    made after it ran, and it cannot stop a malicious superuser, who can do anything. The store database must be
    **dedicated to the factory**, with exactly one store schema: several rules below are database-wide, so two store schemas in one database refuse each other (each one's `audit_append` is an extra SECURITY DEFINER function to the other).
  - `Open` compares the role's **effective** privileges (direct, inherited, through PUBLIC or by column) to an exact
    allowlist, not to a list of forbidden ones. One Go table (`runtimeTableGrants`, `runtimeFunctionGrants`) generates
    `Migrate`'s GRANT statements, is checked by `Migrate` after granting (together with the who-the-role-is rules, so a
    role `Open` would refuse fails at `Migrate`), and is what `Open` compares against:
    - **Tables.** For every table, view or foreign table in the schema, and each of SELECT, INSERT, UPDATE, DELETE,
      TRUNCATE, REFERENCES and TRIGGER (and MAINTAIN on PostgreSQL 17), `has_table_privilege` equals the allowlist
      exactly. An extra privilege is `ErrPrivilege`. A missing one is `ErrSchema` (the grants were not applied).
    - **Columns.** For each table and each of SELECT, INSERT, UPDATE and REFERENCES, `has_any_column_privilege` must
      equal the table-level expectation, so a `GRANT UPDATE (col)` no longer slips past a table-level check. No
      table, column, function or schema privilege may carry WITH GRANT OPTION.
    - **Functions and sequences.** EXECUTE is held on `audit_append` and `audit_lock_head` and on no other function in
      the schema, except trigger functions (PUBLIC has EXECUTE on those by default, and a trigger function cannot be
      called outside a trigger). No sequence privilege is allowed: the identity column is filled under INSERT.
    - **Who the role is.** The role must be the credential that logged in (`session_user`, `current_user` and the
      authenticated user in `pg_stat_activity` agree), so a `role=` or `session_authorization=` parameter or an
      `ALTER ROLE/DATABASE ... SET role` default on a stronger credential is refused. It must be a member of **no**
      role at all (a group granted `WITH INHERIT FALSE`, a `NOINHERIT` role or an ADMIN-only grant reaches privileges
      by `SET ROLE` that the effective-privilege check cannot see). It must not be a superuser or have CREATEROLE,
      CREATEDB, REPLICATION or BYPASSRLS, and must not be in `pg_write_all_data`, `pg_write_server_files` or
      `pg_execute_server_program`.
    - **No ownership.** The role must own nothing in the database or the cluster (`pg_shdepend`: a function behind a
      constraint or event trigger, an inheritance child, a schema, a database), must not be a member of the owner of
      the store schema, the database (which includes `pg_database_owner`) or any relation, function or type in the
      schema, and must not hold CREATE on the schema or the database. An owner can drop or alter the protection
      triggers.
    - **Database-wide.** Outside the store schema (the system catalogs, which only a superuser can modify, aside) the
      role holds no write privilege (INSERT, UPDATE, DELETE, TRUNCATE, TRIGGER, REFERENCES, table or column) on any
      relation, and has no CREATE on any schema, no CREATE or TEMP on the database, no USAGE on a foreign server or user
      mapping, no SET or ALTER SYSTEM privilege on any parameter (`session_replication_role` changes which triggers
      fire) and no default privilege (`pg_default_acl`) granted to it or to PUBLIC. TEMP matters because a temporary
      table or function is searched before the real ones and can shadow what another owner's code refers to. PUBLIC has
      TEMP on every database by default, so `Migrate` runs `REVOKE TEMPORARY ON DATABASE <db> FROM PUBLIC` when its
      credential owns the database (and always revokes TEMP and CREATE from the runtime role). If it does not own the
      database, the operator must run that REVOKE as the owner, or `Migrate`'s verification fails.
    - **Code that runs as someone else.** The database must contain **no event trigger**, **no subscription** and **no
      SECURITY DEFINER function other than `audit_append` and `audit_lock_head`**, in any schema (`pg_catalog` and
      `information_schema` included), whether or not the role can EXECUTE it: a trigger or event trigger runs its
      function as the owner without checking EXECUTE. Each is `ErrSchema`, and `AllowOwnerRuntime` does not waive it.
    - **Exact protection set.** The schema holds exactly the expected tables (an unexpected table, view or foreign
      table is `ErrSchema`), with no rewrite rules, no row-level security (enabled, forced or with policies) and no
      inheritance, dependent view or foreign key crossing the schema boundary. Triggers are exactly the migrations':
      no extra trigger on any table, and each expected one `ENABLE ALWAYS` (migration 0002, so
      `session_replication_role = replica` cannot switch it off) with the expected table, timing and events, no WHEN
      clause, no column list and no arguments. Each protected function must have the migrations' exact body and its
      expected language, security mode, volatility, strictness, leakproofness, parallel safety, result and argument
      types, and a `proconfig` that is exactly the pinned `search_path` for the SECURITY DEFINER functions and empty
      for the others.
    - **Exact columns, constraints and indexes.** For every relation, `Open` compares each column (type, nullability,
      default expression, generated and identity kind, collation), constraint (type, validated, definition), index
      (definition) and sequence to `schema.golden`, an embedded description generated from a fresh `Migrate`
      (`go test ./internal/store/pgstore -run TestSchemaGolden -update`, never by hand; the file is
      `internal/store/pgstore/testdata/schema.golden`). Columns print their collation schema-qualified with provider,
      determinism and locale, and tables their access method, so a look-alike or non-deterministic collation or another
      access method is caught. Storage options (`reloptions`: fillfactor, autovacuum) are not compared. A dropped unique
      key, an added CHECK or a changed default is `ErrSchema` naming the first differing object. The golden is generated
      on PostgreSQL 16 and **v1 supports PostgreSQL 16 only**: a new major version needs a regenerated golden and its
      own CI job.
    - **Planted entries.** In one statement (so one snapshot, immune to a racing append), `Open` refuses an audit entry
      whose `seq` is past its chain's head (`ErrSchema`, wrapping `audit.ErrBrokenChain`).

    `Config.AllowOwnerRuntime` waives only the who-the-role-is reasons (superuser, ownership, memberships, attributes,
    CREATE, a session mismatch, privileges beyond the allowlist), with a warning, for tests and development. It never
    waives a structural or missing-privilege failure.
- **Reserved pool.** It is used for denial appends only (denial reads go over the worker pool). It keeps `ReservedConns` connections open (default 2) and `Open` fails if they cannot
  be established. The server's `max_connections` and the role's `CONNECTION LIMIT` must cover `MaxConns + ReservedConns`
  for every process.
- **Startup verification and checkpoints (owned by WI-10c, which also schedules checkpoint writes).**
  - `VerifyChains` reads each chain's head first, walks the chain once up to that sequence number against its
    checkpoint using the audit package's rules, and requires the last entry's hash to equal the head's, which catches a
    moved head row. Entries appended after the head was read are ignored, so it is safe under load.
  - A chain with entries but **no checkpoint** is refused (`ErrNoCheckpoint`) unless `VerifyOptions{Bootstrap: true}`
    is passed. Bootstrap is a deliberate operator action (first start with checkpoints, or adopting a database), never
    a default, so deleting the checkpoint file does not reset protection.
  - `WriteCheckpoints` verifies each chain the same way and saves exactly the head that walk verified, so a rewrite
    between reads cannot capture the checkpoint. The file sink assumes a single writer process and refuses to move backwards.
- **Driver:** `github.com/jackc/pgx/v5`, the one new runtime dependency (pure Go, no cgo). Its requirements raise
  `golang.org/x/text` from v0.14.0 to v0.41.0. A test pins that `x/text/unicode/norm`, `x/text/cases` and `unicode`
  agree on the Unicode version, which `internal/contract` relies on.

## HTTP surface (WI-10b)

- **Spec:** `api/openapi.yaml` (OpenAPI 3.0.3) defines `POST /v1/webhooks/{forge}`, `GET /healthz` and `GET /readyz`.
- **Generated code:** oapi-codegen chi strict-server output goes in `internal/api/gen` (DO NOT EDIT) via `go generate`. `make gen-check` (part of `make check`) regenerates it with the same `go:generate` line and diffs.
- **Dependencies:** oapi-codegen is pinned in `tools/go.mod`, with `github.com/go-chi/chi/v5` and `github.com/oapi-codegen/runtime` at runtime.
- **Raw-body handling:** the signature is checked by middleware that reads the bounded raw body *before* the generated handler decodes it. Tests drive signed bytes through the generated chi router.
- **Errors:** RFC 9457 problem details with fixed messages.
- **Status codes:**
  - 202 for a new delivery, and also for an event type with no parser, for which nothing is recorded.
  - 200 for an idempotent repeat of a recorded delivery, and for `ping` (nothing recorded).
  - 400 for a malformed payload, a supported event without its installation or repository, or a bad `X-GitHub-Event` or `X-GitHub-Delivery` shape.
  - 401 for a missing, malformed or wrong signature, including one made with a rotated-out secret.
  - 403 when the signed installation or repository is not this install's. The scope check fails closed: an error is a 503.
  - 404 for an unknown forge, 409 for a receipt ID seen with a different digest (a SHA-256 collision, audited) or a work key held by another producer, 411 without a `Content-Length` (chunked is refused), 413 above 25 MiB, 415 for a content type other than `application/json`, and 503 for a store, secrets, scope or audit failure.
- **Work item:** key `delivery/<forge>/sha256-<hex body digest>`, kind `forge-event`, payload `{v, forge, delivery_id, hint}`.
  - The `delivery/` key prefix is reserved for ingest. Another producer holding a key gives a 409 and a log line.
  - The hint (`forge.EventHint`, filled by `internal/forge/github`) is IDs only: the installation, repositories and subject. It carries no raw body and no author, verdict or role.
  - **Scope:** every repository the hint names (the signed one plus related ones, such as a sub-issue's) must pass `Scope.Allowed`. An installation-level event (no repository) is checked by installation alone. WI-10c must scope-check every object it re-reads from a hint too.
  - **Revocation and membership events** (`installation`, `installation_repositories`, `member`, `membership`, `repository`) are recorded as hints and the repositories they name (`repository_ids`, `added_repository_ids`, `removed_repository_ids`) are listed in the hint as evidence only. They never widen scope. A `sub_issues` payload naming a sub-issue or parent issue must carry its repository (else 400). Authorization is always re-read at execution, whatever a hint says (SEC-10, NFR-5).
  - **Strict parsing:** `encoding/json/v2` rejects duplicate keys at any depth, and keys match case-sensitively. Refs must pass `git check-ref-format` rules and 255 bytes.
- **Header-binding precedence:** the generated router binds headers before the signature middleware runs. A request missing a routing header gets 400 before any signature check, and a missing or duplicated signature header gets 401 before the forge, content-type and size checks.
- **Unauthenticated cost bounds:**
  - The signature header and the secrets (at most 4; more is a 503 configuration error) are checked before the body is read, so a malformed signature reads zero body bytes.
  - The body streams once into a buffer sized from `Content-Length` while every secret's HMAC is computed incrementally.
  - A semaphore (`Deps.MaxConcurrentBodies`, default 16) bounds how many requests are in the authentication step (secrets lookup, body read, HMAC) at once. The secrets lookup happens under a slot, so unauthenticated requests cannot hammer the secrets backend.
  - A request waits at most `Deps.SlotWait` (default 1 s, from the injected `Clock`) for a slot, then gets 503, and the wait also ends with the request context. The slot is released before scope and store processing.
  - A read deadline (`Deps.BodyReadTimeout`, default 10 s) is set before the body is read, so an idle or slow body ends instead of holding a slot.
  - `Content-Length` is required (411), so the buffer is sized once and a chunked body cannot stream past the cap before it is refused.
- **New modules and why:**
  - `github.com/go-chi/chi/v5` (runtime): the one REST router (AGENTS.md). The generated chi server is built on it.
  - `github.com/oapi-codegen/runtime` (runtime): the helpers the oapi-codegen output imports (parameter binding and JSON body binding). Its indirect dependencies are `github.com/apapsch/go-jsonmerge/v2` and `github.com/google/uuid`.
  - `github.com/oapi-codegen/oapi-codegen/v2` (tools only, in `tools/go.mod`): the pinned generator, run by `make gen` and checked by `make gen-check`. It is not part of the shipped binary.

## Event loop (WI-10c)

- **Ownership:** `errgroup`-owned workers lease work items.
- **Handlers:** each one re-reads forge state and is idempotent through CAS.
- **Completion:** fenced by lease generation, so an expired holder's completion is rejected.
- **Forge writes:** an ambiguous forge write, such as a timeout after a push or a comment, is reconciled by re-reading before retrying.
- **Retries:** backoff and jitter come from an injected clock and randomness. They honour RetryAfter on rate limits, and `ErrIncomplete` retries.
- **Decision routing:**
  1. Parse a strict, closed command grammar.
  2. Build `authz.Decision` from the re-read object.
  3. Resolve the Target from store state.
  4. Call `Authorize` with the Txn.
  5. Apply the CAS on version plus `Target.Revision` in the same Txn.
- **Rate limiting:** per principal and per repo, before `Authorize`. `DeniedError.Reason` is never echoed.
