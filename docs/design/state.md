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
- **Atomic receipt.** Recording a delivery `(forge, delivery ID, body digest)` and enqueuing its work item happen in **one** transaction, so a crash can't leave a delivery recorded with its only work item lost. A repeat delivery ID with the same digest gets an idempotent 2xx. A repeat delivery ID with a different digest is rejected and audited.
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
    refuses (`ErrPrivilege`) a runtime credential that is a superuser, or that owns or inherits the owner of the
    tables, unless `Config.AllowOwnerRuntime` is set, which needs a logger and warns on every `Open`. The opt-out is for
    tests and development.
  - Every pooled connection pins `search_path` to the migrated schema and sets `lock_timeout` (default 5s) and
    `idle_in_transaction_session_timeout` (default 60s), both configurable.
- **Roles and appends.**
  - The runtime role does not own the tables. It has SELECT on the audit entries and chain heads, SELECT and INSERT on
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
  - `Open` judges the role by effective privileges, not by name: superuser, membership (including `NOINHERIT` and
    `SET`-only) in a table owner, a superuser role or `pg_write_all_data`, `pg_write_server_files` or
    `pg_execute_server_program`, and any privilege that only the owner's functions may use on the audit tables,
    including ones inherited through a group. `Migrate` verifies the grants it made. `Open` also compares each
    protective trigger's table, timing and events, and each protective function's body, security mode and pinned
    `search_path`, with what the embedded migrations install.
  - **Known gaps (WI-10d, [#6](https://github.com/elliott-davis/lightsout/issues/6)).** The check above is a denylist, and it
    still passes two misconfigured runtime roles: one with **column-level** INSERT or UPDATE grants on the audit or state
    tables, and one that **owns** (or is in the owner group of) the store schema or the database. Either can rewrite, wedge
    or wipe the audit tables. Until WI-10d replaces the check with an exact allowlist, the operator must give the runtime
    role no column grants, no ownership of the schema, database or its objects, and no CREATE on either.
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
- **Generated code:** oapi-codegen chi strict-server output goes in `internal/api/gen` (DO NOT EDIT) via `go generate`. A drift test regenerates it and diffs.
- **Dependencies:** oapi-codegen is pinned in `tools/go.mod`, with `github.com/go-chi/chi/v5` and `github.com/oapi-codegen/runtime` at runtime.
- **Raw-body handling:** the signature is checked by middleware that reads the bounded raw body *before* the generated handler decodes it. Tests drive signed bytes through the generated chi router.
- **Errors:** RFC 9457 problem details with fixed messages.

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
