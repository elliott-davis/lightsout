// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

// Package pgstore is the PostgreSQL [store.Store], over a pgx v5 pool.
//
// State transactions run at READ COMMITTED. Correctness comes from explicit conditions: the consumed-decision
// primary key, a compare-and-swap on version and current revision, and a head row per audit chain locked FOR
// UPDATE. The denial chain is written over a separate, reserved pool so a denial persists even while every worker
// connection is busy. Schema changes are embedded, versioned SQL applied by [Migrate], an operator step run as the
// tables' owner under an advisory lock; [Open] only checks the result.
package pgstore

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/elliott-davis/lightsout/internal/audit"
	"github.com/elliott-davis/lightsout/internal/store"
)

// Defaults.
const (
	DefaultMaxConns      = 10
	DefaultReservedConns = 2
)

// Config configures [Open].
type Config struct {
	// URL is the connection string the store runs under: a runtime role that owns nothing in the database and holds
	// exactly the privileges [Migrate] grants (see there), in a database dedicated to the factory. Its search_path
	// names the migrated schema, which Open pins on every connection. The credential that logs in must be the role
	// it runs as (no role= or session_authorization= parameter, no role default). Open refuses anything else
	// unless AllowOwnerRuntime is set, and only waives the reasons listed there.
	//
	// What the role cannot do: alter or drop anything, disable a trigger, update or delete audit entries, consumed
	// decisions or receipts, move a chain head, or append an entry that does not extend its chain (appends go
	// through the owner's audit_append function, which checks seq and prev hash under the head lock). What it
	// can still do: append a correctly hashed entry of its own choosing, because the chain is unkeyed, and write
	// state rows and work items, which it must. Detecting a forged but well-formed entry needs an external signer,
	// a later work item. Checkpoints only protect the prefix they cover.
	URL string
	// AllowOwnerRuntime lets Open run with a credential that is too powerful for who it is: a superuser, an owner
	// of the schema, database or their objects (or a member of an owner), a member of any role, one with CREATEROLE,
	// CREATEDB, REPLICATION or BYPASSRLS, one that can CREATE in the schema or database, one whose login credential
	// differs from the role it runs as, or one holding privileges beyond the allowlist. It never waives the
	// structure of the schema (relations, triggers, rules, row security, columns, constraints, indexes, functions,
	// planted audit entries) or a privilege the role lacks. For tests and development only, and needs a Logger:
	// Open warns loudly each time.
	AllowOwnerRuntime bool
	// Logger receives the owner-credential warning. Required with AllowOwnerRuntime.
	Logger *slog.Logger
	// MaxConns is the size of the worker pool used by state transactions and leases. Default [DefaultMaxConns].
	MaxConns int
	// ReservedConns is the size of the separate pool used only to append to the denial chain. Default
	// [DefaultReservedConns]. Open establishes and keeps all of them (never recycled), and fails if it cannot. The
	// server's max_connections and the role's CONNECTION LIMIT must cover MaxConns + ReservedConns for every
	// process, or the reserved connections can be taken by others before they are made.
	ReservedConns int
	// LockTimeout bounds how long a statement waits for a lock on every runtime session. Zero means 5s, negative
	// means no limit. A statement that times out fails with [store.ErrRetry].
	LockTimeout time.Duration
	// IdleInTxTimeout ends a session that sits idle inside a transaction for this long, so a stuck caller cannot
	// hold the chain head lock forever. Zero means 60s, negative means no limit. A Tx function must not wait on
	// anything slow between statements.
	IdleInTxTimeout time.Duration
	// ApplicationName is reported to the server. Default "lightsout".
	ApplicationName string
	// Clock supplies times for lease expiry, receipts and consumption. Required.
	Clock func() time.Time
}

// Store is a PostgreSQL-backed [store.Store].
type Store struct {
	pool     *pgxpool.Pool // worker pool: state, leases, and every read
	reserved *pgxpool.Pool // denial appends only
	clock    func() time.Time
}

var _ store.Store = (*Store)(nil)

func timeoutParam(d, def time.Duration) string {
	switch {
	case d == 0:
		d = def
	case d < 0:
		return "0"
	}
	return strconv.FormatInt(d.Milliseconds(), 10)
}

// Open connects both pools and checks, read-only, that the database is ready: every embedded migration applied
// with a matching checksum, none newer, the schema exactly what the migrations create (relations, columns,
// constraints, indexes, functions, and every protective trigger present and enabled always), no audit entry past
// its chain's head, and the runtime role's effective privileges exactly the allowlist and nothing it should not be
// (see ErrPrivilege). It checks once, at startup: it cannot see a grant made afterwards. It never creates or alters
// anything: run [Migrate] first, as the owner. The caller must Close the store.
func Open(ctx context.Context, cfg Config) (*Store, error) {
	if cfg.Clock == nil {
		return nil, errors.New("pgstore: nil clock")
	}
	if cfg.AllowOwnerRuntime && cfg.Logger == nil {
		return nil, errors.New("pgstore: AllowOwnerRuntime needs a Logger to warn through")
	}
	if cfg.MaxConns == 0 {
		cfg.MaxConns = DefaultMaxConns
	}
	if cfg.ReservedConns == 0 {
		cfg.ReservedConns = DefaultReservedConns
	}
	if cfg.MaxConns < 1 || cfg.ReservedConns < 1 {
		return nil, fmt.Errorf("pgstore: pool sizes must be at least 1 (max %d, reserved %d)", cfg.MaxConns, cfg.ReservedConns)
	}
	if cfg.ApplicationName == "" {
		cfg.ApplicationName = "lightsout"
	}
	schema, err := currentSchema(ctx, cfg.URL)
	if err != nil {
		return nil, err
	}
	setPath := "SET search_path TO " + pgx.Identifier{schema}.Sanitize()
	mk := func(n int, reserved bool) (*pgxpool.Pool, error) {
		pc, perr := pgxpool.ParseConfig(cfg.URL)
		if perr != nil {
			return nil, fmt.Errorf("parse database URL: %w", perr)
		}
		n32 := int32(min(n, 1<<20)) //nolint:gosec // bounded by min
		pc.MaxConns = n32
		if reserved {
			// Keep every reserved connection open for the life of the store, so none is ever missing when a
			// denial needs it.
			pc.MinConns, pc.MinIdleConns = n32, n32
			pc.MaxConnLifetime, pc.MaxConnIdleTime = 0, 0
		}
		rp := pc.ConnConfig.RuntimeParams
		rp["application_name"] = cfg.ApplicationName
		rp["lock_timeout"] = timeoutParam(cfg.LockTimeout, 5*time.Second)
		rp["idle_in_transaction_session_timeout"] = timeoutParam(cfg.IdleInTxTimeout, 60*time.Second)
		pc.AfterConnect = func(ctx context.Context, c *pgx.Conn) error {
			_, aerr := c.Exec(ctx, setPath)
			return aerr
		}
		p, nerr := pgxpool.NewWithConfig(ctx, pc)
		if nerr != nil {
			return nil, fmt.Errorf("open pool: %w", nerr)
		}
		return p, nil
	}
	pool, err := mk(cfg.MaxConns, false)
	if err != nil {
		return nil, err
	}
	reserved, err := mk(cfg.ReservedConns, true)
	if err != nil {
		pool.Close()
		return nil, err
	}
	fail := func(err error) (*Store, error) {
		pool.Close()
		reserved.Close()
		return nil, err
	}
	if err := holdReserved(ctx, reserved, cfg.ReservedConns); err != nil {
		return fail(err)
	}
	for _, p := range []*pgxpool.Pool{pool, reserved} {
		why, err := checkSchema(ctx, p, cfg.AllowOwnerRuntime)
		if err != nil {
			return fail(err)
		}
		if why != "" {
			cfg.Logger.WarnContext(ctx, "pgstore_owner_runtime_credential", "detail", why+": the audit protections can be bypassed; for tests and development only")
		}
	}
	return &Store{pool: pool, reserved: reserved, clock: cfg.Clock}, nil
}

// currentSchema asks the server which schema the URL's search_path resolves to, so every pooled connection can pin
// exactly that one.
func currentSchema(ctx context.Context, url string) (string, error) {
	c, err := pgx.Connect(ctx, url)
	if err != nil {
		return "", fmt.Errorf("connect to the database: %w", err)
	}
	defer func() { _ = c.Close(context.WithoutCancel(ctx)) }()
	var schema *string
	if err := c.QueryRow(ctx, `SELECT current_schema()`).Scan(&schema); err != nil {
		return "", fmt.Errorf("read current schema: %w", err)
	}
	if schema == nil {
		return "", errors.New("pgstore: the URL's search_path names no existing schema")
	}
	return *schema, nil
}

// Close implements [store.Store].
func (s *Store) Close() error {
	s.pool.Close()
	s.reserved.Close()
	return nil
}

// Tx implements [store.Store].
func (s *Store) Tx(ctx context.Context, fn func(ctx context.Context, tx store.Txn) error) error {
	pt, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	t := &txn{s: s, tx: pt}
	committed := false
	defer func() {
		t.done = true
		if !committed {
			rollback(ctx, pt)
		}
	}()
	if err := fn(ctx, t); err != nil {
		return err
	}
	if err := pt.Commit(ctx); err != nil {
		return mapErr("commit transaction", err)
	}
	committed = true
	return nil
}

// rollback rolls back even when ctx is cancelled, but never waits forever.
func rollback(ctx context.Context, tx pgx.Tx) {
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	_ = tx.Rollback(rctx) // the connection is discarded if this fails
}

// Denials implements [store.Store]: the denial chain, over the reserved pool, one transaction per append.
func (s *Store) Denials() audit.Backend { return denialChain{reserved: s.reserved, pool: s.pool} }

// Decisions implements [store.Store]: a read-only view of the decision chain.
func (s *Store) Decisions() audit.Backend { return readChain{id: store.ChainDecision, q: s.pool} }

// Lease implements [store.Store].
func (s *Store) Lease(ctx context.Context, owner string, maxItems int, ttl time.Duration) ([]store.Lease, error) {
	if err := store.ValidateKey("lease owner", owner); err != nil {
		return nil, err
	}
	if maxItems < 1 || ttl <= 0 {
		return nil, fmt.Errorf("%w: lease max %d ttl %s", store.ErrInvalid, maxItems, ttl)
	}
	now := s.now()
	rows, err := s.pool.Query(ctx, `
WITH c AS (
    SELECT key FROM ONLY work_items
    WHERE NOT completed AND NOT dead
      AND (leased_until IS NULL OR leased_until <= $1)
      AND (not_before IS NULL OR not_before <= $1)
    ORDER BY seq LIMIT $2
    FOR UPDATE SKIP LOCKED)
UPDATE ONLY work_items w
SET generation = w.generation + 1, owner = $3, leased_until = $4
FROM c WHERE w.key = c.key
RETURNING w.seq, w.key, w.kind, w.payload, w.generation, w.leased_until, w.attempts`,
		now, maxItems, owner, now.Add(ttl).Truncate(time.Microsecond))
	if err != nil {
		return nil, fmt.Errorf("lease work: %w", err)
	}
	defer rows.Close()
	type seqLease struct {
		seq int64
		l   store.Lease
	}
	var got []seqLease
	for rows.Next() {
		var sl seqLease
		sl.l.Owner = owner
		if err := rows.Scan(&sl.seq, &sl.l.Key, &sl.l.Kind, &sl.l.Payload, &sl.l.Generation, &sl.l.Expires, &sl.l.Attempts); err != nil {
			return nil, fmt.Errorf("scan lease: %w", err)
		}
		sl.l.Expires = sl.l.Expires.UTC()
		got = append(got, sl)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("lease work: %w", err)
	}
	// RETURNING order is unspecified: oldest first.
	for i := 1; i < len(got); i++ {
		for j := i; j > 0 && got[j].seq < got[j-1].seq; j-- {
			got[j], got[j-1] = got[j-1], got[j]
		}
	}
	out := make([]store.Lease, len(got))
	for i := range got {
		out[i] = got[i].l
	}
	return out, nil
}

// holdReserved proves the reserved pool can really open all its connections at once, which also makes the pool
// create them now rather than when the first denial needs one.
func holdReserved(ctx context.Context, p *pgxpool.Pool, n int) error {
	conns := make([]*pgxpool.Conn, 0, n)
	defer func() {
		for _, c := range conns {
			c.Release()
		}
	}()
	for range n {
		c, err := p.Acquire(ctx)
		if err != nil {
			return fmt.Errorf("establish reserved denial connections (%d wanted): %w", n, err)
		}
		conns = append(conns, c)
	}
	return nil
}

// now is the store's time: UTC, at the microsecond precision PostgreSQL keeps, so a value round-trips unchanged.
func (s *Store) now() time.Time { return s.clock().UTC().Truncate(time.Microsecond) }
