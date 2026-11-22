// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

package pgstore_test

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/elliott-davis/lightsout/internal/audit"
	"github.com/elliott-davis/lightsout/internal/authz"
	"github.com/elliott-davis/lightsout/internal/store"
	"github.com/elliott-davis/lightsout/internal/store/checkpoint"
	"github.com/elliott-davis/lightsout/internal/store/pgstore"
	"github.com/elliott-davis/lightsout/internal/store/storetest"
)

// embeddedMigrations is how many migrations the package embeds (migrations/NNNN_*.sql).
const embeddedMigrations = 2

const envURL = "LIGHTSOUT_TEST_POSTGRES_URL"

// baseURL returns the test database URL or skips the test, saying why.
func baseURL(t *testing.T) string {
	t.Helper()
	u := os.Getenv(envURL)
	if u == "" {
		t.Skipf("%s is not set: skipping the PostgreSQL store tests (a passing real-PostgreSQL run is a merge condition for WI-10a)", envURL)
	}
	return u
}

// newSchema creates an empty schema for one test and returns a URL whose search_path is that schema.
//
// Every call gets a database of its own: Open's checks are database-wide (definer functions, event triggers, default
// privileges, PUBLIC grants), so tests that share a database would see each other's setups.
func newSchema(t *testing.T) string {
	t.Helper()
	dbURL, _ := newDatabase(t)
	return newSchemaAt(t, dbURL)
}

// newSchemaAt is newSchema in the database base names.
func newSchemaAt(t *testing.T, base string) string {
	t.Helper()
	var b [6]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatal(err)
	}
	name := "lo_t_" + hex.EncodeToString(b[:])
	conn, err := pgx.Connect(t.Context(), base)
	if err != nil {
		t.Fatalf("connect to PostgreSQL: %v", err)
	}
	if _, err = conn.Exec(t.Context(), "CREATE SCHEMA "+name); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = conn.Exec(context.WithoutCancel(t.Context()), "DROP SCHEMA "+name+" CASCADE")
		_ = conn.Close(context.WithoutCancel(t.Context()))
	})
	u, err := url.Parse(base)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	q.Set("search_path", name)
	u.RawQuery = q.Encode()
	return u.String()
}

func migrate(t *testing.T, ownerURL, role string) {
	t.Helper()
	if err := pgstore.Migrate(t.Context(), ownerURL, role); err != nil {
		t.Fatalf("migrate: %v", err)
	}
}

func discardLogger() *slog.Logger { return slog.New(slog.DiscardHandler) }

// open migrates the schema as its owner (the test database's superuser) and opens the store as that same owner,
// which only tests may do (AllowOwnerRuntime).
func open(t *testing.T, schemaURL string, clock func() time.Time, mod func(*pgstore.Config)) *pgstore.Store {
	t.Helper()
	migrate(t, schemaURL, "")
	return openOnly(t, schemaURL, clock, mod)
}

func openOnly(t *testing.T, schemaURL string, clock func() time.Time, mod func(*pgstore.Config)) *pgstore.Store {
	t.Helper()
	cfg := pgstore.Config{URL: schemaURL, Clock: clock, AllowOwnerRuntime: true, Logger: discardLogger()}
	if mod != nil {
		mod(&cfg)
	}
	st, err := pgstore.Open(t.Context(), cfg)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

func admin(t *testing.T, schemaURL string) *pgx.Conn {
	t.Helper()
	c, err := pgx.Connect(t.Context(), schemaURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close(context.WithoutCancel(t.Context())) })
	return c
}

func TestConformance(t *testing.T) { // NFR-4, NFR-5, SEC-10
	baseURL(t)
	storetest.Run(t, func(t *testing.T, clock func() time.Time) store.Store {
		t.Helper()
		return open(t, newSchema(t), clock, nil)
	})
}

func newEnv(t *testing.T, mod func(*pgstore.Config)) (*storetest.Env, string) {
	t.Helper()
	u := newSchema(t)
	clock := storetest.NewClock()
	return &storetest.Env{T: t, Store: open(t, u, clock.Now, mod), Clock: clock}, u
}

// barrier releases n callers once all n have arrived.
type barrier struct{ wg sync.WaitGroup }

func newBarrier(n int) *barrier { b := &barrier{}; b.wg.Add(n); return b }
func (b *barrier) wait()        { b.wg.Done(); b.wg.Wait() }

// grant is what an action handler does after Authorize says yes: consume, audit, then CAS the state.
func grant(ctx context.Context, tx store.Txn, decisionID string) error {
	if err := tx.Consume(ctx, decisionID); err != nil {
		return err
	}
	if _, err := tx.Append(ctx, storetest.Record("grant "+decisionID)); err != nil {
		return err
	}
	r := storetest.NewRow("i1")
	r.CurrentRevision = storetest.Rev(2)
	_, err := tx.Put(ctx, r, 1, storetest.Rev(1))
	return err
}

func seed(t *testing.T, e *storetest.Env) {
	t.Helper()
	r := storetest.NewRow("i1")
	r.CurrentRevision = storetest.Rev(1)
	if err := e.Tx(func(tx store.Txn) error { _, err := tx.Put(t.Context(), r, 0, ""); return err }); err != nil {
		t.Fatal(err)
	}
}

func race(t *testing.T, e *storetest.Env, ids []string) []error {
	t.Helper()
	b := newBarrier(len(ids))
	errs := make([]error, len(ids))
	var wg sync.WaitGroup
	for i, id := range ids {
		wg.Go(func() {
			errs[i] = e.Store.Tx(t.Context(), func(ctx context.Context, tx store.Txn) error {
				b.wait() // every transaction is open on its own connection before any of them acts
				return grant(ctx, tx, id)
			})
		})
	}
	wg.Wait()
	return errs
}

func checkOneTransition(t *testing.T, e *storetest.Env) {
	t.Helper()
	var r store.Row
	if err := e.Tx(func(tx store.Txn) error {
		var err error
		r, err = tx.Get(t.Context(), store.KindIssue, "i1")
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if r.Version != 2 || r.CurrentRevision != storetest.Rev(2) {
		t.Errorf("row = %+v, want exactly one transition (version 2)", r)
	}
	h, err := e.DecisionLog().Verify(t.Context())
	if err != nil || h.Seq != 1 {
		t.Errorf("decision chain: head %+v err %v, want one contiguous committed grant", h, err)
	}
}

func TestRace_SameDecisionID_PG(t *testing.T) { // SEC-10, NFR-5
	e, _ := newEnv(t, nil)
	seed(t, e)
	errs := race(t, e, []string{"d-same", "d-same"})
	wins, replays := 0, 0
	for _, err := range errs {
		switch {
		case err == nil:
			wins++
		case errors.Is(err, authz.ErrReplayed):
			replays++
		default:
			t.Errorf("unexpected error: %v", err)
		}
	}
	if wins != 1 || replays != 1 {
		t.Fatalf("wins = %d replays = %d, want 1 and 1", wins, replays)
	}
	checkOneTransition(t, e)
}

func TestRace_DistinctIDsSameRevision_PG(t *testing.T) { // SEC-10, NFR-5
	e, _ := newEnv(t, nil)
	seed(t, e)
	ids := []string{"d-a", "d-b"}
	errs := race(t, e, ids)
	wins, loser := 0, ""
	for i, err := range errs {
		switch {
		case err == nil:
			wins++
		case errors.Is(err, store.ErrConflict):
			loser = ids[i]
		default:
			t.Errorf("unexpected error: %v", err)
		}
	}
	if wins != 1 || loser == "" {
		t.Fatalf("errs = %v, want one winner and one ErrConflict", errs)
	}
	checkOneTransition(t, e)
	// The loser's consumption rolled back with it: its decision ID is still usable.
	if err := e.Tx(func(tx store.Txn) error { return tx.Consume(t.Context(), loser) }); err != nil {
		t.Errorf("the losing decision ID %q was consumed: %v", loser, err)
	}
}

func TestTwoOwner_WorkerConnectionsBusy_PG(t *testing.T) { // NFR-4: a denial persists while every worker connection is busy
	e, _ := newEnv(t, func(c *pgstore.Config) { c.MaxConns = 1 })
	den := e.Denials()
	err := e.Tx(func(tx store.Txn) error {
		if _, err := tx.Append(t.Context(), storetest.Record("grant owner 1")); err != nil {
			return err
		}
		// The only worker connection is ours: a second transaction cannot start.
		ctx, cancel := context.WithTimeout(t.Context(), 300*time.Millisecond)
		defer cancel()
		if err := e.Store.Tx(ctx, func(context.Context, store.Txn) error { return nil }); err == nil {
			t.Error("a second transaction started although the worker pool is exhausted")
		}
		// The second owner's denial still persists, through the reserved pool.
		if _, err := den.Append(t.Context(), storetest.Record("deny owner 2")); err != nil {
			return err
		}
		return errors.New("roll back")
	})
	if err == nil {
		t.Fatal("expected the rollback error")
	}
	if h, _ := den.Head(t.Context()); h.Seq != 1 {
		t.Errorf("denial head seq = %d, want 1", h.Seq)
	}
	if h, _ := e.DecisionLog().Head(t.Context()); h.Seq != 0 {
		t.Errorf("decision head seq = %d, want 0", h.Seq)
	}
}

func TestKilledConnectionRollsBack_PG(t *testing.T) { // NFR-5
	e, u := newEnv(t, func(c *pgstore.Config) { c.ApplicationName = "lo-kill-test" })
	seed(t, e)
	adm := admin(t, u)
	err := e.Tx(func(tx store.Txn) error {
		if err := grant(t.Context(), tx, "d-kill"); err != nil {
			return err
		}
		tag, err := adm.Exec(t.Context(),
			`SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE application_name = 'lo-kill-test' AND state = 'idle in transaction'`)
		if err != nil || tag.RowsAffected() != 1 {
			t.Errorf("terminate: tag %v err %v, want exactly one worker connection", tag, err)
		}
		return tx.Consume(t.Context(), "after-kill") // the connection is gone
	})
	if err == nil {
		t.Fatal("transaction on a killed connection succeeded")
	}
	if errors.Is(err, authz.ErrReplayed) {
		t.Fatalf("a dead connection was reported as a replay: %v", err)
	}
	checkRow := func() store.Row {
		var r store.Row
		if err := e.Tx(func(tx store.Txn) error {
			var err error
			r, err = tx.Get(t.Context(), store.KindIssue, "i1")
			return err
		}); err != nil {
			t.Fatal(err)
		}
		return r
	}
	if r := checkRow(); r.Version != 1 {
		t.Errorf("row = %+v, want the killed transaction rolled back", r)
	}
	if h, _ := e.DecisionLog().Head(t.Context()); h.Seq != 0 {
		t.Errorf("decision head seq = %d, want 0", h.Seq)
	}
	if err := e.Tx(func(tx store.Txn) error { return grant(t.Context(), tx, "d-kill") }); err != nil {
		t.Errorf("retry of the same decision after the kill: %v", err)
	}
}

func countMigrations(t *testing.T, c *pgx.Conn) int {
	t.Helper()
	var n int
	if err := c.QueryRow(t.Context(), `SELECT count(*) FROM schema_migrations`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestRestartMigrationsNoop_PG(t *testing.T) { // NFR-4
	u := newSchema(t)
	clock := storetest.NewClock()
	st := open(t, u, clock.Now, nil)
	e := &storetest.Env{T: t, Store: st, Clock: clock}
	seed(t, e)
	if err := e.Tx(func(tx store.Txn) error {
		_, err := tx.Append(t.Context(), storetest.Record("before restart"))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	migrate(t, u, "")                     // a second migrate is a no-op
	st2 := openOnly(t, u, clock.Now, nil) // and Open only checks
	e2 := &storetest.Env{T: t, Store: st2, Clock: clock}
	if n := countMigrations(t, admin(t, u)); n != embeddedMigrations {
		t.Errorf("schema_migrations has %d rows after a restart, want %d", n, embeddedMigrations)
	}
	if h, err := e2.DecisionLog().Verify(t.Context()); err != nil || h.Seq != 1 {
		t.Errorf("chain after restart: %+v %v", h, err)
	}
	if err := e2.Tx(func(tx store.Txn) error {
		r, err := tx.Get(t.Context(), store.KindIssue, "i1")
		if err == nil && r.Version != 1 {
			t.Errorf("row after restart = %+v", r)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

func TestConcurrentMigrateAppliesOnce_PG(t *testing.T) { // NFR-4
	u := newSchema(t)
	var wg sync.WaitGroup
	for range 4 {
		wg.Go(func() {
			if err := pgstore.Migrate(t.Context(), u, ""); err != nil {
				t.Errorf("migrate: %v", err)
			}
		})
	}
	wg.Wait()
	if n := countMigrations(t, admin(t, u)); n != embeddedMigrations {
		t.Errorf("schema_migrations has %d rows, want %d", n, embeddedMigrations)
	}
}

func TestMigratorTakesAdvisoryLock_PG(t *testing.T) { // NFR-4
	u := newSchema(t)
	holder := admin(t, u)
	if _, err := holder.Exec(t.Context(), `SELECT pg_advisory_lock($1)`, pgstore.MigrationLockKey); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 300*time.Millisecond)
	defer cancel()
	if err := pgstore.Migrate(ctx, u, ""); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Migrate while the lock is held: err = %v, want it to block until the deadline", err)
	}
	var exists bool
	if err := holder.QueryRow(t.Context(), `SELECT to_regclass('state_rows') IS NOT NULL`).Scan(&exists); err != nil || exists {
		t.Fatalf("schema was created without the lock: exists=%v err=%v", exists, err)
	}
	if _, err := holder.Exec(t.Context(), `SELECT pg_advisory_unlock($1)`, pgstore.MigrationLockKey); err != nil {
		t.Fatal(err)
	}
	if err := pgstore.Migrate(t.Context(), u, ""); err != nil {
		t.Fatalf("Migrate after the lock was released: %v", err)
	}
}

func TestNewerSchemaRefused_PG(t *testing.T) { // NFR-4 negative
	u := newSchema(t)
	clock := storetest.NewClock()
	open(t, u, clock.Now, nil)
	adm := admin(t, u)
	if _, err := adm.Exec(t.Context(), `INSERT INTO schema_migrations (version, name, checksum) VALUES (99, 'future', decode(repeat('00', 32), 'hex'))`); err != nil {
		t.Fatal(err)
	}
	if _, err := pgstore.Open(t.Context(), pgstore.Config{URL: u, Clock: clock.Now, AllowOwnerRuntime: true, Logger: discardLogger()}); err == nil {
		t.Fatal("Open succeeded against a schema newer than the binary")
	}
}

func TestAppendOnlyTables_PG(t *testing.T) { // NFR-4 negative: an accidental UPDATE, DELETE or TRUNCATE fails
	e, u := newEnv(t, nil)
	if err := e.Tx(func(tx store.Txn) error {
		if err := tx.Consume(t.Context(), "d1"); err != nil {
			return err
		}
		if _, err := tx.RecordDelivery(t.Context(), "github", "x", storetestDigest(), storetest.Work("k")); err != nil {
			return err
		}
		_, err := tx.Append(t.Context(), storetest.Record("grant"))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	adm := admin(t, u)
	for _, q := range []string{
		`DELETE FROM consumed_decisions`,
		`UPDATE consumed_decisions SET decision_id = 'other'`,
		`TRUNCATE consumed_decisions`,
		`DELETE FROM deliveries`,
		`UPDATE deliveries SET forge = 'other'`,
		`TRUNCATE deliveries`,
		`DELETE FROM audit_entries`,
		`UPDATE audit_entries SET record = '\x7b7d'`,
		`TRUNCATE audit_entries CASCADE`,
		`UPDATE audit_chain_heads SET seq = seq + 2`,
		`UPDATE audit_chain_heads SET seq = seq - 1 WHERE seq > 0`,
		`UPDATE audit_chain_heads SET chain = 'other'`,
		`DELETE FROM audit_chain_heads`,
		`TRUNCATE audit_chain_heads CASCADE`,
	} {
		if _, err := adm.Exec(t.Context(), q); err == nil {
			t.Errorf("%s succeeded", q)
		}
	}
	// Defense in depth only: a superuser can disable the triggers, which is why checkpoints live outside the
	// database. Show that a truncated chain then fails against its checkpoint.
	sink, err := checkpoint.NewFile(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := e.Tx(func(tx store.Txn) error { _, err := tx.Append(t.Context(), storetest.Record("more")); return err }); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.WriteCheckpoints(t.Context(), e.Store, sink, store.VerifyOptions{Bootstrap: true}); err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		`ALTER TABLE audit_entries DISABLE TRIGGER USER`,
		`DELETE FROM audit_entries WHERE chain = 'decision' AND seq = 3`,
	} {
		if _, err := adm.Exec(t.Context(), q); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.VerifyChains(t.Context(), e.Store, sink, store.VerifyOptions{}); !errors.Is(err, audit.ErrBrokenChain) {
		t.Errorf("VerifyChains after tail truncation: err = %v, want ErrBrokenChain", err)
	}
}

func storetestDigest() store.Digest { return store.Digest{1} }

func TestOpenValidation_PG(t *testing.T) { // SEC-1 negative
	u := newSchema(t)
	for name, cfg := range map[string]pgstore.Config{
		"nil clock":                      {URL: u},
		"owner opt-out without a logger": {URL: u, Clock: time.Now, AllowOwnerRuntime: true},
		"negative pool":                  {URL: u, Clock: time.Now, MaxConns: -1},
		"negative resrv":                 {URL: u, Clock: time.Now, ReservedConns: -1},
		"bad URL":                        {URL: "postgres://%zz", Clock: time.Now},
	} {
		if st, err := pgstore.Open(t.Context(), cfg); err == nil {
			_ = st.Close()
			t.Errorf("%s: Open succeeded", name)
		}
	}
}

func TestMigrationChecksumMismatchRefused_PG(t *testing.T) { // NFR-4 negative
	u := newSchema(t)
	clock := storetest.NewClock()
	open(t, u, clock.Now, nil)
	adm := admin(t, u)
	if _, err := adm.Exec(t.Context(), `UPDATE schema_migrations SET checksum = decode(repeat('00', 32), 'hex')`); err != nil {
		t.Fatal(err)
	}
	_, err := pgstore.Open(t.Context(), pgstore.Config{URL: u, Clock: clock.Now, AllowOwnerRuntime: true, Logger: discardLogger()})
	if err == nil || !strings.Contains(err.Error(), "differs") {
		t.Fatalf("Open with an altered migration record: err = %v, want a refusal", err)
	}
}

func TestHeadRowTamperDetected_PG(t *testing.T) { // NFR-4 negative: a moved head row is not trusted
	e, u := newEnv(t, nil)
	for range 3 {
		if err := e.Tx(func(tx store.Txn) error { _, err := tx.Append(t.Context(), storetest.Record("g")); return err }); err != nil {
			t.Fatal(err)
		}
	}
	sink, err := checkpoint.NewFile(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := store.WriteCheckpoints(t.Context(), e.Store, sink, store.VerifyOptions{Bootstrap: true}); err != nil {
		t.Fatal(err)
	}
	adm := admin(t, u)
	// Defense in depth only: the owner can disable the triggers, so verification must catch what they would have.
	mustExec(t, adm, `ALTER TABLE audit_chain_heads DISABLE TRIGGER USER`)
	for name, step := range map[string][2]string{
		"forward":  {`UPDATE audit_chain_heads SET seq = seq + 5 WHERE chain = 'decision'`, `UPDATE audit_chain_heads SET seq = seq - 5 WHERE chain = 'decision'`},
		"rewound":  {`UPDATE audit_chain_heads SET seq = seq - 1 WHERE chain = 'decision'`, `UPDATE audit_chain_heads SET seq = seq + 1 WHERE chain = 'decision'`},
		"rehashed": {`UPDATE audit_chain_heads SET hash = decode(repeat('01', 32), 'hex') WHERE chain = 'decision'`, ``},
	} {
		if name == "rehashed" {
			var h []byte
			if err := adm.QueryRow(t.Context(), `SELECT hash FROM audit_chain_heads WHERE chain = 'decision'`).Scan(&h); err != nil {
				t.Fatal(err)
			}
			step[1] = `UPDATE audit_chain_heads SET hash = '\x` + hex.EncodeToString(h) + `' WHERE chain = 'decision'`
		}
		mustExec(t, adm, step[0])
		for _, opts := range []store.VerifyOptions{{}, {Bootstrap: true}} {
			if err := store.VerifyChains(t.Context(), e.Store, sink, opts); !errors.Is(err, audit.ErrBrokenChain) {
				t.Errorf("head %s (bootstrap=%v): err = %v, want ErrBrokenChain", name, opts.Bootstrap, err)
			}
		}
		mustExec(t, adm, step[1])
		if err := store.VerifyChains(t.Context(), e.Store, sink, store.VerifyOptions{}); err != nil {
			t.Fatalf("after restoring the head (%s): %v", name, err)
		}
	}
}

func mustExec(t *testing.T, c *pgx.Conn, q string) {
	t.Helper()
	if _, err := c.Exec(t.Context(), q); err != nil {
		t.Fatalf("%s: %v", q, err)
	}
}

// newRole creates a login role that owns nothing, with a connection limit, and returns its name.
func newRole(t *testing.T, limit int) string {
	t.Helper()
	var b [5]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatal(err)
	}
	name := "lo_rt_" + hex.EncodeToString(b[:])
	su, err := pgx.Connect(t.Context(), baseURL(t))
	if err != nil {
		t.Fatal(err)
	}
	mustExec(t, su, fmt.Sprintf(`CREATE ROLE %s LOGIN PASSWORD 'rt-pass' CONNECTION LIMIT %d`, name, limit))
	t.Cleanup(func() {
		ctx := context.WithoutCancel(t.Context())
		dropTestDatabases(ctx, t, su) // grants inside them would keep the role from being dropped
		_, _ = su.Exec(ctx, `DROP OWNED BY `+name)
		_, _ = su.Exec(ctx, `DROP ROLE `+name)
		_ = su.Close(ctx)
	})
	return name
}

func roleURL(t *testing.T, schemaURL, role string) string {
	t.Helper()
	u, err := url.Parse(schemaURL)
	if err != nil {
		t.Fatal(err)
	}
	u.User = url.UserPassword(role, "rt-pass")
	return u.String()
}

func openAsRole(t *testing.T, owner, role string, clock func() time.Time, mod func(*pgstore.Config)) *pgstore.Store {
	t.Helper()
	migrate(t, owner, role)
	return openOnly(t, roleURL(t, owner, role), clock, func(c *pgstore.Config) {
		c.AllowOwnerRuntime, c.Logger = false, nil // the runtime role really is one
		if mod != nil {
			mod(c)
		}
	})
}

func TestConformance_RuntimeRole_PG(t *testing.T) { // NFR-4: the whole suite passes under the least-privilege role
	baseURL(t)
	storetest.Run(t, func(t *testing.T, clock func() time.Time) store.Store {
		t.Helper()
		return openAsRole(t, newSchema(t), newRole(t, -1), clock, nil)
	})
}

func TestRuntimeRoleCannotAlterAppendOnlyTables_PG(t *testing.T) { // NFR-4 negative
	owner := newSchema(t)
	role := newRole(t, -1)
	st := openAsRole(t, owner, role, storetest.NewClock().Now, nil)
	e := &storetest.Env{T: t, Store: st, Clock: storetest.NewClock()}
	if err := e.Tx(func(tx store.Txn) error {
		if err := tx.Consume(t.Context(), "d1"); err != nil {
			return err
		}
		_, err := tx.Append(t.Context(), storetest.Record("grant"))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	rc := admin(t, roleURL(t, owner, role))
	for _, q := range []string{
		`ALTER TABLE audit_entries DISABLE TRIGGER USER`,
		`ALTER TABLE audit_chain_heads DISABLE TRIGGER USER`,
		`DROP TRIGGER audit_entries_append_only_row ON audit_entries`,
		`UPDATE audit_entries SET record = '\x7b7d'`,
		`DELETE FROM audit_entries`,
		`UPDATE consumed_decisions SET decision_id = 'x'`,
		`DELETE FROM consumed_decisions`,
		`TRUNCATE deliveries`,
		`UPDATE audit_chain_heads SET seq = seq + 5`,
		`DELETE FROM audit_chain_heads`,
		`UPDATE audit_chain_heads SET seq = 1, hash = decode(repeat('01', 32), 'hex') WHERE chain = 'decision'`,
		`INSERT INTO audit_entries (chain, seq, format, at, record, prev_hash, hash)
		 VALUES ('decision', 5, 1, now(), '\x7b7d', decode(repeat('00', 32), 'hex'), decode(repeat('01', 32), 'hex'))`,
		`SELECT audit_append('decision', 5, 1, now(), '\x7b7d', decode(repeat('00', 32), 'hex'), decode(repeat('01', 32), 'hex'))`,
		`SELECT audit_append('decision', 2, 1, now(), '\x7b7d', decode(repeat('00', 32), 'hex'), decode(repeat('01', 32), 'hex'))`,
		`SELECT audit_append('decision', 1, 1, now(), '\x7b7d', decode(repeat('09', 32), 'hex'), decode(repeat('01', 32), 'hex'))`,
		`SELECT audit_append('nope', 1, 1, now(), '\x7b7d', decode(repeat('00', 32), 'hex'), decode(repeat('01', 32), 'hex'))`,
		`CREATE TABLE lo_x (a int)`,
		`UPDATE schema_migrations SET checksum = checksum`,
	} {
		if _, err := rc.Exec(t.Context(), q); err == nil {
			t.Errorf("runtime role could run: %s", q)
		}
	}
}

func TestReservedPoolReallyReserved_PG(t *testing.T) { // NFR-4: a denial persists even when the role has no connection to spare
	owner := newSchema(t)
	const workers, reserved = 1, 2
	role := newRole(t, workers+reserved)
	clock := storetest.NewClock()
	st := openAsRole(t, owner, role, clock.Now, func(c *pgstore.Config) { c.MaxConns, c.ReservedConns = workers, reserved })
	e := &storetest.Env{T: t, Store: st, Clock: clock}
	den := e.Denials()
	err := e.Tx(func(tx store.Txn) error {
		if _, err := tx.Append(t.Context(), storetest.Record("grant")); err != nil { // the worker connection is in use
			return err
		}
		// Every connection the role may have is now the store's: nobody else can take one.
		if c, err := pgx.Connect(t.Context(), roleURL(t, owner, role)); err == nil {
			_ = c.Close(t.Context())
			t.Error("the role had a connection to spare: the reserved connections were not held")
		}
		if _, err := den.Append(t.Context(), storetest.Record("deny")); err != nil {
			t.Errorf("denial with every worker connection busy and the role at its limit: %v", err)
		}
		return errBoom
	})
	if !errors.Is(err, errBoom) {
		t.Fatal(err)
	}
	if h, _ := den.Head(t.Context()); h.Seq != 1 {
		t.Errorf("denial head seq = %d, want 1", h.Seq)
	}
}

func TestReservedPoolFailureFailsOpen_PG(t *testing.T) { // NFR-4 negative
	owner := newSchema(t)
	role := newRole(t, 1) // fewer connections than the reserved pool needs
	migrate(t, owner, role)
	_, err := pgstore.Open(t.Context(), pgstore.Config{URL: roleURL(t, owner, role), Clock: time.Now, ReservedConns: 2})
	if err == nil {
		t.Fatal("Open succeeded although the reserved connections could not be established")
	}
}

var errBoom = errors.New("boom")

func TestSkipLockedPin_PG(t *testing.T) { // NFR-5: a leaser skips an item a transaction has locked instead of waiting
	e, _ := newEnv(t, nil)
	if err := e.Tx(func(tx store.Txn) error { return tx.Enqueue(t.Context(), storetest.Work("k")) }); err != nil {
		t.Fatal(err)
	}
	l, err := e.Store.Lease(t.Context(), "a", 1, time.Minute)
	if err != nil || len(l) != 1 {
		t.Fatalf("lease: %v %v", l, err)
	}
	err = e.Tx(func(tx store.Txn) error {
		if cerr := tx.Complete(t.Context(), l[0]); cerr != nil { // locks the row, uncommitted
			return cerr
		}
		e.Clock.Advance(2 * time.Minute) // the lease is now expired, so the item is a candidate
		ctx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
		defer cancel()
		got, lerr := e.Store.Lease(ctx, "b", 1, time.Minute)
		if lerr != nil || len(got) != 0 {
			t.Errorf("lease of a locked item: %v %v, want an empty result and no error", got, lerr)
		}
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			t.Error("the lease waited on a locked row until its deadline instead of skipping it")
		}
		return errBoom
	})
	if !errors.Is(err, errBoom) {
		t.Fatal(err)
	}
	if got, err := e.Store.Lease(t.Context(), "b", 1, time.Minute); err != nil || len(got) != 1 {
		t.Fatalf("lease after the lock was released: %v %v", got, err)
	}
}

// authorizeMany is what a transaction authorizing several decisions does: every Consume first, in one global
// order, then the grants' appends.
func authorizeMany(ctx context.Context, tx store.Txn, ids []string) error {
	sorted := slices.Sorted(slices.Values(ids))
	for _, id := range sorted {
		if err := tx.Consume(ctx, id); err != nil {
			return err
		}
	}
	for _, id := range sorted {
		if _, err := tx.Append(ctx, storetest.Record("grant "+id)); err != nil {
			return err
		}
	}
	return nil
}

func TestMultiDecisionTransactionsDoNotDeadlock_PG(t *testing.T) { // SEC-10: Consume sorted, then Append
	e, _ := newEnv(t, nil)
	for round := range 20 {
		p := fmt.Sprintf("r%d-", round)
		sets := [][]string{{p + "a", p + "b", p + "c"}, {p + "b", p + "c", p + "d"}}
		b := newBarrier(len(sets))
		errs := make([]error, len(sets))
		var wg sync.WaitGroup
		for i, ids := range sets {
			wg.Go(func() {
				errs[i] = e.Store.Tx(t.Context(), func(ctx context.Context, tx store.Txn) error {
					b.wait()
					return authorizeMany(ctx, tx, ids)
				})
			})
		}
		wg.Wait()
		wins, replays := 0, 0
		for _, err := range errs {
			switch {
			case err == nil:
				wins++
			case errors.Is(err, authz.ErrReplayed):
				replays++
			default:
				t.Fatalf("round %d: unexpected error (a deadlock?): %v", round, err)
			}
		}
		if wins != 1 || replays != 1 {
			t.Fatalf("round %d: wins = %d replays = %d, want 1 and 1", round, wins, replays)
		}
	}
	if h, err := e.DecisionLog().Verify(t.Context()); err != nil || h.Seq != 60 {
		t.Fatalf("decision chain: %+v %v, want 60 contiguous entries (20 rounds of 3)", h, err)
	}
}

func TestOpenRefusals_PG(t *testing.T) { // NFR-4, SEC-10: Open checks the database read-only and refuses an unsafe one
	clock := storetest.NewClock()
	cfg := func(u string) pgstore.Config { return pgstore.Config{URL: u, Clock: clock.Now} }

	// An unmigrated schema is refused, and Open created nothing.
	bare := newSchema(t)
	owner := cfg(bare)
	owner.AllowOwnerRuntime, owner.Logger = true, discardLogger()
	if _, err := pgstore.Open(t.Context(), owner); !errors.Is(err, pgstore.ErrSchema) {
		t.Errorf("Open on an unmigrated schema: err = %v, want ErrSchema", err)
	}
	var exists bool
	if err := admin(t, bare).QueryRow(t.Context(), `SELECT to_regclass('state_rows') IS NOT NULL`).Scan(&exists); err != nil || exists {
		t.Errorf("Open created the schema: exists=%v err=%v", exists, err)
	}

	// The owner (here a superuser) is refused without the explicit opt-out, accepted with it, and warns.
	u := newSchema(t)
	role := newRole(t, -1)
	migrate(t, u, role)
	if _, err := pgstore.Open(t.Context(), cfg(u)); !errors.Is(err, pgstore.ErrPrivilege) {
		t.Errorf("Open as the owner: err = %v, want ErrPrivilege", err)
	}
	var logs strings.Builder
	allowed := cfg(u)
	allowed.AllowOwnerRuntime, allowed.Logger = true, slog.New(slog.NewTextHandler(&logs, nil))
	st, err := pgstore.Open(t.Context(), allowed)
	if err != nil {
		t.Fatalf("Open as the owner with the opt-out: %v", err)
	}
	_ = st.Close()
	if !strings.Contains(logs.String(), "pgstore_owner_runtime_credential") {
		t.Errorf("no warning logged for an owner credential: %q", logs.String())
	}

	// The runtime role on an already migrated schema works.
	rt, err := pgstore.Open(t.Context(), cfg(roleURL(t, u, role)))
	if err != nil {
		t.Fatalf("Open as the runtime role: %v", err)
	}
	_ = rt.Close()

	// A disabled trigger is refused, even for the owner with the opt-out.
	mustExec(t, admin(t, u), `ALTER TABLE audit_entries DISABLE TRIGGER audit_entries_append_only_row`)
	if _, err := pgstore.Open(t.Context(), allowed); !errors.Is(err, pgstore.ErrSchema) {
		t.Errorf("Open with a disabled trigger: err = %v, want ErrSchema", err)
	}
	if _, err := pgstore.Open(t.Context(), cfg(roleURL(t, u, role))); !errors.Is(err, pgstore.ErrSchema) {
		t.Errorf("Open as the runtime role with a disabled trigger: err = %v, want ErrSchema", err)
	}
}

func TestMigrateRevokesExtraGrants_PG(t *testing.T) { // NFR-4: a re-grant replaces whatever the role held
	owner := newSchema(t)
	role := newRole(t, -1)
	migrate(t, owner, role)
	adm := admin(t, owner)
	mustExec(t, adm, `GRANT UPDATE, DELETE ON audit_entries TO `+role)
	has := func() bool {
		var ok bool
		if err := adm.QueryRow(t.Context(), `SELECT has_table_privilege($1, 'audit_entries', 'UPDATE')`, role).Scan(&ok); err != nil {
			t.Fatal(err)
		}
		return ok
	}
	if !has() {
		t.Fatal("setup: the extra grant did not take")
	}
	migrate(t, owner, role)
	if has() {
		t.Error("the runtime role kept UPDATE on audit_entries after Migrate re-granted")
	}
	if _, err := admin(t, roleURL(t, owner, role)).Exec(t.Context(), `DELETE FROM audit_entries`); err == nil {
		t.Error("the runtime role can DELETE from audit_entries")
	}
}

func TestAuditAppendIgnoresTempShadow_PG(t *testing.T) { // NFR-4 negative: a temp table cannot shadow the chain head
	owner := newSchema(t)
	role := newRole(t, -1)
	migrate(t, owner, role)
	rc := admin(t, roleURL(t, owner, role))
	// Open refuses TEMP, so this is defense in depth: even a role that could shadow the head cannot move it.
	if _, err := rc.Exec(t.Context(), `CREATE TEMP TABLE lo_probe (a int)`); err == nil {
		t.Error("Migrate left the runtime role able to create temporary tables")
	}
	var db string
	if err := admin(t, owner).QueryRow(t.Context(), `SELECT current_database()`).Scan(&db); err != nil {
		t.Fatal(err)
	}
	mustExec(t, admin(t, owner), `GRANT TEMPORARY ON DATABASE `+db+` TO `+role)
	mustExec(t, rc, `CREATE TEMP TABLE audit_chain_heads (chain text, seq bigint, hash bytea)`)
	mustExec(t, rc, `INSERT INTO pg_temp.audit_chain_heads VALUES ('decision', 77, decode(repeat('07', 32), 'hex'))`)
	var seq int64
	if err := rc.QueryRow(t.Context(), `SELECT head_seq FROM audit_lock_head('decision')`).Scan(&seq); err != nil {
		t.Fatal(err)
	}
	if seq != 0 {
		t.Fatalf("audit_lock_head read the caller's temp table (seq %d), not the real head", seq)
	}
}

func TestAuthorizeMultiDecisionRetryOrSucceed_PG(t *testing.T) { // SEC-10: a deadlock fails closed as ErrRetry, never raw
	e, _ := newEnv(t, nil)
	seed(t, e)
	a := e.Authorizer()
	for round := range 5 {
		ids := [2]string{fmt.Sprintf("r%d-x", round), fmt.Sprintf("r%d-y", round)}
		b := newBarrier(2)
		errs := make([]error, 2)
		var wg sync.WaitGroup
		for i := range 2 {
			wg.Go(func() {
				errs[i] = e.Store.Tx(t.Context(), func(ctx context.Context, tx store.Txn) error {
					b.wait()
					// The two transactions authorize the same two decisions in opposite orders, each
					// consuming and then appending, which is the interleaving that can deadlock.
					for _, id := range []string{ids[i], ids[1-i]} {
						d, target := storetest.GrantInputs(id, e.Clock.Now())
						if _, err := a.Authorize(ctx, tx, d, target); err != nil {
							return err
						}
					}
					return nil
				})
			})
		}
		wg.Wait()
		wins := 0
		for _, err := range errs {
			var de *authz.DeniedError
			switch {
			case err == nil:
				wins++
			case errors.Is(err, store.ErrRetry):
			case errors.As(err, &de) && de.Reason == authz.ReasonReplayed:
				// The other transaction won the race for a decision ID: a legitimate denial.
			default:
				t.Fatalf("round %d: err = %v, want nil, ErrRetry or a replayed denial", round, err)
			}
		}
		if wins == 0 && !errors.Is(errors.Join(errs...), store.ErrRetry) && !errors.Is(errors.Join(errs...), authz.ErrDenied) {
			t.Fatalf("round %d: no transaction succeeded and none was told why: %v", round, errs)
		}
	}
	if _, err := e.DecisionLog().Verify(t.Context()); err != nil {
		t.Fatal(err)
	}
}

// privilegedRole sets up a migrated schema and a runtime role, then lets the owner widen what the role can do with
// the given statements, and returns the store config for opening as that role.
func privilegedRole(t *testing.T, stmts ...string) pgstore.Config {
	t.Helper()
	owner := newSchema(t)
	role := newRole(t, -1)
	migrate(t, owner, role)
	adm := admin(t, owner)
	for _, q := range stmts {
		q = strings.ReplaceAll(q, "$ROLE", role)
		mustExec(t, adm, q)
		if m := createRole.FindStringSubmatch(q); m != nil {
			dropRoleOnCleanup(t, m[1]) // a role a statement created is dropped with the test
		}
	}
	return pgstore.Config{URL: roleURL(t, owner, role), Clock: time.Now}
}

var createRole = regexp.MustCompile(`^CREATE ROLE (\w+)`)

// dropRoleOnCleanup drops a role this test created (and what it owns or was granted in this database) at the end
// of the test. Register it after the objects it depends on, so it runs before they are dropped.
func dropRoleOnCleanup(t *testing.T, role string) {
	t.Helper()
	t.Cleanup(func() {
		ctx := context.WithoutCancel(t.Context())
		c, err := pgx.Connect(ctx, baseURL(t))
		if err != nil {
			return
		}
		defer func() { _ = c.Close(ctx) }()
		dropTestDatabases(ctx, t, c)
		_, _ = c.Exec(ctx, "REASSIGN OWNED BY "+role+" TO CURRENT_USER")
		_, _ = c.Exec(ctx, "DROP OWNED BY "+role)
		_, _ = c.Exec(ctx, "DROP ROLE "+role)
	})
}

// testDatabases remembers, per test, the databases newDatabase created, so a role's cleanup can drop them first.
var testDatabases sync.Map // test name -> []string

func dropTestDatabases(ctx context.Context, t *testing.T, c *pgx.Conn) {
	t.Helper()
	v, _ := testDatabases.Load(t.Name())
	names, _ := v.([]string)
	for _, n := range names {
		_, _ = c.Exec(ctx, "DROP DATABASE IF EXISTS "+n+" WITH (FORCE)")
	}
}

func TestOpenRefusesEffectivePrivileges_PG(t *testing.T) { // SEC-10, NFR-4: what the role can do counts, not just who it is
	for name, stmts := range map[string][]string{
		"member of the owner, set only":   {`GRANT postgres TO $ROLE WITH INHERIT FALSE, SET TRUE`},
		"member of the owner, noinherit":  {`ALTER ROLE $ROLE NOINHERIT`, `GRANT postgres TO $ROLE`},
		"pg_write_all_data":               {`GRANT pg_write_all_data TO $ROLE`},
		"pg_write_server_files":           {`GRANT pg_write_server_files TO $ROLE`},
		"pg_execute_server_program":       {`GRANT pg_execute_server_program TO $ROLE`},
		"UPDATE on the audit entries":     {`GRANT UPDATE ON audit_entries TO $ROLE`},
		"INSERT on the chain heads":       {`GRANT INSERT ON audit_chain_heads TO $ROLE`},
		"TRUNCATE on the consumed set":    {`GRANT TRUNCATE ON consumed_decisions TO $ROLE`},
		"DELETE on the receipts":          {`GRANT DELETE ON deliveries TO $ROLE`},
		"TRIGGER on the migrations table": {`GRANT TRIGGER ON schema_migrations TO $ROLE`},
		"REFERENCES on the audit entries": {`GRANT REFERENCES ON audit_entries TO $ROLE`},
		"through a group that can write":  {`CREATE ROLE lo_grp_$ROLE NOLOGIN`, `GRANT INSERT, UPDATE ON audit_entries, audit_chain_heads TO lo_grp_$ROLE`, `GRANT lo_grp_$ROLE TO $ROLE`},
	} {
		cfg := privilegedRole(t, stmts...)
		if _, err := pgstore.Open(t.Context(), cfg); !errors.Is(err, pgstore.ErrPrivilege) {
			t.Errorf("%s: err = %v, want ErrPrivilege", name, err)
		}
	}
	// The unmodified runtime role is accepted.
	cfg := privilegedRole(t)
	st, err := pgstore.Open(t.Context(), cfg)
	if err != nil {
		t.Fatalf("a plain runtime role: %v", err)
	}
	_ = st.Close()
}

func TestMigrateRefusesRoleWithGroupGrants_PG(t *testing.T) { // NFR-4: Migrate verifies the grants it made
	owner := newSchema(t)
	role := newRole(t, -1)
	migrate(t, owner, "")
	adm := admin(t, owner)
	grp := role + "_grp"
	mustExec(t, adm, `CREATE ROLE `+grp+` NOLOGIN`)
	mustExec(t, adm, `GRANT UPDATE ON audit_entries TO `+grp)
	mustExec(t, adm, `GRANT `+grp+` TO `+role)
	dropRoleOnCleanup(t, grp)
	if err := pgstore.Migrate(t.Context(), owner, role); err == nil {
		t.Fatal("Migrate granted a role that still holds UPDATE on the audit entries through a group")
	}
}

func TestOpenRefusesReplacedProtections_PG(t *testing.T) { // NFR-4, SEC-10: the protections must be the ones the migrations created
	for name, stmts := range map[string][]string{
		"replaced trigger function": {`CREATE OR REPLACE FUNCTION forbid_change() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN OLD; END $$`},
		"replaced append function": {`CREATE OR REPLACE FUNCTION audit_lock_head(p_chain text) RETURNS TABLE (head_seq bigint, head_hash bytea)
			LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$ SELECT 0::bigint, '\x'::bytea $$`},
		"unpinned search_path": {`ALTER FUNCTION audit_append(text, bigint, integer, timestamptz, bytea, bytea, bytea) RESET search_path`},
		"security invoker":     {`ALTER FUNCTION audit_lock_head(text) SECURITY INVOKER`},
		"trigger on another event": {
			`DROP TRIGGER audit_entries_append_only_row ON audit_entries`,
			`CREATE TRIGGER audit_entries_append_only_row BEFORE DELETE ON audit_entries FOR EACH ROW EXECUTE FUNCTION forbid_change()`,
		},
		"trigger calling another function": {
			`DROP TRIGGER deliveries_append_only_stmt ON deliveries`,
			`CREATE TRIGGER deliveries_append_only_stmt BEFORE TRUNCATE ON deliveries FOR EACH STATEMENT EXECUTE FUNCTION head_advance_only()`,
		},
	} {
		owner := newSchema(t)
		migrate(t, owner, "")
		adm := admin(t, owner)
		for _, q := range stmts {
			mustExec(t, adm, q)
		}
		_, err := pgstore.Open(t.Context(), pgstore.Config{URL: owner, Clock: time.Now, AllowOwnerRuntime: true, Logger: discardLogger()})
		if !errors.Is(err, pgstore.ErrSchema) {
			t.Errorf("%s: err = %v, want ErrSchema", name, err)
		}
	}
}

func TestPlantedEntryDetected_PG(t *testing.T) { // NFR-4 negative: an entry ahead of the head is not an append
	e, u := newEnv(t, nil)
	for range 2 {
		if err := e.Tx(func(tx store.Txn) error { _, err := tx.Append(t.Context(), storetest.Record("g")); return err }); err != nil {
			t.Fatal(err)
		}
	}
	sink, err := checkpoint.NewFile(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	opts := store.VerifyOptions{Bootstrap: true}
	if err := store.VerifyChains(t.Context(), e.Store, sink, opts); err != nil {
		t.Fatal(err)
	}
	adm := admin(t, u)
	mustExec(t, adm, `ALTER TABLE audit_entries DISABLE TRIGGER USER`)
	mustExec(t, adm, `INSERT INTO audit_entries (chain, seq, format, at, record, prev_hash, hash)
		SELECT chain, 3, format, at, record, hash, decode(repeat('0a', 32), 'hex') FROM audit_entries WHERE chain = 'decision' AND seq = 2`)
	if err := store.VerifyChains(t.Context(), e.Store, sink, opts); !errors.Is(err, audit.ErrBrokenChain) {
		t.Fatalf("a planted entry beyond the head: err = %v, want ErrBrokenChain", err)
	}
}
