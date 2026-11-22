// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

package pgstore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"embed"
	"fmt"
	"io/fs"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed migrations/*.sql
var migrationFS embed.FS

// MigrationLockKey is the advisory lock key the migrator holds while it migrates. Two processes starting at once
// serialize on it, so a migration never runs twice.
const MigrationLockKey int64 = 0x6c6f5f6d69677261 // "lo_migra"

type migration struct {
	version  int
	name     string
	sql      string
	checksum [sha256.Size]byte
}

var migrationName = regexp.MustCompile(`^(\d{4})_([a-z0-9_]+)\.sql$`)

func loadMigrations() ([]migration, error) {
	entries, err := fs.ReadDir(migrationFS, "migrations")
	if err != nil {
		return nil, fmt.Errorf("read embedded migrations: %w", err)
	}
	var out []migration
	for _, e := range entries {
		m := migrationName.FindStringSubmatch(e.Name())
		if m == nil {
			return nil, fmt.Errorf("migration file %q does not match NNNN_name.sql", e.Name())
		}
		v, _ := strconv.Atoi(m[1])
		b, err := migrationFS.ReadFile("migrations/" + e.Name())
		if err != nil {
			return nil, fmt.Errorf("read migration %s: %w", e.Name(), err)
		}
		out = append(out, migration{version: v, name: e.Name(), sql: string(b), checksum: sha256.Sum256(b)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].version < out[j].version })
	for i, m := range out {
		if m.version != i+1 {
			return nil, fmt.Errorf("migration versions must be contiguous from 1: found %d at position %d", m.version, i+1)
		}
	}
	return out, nil
}

// Migrate is the explicit operator step that creates and upgrades the schema. Run it with the tables' owner
// credential (ownerURL, whose search_path names the schema), never from the running service: [Open] only checks.
// It applies every pending embedded migration, each in its own transaction, while holding the advisory lock
// [MigrationLockKey], verifies the checksum of every applied one and, if runtimeRole is set, grants that existing
// role its least-privilege access (replacing whatever it held on the schema's tables). It is a no-op when the
// schema is current. A database that is ahead of this binary is an error: an older binary must not run against a
// newer schema.
func Migrate(ctx context.Context, ownerURL, runtimeRole string) error {
	pc, err := pgxpool.ParseConfig(ownerURL)
	if err != nil {
		return fmt.Errorf("parse owner URL: %w", err)
	}
	pc.MaxConns = 1
	pool, err := pgxpool.NewWithConfig(ctx, pc)
	if err != nil {
		return fmt.Errorf("open migration pool: %w", err)
	}
	defer pool.Close()
	return migrate(ctx, pool, runtimeRole)
}

func migrate(ctx context.Context, pool *pgxpool.Pool, runtimeRole string) error {
	migs, err := loadMigrations()
	if err != nil {
		return err
	}
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("acquire migration connection: %w", err)
	}
	defer conn.Release()
	if _, err = conn.Exec(ctx, `SELECT pg_advisory_lock($1)`, MigrationLockKey); err != nil {
		return fmt.Errorf("take migration lock: %w", err)
	}
	defer func() {
		// Unlock on a fresh context: the caller's may be cancelled. If this fails, the connection is destroyed
		// below, which also drops the session lock.
		if _, uerr := conn.Exec(context.WithoutCancel(ctx), `SELECT pg_advisory_unlock($1)`, MigrationLockKey); uerr != nil {
			_ = conn.Conn().Close(context.WithoutCancel(ctx))
		}
	}()

	if _, err = conn.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		version int PRIMARY KEY CHECK (version >= 1),
		name text NOT NULL,
		checksum bytea NOT NULL CHECK (length(checksum) = 32),
		applied_at timestamptz NOT NULL DEFAULT now())`); err != nil {
		return fmt.Errorf("create schema_migrations: %w", err)
	}
	applied, err := checkApplied(ctx, conn, migs)
	if err != nil {
		return err
	}
	for _, m := range migs[applied:] {
		if err := applyOne(ctx, conn, m); err != nil {
			return err
		}
	}
	if runtimeRole != "" {
		return grantRuntimeRole(ctx, conn, runtimeRole)
	}
	return nil
}

func applyOne(ctx context.Context, conn *pgxpool.Conn, m migration) (err error) {
	tx, err := conn.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("begin migration %s: %w", m.name, err)
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback(context.WithoutCancel(ctx))
		}
	}()
	// No arguments, so pgx uses the simple protocol and the file may hold many statements.
	if _, err = tx.Exec(ctx, m.sql); err != nil {
		return fmt.Errorf("apply migration %s: %w", m.name, err)
	}
	if _, err = tx.Exec(ctx, `INSERT INTO schema_migrations (version, name, checksum) VALUES ($1, $2, $3)`, m.version, m.name, m.checksum[:]); err != nil {
		return fmt.Errorf("record migration %s: %w", m.name, err)
	}
	if err = tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit migration %s: %w", m.name, err)
	}
	return nil
}

// checkApplied returns how many migrations the database has applied, after checking that they are exactly
// 1..n, that this binary knows all of them, and that each one's recorded checksum matches the embedded bytes: an
// applied migration that was edited afterwards means the schema is not what this code expects.
func checkApplied(ctx context.Context, conn queryer, migs []migration) (int, error) {
	rows, err := conn.Query(ctx, `SELECT version, name, checksum FROM schema_migrations ORDER BY version`)
	if err != nil {
		return 0, fmt.Errorf("read applied migrations: %w", err)
	}
	defer rows.Close()
	n := 0
	for rows.Next() {
		var v int
		var name string
		var sum []byte
		if err := rows.Scan(&v, &name, &sum); err != nil {
			return 0, fmt.Errorf("scan applied migration: %w", err)
		}
		n++
		if v != n {
			return 0, fmt.Errorf("applied migrations are not contiguous: found version %d at position %d", v, n)
		}
		if v > len(migs) {
			return 0, fmt.Errorf("database schema version %d is newer than this binary's %d", v, len(migs))
		}
		if m := migs[v-1]; m.name != name || !bytes.Equal(sum, m.checksum[:]) {
			return 0, fmt.Errorf("applied migration %d (%s) differs from this binary's embedded %s: refusing to run on an altered schema", v, name, m.name)
		}
	}
	if err := rows.Err(); err != nil {
		return 0, fmt.Errorf("read applied migrations: %w", err)
	}
	return n, nil
}

var roleName = regexp.MustCompile(`^[a-z_][a-z0-9_]{0,62}$`)

// grantRuntimeRole lets role, which must already exist, use the schema in the connection's search_path with the
// least privilege the store needs: SELECT only on the audit entries and chain heads (it appends through the
// owner's audit_append function), SELECT and INSERT only on the consumed set and the delivery receipts, and
// read-write on state and work. It does not own anything and cannot update, delete, truncate or alter the
// append-only tables. It is idempotent, and it first revokes everything the role held on the schema's tables.
func grantRuntimeRole(ctx context.Context, conn *pgxpool.Conn, role string) error {
	if !roleName.MatchString(role) {
		return fmt.Errorf("runtime role %q must match %s", role, roleName)
	}
	var schema string
	if err := conn.QueryRow(ctx, `SELECT current_schema()`).Scan(&schema); err != nil {
		return fmt.Errorf("read current schema: %w", err)
	}
	r, sch := pgx.Identifier{role}.Sanitize(), pgx.Identifier{schema}.Sanitize()
	for _, q := range []string{
		`GRANT USAGE ON SCHEMA ` + sch + ` TO ` + r,
		`REVOKE ALL ON ALL TABLES IN SCHEMA ` + sch + ` FROM ` + r,
		// The audit tables are readable only: appends go through audit_append, which runs as the owner.
		`GRANT SELECT ON audit_entries, audit_chain_heads, schema_migrations TO ` + r,
		`GRANT SELECT, INSERT ON consumed_decisions, deliveries TO ` + r,
		`GRANT SELECT, INSERT, UPDATE ON state_rows, work_items TO ` + r,
		`GRANT EXECUTE ON FUNCTION audit_lock_head(text), audit_append(text, bigint, integer, timestamptz, bytea, bytea, bytea) TO ` + r, //nolint:dupword // the function's argument types
	} {
		if _, err := conn.Exec(ctx, q); err != nil {
			return fmt.Errorf("grant to runtime role %s: %w", role, err)
		}
	}
	return verifyGrants(ctx, conn, role, schema)
}

// verifyGrants checks the outcome rather than trusting the statements: the role can use the schema and has every
// privilege it needs, and none that only the owner's functions may use, whether granted directly or inherited.
func verifyGrants(ctx context.Context, conn queryer, role, schema string) error {
	var usage bool
	if err := conn.QueryRow(ctx, `SELECT has_schema_privilege($1::name, $2::name, 'USAGE')`, role, schema).Scan(&usage); err != nil {
		return fmt.Errorf("check schema privilege of %s: %w", role, err)
	}
	if !usage {
		return fmt.Errorf("runtime role %s cannot use schema %s after the grant", role, schema)
	}
	for table, privs := range map[string][]string{
		"audit_entries": {privSelect}, tblHeads: {privSelect}, "schema_migrations": {privSelect},
		"consumed_decisions": {privSelect, privInsert}, "deliveries": {privSelect, privInsert},
		"state_rows": {privSelect, privInsert, "UPDATE"}, "work_items": {privSelect, privInsert, "UPDATE"},
	} {
		for _, p := range privs {
			var ok bool
			if err := conn.QueryRow(ctx, `SELECT has_table_privilege($1::name, $2, $3)`, role, table, p).Scan(&ok); err != nil {
				return fmt.Errorf("check %s on %s for %s: %w", p, table, role, err)
			}
			if !ok {
				return fmt.Errorf("runtime role %s lacks %s on %s after the grant", role, p, table)
			}
		}
	}
	for _, fn := range []string{
		"audit_lock_head(text)",
		"audit_append(text, bigint, integer, timestamptz, bytea, bytea, bytea)", //nolint:dupword // the function's argument types
	} {
		var ok bool
		if err := conn.QueryRow(ctx, `SELECT has_function_privilege($1::name, $2::regprocedure, 'EXECUTE')`, role, fn).Scan(&ok); err != nil {
			return fmt.Errorf("check EXECUTE on %s for %s: %w", fn, role, err)
		}
		if !ok {
			return fmt.Errorf("runtime role %s cannot execute %s after the grant", role, fn)
		}
	}
	forbidden, err := forbiddenPrivileges(ctx, conn, role)
	if err != nil {
		return err
	}
	if len(forbidden) > 0 {
		return fmt.Errorf("runtime role %s still holds privileges reserved for the owner's functions (through a group or default privileges?): %s", role, strings.Join(forbidden, ", "))
	}
	return nil
}

const (
	privSelect = "SELECT"
	privInsert = "INSERT"
)
