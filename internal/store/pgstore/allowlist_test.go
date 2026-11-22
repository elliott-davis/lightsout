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
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/elliott-davis/lightsout/internal/audit"
	"github.com/elliott-davis/lightsout/internal/store"
	"github.com/elliott-davis/lightsout/internal/store/pgstore"
	"github.com/elliott-davis/lightsout/internal/store/storetest"
)

// newDatabase creates a database for one test, so a test can hand its ownership to a role, and returns a URL to it.
func newDatabase(t *testing.T) (dbURL, name string) {
	t.Helper()
	var b [6]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatal(err)
	}
	name = "lo_db_" + hex.EncodeToString(b[:])
	base := baseURL(t)
	su, err := pgx.Connect(t.Context(), base)
	if err != nil {
		t.Fatal(err)
	}
	mustExec(t, su, "CREATE DATABASE "+name)
	v, _ := testDatabases.Load(t.Name())
	prev, _ := v.([]string)
	testDatabases.Store(t.Name(), append(prev, name))
	t.Cleanup(func() {
		ctx := context.WithoutCancel(t.Context())
		_, _ = su.Exec(ctx, "DROP DATABASE "+name+" WITH (FORCE)")
		_ = su.Close(ctx)
	})
	u, err := url.Parse(base)
	if err != nil {
		t.Fatal(err)
	}
	u.Path = "/" + name
	return u.String(), name
}

func withSearchPath(t *testing.T, dbURL, path string) string {
	t.Helper()
	u, err := url.Parse(dbURL)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	q.Set("search_path", path)
	u.RawQuery = q.Encode()
	return u.String()
}

// runtimeOpen opens as the runtime role with no owner opt-out and returns the error, closing a store that opened.
func runtimeOpen(t *testing.T, u string) error {
	t.Helper()
	st, err := pgstore.Open(t.Context(), pgstore.Config{URL: u, Clock: time.Now})
	if err == nil {
		_ = st.Close()
	}
	return err
}

// reassignOnCleanup hands everything role owns back to the superuser before its role is dropped (newRole's cleanup
// runs after this one), so a test that made it an owner leaves nothing behind.
func reassignOnCleanup(t *testing.T, role string) {
	t.Helper()
	t.Cleanup(func() {
		ctx := context.WithoutCancel(t.Context())
		su, err := pgx.Connect(ctx, baseURL(t))
		if err != nil {
			return
		}
		defer func() { _ = su.Close(ctx) }()
		_, _ = su.Exec(ctx, "REASSIGN OWNED BY "+role+" TO CURRENT_USER")
	})
}

// fixture is a migrated store schema in a database of its own (the checks are database-wide, so a PUBLIC grant or a
// definer function in one test must not reach another), a runtime role and an empty group role.
type fixture struct {
	owner, role, group, schema, db string
	su                             *pgx.Conn
}

// newFixture registers cleanups so that the database is dropped first, then the group, then the role.
func newFixture(t *testing.T) fixture {
	t.Helper()
	f := fixture{role: newRole(t, -1)}
	reassignOnCleanup(t, f.role)
	f.group = f.role + "_g"
	base, err := pgx.Connect(t.Context(), baseURL(t))
	if err != nil {
		t.Fatal(err)
	}
	mustExec(t, base, `CREATE ROLE `+f.group)
	_ = base.Close(t.Context())
	dropRoleOnCleanup(t, f.group)
	var dbURL string
	dbURL, f.db = newDatabase(t)
	f.owner = newSchemaAt(t, dbURL)
	migrate(t, f.owner, f.role)
	f.su = admin(t, f.owner)
	if err := f.su.QueryRow(t.Context(), `SELECT current_schema()`).Scan(&f.schema); err != nil {
		t.Fatal(err)
	}
	return f
}

// sql fills %[1]s (runtime role), %[2]s (store schema), %[3]s (group role) and %[4]s (database) in q.
func (f fixture) sql(q string) string {
	return strings.NewReplacer("%[1]s", f.role, "%[2]s", f.schema, "%[3]s", f.group, "%[4]s", f.db).Replace(q)
}

func (f fixture) exec(t *testing.T, stmts ...string) {
	t.Helper()
	for _, q := range stmts {
		mustExec(t, f.su, f.sql(q))
	}
}

func (f fixture) roleURL(t *testing.T) string { t.Helper(); return roleURL(t, f.owner, f.role) }

func wantAny(errs ...error) []error { return errs }

// TestOpenExactAllowlist_PG is the negative suite for the startup privilege check: every way found to get past the
// old denylist, each against real PostgreSQL. Statements run as the superuser after Migrate; %[1]s is the runtime
// role, %[2]s the store schema, %[3]s a group role (created, empty), %[4]s the database. Open must fail with one of
// want (none: succeed).
func TestOpenExactAllowlist_PG(t *testing.T) { // NFR-4, NFR-5
	baseURL(t)
	t.Parallel()
	var (
		priv   = wantAny(pgstore.ErrPrivilege)
		schema = wantAny(pgstore.ErrSchema)
		either = wantAny(pgstore.ErrPrivilege, pgstore.ErrSchema)
	)
	const (
		fnAppend = `audit_append(text, bigint, integer, timestamptz, bytea, bytea, bytea)`
		rowTrig  = `CREATE TRIGGER audit_entries_append_only_row BEFORE %s ON audit_entries FOR EACH ROW %s EXECUTE FUNCTION forbid_change(%s)`
		other    = `CREATE SCHEMA %[2]s_o`
		useOther = `GRANT USAGE ON SCHEMA %[2]s_o TO %[1]s`
	)
	for name, tc := range map[string]struct {
		stmts   []string
		want    []error
		cleanup []string // run as the superuser, in the shared database, before the role is dropped
	}{
		"a correctly migrated runtime role opens": {nil, nil, nil},

		// HIGH 1: column-level grants are invisible to has_table_privilege.
		"column UPDATE on audit_entries":           {[]string{`GRANT UPDATE (record) ON audit_entries TO %[1]s`}, priv, nil},
		"column INSERT on audit_chain_heads":       {[]string{`GRANT INSERT (chain) ON audit_chain_heads TO %[1]s`}, priv, nil},
		"column UPDATE on consumed_decisions":      {[]string{`GRANT UPDATE (consumed_at) ON consumed_decisions TO %[1]s`}, priv, nil},
		"column REFERENCES on deliveries":          {[]string{`GRANT REFERENCES (forge) ON deliveries TO %[1]s`}, priv, nil},
		"column UPDATE on audit_entries to PUBLIC": {[]string{`GRANT UPDATE (record) ON audit_entries TO PUBLIC`}, priv, nil},

		// HIGH 2: owning, or being in the owner's group.
		"owns the schema":                  {[]string{`ALTER SCHEMA %[2]s OWNER TO %[1]s`}, priv, nil},
		"member of the schema owner group": {[]string{`ALTER SCHEMA %[2]s OWNER TO %[3]s`, `GRANT %[3]s TO %[1]s`}, priv, nil},
		"member of the owner, no inherit":  {[]string{`ALTER SCHEMA %[2]s OWNER TO %[3]s`, `GRANT %[3]s TO %[1]s WITH INHERIT FALSE`}, priv, nil},
		"owns a table":                     {[]string{`ALTER TABLE state_rows OWNER TO %[1]s`}, priv, nil},
		"member of a table owner group":    {[]string{`ALTER TABLE audit_entries OWNER TO %[3]s`, `GRANT %[3]s TO %[1]s`}, priv, nil},
		"owns a function":                  {[]string{`ALTER FUNCTION forbid_change() OWNER TO %[1]s`}, priv, nil},
		"CREATE on the schema":             {[]string{`GRANT CREATE ON SCHEMA %[2]s TO %[1]s`}, priv, nil},

		// Memberships the effective-privilege check cannot see: SET ROLE reaches them.
		"INHERIT FALSE group with DELETE on state_rows":  {[]string{`GRANT DELETE ON state_rows TO %[3]s`, `GRANT %[3]s TO %[1]s WITH INHERIT FALSE`}, priv, nil},
		"NOINHERIT role in a group with DELETE":          {[]string{`GRANT DELETE ON state_rows TO %[3]s`, `ALTER ROLE %[1]s NOINHERIT`, `GRANT %[3]s TO %[1]s`}, priv, nil},
		"ADMIN-only membership of an unprivileged group": {[]string{`GRANT %[3]s TO %[1]s WITH ADMIN TRUE, INHERIT FALSE, SET FALSE`}, priv, nil},
		"plain membership of an unprivileged group":      {[]string{`GRANT %[3]s TO %[1]s`}, priv, nil},

		// Role attributes and ownership anywhere in the database.
		"CREATEDB":                          {[]string{`ALTER ROLE %[1]s CREATEDB`}, priv, nil},
		"CREATEROLE":                        {[]string{`ALTER ROLE %[1]s CREATEROLE`}, priv, nil},
		"REPLICATION":                       {[]string{`ALTER ROLE %[1]s REPLICATION`}, priv, nil},
		"BYPASSRLS":                         {[]string{`ALTER ROLE %[1]s BYPASSRLS`}, priv, nil},
		"owns another schema":               {[]string{`CREATE SCHEMA %[2]s_o AUTHORIZATION %[1]s`}, priv, nil},
		"owns a function in another schema": {[]string{other, `CREATE FUNCTION %[2]s_o.f() RETURNS int LANGUAGE sql AS 'SELECT 1'`, `ALTER FUNCTION %[2]s_o.f() OWNER TO %[1]s`}, priv, nil},
		"CHECK calls a function the role owns": {[]string{
			other, `CREATE FUNCTION %[2]s_o.ok(bytea) RETURNS boolean LANGUAGE sql AS 'SELECT true'`,
			`ALTER FUNCTION %[2]s_o.ok(bytea) OWNER TO %[1]s`, `GRANT USAGE ON SCHEMA %[2]s_o TO PUBLIC`,
			`ALTER TABLE audit_entries ADD CONSTRAINT lo_ok CHECK (%[2]s_o.ok(record))`,
		}, either, nil},
		"event trigger runs a function the role owns": {[]string{
			other, `CREATE FUNCTION %[2]s_o.et() RETURNS event_trigger LANGUAGE plpgsql AS 'BEGIN END'`,
			`ALTER FUNCTION %[2]s_o.et() OWNER TO %[1]s`, `CREATE EVENT TRIGGER lo_et ON ddl_command_end EXECUTE FUNCTION %[2]s_o.et()`,
		}, either, nil},
		"event trigger with a definer function nobody can EXECUTE (DDL audit log)": {[]string{
			`CREATE SCHEMA ops`, `CREATE TABLE ops.ddl_log (tag text)`,
			`CREATE FUNCTION ops.log_ddl() RETURNS event_trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path = ops AS $$ BEGIN INSERT INTO ddl_log (tag) VALUES (tg_tag); END $$`,
			`REVOKE EXECUTE ON FUNCTION ops.log_ddl() FROM PUBLIC`, `CREATE EVENT TRIGGER lo_log ON ddl_command_end EXECUTE FUNCTION ops.log_ddl()`,
		}, schema, nil},
		"definer function with EXECUTE revoked from PUBLIC": {[]string{
			other, `CREATE FUNCTION %[2]s_o.purge() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS $$ BEGIN RETURN NEW; END $$`,
			`REVOKE EXECUTE ON FUNCTION %[2]s_o.purge() FROM PUBLIC`,
		}, schema, nil},
		"definer function in pg_catalog": {[]string{
			`CREATE FUNCTION pg_catalog.lo_run(q text) RETURNS void LANGUAGE plpgsql SECURITY DEFINER AS $$ BEGIN EXECUTE q; END $$`,
		}, schema, nil},
		"definer function in information_schema": {[]string{
			`CREATE FUNCTION information_schema.lo_run(q text) RETURNS void LANGUAGE plpgsql SECURITY DEFINER AS $$ BEGIN EXECUTE q; END $$`,
		}, schema, nil},
		"table in information_schema writable by the role": {[]string{
			`CREATE TABLE information_schema.lo_q (a int)`, `GRANT INSERT ON information_schema.lo_q TO %[1]s`,
		}, priv, nil},
		"TEMP on the database for the role": {[]string{`GRANT TEMPORARY ON DATABASE %[4]s TO %[1]s`}, priv, nil},
		"TEMP on the database for PUBLIC":   {[]string{`GRANT TEMPORARY ON DATABASE %[4]s TO PUBLIC`}, priv, nil},
		"CREATE on another schema":          {[]string{other, `GRANT USAGE, CREATE ON SCHEMA %[2]s_o TO %[1]s`}, priv, nil},
		"default privileges for the role":   {[]string{other, `ALTER DEFAULT PRIVILEGES IN SCHEMA %[2]s_o GRANT SELECT ON TABLES TO %[1]s`}, priv, nil},
		"default privileges for PUBLIC":     {[]string{`ALTER DEFAULT PRIVILEGES GRANT SELECT ON TABLES TO PUBLIC`}, priv, nil},
		"non-deterministic collation named default": {[]string{
			other, `CREATE COLLATION %[2]s_o."default" (provider = icu, locale = 'und-u-ks-level2', deterministic = false)`,
			`ALTER TABLE consumed_decisions ALTER COLUMN decision_id TYPE text COLLATE %[2]s_o."default"`,
		}, schema, nil},
		"table moved to another access method": {[]string{`CREATE ACCESS METHOD lo_am TYPE TABLE HANDLER heap_tableam_handler`, `ALTER TABLE deliveries SET ACCESS METHOD lo_am`}, schema, nil},
		"storage options on work_items":        {[]string{`ALTER TABLE work_items SET (autovacuum_vacuum_scale_factor = 0.01)`}, nil, nil},

		// Wired to the store tables from outside the schema.
		"inheritance child owned by the owner": {[]string{other, `CREATE TABLE %[2]s_o.ae () INHERITS (audit_entries)`}, schema, nil},
		"inheritance child owned by the role":  {[]string{other, `CREATE TABLE %[2]s_o.ae () INHERITS (audit_entries)`, `ALTER TABLE %[2]s_o.ae OWNER TO %[1]s`}, either, nil},
		"view over state_rows granted DELETE":  {[]string{other, useOther, `CREATE VIEW %[2]s_o.sr AS SELECT * FROM state_rows`, `GRANT DELETE ON %[2]s_o.sr TO %[1]s`}, schema, nil},
		"foreign key from another schema":      {[]string{other, `CREATE TABLE %[2]s_o.t (chain text REFERENCES audit_chain_heads (chain))`}, schema, nil},

		// Database-wide rules.
		"definer function in another schema, executable by PUBLIC": {[]string{
			other, useOther, `CREATE FUNCTION %[2]s_o.run(q text) RETURNS void LANGUAGE plpgsql SECURITY DEFINER AS $$ BEGIN EXECUTE q; END $$`,
		}, schema, nil},
		"INSERT on a table in another schema":        {[]string{other, useOther, `CREATE TABLE %[2]s_o.t (a int)`, `GRANT INSERT ON %[2]s_o.t TO %[1]s`}, priv, nil},
		"column UPDATE on a table in another schema": {[]string{other, useOther, `CREATE TABLE %[2]s_o.t (a int)`, `GRANT UPDATE (a) ON %[2]s_o.t TO %[1]s`}, priv, nil},
		"SET on session_replication_role": {
			[]string{`GRANT SET ON PARAMETER session_replication_role TO %[1]s`},
			priv,
			[]string{`REVOKE SET ON PARAMETER session_replication_role FROM %[1]s`},
		},
		"ALTER SYSTEM on a parameter": {
			[]string{`GRANT ALTER SYSTEM ON PARAMETER work_mem TO %[1]s`},
			priv,
			[]string{`REVOKE ALTER SYSTEM ON PARAMETER work_mem FROM %[1]s`},
		},
		"USAGE on a foreign server": {[]string{`CREATE FOREIGN DATA WRAPPER lo_fdw`, `CREATE SERVER lo_srv FOREIGN DATA WRAPPER lo_fdw`, `GRANT USAGE ON FOREIGN SERVER lo_srv TO %[1]s`}, priv, nil},
		"a user mapping":            {[]string{`CREATE FOREIGN DATA WRAPPER lo_fdw`, `CREATE SERVER lo_srv FOREIGN DATA WRAPPER lo_fdw`, `CREATE USER MAPPING FOR %[1]s SERVER lo_srv`}, priv, nil},

		// Table-level excess and shortfall, and the other object kinds.
		"DELETE on state_rows":                   {[]string{`GRANT DELETE ON state_rows TO %[1]s`}, priv, nil},
		"TRUNCATE on work_items":                 {[]string{`GRANT TRUNCATE ON work_items TO %[1]s`}, priv, nil},
		"TRIGGER on state_rows":                  {[]string{`GRANT TRIGGER ON state_rows TO %[1]s`}, priv, nil},
		"UPDATE on audit_entries via PUBLIC":     {[]string{`GRANT UPDATE ON audit_entries TO PUBLIC`}, priv, nil},
		"INSERT on schema_migrations":            {[]string{`GRANT INSERT ON schema_migrations TO %[1]s`}, priv, nil},
		"EXECUTE on an extra function":           {[]string{`CREATE FUNCTION %[2]s.lo_extra() RETURNS int LANGUAGE sql AS 'SELECT 1'`}, priv, nil},
		"USAGE on the identity sequence":         {[]string{`GRANT USAGE ON ALL SEQUENCES IN SCHEMA %[2]s TO %[1]s`}, priv, nil},
		"INSERT on deliveries WITH GRANT OPTION": {[]string{`GRANT INSERT ON deliveries TO %[1]s WITH GRANT OPTION`}, priv, nil},
		"column SELECT WITH GRANT OPTION":        {[]string{`GRANT SELECT (forge) ON deliveries TO %[1]s WITH GRANT OPTION`}, priv, nil},
		"EXECUTE WITH GRANT OPTION":              {[]string{`GRANT EXECUTE ON FUNCTION audit_lock_head(text) TO %[1]s WITH GRANT OPTION`}, priv, nil},
		"USAGE on the schema WITH GRANT OPTION":  {[]string{`GRANT USAGE ON SCHEMA %[2]s TO %[1]s WITH GRANT OPTION`}, priv, nil},
		"missing UPDATE on state_rows":           {[]string{`REVOKE UPDATE ON state_rows FROM %[1]s`}, schema, nil},
		"missing SELECT on audit_entries":        {[]string{`REVOKE SELECT ON audit_entries FROM %[1]s`}, schema, nil},
		"missing EXECUTE on the append funcs":    {[]string{`REVOKE EXECUTE ON FUNCTION ` + fnAppend + ` FROM %[1]s`}, schema, nil},

		// The exact protection set.
		"extra trigger on a protected table": {[]string{`CREATE TRIGGER lo_extra AFTER INSERT ON audit_entries FOR EACH ROW EXECUTE FUNCTION forbid_change()`}, schema, nil},
		"extra trigger on state_rows":        {[]string{`CREATE TRIGGER lo_extra BEFORE INSERT ON state_rows FOR EACH ROW EXECUTE FUNCTION forbid_change()`}, schema, nil},
		"trigger with a WHEN clause": {[]string{
			`DROP TRIGGER audit_entries_append_only_row ON audit_entries`, fmt.Sprintf(rowTrig, "UPDATE OR DELETE", "WHEN (false)", ""),
		}, schema, nil},
		"trigger with a column list": {[]string{
			`DROP TRIGGER audit_entries_append_only_row ON audit_entries`, fmt.Sprintf(rowTrig, "UPDATE OF record OR DELETE", "", ""),
		}, schema, nil},
		"trigger with arguments": {[]string{
			`DROP TRIGGER audit_entries_append_only_row ON audit_entries`, fmt.Sprintf(rowTrig, "UPDATE OR DELETE", "", "'x'"),
		}, schema, nil},
		"trigger reset to enabled for origin only":  {[]string{`ALTER TABLE audit_entries ENABLE TRIGGER audit_entries_append_only_row`}, schema, nil},
		"trigger reset to enabled for replica only": {[]string{`ALTER TABLE deliveries ENABLE REPLICA TRIGGER deliveries_append_only_stmt`}, schema, nil},
		"rewrite rule":                     {[]string{`CREATE RULE lo_rule AS ON INSERT TO state_rows DO ALSO NOTHING`}, schema, nil},
		"rewrite rule on audit":            {[]string{`CREATE RULE lo_rule AS ON UPDATE TO audit_entries DO INSTEAD NOTHING`}, schema, nil},
		"row-level security":               {[]string{`ALTER TABLE state_rows ENABLE ROW LEVEL SECURITY`}, schema, nil},
		"forced row-level security":        {[]string{`ALTER TABLE audit_entries FORCE ROW LEVEL SECURITY`}, schema, nil},
		"a policy":                         {[]string{`CREATE POLICY lo_pol ON work_items USING (true)`}, schema, nil},
		"extra table":                      {[]string{`CREATE TABLE %[2]s.lo_extra (a int)`}, schema, nil},
		"extra view":                       {[]string{`CREATE VIEW %[2]s.lo_view AS SELECT 1 AS a`}, schema, nil},
		"definer function gains a setting": {[]string{`ALTER FUNCTION audit_lock_head(text) SET work_mem = '1MB'`}, schema, nil},
		"invoker function gains a setting": {[]string{`ALTER FUNCTION forbid_change() SET work_mem = '1MB'`}, schema, nil},
		"function volatility changed":      {[]string{`ALTER FUNCTION forbid_change() IMMUTABLE`}, schema, nil},
		"function made strict":             {[]string{`ALTER FUNCTION audit_lock_head(text) STRICT`}, schema, nil},
		"function made leakproof":          {[]string{`ALTER FUNCTION forbid_change() LEAKPROOF`}, schema, nil},

		// Constraints, indexes, columns and defaults no privilege check sees.
		"primary key dropped from consumed_decisions": {[]string{`ALTER TABLE consumed_decisions DROP CONSTRAINT consumed_decisions_pkey`}, schema, nil},
		"CHECK added":                          {[]string{`ALTER TABLE state_rows ADD CONSTRAINT lo_chk CHECK (version < 100)`}, schema, nil},
		"column with a volatile default added": {[]string{`ALTER TABLE state_rows ADD COLUMN lo_x timestamptz DEFAULT clock_timestamp()`}, schema, nil},
		"column default changed":               {[]string{`ALTER TABLE work_items ALTER COLUMN attempts SET DEFAULT 5`}, schema, nil},
		"column dropped":                       {[]string{`ALTER TABLE deliveries DROP COLUMN digest`}, schema, nil},
		"extra index":                          {[]string{`CREATE INDEX lo_idx ON state_rows (repo)`}, schema, nil},

		// A planted entry past the head, in one statement.
		"planted entry beyond the head": {[]string{
			`INSERT INTO audit_entries (chain, seq, format, at, record, prev_hash, hash)
			 VALUES ('decision', 1, 1, now(), '\x7b7d', decode(repeat('00', 32), 'hex'), decode(repeat('0a', 32), 'hex'))`,
		}, schema, nil},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			f := newFixture(t)
			if len(tc.cleanup) > 0 {
				t.Cleanup(func() {
					ctx := context.WithoutCancel(t.Context())
					c, err := pgx.Connect(ctx, baseURL(t))
					if err != nil {
						return
					}
					defer func() { _ = c.Close(ctx) }()
					for _, q := range tc.cleanup {
						_, _ = c.Exec(ctx, f.sql(q))
					}
				})
			}
			f.exec(t, tc.stmts...)
			err := runtimeOpen(t, f.roleURL(t))
			if len(tc.want) == 0 {
				if err != nil {
					t.Errorf("Open: %v, want success", err)
				}
				return
			}
			for _, w := range tc.want {
				if errors.Is(err, w) {
					return
				}
			}
			t.Errorf("Open: err = %v, want one of %v", err, tc.want)
		})
	}
}

// TestOpenRefusesSessionRoleMismatch_PG: current_user is the runtime role but the credential that logged in is not,
// so whoever holds it can reset to its own powers.
func TestOpenRefusesSessionRoleMismatch_PG(t *testing.T) { // NFR-4, NFR-5
	baseURL(t)
	t.Parallel()
	for name, mk := range map[string]func(t *testing.T, f fixture) string{
		"role= startup parameter on a superuser credential": func(t *testing.T, f fixture) string {
			t.Helper()
			return withParam(f.owner, "role", f.role)
		},
		"session_authorization= startup parameter": func(t *testing.T, f fixture) string {
			t.Helper()
			return withParam(f.owner, "session_authorization", f.role)
		},
		"ALTER ROLE ... SET role on a superuser": func(t *testing.T, f fixture) string {
			t.Helper()
			sup := f.role + "_su"
			base, err := pgx.Connect(t.Context(), baseURL(t))
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = base.Close(t.Context()) }()
			mustExec(t, base, `CREATE ROLE `+sup+` LOGIN SUPERUSER PASSWORD 'rt-pass'`)
			dropRoleOnCleanup(t, sup)
			mustExec(t, f.su, `ALTER ROLE `+sup+` SET role = '`+f.role+`'`)
			return roleURL(t, f.owner, sup)
		},
		"ALTER DATABASE ... SET role": func(t *testing.T, f fixture) string {
			t.Helper()
			mustExec(t, f.su, `ALTER DATABASE `+f.db+` SET role = '`+f.role+`'`)
			return f.owner
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			f := newFixture(t)
			u := mk(t, f)
			if err := runtimeOpen(t, u); !errors.Is(err, pgstore.ErrPrivilege) {
				t.Errorf("Open: err = %v, want ErrPrivilege", err)
			}
		})
	}
}

func withParam(u, k, v string) string {
	pu, err := url.Parse(u)
	if err != nil {
		panic(err) // a test URL built by this package
	}
	q := pu.Query()
	q.Set(k, v)
	pu.RawQuery = q.Encode()
	return pu.String()
}

// TestProtectionTriggersFireInReplicaMode_PG: ENABLE ALWAYS keeps the append-only triggers on when a session sets
// session_replication_role = replica (which a role granted SET on it, or given it as a default, can do).
func TestProtectionTriggersFireInReplicaMode_PG(t *testing.T) { // NFR-4
	owner := newSchema(t)
	migrate(t, owner, "")
	su := admin(t, owner)
	mustExec(t, su, `INSERT INTO consumed_decisions VALUES ('d1', now())`)
	mustExec(t, su, `SET session_replication_role = replica`)
	for _, q := range []string{`DELETE FROM consumed_decisions`, `UPDATE consumed_decisions SET decision_id = 'x'`, `TRUNCATE consumed_decisions`} {
		if _, err := su.Exec(t.Context(), q); err == nil {
			t.Errorf("%s succeeded in replica mode", q)
		}
	}
}

// TestOpenRefusesDatabaseOwner_PG: a role that owns the database, or is in its owner group, can drop the
// protections, with the store in its own schema or in public (whose owner is pg_database_owner).
func TestOpenRefusesDatabaseOwner_PG(t *testing.T) { // NFR-4, NFR-5
	baseURL(t)
	t.Parallel()
	for name, tc := range map[string]struct {
		searchPath string // "" makes a schema of its own
		stmt       string // %[1]s role, %[2]s database
	}{
		"own schema, owns the database":      {"", `ALTER DATABASE %[2]s OWNER TO %[1]s`},
		"public schema, owns the database":   {"public", `ALTER DATABASE %[2]s OWNER TO %[1]s`},
		"own schema, CREATE on the database": {"", `GRANT CREATE ON DATABASE %[2]s TO %[1]s`},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			// The role first, so the database is dropped before the role: a grant in another database would
			// otherwise keep the role from being dropped.
			role := newRole(t, -1)
			reassignOnCleanup(t, role)
			dbURL, db := newDatabase(t)
			var owner string
			if tc.searchPath == "" {
				owner = newSchemaAt(t, dbURL)
			} else {
				owner = withSearchPath(t, dbURL, tc.searchPath)
			}
			migrate(t, owner, role)
			if err := runtimeOpen(t, roleURL(t, owner, role)); err != nil {
				t.Fatalf("Open before the change: %v", err)
			}
			mustExec(t, admin(t, owner), strings.NewReplacer("%[1]s", role, "%[2]s", db).Replace(tc.stmt))
			if err := runtimeOpen(t, roleURL(t, owner, role)); !errors.Is(err, pgstore.ErrPrivilege) {
				t.Errorf("Open: err = %v, want ErrPrivilege", err)
			}
		})
	}
}

// TestOpenOptOutWaivesOnlyWhoTheRoleIs_PG: AllowOwnerRuntime waives who the role is (superuser, owner, memberships,
// attributes, CREATE, session mismatch) with a warning, never what the schema is or what the role lacks.
func TestOpenOptOutWaivesOnlyWhoTheRoleIs_PG(t *testing.T) { // NFR-4
	baseURL(t)
	t.Parallel()
	open := func(t *testing.T, u string) error {
		t.Helper()
		var logs strings.Builder
		st, err := pgstore.Open(t.Context(), pgstore.Config{URL: u, Clock: time.Now, AllowOwnerRuntime: true, Logger: slog.New(slog.NewTextHandler(&logs, nil))})
		if err == nil {
			_ = st.Close()
			if !strings.Contains(logs.String(), "pgstore_owner_runtime_credential") {
				t.Errorf("Open succeeded without the owner-credential warning: %q", logs.String())
			}
		}
		return err
	}
	for name, tc := range map[string]struct {
		asOwner bool     // open with the superuser credential instead of the runtime role
		stmts   []string // %[1]s role
		want    error
	}{
		"the superuser owner":             {true, nil, nil},
		"a role with CREATEDB":            {false, []string{`ALTER ROLE %[1]s CREATEDB`}, nil},
		"a role in a group":               {false, []string{`GRANT pg_monitor TO %[1]s`}, nil},
		"extra trigger, owner":            {true, []string{`CREATE TRIGGER lo_extra BEFORE INSERT ON state_rows FOR EACH ROW EXECUTE FUNCTION forbid_change()`}, pgstore.ErrSchema},
		"rule, owner":                     {true, []string{`CREATE RULE lo_rule AS ON INSERT TO state_rows DO ALSO NOTHING`}, pgstore.ErrSchema},
		"row-level security, owner":       {true, []string{`ALTER TABLE state_rows ENABLE ROW LEVEL SECURITY`}, pgstore.ErrSchema},
		"dropped key, owner":              {true, []string{`ALTER TABLE consumed_decisions DROP CONSTRAINT consumed_decisions_pkey`}, pgstore.ErrSchema},
		"origin-only trigger, owner":      {true, []string{`ALTER TABLE audit_entries ENABLE TRIGGER audit_entries_append_only_row`}, pgstore.ErrSchema},
		"planted entry, owner":            {true, []string{`INSERT INTO audit_entries VALUES ('decision', 1, 1, now(), '\x7b7d', decode(repeat('00', 32), 'hex'), decode(repeat('0a', 32), 'hex'))`}, pgstore.ErrSchema},
		"missing privilege, runtime role": {false, []string{`REVOKE UPDATE ON state_rows FROM %[1]s`}, pgstore.ErrSchema},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			owner := newSchema(t)
			role := newRole(t, -1)
			migrate(t, owner, role)
			su := admin(t, owner)
			for _, q := range tc.stmts {
				mustExec(t, su, strings.ReplaceAll(q, "%[1]s", role))
			}
			u := roleURL(t, owner, role)
			if tc.asOwner {
				u = owner
			}
			if err := open(t, u); !errors.Is(err, tc.want) || (tc.want == nil && err != nil) {
				t.Errorf("Open with the opt-out: err = %v, want %v", err, tc.want)
			}
		})
	}
}

// TestOpenDoesNotMistakeAppendForPlantedEntry_PG: the planted-entry check is one statement, so appends racing
// with Open are never reported as an entry beyond the head.
func TestOpenDoesNotMistakeAppendForPlantedEntry_PG(t *testing.T) { // NFR-4
	owner := newSchema(t)
	role := newRole(t, -1)
	st := openAsRole(t, owner, role, time.Now, nil)
	stop := make(chan struct{})
	var wg sync.WaitGroup
	var appendErr error
	wg.Go(func() {
		for {
			select {
			case <-stop:
				return
			default:
			}
			err := st.Tx(t.Context(), func(ctx context.Context, tx store.Txn) error {
				_, err := tx.Append(ctx, storetest.Record("racing"))
				return err
			})
			if err != nil {
				appendErr = err
				return
			}
		}
	})
	for range 25 {
		if err := runtimeOpen(t, roleURL(t, owner, role)); err != nil {
			t.Errorf("Open during appends: %v", err)
			break
		}
	}
	close(stop)
	wg.Wait()
	if appendErr != nil {
		t.Fatalf("append: %v", appendErr)
	}
}

func TestOpenPlantedEntryIsBrokenChain_PG(t *testing.T) { // NFR-4: the refusal names the broken chain
	owner := newSchema(t)
	role := newRole(t, -1)
	migrate(t, owner, role)
	su := admin(t, owner)
	mustExec(t, su, `INSERT INTO audit_entries (chain, seq, format, at, record, prev_hash, hash)
		VALUES ('denial', 1, 1, now(), '\x7b7d', decode(repeat('00', 32), 'hex'), decode(repeat('0a', 32), 'hex'))`)
	if err := runtimeOpen(t, roleURL(t, owner, role)); !errors.Is(err, audit.ErrBrokenChain) || !errors.Is(err, pgstore.ErrSchema) {
		t.Errorf("Open with a planted entry: err = %v, want ErrSchema and ErrBrokenChain", err)
	}
}

// TestOpenRefusesSubscription_PG: a logical replication subscription in the database is refused.
func TestOpenRefusesSubscription_PG(t *testing.T) { // NFR-4
	baseURL(t)
	f := newFixture(t)
	f.exec(t, `CREATE SUBSCRIPTION lo_sub CONNECTION 'dbname=lo_unused' PUBLICATION lo_pub WITH (connect = false, slot_name = NONE, enabled = false)`)
	t.Cleanup(func() { // a subscription would keep the database from being dropped
		ctx := context.WithoutCancel(t.Context())
		if c, err := pgx.Connect(ctx, f.owner); err == nil {
			_, _ = c.Exec(ctx, `DROP SUBSCRIPTION lo_sub`)
			_ = c.Close(ctx)
		}
	})
	if err := runtimeOpen(t, f.roleURL(t)); !errors.Is(err, pgstore.ErrSchema) {
		t.Errorf("Open: err = %v, want ErrSchema", err)
	}
}

// TestUpgradeFromFirstMigration_PG: a database migrated only to 0001 (triggers enabled for origin sessions only) is
// refused until Migrate applies 0002, after which Open works.
func TestUpgradeFromFirstMigration_PG(t *testing.T) { // NFR-4
	baseURL(t)
	f := newFixture(t)
	f.exec(t, `DELETE FROM schema_migrations WHERE version = 2`)
	for _, tbl := range []string{"audit_chain_heads", "audit_entries", "consumed_decisions", "deliveries"} {
		f.exec(t, `ALTER TABLE `+tbl+` ENABLE TRIGGER USER`) // what 0001 left: enabled for origin only
	}
	if err := runtimeOpen(t, f.roleURL(t)); !errors.Is(err, pgstore.ErrSchema) {
		t.Fatalf("Open on a database at migration 1: err = %v, want ErrSchema", err)
	}
	migrate(t, f.owner, "")
	if err := runtimeOpen(t, f.roleURL(t)); err != nil {
		t.Errorf("Open after Migrate: %v", err)
	}
}
