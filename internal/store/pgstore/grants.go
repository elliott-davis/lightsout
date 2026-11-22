// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

package pgstore

import (
	"context"
	"fmt"
	"slices"
	"sort"
	"strings"
)

// tableGrant is the exact set of privileges the runtime role holds on one table. Anything else, including a
// column-level grant of the same privilege, is excess.
type tableGrant struct {
	table string
	privs []string
}

// runtimeTableGrants is the one definition of what the runtime role may do with the store's tables. [Migrate]
// generates its GRANT statements from it, [verifyGrants] checks the outcome against it and [Open]'s startup check
// compares the role's effective privileges to it, so the three cannot drift. Appends to the audit tables go
// through the owner's audit_append function, which is why those are SELECT only.
func runtimeTableGrants() []tableGrant {
	return []tableGrant{
		{"audit_entries", []string{privSelect}},
		{tblHeads, []string{privSelect}},
		{"schema_migrations", []string{privSelect}},
		{"consumed_decisions", []string{privSelect, privInsert}},
		{"deliveries", []string{privSelect, privInsert}},
		{"state_rows", []string{privSelect, privInsert, privUpdate}},
		{"work_items", []string{privSelect, privInsert, privUpdate}},
	}
}

// runtimeFunctionGrants are the signatures the runtime role may EXECUTE. No sequence is granted: the identity
// column on work_items is filled under the table's INSERT privilege.
func runtimeFunctionGrants() []string {
	return []string{
		"audit_lock_head(text)",
		"audit_append(text, bigint, integer, timestamptz, bytea, bytea, bytea)", //nolint:dupword // the function's argument types
	}
}

const (
	privSelect     = "SELECT"
	privInsert     = "INSERT"
	privUpdate     = "UPDATE"
	privReferences = "REFERENCES"
)

// tablePrivileges are every table privilege PostgreSQL has had since 9.x; MAINTAIN (PostgreSQL 17) is added by the
// query when the server knows it. Column privileges exist for the first four only.
func tablePrivileges() []string {
	return []string{privSelect, privInsert, privUpdate, "DELETE", "TRUNCATE", privReferences, "TRIGGER"}
}

func columnPrivileges() []string { return []string{privSelect, privInsert, privUpdate, privReferences} }

// writePrivileges are the ones that let a role change data or behavior outside the store schema.
func writePrivileges() []string {
	return []string{privInsert, privUpdate, "DELETE", "TRUNCATE", "TRIGGER", privReferences}
}

// grantStatements is what Migrate runs, with sch and r the quoted schema and role: reset, then grant exactly the
// allowlist. REVOKE on a table also revokes the role's column-level grants of that privilege.
//
// db is the quoted database name. The role gets no TEMP or CREATE on it, and when revokePublicTemp is set (the migrator
// owns the database) PUBLIC loses TEMP too: a temporary table or function is searched before the real ones, so a
// session that may create them can shadow what a definer function or trigger of another owner refers to.
func grantStatements(sch, r, db string, revokePublicTemp bool) []string {
	out := []string{
		`GRANT USAGE ON SCHEMA ` + sch + ` TO ` + r,
		`REVOKE TEMPORARY, CREATE ON DATABASE ` + db + ` FROM ` + r,
		`REVOKE ALL ON ALL TABLES IN SCHEMA ` + sch + ` FROM ` + r,
		`REVOKE ALL ON ALL SEQUENCES IN SCHEMA ` + sch + ` FROM ` + r,
		`REVOKE ALL ON ALL FUNCTIONS IN SCHEMA ` + sch + ` FROM ` + r,
	}
	if revokePublicTemp {
		out = append(out, `REVOKE TEMPORARY ON DATABASE `+db+` FROM PUBLIC`)
	}
	for _, g := range runtimeTableGrants() {
		out = append(out, `GRANT `+strings.Join(g.privs, ", ")+` ON `+g.table+` TO `+r)
	}
	for _, fn := range runtimeFunctionGrants() {
		out = append(out, `GRANT EXECUTE ON FUNCTION `+fn+` TO `+r)
	}
	return out
}

// diffGrants compares what role can effectively do (directly, inherited, through PUBLIC or by column grants) to
// the runtime allowlist, exactly. In the store schema: every table privilege, every column privilege, each of those
// WITH GRANT OPTION, EXECUTE on every function, USAGE/SELECT/UPDATE on every sequence, and USAGE on the schema. In
// the rest of the database (which must be dedicated to the factory): no write privilege on any relation (the system
// catalogs, which only a superuser can modify, aside), no CREATE on any schema, no TEMP or CREATE on the database, no
// default privileges for the role or PUBLIC, no USAGE on a foreign server, no user mapping and no parameter privilege.
// excess is a privilege the allowlist does not give; missing is one it does and the role lacks.
//
// Trigger functions are exempt from the EXECUTE rule: PUBLIC holds EXECUTE on them by default, and a trigger
// function cannot be called except by a trigger (PostgreSQL raises an error for a direct call), so it grants
// nothing. Any other function in the schema that the role can execute, and is not on the list, is excess.
func diffGrants(ctx context.Context, q queryer, role string) (excess, missing []string, err error) {
	wantTable := map[string][]string{}
	for _, g := range runtimeTableGrants() {
		wantTable[g.table] = g.privs
	}
	byTable := func(table, priv string) bool { return slices.Contains(wantTable[table], priv) }
	never := func(string, string) bool { return false }
	const (
		inStore  = `c.relnamespace = current_schema()::regnamespace`
		outStore = `c.relnamespace <> current_schema()::regnamespace AND n.nspname <> 'pg_catalog'
  AND n.nspname NOT LIKE 'pg\_toast%' AND n.nspname NOT LIKE 'pg\_temp\_%'`
		kinds = `c.relkind IN ('r', 'p', 'v', 'm', 'f')`
	)
	tableSQL := func(where string) string {
		return `
SELECT n.nspname || '.' || c.relname, p || $3, COALESCE(has_table_privilege($1::name, c.oid, p || $3), false)
FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace,
     unnest($2::text[] || CASE WHEN current_setting('server_version_num')::int >= 170000 AND $3 = '' AND $4 THEN ARRAY['MAINTAIN'] ELSE ARRAY[]::text[] END) p
WHERE ` + where + ` AND ` + kinds + ` ORDER BY 1, 2`
	}
	// has_any_column_privilege is true for a table-level grant as well, so the expectation is the table-level one.
	columnSQL := func(where string) string {
		return `
SELECT n.nspname || '.' || c.relname || ' (any column)', p || $3, COALESCE(has_any_column_privilege($1::name, c.oid, p || $3), false)
FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace, unnest($2::text[]) p
WHERE ` + where + ` AND ` + kinds + ` ORDER BY 1, 2`
	}
	storeName := func(name string) string {
		return strings.TrimSuffix(name[strings.IndexByte(name, '.')+1:], " (any column)")
	}
	const grantOpt = " WITH GRANT OPTION"
	var d diff
	steps := []func() error{
		func() error {
			return d.relation(ctx, q, "table", tableSQL(inStore), func(n, p string) bool { return byTable(storeName(n), p) }, role, tablePrivileges(), "", true)
		},
		func() error {
			return d.relation(ctx, q, "column", columnSQL(inStore), func(n, p string) bool { return byTable(storeName(n), p) }, role, columnPrivileges(), "")
		},
		func() error {
			return d.relation(ctx, q, "table grant option", tableSQL(inStore), never, role, tablePrivileges(), grantOpt, false)
		},
		func() error {
			return d.relation(ctx, q, "column grant option", columnSQL(inStore), never, role, columnPrivileges(), grantOpt)
		},
		func() error { return d.functions(ctx, q, role) },
		// No sequence privilege is ever expected.
		func() error {
			return d.relation(ctx, q, "sequence", `
SELECT c.relname, p, COALESCE(has_sequence_privilege($1::name, c.oid, p), false)
FROM pg_class c, unnest($2::text[]) p
WHERE `+inStore+` AND c.relkind = 'S' ORDER BY 1, 2`, never, role, []string{"USAGE", privSelect, privUpdate})
		},
		// Outside the store schema: the database is dedicated to the factory, so the role needs no write access to
		// any relation (a view or inheritance child of a store table, say) and no definer function that could act
		// as its owner.
		func() error {
			return d.relation(ctx, q, "other relation", tableSQL(outStore), never, role, writePrivileges(), "", false)
		},
		func() error {
			return d.relation(ctx, q, "other column", columnSQL(outStore), never, role, []string{privInsert, privUpdate, privReferences}, "")
		},
		func() error {
			return d.relation(ctx, q, "schema CREATE", `
SELECT n.nspname, 'CREATE', COALESCE(has_schema_privilege($1::name, n.oid, 'CREATE'), false)
FROM pg_namespace n WHERE n.nspname NOT LIKE 'pg\_temp\_%' AND n.nspname NOT LIKE 'pg\_toast\_temp\_%' ORDER BY 1`, never, role)
		},
		func() error {
			return d.relation(ctx, q, "database", `
SELECT current_database(), p, COALESCE(has_database_privilege($1::name, current_database(), p), false)
FROM unnest(ARRAY['TEMP', 'CREATE']) p ORDER BY 2`, never, role)
		},
		func() error {
			return d.relation(ctx, q, "default privilege", `
SELECT COALESCE(n.nspname, 'any schema') || ' (' || d.defaclobjtype::text || ')', 'DEFAULT ACL', true
FROM pg_default_acl d LEFT JOIN pg_namespace n ON n.oid = d.defaclnamespace
WHERE EXISTS (SELECT 1 FROM aclexplode(d.defaclacl) a WHERE a.grantee = 0 OR a.grantee = (SELECT oid FROM pg_roles WHERE rolname = $1::name))
ORDER BY 1`, never, role)
		},
		func() error {
			return d.relation(ctx, q, "foreign server", `
SELECT s.srvname, 'USAGE', COALESCE(has_server_privilege($1::name, s.oid, 'USAGE'), false) FROM pg_foreign_server s ORDER BY 1`, never, role)
		},
		func() error {
			return d.relation(ctx, q, "user mapping", `
SELECT srvname, 'USER MAPPING', true FROM pg_user_mappings WHERE umuser = 0 OR usename = $1::name ORDER BY 1`, never, role)
		},
		func() error { return d.parameters(ctx, q, role) },
	}
	for _, step := range steps {
		if err := step(); err != nil {
			return nil, nil, err
		}
	}
	var usage, usageOpt, createOpt bool
	if err := q.QueryRow(ctx, `SELECT has_schema_privilege($1::name, current_schema(), 'USAGE'),
  has_schema_privilege($1::name, current_schema(), 'USAGE WITH GRANT OPTION'),
  has_schema_privilege($1::name, current_schema(), 'CREATE WITH GRANT OPTION')`, role).Scan(&usage, &usageOpt, &createOpt); err != nil {
		return nil, nil, fmt.Errorf("read schema privilege: %w", err)
	}
	d.add("the schema", "USAGE", usage, true)
	d.add("the schema", "USAGE WITH GRANT OPTION", usageOpt, false)
	d.add("the schema", "CREATE WITH GRANT OPTION", createOpt, false)
	sort.Strings(d.excess)
	sort.Strings(d.missing)
	return d.excess, d.missing, nil
}

type diff struct{ excess, missing []string }

func (d *diff) add(name, priv string, has, want bool) {
	switch {
	case has && !want:
		d.excess = append(d.excess, name+":"+priv)
	case !has && want:
		d.missing = append(d.missing, name+":"+priv)
	}
}

// relation runs a query of (object name, privilege, held) rows and compares each to want.
func (d *diff) relation(ctx context.Context, q queryer, what, sql string, want func(name, priv string) bool, args ...any) error {
	rows, err := q.Query(ctx, sql, args...)
	if err != nil {
		return fmt.Errorf("read %s privileges: %w", what, err)
	}
	defer rows.Close()
	for rows.Next() {
		var name, priv string
		var has bool
		if err := rows.Scan(&name, &priv, &has); err != nil {
			return fmt.Errorf("scan %s privilege: %w", what, err)
		}
		d.add(name, priv, has, want(name, priv))
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("read %s privileges: %w", what, err)
	}
	return nil
}

// parameters refuses a role (or PUBLIC) that was granted SET or ALTER SYSTEM on any configuration parameter
// (PostgreSQL 15 and later): session_replication_role, for one, changes which triggers fire.
func (d *diff) parameters(ctx context.Context, q queryer, role string) error {
	var version int
	if err := q.QueryRow(ctx, `SELECT current_setting('server_version_num')::int`).Scan(&version); err != nil {
		return fmt.Errorf("read server version: %w", err)
	}
	if version < 150000 {
		return nil
	}
	return d.relation(ctx, q, "parameter", `
SELECT a.parname, p, COALESCE(has_parameter_privilege($1::name, a.parname, p), false)
FROM pg_parameter_acl a, unnest(ARRAY['SET', 'ALTER SYSTEM']) p ORDER BY 1, 2`, func(string, string) bool { return false }, role)
}

// functions compares EXECUTE on every function in the schema, resolving the allowlist's signatures to OIDs so an
// overload of an allowed name is not allowed with it.
func (d *diff) functions(ctx context.Context, q queryer, role string) error {
	rows, err := q.Query(ctx, `
SELECT p.proname || '(' || pg_get_function_identity_arguments(p.oid) || ')',
       has_function_privilege($1::name, p.oid, 'EXECUTE'),
       COALESCE(has_function_privilege($1::name, p.oid, 'EXECUTE WITH GRANT OPTION'), false),
       p.oid = ANY (ARRAY(SELECT to_regprocedure(quote_ident(current_schema()) || '.' || s)::oid FROM unnest($2::text[]) s)),
       p.prorettype = 'trigger'::regtype
FROM pg_proc p WHERE p.pronamespace = current_schema()::regnamespace ORDER BY 1`, role, runtimeFunctionGrants())
	if err != nil {
		return fmt.Errorf("read function privileges: %w", err)
	}
	defer rows.Close()
	listed := 0
	for rows.Next() {
		var fn string
		var has, opt, want, trigger bool
		if err := rows.Scan(&fn, &has, &opt, &want, &trigger); err != nil {
			return fmt.Errorf("scan function privilege: %w", err)
		}
		if want {
			listed++
		}
		if !trigger {
			d.add(fn, "EXECUTE", has, want)
			d.add(fn, "EXECUTE WITH GRANT OPTION", opt, false)
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("read function privileges: %w", err)
	}
	if listed != len(runtimeFunctionGrants()) {
		d.missing = append(d.missing, "the store's append functions are absent:EXECUTE")
	}
	return nil
}
