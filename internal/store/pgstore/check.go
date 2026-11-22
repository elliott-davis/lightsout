// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

package pgstore

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/elliott-davis/lightsout/internal/audit"
)

// ErrSchema means the database is not in the state the running binary requires: not migrated, altered, or a
// protection disabled or replaced. Run [Migrate] as the owner, or investigate.
var ErrSchema = errors.New("pgstore: database schema is not as required")

// ErrPrivilege means the runtime credential is too powerful: a superuser, an owner of anything in the database, a
// member of any role, holder of CREATEROLE, CREATEDB, REPLICATION or BYPASSRLS, able to CREATE in the schema or
// database, logged in as one role but running as another, or holder of any privilege (table, column, function,
// grant option, or beyond the store schema) outside the exact runtime allowlist.
var ErrPrivilege = errors.New("pgstore: runtime credential is too privileged")

const (
	langPlpgsql = "plpgsql"
	tblHeads    = "audit_chain_heads"
	fnForbid    = "forbid_change"
)

// pg_trigger.tgtype bits.
const (
	tgRow      = 1
	tgBefore   = 2
	tgDelete   = 8
	tgUpdate   = 16
	tgTruncate = 32
)

type triggerSpec struct {
	table string
	typ   int // tgtype: timing, level and events
	fn    string
}

// protectedTriggers are the triggers that make the audit tables, the consumed set and the delivery receipts
// append-only and keep chain heads advancing by one, with the table, timing, level, events and function each must
// have. Open refuses a schema in which any is missing, disabled or different.
func protectedTriggers() map[string]triggerSpec {
	out := map[string]triggerSpec{
		"audit_chain_heads_advance":     {tblHeads, tgRow | tgBefore | tgUpdate, "head_advance_only"},
		"audit_chain_heads_no_delete":   {tblHeads, tgRow | tgBefore | tgDelete, fnForbid},
		"audit_chain_heads_no_truncate": {tblHeads, tgBefore | tgTruncate, fnForbid},
	}
	for _, t := range []string{"audit_entries", "consumed_decisions", "deliveries"} {
		out[t+"_append_only_row"] = triggerSpec{t, tgRow | tgBefore | tgUpdate | tgDelete, fnForbid}
		out[t+"_append_only_stmt"] = triggerSpec{t, tgBefore | tgTruncate, fnForbid}
	}
	return out
}

// fnSpec is what a protected function must be, beyond its body: the migrations create each of these, and
// Open compares every property that changes what a call does or who it runs as.
type fnSpec struct {
	lang   string // pg_language.lanname
	secdef bool   // SECURITY DEFINER; also means search_path must be pinned (and be nothing else in proconfig)
	retset bool
	args   string // pg_get_function_identity_arguments
	result string // pg_get_function_result
}

// protectedFunctions are the functions whose bodies the triggers and appends depend on.
//
// Expected state is compared field by field rather than by the SHA-256 of pg_get_functiondef: the expected
// definition would have to be re-derived from the embedded SQL text, and pg_get_functiondef normalizes it (adds
// the schema, re-quotes, appends the SET clause), so a hash would be brittle across PostgreSQL versions. The
// equivalent used here is the exact prosrc (the body, taken from the migrations), plus language, security mode,
// proconfig equal to exactly the pinned search_path (not a containing array), volatility, strictness, leakproofness,
// parallel safety, kind, set-returning flag, result type and argument types.
func protectedFunctions() map[string]fnSpec {
	return map[string]fnSpec{
		fnForbid:            {lang: langPlpgsql, args: "", result: "trigger"},
		"head_advance_only": {lang: langPlpgsql, args: "", result: "trigger"},
		"audit_lock_head":   {lang: "sql", secdef: true, retset: true, args: "p_chain text", result: "TABLE(head_seq bigint, head_hash bytea)"},
		"audit_append": {
			lang: langPlpgsql, secdef: true, result: "void",
			args: "p_chain text, p_seq bigint, p_format integer, p_at timestamp with time zone, p_record bytea, p_prev_hash bytea, p_hash bytea",
		},
	}
}

var functionDef = regexp.MustCompile(`(?s)CREATE FUNCTION (\w+)\(.*?\bAS \$\$(.*?)\$\$;`)

// expectedBodies extracts each protected function's body from the embedded migrations: the expectation is what this
// binary would have installed.
func expectedBodies() (map[string]string, error) {
	migs, err := loadMigrations()
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, m := range migs {
		for _, sub := range functionDef.FindAllStringSubmatch(m.sql, -1) {
			out[sub[1]] = sub[2]
		}
	}
	for name := range protectedFunctions() {
		if _, ok := out[name]; !ok {
			return nil, fmt.Errorf("embedded migrations do not define %s", name)
		}
	}
	return out, nil
}

// checkSchema verifies read-only, on one pool, that the schema is fully migrated with matching checksums; that it
// holds exactly the expected relations, with no rules, row security or extra triggers; that every append-only and
// head trigger exists, is enabled and is what the migrations created; that the functions behind them are what the
// migrations installed; that no audit entry lies beyond its chain's head; and (unless allowOwner) that the pool's
// role holds exactly the runtime allowlist and owns nothing. It reports why the role is privileged, if it is, for the
// caller to warn about when it allowed that.
func checkSchema(ctx context.Context, q queryer, allowOwner bool) (privileged string, err error) {
	migs, err := loadMigrations()
	if err != nil {
		return "", err
	}
	applied, err := checkApplied(ctx, q, migs)
	if err != nil {
		return "", fmt.Errorf("%w: %w (run pgstore.Migrate as the owner)", ErrSchema, err)
	}
	if applied != len(migs) {
		return "", fmt.Errorf("%w: %d of %d migrations applied (run pgstore.Migrate as the owner)", ErrSchema, applied, len(migs))
	}
	if serr := checkStructure(ctx, q); serr != nil {
		return "", serr
	}
	if terr := checkTriggers(ctx, q); terr != nil {
		return "", terr
	}
	if ferr := checkFunctions(ctx, q); ferr != nil {
		return "", ferr
	}
	// Privileges first: a role that lacks SELECT cannot run the planted-entry check, and should be told why.
	why, err := privilegeReasons(ctx, q)
	if err != nil {
		return "", err
	}
	if perr := checkNoPlantedEntries(ctx, q); perr != nil {
		return "", perr
	}
	if why != "" && !allowOwner {
		return why, fmt.Errorf("%w: %s; run as a separate runtime role (see Migrate), or set AllowOwnerRuntime for tests and development", ErrPrivilege, why)
	}
	return why, nil
}

// checkNoPlantedEntries refuses a database in which a chain has an entry past its head. One statement means one
// snapshot, and an append inserts the entry and advances the head in one transaction, so a concurrent append can
// never look like a planted entry (two statements could see the entry without the advanced head).
func checkNoPlantedEntries(ctx context.Context, q queryer) error {
	var planted bool
	if err := q.QueryRow(ctx, `
SELECT EXISTS (SELECT 1 FROM ONLY audit_entries e JOIN ONLY audit_chain_heads h USING (chain) WHERE e.seq > h.seq)
    OR EXISTS (SELECT 1 FROM ONLY audit_entries e WHERE NOT EXISTS (SELECT 1 FROM ONLY audit_chain_heads h WHERE h.chain = e.chain))`).Scan(&planted); err != nil {
		return fmt.Errorf("read audit entries past the heads: %w", err)
	}
	if planted {
		return fmt.Errorf("%w: %w: an audit entry lies beyond its chain's head", ErrSchema, audit.ErrBrokenChain)
	}
	return nil
}

// checkStructure refuses anything in the schema the migrations did not create that could change what a statement
// on these tables does: an unexpected relation (table, view, materialized or foreign table), a rewrite rule, row
// security (enabled, forced or with policies).
func checkStructure(ctx context.Context, q queryer) error {
	rows, err := q.Query(ctx, `
SELECT c.relname, c.relrowsecurity, c.relforcerowsecurity,
       EXISTS (SELECT 1 FROM pg_rewrite r WHERE r.ev_class = c.oid AND r.rulename <> '_RETURN'),
       EXISTS (SELECT 1 FROM pg_policy p WHERE p.polrelid = c.oid)
FROM pg_class c
WHERE c.relnamespace = current_schema()::regnamespace AND c.relkind IN ('r', 'p', 'v', 'm', 'f')`)
	if err != nil {
		return fmt.Errorf("read relations: %w", err)
	}
	defer rows.Close()
	want := map[string]bool{}
	for _, g := range runtimeTableGrants() {
		want[g.table] = true
	}
	seen := map[string]bool{}
	for rows.Next() {
		var name string
		var rls, forced, rule, policy bool
		if err := rows.Scan(&name, &rls, &forced, &rule, &policy); err != nil {
			return fmt.Errorf("scan relation: %w", err)
		}
		seen[name] = true
		switch {
		case !want[name]:
			return fmt.Errorf("%w: unexpected relation %s in the store schema", ErrSchema, name)
		case rls || forced || policy:
			return fmt.Errorf("%w: row-level security is configured on %s", ErrSchema, name)
		case rule:
			return fmt.Errorf("%w: %s has a rewrite rule", ErrSchema, name)
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("read relations: %w", err)
	}
	for name := range want {
		if !seen[name] {
			return fmt.Errorf("%w: table %s is missing", ErrSchema, name)
		}
	}
	if err := checkOutsiders(ctx, q); err != nil {
		return err
	}
	return checkDescription(ctx, q)
}

// checkOutsiders refuses anything outside the store schema that is wired to its tables or runs code as another
// role: an inheritance parent or child, a view or rule that reads one, a foreign key across the boundary, any event
// trigger, any SECURITY DEFINER function but the store's two (in any schema, pg_catalog included) and any
// subscription. Each is a way to reach (or be
// reached by) the append-only tables through an object the store's own grants do not cover.
func checkOutsiders(ctx context.Context, q queryer) error {
	var inherit, dependent, fk, evt, definer, sub bool
	var definers []string
	for name, spec := range protectedFunctions() {
		if spec.secdef {
			definers = append(definers, name)
		}
	}
	if err := q.QueryRow(ctx, `
WITH store AS (SELECT oid FROM pg_class WHERE relnamespace = current_schema()::regnamespace)
SELECT EXISTS (SELECT 1 FROM pg_inherits i WHERE i.inhparent IN (SELECT oid FROM store) OR i.inhrelid IN (SELECT oid FROM store)),
       EXISTS (SELECT 1 FROM pg_depend d
               JOIN pg_rewrite r ON d.classid = 'pg_rewrite'::regclass AND d.objid = r.oid
               JOIN pg_class vc ON vc.oid = r.ev_class
               WHERE d.refclassid = 'pg_class'::regclass AND d.refobjid IN (SELECT oid FROM store)
                 AND vc.relnamespace <> current_schema()::regnamespace),
       EXISTS (SELECT 1 FROM pg_constraint k WHERE k.contype = 'f'
               AND ((k.conrelid IN (SELECT oid FROM store)) <> (k.confrelid IN (SELECT oid FROM store)))),
       EXISTS (SELECT 1 FROM pg_event_trigger),
       EXISTS (SELECT 1 FROM pg_proc p WHERE p.prosecdef
               AND NOT (p.pronamespace = current_schema()::regnamespace AND p.proname = ANY ($1))),
       EXISTS (SELECT 1 FROM pg_subscription s WHERE s.subdbid = (SELECT oid FROM pg_database WHERE datname = current_database()))`, definers).
		Scan(&inherit, &dependent, &fk, &evt, &definer, &sub); err != nil {
		return fmt.Errorf("read dependents of the store tables: %w", err)
	}
	switch {
	case inherit:
		return fmt.Errorf("%w: a store table has an inheritance parent or child", ErrSchema)
	case dependent:
		return fmt.Errorf("%w: a view or rule outside the store schema reads a store table", ErrSchema)
	case fk:
		return fmt.Errorf("%w: a foreign key joins a store table to a table outside the store schema", ErrSchema)
	case evt:
		return fmt.Errorf("%w: the database has an event trigger (it runs on the role's own DDL, as its owner)", ErrSchema)
	case definer:
		return fmt.Errorf("%w: the database has a SECURITY DEFINER function other than the store's (a trigger or event trigger runs it whether or not the role can EXECUTE it)", ErrSchema)
	case sub:
		return fmt.Errorf("%w: the database has a logical replication subscription", ErrSchema)
	}
	return nil
}

// checkTriggers requires the non-internal triggers on the schema's tables to be exactly protectedTriggers: no
// extra trigger on any table, and each expected one ENABLE ALWAYS (so session_replication_role cannot switch it off), calling this schema's function, with the expected
// timing and events, no WHEN clause, no column list, no arguments and no transition tables.
func checkTriggers(ctx context.Context, q queryer) error {
	rows, err := q.Query(ctx, `
SELECT t.tgname, c.relname, t.tgtype::int, p.proname,
       p.pronamespace = current_schema()::regnamespace,
       t.tgenabled = 'A',
       t.tgqual IS NULL AND t.tgattr::text = '' AND t.tgnargs = 0 AND t.tgconstraint = 0
           AND t.tgoldtable IS NULL AND t.tgnewtable IS NULL
FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid JOIN pg_proc p ON p.oid = t.tgfoid
WHERE c.relnamespace = current_schema()::regnamespace AND NOT t.tgisinternal`)
	if err != nil {
		return fmt.Errorf("read triggers: %w", err)
	}
	type have struct {
		spec                 triggerSpec
		local, enabled, bare bool
	}
	seen := map[string][]have{}
	for rows.Next() {
		var name string
		var h have
		if err := rows.Scan(&name, &h.spec.table, &h.spec.typ, &h.spec.fn, &h.local, &h.enabled, &h.bare); err != nil {
			rows.Close()
			return fmt.Errorf("scan trigger: %w", err)
		}
		seen[name] = append(seen[name], h)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return fmt.Errorf("read triggers: %w", err)
	}
	want := protectedTriggers()
	for name, hs := range seen {
		spec, ok := want[name]
		if !ok {
			return fmt.Errorf("%w: unexpected trigger %s on %s", ErrSchema, name, hs[0].spec.table)
		}
		if len(hs) != 1 {
			return fmt.Errorf("%w: trigger name %s is used on more than one table", ErrSchema, name)
		}
		h := hs[0]
		switch {
		case !h.enabled:
			return fmt.Errorf("%w: trigger %s is missing, disabled or not enabled always", ErrSchema, name)
		case h.spec != spec || !h.local || !h.bare:
			return fmt.Errorf("%w: trigger %s is not what the migrations created", ErrSchema, name)
		}
	}
	for name := range want {
		if len(seen[name]) == 0 {
			return fmt.Errorf("%w: trigger %s is missing or disabled", ErrSchema, name)
		}
	}
	return nil
}

func checkFunctions(ctx context.Context, q queryer) error {
	bodies, err := expectedBodies()
	if err != nil {
		return err
	}
	want := protectedFunctions()
	names := make([]string, 0, len(want))
	for n := range want {
		names = append(names, n)
	}
	rows, err := q.Query(ctx, `
SELECT p.proname, p.prosrc, l.lanname, p.prosecdef, p.proretset, p.provolatile::text, p.proisstrict, p.proleakproof,
       p.proparallel::text, p.prokind::text, pg_get_function_identity_arguments(p.oid), pg_get_function_result(p.oid),
       p.proconfig IS NULL,
       p.proconfig IS NOT DISTINCT FROM ARRAY[format('search_path=%I, pg_temp', current_schema())]
FROM pg_proc p JOIN pg_language l ON l.oid = p.prolang
WHERE p.pronamespace = current_schema()::regnamespace AND p.proname = ANY($1)`, names)
	if err != nil {
		return fmt.Errorf("read functions: %w", err)
	}
	defer rows.Close()
	seen := map[string]int{}
	for rows.Next() {
		var name, src, lang, vol, par, kind string
		var secdef, retset, strict, leakproof, noConfig, pinned bool
		var got fnSpec
		if err := rows.Scan(&name, &src, &lang, &secdef, &retset, &vol, &strict, &leakproof, &par, &kind, &got.args, &got.result, &noConfig, &pinned); err != nil {
			return fmt.Errorf("scan function: %w", err)
		}
		seen[name]++
		spec := want[name]
		got.lang, got.secdef, got.retset = lang, secdef, retset
		switch {
		case src != bodies[name]:
			return fmt.Errorf("%w: function %s has been replaced", ErrSchema, name)
		case secdef != spec.secdef:
			return fmt.Errorf("%w: function %s has the wrong security mode", ErrSchema, name)
		case spec.secdef && !pinned, !spec.secdef && !noConfig:
			return fmt.Errorf("%w: function %s has a changed or missing pinned search_path", ErrSchema, name)
		case got != spec, vol != "v", strict, leakproof, par != "u", kind != "f":
			return fmt.Errorf("%w: function %s is not what the migrations created", ErrSchema, name)
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("read functions: %w", err)
	}
	for name := range want {
		if seen[name] != 1 {
			return fmt.Errorf("%w: function %s is missing or overloaded", ErrSchema, name)
		}
	}
	return nil
}

// privilegeReasons says why the current role is too powerful, or returns "". Membership is tested with MEMBER, not
// USAGE, so a role that does not inherit (NOINHERIT, or a grant WITH INHERIT FALSE) but can SET ROLE still counts.
// It also returns an error when the role lacks a privilege the store needs: that role cannot work, and no opt-out
// applies, so it is an ErrSchema (the grants were not applied), not a reason.
func privilegeReasons(ctx context.Context, q queryer) (string, error) {
	var user, session, login string
	if err := q.QueryRow(ctx, `SELECT current_user::text, session_user::text,
  COALESCE((SELECT usename::text FROM pg_stat_activity WHERE pid = pg_backend_pid()), '')`).Scan(&user, &session, &login); err != nil {
		return "", fmt.Errorf("read current role: %w", err)
	}
	why, err := roleReasons(ctx, q, user)
	if err != nil {
		return "", err
	}
	// The checks judge current_user, which a startup parameter (role=, session_authorization=) or a role default
	// (ALTER ROLE ... SET role) can set to the runtime role on the credential of a far more powerful one, and
	// which that credential can reset. The credential that logged in must be the role judged.
	if user != session || user != login {
		why = append(why, "the session's login credential is not the role it runs as (a role= or session_authorization= parameter, or a per-role or per-database role default)")
	}
	excess, missing, err := diffGrants(ctx, q, user)
	if err != nil {
		return "", err
	}
	if len(missing) > 0 {
		return "", fmt.Errorf("%w: the runtime role lacks required privileges: %s (run pgstore.Migrate with this role as the runtime role)", ErrSchema, listN(missing))
	}
	if len(excess) > 0 {
		why = append(why, "the role holds privileges beyond the runtime allowlist: "+listN(excess))
	}
	return strings.Join(why, "; "), nil
}

// listN joins at most eight items, so a superuser's thousand excess privileges stay readable.
func listN(items []string) string {
	const limit = 8
	if len(items) <= limit {
		return strings.Join(items, ", ")
	}
	return strings.Join(items[:limit], ", ") + fmt.Sprintf(", and %d more", len(items)-limit)
}

// roleReasons lists the ways role is too powerful that are about who it is, not what it was granted: a superuser,
// a member of one, a member of a write-capable built-in role, a member of the owner of the schema, the database or
// any relation, function or type in the schema (an owner can drop the protection triggers), or able to create in
// the schema or the database.
func roleReasons(ctx context.Context, q queryer, role string) ([]string, error) {
	var super, superMember, writeMember, ownsSchema, ownsDB, ownsObj, createSchema, createDB, member, attrs, owns bool
	if err := q.QueryRow(ctx, `
SELECT COALESCE((SELECT rolsuper FROM pg_roles WHERE rolname = $1::name), false),
  EXISTS (SELECT 1 FROM pg_roles WHERE rolsuper AND pg_has_role($1::name, oid, 'MEMBER')),
  EXISTS (SELECT 1 FROM pg_roles WHERE rolname IN ('pg_write_all_data', 'pg_write_server_files', 'pg_execute_server_program')
                                   AND pg_has_role($1::name, oid, 'MEMBER')),
  EXISTS (SELECT 1 FROM pg_namespace WHERE oid = current_schema()::regnamespace AND pg_has_role($1::name, nspowner, 'MEMBER')),
  EXISTS (SELECT 1 FROM pg_database WHERE datname = current_database() AND pg_has_role($1::name, datdba, 'MEMBER')),
  EXISTS (SELECT 1 FROM pg_class WHERE relnamespace = current_schema()::regnamespace AND pg_has_role($1::name, relowner, 'MEMBER'))
  OR EXISTS (SELECT 1 FROM pg_proc WHERE pronamespace = current_schema()::regnamespace AND pg_has_role($1::name, proowner, 'MEMBER'))
  OR EXISTS (SELECT 1 FROM pg_type WHERE typnamespace = current_schema()::regnamespace AND pg_has_role($1::name, typowner, 'MEMBER')),
  has_schema_privilege($1::name, current_schema(), 'CREATE'),
  has_database_privilege($1::name, current_database(), 'CREATE'),
  EXISTS (SELECT 1 FROM pg_auth_members m JOIN pg_roles r ON r.oid = m.member WHERE r.rolname = $1::name),
  COALESCE((SELECT rolcreaterole OR rolcreatedb OR rolreplication OR rolbypassrls FROM pg_roles WHERE rolname = $1::name), false),
  EXISTS (SELECT 1 FROM pg_shdepend d JOIN pg_roles r ON r.oid = d.refobjid
          WHERE d.deptype = 'o' AND d.refclassid = 'pg_authid'::regclass AND r.rolname = $1::name
            AND d.dbid IN (0, (SELECT oid FROM pg_database WHERE datname = current_database())))`, role).
		Scan(&super, &superMember, &writeMember, &ownsSchema, &ownsDB, &ownsObj, &createSchema, &createDB, &member, &attrs, &owns); err != nil {
		return nil, fmt.Errorf("read role privileges: %w", err)
	}
	var why []string
	for _, c := range []struct {
		hit  bool
		text string
	}{
		{super, "the role is a superuser"},
		{superMember, "the role is a member of a superuser role"},
		{writeMember, "the role is a member of pg_write_all_data, pg_write_server_files or pg_execute_server_program"},
		{ownsSchema, "the role owns, or is a member of the owner of, the store schema"},
		{ownsDB, "the role owns, or is a member of the owner of, the database"},
		{ownsObj, "the role owns, or is a member of the owner of, objects in the store schema"},
		{createSchema, "the role can CREATE in the store schema"},
		{createDB, "the role can CREATE in the database"},
		// A role granted any other role, however (INHERIT FALSE, NOINHERIT, ADMIN-only, SET-only), can reach that
		// role's privileges with SET ROLE or by granting itself more, which the effective-privilege check cannot see.
		{member, "the role is a member of another role"},
		{attrs, "the role has CREATEROLE, CREATEDB, REPLICATION or BYPASSRLS"},
		// Anything it owns anywhere in the database or cluster (a function behind a constraint, an inheritance child,
		// an event trigger's function, a database) can be rewritten by it and run by an owner.
		{owns, "the role owns objects in the database or the cluster"},
	} {
		if c.hit {
			why = append(why, c.text)
		}
	}
	return why, nil
}
