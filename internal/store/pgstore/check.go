// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

package pgstore

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// ErrSchema means the database is not in the state the running binary requires: not migrated, altered, or a
// protection disabled or replaced. Run [Migrate] as the owner, or investigate.
var ErrSchema = errors.New("pgstore: database schema is not as required")

// ErrPrivilege means the runtime credential is too powerful: a superuser, the owner of the store's tables or a
// member of that owner, a member of a write-capable built-in role, or holder of a privilege on the append-only
// tables that only the owner's functions may use.
var ErrPrivilege = errors.New("pgstore: runtime credential is too privileged")

const (
	tblHeads = "audit_chain_heads"
	fnForbid = "forbid_change"
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

// protectedFunctions are the functions whose bodies the triggers and appends depend on, and whether each is
// SECURITY DEFINER.
func protectedFunctions() map[string]bool {
	return map[string]bool{fnForbid: false, "head_advance_only": false, "audit_append": true, "audit_lock_head": true}
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

// forbiddenPrivileges lists the privileges role holds, directly, inherited or through a group, that only the owner's
// functions may use on the append-only tables. has_table_privilege counts all of them.
func forbiddenPrivileges(ctx context.Context, q queryer, role string) ([]string, error) {
	rows, err := q.Query(ctx, `
SELECT t || ':' || p FROM (
    SELECT t, p FROM unnest(ARRAY['audit_entries', 'audit_chain_heads', 'schema_migrations']) t,
                     unnest(ARRAY['INSERT', 'UPDATE', 'DELETE', 'TRUNCATE', 'TRIGGER', 'REFERENCES']) p
    UNION ALL
    SELECT t, p FROM unnest(ARRAY['consumed_decisions', 'deliveries']) t,
                     unnest(ARRAY['UPDATE', 'DELETE', 'TRUNCATE', 'TRIGGER', 'REFERENCES']) p
) x WHERE has_table_privilege($1::name, t, p) ORDER BY 1`, role)
	if err != nil {
		return nil, fmt.Errorf("read table privileges: %w", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, fmt.Errorf("scan privilege: %w", err)
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// checkSchema verifies read-only, on one pool, that the schema is fully migrated with matching checksums, that every
// append-only and head trigger exists, is enabled and is what the migrations created, that the functions behind
// them have the expected bodies, and (unless allowOwner) that the pool's role is not too privileged. It reports why
// the role is privileged, if it is, for the caller to warn about when it allowed that.
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
	if terr := checkTriggers(ctx, q); terr != nil {
		return "", terr
	}
	if ferr := checkFunctions(ctx, q); ferr != nil {
		return "", ferr
	}
	why, err := privilegeReasons(ctx, q)
	if err != nil {
		return "", err
	}
	if why != "" && !allowOwner {
		return why, fmt.Errorf("%w: %s; run as a separate runtime role (see Migrate), or set AllowOwnerRuntime for tests and development", ErrPrivilege, why)
	}
	return why, nil
}

func checkTriggers(ctx context.Context, q queryer) error {
	rows, err := q.Query(ctx, `
SELECT t.tgname, c.relname, t.tgtype::int, p.proname
FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid JOIN pg_proc p ON p.oid = t.tgfoid
WHERE c.relnamespace = current_schema()::regnamespace AND p.pronamespace = current_schema()::regnamespace
  AND NOT t.tgisinternal AND t.tgenabled IN ('O', 'A')`)
	if err != nil {
		return fmt.Errorf("read triggers: %w", err)
	}
	have := map[string]triggerSpec{}
	for rows.Next() {
		var name string
		var s triggerSpec
		if err := rows.Scan(&name, &s.table, &s.typ, &s.fn); err != nil {
			rows.Close()
			return fmt.Errorf("scan trigger: %w", err)
		}
		have[name] = s
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return fmt.Errorf("read triggers: %w", err)
	}
	for name, want := range protectedTriggers() {
		got, ok := have[name]
		if !ok {
			return fmt.Errorf("%w: trigger %s is missing or disabled", ErrSchema, name)
		}
		if got != want {
			return fmt.Errorf("%w: trigger %s is not what the migrations created", ErrSchema, name)
		}
	}
	return nil
}

func checkFunctions(ctx context.Context, q queryer) error {
	want, err := expectedBodies()
	if err != nil {
		return err
	}
	rows, err := q.Query(ctx, `
SELECT proname, prosrc, prosecdef,
       COALESCE(proconfig @> ARRAY[format('search_path=%I, pg_temp', current_schema())], false)
FROM pg_proc WHERE pronamespace = current_schema()::regnamespace AND proname = ANY($1)`, keys(protectedFunctions()))
	if err != nil {
		return fmt.Errorf("read functions: %w", err)
	}
	defer rows.Close()
	seen := map[string]int{}
	for rows.Next() {
		var name, src string
		var secdef, pinned bool
		if err := rows.Scan(&name, &src, &secdef, &pinned); err != nil {
			return fmt.Errorf("scan function: %w", err)
		}
		seen[name]++
		definer := protectedFunctions()[name]
		switch {
		case src != want[name]:
			return fmt.Errorf("%w: function %s has been replaced", ErrSchema, name)
		case secdef != definer:
			return fmt.Errorf("%w: function %s has the wrong security mode", ErrSchema, name)
		case definer && !pinned:
			return fmt.Errorf("%w: function %s lost its pinned search_path", ErrSchema, name)
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("read functions: %w", err)
	}
	for name := range protectedFunctions() {
		if seen[name] != 1 {
			return fmt.Errorf("%w: function %s is missing or overloaded", ErrSchema, name)
		}
	}
	return nil
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// privilegeReasons says why the current role is too powerful, or returns "". Membership is tested with MEMBER, not
// USAGE, so a role that does not inherit (NOINHERIT, or a grant WITH INHERIT FALSE) but can SET ROLE still counts.
func privilegeReasons(ctx context.Context, q queryer) (string, error) {
	var user string
	var super, owner, superMember, writeMember bool
	if err := q.QueryRow(ctx, `
SELECT current_user::text,
  COALESCE((SELECT rolsuper FROM pg_roles WHERE rolname = current_user), false),
  EXISTS (SELECT 1 FROM pg_tables WHERE schemaname = current_schema() AND pg_has_role(current_user, tableowner, 'MEMBER')),
  EXISTS (SELECT 1 FROM pg_roles WHERE rolsuper AND pg_has_role(current_user, oid, 'MEMBER')),
  EXISTS (SELECT 1 FROM pg_roles WHERE rolname IN ('pg_write_all_data', 'pg_write_server_files', 'pg_execute_server_program')
                                   AND pg_has_role(current_user, oid, 'MEMBER'))`).
		Scan(&user, &super, &owner, &superMember, &writeMember); err != nil {
		return "", fmt.Errorf("read role privileges: %w", err)
	}
	var why []string
	for _, c := range []struct {
		hit  bool
		text string
	}{
		{super, "the role is a superuser"},
		{owner, "the role owns, or is a member of the owner of, the store's tables"},
		{superMember, "the role is a member of a superuser role"},
		{writeMember, "the role is a member of pg_write_all_data, pg_write_server_files or pg_execute_server_program"},
	} {
		if c.hit {
			why = append(why, c.text)
		}
	}
	forbidden, err := forbiddenPrivileges(ctx, q, user)
	if err != nil {
		return "", err
	}
	if len(forbidden) > 0 {
		why = append(why, "the role holds privileges that only the owner's functions may use: "+strings.Join(forbidden, ", "))
	}
	return strings.Join(why, "; "), nil
}
