// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

package pgstore

import (
	"context"
	_ "embed" // schema.golden
	"fmt"
	"strings"
)

// schemaGolden (testdata/schema.golden) describes every relation the migrations create, one line per table, column, constraint, index and
// sequence, as [describeSchema] prints them for a freshly migrated schema. It is generated, never edited by hand:
//
//	go test ./internal/store/pgstore -run TestSchemaGolden -update
//
// with LIGHTSOUT_TEST_POSTGRES_URL set. A new migration changes it. It is generated on PostgreSQL 16, and v1
// supports PostgreSQL 16 only: the text of pg_get_constraintdef, pg_get_indexdef and format_type, and the
// pg_collation columns it reads, are the server's. A new major version needs a regenerated golden and its own CI job.
// Storage options (reloptions: fillfactor, autovacuum tuning) are deliberately not described: they do not affect
// integrity.
//
//go:embed testdata/schema.golden
var schemaGolden string

// describeSchema lists the structure of the current schema in a stable order, schema name removed. Open compares
// it to schemaGolden, so an owner who drops a unique key, adds a check or a column, or changes a default
// (changes that no privilege check can see) is noticed.
func describeSchema(ctx context.Context, q queryer) ([]string, error) {
	rows, err := q.Query(ctx, `
SELECT line FROM (
  SELECT c.relname || '|0' AS k,
         format('table %s relkind=%s persistence=%s am=%s', c.relname, c.relkind, c.relpersistence, COALESCE((SELECT amname FROM pg_am WHERE oid = c.relam)::text, '')) AS line
  FROM pg_class c WHERE c.relnamespace = current_schema()::regnamespace AND c.relkind IN ('r', 'p', 'v', 'm', 'f')
  UNION ALL
  SELECT c.relname || '|1' || lpad(a.attnum::text, 5, '0'),
         format('column %s.%s type=%s notnull=%s default=%s generated=%s identity=%s collation=%s', c.relname, a.attname,
                format_type(a.atttypid, a.atttypmod), a.attnotnull, COALESCE(pg_get_expr(d.adbin, d.adrelid), ''),
                a.attgenerated::text, a.attidentity::text, COALESCE((SELECT format('%I.%I provider=%s deterministic=%s collate=%s ctype=%s', cn.nspname, co.collname, co.collprovider, co.collisdeterministic, co.collcollate, co.collctype) FROM pg_namespace cn WHERE cn.oid = co.collnamespace), ''))
  FROM pg_class c JOIN pg_attribute a ON a.attrelid = c.oid AND a.attnum > 0 AND NOT a.attisdropped
       LEFT JOIN pg_attrdef d ON d.adrelid = a.attrelid AND d.adnum = a.attnum
       LEFT JOIN pg_collation co ON co.oid = a.attcollation AND a.attcollation <> 0
  WHERE c.relnamespace = current_schema()::regnamespace AND c.relkind IN ('r', 'p', 'v', 'm', 'f')
  UNION ALL
  SELECT c.relname || '|2' || k.conname,
         format('constraint %s.%s type=%s validated=%s def=%s', c.relname, k.conname, k.contype, k.convalidated, pg_get_constraintdef(k.oid))
  FROM pg_constraint k JOIN pg_class c ON c.oid = k.conrelid
  WHERE c.relnamespace = current_schema()::regnamespace AND k.contype <> 'n'
  UNION ALL
  SELECT c.relname || '|3' || ic.relname,
         format('index %s.%s valid=%s def=%s', c.relname, ic.relname, i.indisvalid,
                replace(pg_get_indexdef(i.indexrelid), quote_ident(current_schema()) || '.', ''))
  FROM pg_index i JOIN pg_class c ON c.oid = i.indrelid JOIN pg_class ic ON ic.oid = i.indexrelid
  WHERE c.relnamespace = current_schema()::regnamespace
  UNION ALL
  SELECT c.relname || '|4',
         format('sequence %s type=%s start=%s increment=%s min=%s max=%s cache=%s cycle=%s', c.relname,
                format_type(s.seqtypid, NULL), s.seqstart, s.seqincrement, s.seqmin, s.seqmax, s.seqcache, s.seqcycle)
  FROM pg_sequence s JOIN pg_class c ON c.oid = s.seqrelid
  WHERE c.relnamespace = current_schema()::regnamespace
) x ORDER BY k COLLATE "C"`)
	if err != nil {
		return nil, fmt.Errorf("describe the schema: %w", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var line string
		if err := rows.Scan(&line); err != nil {
			return nil, fmt.Errorf("scan schema description: %w", err)
		}
		out = append(out, strings.Join(strings.Fields(line), " "))
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("describe the schema: %w", err)
	}
	return out, nil
}

// checkDescription compares the live structure to the golden description line by line and names the first object
// that differs (its kind and name, not its definition).
func checkDescription(ctx context.Context, q queryer) error {
	got, err := describeSchema(ctx, q)
	if err != nil {
		return err
	}
	want := strings.Split(strings.TrimRight(schemaGolden, "\n"), "\n")
	for i := range max(len(got), len(want)) {
		var g, w string
		if i < len(got) {
			g = got[i]
		}
		if i < len(want) {
			w = want[i]
		}
		if g != w {
			if g == "" {
				g = w
			}
			return fmt.Errorf("%w: %s differs from what the migrations create (or is missing, or is extra)", ErrSchema, objectName(g))
		}
	}
	return nil
}

// objectName is the first two words of a description line: its kind and name.
func objectName(line string) string {
	f := strings.Fields(line)
	if len(f) < 2 {
		return "an object"
	}
	return f[0] + " " + f[1]
}
