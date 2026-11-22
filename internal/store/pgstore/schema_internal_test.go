// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

package pgstore

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/jackc/pgx/v5"
)

var update = flag.Bool("update", false, "rewrite schema.golden from a freshly migrated schema")

// TestSchemaGolden_PG keeps schema.golden equal to what the migrations create. Run with -update after adding a
// migration, and review the diff.
func TestSchemaGolden_PG(t *testing.T) { // NFR-4
	base := os.Getenv("LIGHTSOUT_TEST_POSTGRES_URL")
	if base == "" {
		t.Skip("LIGHTSOUT_TEST_POSTGRES_URL is not set")
	}
	ctx := t.Context()
	var b [6]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatal(err)
	}
	name := "lo_g_" + hex.EncodeToString(b[:])
	su, err := pgx.Connect(ctx, base)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = su.Exec(ctx, "CREATE SCHEMA "+name); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = su.Exec(context.WithoutCancel(ctx), "DROP SCHEMA "+name+" CASCADE")
		_ = su.Close(context.WithoutCancel(ctx))
	})
	u, err := url.Parse(base)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	q.Set("search_path", name)
	u.RawQuery = q.Encode()
	if err = Migrate(ctx, u.String(), ""); err != nil {
		t.Fatal(err)
	}
	c, err := pgx.Connect(ctx, u.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close(context.WithoutCancel(ctx)) })
	got, err := describeSchema(ctx, c)
	if err != nil {
		t.Fatal(err)
	}
	text := strings.Join(got, "\n") + "\n"
	if *update {
		if err := os.WriteFile("testdata/schema.golden", []byte(text), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	if diff := cmp.Diff(schemaGolden, text); diff != "" {
		t.Errorf("schema.golden is stale (-golden +migrated); regenerate with -update:\n%s", diff)
	}
}
