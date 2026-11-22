// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

package store_test

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"unicode"

	"golang.org/x/text/cases"
	"golang.org/x/text/unicode/norm"

	"github.com/elliott-davis/lightsout/internal/store"
)

func TestRowValidate(t *testing.T) { // SEC-1
	t.Parallel()
	ok := store.Row{Kind: store.KindTrain, ID: "t1", Repo: "r", SchemaVersion: 1, Payload: []byte(`{}`)}
	if err := ok.Validate(); err != nil {
		t.Fatal(err)
	}
	for name, mut := range map[string]func(*store.Row){
		"uppercase approved revision": func(r *store.Row) { r.ApprovedRevision = "ABCDEF" },
		"short current revision":      func(r *store.Row) { r.CurrentRevision = "abc" },
		"unknown kind":                func(r *store.Row) { r.Kind = "x" },
		"oversized id":                func(r *store.Row) { r.ID = strings.Repeat("a", store.MaxKeyBytes+1) },
		"oversized payload": func(r *store.Row) {
			r.Payload = json.RawMessage(`{"a":"` + strings.Repeat("a", store.MaxPayloadBytes) + `"}`)
		},
	} {
		r := ok
		mut(&r)
		if err := r.Validate(); !errors.Is(err, store.ErrInvalid) {
			t.Errorf("%s: err = %v, want ErrInvalid", name, err)
		}
	}
}

func TestWorkItemValidate(t *testing.T) { // SEC-1
	t.Parallel()
	if err := (store.WorkItem{Key: "k", Kind: "x", Payload: []byte(`null`)}).Validate(); !errors.Is(err, store.ErrInvalid) {
		t.Errorf("null payload: %v", err)
	}
	if err := (store.WorkItem{Key: "k", Kind: "x"}).Validate(); err != nil {
		t.Errorf("empty payload: %v", err)
	}
}

// TestUnicodeTablesAgree // SEC-5: internal/contract folds and normalizes names with x/text's cases and norm
// packages and the standard library's unicode. Their tables must come from one Unicode version, or the same name
// could fold differently in two places. A dependency bump (pgx pulled x/text forward) that moves them apart fails
// here, loudly.
func TestUnicodeTablesAgree(t *testing.T) {
	t.Parallel()
	versions := map[string]string{"x/text/unicode/norm": norm.Version, "x/text/cases": cases.UnicodeVersion, "unicode": unicode.Version}
	for pkg, v := range versions {
		if v != norm.Version {
			t.Errorf("Unicode versions differ: %v", versions)
			t.Fatalf("%s has %s, norm has %s", pkg, v, norm.Version)
		}
	}
}
