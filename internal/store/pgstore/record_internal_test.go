// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

package pgstore

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/google/go-cmp/cmp"

	"github.com/elliott-davis/lightsout/internal/audit"
	"github.com/elliott-davis/lightsout/internal/store"
)

// fill sets every exported field reachable from v to a distinct non-zero value.
func fill(t *testing.T, v reflect.Value, path string) {
	t.Helper()
	switch v.Kind() { //nolint:exhaustive // only the kinds audit.Record is built from; anything else fails the test below
	case reflect.String:
		v.SetString("v:" + path)
	case reflect.Pointer:
		v.Set(reflect.New(v.Type().Elem()))
		fill(t, v.Elem(), path)
	case reflect.Struct:
		for i := range v.NumField() {
			f := v.Type().Field(i)
			if !f.IsExported() {
				t.Fatalf("%s.%s is unexported: the audit record gained state this test cannot fill", path, f.Name)
			}
			fill(t, v.Field(i), path+"."+f.Name)
		}
	case reflect.Map:
		if v.Type().Key().Kind() != reflect.String || v.Type().Elem().Kind() != reflect.String {
			t.Fatalf("%s: unsupported map type %s", path, v.Type())
		}
		m := reflect.MakeMap(v.Type())
		m.SetMapIndex(reflect.ValueOf("k."+path).Convert(v.Type().Key()), reflect.ValueOf("v:"+path).Convert(v.Type().Elem()))
		v.Set(m)
	default:
		t.Fatalf("%s: unsupported kind %s: extend recordJSON and this test together", path, v.Kind())
	}
}

func TestRecordJSONRoundTripsEveryField(t *testing.T) { // NFR-4: a field recordJSON forgets would break every hash
	t.Parallel()
	var r audit.Record
	fill(t, reflect.ValueOf(&r).Elem(), "Record")
	b, err := json.Marshal(toRecordJSON(r))
	if err != nil {
		t.Fatal(err)
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var rj recordJSON
	if err := dec.Decode(&rj); err != nil {
		t.Fatal(err)
	}
	if diff := cmp.Diff(r, rj.record()); diff != "" {
		t.Fatalf("record changed through recordJSON (-want +got):\n%s", diff)
	}
}

func TestMapErr(t *testing.T) { // SEC-1: the database's refusal of a value is ErrInvalid, a lost race is ErrRetry
	t.Parallel()
	for code, want := range map[string]error{
		"22P05": store.ErrInvalid, "22P02": store.ErrInvalid, "22021": store.ErrInvalid, "22003": store.ErrInvalid,
		"40P01": store.ErrRetry, "40001": store.ErrRetry, "55P03": store.ErrRetry,
	} {
		err := mapErr("op", &pgconn.PgError{Code: code, Message: "m"})
		if !errors.Is(err, want) {
			t.Errorf("SQLSTATE %s: err = %v, want %v", code, err, want)
		}
	}
	other := &pgconn.PgError{Code: "23505"}
	if err := mapErr("op", other); errors.Is(err, store.ErrInvalid) || errors.Is(err, store.ErrRetry) || !errors.Is(err, other) {
		t.Errorf("an unrelated error was reclassified: %v", err)
	}
}
