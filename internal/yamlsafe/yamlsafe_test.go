// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

package yamlsafe

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

var testLimits = Limits{MaxBytes: 1 << 10, MaxDepth: 4, MaxNodes: 50, Name: "thing"}

func TestDecode_Values(t *testing.T) { // SEC-1, CON-11
	t.Parallel()
	got, err := Decode([]byte("a: 1\nb: [x, \"2\", true, ~]\nc: {d: -7}\n"), testLimits)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]any{
		"a": jsonNumber("1"),
		"b": []any{"x", "2", true, nil},
		"c": map[string]any{"d": jsonNumber("-7")},
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("value (-want +got):\n%s", diff)
	}
}

func TestDecode_Rejects(t *testing.T) { // SEC-1
	t.Parallel()
	tests := []struct {
		name string
		in   string
		code Code
		path string
		msg  string
	}{
		{"alias", "a: &x [1]\nb: *x\n", CodeUnsafeYAML, "/a", "anchors"},
		{"anchor", "a: &x 1\n", CodeUnsafeYAML, "/a", "anchors"},
		{"tag", "a: !custom 1\n", CodeUnsafeYAML, "/a", "tag"},
		{"merge key", "a: {<<: {b: 1}}\n", CodeUnsafeYAML, "/a", "merge"},
		{"duplicate key", "a: 1\na: 2\n", CodeUnsafeYAML, "", "duplicate"},
		{"integer key", "1: a\n", CodeUnsafeYAML, "", "string"},
		{"second document", "a: 1\n---\nb: 2\n", CodeUnsafeYAML, "", "multiple"},
		{"timestamp", "a: 2001-12-14\n", CodeUnsafeYAML, "/a", "timestamp"},
		{"too deep", "a: {b: {c: {d: {e: 1}}}}\n", CodeUnsafeYAML, "/a/b/c/d", "nested deeper than 4"},
		{"too many nodes", "a: [" + strings.Repeat("1,", 60) + "]\n", CodeUnsafeYAML, "/a/47", "more than 50 nodes"},
		{"too large", "# " + strings.Repeat("x", 1<<10), CodeTooLarge, "", "thing is "},
		{"bom", "\xef\xbb\xbfa: 1\n", CodeUnsafeYAML, "", "things must be UTF-8"},
		{"nul", "a: 1\x00\n", CodeUnsafeYAML, "", "UTF-8"},
		{"empty", "", CodeSyntax, "", "thing is empty"},
		{"broken", "a: [", CodeSyntax, "", ""},
		{"list top", "- a\n", CodeSchema, "", "mapping"},
		{"float", "a: 1.5\n", CodeSchema, "/a", "integer"},
		{"hex", "a: 0x10\n", CodeSchema, "/a", "decimal"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			v, err := Decode([]byte(tt.in), testLimits)
			if err == nil {
				t.Fatalf("Decode succeeded: %v", v)
			}
			if err.Code != tt.code || err.Path != tt.path || !strings.Contains(err.Message, tt.msg) {
				t.Errorf("got %+v, want code %s path %q message containing %q", *err, tt.code, tt.path, tt.msg)
			}
		})
	}
}

func TestEscape(t *testing.T) { // SEC-1
	t.Parallel()
	if got := Escape("a\n##[x]\\\u202e", 100); got != `a\u000a\x23\x23[x]\\\u202e` {
		t.Errorf("Escape = %q", got)
	}
	if got := Pointer([]string{"a/b", "c~d", "e#"}); got != `/a~1b/c~0d/e\x23` {
		t.Errorf("Pointer = %q", got)
	}
}

func jsonNumber(s string) any { return json.Number(s) }
