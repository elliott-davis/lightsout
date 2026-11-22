// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

package contract

import (
	"errors"
	"strings"
	"testing"

	"github.com/elliott-davis/lightsout/internal/pathglob"
)

func denyMatch(t *testing.T, pattern, dir, path string) bool {
	t.Helper()
	p, err := compilePat(pattern, dir)
	if err != nil {
		t.Fatal(err)
	}
	f, err := newPathForms(path)
	if err != nil {
		t.Fatal(err)
	}
	return anyDenies([]pat{p}, f, &workBudget{limit: 1 << 40})
}

func TestDeny_FoldedAndDescendantMatching(t *testing.T) { // CON-7
	t.Parallel()
	tests := []struct {
		name    string
		dir     string
		pattern string
		path    string
		want    bool
	}{
		{"exact", "", "deploy/**", "deploy/x", true},
		{"descendant of a literal", "", "deploy", "deploy/x/y", true},
		{"the literal itself", "", "deploy", "deploy", true},
		{"upper case path", "", "deploy/**", "DEPLOY/x", true},
		{"title case path", "", "deploy/**", "Deploy/x", true},
		{"upper case descendant of a literal", "", "deploy", "DEPLOY/x/y", true},
		{"upper case pattern is folded too", "", "Deploy/**", "deploy/x", true},
		{"Kelvin sign folds to k", "", "kube/**", "Kube/x", true},
		{"Kelvin sign in a glob segment", "", "k*/x", "Kube/x", true},
		{"sharp s against ? (simple lower case keeps one rune)", "", "deploy/?.yaml", "DEPLOY/ß.yaml", true},
		{"dotless i behaves like NTFS upper case", "", "infra/**", "ınfra/x", true},
		{"NFD cafe is denied by an ASCII pattern through the skeleton", "", "cafe/**", "café/x", true},
		{"NFC cafe is denied by an ASCII pattern through the skeleton", "", "cafe/**", "café/x", true},
		{"an accent on another letter is not the same name", "", "cafe/**", "caf\u00e9s/x", false},
		{"unrelated path", "", "deploy/**", "src/x", false},
		{"sibling with the same prefix", "", "deploy", "deployment/x", false},
		{"anchored at the contract directory", "svc", "*.pem", "svc/a.pem", true},
		{"anchored: not deeper", "svc", "*.pem", "svc/sub/a.pem", false},
		{"anchored: not elsewhere", "svc", "*.pem", "a.pem", false},
		{"folded directory", "Svc", "secrets", "SVC/SECRETS/x", true},
		{"directory with a wildcard character is literal", "a*", "x", "ab/x", false},
		{"directory with a wildcard character matches itself", "a*", "x", "a*/x", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := denyMatch(t, tt.pattern, tt.dir, tt.path); got != tt.want {
				t.Errorf("denies(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

func TestDeny_InvalidFormIsAnError(t *testing.T) { // CON-7
	t.Parallel()
	// U+023A grows from 2 to 3 bytes when lower-cased, so this segment is valid as
	// written (200 bytes) and too long in every folded form (300 bytes).
	long := strings.Repeat("\u023a", 100)
	if err := pathglob.ValidatePath("a/" + long); err != nil {
		t.Fatalf("test path is not valid as written: %v", err)
	}
	for name, path := range map[string]string{
		"grows when folded": "a/" + long,
		"empty skeleton":    "a/\u200b/x",
		"only dots":         "a/.../x",
	} {
		if _, err := newPathForms(path); !errors.Is(err, pathglob.ErrInvalidPath) {
			t.Errorf("%s: err = %v, want ErrInvalidPath", name, err)
		}
	}
}

func TestDirKey(t *testing.T) { // CON-3
	t.Parallel()
	same := [][]string{
		{"deploy", "DEPLOY", "Deploy", "deploy.", "deploy ", "dep\u00adloy", "deploy\u200d"},
		{"ss", "\u00df", "SS"},
		{"infra", "\u0131nfra"},
		{"i", "\u0130", "i\u0307"},
		{"cafe", "caf\u00e9", "cafe\u0301"},
		{"k", "\u212a"},
	}
	for _, group := range same {
		for _, s := range group[1:] {
			if dirKey(s) != dirKey(group[0]) {
				t.Errorf("dirKey(%q) = %q, dirKey(%q) = %q, want equal", s, dirKey(s), group[0], dirKey(group[0]))
			}
		}
	}
	if dirKey("deploy") == dirKey("deployx") {
		t.Error("distinct names share a key")
	}
}

func TestCompilePat_Errors(t *testing.T) { // CON-7
	t.Parallel()
	for _, p := range []string{"", "../x", "a/[b]", "/abs"} {
		if _, err := compilePat(p, ""); err == nil {
			t.Errorf("compilePat(%q) succeeded", p)
		}
	}
	// A pattern whose descendant variant is too long still works in exact form.
	long := strings.Repeat("aa/", 169) + "aa"
	d, err := compilePat(long, "")
	if err != nil || !d.hasForm[1] {
		t.Fatalf("compilePat(long) = %+v, %v", d, err)
	}
	f, err := newPathForms(long + "/x")
	if err != nil {
		t.Fatal(err)
	}
	if !anyDenies([]pat{d}, f, &workBudget{limit: 1 << 40}) {
		t.Error("long pattern does not deny its descendant")
	}
}

func TestTransform(t *testing.T) { // CON-7
	t.Parallel()
	tests := []struct {
		k        int
		in, want string
	}{
		{1, "DEPLOY", "deploy"},
		{1, "K", "k"},
		{1, "Straße", "strasse"},
		{1, "café", "cafe"},
		{2, "Straße", "straße"},
		{3, "ınfra", "infra"},
		{0, "AbC", "AbC"},
	}
	for _, tt := range tests {
		if got := transform(tt.k, tt.in); got != tt.want {
			t.Errorf("transform(%d, %q) = %q, want %q", tt.k, tt.in, got, tt.want)
		}
	}
}
