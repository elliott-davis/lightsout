// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

package codeowners

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func deepPath() string { return strings.TrimSuffix(strings.Repeat("a/", 256), "/") }

// stepBound is the documented bound on the work of resolving one path through a file at the caps.
func stepBound(path string) int { return (MaxFileRunes + MaxRules) * (len(path) + 1) }

func TestLookup_ParseCapsBoundWork(t *testing.T) { // CON-2, SEC-11
	// This proves the parse caps keep the modeled work (pattern runes times path runes) within the documented
	// bound. It does not measure the matcher's actual cost.
	t.Parallel()
	path := deepPath()
	files := map[string]string{
		"5000 simple rules":    strings.Repeat("**/zz @x\n", MaxRules),
		"globs and two stars":  strings.Repeat("**/*a*a*a*a/**/zz @x\n", MaxRules),
		"three stars":          strings.Repeat("/**/a*/**/b*/**/zz @x\n", 2000),
		"32 segment patterns":  strings.Repeat("/"+strings.Repeat("a/", 31)+"zz @x\n", 1000),
		"owner-heavy rules":    strings.Repeat("/zz "+strings.Repeat("@x ", MaxRuleOwners)+"\n", 900),
		"wide globs":           strings.Repeat("/"+strings.Repeat("*a", 100)+"/zz @x\n", 400),
		"descendant directory": strings.Repeat("zz/ @x\n", MaxRules),
	}
	for name, text := range files {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			f := mustParse(t, text)
			total := 0
			if _, err := f.lookup(t.Context(), path, func(n int) error { total += n; return nil }); err != nil {
				t.Fatal(err)
			}
			if bound := stepBound(path); total > bound {
				t.Errorf("work = %d steps, want at most the documented bound %d", total, bound)
			}
		})
	}
}

func TestParse_RejectsHostileShapes(t *testing.T) { // CON-2, SEC-11
	t.Parallel()
	star := "*" + strings.Repeat("a", 120)
	tests := map[string]string{
		"four double stars with long globs": "**/" + star + "/**/" + star + "/**/" + star + "/**/" + star + "/zz @x\n",
		"126 segments":                      strings.Repeat("**/*a*a/", 63) + "zz @x\n",
		"33 segments":                       strings.Repeat("a/", 32) + "zz @x\n",
		"four double stars":                 "/a/**/b/**/c/**/d/**/e @x\n",
		"three plus unanchored double star": "**/**/**/**/a @x\n",
		"too many owners on a rule":         "/a" + strings.Repeat(" @x", MaxRuleOwners+1) + "\n",
	}
	for name, text := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			var pe *ParseError
			if _, err := Parse("CODEOWNERS", []byte(text)); !errors.As(err, &pe) {
				t.Errorf("Parse = %v, want a *ParseError", err)
			}
		})
	}
}

func TestParse_PatternLimitsAtTheEdge(t *testing.T) { // CON-2
	t.Parallel()
	for name, text := range map[string]string{
		"32 segments":        "/" + strings.Repeat("a/", 31) + "z @x\n",
		"three double stars": "/a/**/b/**/c/**/d @x\n",
		"50 owners":          "/a" + strings.Repeat(" @x", MaxRuleOwners) + "\n",
	} {
		if _, err := Parse("CODEOWNERS", []byte(text)); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestParse_FileTotals(t *testing.T) { // CON-2
	t.Parallel()
	// 4,000 rules of 32 segments each is 128,000 segments, over the 100,000 file cap.
	long := "/" + strings.Repeat("a/", 31) + "z @x\n"
	if _, err := Parse("CODEOWNERS", []byte(strings.Repeat(long, 4000))); err == nil {
		t.Error("segment total over the cap parsed")
	}
	// 1,001 rules of 50 owners is over 50,000 owner tokens.
	owners := "/a" + strings.Repeat(" @x", MaxRuleOwners) + "\n"
	if _, err := Parse("CODEOWNERS", []byte(strings.Repeat(owners, 1001))); err == nil {
		t.Error("owner total over the cap parsed")
	}
	// Total pattern characters.
	wide := "/" + strings.Repeat("a", 200) + " @x\n"
	if _, err := Parse("CODEOWNERS", []byte(strings.Repeat(wide, 600))); err == nil {
		t.Error("character total over the cap parsed")
	}
	if _, err := Parse("CODEOWNERS", []byte(strings.Repeat(owners, 1000))); err != nil {
		t.Errorf("exactly 50,000 owner tokens: %v", err)
	}
}

func TestParse_SegmentCapFiresAlone(t *testing.T) { // CON-2
	t.Parallel()
	// 1,700 rules of 32 one-rune segments: 54,400 segments but only 54,400 runes, so the rune cap (100,000) holds.
	rule := "/" + strings.Repeat("a/", 31) + "z @x\n"
	if _, err := Parse("CODEOWNERS", []byte(strings.Repeat(rule, 1500))); err != nil {
		t.Errorf("48,000 segments: %v", err)
	}
	var pe *ParseError
	if _, err := Parse("CODEOWNERS", []byte(strings.Repeat(rule, 1700))); !errors.As(err, &pe) {
		t.Errorf("54,400 segments parsed, want the segment cap to reject them")
	}
}

func TestOwners_Cancellation(t *testing.T) { // CON-2
	t.Parallel()
	f := mustParse(t, strings.Repeat("**/zz @x\n", 1000))
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, _, err := f.Owners(ctx, "a/b"); !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want context.Canceled", err)
	}
}

func TestValidators(t *testing.T) { // CON-2
	t.Parallel()
	tests := []struct {
		name string
		got  bool
		want bool
	}{
		{"login empty", validLogin(""), false},
		{"login 39", validLogin(strings.Repeat("a", 39)), true},
		{"login 40", validLogin(strings.Repeat("a", 40)), false},
		{"login leading hyphen", validLogin("-a"), false},
		{"login inner hyphen", validLogin("a-b"), true},
		{"login unicode", validLogin("alïce"), false},
		{"login kelvin", validLogin("Kate"), false},
		{"login space", validLogin("a b"), false},
		{"team 100", validTeam(strings.Repeat("a", 100)), true},
		{"team 101", validTeam(strings.Repeat("a", 101)), false},
		{"team empty", validTeam(""), false},
		{"team dots", validTeam("a_b.c-d"), true},
		{"team slash", validTeam("a/b"), false},
		{"email ok", validEmail("x@y.io"), true},
		{"email 254", validEmail(strings.Repeat("a", 254-len("@y.io")) + "@y.io"), true},
		{"email 255", validEmail(strings.Repeat("a", 255-len("@y.io")) + "@y.io"), false},
		{"email dot first", validEmail("x@.io"), false},
		{"email dot last", validEmail("x@y."), false},
		{"email no dot", validEmail("x@y"), false},
		{"email two at", validEmail("x@y@z.io"), false},
		{"email empty local", validEmail("@y.io"), false},
		{"email space", validEmail("x @y.io"), false},
	}
	for _, tc := range tests {
		if tc.got != tc.want {
			t.Errorf("%s = %v, want %v", tc.name, tc.got, tc.want)
		}
	}
}

func BenchmarkLookup_Worst(b *testing.B) {
	f, err := Parse("CODEOWNERS", []byte(strings.Repeat("**/*a*a*a*a/**/zz @x\n", MaxRules)))
	if err != nil {
		b.Fatal(err)
	}
	path := deepPath()
	b.ResetTimer()
	for range b.N {
		if _, err := f.lookup(b.Context(), path, nil); err != nil {
			b.Fatal(err)
		}
	}
}
