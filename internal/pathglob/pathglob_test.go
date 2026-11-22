// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

package pathglob

import (
	"errors"
	"strings"
	"testing"
)

func mustCompile(tb testing.TB, s string) Pattern {
	tb.Helper()
	p, err := Compile(s)
	if err != nil {
		tb.Fatalf("Compile(%q): %v", s, err)
	}
	return p
}

func TestCompile_Valid(t *testing.T) { // CON-7
	t.Parallel()
	tests := []struct{ in, want string }{
		{"a", "a"},
		{"src/**", "src/**"},
		{"**", "**"},
		{"*.go", "*.go"},
		{"a/**/**/b", "a/**/b"},
		{"**/**", "**"},
		{"a?c/*/x*y", "a?c/*/x*y"},
		{strings.Repeat("a", 512), strings.Repeat("a", 512)},
	}
	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			t.Parallel()
			p, err := Compile(tc.in)
			if err != nil {
				t.Fatalf("Compile: %v", err)
			}
			if got := p.String(); got != tc.want {
				t.Errorf("String() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestCompile_Invalid(t *testing.T) { // CON-7
	t.Parallel()
	tests := map[string]string{
		"empty":           "",
		"too long":        strings.Repeat("a", 513),
		"bad utf8":        "a/\xff",
		"leading slash":   "/a",
		"trailing slash":  "a/",
		"empty segment":   "a//b",
		"dot":             "a/./b",
		"dotdot":          "../a",
		"dotdot mid":      "a/../b",
		"backslash":       `a\b`,
		"open bracket":    "a[1]",
		"close bracket":   "a]",
		"open brace":      "{a,b}",
		"close brace":     "a}",
		"nul":             "a\x00b",
		"control":         "a\tb",
		"newline":         "a\nb",
		"del":             "a\x7fb",
		"embedded **":     "a**",
		"leading **":      "**b",
		"mid **":          "a/x**y/b",
		"triple star seg": "a/***",
		"only slash":      "/",
		"bracket in name": "a[1].txt",
		"next line":       "a\u0085b",
		"zero width":      "a\u200bb",
		"bidi override":   "a\u202eb",
		"bom":             "a\ufeffb",
		"line separator":  "a\u2028b",
		"para separator":  "a\u2029b",
		"soft hyphen":     "a\u00adb",
		"hangul filler":   "a\u3164b",
		"nbsp":            "a\u00a0b",
		"cyrillic e":      "a\u0435b",
		"e acute":         "a\u00e9b",
		"invalid utf8":    "a\xffb",
	}
	for name, in := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, err := Compile(in)
			if !errors.Is(err, ErrSyntax) {
				t.Errorf("Compile(%q) error = %v, want ErrSyntax", in, err)
			}
		})
	}
}

func TestCompile_ErrorTruncatesInput(t *testing.T) {
	t.Parallel()
	_, err := Compile(strings.Repeat("a", 600))
	if err == nil || len(err.Error()) > 300 {
		t.Fatalf("error should be truncated, got len %d", len(err.Error()))
	}
}

func TestValidatePath(t *testing.T) {
	t.Parallel()
	valid := []string{"a", "a/b", "a[1].txt", `a\b`, "we*rd/x?", "héllo/世界", strings.Repeat("a", 255), strings.Repeat(strings.Repeat("a", 255)+"/", 15) + "a"}
	invalid := []string{
		strings.Repeat("a/", 256) + "a", // 257 segments
		"", "/a", "a/", "a//b", ".", "..", "a/./b", "a/../b", "a\x00b",
		"a/\xff", strings.Repeat("a", 4097), strings.Repeat("a", 256), "a/" + strings.Repeat("a", 4000),
		strings.Repeat(strings.Repeat("a", 255)+"/", 17) + "a", // over 4096 bytes
	}
	valid = append(valid, strings.Repeat("a/", 255)+"a") // 256 segments
	for _, p := range valid {
		if err := ValidatePath(p); err != nil {
			t.Errorf("ValidatePath(%.20q) = %v, want nil", p, err)
		}
	}
	for _, p := range invalid {
		if err := ValidatePath(p); !errors.Is(err, ErrInvalidPath) {
			t.Errorf("ValidatePath(%.20q) = %v, want ErrInvalidPath", p, err)
		}
	}
}

func TestString_RebaseIsDisplayOnly(t *testing.T) { // CON-12
	t.Parallel()
	p, err := mustCompile(t, "x").Rebase("*")
	if err != nil {
		t.Fatal(err)
	}
	if p.Match("other/x") {
		t.Error("rebased literal dir * must not match other/x")
	}
	if !p.Match("*/x") {
		t.Error("rebased literal dir * must match */x")
	}
	// String prints the literal dir unescaped, so recompiling it yields a
	// wildcard that matches more than the original. This is why String is
	// display only.
	if !mustCompile(t, p.String()).Match("other/x") {
		t.Error("Compile(String()) is expected to widen the pattern")
	}
}

func TestMatch(t *testing.T) { // CON-7
	t.Parallel()
	tests := []struct {
		pat, path string
		want      bool
	}{
		{"**", "a", true},
		{"**", "a/b/c.go", true},
		{"src/**", "src", true},
		{"src/**", "src/a", true},
		{"src/**", "src/a/b/c", true},
		{"src/**", "srcx/a", false},
		{"src/**", "other/src/a", false},
		{"*.go", "main.go", true},
		{"*.go", "cmd/main.go", false},
		{"*.go", "main.rs", false},
		{"*", "a", true},
		{"*", "a/b", false},
		{"a?c", "abc", true},
		{"a?c", "ac", false},
		{"a?c", "abbc", false},
		{"a?c", "aéc", true},
		{"a?c", "a世c", true},
		{"?", "é", true},
		{"?", "ab", false},
		{"README", "readme", false},
		{"README", "README", true},
		{"*.txt", "a[1].txt", true},
		{"**/x", "x", true},
		{"**/x", "a/b/x", true},
		{"**/x", "a/b/y", false},
		{"a/**/b", "a/b", true},
		{"a/**/b", "a/x/y/b", true},
		{"a/**/b/**", "a/b", true},
		{"a*b*c", "aXbYc", true},
		{"a*b*c", "abc", true},
		{"a*b*c", "acb", false},
		{"*a", "ba", true},
		{"*a", "ab", false},
		{"**", "", false},
		{"**", "/a", false},
		{"**", "a//b", false},
		{"**", "a/../b", false},
		{"**", "a/", false},
	}
	for _, tc := range tests {
		t.Run(tc.pat+"|"+tc.path, func(t *testing.T) {
			t.Parallel()
			p, err := Compile(tc.pat)
			if err != nil {
				t.Fatal(err)
			}
			if got := p.Match(tc.path); got != tc.want {
				t.Errorf("Match(%q, %q) = %v, want %v", tc.pat, tc.path, got, tc.want)
			}
		})
	}
}

func TestRebase(t *testing.T) { // CON-12
	t.Parallel()
	t.Run("literal dir with wildcard chars", func(t *testing.T) {
		t.Parallel()
		p, err := mustCompile(t, "x/*").Rebase("a/we*rd")
		if err != nil {
			t.Fatal(err)
		}
		if !p.Match("a/we*rd/x/y") || p.Match("a/weXrd/x/y") {
			t.Errorf("unexpected match behavior for %s", p)
		}
		q, err := mustCompile(t, "**").Rebase("we*rd")
		if err != nil {
			t.Fatal(err)
		}
		if q.String() != "we*rd/**" {
			t.Errorf("String() = %q", q)
		}
		if !q.Match("we*rd/a") || q.Match("weXrd/a") || q.Match("we?rd/a") {
			t.Error("dir segment must be literal")
		}
		r, _ := mustCompile(t, "x").Rebase("a?c")
		if r.Match("abc/x") || !r.Match("a?c/x") {
			t.Error("? in dir must be literal")
		}
	})
	t.Run("root", func(t *testing.T) {
		t.Parallel()
		p, err := mustCompile(t, "src/**").Rebase("")
		if err != nil || p.String() != "src/**" {
			t.Errorf("got %v, %v", p, err)
		}
	})
	t.Run("invalid dir", func(t *testing.T) {
		t.Parallel()
		for _, d := range []string{"/a", "a/", "a/../b", "a//b", "."} {
			if _, err := mustCompile(t, "**").Rebase(d); !errors.Is(err, ErrInvalidPath) {
				t.Errorf("Rebase(%q) = %v, want ErrInvalidPath", d, err)
			}
		}
	})
}

func TestContains(t *testing.T) { // CON-7
	t.Parallel()
	tests := []struct {
		outer, inner string
		want         bool
	}{
		{"**", "a", true},
		{"**", "**", true},
		{"**", "a/*/b/**", true},
		{"src/**", "src/a/**", true},
		{"src/**", "src/*.go", true},
		{"src/**", "src/**/x", true},
		{"src/**", "src", true},
		{"src/*.go", "src/**", false},
		{"*", "foo", true},
		{"*.go", "*", false},
		{"src/**", "**", false},
		{"a/*/c", "a/b/c", true},
		{"a/*/c", "a/**/c", false},
		{"**/x", "a/**/x", true},
		{"**/x", "x", true},
		{"svc/**/*.go", "svc/**", false},
		{"svc/**", "svc/**/*.go", true},
		{"src/*.go", "src/*.go", true},
		{"a/**/b", "a/**/b", true},
		{"*.go", "*.go", true},
		{"*.go", "main.go", true},
		{"*.go", "main.rs", false},
		{"a", "b", false},
		{"a/b", "a", false},
		{"a", "a/b", false},
		{"a/**", "b/**", false},
		// True semantically, but not proven: reported as false (fails closed).
		{"*.go", "?*.go", false},
		{"*", "a*", true},
		{"a*", "*", false},
	}
	for _, tc := range tests {
		t.Run(tc.outer+"|"+tc.inner, func(t *testing.T) {
			t.Parallel()
			if got := Contains(mustCompile(t, tc.outer), mustCompile(t, tc.inner)); got != tc.want {
				t.Errorf("Contains(%q, %q) = %v, want %v", tc.outer, tc.inner, got, tc.want)
			}
		})
	}
}

func TestContains_RebasedChild(t *testing.T) { // CON-12
	t.Parallel()
	child, err := mustCompile(t, "payment/**").Rebase("src/checkout")
	if err != nil {
		t.Fatal(err)
	}
	if !Contains(mustCompile(t, "src/**"), child) {
		t.Error("src/** should contain src/checkout/payment/**")
	}
	if Contains(mustCompile(t, "lib/**"), child) {
		t.Error("lib/** must not contain src/checkout/payment/**")
	}
	// Literal dir text with wildcard chars is not matched by a glob outer
	// unless the glob really matches that text.
	weird, _ := mustCompile(t, "**").Rebase("we*rd")
	if Contains(mustCompile(t, "weXrd/**"), weird) {
		t.Error("weXrd/** must not contain we*rd/**")
	}
	if !Contains(mustCompile(t, "we*rd/**"), weird) {
		t.Error("glob we*rd/** matches the literal text we*rd")
	}
}

func TestWitness(t *testing.T) {
	t.Parallel()
	outer, inner := mustCompile(t, "src/*.go"), mustCompile(t, "src/**")
	w, ok := Witness(outer, inner)
	if !ok {
		t.Fatal("expected a witness")
	}
	if ValidatePath(w) != nil || !inner.Match(w) || outer.Match(w) {
		t.Errorf("bad witness %q", w)
	}
	for _, tc := range [][2]string{{"src/**", "src/a/**"}, {"**", "a/*/b"}, {"*", "foo"}} {
		if w, ok := Witness(mustCompile(t, tc[0]), mustCompile(t, tc[1])); ok {
			t.Errorf("Witness(%q, %q) = %q, want none", tc[0], tc[1], w)
		}
	}
}

var corpusPatterns = []string{
	"**", "*", "*.go", "?*.go", "src/**", "src/*.go", "src/**/x", "src/a/**", "src", "a/*/c",
	"a/b/c", "**/x", "a/**/x", "x", "svc/**", "svc/**/*.go", "a*", "*a", "a?c", "?",
	"a/**/b", "**/*.go", "src/*/*.go", "a/*", "a/**/*", "*/*", "docs/**", "we*rd/**", "x/**/y/**", "a?",
}

var corpusPaths = []string{
	"a", "x", "src", "src/a", "src/x", "src/a.go", "src/a/b", "src/a/x", "src/a/b/x", "src/a/b.go",
	"main.go", "cmd/main.go", "a/b/c", "a/c", "a/b", "a/x/c", "a/x", "a/b/x", "x/y", "svc",
	"svc/a.go", "svc/a/b.go", "svc/a/b", "ab", "ba", "abc", "aXc", "é", "ab/c", "docs",
	"docs/readme.md", "we*rd/a", "weXrd/a", "a/b/b", "a/b/c/d", "a/c/b", "x/y/y", "x/a/y/b/y/c",
	"x/y/z", "ac", "a/b/c.go", "z/x", "z/a/x", "q.go", "q/r.go", "a.go", "ab.go", "x.go",
	"src/x/y.go", "src/x/y", "a/", "b", "b/a", "a/a", "a/a/a", "a/a/b", "src/src", "svc/x/y/z.go", "?", "a?",
}

func TestContains_Sound(t *testing.T) { // CON-7
	t.Parallel()
	pats := make([]Pattern, len(corpusPatterns))
	for i, s := range corpusPatterns {
		pats[i] = mustCompile(t, s)
	}
	for i, outer := range pats {
		for j, inner := range pats {
			if !Contains(outer, inner) {
				continue
			}
			for _, path := range corpusPaths {
				if inner.Match(path) && !outer.Match(path) {
					t.Errorf("Contains(%q, %q) but %q matches only inner", corpusPatterns[i], corpusPatterns[j], path)
				}
			}
		}
	}
}

// enumerate returns every join of 1..maxLen words from the alphabet.
func enumerate(alphabet []string, maxLen int) []string {
	var out []string
	var rec func(prefix []string)
	rec = func(prefix []string) {
		if len(prefix) > 0 {
			out = append(out, strings.Join(prefix, "/"))
		}
		if len(prefix) == maxLen {
			return
		}
		for _, w := range alphabet {
			rec(append(prefix[:len(prefix):len(prefix)], w))
		}
	}
	rec(nil)
	return out
}

func TestContains_BruteForceSound(t *testing.T) { // CON-7, CON-12
	t.Parallel()
	var pats []Pattern
	var names []string
	for _, s := range enumerate([]string{"a", "b", "*", "?", "**", "a*", "*b"}, 3) {
		p := mustCompile(t, s)
		q, err := p.Rebase("d*")
		if err != nil {
			t.Fatal(err)
		}
		pats = append(pats, p, q)
		names = append(names, s, "d*(literal)/"+s)
	}

	words := []string{"a", "b", "ab", "ba", "x"}
	paths := enumerate(words, 4)
	for _, p := range enumerate(words, 3) {
		paths = append(paths, "d*/"+p, "dx/"+p)
	}

	matches := make([][]bool, len(pats))
	for i, p := range pats {
		matches[i] = make([]bool, len(paths))
		for k, path := range paths {
			matches[i][k] = p.Match(path)
		}
	}
	for i, o := range pats {
		for j, in := range pats {
			if !Contains(o, in) {
				continue
			}
			for k, path := range paths {
				if matches[j][k] && !matches[i][k] {
					t.Fatalf("Contains(%q, %q) but %q matches only inner", names[i], names[j], path)
				}
			}
			if w, ok := Witness(o, in); ok {
				t.Fatalf("Contains(%q, %q) but Witness returned %q", names[i], names[j], w)
			}
		}
	}
}

func FuzzCompileMatch(f *testing.F) {
	for _, s := range []string{"**", "src/**", "*.go", "a/?/c", "a/**/b/**", "we*rd", "a**", "/a", ""} {
		f.Add(s, s, "src/a.go")
	}
	f.Add("a/*/c", "a/b/c", "a/b/c")
	f.Add("src/**", "src/a/**", "src/a/b")
	f.Add("**", "a/*/b", "a/x/b")
	f.Add("*", "a*", "ab")
	f.Add("**/x", "a/**/x", "a/b/x")
	f.Add("src/**", "src/*.go", "src/a.go")
	f.Fuzz(func(t *testing.T, patA, patB, path string) {
		a, err := Compile(patA)
		if err != nil {
			return
		}
		_ = a.Match(path)
		_ = a.Match(patA)
		if !Contains(a, a) {
			t.Errorf("Contains(%q, %q) = false, want reflexive", patA, patA)
		}
		if q, rerr := a.Rebase("d/e"); rerr == nil {
			_ = Contains(a, q)
			_ = Contains(q, a)
			_, _ = Witness(q, a)
		}
		b, err := Compile(patB)
		if err != nil {
			return
		}
		if ValidatePath(path) == nil && Contains(a, b) && b.Match(path) && !a.Match(path) {
			t.Errorf("Contains(%q, %q) but %q matches only inner", patA, patB, path)
		}
	})
}

func TestWithDescendants(t *testing.T) { // CON-7
	t.Parallel()
	long := strings.Repeat("aa/", 169) + "aa" // near the pattern length limit
	tests := []struct {
		pattern string
		path    string
		want    bool
	}{
		{"deploy", "deploy", true},
		{"deploy", "deploy/x/y", true},
		{"deploy", "deployment/x", false},
		{"src/*.go", "src/a.go/b", true},
		{"src/*.go", "src/a.txt", false},
		{"deploy/**", "deploy", true},
		{"deploy/**", "deploy/x", true},
		{"**/*.pem", "a/b.pem/c", true},
		{long, long + "/x", true},
	}
	for _, tt := range tests {
		got := mustCompile(t, tt.pattern).WithDescendants().Match(tt.path)
		if got != tt.want {
			t.Errorf("%.20q.WithDescendants().Match(%.20q) = %v, want %v", tt.pattern, tt.path, got, tt.want)
		}
	}
	if _, err := Compile(strings.Repeat("aa/", 170) + "aa/**"); err == nil {
		t.Fatal("test pattern is not at the limit")
	}
	over := mustCompile(t, strings.Repeat("aa/", 170)+"aa").WithDescendants()
	if !over.Match(strings.Repeat("aa/", 170) + "aa/x") {
		t.Error("a 512-byte pattern lost its descendants")
	}
	var zero Pattern
	if zero.WithDescendants().Match("x") || zero.WithDescendants().Segments() != 0 {
		t.Error("the zero pattern must keep matching nothing")
	}
	p := mustCompile(t, "a/b")
	_ = p.WithDescendants()
	if p.Match("a/b/c") || p.Segments() != 2 {
		t.Error("WithDescendants changed the receiver")
	}
}

func TestRunes(t *testing.T) { // CON-7
	t.Parallel()
	tests := []struct {
		pattern string
		want    int
	}{{"a", 1}, {"src/**", 5}, {"*.go", 4}, {"a/*", 2}}
	for _, tt := range tests {
		p := mustCompile(t, tt.pattern)
		if got := p.Runes(); got != tt.want {
			t.Errorf("%q: Runes() = %d, want %d", tt.pattern, got, tt.want)
		}
		if got := p.WithDescendants().Runes(); got != tt.want+2 && !strings.HasSuffix(tt.pattern, "**") {
			t.Errorf("%q: WithDescendants().Runes() = %d, want %d", tt.pattern, got, tt.want+2)
		}
	}
	r, err := mustCompile(t, "x/*").Rebase("d\u00e9/y")
	if err != nil || r.Runes() != 5 {
		t.Errorf("Rebase Runes() = %d, %v", r.Runes(), err)
	}
	if (Pattern{}).Runes() != 0 {
		t.Error("zero pattern has runes")
	}
}
