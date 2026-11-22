// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

package switches

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestParseJSON_Boundaries_FLG2(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		data string
		max  int
		code Code // empty: must parse
	}{
		{"depth equal to the cap", nest(4), 4, ""},
		{"depth over the cap", nest(5), 4, CodeTooDeep},
		{"array depth over the cap", `[[[[1]]]]`, 3, CodeTooDeep},
		{"array depth at the cap", `[[[1]]]`, 3, ""},
		{"scalar top level", `1`, 1, ""},
		{"byte-order mark", "\xEF\xBB\xBF{}", 4, CodeEncoding},
		{"invalid UTF-8", "{\"a\":\"\xff\"}", 4, CodeEncoding},
		{"trailing value", `{} {}`, 4, CodeSyntax},
		{"trailing scalar", `{} 1`, 4, CodeSyntax},
		{"trailing whitespace is fine", "{}\n \t", 4, ""},
		{"duplicate key in an array element", `[{"a":1,"a":2}]`, 4, CodeDuplicateKey},
		{"same key in sibling objects is fine", `[{"a":1},{"a":2}]`, 4, ""},
		{"empty input", ``, 4, CodeSyntax},
		{"unclosed array", `[1`, 4, CodeSyntax},
		{"unclosed object", `{"a":1`, 4, CodeSyntax},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, perr := parseJSON([]byte(tt.data), tt.max)
			switch {
			case tt.code == "" && perr != nil:
				t.Errorf("unexpected error %+v", perr)
			case tt.code != "" && (perr == nil || perr.code != tt.code):
				t.Errorf("error = %+v, want %s", perr, tt.code)
			}
		})
	}
}

func TestParseJSON_DuplicateKeyPointer_FLG2(t *testing.T) {
	t.Parallel()
	_, perr := parseJSON([]byte(`{"a":[{"b":1,"b":2}]}`), 8)
	if perr == nil || strings.Join(perr.path, "/") != "a/0/b" {
		t.Errorf("error = %+v", perr)
	}
}

func TestEscape_EveryCharacter_FLG3(t *testing.T) {
	t.Parallel()
	tests := map[string]string{
		"@": `\x40`, "<": `\x3c`, ">": `\x3e`, "&": `\x26`, "`": "\\x60", "[": `\x5b`, "]": `\x5d`,
		"(": `\x28`, ")": `\x29`, "|": `\x7c`, "*": `\x2a`, "~": `\x7e`, "!": `\x21`, "#": `\x23`,
		"::": `\x3a\x3a`, "://": `:\/\/`, "www.": `www\.`, "WWW.": `WWW\.`, "xWwW.y": `xWwW\.y`,
		"\n": `\u000a`, `\`: `\\`, "\xff": `\xff`, "a:b": "a:b", "plain_key-1": "plain_key-1",
	}
	for in, want := range tests {
		if got := escape(in); got != want {
			t.Errorf("escape(%q) = %q, want %q", in, got, want)
		}
	}
	if got := escape(strings.Repeat("a", 500)); len(got) > escapeLimit {
		t.Errorf("escaped text is %d bytes, over the %d limit", len(got), escapeLimit)
	}
}

func TestPointer_FLG2(t *testing.T) {
	t.Parallel()
	if got := pointer(nil); got != "" {
		t.Errorf("pointer(nil) = %q", got)
	}
	if got := pointer([]string{"flags", "a/b", "~", "@x"}); got != `/flags/a~1b/\x7e/\x40x` {
		t.Errorf("pointer = %q", got)
	}
}

func TestBreakWWW_FLG3(t *testing.T) {
	t.Parallel()
	// Lower-casing "Ⱥ", "İ", "K" (Kelvin) and "ẞ" changes their length in bytes, which broke offsets taken from the
	// lower-cased copy.
	for in, want := range map[string]string{
		"www.x": `www\.x`, "WwW.x": `WwW\.x`, "xwww.": `xwww\.`, "wwww.": `wwww\.`, "www": "www", "ww.": "ww.", "": "",
		"Ⱥwww.x": `Ⱥwww\.x`, "İwww.x": `İwww\.x`, "Kwww.x": `Kwww\.x`, "ẞwww.x": `ẞwww\.x`,
		"www.Ⱥwww.": `www\.Ⱥwww\.`, "İİİwww.İ": `İİİwww\.İ`, "KKWWW.": `KKWWW\.`,
	} {
		if got := breakWWW(in); got != want {
			t.Errorf("breakWWW(%q) = %q, want %q", in, got, want)
		}
		if got := escape(in); strings.Contains(strings.ToLower(got), "www.") {
			t.Errorf("escape(%q) = %q still has www.", in, got)
		}
	}
}

func FuzzEscape(f *testing.F) {
	for _, s := range []string{
		"", "plain", "@team ::error:: ##[group] <img src=x> `tick` | [l](u)", "https://evil.example/x www.evil.example",
		"WWW.EXAMPLE", "Ⱥwww.x", "İwww.x", "Kwww.x", "ẞwww.x", "ſ://x", "::", ":::/", "://:/", "\xff\xfe", "a\nb\r\x00",
		"www.www.www.", ":/:/", ": //", "\\x40", "~!&*()",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		got := escape(s)
		if !utf8.ValidString(got) {
			t.Fatalf("escape(%q) = %q is not valid UTF-8", s, got)
		}
		lower := strings.ToLower(got)
		if strings.Contains(got, "://") || strings.Contains(lower, "www.") || strings.Contains(got, "::") {
			t.Fatalf("escape(%q) = %q keeps an autolink or command token", s, got)
		}
		if i := strings.IndexAny(got, "@<>&`[]()|*~!#\n\r"); i >= 0 {
			t.Fatalf("escape(%q) = %q keeps %q", s, got, got[i])
		}
	})
}
