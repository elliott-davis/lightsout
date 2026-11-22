// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

package codeowners

import (
	"errors"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func mustParse(t *testing.T, text string) *File {
	t.Helper()
	f, err := Parse("CODEOWNERS", []byte(text))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return f
}

// winner returns the winning pattern for path, "" for no match.
func winner(t *testing.T, f *File, path string) string {
	t.Helper()
	_, r, err := f.Owners(t.Context(), path)
	if err != nil {
		t.Fatalf("Owners(%q): %v", path, err)
	}
	return r.Pattern
}

// githubExample is written by hand from the example in GitHub's CODEOWNERS documentation.
const githubExample = `# This is a comment.
* @global-owner1 @global-owner2
*.js @js-owner #This is an inline comment.
*.go docs@example.com
*.txt @octo-org/octocats
/build/logs/ @doctocat
docs/*  docs@example.com
apps/ @octocat
/docs/ @doctocat
/scripts/ @doctocat @octocat
**/logs @octocat
/apps/ @octocat
/apps/github
`

func TestOwners_GitHubExample(t *testing.T) { // CON-2
	t.Parallel()
	f := mustParse(t, githubExample)
	tests := []struct{ path, want string }{
		{"README.md", "*"},
		{"deep/dir/README.md", "*"},
		{"main.go", "*.go"},
		{"src/a/b.js", "*.js"},
		{"notes/todo.txt", "*.txt"},
		{"build/logs/x/y.log", "**/logs"}, // later than /build/logs/
		{"build/logs/app.js", "**/logs"},
		{"other/build/logs/x.log", "**/logs"},
		{"src/logs/a.js", "**/logs"},
		{"docs/getting-started.md", "/docs/"}, // later than docs/*
		{"docs/build-app/troubleshooting.md", "/docs/"},
		{"a/docs/x.md", "*"}, // docs/* and /docs/ are anchored
		{"scripts/run.sh", "/scripts/"},
		{"apps/other/x.md", "/apps/"},
		{"deep/apps/x.md", "apps/"}, // a trailing-slash-only pattern matches at any depth
		{"apps/x.go", "/apps/"},
		{"apps/github/main.go", "/apps/github"},
		{"apps/github", "/apps/github"},
	}
	for _, tc := range tests {
		t.Run(tc.path, func(t *testing.T) {
			t.Parallel()
			if got := winner(t, f, tc.path); got != tc.want {
				t.Errorf("winner(%q) = %q, want %q", tc.path, got, tc.want)
			}
		})
	}
	owners, rule, err := f.Owners(t.Context(), "apps/github/main.go")
	if err != nil || len(owners) != 0 || rule.Line != 13 {
		t.Errorf("owner-less override: owners=%v rule=%+v err=%v, want no owners from line 13", owners, rule, err)
	}
	owners, rule, _ = f.Owners(t.Context(), "README.md")
	want := []Owner{{Kind: OwnerUser, Login: "global-owner1"}, {Kind: OwnerUser, Login: "global-owner2"}}
	if diff := cmp.Diff(want, owners); diff != "" || rule.Line != 2 {
		t.Errorf("owners of README.md (line %d) mismatch (-want +got):\n%s", rule.Line, diff)
	}
}

func TestOwners_Patterns(t *testing.T) { // CON-2
	t.Parallel()
	tests := []struct {
		name, file, path, want string
	}{
		{"unanchored name any depth", "foo @a", "x/y/foo", "foo"},
		{"unanchored name owns dir contents", "foo @a", "x/foo/z.txt", "foo"},
		{"leading slash anchors", "/foo @a", "x/foo", ""},
		{"leading slash at root", "/foo @a", "foo", "/foo"},
		{"middle slash anchors", "a/b @x", "z/a/b", ""},
		{"middle slash at root", "a/b @x", "a/b", "a/b"},
		{"directory owns below", "/docs/ @a", "docs/x/y.md", "/docs/"},
		{"trailing slash is not a file", "/docs/ @a", "docs", ""},
		{"trailing slash any depth", "docs/ @a", "x/docs/y.md", "docs/"},
		{"literal dir without slash owns below", "/docs @a", "docs/x/y.md", "/docs"},
		{"star stays in segment", "/a/*.md @x", "a/b/c.md", ""},
		{"star in segment", "/a/*.md @x", "a/c.md", "/a/*.md"},
		{"dir-only double star not root file", "**/ @x", "README", ""},
		{"dir-only double star", "**/ @x", "a/b", "**/"},
		{"anchored dir-only double star not root file", "/**/ @x", "README", ""},
		{"anchored dir-only double star", "/**/ @x", "a/b", "/**/"},
		{"nested dir-only double star not level one", "docs/**/ @x", "docs/a", ""},
		{"nested dir-only double star", "docs/**/ @x", "docs/x/y", "docs/**/"},
		{"repeated dir-only double star not root file", "**/**/ @x", "README", ""},
		{"repeated dir-only double star", "**/**/ @x", "a/b", "**/**/"},
		{"dir-only double star keeps broader owner", "* @security\ndocs/**/ @docs", "docs/README.md", "*"},
		{"docs star owns that level", "docs/* @x", "docs/a.md", "docs/*"},
		{"docs star does not descend", "* @all\ndocs/* @x", "docs/sub/b.md", "*"},
		{"wildcard dir owns below", "* @all\n*.d @secure", "conf.d/x", "*.d"},
		{"question mark dir owns below", "* @all\ndoc? @x", "docs/x", "doc?"},
		{"star-suffix dir owns below", "/src/*-config @x", "src/app-config/x.yml", "/src/*-config"},
		{"dir-only wildcard owns below", "/a/*/ @x", "a/b/c", "/a/*/"},
		{"dir-only wildcard not a file", "/a/*/ @x", "a/c", ""},
		{"dir-only wildcard deep", "/a/*/ @x", "a/b/c/d", "/a/*/"},
		{"any-depth dir-only wildcard", "*/ @x", "x/y", "*/"},
		{"any-depth dir-only wildcard not top file", "*/ @x", "y", ""},
		{"trailing double star is strict", "docs/** @x", "docs", ""},
		{"trailing double star below", "docs/** @x", "docs/a/b", "docs/**"},
		{"trailing double star anchored", "docs/** @x", "a/docs/b", ""},
		{"star does not own dir contents", "/a/* @x", "a/b/c.md", ""},
		{"double star any depth", "/a/**/z.md @x", "a/b/c/z.md", "/a/**/z.md"},
		{"double star zero segments", "/a/**/z.md @x", "a/z.md", "/a/**/z.md"},
		{"trailing double star", "/a/** @x", "a/b/c", "/a/**"},
		{"leading double star", "**/logs @x", "a/b/logs/x", "**/logs"},
		{"question mark", "/f?o.txt @x", "fao.txt", "/f?o.txt"},
		{"question mark is one char", "/f?o.txt @x", "faao.txt", ""},
		{"question mark not slash", "/a?b @x", "a/b", ""},
		{"star alone", "* @x", "a/b/c", "*"},
		{"case sensitive path", "/Docs/ @x", "docs/x", ""},
		{"case sensitive path match", "/Docs/ @x", "Docs/x", "/Docs/"},
		{"last match wins", "* @a\n/x/ @b\n*.md @c", "x/r.md", "*.md"},
		{"last match wins earlier narrower", "/x/ @b\n* @a", "x/r.md", "*"},
		{"owner-less override", "* @a\n/x/", "x/r.md", "/x/"},
		{"inline comment ends owners", "/a @x # @y", "a", "/a"},
		{"tab separates", "/a\t@x", "a", "/a"},
		{"crlf", "/a @x\r\n/b @y\r\n", "b", "/b"},
		{"comment line", "# /a @x\n/b @y", "a", ""},
		{"blank lines", "\n\n  \n/b @y", "b", "/b"},
		{"indented line", "   /b @y", "b", "/b"},
		{"no trailing newline", "/b @y", "b", "/b"},
		{"empty file", "", "b", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := winner(t, mustParse(t, tc.file), tc.path); got != tc.want {
				t.Errorf("winner(%q) = %q, want %q", tc.path, got, tc.want)
			}
		})
	}
}

func TestParse_InlineCommentOwners(t *testing.T) { // CON-2
	t.Parallel()
	f := mustParse(t, "/a @x @Y #@z\n/b # nobody")
	owners, _, _ := f.Owners(t.Context(), "a")
	want := []Owner{{Kind: OwnerUser, Login: "x"}, {Kind: OwnerUser, Login: "y"}}
	if diff := cmp.Diff(want, owners); diff != "" {
		t.Errorf("owners mismatch (-want +got):\n%s", diff)
	}
	owners, rule, _ := f.Owners(t.Context(), "b")
	if len(owners) != 0 || rule.Line != 2 {
		t.Errorf("owners of b = %v rule %+v, want none from line 2", owners, rule)
	}
}

func TestParse_OwnerKinds(t *testing.T) { // CON-2
	t.Parallel()
	f := mustParse(t, "/a @Org/Team @user dev@example.com")
	owners, _, _ := f.Owners(t.Context(), "a")
	want := []Owner{
		{Kind: OwnerTeam, Org: "org", Team: "team"},
		{Kind: OwnerUser, Login: "user"},
		{Kind: OwnerEmail, Email: "dev@example.com"},
	}
	if diff := cmp.Diff(want, owners); diff != "" {
		t.Errorf("owners mismatch (-want +got):\n%s", diff)
	}
	for i, w := range []string{"@org/team", "@user", "dev@example.com"} {
		if owners[i].String() != w {
			t.Errorf("owner %d String = %q, want %q", i, owners[i], w)
		}
	}
	ws := f.Warnings()
	if len(ws) != 1 || ws[0].Line != 1 || !strings.Contains(ws[0].Message, `dev\x40example.com`) {
		t.Errorf("warnings = %+v, want one email warning on line 1", ws)
	}
}

func TestParse_SyntaxErrors(t *testing.T) { // CON-2: fail closed
	t.Parallel()
	tests := []struct{ name, file string }{
		{"negation", "!/a @x"},
		{"range", "/[a-z].go @x"},
		{"bracket", "/a[1] @x"},
		{"owner without at", "/a x"},
		{"owner empty login", "/a @"},
		{"owner bad login", "/a @-bad"},
		{"owner bad team", "/a @org/"},
		{"owner two slashes", "/a @org/t/u"},
		{"owner bad email", "/a x@y"},
		{"unknown escape", `/a\x @x`},
		{"leading escaped hash", `\#foo @x`},
		{"escaped space", `/a\ b @x`},
		{"escaped bang", `\!a @x`},
		{"escaped star", `\*a @x`},
		{"double star suffix", "foo** @x"},
		{"braces", "{a,b} @x"},
		{"escaped hash not leading", `/a\#b @x`},
		{"login too long", "/a @" + strings.Repeat("a", 40)},
		{"email second at", "/a x@y@z.io"},
		{"trailing backslash", `/a\`},
		{"empty pattern slash", "/ @x"},
		{"double star in segment", "/a**b @x"},
		{"non ascii pattern", "/café @x"},
		{"control char pattern", "/a\x1b[0m @x"},
		{"nul in pattern", "/a\x00 @x"},
		{"double trailing slash", "/a// @x"},
		{"empty segment", "/a//b @x"},
		{"dot dot", "/a/../b @x"},
		{"nbsp owner", "/a @x @y"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f, err := Parse("CODEOWNERS", []byte("/ok @fine\n"+tc.file+"\n"))
			var pe *ParseError
			if !errors.As(err, &pe) || f != nil {
				t.Fatalf("Parse = (%v, %v), want a *ParseError and no file", f, err)
			}
			if len(pe.Problems) != 1 || pe.Problems[0].Line != 2 {
				t.Errorf("problems = %+v, want exactly one, on line 2", pe.Problems)
			}
			for _, r := range pe.Error() {
				if r < 0x20 || r > 0x7e {
					t.Errorf("error text %q holds raw non-printable input", pe.Error())
					break
				}
			}
		})
	}
}

func TestParse_ReportsEveryLine(t *testing.T) { // CON-2
	t.Parallel()
	_, err := Parse("CODEOWNERS", []byte("/a @x\n!b @x\n\n/c [d] @x\n"))
	var pe *ParseError
	if !errors.As(err, &pe) {
		t.Fatalf("err = %v, want *ParseError", err)
	}
	var lines []int
	for _, p := range pe.Problems {
		lines = append(lines, p.Line)
	}
	if diff := cmp.Diff([]int{2, 4}, lines); diff != "" {
		t.Errorf("problem lines mismatch (-want +got):\n%s", diff)
	}
}

func TestParse_ProblemCap(t *testing.T) { // CON-2
	t.Parallel()
	_, err := Parse("CODEOWNERS", []byte(strings.Repeat("!x @a\n", 200)))
	var pe *ParseError
	if !errors.As(err, &pe) || len(pe.Problems) != maxProblems || !pe.Truncated {
		t.Fatalf("err = %v, want a truncated ParseError of %d problems", err, maxProblems)
	}
}

func TestParse_Login39(t *testing.T) { // CON-2
	t.Parallel()
	login := strings.Repeat("a", 39)
	f := mustParse(t, "/a @"+login)
	if o, _, _ := f.Owners(t.Context(), "a"); len(o) != 1 || o[0].Login != login {
		t.Errorf("owners = %v, want the 39-character login", o)
	}
}

func TestParse_RuleCap(t *testing.T) { // CON-2
	t.Parallel()
	rule := "/a @x\n"
	if _, err := Parse("CODEOWNERS", []byte(strings.Repeat(rule, MaxRules))); err != nil {
		t.Errorf("%d rules: %v", MaxRules, err)
	}
	_, err := Parse("CODEOWNERS", []byte("# c\n\n"+strings.Repeat(rule, MaxRules)+"# more comments\n/b @x\n"))
	var pe *ParseError
	if !errors.As(err, &pe) || len(pe.Problems) != 1 || pe.Problems[0].Line != MaxRules+4 {
		t.Errorf("err = %v, want one problem on line %d", err, MaxRules+4)
	}
}

func TestParseError_NoProblems(t *testing.T) { // CON-2
	t.Parallel()
	if s := (&ParseError{Path: "CODEOWNERS"}).Error(); s == "" {
		t.Error("empty error text")
	}
}

func TestParse_SizeCap(t *testing.T) { // CON-2
	t.Parallel()
	ok := []byte(strings.Repeat("#", MaxFileBytes-1))
	if _, err := Parse("CODEOWNERS", ok); err != nil {
		t.Errorf("a file one byte under the cap: %v", err)
	}
	_, err := Parse("CODEOWNERS", append(ok, '#'))
	var pe *ParseError
	if !errors.As(err, &pe) {
		t.Fatalf("err = %v, want *ParseError for a file of the cap size", err)
	}
}

func TestOwners_InvalidPath(t *testing.T) { // CON-2, SEC-11: never "unowned"
	t.Parallel()
	f := mustParse(t, "* @x")
	for _, p := range []string{"", "/a", "a/", "a//b", "../a", "a/./b", "a\x00b"} {
		if _, _, err := f.Owners(t.Context(), p); err == nil {
			t.Errorf("Owners(%q) succeeded, want an error", p)
		}
	}
}

func TestOwners_ReturnsCopies(t *testing.T) { // CON-2
	t.Parallel()
	f := mustParse(t, "* @x")
	o, _, _ := f.Owners(t.Context(), "a")
	o[0].Login = "evil"
	o2, _, _ := f.Owners(t.Context(), "a")
	if o2[0].Login != "x" {
		t.Errorf("mutating a result changed the file: %v", o2)
	}
}

func TestParse_CRLFRuleCap(t *testing.T) { // CON-2
	t.Parallel()
	text := strings.Repeat("/a @x\r\n", MaxRules) + "\r\n# c\r\n"
	if _, err := Parse("CODEOWNERS", []byte(text)); err != nil {
		t.Errorf("%d CRLF rules and a blank CRLF line: %v", MaxRules, err)
	}
}

func TestParse_ErrorTextEscapesMentions(t *testing.T) { // CON-2, SEC-1
	t.Parallel()
	_, err := Parse("CODEOWNERS", []byte("/a @acme/everyone!\n/b @x ##[error]\n/c ##[x] @y\n"))
	if err == nil {
		t.Fatal("Parse accepted an invalid owner")
	}
	if s := err.Error(); strings.ContainsAny(s, "@#") {
		t.Errorf("error text %q holds a raw @ or #", s)
	}
	var pe *ParseError
	if errors.As(err, &pe) {
		for _, p := range pe.Problems {
			if strings.ContainsAny(p.Message, "@#") {
				t.Errorf("problem %q holds a raw @ or #", p.Message)
			}
		}
	}
	if !strings.Contains(err.Error(), `\x40acme`) {
		t.Errorf("error text %q does not show the escaped mention", err)
	}
}

func TestParse_ErrorTextEscapesMarkdownLinks(t *testing.T) { // CON-2, SEC-1
	t.Parallel()
	_, err := Parse("CODEOWNERS", []byte("/a [Approve](https://evil.example/x)\n"))
	if err == nil {
		t.Fatal("Parse accepted an invalid owner")
	}
	if strings.ContainsAny(err.Error(), "[]()") {
		t.Errorf("error text %q holds Markdown link characters", err)
	}
}
