// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

package codeowners

import (
	"context"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/elliott-davis/lightsout/internal/forge"
	"github.com/elliott-davis/lightsout/internal/pathglob"
)

const (
	// MaxFileBytes is the size at which a CODEOWNERS file is rejected: GitHub ignores a file that is not under
	// 3 MB, so a file of this many bytes or more is an error here.
	MaxFileBytes = 3_000_000
	// MaxRules bounds the rules in one file. More is a [ParseError].
	MaxRules = 5000
	// Going over any of the limits below is a [ParseError]: fail closed, and bound the work of resolving a path.
	//
	// Work per path is at most (MaxFileRunes+MaxRules) * (path runes+1) elementary steps, because pathglob matching
	// costs at most (pattern runes+1) * (path runes+1) per pattern. With a path of at most 4096 bytes that is about
	// 4*10^8 steps at the very worst, and far less for any real file.

	// MaxPatternSegments bounds the segments of one pattern as written.
	MaxPatternSegments = 32
	// MaxPatternDoubleStars bounds the "**" segments of one pattern as written.
	MaxPatternDoubleStars = 3
	// MaxFileSegments bounds the compiled pattern segments of a whole file.
	MaxFileSegments = 50_000
	// MaxFileRunes bounds the compiled pattern characters of a whole file.
	MaxFileRunes = 100_000
	// MaxRuleOwners bounds the owner tokens of one rule.
	MaxRuleOwners = 50
	// MaxFileOwners bounds the owner tokens of a whole file.
	MaxFileOwners = 50_000
)

const (
	maxProblems = 50
	maxEcho     = 100
)

// OwnerKind says what an owner entry names.
type OwnerKind int

// Owner kinds. The zero value is invalid.
const (
	OwnerInvalid OwnerKind = iota
	OwnerUser              // @login
	OwnerTeam              // @org/team
	OwnerEmail             // an email address, which never grants ownership
)

// Owner is one owner of a rule. Logins, orgs and teams are stored lowercased, because GitHub compares them
// case-insensitively. An Email is stored as written.
type Owner struct {
	Kind  OwnerKind
	Login string // OwnerUser
	Org   string // OwnerTeam
	Team  string // OwnerTeam
	Email string // OwnerEmail
}

// String returns the owner in CODEOWNERS syntax.
func (o Owner) String() string {
	if o.Kind == OwnerUser {
		return "@" + o.Login
	}
	if o.Kind == OwnerTeam {
		return "@" + o.Org + "/" + o.Team
	}
	if o.Kind == OwnerEmail {
		return o.Email
	}
	return ""
}

// Rule is one CODEOWNERS line, for explanation and audit.
type Rule struct {
	Line    int    // 1-based line number, 0 when no line matched
	Pattern string // the pattern as written, after unescaping
	Owners  []Owner
}

// Warning is a non-fatal observation about a line.
type Warning struct {
	Line    int
	Message string
}

// Problem is one syntax error. Message never contains raw input: echoed text is quoted and clipped.
type Problem struct {
	Line    int
	Message string
}

// ParseError says the file is invalid. A file with any problem grants nothing.
type ParseError struct {
	Path      string
	Problems  []Problem // at most 50, in line order
	Truncated bool      // more problems existed than are listed
}

func (e *ParseError) Error() string {
	if len(e.Problems) == 0 {
		return fmt.Sprintf("codeowners: %s is invalid", echo(e.Path))
	}
	first := e.Problems[0]
	more := ""
	if len(e.Problems) > 1 || e.Truncated {
		more = fmt.Sprintf(" (and more, %d listed)", len(e.Problems))
	}
	return fmt.Sprintf("codeowners: %s is invalid: line %d: %s%s", echo(e.Path), first.Line, first.Message, more)
}

// compiled is a rule and the one pattern that decides it, which already includes whatever descent the rule has,
// so resolving a path costs one Match per rule.
type compiled struct {
	rule Rule
	pat  pathglob.Pattern
}

// File is a parsed CODEOWNERS. It is immutable.
type File struct {
	path     string
	revision string
	repo     forge.RepoID
	rules    []compiled
	warnings []Warning
}

// Path is the repository path the file was read from, or "" when there was none.
func (f *File) Path() string { return f.path }

// Repo is the repository the file was loaded from, or "" for a file made by [Parse].
func (f *File) Repo() forge.RepoID { return f.repo }

// Revision is the commit SHA the file was loaded at, or "" for a file made by [Parse].
func (f *File) Revision() string { return f.revision }

// Warnings returns what the parse noticed, such as email owners that grant nothing.
func (f *File) Warnings() []Warning { return slices.Clone(f.warnings) }

// Rules returns the parsed rules in file order.
func (f *File) Rules() []Rule {
	out := make([]Rule, len(f.rules))
	for i, r := range f.rules {
		out[i] = cloneRule(r.rule)
	}
	return out
}

func cloneRule(r Rule) Rule {
	r.Owners = slices.Clone(r.Owners)
	return r
}

// echo quotes untrusted text for a message: ASCII only, and "@" and "#" escaped so a posted error can't mention
// anyone or form a workflow command.
func echo(s string) string {
	if len(s) > maxEcho {
		s = s[:maxEcho] + "..."
	}
	return escapeText(strconv.QuoteToASCII(s))
}

// ascii is echo without the quotes.
func ascii(s string) string {
	q := echo(s)
	return q[1 : len(q)-1]
}

// escapeText hides what forges render specially in a posted message: mentions, workflow commands and Markdown links.
func escapeText(s string) string {
	return strings.NewReplacer("@", `\x40`, "#", `\x23`, "[", `\x5b`, "]", `\x5d`, "(", `\x28`, ")", `\x29`).Replace(s)
}

// escapedError wraps an error whose text may echo untrusted input, such as a bad path. It keeps the chain for
// errors.Is and escapes the text.
type escapedError struct{ err error }

func (e escapedError) Error() string {
	q := strconv.QuoteToASCII(e.err.Error())
	return escapeText(q[1 : len(q)-1])
}

func (e escapedError) Unwrap() error { return e.err }

type parser struct {
	path   string
	err    ParseError
	stop   bool // a file-wide cap was hit
	segs   int
	runes  int
	owners int
}

func (p *parser) failf(line int, format string, args ...any) {
	if len(p.err.Problems) >= maxProblems {
		p.err.Truncated = true
		return
	}
	p.err.Problems = append(p.err.Problems, Problem{Line: line, Message: fmt.Sprintf(format, args...)})
}

// Parse parses CODEOWNERS data read from path. Any syntax error returns a [*ParseError] and no file (CON-2,
// fail closed). data of [MaxFileBytes] or more is an error.
func Parse(path string, data []byte) (*File, error) {
	if len(data) >= MaxFileBytes {
		return nil, &ParseError{Path: path, Problems: []Problem{{Line: 0, Message: "file is not under 3,000,000 bytes"}}}
	}
	p := &parser{path: path, err: ParseError{Path: path}}
	f := &File{path: path}
	for i, raw := range strings.Split(string(data), "\n") {
		raw = strings.TrimSuffix(raw, "\r")
		if len(f.rules) >= MaxRules && p.moreRules(raw) {
			p.failf(i+1, "more than %d rules", MaxRules)
			break
		}
		p.line(f, i+1, raw)
		if p.stop {
			break
		}
	}
	if len(p.err.Problems) > 0 {
		return nil, &p.err
	}
	return f, nil
}

// moreRules reports whether the line would add a rule, for the cap.
func (p *parser) moreRules(raw string) bool {
	s := strings.TrimLeft(raw, " \t")
	return s != "" && s[0] != '#'
}

func isSpace(r rune) bool { return r == ' ' || r == '\t' }

func (p *parser) line(f *File, n int, s string) {
	s = strings.TrimLeft(s, " \t")
	if s == "" || s[0] == '#' {
		return
	}
	pattern, rest, ok := p.splitPattern(n, s)
	if !ok {
		return
	}
	var owners []Owner
	for _, tok := range strings.FieldsFunc(rest, isSpace) {
		if tok[0] == '#' {
			break // an inline comment
		}
		if len(owners) >= MaxRuleOwners {
			p.failf(n, "more than %d owners on one rule", MaxRuleOwners)
			return
		}
		o, err := parseOwner(tok)
		if err != "" {
			p.failf(n, "%s", err)
			return
		}
		if o.Kind == OwnerEmail {
			f.warnings = append(f.warnings, Warning{Line: n, Message: fmt.Sprintf("email owner %s grants no ownership", echo(o.Email))})
		}
		owners = append(owners, o)
	}
	c, err := compileRule(pattern)
	if err != "" {
		p.failf(n, "%s", err)
		return
	}
	p.segs += c.pat.Segments()
	p.runes += c.pat.Runes()
	p.owners += len(owners)
	if p.segs > MaxFileSegments || p.runes > MaxFileRunes || p.owners > MaxFileOwners {
		p.failf(n, "the file's patterns or owners exceed the limits (%d segments, %d characters, %d owners)",
			MaxFileSegments, MaxFileRunes, MaxFileOwners)
		p.stop = true
		return
	}
	c.rule = Rule{Line: n, Pattern: pattern, Owners: owners}
	f.rules = append(f.rules, c)
}

// splitPattern reads the pattern up to the first space or tab. Backslash escapes are refused: GitHub documents
// that escaping a leading # does not work, and the rest are undocumented, so none is guessed at.
func (p *parser) splitPattern(n int, s string) (pattern, rest string, ok bool) {
	for i := range len(s) {
		switch s[i] {
		case '\\':
			p.failf(n, "backslash escapes are not supported (%s)", echo(s[i:min(i+2, len(s))]))
			return "", "", false
		case ' ', '\t':
			return s[:i], s[i:], true
		}
	}
	return s, "", true
}

// compileRule turns a CODEOWNERS pattern into the one pathglob pattern that decides it. The message is empty on
// success. A trailing "/" means a directory and everything below it. A trailing "/**" means strict descendants
// only. A last segment of exactly "*" matches that level only, as GitHub documents for "docs/*". Anything else
// matches the path and everything below it, as in gitignore.
func compileRule(pat string) (compiled, string) {
	switch {
	case strings.HasPrefix(pat, "!"):
		return compiled{}, "negation with \"!\" is not supported by GitHub CODEOWNERS"
	case strings.ContainsAny(pat, "[]"):
		return compiled{}, "character ranges with [ ] are not supported by GitHub CODEOWNERS"
	}
	anchored := strings.HasPrefix(pat, "/")
	body := strings.TrimPrefix(pat, "/")
	dirOnly := strings.HasSuffix(body, "/")
	body = strings.TrimSuffix(body, "/")
	if body == "" {
		return compiled{}, "empty pattern " + echo(pat)
	}
	glob := body
	if !anchored && !strings.Contains(body, "/") {
		glob = "**/" + body // no slash outside a trailing one: matches at any depth
	}
	segs := strings.Split(body, "/")
	if len(segs) > MaxPatternSegments {
		return compiled{}, fmt.Sprintf("more than %d segments in a pattern", MaxPatternSegments)
	}
	if n := countDoubleStars(segs); n > MaxPatternDoubleStars {
		return compiled{}, fmt.Sprintf("more than %d \"**\" segments in a pattern", MaxPatternDoubleStars)
	}
	last := segs[len(segs)-1]
	descend := false
	switch {
	case dirOnly:
		if last == "**" {
			glob += "/*" // a directory-only "**" means at least one directory level
		}
		glob += "/*/**"
	case strings.HasSuffix(body, "/**"):
		glob = strings.TrimSuffix(glob, "/**") + "/*/**"
	default:
		descend = last != "*"
	}
	cp, err := pathglob.Compile(glob)
	if err != nil {
		return compiled{}, "invalid pattern: " + ascii(err.Error())
	}
	if descend {
		cp = cp.WithDescendants()
	}
	return compiled{pat: cp}, ""
}

// parseOwner parses one owner token. The message is empty on success.
func parseOwner(tok string) (Owner, string) {
	bad := func() (Owner, string) { return Owner{}, "invalid owner " + echo(tok) }
	if strings.HasPrefix(tok, "@") {
		name := tok[1:]
		if org, team, found := strings.Cut(name, "/"); found {
			if !validLogin(org) || !validTeam(team) {
				return bad()
			}
			return Owner{Kind: OwnerTeam, Org: strings.ToLower(org), Team: strings.ToLower(team)}, ""
		}
		if !validLogin(name) {
			return bad()
		}
		return Owner{Kind: OwnerUser, Login: strings.ToLower(name)}, ""
	}
	if validEmail(tok) {
		return Owner{Kind: OwnerEmail, Email: tok}, ""
	}
	return bad()
}

func alnum(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
}

func validLogin(s string) bool {
	if s == "" || len(s) > 39 || s[0] == '-' {
		return false
	}
	for i := range len(s) {
		if !alnum(s[i]) && s[i] != '-' {
			return false
		}
	}
	return true
}

func validTeam(s string) bool {
	if s == "" || len(s) > 100 {
		return false
	}
	for i := range len(s) {
		if !alnum(s[i]) && s[i] != '-' && s[i] != '_' && s[i] != '.' {
			return false
		}
	}
	return true
}

func validEmail(s string) bool {
	local, domain, ok := strings.Cut(s, "@")
	if !ok || local == "" || strings.Contains(domain, "@") || len(s) > 254 {
		return false
	}
	dot := strings.Index(domain, ".")
	if dot <= 0 || dot == len(domain)-1 {
		return false
	}
	for i := range len(s) {
		c := s[i]
		if c <= 0x20 || c >= 0x7f || strings.IndexByte("<>()[]\\,;:\"/", c) >= 0 {
			return false
		}
	}
	return true
}

// Owners returns the owners of path and the rule that decided it. The last matching line wins. A path no line
// matches returns no owners and the zero Rule, and a matching line with no owners returns no owners and that
// rule: both mean unowned. An invalid path is an error, never "unowned". It honors cancellation while it scans the
// rules.
func (f *File) Owners(ctx context.Context, path string) ([]Owner, Rule, error) {
	r, err := f.lookup(ctx, path, nil)
	if err != nil {
		return nil, Rule{}, err
	}
	r = cloneRule(r)
	return r.Owners, r, nil
}

// lookup returns the winning rule without cloning its owners, so callers inside the package must not modify it.
// onWork, when set, is called before each pattern match with a bound on its steps. A non-nil error stops the scan. HasRole
// uses it for its work budget, and tests use it to count work.
func (f *File) lookup(ctx context.Context, path string, onWork func(steps int) error) (Rule, error) {
	if err := pathglob.ValidatePath(path); err != nil {
		return Rule{}, fmt.Errorf("owners of path: %w", escapedError{err})
	}
	pathRunes := utf8.RuneCountInString(path)
	for i := len(f.rules) - 1; i >= 0; i-- {
		if i%256 == 0 {
			if err := ctx.Err(); err != nil {
				return Rule{}, fmt.Errorf("owners of path: %w", err)
			}
		}
		if onWork != nil {
			if err := onWork((f.rules[i].pat.Runes() + 1) * (pathRunes + 1)); err != nil {
				return Rule{}, err
			}
		}
		if f.rules[i].pat.Match(path) {
			return f.rules[i].rule, nil
		}
	}
	return Rule{}, nil
}

func countDoubleStars(segs []string) int {
	n := 0
	for _, s := range segs {
		if s == "**" {
			n++
		}
	}
	return n
}
