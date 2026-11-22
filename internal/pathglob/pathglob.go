// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

package pathglob

import (
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"
)

// ErrSyntax is wrapped by every error that [Compile] returns.
var ErrSyntax = errors.New("pathglob: invalid pattern")

// ErrInvalidPath is wrapped by errors from [ValidatePath] and [Pattern.Rebase].
var ErrInvalidPath = errors.New("pathglob: invalid path")

const (
	maxPatternLen = 512
	maxPathLen    = 4096
	maxEcho       = 100

	// maxSegments bounds the number of segments in a path accepted by
	// [ValidatePath], which keeps Match and Contains costs predictable.
	maxSegments = 256

	// maxSegmentLen is the longest path segment [ValidatePath] accepts, in bytes
	// (NAME_MAX). A longer name can't exist on any supported filesystem, and
	// capping it bounds the work of matching one segment.
	maxSegmentLen = 255

	// maxDoubleStars bounds how many "**" segments [Witness] instantiates
	// independently (2^n candidates).
	maxDoubleStars = 3
)

type segKind uint8

const (
	kindLiteral    segKind = iota // matches its text exactly
	kindGlob                      // contains * or ?
	kindDoubleStar                // "**": zero or more whole segments
)

type segment struct {
	kind segKind
	text string
}

// Pattern is a compiled, immutable path glob. The zero value matches nothing.
type Pattern struct {
	segments []segment
	runes    int // total runes of the segment texts
}

func countRunes(segs []segment) int {
	n := 0
	for _, s := range segs {
		n += utf8.RuneCountInString(s.text)
	}
	return n
}

func echo(s string) string {
	if len(s) > maxEcho {
		s = s[:maxEcho] + "..."
	}
	// A "#" is escaped so that no "##[" workflow command can reach a CI log.
	return strings.ReplaceAll(fmt.Sprintf("%q", s), "#", `\x23`)
}

// printableASCII reports whether s holds only bytes 0x20 through 0x7e. In v1
// patterns are printable ASCII: invisible or lookalike characters (bidi
// overrides, zero-width characters, Cyrillic homoglyphs) could mislead an
// approver, and a portable schema regex needs it.
func printableASCII(s string) bool {
	for i := range len(s) {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

// Compile parses a pattern. Errors wrap [ErrSyntax].
func Compile(pattern string) (Pattern, error) {
	syn := func(why string) (Pattern, error) {
		return Pattern{}, fmt.Errorf("%w: %s: %s", ErrSyntax, echo(pattern), why)
	}
	switch {
	case pattern == "":
		return syn("empty pattern")
	case len(pattern) > maxPatternLen:
		return syn("pattern too long")
	case !printableASCII(pattern):
		return syn("only printable ASCII is allowed")
	case strings.ContainsAny(pattern, `\[]{}`):
		return syn(`unsupported character (one of \ [ ] { })`)
	case pattern[0] == '/':
		return syn("leading slash")
	case pattern[len(pattern)-1] == '/':
		return syn("trailing slash")
	}
	var segs []segment
	for _, s := range strings.Split(pattern, "/") {
		switch {
		case s == "":
			return syn("empty segment")
		case s == "." || s == "..":
			return syn(`"." and ".." segments are not allowed`)
		case s == "**":
			if n := len(segs); n > 0 && segs[n-1].kind == kindDoubleStar {
				continue
			}
			segs = append(segs, segment{kind: kindDoubleStar, text: s})
		case strings.Contains(s, "**"):
			return syn(`"**" must be an entire segment`)
		case strings.ContainsAny(s, "*?"):
			segs = append(segs, segment{kind: kindGlob, text: s})
		default:
			segs = append(segs, segment{kind: kindLiteral, text: s})
		}
	}
	return Pattern{segments: segs, runes: countRunes(segs)}, nil
}

// ValidatePath reports whether p is a valid repository-relative path. Errors
// wrap [ErrInvalidPath]. Wildcard characters are allowed in paths. A path is
// limited to 4096 bytes and 256 segments, and a segment to 255 bytes.
func ValidatePath(p string) error {
	bad := func(why string) error {
		return fmt.Errorf("%w: %s: %s", ErrInvalidPath, echo(p), why)
	}
	switch {
	case p == "":
		return bad("empty path")
	case len(p) > maxPathLen:
		return bad("path too long")
	case !utf8.ValidString(p):
		return bad("not valid UTF-8")
	case strings.IndexByte(p, 0) >= 0:
		return bad("NUL byte")
	case p[0] == '/':
		return bad("leading slash")
	case p[len(p)-1] == '/':
		return bad("trailing slash")
	}
	segs := strings.Split(p, "/")
	if len(segs) > maxSegments {
		return bad("too many segments")
	}
	for _, s := range segs {
		switch s {
		case "":
			return bad("empty segment")
		case ".", "..":
			return bad(`"." and ".." segments are not allowed`)
		}
		if len(s) > maxSegmentLen {
			return bad("segment too long")
		}
	}
	return nil
}

// String returns the repo-relative display form of the pattern.
//
// The output is for display only and must never be passed back to [Compile]:
// literal segments that came from [Pattern.Rebase] are printed unescaped, so
// a directory named "*" is indistinguishable from a wildcard segment.
func (p Pattern) String() string {
	parts := make([]string, len(p.segments))
	for i, s := range p.segments {
		parts[i] = s.text
	}
	return strings.Join(parts, "/")
}

// Match reports whether path is matched by the pattern. It returns false for
// invalid paths, which is the wrong answer for a deny list. Callers evaluating
// deny lists MUST call [ValidatePath] first and treat an invalid path as an
// error, not as "no match".
func (p Pattern) Match(path string) bool {
	if ValidatePath(path) != nil {
		return false
	}
	parts := strings.Split(path, "/")
	segs := p.segments
	memo := newMemo(len(segs), len(parts))
	var rec func(i, j int) bool
	rec = func(i, j int) bool {
		if i == len(segs) {
			return j == len(parts)
		}
		return memo.do(i, j, func() bool {
			s := segs[i]
			if s.kind == kindDoubleStar {
				return rec(i+1, j) || (j < len(parts) && rec(i, j+1))
			}
			return j < len(parts) && segMatch(s, parts[j]) && rec(i+1, j+1)
		})
	}
	return rec(0, 0)
}

// Runes returns the total number of runes in the pattern's segments. Matching
// costs at most (Runes()+1) times (path runes+1) steps, so consumers use it to
// bound the work they allow.
func (p Pattern) Runes() int { return p.runes }

// Segments returns the number of segments in the compiled pattern. Consumers
// use it to bound the cost of Match and Contains, which grow with it.
func (p Pattern) Segments() int { return len(p.segments) }

// WithDescendants returns a pattern that matches whatever p matches and every
// path below a path p matches. A trailing "**" matches zero or more segments,
// so appending one gives exactly "p, or any descendant of a p-match". It is
// built from the compiled segments, not by compiling text, so it works for a
// pattern of any length. The zero Pattern matches nothing and stays that way.
func (p Pattern) WithDescendants() Pattern {
	if len(p.segments) == 0 {
		return p
	}
	if p.segments[len(p.segments)-1].kind == kindDoubleStar {
		return p
	}
	segs := make([]segment, 0, len(p.segments)+1)
	segs = append(segs, p.segments...)
	segs = append(segs, segment{kind: kindDoubleStar, text: "**"})
	return Pattern{segments: segs, runes: p.runes + 2}
}

// Rebase prefixes the pattern with the segments of dir, which are always
// literal. dir "" means the repository root and returns p unchanged.
func (p Pattern) Rebase(dir string) (Pattern, error) {
	if dir == "" {
		return p, nil
	}
	if err := ValidatePath(dir); err != nil {
		return Pattern{}, fmt.Errorf("rebase pattern %s: %w", echo(p.String()), err)
	}
	parts := strings.Split(dir, "/")
	segs := make([]segment, 0, len(parts)+len(p.segments))
	for _, d := range parts {
		segs = append(segs, segment{kind: kindLiteral, text: d})
	}
	segs = append(segs, p.segments...)
	return Pattern{segments: segs, runes: countRunes(segs)}, nil
}

// memo caches boolean results for (i, j) index pairs.
type memo struct {
	cols int
	vals []int8 // 0 unknown, 1 true, 2 false
}

func newMemo(rows, cols int) *memo {
	return &memo{cols: cols + 1, vals: make([]int8, (rows+1)*(cols+1))}
}

func (m *memo) do(i, j int, f func() bool) bool {
	k := i*m.cols + j
	switch m.vals[k] {
	case 1:
		return true
	case 2:
		return false
	}
	r := f()
	if r {
		m.vals[k] = 1
	} else {
		m.vals[k] = 2
	}
	return r
}

func segMatch(s segment, text string) bool {
	if s.kind == kindLiteral {
		return s.text == text
	}
	return globMatch(s.text, text)
}

// globMatch matches a single-segment glob with * and ? against text.
func globMatch(pat, text string) bool {
	p, t := []rune(pat), []rune(text)
	pi, ti := 0, 0
	star, mark := -1, 0
	for ti < len(t) {
		switch {
		case pi < len(p) && p[pi] == '*':
			star, mark = pi, ti
			pi++
		case pi < len(p) && (p[pi] == '?' || p[pi] == t[ti]):
			pi++
			ti++
		case star >= 0:
			mark++
			ti = mark
			pi = star + 1
		default:
			return false
		}
	}
	for pi < len(p) && p[pi] == '*' {
		pi++
	}
	return pi == len(p)
}

// Contains reports whether every path matched by inner is matched by outer.
//
// The proof is conservative: true means contained, but false only means "not
// proven". Some contained pairs (for example outer "*.go" and inner "?*.go")
// are reported as false. Callers must treat false as a failure to prove.
func Contains(outer, inner Pattern) bool {
	o, n := outer.segments, inner.segments
	m := newMemo(len(o), len(n))
	var rec func(i, j int) bool
	rec = func(i, j int) bool {
		if i == len(o) {
			return j == len(n)
		}
		return m.do(i, j, func() bool {
			if o[i].kind == kindDoubleStar {
				return rec(i+1, j) || (j < len(n) && rec(i, j+1))
			}
			if j >= len(n) || n[j].kind == kindDoubleStar {
				return false
			}
			return segContains(o[i], n[j]) && rec(i+1, j+1)
		})
	}
	return rec(0, 0)
}

// segContains proves that every text matched by n is matched by o, where
// neither is a doublestar.
func segContains(o, n segment) bool {
	switch {
	case n.kind == kindLiteral:
		return segMatch(o, n.text)
	case o.kind == kindGlob && o.text == "*":
		return true
	case o.kind == kindGlob && n.kind == kindGlob:
		return o.text == n.text
	}
	return false
}

// Witness looks for a concrete valid path matched by inner but not by outer,
// trying a small bounded set of candidates. It returns ("", false) when none
// works, which does not mean that inner is contained in outer.
func Witness(outer, inner Pattern) (string, bool) {
	var dsCount int
	for _, s := range inner.segments {
		if s.kind == kindDoubleStar {
			dsCount++
		}
	}
	dsCount = min(dsCount, maxDoubleStars)
	for mask := (1 << dsCount) - 1; mask >= 0; mask-- {
		for _, fill := range []string{"x", ""} {
			c, ok := instantiate(inner.segments, mask, fill)
			if ok && inner.Match(c) && !outer.Match(c) {
				return c, true
			}
		}
	}
	return "", false
}

// instantiate builds a candidate path. Bit k of mask selects whether the k-th
// doublestar becomes one segment "x" (set) or zero segments (clear).
func instantiate(segs []segment, mask int, star string) (string, bool) {
	var parts []string
	ds := 0
	for _, s := range segs {
		switch s.kind {
		case kindLiteral:
			parts = append(parts, s.text)
		case kindDoubleStar:
			if ds < maxDoubleStars && mask&(1<<ds) != 0 {
				parts = append(parts, "x")
			}
			ds++
		case kindGlob:
			part := strings.NewReplacer("*", star, "?", "x").Replace(s.text)
			if part == "" {
				return "", false
			}
			parts = append(parts, part)
		}
	}
	p := strings.Join(parts, "/")
	return p, ValidatePath(p) == nil
}
