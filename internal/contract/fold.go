// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

package contract

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/cases"
	"golang.org/x/text/unicode/norm"

	"github.com/elliott-davis/lightsout/internal/pathglob"
)

// nForms is the number of forms of a path that deny lists are compared in.
// Form 0 is the path as given. The others make a case-insensitive or
// normalizing checkout land in the same place:
//
//	1: clean, then full case fold (Kelvin sign to k, sharp s to ss)
//	2: clean, then simple per-rune lower case (keeps "?" matching one rune)
//	3: clean, then lower(upper(s)) (dotless i behaves like it does on NTFS)
//	4: skeleton: dirKey of each segment (see dirKey)
//
// Factory checkouts are case-sensitive Linux. The folded forms defend against
// case-insensitive or normalizing checkouts elsewhere. NTFS 8.3 short names are
// not modeled.
const nForms = 5

// skeletonForm is the form whose segments are rewritten by dirKey.
const skeletonForm = 4

// transform returns form k of s. Form 0 is s itself. It is applied to whole
// paths and to contract directories alike, one segment at a time, so "/" and
// the segment structure are preserved. Forms 1 to 3 clean each segment (see
// clean) and then apply one case transformation, so a case variant that also
// carries a trailing dot or an invisible character can't slip past. A new
// Caser is made per call because a cases.Caser is stateful and not safe for
// concurrent use.
func transform(k int, s string) string {
	switch k {
	case 1:
		return perSegment(s, func(seg string) string { return norm.NFC.String(cases.Fold().String(clean(seg))) })
	case 2:
		return perSegment(s, func(seg string) string { return norm.NFC.String(strings.ToLower(clean(seg))) })
	case 3:
		return perSegment(s, func(seg string) string { return norm.NFC.String(strings.ToLower(strings.ToUpper(clean(seg)))) })
	case skeletonForm:
		return skeleton(s)
	default:
		return s
	}
}

func perSegment(s string, f func(string) string) string {
	segs := strings.Split(s, "/")
	for i, seg := range segs {
		segs[i] = f(seg)
	}
	return strings.Join(segs, "/")
}

// clean removes what a filesystem or a renderer ignores in a name: combining
// marks (NFD, drop Mn, NFC, so a precomposed letter is still one rune),
// default-ignorable code points, and trailing dots and spaces (NTFS drops them).
func clean(seg string) string {
	s := strings.Map(func(r rune) rune {
		if unicode.Is(unicode.Mn, r) || defaultIgnorable(r) {
			return -1
		}
		return r
	}, norm.NFD.String(seg))
	return norm.NFC.String(strings.TrimRight(s, ". "))
}

// skeleton returns dirKey of every segment of s, joined with "/".
func skeleton(s string) string {
	return perSegment(s, dirKey)
}

// dirKey is the canonical key of one path segment. Two segments with the same
// key are treated as the same directory: a contract at one is on the stack of
// every path below the other, and two contract directories with equal keys
// are a collision. The key over-conflates on purpose. Conflating can only add
// contracts to a stack and reject more directory pairs, and both tighten.
//
// Steps: NFC; upper then lower case; full case fold; NFD with every combining
// mark removed; every default-ignorable code point removed; trailing dots and
// spaces trimmed (NTFS drops them); NFC.
func dirKey(seg string) string {
	s := norm.NFC.String(seg)
	s = strings.ToLower(strings.ToUpper(s))
	return clean(cases.Fold().String(s))
}

// defaultIgnorable reports whether r has the Unicode property
// Default_Ignorable_Code_Point (DerivedCoreProperties.txt): code points that
// render as nothing and so can hide inside a name.
func defaultIgnorable(r rune) bool {
	switch {
	case r == 0x00AD, r == 0x034F, r == 0x061C, r == 0x3164, r == 0xFEFF, r == 0xFFA0:
		return true
	case r >= 0x115F && r <= 0x1160, r >= 0x17B4 && r <= 0x17B5, r >= 0x180B && r <= 0x180F,
		r >= 0x200B && r <= 0x200F, r >= 0x202A && r <= 0x202E, r >= 0x2060 && r <= 0x206F,
		r >= 0xFE00 && r <= 0xFE0F, r >= 0xFFF0 && r <= 0xFFF8, r >= 0x1BCA0 && r <= 0x1BCA3,
		r >= 0x1D173 && r <= 0x1D17A, r >= 0xE0000 && r <= 0xE0FFF:
		return true
	}
	return false
}

// pathForms holds the forms of one path and its dirKey per segment.
type pathForms struct {
	s     [nForms]string
	runes [nForms]int // rune count of each form
	keys  []string    // dirKey of each segment
}

// newPathForms returns the forms of path, which must already pass
// pathglob.ValidatePath. It returns an error wrapping pathglob.ErrInvalidPath
// if a form is not a valid path: folding can lengthen a path past the limit, and
// the skeleton can empty a segment. Such a path cannot be checked against a deny
// list in every form, so it is refused rather than guessed at.
func newPathForms(path string) (pathForms, error) {
	f := pathForms{}
	f.s[0], f.runes[0] = path, utf8.RuneCountInString(path)
	for k := 1; k < nForms; k++ {
		t := transform(k, path)
		if err := pathglob.ValidatePath(t); err != nil {
			return pathForms{}, fmt.Errorf("form %d of path %s: %w", k, quote(path), err)
		}
		f.s[k], f.runes[k] = t, utf8.RuneCountInString(t)
	}
	f.keys = strings.Split(f.s[skeletonForm], "/")
	return f, nil
}

// patternText returns the text of a pattern for form k: lower-cased for the
// folded forms (patterns are printable ASCII), and dirKey per segment for the
// skeleton.
func patternText(k int, text string) string {
	switch k {
	case 0:
		return text
	case skeletonForm:
		return perSegment(skeleton(text), widen)
	default:
		return perSegment(text, func(seg string) string { return widen(strings.ToLower(clean(seg))) })
	}
}

// widen turns each "?" of a pattern segment into "*" for the folded forms. Spellings a
// filesystem treats as the same name can have different rune counts (ß and ss,
// ﬁ and fi, NFC and NFD), so "?" can't be trusted to count them. Widening only
// widens what a deny pattern matches, which the design accepts. The "**"
// segment stays as it is, and a run of stars inside a segment becomes one.
func widen(seg string) string {
	if seg == "**" || !strings.Contains(seg, "?") {
		return seg
	}
	seg = strings.ReplaceAll(seg, "?", "*")
	for strings.Contains(seg, "**") {
		seg = strings.ReplaceAll(seg, "**", "*")
	}
	return seg
}

// pat is a path pattern anchored at its contract's directory, compiled for
// every form. A form's variant is dropped if it fails to compile; the exact
// variant is the only fatal one.
type pat struct {
	form    [nForms]pathglob.Pattern // the pattern itself, anchored under transform(k, dir)
	desc    [nForms]pathglob.Pattern // form[k].WithDescendants(): the pattern and everything below
	hasForm [nForms]bool
	lit     [nForms]string // leading literal segments, including the directory
	last    [nForms]string // final segment when it is a literal and the pattern does not end in "**"
	same    [nForms]bool   // form k (k > 0) is the same pattern as form 0
}

// compilePat compiles text anchored at dir. It returns the compile or rebase
// error of the exact variant.
func compilePat(text, dir string) (pat, error) {
	var p pat
	for k := range nForms {
		pt, tdir := patternText(k, text), transform(k, dir)
		g, err := pathglob.Compile(pt)
		if err == nil {
			g, err = g.Rebase(tdir)
		}
		if err != nil {
			if k == 0 {
				return pat{}, err
			}
			continue
		}
		p.form[k], p.hasForm[k] = g, true
		p.desc[k] = g.WithDescendants()
		p.lit[k] = literalPrefix(pt, tdir)
		p.last[k] = literalLast(pt)
		p.same[k] = k > 0 && pt == text && tdir == dir
	}
	return p, nil
}

// literalPrefix returns the leading segments of dir and pattern text that
// contain no wildcard. A path that a pattern matches starts with them.
func literalPrefix(text, dir string) string {
	var segs []string
	if dir != "" {
		segs = append(segs, dir)
	}
	for s := range strings.SplitSeq(text, "/") {
		if strings.ContainsAny(s, "*?") {
			break
		}
		segs = append(segs, s)
	}
	return strings.Join(segs, "/")
}

// literalLast returns the last segment of text if it has no wildcard, else "".
func literalLast(text string) string {
	last := text[strings.LastIndexByte(text, '/')+1:]
	if strings.ContainsAny(last, "*?") {
		return ""
	}
	return last
}

// prefixOK is a cheap necessary condition: form is lit or below it.
func prefixOK(form, lit string) bool {
	return lit == "" || form == lit || strings.HasPrefix(form, lit+"/")
}

// matchWork is the work, in units, charged for matching a pattern against a
// path of pathRunes runes. Matching a segment pair costs at most the product
// of their runes, and memoization visits each pair once, so (pattern runes + 1)
// times (path runes + 1) is an upper bound, and 16 covers the fixed overhead.
func matchWork(patternRunes, pathRunes int) int64 {
	return int64(patternRunes+1)*int64(pathRunes+1) + 16
}

// workBudget bounds the work one resolve may do, in the units of matchWork. It
// is not safe for concurrent use.
type workBudget struct {
	limit, spent int64
}

func (b *workBudget) over() bool { return b.spent > b.limit }

// match is p.Match(path) charged to the budget. Once the budget is over, it
// stops matching: the caller must check over() and fail.
func (b *workBudget) match(p pathglob.Pattern, path string, pathRunes int) bool {
	b.spent += matchWork(p.Runes(), pathRunes)
	if b.over() {
		return false
	}
	return p.Match(path)
}

// matchExact reports whether the pattern matches the path as written. It is
// for writable and generated lists, which have no descendant rule.
func (p *pat) matchExact(path string, f pathForms, b *workBudget) bool {
	if l := p.last[0]; l != "" && path[strings.LastIndexByte(path, '/')+1:] != l {
		return false
	}
	return b.match(p.form[0], path, f.runes[0])
}

// denies reports whether the pattern matches form k of a path or any path
// above it (the descendant rule).
func (p *pat) denies(k int, f pathForms, b *workBudget) bool {
	if !p.hasForm[k] || !prefixOK(f.s[k], p.lit[k]) {
		return false
	}
	return b.match(p.desc[k], f.s[k], f.runes[k])
}

// exactDenies reports whether a pattern denies the path as written.
func exactDenies(ps []pat, f pathForms, b *workBudget) bool {
	for i := range ps {
		if ps[i].denies(0, f, b) {
			return true
		}
	}
	return false
}

// otherDenies reports whether a pattern denies only a folded or normalized
// form of the path.
func otherDenies(ps []pat, f pathForms, b *workBudget) bool {
	for i := range ps {
		for k := 1; k < nForms; k++ {
			if ps[i].same[k] && f.s[k] == f.s[0] {
				continue // already checked as form 0
			}
			if ps[i].denies(k, f, b) {
				return true
			}
		}
	}
	return false
}

// anyDenies reports whether a pattern denies the path in any form.
func anyDenies(ps []pat, f pathForms, b *workBudget) bool {
	return exactDenies(ps, f, b) || otherDenies(ps, f, b)
}
