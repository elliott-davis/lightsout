// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

package contract

import (
	"cmp"
	"fmt"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	maxProblems   = 100                              // problems reported per ValidationError, including the "omitted" note
	maxFieldLen   = 200                              // bytes of one pointer token
	maxPathBytes  = 4096                             // longest path pathglob accepts
	maxFileLen    = maxPathBytes + len("/"+FileName) // bytes of File, so it always identifies the file
	maxMessageLen = 300                              // bytes of Message text built from untrusted input
	noLimit       = 1 << 30
)

// Code classifies a Problem. It is an open string type: later work items add codes.
type Code string

// Problem codes.
const (
	CodeSyntax       Code = "syntax"
	CodeUnsafeYAML   Code = "unsafe-yaml"
	CodeSchema       Code = "schema"
	CodeUnknownField Code = "unknown-field"
	CodeTooLarge     Code = "too-large"
	CodeMisnamed     Code = "misnamed"
	CodeSymlink      Code = "symlink"
	CodeNotRegular   Code = "not-regular-file"
	// CodeForeignTree marks a .git entry below the root: a nested repository or submodule.
	CodeForeignTree Code = "foreign-tree"
	// CodeInvalidPath marks a contract directory that is not a valid repo path.
	CodeInvalidPath Code = "invalid-path"
	// CodeInvalidPattern marks a path pattern the glob compiler rejects.
	CodeInvalidPattern Code = "invalid-pattern"
	// CodeTooMany marks an exceeded count limit, or the note that problems were omitted.
	CodeTooMany Code = "too-many"
)

// Problem is one validation finding.
type Problem struct {
	File    string // repo-relative contract file path, e.g. "src/.factory.yaml"
	Field   string // JSON pointer of the offending value, if any
	Code    Code
	Message string
}

// String renders the problem as "file: field: [code] message". The text
// fields of a Problem in a ValidationError are already escaped (see display),
// so String does not escape them again.
func (p Problem) String() string {
	var b strings.Builder
	if p.File != "" {
		b.WriteString(p.File)
		b.WriteString(": ")
	}
	if p.Field != "" {
		b.WriteString(p.Field)
		b.WriteString(": ")
	}
	fmt.Fprintf(&b, "[%s] %s", p.Code, p.Message)
	return b.String()
}

// ValidationError carries every problem found. Callers branch on Problem.Code
// with errors.As.
type ValidationError struct {
	Problems []Problem
}

// Error summarizes the first problem and the total count.
func (e *ValidationError) Error() string {
	switch len(e.Problems) {
	case 0:
		return "contract validation failed"
	case 1:
		return e.Problems[0].String()
	default:
		return fmt.Sprintf("%s (and %d more problems)", e.Problems[0], len(e.Problems)-1)
	}
}

// newValidationError makes File printable and bounded, sorts the
// problems by File, Field, Code and Message, and keeps at most maxProblems:
// the first maxProblems-1 and a final note of how many were omitted. It is the
// only place the cap is applied, so callers pass every problem they found.
func newValidationError(problems []Problem) *ValidationError {
	// Field and Message are escaped where they are built (pointer, quote,
	// sanitize). File is the raw path and is escaped here, once.
	for i := range problems {
		problems[i].File = display(problems[i].File, maxFileLen)
	}
	slices.SortStableFunc(problems, func(a, b Problem) int {
		return cmp.Or(
			cmp.Compare(a.File, b.File),
			cmp.Compare(a.Field, b.Field),
			cmp.Compare(a.Code, b.Code),
			cmp.Compare(a.Message, b.Message),
		)
	})
	if len(problems) > maxProblems {
		omitted := len(problems) - (maxProblems - 1)
		problems = append(problems[:maxProblems-1:maxProblems-1], Problem{
			Code:    CodeTooMany,
			Message: fmt.Sprintf("%d more problems omitted", omitted),
		})
	}
	return &ValidationError{Problems: problems}
}

// display makes untrusted text safe to print on one line. It escapes every
// rune that is not printable or is a format character (so newlines, escape
// sequences and bidi overrides cannot forge output) and a literal backslash
// (so the text \u000a in input cannot pass for an escaped newline). It returns
// at most limit bytes including the ellipsis that marks a cut, which falls on a
// rune boundary.
func display(s string, limit int) string {
	const marker = "\u2026"
	var b strings.Builder
	cut := 0 // longest prefix of b at a piece boundary that leaves room for the marker
	for s != "" {
		r, size := utf8.DecodeRuneInString(s)
		var piece string
		switch {
		case r == utf8.RuneError && size == 1:
			piece = fmt.Sprintf(`\x%02x`, s[0])
		case r == '\\':
			piece = `\\`
		case !unicode.IsPrint(r) || unicode.Is(unicode.Cf, r):
			if r <= 0xffff {
				piece = fmt.Sprintf(`\u%04x`, r)
			} else {
				piece = fmt.Sprintf(`\U%08x`, r)
			}
		default:
			piece = s[:size]
		}
		b.WriteString(piece)
		s = s[size:]
		if b.Len()+len(marker) <= limit {
			cut = b.Len()
		}
		if b.Len() > limit {
			return b.String()[:cut] + marker
		}
	}
	return b.String()
}

// quote renders untrusted text safely and bounded.
func quote(s string) string {
	const maxLen = 100
	if len(s) > maxLen {
		s = strings.ToValidUTF8(s[:maxLen], "") + "..."
	}
	return fmt.Sprintf("%q", s)
}
