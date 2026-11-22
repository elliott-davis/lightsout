// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

package contract

import (
	"cmp"
	"fmt"
	"slices"
	"strings"

	"github.com/elliott-davis/lightsout/internal/yamlsafe"
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
	// CodeLoosening marks a child contract that loosens a safety field of an
	// ancestor or of the factory baseline (CON-5, CON-12).
	CodeLoosening Code = "loosening"
	// CodeConflict marks gate declarations that can never both pass: the same
	// identity twice in one contract, or pinned at different revisions on one stack.
	CodeConflict Code = "conflict"
	// CodeMissingWritable marks a topmost contract without paths.writable (CON-7).
	CodeMissingWritable Code = "missing-writable"
	// CodeUnknownAgent marks an agents.verify entry that is not in the agent catalog (AGD-3).
	CodeUnknownAgent Code = "unknown-agent"
)

// Problem is one validation finding.
type Problem struct {
	File    string // repo-relative contract file path, e.g. "src/.factory.yaml"
	Field   string // JSON pointer of the offending value, if any
	Code    Code
	Message string
}

// String renders the problem as `"file" "field": [code] message`, with an
// empty File or Field left out. File and Field are untrusted repo text,
// so they are quoted: a line never starts with attacker text, and a ':' or '['
// inside a directory name cannot pass for the field or the code. The text
// fields of a Problem in a ValidationError are already escaped (see display),
// so String only adds the quotes and escapes a '"' inside them.
func (p Problem) String() string {
	var b strings.Builder
	if p.File != "" {
		b.WriteString(quoteEscaped(p.File))
	}
	if p.Field != "" {
		if p.File != "" {
			b.WriteByte(' ')
		}
		b.WriteString(quoteEscaped(p.Field))
	}
	if p.File != "" || p.Field != "" {
		b.WriteString(": ")
	}
	fmt.Fprintf(&b, "[%s] %s", p.Code, p.Message)
	return b.String()
}

// quoteEscaped wraps text that display has already made printable in double
// quotes, escaping any '"' in it. (display escapes backslashes.)
func quoteEscaped(s string) string {
	return `"` + strings.ReplaceAll(s, `"`, `\"`) + `"`
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

// display makes untrusted text safe to print on one line and at most limit
// bytes long. See [yamlsafe.Escape] for the rules.
func display(s string, limit int) string { return yamlsafe.Escape(s, limit) }

// EscapeText makes untrusted text, such as an error message that carries a
// repository path, safe to print on one line: it escapes control and format
// characters, invalid UTF-8, backslashes and '#' as display does, and bounds
// the result. The CLI applies it to every error it prints.
func EscapeText(s string) string { return display(s, 8192) }

// quote renders untrusted text safely and bounded.
func quote(s string) string { return yamlsafe.Quote(s) }
