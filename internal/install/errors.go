// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

package install

import (
	"cmp"
	"fmt"
	"slices"
	"strings"

	"github.com/elliott-davis/lightsout/internal/yamlsafe"
)

// maxProblems is the most problems one ValidationError reports, including the "omitted" note.
const maxProblems = 100

// Code classifies a Problem. It is an open string type. The first five values equal the contract package's
// codes of the same meaning.
type Code string

// Problem codes.
const (
	CodeSyntax       Code = "syntax"
	CodeUnsafeYAML   Code = "unsafe-yaml"
	CodeTooLarge     Code = "too-large"
	CodeSchema       Code = "schema"
	CodeUnknownField Code = "unknown-field"
	CodeTooMany      Code = "too-many"
	// CodeInvalid marks a value that passed the schema but breaks a rule.
	CodeInvalid Code = "invalid"
	// CodeDuplicate marks a value that must be unique and is not.
	CodeDuplicate Code = "duplicate"
	// CodeMissing marks something that must be present and is not.
	CodeMissing Code = "missing"
	// CodeUnregisteredGate marks a baseline gate that the gate registry does not list (CON-4).
	CodeUnregisteredGate Code = "unregistered-gate"
	// CodeUnsafeRole marks a role that could combine untrusted input, secrets and open egress (SEC-1, RUN-4).
	CodeUnsafeRole Code = "unsafe-role"
	// CodeUnknownRole marks a reference to a role that is not enabled.
	CodeUnknownRole Code = "unknown-role"
	// CodeBaseline marks a baseline that contract's own validation rejects.
	CodeBaseline Code = "baseline"
)

// Problem is one validation finding. Field and Message are escaped and bounded: they carry untrusted keys.
type Problem struct {
	Field   string // JSON pointer of the offending value, if any
	Code    Code
	Message string
}

// String renders the problem as `"field": [code] message`, with an empty Field left out. Field is quoted so that
// attacker text cannot pass for the code.
func (p Problem) String() string {
	if p.Field == "" {
		return fmt.Sprintf("[%s] %s", p.Code, p.Message)
	}
	return `"` + strings.ReplaceAll(p.Field, `"`, `\"`) + fmt.Sprintf(`": [%s] %s`, p.Code, p.Message)
}

// ValidationError carries every problem found. Callers branch on Problem.Code with errors.As.
type ValidationError struct {
	Problems []Problem
}

// Error summarizes the first problem and the total count.
func (e *ValidationError) Error() string {
	switch len(e.Problems) {
	case 0:
		return "install config validation failed"
	case 1:
		return e.Problems[0].String()
	default:
		return fmt.Sprintf("%s (and %d more problems)", e.Problems[0], len(e.Problems)-1)
	}
}

// newValidationError sorts the problems by Field, Code and Message and keeps at most maxProblems: the first
// maxProblems-1 and a final note of how many were omitted.
func newValidationError(problems []Problem) *ValidationError {
	slices.SortStableFunc(problems, func(a, b Problem) int {
		return cmp.Or(cmp.Compare(a.Field, b.Field), cmp.Compare(a.Code, b.Code), cmp.Compare(a.Message, b.Message))
	})
	problems = slices.CompactFunc(problems, func(a, b Problem) bool { return a == b })
	if len(problems) > maxProblems {
		omitted := len(problems) - (maxProblems - 1)
		problems = append(problems[:maxProblems-1:maxProblems-1], Problem{
			Code:    CodeTooMany,
			Message: fmt.Sprintf("%d more problems omitted", omitted),
		})
	}
	return &ValidationError{Problems: problems}
}

// collector gathers problems with escaped fields and messages.
type collector struct {
	problems []Problem
}

// addf records a problem at the pointer made of parts. The message is built from format and args; untrusted
// values in args must go through q first.
func (c *collector) addf(code Code, parts []string, format string, args ...any) {
	c.problems = append(c.problems, Problem{
		Field:   yamlsafe.Pointer(parts),
		Code:    code,
		Message: yamlsafe.Sanitize(fmt.Sprintf(format, args...)),
	})
}

// q renders untrusted text for a message.
func q(s string) string { return yamlsafe.Quote(s) }

// at builds pointer parts.
func at(parts ...string) []string { return parts }
