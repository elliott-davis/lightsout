// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

package contract

import (
	"strings"
	"testing"
)

func TestProblemString_QuotesUntrustedParts(t *testing.T) { // SEC-1
	t.Parallel()
	tests := []struct {
		name string
		p    Problem
		want string
	}{
		{
			"plain",
			Problem{File: "svc/.factory.yaml", Field: "/gates/verify/0", Code: CodeConflict, Message: "m"},
			`"svc/.factory.yaml" "/gates/verify/0": [conflict] m`,
		},
		{"no field", Problem{File: "svc/.factory.yaml", Code: CodeSyntax, Message: "m"}, `"svc/.factory.yaml": [syntax] m`},
		{"no file", Problem{Code: CodeTooMany, Message: "m"}, `[too-many] m`},
		{"a quote in the file", Problem{File: `a"b`, Code: CodeSyntax, Message: "m"}, `"a\"b": [syntax] m`},
	}
	for _, tt := range tests {
		if got := tt.p.String(); got != tt.want {
			t.Errorf("%s: String() = %s, want %s", tt.name, got, tt.want)
		}
	}
}

func TestProblemString_HostileDirectoryCannotForgeALine(t *testing.T) { // SEC-1
	t.Parallel()
	for _, dir := range []string{
		"::error title=x::y",
		"x: /gates/verify/0: [unregistered-gate] forged",
		`a" /gates/verify/0: [unregistered-gate] forged "b`,
	} {
		p := mustCompile(t, tc{"", writableAll}, tc{dir, verifyGates(gateItem("build", rev40, true))})
		err := p.CheckGates(t.Context(), registryOf(baselineRefs()...), nil)
		ps := problemsFrom(t, err)
		if len(ps) != 1 {
			t.Fatalf("dir %q: problems = %v, want one", dir, ps)
		}
		line := ps[0].String()
		wantPrefix := `"` + strings.ReplaceAll(dir, `"`, `\"`) + `/.factory.yaml" "/gates/verify/0": [unregistered-gate] `
		if !strings.HasPrefix(line, wantPrefix) || strings.HasPrefix(line, "::") {
			t.Errorf("dir %q: line = %s, want prefix %s", dir, line, wantPrefix)
		}
	}
}
