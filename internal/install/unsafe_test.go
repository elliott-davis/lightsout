// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

package install_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/elliott-davis/lightsout/internal/contract"
	"github.com/elliott-davis/lightsout/internal/install"
)

// TestUnsafeYAML_BothEntryPoints feeds the same hostile bytes to contract parsing and install parsing. Both use
// internal/yamlsafe, so both must refuse them for the same reason, before any schema is consulted (SEC-1, CON-11).
func TestUnsafeYAML_BothEntryPoints(t *testing.T) { // SEC-1, CON-11
	t.Parallel()
	head := "apiVersion: factory/v1alpha1\nkind: Thing\n"
	deep := head + "x: " + strings.Repeat("[", 20) + strings.Repeat("]", 20) + "\n"
	tests := map[string]struct {
		in   string
		code string
	}{
		"anchor":           {head + "x: &a [1]\n", "unsafe-yaml"},
		"alias":            {head + "x: &a [1]\ny: *a\n", "unsafe-yaml"},
		"custom tag":       {head + "x: !custom 1\n", "unsafe-yaml"},
		"binary tag":       {head + "x: !!binary aGk=\n", "unsafe-yaml"},
		"timestamp":        {head + "x: 2001-12-14\n", "unsafe-yaml"},
		"merge key":        {head + "x: {<<: {a: 1}}\n", "unsafe-yaml"},
		"duplicate key":    {head + "x: 1\nx: 2\n", "unsafe-yaml"},
		"nested dup":       {head + "x: {a: 1, a: 2}\n", "unsafe-yaml"},
		"multiple docs":    {head + "---\n" + head, "unsafe-yaml"},
		"non-string key":   {head + "1: x\n", "unsafe-yaml"},
		"too deep":         {deep, "unsafe-yaml"},
		"utf-8 bom":        {"\xef\xbb\xbf" + head, "unsafe-yaml"},
		"utf-16 bom":       {"\xff\xfea\x00", "unsafe-yaml"},
		"nul byte":         {head + "x: 1\x00\n", "unsafe-yaml"},
		"invalid utf-8":    {head + "# \xff\n", "unsafe-yaml"},
		"too large":        {"# " + strings.Repeat("x", install.MaxFileSize), "too-large"},
		"empty":            {"", "syntax"},
		"syntax":           {"a: [", "syntax"},
		"float":            {head + "x: 1.5\n", "schema"},
		"hex int":          {head + "x: 0x10\n", "schema"},
		"top-level list":   {"- a\n", "schema"},
		"top-level scalar": {"hello\n", "schema"},
	}
	parser, err := contract.NewParser()
	if err != nil {
		t.Fatal(err)
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, ierr := install.Parse([]byte(tt.in))
			var iv *install.ValidationError
			if !errors.As(ierr, &iv) || len(iv.Problems) == 0 || string(iv.Problems[0].Code) != tt.code {
				t.Errorf("install.Parse: %v, want a first problem with code %s", ierr, tt.code)
			}
			if tt.code == "too-large" {
				// The contract's cap is lower, so the same bytes are too large there too.
				return
			}
			_, cerr := parser.Parse("", []byte(tt.in))
			var cv *contract.ValidationError
			if !errors.As(cerr, &cv) || len(cv.Problems) == 0 || string(cv.Problems[0].Code) != tt.code {
				t.Errorf("contract.Parse: %v, want a first problem with code %s", cerr, tt.code)
			}
			if iv != nil && cv != nil && len(iv.Problems) > 0 && len(cv.Problems) > 0 {
				if iv.Problems[0].Field != cv.Problems[0].Field {
					t.Errorf("the entry points disagree on the field: install %q, contract %q", iv.Problems[0].Field, cv.Problems[0].Field)
				}
			}
		})
	}
	// The contract parser also refuses its (lower) size cap.
	big := []byte("# " + strings.Repeat("x", contract.MaxFileSize))
	if _, err := parser.Parse("", big); err == nil {
		t.Error("contract.Parse accepted an oversized file")
	}
}

func TestParse_UnknownFieldAnywhere(t *testing.T) { // CON-11, SEC-1
	t.Parallel()
	valid := validYAML(t)
	anchors := map[string]struct{ old, new, field string }{
		"top level":         {"kind: Install\n", "kind: Install\nextra: 1\n", "/extra"},
		"installation":      {`installation: { id: "inst-1", forge: github }`, `installation: { id: "inst-1", forge: github, region: eu }`, "/installation/region"},
		"policyApprovers":   {"  quorum: 2\n", "  quorum: 2\n  emergency: true\n", "/policyApprovers/emergency"},
		"timers":            {"  sameGateFailures: 3\n", "  sameGateFailures: 3\n  panic: 1\n", "/timers/panic"},
		"quotas":            {"  ciRunsPerPRPerHour: 6\n", "  ciRunsPerPRPerHour: 6\n  burst: 1\n", "/quotas/burst"},
		"team":              {`agentSessions: 4, ciRuns: 8 }`, `agentSessions: 4, ciRuns: 8, gpus: 1 }`, "/quotas/teams/0/gpus"},
		"default team":      {`defaultTeam: { agentSessions: 2, ciRuns: 4 }`, `defaultTeam: { agentSessions: 2, ciRuns: 4, gpus: 1 }`, "/quotas/defaultTeam/gpus"},
		"contract defaults": {`reviewBudgetLines: 300 }`, `reviewBudgetLines: 300, command: x }`, "/contractDefaults/command"},
		"baseline":          {"  union: []\n", "  union: []\n  run: x\n", "/baseline/run"},
		"baseline gate":     {"      mandatory: true\n  union", "      mandatory: true\n      command: x\n  union", "/baseline/verify/1/command"},
		"reviewers":         {"reviewers: { pr: pr-reviewer, security: security-reviewer }", "reviewers: { pr: pr-reviewer, security: security-reviewer, extra: x }", "/baseline/reviewers/extra"},
		"registry entry":    {`checkId: "unit" }`, `checkId: "unit", name: x }`, "/gateRegistry/2/name"},
		"decisions":         {"decisions: { expiry: { halt: 3600 }, ", "decisions: { quorum: 1, expiry: { halt: 3600 }, ", "/decisions/quorum"},
		"qualifier key":     {`{ id: q1, key: `, `{ id: q1, trusted: true, key: `, "/qualifierKeys/0/trusted"},
		"role":              {"    sandboxSecrets: []\n    qualification", "    sandboxSecrets: []\n    untrustedInput: false\n    qualification", "/roles/coder/untrustedInput"},
		"profile template":  {`template: { digest: "sha256:1111111111111111111111111111111111111111111111111111111111111111" }`, `template: { digest: "sha256:1111111111111111111111111111111111111111111111111111111111111111", path: x }`, "/roles/coder/profile/template/path"},
		"profile runtime": {`runtime: { image: "registry.internal/agent@sha256:2222222222222222222222222222222222222222222222222222222222222222" }
      harness: { name: claude-code, version: "2.1.0", digest: "sha256:3333333333333333333333333333333333333333333333333333333333333333" }
      model: { name: "model-a", revision: "2026-10-01" }
      endpoint: { digest: "sha256:4444444444444444444444444444444444444444444444444444444444444444" }
      tools:
        - { name: git, version: "2.47.0", permissions: ["repo:read", "branch:push-own"] }
        - { name: go`, `runtime: { image: "registry.internal/agent@sha256:2222222222222222222222222222222222222222222222222222222222222222", privileged: true }
      harness: { name: claude-code, version: "2.1.0", digest: "sha256:3333333333333333333333333333333333333333333333333333333333333333" }
      model: { name: "model-a", revision: "2026-10-01" }
      endpoint: { digest: "sha256:4444444444444444444444444444444444444444444444444444444444444444" }
      tools:
        - { name: git, version: "2.47.0", permissions: ["repo:read", "branch:push-own"] }
        - { name: go`, "/roles/coder/profile/runtime/privileged"},
		"tool": {`version: "2.47.0", permissions: ["repo:read", "branch:push-own"] }`, `version: "2.47.0", permissions: ["repo:read", "branch:push-own"], path: /usr/bin/git }`, "/roles/coder/profile/tools/0/path"},
		"egress": {`egress: { hosts: ["models.internal:443"] }
    gatewayCredentials:`, `egress: { hosts: ["models.internal:443"], allowAll: true }
    gatewayCredentials:`, "/roles/coder/egress/allowAll"},
		"credential": {`operations: ["POST /v1/messages"] }`, `operations: ["POST /v1/messages"], value: secret }`, "/roles/coder/gatewayCredentials/0/value"},
	}
	for name, a := range anchors {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if strings.Count(valid, a.old) < 1 {
				t.Fatalf("anchor %q is not in the fixture", a.old)
			}
			doc := strings.Replace(valid, a.old, a.new, 1)
			wantProblem(t, doc, install.CodeUnknownField, a.field)
		})
	}
}
