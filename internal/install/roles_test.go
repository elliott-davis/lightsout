// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

package install_test

import (
	"strings"
	"testing"

	"github.com/elliott-davis/lightsout/internal/contract"
	"github.com/elliott-davis/lightsout/internal/install"
)

// coderBlock returns the coder role's text, so a test can change it.
func coderBlock(t *testing.T, doc string) string {
	t.Helper()
	i := strings.Index(doc, "  coder:\n")
	j := strings.Index(doc, "  pr-reviewer:\n")
	if i < 0 || j < i {
		t.Fatal("fixture has no coder block")
	}
	return doc[i:j]
}

// withCoder replaces the coder's block with mutate(block).
func withCoder(t *testing.T, mutate func(block string) string) string {
	t.Helper()
	doc := validYAML(t)
	block := coderBlock(t, doc)
	return strings.Replace(doc, block, mutate(block), 1)
}

func TestRoles_UnsafeCombinationsFail(t *testing.T) { // SEC-1, RUN-4
	t.Parallel()
	tests := map[string]struct {
		mutate func(block string) string
		code   install.Code
		field  string
	}{
		"sandbox secrets": {
			func(b string) string {
				return strings.Replace(b, "sandboxSecrets: []", `sandboxSecrets: ["MODEL_API_KEY"]`, 1)
			},
			install.CodeUnsafeRole, "/roles/coder/sandboxSecrets",
		},
		"wildcard egress host": {
			func(b string) string {
				return strings.Replace(b, `egress: { hosts: ["models.internal:443"] }`, `egress: { hosts: ["*.internal:443"] }`, 1)
			},
			install.CodeSchema, "/roles/coder/egress/hosts/0",
		},
		"bare wildcard host": {
			func(b string) string {
				return strings.Replace(b, `egress: { hosts: ["models.internal:443"] }`, `egress: { hosts: ["*:443"] }`, 1)
			},
			install.CodeSchema, "/roles/coder/egress/hosts/0",
		},
		"wildcard port": {
			func(b string) string {
				return strings.Replace(b, `egress: { hosts: ["models.internal:443"] }`, `egress: { hosts: ["models.internal:*"] }`, 1)
			},
			install.CodeSchema, "/roles/coder/egress/hosts/0",
		},
		"host without a port": {
			func(b string) string {
				return strings.Replace(b, `egress: { hosts: ["models.internal:443"] }`, `egress: { hosts: ["models.internal"] }`, 1)
			},
			install.CodeSchema, "/roles/coder/egress/hosts/0",
		},
		"url instead of host": {
			func(b string) string {
				return strings.Replace(b, `egress: { hosts: ["models.internal:443"] }`, `egress: { hosts: ["https://models.internal:443/v1"] }`, 1)
			},
			install.CodeSchema, "/roles/coder/egress/hosts/0",
		},
		"cidr": {
			func(b string) string {
				return strings.Replace(b, `egress: { hosts: ["models.internal:443"] }`, `egress: { hosts: ["10.0.0.0/8:443"] }`, 1)
			},
			install.CodeSchema, "/roles/coder/egress/hosts/0",
		},
		"port out of range": {
			func(b string) string {
				return strings.Replace(b, `egress: { hosts: ["models.internal:443"] }`, `egress: { hosts: ["models.internal:70000"] }`, 1)
			},
			install.CodeUnsafeRole, "/roles/coder/egress/hosts/0",
		},
		"port zero": {
			func(b string) string {
				return strings.Replace(b, `egress: { hosts: ["models.internal:443"] }`, `egress: { hosts: ["models.internal:0"] }`, 1)
			},
			install.CodeUnsafeRole, "/roles/coder/egress/hosts/0",
		},
		"credential host not in egress": {
			func(b string) string {
				return strings.Replace(b, `host: "models.internal:443"`, `host: "other.internal:443"`, 1)
			},
			install.CodeUnsafeRole, "/roles/coder/gatewayCredentials/0/host",
		},
		"credential on another port": {
			func(b string) string {
				return strings.Replace(b, `host: "models.internal:443"`, `host: "models.internal:8443"`, 1)
			},
			install.CodeUnsafeRole, "/roles/coder/gatewayCredentials/0/host",
		},
		"credential with no egress at all": {
			func(b string) string {
				return strings.Replace(b, `egress: { hosts: ["models.internal:443"] }`, `egress: { hosts: [] }`, 1)
			},
			install.CodeUnsafeRole, "/roles/coder/gatewayCredentials/0/host",
		},
		"credential wildcard operation": {
			func(b string) string { return strings.Replace(b, `"POST /v1/messages"`, `"POST /v1/*"`, 1) },
			install.CodeSchema, "/roles/coder/gatewayCredentials/0/operations/0",
		},
		"credential without operations": {
			func(b string) string {
				return strings.Replace(b, `operations: ["POST /v1/messages"]`, `operations: []`, 1)
			},
			install.CodeSchema, "/roles/coder/gatewayCredentials/0/operations",
		},
		"credential any operation": {
			func(b string) string { return strings.Replace(b, `"POST /v1/messages"`, `"ANY"`, 1) },
			install.CodeSchema, "/roles/coder/gatewayCredentials/0/operations/0",
		},
		"declared untrustedInput false": {
			func(b string) string {
				return strings.Replace(b, "    egress:", "    untrustedInput: false\n    egress:", 1)
			},
			install.CodeUnknownField, "/roles/coder/untrustedInput",
		},
		"declared untrustedInput true": {
			func(b string) string {
				return strings.Replace(b, "    egress:", "    untrustedInput: true\n    egress:", 1)
			},
			install.CodeUnknownField, "/roles/coder/untrustedInput",
		},
		"inline secret value": {
			func(b string) string {
				return strings.Replace(b, "    egress:", "    env: { TOKEN: x }\n    egress:", 1)
			},
			install.CodeUnknownField, "/roles/coder/env",
		},
		"duplicate credential name": {
			func(b string) string {
				return strings.Replace(b, "    sandboxSecrets: []", `      - { name: model-key, host: "models.internal:443", operations: ["POST /v1/other"] }`+"\n    sandboxSecrets: []", 1)
			},
			install.CodeDuplicate, "/roles/coder/gatewayCredentials/1/name",
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			wantProblem(t, withCoder(t, tt.mutate), tt.code, tt.field)
		})
	}
	// The unmodified role is accepted: the cases above fail for the reason they name.
	mustParse(t, validYAML(t))
}

func TestRoles_ProfilesArePinned(t *testing.T) { // RUN-6, AGT-7
	t.Parallel()
	tests := map[string]struct {
		mutate func(block string) string
		code   install.Code
		field  string
	}{
		"image by tag": {
			func(b string) string {
				return strings.Replace(b, "registry.internal/agent@sha256:2222222222222222222222222222222222222222222222222222222222222222", "registry.internal/agent:latest", 1)
			},
			install.CodeSchema, "/roles/coder/profile/runtime/image",
		},
		"image by short digest": {
			func(b string) string {
				return strings.Replace(b, "@sha256:2222222222222222222222222222222222222222222222222222222222222222", "@sha256:2222", 1)
			},
			install.CodeSchema, "/roles/coder/profile/runtime/image",
		},
		"image by other algorithm": {
			func(b string) string {
				return strings.Replace(b, "@sha256:2222222222222222222222222222222222222222222222222222222222222222", "@sha512:2222222222222222222222222222222222222222222222222222222222222222", 1)
			},
			install.CodeSchema, "/roles/coder/profile/runtime/image",
		},
		"harness digest missing": {
			func(b string) string {
				return strings.Replace(b, `, digest: "sha256:3333333333333333333333333333333333333333333333333333333333333333" }`, ` }`, 1)
			},
			install.CodeSchema, "/roles/coder/profile/harness",
		},
		"harness digest not a digest": {
			func(b string) string {
				return strings.Replace(b, "sha256:3333333333333333333333333333333333333333333333333333333333333333", "latest", 1)
			},
			install.CodeSchema, "/roles/coder/profile/harness/digest",
		},
		"harness version missing": {
			func(b string) string { return strings.Replace(b, `version: "2.1.0", `, ``, 1) },
			install.CodeSchema, "/roles/coder/profile/harness",
		},
		"template digest missing": {
			func(b string) string {
				return strings.Replace(b, `      template: { digest: "sha256:1111111111111111111111111111111111111111111111111111111111111111" }`+"\n", "", 1)
			},
			install.CodeSchema, "/roles/coder/profile",
		},
		"endpoint digest missing": {
			func(b string) string {
				return strings.Replace(b, `      endpoint: { digest: "sha256:4444444444444444444444444444444444444444444444444444444444444444" }`+"\n", "", 1)
			},
			install.CodeSchema, "/roles/coder/profile",
		},
		"model revision missing": {
			func(b string) string {
				return strings.Replace(b, `model: { name: "model-a", revision: "2026-10-01" }`, `model: { name: "model-a" }`, 1)
			},
			install.CodeSchema, "/roles/coder/profile/model",
		},
		"tool version missing": {
			func(b string) string { return strings.Replace(b, `version: "2.47.0", `, ``, 1) },
			install.CodeSchema, "/roles/coder/profile/tools/0",
		},
		"tool permissions missing": {
			func(b string) string {
				return strings.Replace(b, `, permissions: ["repo:read", "branch:push-own"]`, ``, 1)
			},
			install.CodeSchema, "/roles/coder/profile/tools/0",
		},
		"tool permission wildcard": {
			func(b string) string { return strings.Replace(b, `"branch:push-own"`, `"branch:*"`, 1) },
			install.CodeSchema, "/roles/coder/profile/tools/0/permissions/1",
		},
		"duplicate tool": {
			func(b string) string {
				return strings.Replace(b, `        - { name: go,`, `        - { name: git, version: "2.0", permissions: [] }`+"\n        - { name: go,", 1)
			},
			install.CodeDuplicate, "/roles/coder/profile/tools/1/name",
		},
		"profile missing": {
			func(b string) string {
				before, rest, _ := strings.Cut(b, "    profile:")
				_, after, _ := strings.Cut(rest, "    egress:")
				return before + "    egress:" + after
			},
			install.CodeSchema, "/roles/coder",
		},
		"qualification missing": {
			func(b string) string {
				before, _, _ := strings.Cut(b, "    qualification:")
				return before
			},
			install.CodeSchema, "/roles/coder",
		},
		"qualification not a digest": {
			func(b string) string {
				return strings.Replace(b, qualOf(t, "coder"), "qualified", 1)
			},
			install.CodeSchema, "/roles/coder/qualification",
		},
		"unknown profile field": {
			func(b string) string {
				return strings.Replace(b, "      tools:", "      command: run.sh\n      tools:", 1)
			},
			install.CodeUnknownField, "/roles/coder/profile/command",
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			wantProblem(t, withCoder(t, tt.mutate), tt.code, tt.field)
		})
	}
}

func TestRoles_NoRoles(t *testing.T) { // RUN-6
	t.Parallel()
	doc := validYAML(t)
	before, _, _ := strings.Cut(doc, "roles:\n")
	doc = before + "roles: {}\n"
	ps := problemsOf(t, doc)
	if !has(ps, install.CodeSchema, "/roles") {
		t.Errorf("problems = %v", ps)
	}
	hostile := replaceOnce(t, validYAML(t), "  coder:\n", "  Bad_Name:\n")
	wantProblem(t, hostile, install.CodeUnknownField, "/roles/Bad_Name")
}

func TestTupleDigest_ProfileIsolation(t *testing.T) { // AGT-7, RUN-6
	t.Parallel()
	valid := validYAML(t)
	base := mustParse(t, valid)
	coder, _ := base.Role("coder")
	reviewer, _ := base.Role("pr-reviewer")
	security, _ := base.Role("security-reviewer")

	changed := mustParse(t, withCoder(t, func(b string) string {
		return strings.Replace(b, `model: { name: "model-a", revision: "2026-10-01" }`, `model: { name: "model-b", revision: "2026-10-01" }`, 1)
	}))
	coder2, _ := changed.Role("coder")
	reviewer2, _ := changed.Role("pr-reviewer")
	security2, _ := changed.Role("security-reviewer")
	if coder2.TupleDigest() == coder.TupleDigest() {
		t.Error("changing the coder profile left the coder's digest unchanged")
	}
	if reviewer2.TupleDigest() != reviewer.TupleDigest() || security2.TupleDigest() != security.TupleDigest() {
		t.Error("changing the coder profile changed a reviewer profile's digest")
	}
	if reviewer.TupleDigest() == security.TupleDigest() || reviewer.TupleDigest() == coder.TupleDigest() {
		t.Error("different roles share a tuple digest")
	}
	// Two roles with identical profiles still differ by name, so a record for one never admits the other.
	renamed := reviewer
	renamed.Name = "other"
	if renamed.TupleDigest() == reviewer.TupleDigest() {
		t.Error("the role name is not part of the tuple")
	}
}

func TestRoles_BaselineSurvivesContract(t *testing.T) { // SEC-1
	t.Parallel()
	// A role named like a baseline reviewer carries the reviewer's profile and is a normal enabled role.
	cfg := mustParse(t, validYAML(t))
	r, ok := cfg.Role(baselineOf(t, cfg).SecurityReviewer)
	if !ok || r.Name != "security-reviewer" || len(r.SandboxSecrets) != 0 {
		t.Errorf("security reviewer role = %+v, %v", r, ok)
	}
	set, err := contract.NewSet(strings.Repeat("c", 40))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := contract.Compile(set, baselineOf(t, cfg), cfg.Defaults()); err != nil {
		t.Error(err)
	}
}

// qualOf returns the qualification digest of a fixture role.
func qualOf(t *testing.T, role string) string {
	t.Helper()
	r, ok := mustParse(t, validYAML(t)).Role(role)
	if !ok {
		t.Fatalf("no role %s", role)
	}
	return r.Qualification
}
