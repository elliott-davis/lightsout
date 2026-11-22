// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

package install_test

import (
	"context"
	"testing"

	"github.com/elliott-davis/lightsout/internal/authz"
)

func TestRoleSource(t *testing.T) { // SEC-6, SEC-10
	t.Parallel()
	cfg := mustParse(t, validYAML(t))
	src := cfg.RoleSource()
	target := authz.Target{Scope: authz.Scope{Kind: authz.ScopeInstall, ID: "inst-1"}}
	user := func(forge, id string) authz.Principal {
		return authz.Principal{Forge: forge, ID: id, Kind: authz.PrincipalUser}
	}
	tests := []struct {
		name string
		p    authz.Principal
		role authz.Role
		tg   authz.Target
		want bool
	}{
		{"admin is an admin", user("github", "12345"), authz.RoleAdmin, target, true},
		{"admin is not a policy approver", user("github", "12345"), authz.RolePolicyApprover, target, false},
		{"approver is an approver", user("github", "111"), authz.RolePolicyApprover, target, true},
		{"second approver", user("github", "222"), authz.RolePolicyApprover, target, true},
		{"approver is not an admin", user("github", "111"), authz.RoleAdmin, target, false},
		{"stranger", user("github", "999"), authz.RoleAdmin, target, false},
		{"same ID on another forge", user("gitlab", "12345"), authz.RoleAdmin, target, false},
		{"empty principal", authz.Principal{}, authz.RoleAdmin, target, false},
		{"a bot with an admin's ID", authz.Principal{Forge: "github", ID: "12345", Kind: authz.PrincipalBot}, authz.RoleAdmin, target, false},
		{"an app with an approver's ID", authz.Principal{Forge: "github", ID: "111", Kind: authz.PrincipalApp}, authz.RolePolicyApprover, target, false},
		{"login of an admin is no identity", authz.Principal{Forge: "github", ID: "alice", Login: "12345", Kind: authz.PrincipalUser}, authz.RoleAdmin, target, false},
		{"another installation", user("github", "12345"), authz.RoleAdmin, authz.Target{Scope: authz.Scope{Kind: authz.ScopeInstall, ID: "inst-2"}}, false},
		{"a repo scope", user("github", "12345"), authz.RoleAdmin, authz.Target{Scope: authz.Scope{Kind: authz.ScopeRepo, ID: "inst-1"}}, false},
		{"an owner role", user("github", "12345"), authz.RoleCodeOwner, target, false},
		{"the contract owner role", user("github", "111"), authz.RoleContractOwner, target, false},
		{"an unknown role", user("github", "12345"), "superuser", target, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := src.HasRole(t.Context(), tt.p, tt.role, tt.tg)
			if err != nil || got != tt.want {
				t.Errorf("HasRole = %v, %v, want %v", got, err, tt.want)
			}
		})
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if got, err := src.HasRole(ctx, user("github", "12345"), authz.RoleAdmin, target); got || err == nil {
		t.Errorf("cancelled context: %v, %v, want a denial and an error", got, err)
	}
}
