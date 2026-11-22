// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

package forge

import "testing"

func TestPermission_AtLeast(t *testing.T) { // SEC-10: unknown fails closed
	t.Parallel()
	tests := []struct {
		p, min Permission
		want   bool
	}{
		{PermWrite, PermWrite, true},
		{PermAdmin, PermWrite, true},
		{PermMaintain, PermWrite, true},
		{PermTriage, PermWrite, false},
		{PermNone, PermNone, true},
		{PermNone, PermRead, false},
		{PermUnknown, PermNone, false},
		{PermUnknown, PermUnknown, false},
		{PermAdmin, PermUnknown, false},
		{Permission(99), PermWrite, false},
		{Permission(1 << 30), PermWrite, false},
		{PermWrite, Permission(99), false},
		{Permission(-1), PermNone, false},
	}
	for _, tc := range tests {
		if got := tc.p.AtLeast(tc.min); got != tc.want {
			t.Errorf("%s.AtLeast(%s) = %v, want %v", tc.p, tc.min, got, tc.want)
		}
	}
	if PermWrite.String() != "write" || PermUnknown.String() != "unknown" {
		t.Errorf("String: %s, %s", PermWrite, PermUnknown)
	}
}
