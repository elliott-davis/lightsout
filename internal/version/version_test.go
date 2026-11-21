// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

package version

import (
	"runtime/debug"
	"testing"
)

func TestResolve(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		v    string
		info *debug.BuildInfo
		ok   bool
		want string
	}{
		{name: "ldflags wins", v: "1.2.3", want: "1.2.3"},
		{name: "no build info", want: "unknown"},
		{
			name: "module version",
			info: &debug.BuildInfo{Main: debug.Module{Version: "v0.1.0"}},
			ok:   true,
			want: "v0.1.0",
		},
		{
			name: "vcs revision",
			info: &debug.BuildInfo{
				Main:     debug.Module{Version: "(devel)"},
				Settings: []debug.BuildSetting{{Key: "vcs.revision", Value: "abc123"}},
			},
			ok:   true,
			want: "abc123",
		},
		{
			name: "devel",
			info: &debug.BuildInfo{Main: debug.Module{Version: "(devel)"}},
			ok:   true,
			want: "devel",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			read := func() (*debug.BuildInfo, bool) { return tt.info, tt.ok }
			if got := resolve(tt.v, read); got != tt.want {
				t.Errorf("resolve(%q) = %q, want %q", tt.v, got, tt.want)
			}
		})
	}
}

func TestStringPrefersLdflags(t *testing.T) {
	old := Version
	t.Cleanup(func() { Version = old })
	Version = "9.9.9"
	if got := String(); got != "9.9.9" {
		t.Errorf("String() = %q, want 9.9.9", got)
	}
}
