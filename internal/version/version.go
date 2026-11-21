// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

// Package version reports the build version of the binary.
package version

import "runtime/debug"

// Version is set at link time via -ldflags "-X .../internal/version.Version=...".
var Version string

// String returns the build version. When Version is unset it falls back to the
// module version or VCS revision recorded in the build info.
func String() string {
	return resolve(Version, debug.ReadBuildInfo)
}

func resolve(v string, read func() (*debug.BuildInfo, bool)) string {
	if v != "" {
		return v
	}
	info, ok := read()
	if !ok {
		return "unknown"
	}
	if mv := info.Main.Version; mv != "" && mv != "(devel)" {
		return mv
	}
	for _, s := range info.Settings {
		if s.Key == "vcs.revision" && s.Value != "" {
			return s.Value
		}
	}
	return "devel"
}
