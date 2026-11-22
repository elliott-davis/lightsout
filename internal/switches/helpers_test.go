// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

package switches

import (
	"io/fs"
	"maps"
	"slices"
	"strings"
	"testing"

	"github.com/elliott-davis/lightsout/internal/forge/gittree"
)

const (
	offFlag = `{"state":"ENABLED","variants":{"on":true,"off":false},"defaultVariant":"off"}`
	onFlag  = `{"state":"ENABLED","variants":{"on":true,"off":false},"defaultVariant":"on"}`
	schema  = `"$schema":"https://flagd.dev/schema/v0/flags.json"`
)

// flagdFile wraps flag bodies, keyed by name, in a flagd document.
func flagdFile(flags map[string]string) string {
	var parts []string
	for _, k := range slices.Sorted(maps.Keys(flags)) {
		parts = append(parts, `"`+k+`":`+flags[k])
	}
	return `{` + schema + `,"flags":{` + strings.Join(parts, ",") + `}}`
}

// manifestFile is an OpenFeature manifest with one flag.
func manifestFile(key, flagType, defaultValue string) string {
	return `{"flags":{"` + key + `":{"flagType":"` + flagType + `","defaultValue":` + defaultValue + `}}}`
}

// flagdYAML is a flagd YAML file with one flag.
func flagdYAML(key string) string {
	return "flags:\n  " + key + ":\n    state: ENABLED\n    variants:\n      on: true\n      off: false\n    defaultVariant: off\n"
}

// mkTree builds a tree. A path in links is a symlink to its target.
func mkTree(t *testing.T, files, links map[string]string) fs.FS {
	t.Helper()
	var entries []gittree.Entry
	for _, p := range slices.Sorted(maps.Keys(files)) {
		entries = append(entries, gittree.Entry{Path: p, Mode: gittree.ModeBlob, Data: []byte(files[p])})
	}
	for _, p := range slices.Sorted(maps.Keys(links)) {
		entries = append(entries, gittree.Entry{Path: p, Mode: gittree.ModeSymlink, Data: []byte(links[p])})
	}
	return mkEntries(t, entries)
}

func mkEntries(t *testing.T, entries []gittree.Entry) fs.FS {
	t.Helper()
	tree, err := gittree.New(entries, gittree.Limits{})
	if err != nil {
		t.Fatalf("build tree: %v", err)
	}
	return tree
}

func gitlink(p string) gittree.Entry {
	return gittree.Entry{Path: p, Mode: gittree.ModeGitlink, SHA: "0123456789012345678901234567890123456789"}
}

func blob(p, data string) gittree.Entry {
	return gittree.Entry{Path: p, Mode: gittree.ModeBlob, Data: []byte(data)}
}

func detectFiles(t *testing.T, files map[string]string) Set {
	t.Helper()
	set, err := Detect(t.Context(), mkTree(t, files, nil), DefaultLimits())
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	return set
}

func detectTree(t *testing.T, tree fs.FS) Set {
	t.Helper()
	set, err := Detect(t.Context(), tree, DefaultLimits())
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	return set
}

// nest returns n nested objects, the innermost holding 1.
func nest(n int) string {
	return strings.Repeat(`{"a":`, n) + `1` + strings.Repeat(`}`, n)
}

func hasCode(set Set, code Code) bool {
	return slices.ContainsFunc(set.Problems, func(p Problem) bool { return p.Code == code })
}
