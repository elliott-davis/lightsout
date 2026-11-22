// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

package oracle_test

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/elliott-davis/lightsout/internal/contract"
	"github.com/elliott-davis/lightsout/internal/oracle"
)

func TestValidateManifest_Valid(t *testing.T) { // PIP-13
	t.Parallel()
	m, err := oracle.ValidateManifest(manifestYAML([]string{"src/checkout/**", "lib/*.go"}, all5...), observablesOf(all5))
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Cases) != 2 || len(m.Boundaries) != 5 || len(m.CoverGlobs) != 2 {
		t.Errorf("manifest = %+v", m)
	}
	for p, want := range map[string]bool{"src/checkout/a/b.go": true, "lib/x.go": true, "lib/a/x.go": false, "src/other.go": false} {
		if got := m.Covers(p); got != want {
			t.Errorf("Covers(%q) = %t, want %t", p, got, want)
		}
	}
	if (oracle.Manifest{}).Covers("src/a.go") {
		t.Error("the zero manifest covers a path")
	}
	// JSON is accepted too.
	js := `{"schema":"lightsout.oracle-cases/v1","cases":[{"id":"a","fixture":"` + fixtureA + `"}],` +
		`"boundaries":[{"name":"b","observable":"reads"}],"covers":["**"]}`
	if _, err := oracle.ValidateManifest([]byte(js), []contract.Observable{contract.ObservableReads}); err != nil {
		t.Errorf("JSON manifest: %v", err)
	}
}

func TestValidateManifest_Denials(t *testing.T) { // PIP-13
	t.Parallel()
	declared := observablesOf(all5)
	good := string(manifestYAML([]string{"src/**"}, all5...))
	cases := func(n int) string {
		var b strings.Builder
		b.WriteString("schema: lightsout.oracle-cases/v1\ncases:\n")
		for i := range n {
			fmt.Fprintf(&b, "  - {id: c%d, fixture: '%s'}\n", i, fixtureA)
		}
		b.WriteString("boundaries:\n  - {name: b, observable: reads}\ncovers: ['**']\n")
		return b.String()
	}
	bounds := func(n int) string {
		var b strings.Builder
		b.WriteString("schema: lightsout.oracle-cases/v1\ncases:\n  - {id: c, fixture: '" + fixtureA + "'}\nboundaries:\n")
		for i := range n {
			fmt.Fprintf(&b, "  - {name: b%d, observable: reads}\n", i)
		}
		b.WriteString("covers: ['**']\n")
		return b.String()
	}
	tests := []struct {
		name     string
		text     string
		declared []contract.Observable
	}{
		{"matrix over 4096", cases(4097), []contract.Observable{contract.ObservableReads}},
		{"too many boundaries", bounds(65), []contract.Observable{contract.ObservableReads}},
		{"boundary observables not the declared set", good, declared[:4]},
		{"declared has one more than the boundaries", string(manifestYAML([]string{"src/**"}, 0, 1, 2, 3)), declared},
		{"duplicate case ids", strings.Replace(good, "id: c2", "id: c1", 1), declared},
		{"duplicate boundary names", strings.Replace(good, "name: db-read", "name: http-api", 1), declared},
		{"unknown top-level field", good + "extra: 1\n", declared},
		{"unknown case field", strings.Replace(good, "{id: c1,", "{note: x, id: c1,", 1), declared},
		{"unknown boundary field", strings.Replace(good, "{name: http-api,", "{note: x, name: http-api,", 1), declared},
		{"duplicate key", good + "covers: ['**']\n", declared},
		{"wrong schema", strings.Replace(good, "oracle-cases/v1", "oracle-cases/v2", 1), declared},
		{"missing covers", strings.Split(good, "covers:")[0], declared},
		{"empty covers", strings.Split(good, "covers:")[0] + "covers: []\n", declared},
		{"bad case id", strings.Replace(good, "id: c1", "id: C1", 1), declared},
		{"case id with newline", strings.Replace(good, "id: c1", "id: \"c1\\nx\"", 1), declared},
		{"fixture without prefix", strings.Replace(good, fixtureA, strings.TrimPrefix(fixtureA, "sha256:"), 1), declared},
		{"short fixture", strings.Replace(good, fixtureA, "sha256:abc", 1), declared},
		{"unknown observable", strings.Replace(good, "observable: reads", "observable: logs", 1), declared},
		{"bad glob", strings.Replace(good, "'src/**'", "'/src/**'", 1), declared},
		{"glob with a dot-dot segment", strings.Replace(good, "'src/**'", "'../src/**'", 1), declared},
		{"no cases", "schema: lightsout.oracle-cases/v1\ncases: []\nboundaries:\n  - {name: b, observable: reads}\ncovers: ['**']\n", []contract.Observable{contract.ObservableReads}},
		{"alias", strings.Replace(good, "covers:", "x: &a ['**']\ncovers:", 1), declared},
		{"a list at the top", "- a\n", declared},
		{"not YAML", "\t: [", declared},
		{"empty", "", declared},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := oracle.ValidateManifest([]byte(tt.text), tt.declared)
			if !errors.Is(err, oracle.ErrManifest) {
				t.Errorf("err = %v, want ErrManifest", err)
			}
		})
	}
	t.Run("oversized", func(t *testing.T) {
		t.Parallel()
		_, err := oracle.ValidateManifest([]byte(good+"# "+strings.Repeat("x", oracle.MaxManifestSize)), declared)
		if !errors.Is(err, oracle.ErrManifest) {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("the largest matrix is accepted", func(t *testing.T) {
		t.Parallel()
		var b strings.Builder
		b.WriteString("schema: lightsout.oracle-cases/v1\ncases:\n")
		for i := range 4096 {
			fmt.Fprintf(&b, "  - {id: c%d, fixture: '%s'}\n", i, fixtureA)
		}
		b.WriteString("boundaries:\n  - {name: b, observable: reads}\ncovers: ['**']\n")
		if _, err := oracle.ValidateManifest([]byte(b.String()), []contract.Observable{contract.ObservableReads}); err != nil {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("errors escape input text", func(t *testing.T) {
		t.Parallel()
		_, err := oracle.ValidateManifest([]byte(strings.Replace(good, "id: c1", "id: \"c1\\n::error::x\"", 1)), declared)
		if err == nil || strings.ContainsAny(err.Error(), "\n") {
			t.Errorf("err = %q", err)
		}
	})
}

func TestDeriveConfig(t *testing.T) { // PIP-13
	t.Parallel()
	if got := oracle.DeriveConfig(defaults, nil); got != defaults {
		t.Errorf("no overrides = %s, want unchanged", got)
	}
	if got := oracle.DeriveConfig(defaults, map[string]string{}); got != defaults {
		t.Errorf("empty overrides = %s, want unchanged", got)
	}
	// Pinned: the harness reproduces this encoding byte for byte.
	const golden = "sha256:d8242196983b7d205130e6c46116a9d2e13dcdf4cad1a4bd5f4199723d50fe17"
	got := oracle.DeriveConfig(defaults, map[string]string{"new-key": "off", "a": "off"})
	if got != golden {
		t.Errorf("DeriveConfig = %s, want %s", got, golden)
	}
	distinct := map[string]string{}
	for name, ov := range map[string]map[string]string{
		"one":          {"a": "off"},
		"another key":  {"b": "off"},
		"another val":  {"a": "on"},
		"two":          {"a": "off", "b": "off"},
		"concat split": {"a": "bc"},
		"concat other": {"ab": "c"},
		"empty value":  {"a": ""},
		"empty key":    {"": "a"},
	} {
		g := oracle.DeriveConfig(defaults, ov)
		if prev, ok := distinct[g]; ok {
			t.Errorf("%s and %s derive the same config", name, prev)
		}
		distinct[g] = name
		if g == defaults {
			t.Errorf("%s derives the release defaults", name)
		}
	}
	if oracle.DeriveConfig("sha256:other", map[string]string{"a": "off"}) == oracle.DeriveConfig(defaults, map[string]string{"a": "off"}) {
		t.Error("the release defaults are not covered")
	}
	a := oracle.DeriveConfig(defaults, map[string]string{"x": "off", "y": "off", "z": "off"})
	for range 20 {
		if b := oracle.DeriveConfig(defaults, map[string]string{"z": "off", "y": "off", "x": "off"}); b != a {
			t.Fatalf("map order changes the digest: %s vs %s", a, b)
		}
	}
	if diff := cmp.Diff(true, strings.HasPrefix(a, "sha256:") && len(a) == len("sha256:")+64); diff != "" {
		t.Errorf("format: %s", a)
	}
}
