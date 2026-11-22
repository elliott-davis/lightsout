// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

package install_test

import (
	"flag"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/elliott-davis/lightsout/internal/contract"
	"github.com/elliott-davis/lightsout/internal/install"
	"github.com/elliott-davis/lightsout/internal/install/installtest"
)

var update = flag.Bool("update", false, "rewrite the qualifier key and qualification digests of testdata/valid.yaml")

const validPath = "testdata/valid.yaml"

// fixtureRoles are the roles of testdata/valid.yaml in file order.
var fixtureRoles = []string{"coder", "pr-reviewer", "security-reviewer", "payments-specialist"}

func qualifier() *installtest.Signer { return installtest.NewSigner("q1", "fixture") }

func validYAML(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(validPath)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func mustParse(t *testing.T, doc string) *install.Config {
	t.Helper()
	cfg, err := install.Parse([]byte(doc))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return cfg
}

// replaceOnce replaces the one occurrence of old in doc, failing if there is not exactly one.
func replaceOnce(t *testing.T, doc, old, repl string) string {
	t.Helper()
	if n := strings.Count(doc, old); n != 1 {
		t.Fatalf("%q occurs %d times in the fixture, want 1", old, n)
	}
	return strings.Replace(doc, old, repl, 1)
}

var (
	qualLine = regexp.MustCompile(`(?m)^(\s+qualification: )"[^"]*"`)
	keyLine  = regexp.MustCompile(`(?m)(\{ id: q1, key: )"[^"]*"`)
)

// TestFixture_IsCurrent keeps testdata/valid.yaml's qualifier key and qualification digests in step with the
// profiles in it: a fixture whose records are stale would make every admission test fail for the wrong reason.
// Run with -update after changing a profile.
func TestFixture_IsCurrent(t *testing.T) { // NFR-2
	doc := validYAML(t)
	cfg := mustParse(t, doc)
	want := map[string]string{}
	for _, role := range fixtureRoles {
		profile, ok := cfg.Role(role)
		if !ok {
			t.Fatalf("fixture lacks role %s", role)
		}
		_, digest := installtest.Encode(qualifier().Record(profile.TupleDigest(), install.ResultPass))
		want[role] = digest
	}
	if *update {
		i := 0
		doc = qualLine.ReplaceAllStringFunc(doc, func(m string) string {
			sub := qualLine.FindStringSubmatch(m)
			role := fixtureRoles[i]
			i++
			return sub[1] + `"` + want[role] + `"`
		})
		doc = keyLine.ReplaceAllString(doc, `${1}"`+qualifier().PublicKey()+`"`)
		if err := os.WriteFile(validPath, []byte(doc), 0o600); err != nil {
			t.Fatal(err)
		}
		cfg = mustParse(t, doc)
	}
	for _, role := range fixtureRoles {
		profile, _ := cfg.Role(role)
		if profile.Qualification != want[role] {
			t.Errorf("role %s: qualification is %s, want %s (run go test ./internal/install -run Fixture -update)", role, profile.Qualification, want[role])
		}
	}
	if !strings.Contains(doc, qualifier().PublicKey()) {
		t.Errorf("the fixture does not list the fixture signer's key (run with -update)")
	}
}

// fixtureRevision is the install revision baselineOf gives a config that has none.
const fixtureRevision = "d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4"

// baselineOf returns cfg's baseline, giving a config without an install revision fixtureRevision first.
func baselineOf(t *testing.T, cfg *install.Config) contract.Baseline {
	t.Helper()
	if cfg.Revision() == "" {
		var err error
		if cfg, err = cfg.WithRevision(fixtureRevision); err != nil {
			t.Fatal(err)
		}
	}
	b, err := cfg.Baseline()
	if err != nil {
		t.Fatal(err)
	}
	return b
}
