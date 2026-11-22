// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

package contract

import (
	"strings"
	"testing"
)

func TestEffective_CarriesInstallRevision(t *testing.T) { // RUN-1, CON-5
	t.Parallel()
	set := buildSet(t, tc{"", "paths:\n  writable: ['src/**']\n"})
	var digests []string
	for _, rev := range []string{"", otherRev, strings.Repeat("d", 64)} {
		b := testBaseline()
		b.InstallRevision = rev
		p, err := Compile(set, b, testDefaults())
		if err != nil {
			t.Fatalf("Compile(%q): %v", rev, err)
		}
		eff, err := p.Resolve([]string{"src/a.go"})
		if err != nil {
			t.Fatal(err)
		}
		if eff.InstallRevision != rev {
			t.Errorf("Effective.InstallRevision = %q, want %q", eff.InstallRevision, rev)
		}
		digests = append(digests, TrustDigest(b, testDefaults()))
	}
	if digests[0] == digests[1] || digests[1] == digests[2] || digests[0] == digests[2] {
		t.Errorf("the trust digest does not cover the install revision: %v", digests)
	}
}

func TestCompile_RejectsBadInstallRevision(t *testing.T) { // RUN-1
	t.Parallel()
	for name, rev := range map[string]string{
		"short":     "abc123",
		"uppercase": strings.ToUpper(otherRev),
		"not hex":   strings.Repeat("g", 40),
		"mid size":  strings.Repeat("a", 50),
		"newline":   otherRev + "\n",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			b := testBaseline()
			b.InstallRevision = rev
			if _, err := Compile(buildSet(t), b, testDefaults()); err == nil {
				t.Errorf("Compile accepted install revision %q", rev)
			}
		})
	}
}

func TestExplain_PrintsInstallRevision(t *testing.T) { // RUN-1, CON-13
	t.Parallel()
	b := testBaseline()
	b.InstallRevision = otherRev
	p, err := Compile(buildSet(t, tc{"", "paths:\n  writable: ['src/**']\n"}), b, testDefaults())
	if err != nil {
		t.Fatal(err)
	}
	ex, err := p.Explain("src/a.go")
	if err != nil {
		t.Fatal(err)
	}
	var text strings.Builder
	if werr := WriteExplanation(&text, ex); werr != nil {
		t.Fatal(werr)
	}
	if !strings.Contains(text.String(), `installRevision: "`+otherRev+`"`) {
		t.Errorf("text output lacks the install revision:\n%s", text.String())
	}
	data, err := ex.MarshalJSON()
	if err != nil || !strings.Contains(string(data), `"installRevision":"`+otherRev+`"`) {
		t.Errorf("JSON output lacks the install revision: %s, %v", data, err)
	}
}
