// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

package contract

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// yamlPinCorpus is every kind of input the bounded YAML pipeline must treat
// the same way before and after its move to internal/yamlsafe: the fixtures in
// testdata and a case for each branch of the walker.
func yamlPinCorpus(t *testing.T) map[string][]byte {
	t.Helper()
	c := map[string][]byte{}
	files, err := filepath.Glob(filepath.Join("testdata", "*.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		c["fixture "+filepath.Base(f)] = data
	}
	deep := head + "overrides:\n  x: " + strings.Repeat("[", 20) + strings.Repeat("]", 20) + "\n"
	deepOK := head + "overrides:\n  x: " + strings.Repeat("[", 12) + strings.Repeat("]", 12) + "\n"
	many := head + "paths:\n  writable: [" + strings.TrimSuffix(strings.Repeat("a, ", 10001), ", ") + "]\n"
	utf16le := []byte{0xFF, 0xFE}
	for _, r := range head {
		utf16le = append(utf16le, byte(r), 0)
	}
	for name, doc := range map[string]any{
		"minimal":          head,
		"alias":            head + "paths:\n  writable: &w [a]\n  readOnly: *w\n",
		"anchor only":      head + "paths:\n  writable: &w [a]\n",
		"anchor on key":    head + "&k lightsOn: true\n",
		"alias key":        head + "a: &k x\n*k : y\n",
		"merge key":        head + "overrides:\n  <<: {switchStaleDays: 3}\n",
		"quoted merge":     head + "overrides:\n  \"<<\": 3\n",
		"duplicate key":    head + "lightsOn: true\nlightsOn: false\n",
		"nested dup":       head + "gates:\n  verify: []\n  verify: []\n",
		"second doc":       head + "---\n" + head,
		"third doc":        head + "---\na: 1\n---\nb: 2\n",
		"broken second":    head + "---\na: [\n",
		"custom tag":       head + "lightsOn: !custom true\n",
		"seq tag":          head + "paths:\n  writable: !custom [a]\n",
		"map tag":          head + "overrides: !custom {a: 1}\n",
		"binary":           head + "paths:\n  writable: [!!binary aGk=]\n",
		"timestamp":        head + "paths:\n  writable: [2001-12-14]\n",
		"int key":          head + "1: x\n",
		"bool key":         head + "true: x\n",
		"null key":         head + "~: x\n",
		"complex key":      head + "? [a]\n: x\n",
		"too deep":         deep,
		"deep ok":          deepOK,
		"too many nodes":   many,
		"oversize":         []byte(head + "# " + strings.Repeat("x", MaxFileSize)),
		"empty":            nil,
		"whitespace":       []byte(" \n\t\n"),
		"comment only":     []byte("# nothing\n"),
		"broken syntax":    []byte("a: ["),
		"tab indent":       []byte("a:\n\tb: 1\n"),
		"top scalar":       []byte("hello\n"),
		"top list":         []byte("- a\n"),
		"top null":         []byte("~\n"),
		"nan float":        []byte(head + "overrides:\n  switchStaleDays: .nan\n"),
		"exponent":         []byte(head + "overrides:\n  switchStaleDays: 1e2\n"),
		"float":            []byte(head + "overrides:\n  switchStaleDays: 45.0\n"),
		"hex int":          []byte(head + "overrides:\n  switchStaleDays: 0x10\n"),
		"octal":            []byte(head + "overrides:\n  reviewBudgetLines: 0o17\n"),
		"leading zero":     []byte(head + "overrides:\n  reviewBudgetLines: 017\n"),
		"underscore":       []byte(head + "overrides:\n  reviewBudgetLines: 1_000\n"),
		"plus":             []byte(head + "overrides:\n  switchStaleDays: +5\n"),
		"negative":         []byte(head + "overrides:\n  switchStaleDays: -5\n"),
		"huge int":         []byte(head + "overrides:\n  switchStaleDays: " + strings.Repeat("9", 31) + "\n"),
		"max int digits":   []byte(head + "overrides:\n  switchStaleDays: " + strings.Repeat("9", 30) + "\n"),
		"bad bool":         []byte(head + "lightsOn: yes\n"),
		"bool":             []byte(head + "lightsOn: true\n"),
		"null value":       []byte(head + "lightsOn: ~\n"),
		"quoted number":    []byte(head + "paths:\n  writable: [\"1\", '2']\n"),
		"unicode":          []byte(head + "paths:\n  writable: [\"caf\u00e9/\u202e#x\"]\n"),
		"hash key":         []byte(head + "\"a#b\": 1\n"),
		"slash key":        []byte(head + "\"a/b~c\": 1\n"),
		"long key":         []byte(head + "\"" + strings.Repeat("k", 300) + "\": 1\n"),
		"utf8 bom":         append([]byte{0xEF, 0xBB, 0xBF}, head...),
		"utf16le bom":      utf16le,
		"utf16le no bom":   utf16le[2:],
		"utf16be bom":      []byte{0xFE, 0xFF, 0, 'a'},
		"utf32be bom":      []byte{0, 0, 0xFE, 0xFF, 0, 0, 0, 'a'},
		"nul":              []byte(head + "lightsOn: true\x00\n"),
		"invalid utf8":     []byte(head + "# \xff\xfe bad\n"),
		"flow map":         []byte(head + "overrides: {switchStaleDays: 3}\n"),
		"nested list":      []byte(head + "gates:\n  verify: [[1], [2]]\n"),
		"folded scalar":    []byte(head + "paths:\n  writable:\n    - >\n      a\n      b\n"),
		"explicit str tag": []byte(head + "paths:\n  writable: [!!str 5]\n"),
		"explicit int tag": []byte(head + "overrides:\n  switchStaleDays: !!int 5\n"),
		"set tag":          []byte(head + "x: !!set {a}\n"),
	} {
		switch v := doc.(type) {
		case string:
			c[name] = []byte(v)
		case []byte:
			c[name] = v
		}
	}
	return c
}

// TestYAMLPipeline_Pinned pins what the bounded YAML pipeline does to every
// corpus input, through Parse (so the schema and decoder see its output): the
// problems, or the canonical contract. The golden file was recorded before
// the pipeline moved to internal/yamlsafe, so a diff is a behaviour change.
func TestYAMLPipeline_Pinned(t *testing.T) {
	p := newParser(t)
	corpus := yamlPinCorpus(t)
	names := make([]string, 0, len(corpus))
	for n := range corpus {
		names = append(names, n)
	}
	slices.Sort(names)
	var b strings.Builder
	for _, n := range names {
		fmt.Fprintf(&b, "== %s\n", n)
		c, err := p.Parse("", corpus[n])
		if err != nil {
			var ve *ValidationError
			if errors.As(err, &ve) {
				for _, pr := range ve.Problems {
					fmt.Fprintf(&b, "problem %q %q %q %q\n", pr.File, pr.Field, pr.Code, pr.Message)
				}
				continue
			}
			t.Fatalf("%s: %v", n, err)
		}
		data, err := json.Marshal(c)
		if err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(&b, "ok %s\n", data)
	}
	golden := filepath.Join("testdata", "yaml_pipeline.golden")
	if *update {
		if err := os.WriteFile(golden, []byte(b.String()), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatal(err)
	}
	if string(want) != b.String() {
		t.Errorf("YAML pipeline output changed; diff the golden file (go test -run YAMLPipeline_Pinned -update)\n%s", firstDiff(string(want), b.String()))
	}
}

func firstDiff(a, b string) string {
	al, bl := strings.Split(a, "\n"), strings.Split(b, "\n")
	for i := 0; i < len(al) && i < len(bl); i++ {
		if al[i] != bl[i] {
			return fmt.Sprintf("line %d:\n- %s\n+ %s", i+1, al[i], bl[i])
		}
	}
	return fmt.Sprintf("lengths differ: %d vs %d lines", len(al), len(bl))
}
