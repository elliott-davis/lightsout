// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

package switches

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

// recorded is a testdata/flagd-differential/*.expected.json file: what flagd core v0.19.3 loaded from the input.
type recorded struct {
	Stage string `json:"stage"`
	Flags []struct {
		Key            string         `json:"key"`
		State          string         `json:"state"`
		DefaultVariant string         `json:"defaultVariant"`
		Variants       map[string]any `json:"variants"`
		HasTargeting   bool           `json:"hasTargeting"`
	} `json:"flags"`
}

// TestEmulation_MatchesFlagd_FLG2 checks the ported load pipeline against what real flagd loaded from every file of
// the differential corpus. The expected files are recorded, never written by hand: see the README beside them.
func TestEmulation_MatchesFlagd_FLG2(t *testing.T) {
	t.Parallel()
	const dir = "testdata/flagd-differential"
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	cases := 0
	for _, e := range entries {
		name := e.Name()
		if name == "README.md" || strings.HasSuffix(name, ".expected.json") {
			continue
		}
		cases++
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			data, err := os.ReadFile(filepath.Join(dir, name))
			if err != nil {
				t.Fatal(err)
			}
			raw, err := os.ReadFile(filepath.Join(dir, name+".expected.json"))
			if err != nil {
				t.Fatalf("no recorded result: %v", err)
			}
			var want recorded
			if err := json.Unmarshal(raw, &want); err != nil {
				t.Fatal(err)
			}
			stage, got := emulateFile(data, filepath.Ext(name))
			if stage != want.Stage {
				t.Fatalf("stage = %s, flagd reached %s", stage, want.Stage)
			}
			if len(got) != len(want.Flags) {
				t.Fatalf("flags = %d, flagd served %d", len(got), len(want.Flags))
			}
			for i, w := range want.Flags {
				g := got[i]
				// Compare variants through JSON, as the recording was.
				gv, _ := json.Marshal(g.Variants)
				wv, _ := json.Marshal(w.Variants)
				if g.Key != w.Key || g.State != w.State || g.DefaultVariant != w.DefaultVariant || g.HasTargeting != w.HasTargeting || !bytes.Equal(gv, wv) {
					t.Errorf("flag %d = %+v, flagd served %+v", i, g, w)
				}
			}
		})
	}
	if cases < 80 {
		t.Errorf("the corpus has %d cases", cases)
	}
}

// TestDetect_Corpus_FLG2 runs detection over every corpus file against an empty base and checks it judges what flagd
// would serve: a file that serves a flag with variants, and is not default-off, is never a pass.
func TestDetect_Corpus_FLG2(t *testing.T) {
	t.Parallel()
	const dir = "testdata/flagd-differential"
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	empty := detectFiles(t, nil)
	for _, e := range entries {
		name := e.Name()
		if name == "README.md" || strings.HasSuffix(name, ".expected.json") {
			continue
		}
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			data, err := os.ReadFile(filepath.Join(dir, name))
			if err != nil {
				t.Fatal(err)
			}
			stage, flags := emulateFile(data, filepath.Ext(name))
			set, err := Detect(t.Context(), mkTree(t, map[string]string{"x/" + name: string(data)}, nil), DefaultLimits())
			if err != nil {
				t.Fatal(err)
			}
			got := Compare(empty, set)
			served := false
			risky := false
			for _, f := range flags {
				if len(f.Variants) > 0 {
					served = true
					on, _ := f.Variants[f.DefaultVariant].(bool)
					risky = risky || f.DefaultVariant == "" || on || f.State != "ENABLED" || f.HasTargeting
				}
			}
			switch {
			case stage == stageOK && risky && got.Verdict == VerdictPass:
				t.Errorf("flagd serves a flag that may be on, and the verdict is pass: %+v", flags)
			case stage == stageOK && served && len(set.Switches) == 0 && len(set.Problems) == 0:
				t.Errorf("flagd serves flags and none was detected")
			}
		})
	}
}

func TestEmulation_Extension_FLG2(t *testing.T) {
	t.Parallel()
	for ext, want := range map[string]string{
		".json": "json", ".JSON": "json", ".js-on": "json", ".jsoné": "json", ".jsonſ": "json", ".json٣": "json",
		".yamlé": "yaml", ".ymlß": "yml", ".y_a-m_l": "yaml", ".": "", "": "", ".txt": "txt", ".jsonx": "jsonx",
	} {
		if got := asciiExtension(ext); got != want {
			t.Errorf("asciiExtension(%q) = %q, want %q", ext, got, want)
		}
	}
}

func TestEmulation_Pipeline_FLG2(t *testing.T) {
	t.Parallel()
	good := `{"flags":{"a":` + offFlag + `}}`
	tests := []struct {
		name  string
		file  string
		ext   string
		stage string
		keys  []string
	}{
		{"json", good, ".json", stageOK, []string{"a"}},
		{"upper-case field names", `{"Flags":{"a":{"State":"ENABLED","Variants":{"on":true},"DefaultVariant":"on"}}}`, ".json", stageOK, []string{"a"}},
		{"array form", `{"flags":[{"key":"a","state":"ENABLED","variants":{"on":true}}]}`, ".json", stageOK, []string{"a"}},
		{"default variant that names nothing", `{"flags":{"a":{"state":"ENABLED","variants":{"on":true},"defaultVariant":"off"}}}`, ".json", stageLoad, nil},
		{"no flags", `{"x":1}`, ".json", stageLoad, nil},
		{"null flags", `{"flags":null}`, ".json", stageOK, nil},
		{"not json", `{`, ".json", stageLoad, nil},
		{"unsupported extension", good, ".txt", stageConvert, nil},
		{"no extension", good, "", stageConvert, nil},
		{"yaml", "flags:\n  a:\n    state: ENABLED\n    variants: {on: true}\n    defaultVariant: on\n", ".yaml", stageOK, []string{"a"}},
		{"empty yaml", "", ".yml", stageLoad, nil},
		{"broken yaml", "flags: [", ".yaml", stageConvert, nil},
		{"evaluator empty", `{"$evaluators":{"x":{}},"flags":{"a":` + offFlag + `}}`, ".json", stageLoad, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			stage, flags := emulateFile([]byte(tt.file), tt.ext)
			var keys []string
			for _, f := range flags {
				keys = append(keys, f.Key)
			}
			if stage != tt.stage || !cmp.Equal(keys, tt.keys) {
				t.Errorf("stage %s keys %v, want %s %v", stage, keys, tt.stage, tt.keys)
			}
		})
	}
}
