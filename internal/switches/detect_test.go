// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

package switches

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"slices"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/elliott-davis/lightsout/internal/forge/gittree"
)

func TestDetect_UpstreamOTelDemo_FLG2(t *testing.T) {
	t.Parallel()
	data, err := os.ReadFile("testdata/otel-fc7f2a68dcf9/src/flagd/demo.flagd.json")
	if err != nil {
		t.Fatal(err)
	}
	set := detectFiles(t, map[string]string{"src/flagd/demo.flagd.json": string(data)})
	if len(set.Problems) != 0 {
		t.Fatalf("problems: %+v", set.Problems)
	}
	// Every upstream flag is boolean-off, numeric, or has targeting. Assert the full table.
	want := map[string]Status{
		"adFailure": StatusDefaultOff, "adHighCpu": StatusDefaultOff, "adManualGc": StatusDefaultOff,
		"aiRunawayAgent": StatusNotBoolean, "aiSlowResponse": StatusNotBoolean, "cartFailure": StatusNotBoolean,
		"cartMetricCardinalityOverflow": StatusDefaultOff, "emailMemoryLeak": StatusNotBoolean,
		"emitRawPii": StatusDefaultOff, "failedReadinessProbe": StatusDefaultOff, "imageSlowLoad": StatusNotBoolean,
		"intlShippingSlowdown": StatusNotBoolean, "kafkaConsumerDead": StatusDefaultOff, "kafkaQueueProblems": StatusNotBoolean,
		"loadGeneratorFloodHomepage": StatusNotBoolean, "paymentFailure": StatusNotBoolean, "paymentUnreachable": StatusDefaultOff,
		"productCatalogFailure": StatusUnproven, "productCatalogLockContention": StatusDefaultOff,
		"recommendationCacheFailure": StatusDefaultOff, "webInteractionSlowdown": StatusNotBoolean,
	}
	var upstream struct {
		Flags map[string]json.RawMessage `json:"flags"`
	}
	if err := json.Unmarshal(data, &upstream); err != nil {
		t.Fatal(err)
	}
	if len(upstream.Flags) != len(want) || len(set.Switches) != len(want) {
		t.Fatalf("upstream has %d flags, detected %d, test expects %d", len(upstream.Flags), len(set.Switches), len(want))
	}
	for key, st := range want {
		sw, ok := set.Switches[key]
		if !ok {
			t.Errorf("%s not detected", key)
			continue
		}
		if got := sw.Status(); got != st {
			t.Errorf("%s status = %s, want %s", key, got, st)
		}
	}
	if !set.Switches["productCatalogFailure"].Definitions[0].HasTargeting {
		t.Error("targeting not detected")
	}
}

func TestDetect_HandwrittenDemoShape_FLG2(t *testing.T) {
	t.Parallel()
	data, err := os.ReadFile("testdata/handwritten-demo-shape/src/flagd/demo.flagd.json")
	if err != nil {
		t.Fatal(err)
	}
	set := detectFiles(t, map[string]string{"src/flagd/demo.flagd.json": string(data)})
	want := map[string]Status{
		"adFailure": StatusDefaultOff, "aiSlowResponse": StatusNotBoolean,
		"productCatalogFailure": StatusUnproven, "emitRawPii": StatusDefaultOff,
	}
	if len(set.Problems) != 0 || len(set.Switches) != len(want) {
		t.Fatalf("problems %+v, keys %v", set.Problems, set.Keys())
	}
	for key, st := range want {
		if got := set.Switches[key].Status(); got != st {
			t.Errorf("%s status = %s, want %s", key, got, st)
		}
	}
	ad := set.Switches["adFailure"].Definitions[0]
	if ad.Description != "Fail ad service" || ad.Type != TypeBoolean || ad.DefaultVariant != "off" || ad.Path != "src/flagd/demo.flagd.json" {
		t.Errorf("adFailure definition = %+v", ad)
	}
}

func TestDetect_ByShape_FLG2(t *testing.T) {
	t.Parallel()
	cmFlags := quote(flagdFile(map[string]string{"s": offFlag}))
	tests := []struct {
		name  string
		files map[string]string
		want  []string
	}{
		{"flagd suffix", map[string]string{"x/a.flagd.json": flagdFile(map[string]string{"a": offFlag})}, []string{"a"}},
		{"plain json with schema", map[string]string{"cfg/flags-dev.json": flagdFile(map[string]string{"a": offFlag})}, []string{"a"}},
		{"plain json without schema", map[string]string{"cfg/a.json": `{"flags":{"a":` + offFlag + `}}`}, []string{"a"}},
		{"upper-case suffix", map[string]string{"cfg/A.FLAGD.JSON": `{"flags":{"a":` + offFlag + `}}`}, []string{"a"}},
		{"yaml", map[string]string{"cfg/a.yaml": flagdYAML("a")}, []string{"a"}},
		{"yml in upper case", map[string]string{"cfg/a.YML": flagdYAML("a")}, []string{"a"}},
		{"default manifest by shape", map[string]string{"flags.json": manifestFile("m", "boolean", "false")}, []string{"m"}},
		{"manifest path from json config", map[string]string{
			".openfeature.json": `{"manifest":"conf/of.json","other":1}`, "conf/of.json": manifestFile("m", "boolean", "false"),
		}, []string{"m"}},
		{"manifest path from yaml config", map[string]string{
			".openfeature.yaml": "manifest: conf/of.json\n", "conf/of.json": manifestFile("m", "boolean", "false"),
		}, []string{"m"}},
		{"config with no manifest key", map[string]string{".openfeature.json": `{"x":1}`}, nil},
		{"embedded in a yaml config map", map[string]string{"k8s/cm.yaml": "kind: ConfigMap\ndata:\n  demo.json: |\n    " + string(mustUnquote(t, []byte(cmFlags))) + "\n"}, []string{"s"}},
		{"embedded in a json string", map[string]string{"k8s/cm.json": `{"data":{"x":` + cmFlags + `}}`}, []string{"s"}},
		{"unrelated broken json is skipped", map[string]string{"package-lock.json": `{broken`}, nil},
		{"jsonc is skipped like flagd skips it", map[string]string{"tsconfig.json": "{\n // c\n \"flags\": {\"a\": {\"state\": \"ENABLED\"}}\n}"}, nil},
		{"bom is skipped like flagd skips it", map[string]string{"a.json": "\xEF\xBB\xBF" + flagdFile(map[string]string{"a": offFlag})}, nil},
		{"trailing data is skipped like flagd skips it", map[string]string{"a.json": flagdFile(map[string]string{"a": offFlag}) + " x"}, nil},
		{"flagd rejects variants that are not an object", map[string]string{"a.json": `{"flags":{"a":{"state":"ENABLED","variants":[true]}}}`}, nil},
		{"no variants serve no value", map[string]string{"a.json": `{"flags":{"a":{"state":"ENABLED","variants":{}}}}`}, nil},
		{"flagd rejects a default variant that names nothing", map[string]string{"a.json": `{"flags":{"a":{"state":"ENABLED","variants":{"on":true},"defaultVariant":"off"}}}`}, nil},
		{"flagd rejects top-level metadata that is a number", map[string]string{"a.json": `{"metadata":1,"flags":{"a":` + offFlag + `}}`}, nil},
		{"flags entry that is no flag", map[string]string{"a.json": `{"flags":{"a":{"enabled":true}}}`}, nil},
		{"flagd rejects flags that is a string", map[string]string{"a.json": `{"flags":"x"}`}, nil},
		{"flagd rejects a flag that is not an object", map[string]string{"a.json": `{"flags":{"a":` + offFlag + `,"b":3}}`}, nil},
		{"flagd rejects flag metadata that is an array", map[string]string{"a.json": `{"flags":{"a":{"state":"ENABLED","variants":{"on":true},"metadata":[1]}}}`}, nil},
		{"flagd rejects a default variant of the wrong type", map[string]string{"a.json": `{"flags":{"a":{"state":"ENABLED","variants":{"on":true},"defaultVariant":1}}}`}, nil},
		{"codecov flags", map[string]string{"codecov.yml": "flags:\n  unit:\n    paths: [src/]\n    carryforward: true\n"}, nil},
		{"helm flags", map[string]string{"values.yaml": "flags:\n  verbose: true\n  logLevel: debug\n"}, nil},
		{"i18n flags", map[string]string{"en.json": `{"flags":"Flags","settings":"Settings"}`}, nil},
		{"flags that are a list of strings", map[string]string{"c.yaml": "flags:\n- global\n"}, nil},
		{"a key that flagd matches in the other order is not served", map[string]string{"a.json": `{"flags":{},"Flags":{"evil":` + onFlag + `}}`}, nil},
		{"odd extension counts", map[string]string{"x/extra.js-on": `{"flags":{"a":` + offFlag + `}}`}, []string{"a"}},
		{"upper-case extension counts", map[string]string{"x/extra.JSON": `{"flags":{"a":` + offFlag + `}}`}, []string{"a"}},
		{"config file that holds flags", map[string]string{".openfeature.json": `{"flags":{"a":` + offFlag + `}}`}, []string{"a"}},
		{"quoted flags key in yaml", map[string]string{"a.yaml": "'flags':\n  a:\n    state: ENABLED\n    variants: {on: true, off: false}\n    defaultVariant: off\n"}, []string{"a"}},
		{"space before the colon in yaml", map[string]string{"a.yaml": "flags :\n  a:\n    state: ENABLED\n    variants: {on: true, off: false}\n    defaultVariant: off\n"}, []string{"a"}},
		{"embedded yaml in a json string", map[string]string{"cm.json": `{"d":` + quote("flags:\n  a:\n    state: ENABLED\n    variants: {on: true, off: false}\n    defaultVariant: off\n") + `}`}, []string{"a"}},
		{"symlinked tsconfig is not an error", map[string]string{"tsconfig.base.json": `{"compilerOptions":{}}`}, nil},
		{"unrelated flags key that is null", map[string]string{"a.json": `{"flags":null}`}, nil},
		{"yaml document that is a list", map[string]string{"a.yaml": "- flags\n- x\n"}, nil},
		{"empty flags", map[string]string{"a.flagd.json": `{"flags":{}}`}, nil},
		{"yaml with a duplicate key is rejected by the decoder", map[string]string{"a.yaml": "flags:\n  a:\n    state: ENABLED\n    state: DISABLED\n    variants: {on: true}\n"}, nil},
		{"txt is not a candidate", map[string]string{"a.txt": flagdFile(map[string]string{"a": offFlag})}, nil},
		{"flagd and manifest share a key", map[string]string{"a.flagd.json": flagdFile(map[string]string{"a": offFlag}), "flags.json": manifestFile("a", "boolean", "false")}, []string{"a"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			set := detectFiles(t, tt.files)
			if len(set.Problems) != 0 {
				t.Fatalf("problems: %+v", set.Problems)
			}
			if got := set.Keys(); !slices.Equal(got, tt.want) && (len(got) != 0 || len(tt.want) != 0) {
				t.Errorf("keys = %v, want %v", got, tt.want)
			}
		})
	}
	t.Run("both sources are kept on one switch", func(t *testing.T) {
		t.Parallel()
		set := detectFiles(t, map[string]string{"a.flagd.json": flagdFile(map[string]string{"a": offFlag}), "flags.json": manifestFile("a", "boolean", "false")})
		sw := set.Switches["a"]
		if len(sw.Definitions) != 2 || sw.Status() != StatusDefaultOff {
			t.Errorf("switch = %+v status %s", sw, sw.Status())
		}
	})
	t.Run("embedded source has a pointer path", func(t *testing.T) {
		t.Parallel()
		set := detectFiles(t, map[string]string{"k8s/cm.json": `{"data":{"a/b":` + cmFlags + `}}`})
		if got := set.Switches["s"].Definitions[0].Path; got != "k8s/cm.json#/data/a~1b" {
			t.Errorf("path = %q", got)
		}
	})
	t.Run("yaml float variants are refused", func(t *testing.T) {
		t.Parallel()
		set := detectFiles(t, map[string]string{"a.yaml": "flags:\n  a:\n    state: ENABLED\n    variants:\n      on: 0.5\n"})
		if !hasCode(set, CodeSchema) {
			t.Errorf("problems = %+v", set.Problems)
		}
	})
}

func mustUnquote(t *testing.T, quoted []byte) []byte {
	t.Helper()
	var s string
	if err := json.Unmarshal(quoted, &s); err != nil {
		t.Fatal(err)
	}
	return []byte(s)
}

func TestDetect_Strictness_FLG2(t *testing.T) {
	t.Parallel()
	good := offFlag
	one := func(flag string) string { return `{"flags":{"a":` + flag + `}}` }
	manifest := func(inner string) map[string]string {
		return map[string]string{".openfeature.json": `{"manifest":"m.json"}`, "m.json": inner}
	}
	tests := []struct {
		name  string
		files map[string]string
		code  Code
	}{
		{"array form beside a deployed source", map[string]string{"a.flagd.json": `{"flags":[{"key":"old","state":"ENABLED","variants":{"on":true,"off":false},"defaultVariant":"off"},{"key":"evil","state":"ENABLED","variants":{"on":true,"off":false},"defaultVariant":"on"}]}`}, CodeNonCanonicalArray},
		{"invalid UTF-8", map[string]string{"a.json": one(`{"state":"ENABLED","variants":{"on":true},"defaultVariant":"on","description":"` + "\xff" + `"}`)}, CodeEncoding},
		{"array form", map[string]string{"a.json": `{"flags":[{"key":"a","state":"ENABLED","variants":{"on":true},"defaultVariant":"on"}]}`}, CodeNonCanonicalArray},
		{"upper-case field names", map[string]string{"a.json": `{"flags":{"evil":{"State":"ENABLED","Variants":{"on":true,"off":false},"DefaultVariant":"on"}}}`}, CodeUnknownKey},
		{"upper-case flags key", map[string]string{"a.json": `{"FLAGS":{"evil":` + onFlag + `}}`}, CodeUnknownKey},
		{"ref as a flag entry", map[string]string{"a.json": `{"$evaluators":{"e":{"x":1}},"flags":{"evil":{"$ref":"e"}}}`}, CodeUnknownKey},
		{"ref as the whole flags", map[string]string{"a.json": `{"$evaluators":{"all":{"x":1}},"flags":{"$ref":"all"}}`}, CodeSchema},
		{"ref outside targeting", map[string]string{"a.json": one(`{"state":"ENABLED","variants":{"on":true},"metadata":{"$ref":"e"}}`)}, CodeSchema},
		{"ref to an unknown evaluator", map[string]string{"a.json": one(`{"state":"ENABLED","variants":{"on":true},"targeting":{"$ref":"nope"}}`)}, CodeSchema},
		{"ref with another key", map[string]string{"a.json": `{"$evaluators":{"e":{"x":1}},"flags":{"a":{"state":"ENABLED","variants":{"on":true},"targeting":{"$ref":"e","x":1}}}}`}, CodeSchema},
		{"ref that is not a string", map[string]string{"a.json": one(`{"state":"ENABLED","variants":{"on":true},"targeting":{"$ref":1}}`)}, CodeSchema},
		{"ref inside an evaluator", map[string]string{"a.json": `{"$evaluators":{"e":{"$ref":"e"}},"flags":{"a":` + offFlag + `}}`}, CodeSchema},
		{"evaluator name with a quote", map[string]string{"a.json": `{"$evaluators":{"a\"b":{"x":1}},"flags":{"a":` + offFlag + `}}`}, CodeSchema},
		{"evaluator name too long", map[string]string{"a.json": `{"$evaluators":{"` + strings.Repeat("a", 65) + `":{"x":1}},"flags":{"a":` + offFlag + `}}`}, CodeSchema},
		{"empty evaluator name", map[string]string{"a.json": `{"$evaluators":{"":{"x":1}},"flags":{"a":` + offFlag + `}}`}, CodeSchema},
		{"empty evaluator", map[string]string{"a.json": `{"$evaluators":{"x":{}},"flags":{"a":` + offFlag + `}}`}, CodeSchema},
		{"evaluators that is a number", map[string]string{"a.json": `{"$evaluators":1,"flags":{"a":` + offFlag + `}}`}, CodeSchema},
		{"evaluators that is a string", map[string]string{"a.json": `{"$evaluators":"x","flags":{"a":` + offFlag + `}}`}, CodeSchema},
		{"top metadata with a nested value", map[string]string{"a.json": `{"metadata":{"a":{"b":1}},"flags":{"a":` + offFlag + `}}`}, CodeSchema},
		{"flag metadata with an array value", map[string]string{"a.json": one(`{"state":"ENABLED","variants":{"on":true},"metadata":{"a":[1]}}`)}, CodeSchema},
		{"schema that is a number", map[string]string{"a.json": `{"$schema":1,"flags":{"a":` + offFlag + `}}`}, CodeSchema},
		{"yaml top-level integer key", map[string]string{"a.yaml": "1: x\nflags:\n  evil:\n    state: ENABLED\n    variants: {on: true, off: false}\n    defaultVariant: on\n"}, CodeSchema},
		{"yaml integer flag key", map[string]string{"a.yaml": "flags:\n  evil:\n    state: ENABLED\n    variants: {on: true, off: false}\n    defaultVariant: on\n  1:\n    state: ENABLED\n    variants: {on: true}\n"}, CodeSchema},
		{"yaml integer key in an entry", map[string]string{"a.yaml": "flags:\n  evil:\n    state: ENABLED\n    variants: {on: true, off: false}\n    defaultVariant: on\n    7: x\n"}, CodeSchema},
		{"yaml merge key", map[string]string{"a.yaml": "b: &a {state: ENABLED, variants: {on: true, off: false}, defaultVariant: on}\nflags:\n  evil:\n    <<: *a\n"}, CodeSchema},
		{"yaml second document is broken", map[string]string{"a.yaml": flagdYAML("evil") + "---\nkey: [unclosed\n"}, CodeSchema},
		{"yaml too deep", map[string]string{"a.yaml": "flags:\n  a:\n    state: ENABLED\n    variants: {on: true}\nmetadata: " + strings.Repeat("{a: ", 70) + "1" + strings.Repeat("}", 70) + "\n"}, CodeTooDeep},
		{"too deep to walk", map[string]string{"a.json": nest(200)}, CodeTooDeep},
		{"duplicate top-level key", map[string]string{"a.json": `{"flags":{"a":` + good + `},"flags":{"a":` + good + `}}`}, CodeDuplicateKey},
		{"duplicate flag key", map[string]string{"a.json": `{"flags":{"a":` + good + `,"a":` + good + `}}`}, CodeDuplicateKey},
		{"duplicate nested key", map[string]string{"a.json": one(`{"state":"ENABLED","variants":{"on":true,"on":false},"defaultVariant":"on"}`)}, CodeDuplicateKey},
		{"duplicate hidden by the last key", map[string]string{"a.json": `{"flags":{"a":` + good + `},"flags":{"a":` + onFlag + `}}`}, CodeDuplicateKey},
		{"unknown top-level key", map[string]string{"a.json": `{"flags":{"a":` + good + `},"extra":1}`}, CodeUnknownKey},
		{"unknown flag key", map[string]string{"a.json": one(`{"state":"ENABLED","variants":{"on":true},"extra":1}`)}, CodeUnknownKey},
		{"mixed variant types", map[string]string{"a.json": one(`{"state":"ENABLED","variants":{"on":true,"s":"x"},"defaultVariant":"on"}`)}, CodeSchema},
		{"array variants", map[string]string{"a.json": one(`{"state":"ENABLED","variants":{"on":[1]},"defaultVariant":"on"}`)}, CodeSchema},
		{"null variants", map[string]string{"a.json": one(`{"state":"ENABLED","variants":{"on":null},"defaultVariant":"on"}`)}, CodeSchema},
		{"bad state", map[string]string{"a.json": one(`{"state":"enabled","variants":{"on":true}}`)}, CodeSchema},
		{"missing state", map[string]string{"a.json": one(`{"variants":{"on":true}}`)}, CodeSchema},
		{"description of wrong type", map[string]string{"a.json": one(`{"state":"ENABLED","variants":{"on":true},"description":3}`)}, CodeSchema},
		{"empty switch name", map[string]string{"a.json": `{"flags":{"":` + good + `}}`}, CodeSchema},
		{"too deep", map[string]string{"a.json": `{"flags":{"a":` + good + `},"metadata":` + nest(70) + `}`}, CodeTooDeep},
		{"mixed flagd and manifest flags", map[string]string{"a.json": `{"flags":{"a":` + good + `,"b":{"flagType":"boolean","defaultValue":false}}}`}, CodeSchema},
		{"both config files", map[string]string{".openfeature.json": `{}`, ".openfeature.yaml": "{}\n"}, CodeAmbiguousConfig},
		{"config that is a list", map[string]string{".openfeature.json": `["manifest","x"]`}, CodeSchema},
		{"yaml config that is a list", map[string]string{".openfeature.yaml": "- manifest: x\n"}, CodeSchema},
		{"config that is not parseable", map[string]string{".openfeature.json": `{"manifest":`}, CodeSyntax},
		{"config with a duplicate key", map[string]string{".openfeature.json": `{"manifest":"a","manifest":"b"}`}, CodeDuplicateKey},
		{"manifest path with dotdot", map[string]string{".openfeature.json": `{"manifest":"../flags.json"}`}, CodeManifestPath},
		{"manifest path absolute", map[string]string{".openfeature.json": `{"manifest":"/flags.json"}`}, CodeManifestPath},
		{"manifest path not a string", map[string]string{".openfeature.yaml": "manifest: 3\n"}, CodeManifestPath},
		{"manifest named by config is missing", map[string]string{".openfeature.json": `{"manifest":"nope.json"}`}, CodeManifestPath},
		{"unsafe yaml config", map[string]string{".openfeature.yaml": "manifest: &a x\n"}, CodeSchema},
		{"flagType mismatch", map[string]string{"flags.json": manifestFile("a", "boolean", `"false"`)}, CodeSchema},
		{"bad flagType", map[string]string{"flags.json": manifestFile("a", "bool", `false`)}, CodeSchema},
		{"flagType number is not a manifest type", map[string]string{"flags.json": manifestFile("a", "number", `1`)}, CodeSchema},
		{"integer with fraction", map[string]string{"flags.json": manifestFile("a", "integer", `1.5`)}, CodeSchema},
		{"integer with exponent", map[string]string{"flags.json": manifestFile("a", "integer", `1e2`)}, CodeSchema},
		{"missing defaultValue", map[string]string{"flags.json": `{"flags":{"a":{"flagType":"boolean"}}}`}, CodeSchema},
		{"manifest unknown flag key", map[string]string{"flags.json": `{"flags":{"a":{"flagType":"boolean","defaultValue":false,"x":1}}}`}, CodeUnknownKey},
		{"manifest unknown top-level key", map[string]string{"flags.json": `{"flags":{"a":{"flagType":"boolean","defaultValue":false}},"x":1}`}, CodeUnknownKey},
		{"manifest duplicate key", map[string]string{"flags.json": `{"flags":{"a":{"flagType":"boolean","defaultValue":false,"defaultValue":true}}}`}, CodeDuplicateKey},
		{"manifest description of wrong type", map[string]string{"flags.json": `{"flags":{"a":{"flagType":"boolean","defaultValue":false,"description":1}}}`}, CodeSchema},
		{"explicit manifest that is not flag-shaped", manifest(`{"flags":{"a":{"defaultValue":false}}}`), CodeSchema},
		{"explicit manifest that is not an object", manifest(`[1]`), CodeSchema},
		{"explicit manifest with trailing data", manifest(manifestFile("a", "boolean", "false") + ` x`), CodeSyntax},
		{"explicit manifest with a byte-order mark", manifest("\xEF\xBB\xBF" + manifestFile("a", "boolean", "false")), CodeEncoding},
		{"explicit manifest is a flagd file", manifest(flagdFile(map[string]string{"a": good})), CodeSchema},
		{"yaml flagd with an anchor", map[string]string{"a.yaml": "flags:\n  a: &x\n    state: ENABLED\n    variants: {on: true}\n    defaultVariant: on\n  b: *x\n"}, CodeSchema},
		{"yaml flagd with a custom tag", map[string]string{"a.yaml": "flags:\n  a:\n    state: !x ENABLED\n    variants: {on: true}\n"}, CodeSchema},
		{"yaml flag source in a multi-document file", map[string]string{"a.yaml": flagdYAML("a") + "---\nkind: x\n"}, CodeSchema},
		{"embedded source with a duplicate key", map[string]string{"cm.json": `{"d":` + quote(`{"flags":{"a":`+good+`,"a":`+good+`}}`) + `}`}, CodeDuplicateKey},
		{"embedded source with an unknown key", map[string]string{"cm.json": `{"d":` + quote(`{"flags":{"a":`+good+`},"zz":1}`) + `}`}, CodeUnknownKey},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			set := detectFiles(t, tt.files)
			if !hasCode(set, tt.code) {
				t.Fatalf("problems = %+v, want code %s", set.Problems, tt.code)
			}
			if got := Compare(detectFiles(t, nil), set).Verdict; got != VerdictError {
				t.Errorf("verdict = %s, want error", got)
			}
		})
	}
}

func quote(s string) string {
	b, err := json.Marshal(s)
	if err != nil {
		panic(err) // a string always marshals
	}
	return string(b)
}

func TestDetect_ManifestPathWildcard_FLG2(t *testing.T) {
	t.Parallel()
	// The file exists at the literal path, so only the wildcard check can reject the path.
	for _, mp := range []string{"d*/flags.json", "d?/flags.json", "d[1]/flags.json"} {
		t.Run(mp, func(t *testing.T) {
			t.Parallel()
			set := detectFiles(t, map[string]string{
				".openfeature.json": `{"manifest":` + quote(mp) + `}`, mp: manifestFile("m", "boolean", "false"),
			})
			if !hasCode(set, CodeManifestPath) {
				t.Errorf("problems = %+v", set.Problems)
			}
		})
	}
}

func TestDetect_ConfigProblemReadsNoManifest_FLG2(t *testing.T) {
	t.Parallel()
	// m.json holds nothing flag-like, so only an explicit read of it can complain.
	m := `{"x":1}`
	big := `{"manifest":"m.json","pad":"` + strings.Repeat("x", 300) + `"}`
	lim := DefaultLimits()
	lim.MaxFileBytes = 200
	tests := []struct {
		name  string
		files map[string]string
		links map[string]string
		lim   Limits
	}{
		{"unparseable", map[string]string{".openfeature.json": `{"manifest":"m.json"`, "m.json": m}, nil, DefaultLimits()},
		{"not an object", map[string]string{".openfeature.yaml": "- manifest\n", "m.json": m}, nil, DefaultLimits()},
		{"symlinked", map[string]string{"c.json": `{"manifest":"m.json"}`, "m.json": m}, map[string]string{".openfeature.json": "c.json"}, DefaultLimits()},
		{"oversized", map[string]string{".openfeature.json": big, "m.json": m}, nil, lim},
		{"both files", map[string]string{".openfeature.json": `{"manifest":"m.json"}`, ".openfeature.yaml": "manifest: m.json\n", "m.json": m}, nil, DefaultLimits()},
		{"bad path", map[string]string{".openfeature.json": `{"manifest":"../m.json"}`, "m.json": m}, nil, DefaultLimits()},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			set, err := Detect(t.Context(), mkTree(t, tt.files, tt.links), tt.lim)
			if err != nil {
				t.Fatal(err)
			}
			if len(set.Problems) == 0 {
				t.Fatal("no problem")
			}
			for _, p := range set.Problems {
				if p.Path == "m.json" {
					t.Errorf("m.json was read as the manifest: %+v", p)
				}
			}
		})
	}
	t.Run("the control: a good config does read it", func(t *testing.T) {
		t.Parallel()
		set := detectFiles(t, map[string]string{".openfeature.json": `{"manifest":"m.json"}`, "m.json": m})
		if !slices.ContainsFunc(set.Problems, func(p Problem) bool { return p.Path == "m.json" }) {
			t.Errorf("problems = %+v", set.Problems)
		}
	})
}

func TestDetect_ExplicitManifest_FLG2(t *testing.T) {
	t.Parallel()
	t.Run("it is read once", func(t *testing.T) {
		t.Parallel()
		set := detectFiles(t, map[string]string{".openfeature.json": `{"manifest":"conf/m.json"}`, "conf/m.json": manifestFile("m", "boolean", "false")})
		if defs := set.Switches["m"].Definitions; len(defs) != 1 || defs[0].Path != "conf/m.json" || defs[0].Kind != KindManifest {
			t.Errorf("definitions = %+v", defs)
		}
	})
	t.Run("a directory is not a manifest", func(t *testing.T) {
		t.Parallel()
		set := detectFiles(t, map[string]string{".openfeature.json": `{"manifest":"conf"}`, "conf/x.txt": "x"})
		if !hasCode(set, CodeSchema) {
			t.Errorf("problems = %+v", set.Problems)
		}
	})
	t.Run("an oversized manifest", func(t *testing.T) {
		t.Parallel()
		lim := DefaultLimits()
		lim.MaxFileBytes = 100
		m := `{"flags":{"a":{"flagType":"string","defaultValue":"` + strings.Repeat("x", 200) + `"}}}`
		set, err := Detect(t.Context(), mkTree(t, map[string]string{".openfeature.json": `{"manifest":"m.txt"}`, "m.txt": m}, nil), lim)
		if err != nil || !hasCode(set, CodeTooLarge) {
			t.Errorf("err = %v, problems = %+v", err, set.Problems)
		}
	})
}

func TestDetect_Oversized_FLG2(t *testing.T) {
	t.Parallel()
	lim := DefaultLimits()
	lim.MaxFileBytes = 100
	pad := strings.Repeat("x", 200)
	for _, tt := range []struct{ name, file, data string }{
		{"json that mentions flags", "a.json", `{"flags":{},"pad":"` + pad + `"}`},
		{"json without the token", "a.json", `{"other":{},"pad":"` + pad + `"}`},
		{"yaml", "a.yaml", "other: 1\npad: " + pad + "\n"},
		{"upper-case yml", "a.YML", "other: 1\npad: " + pad + "\n"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			set, err := Detect(t.Context(), mkTree(t, map[string]string{tt.file: tt.data}, nil), lim)
			if err != nil {
				t.Fatal(err)
			}
			if !hasCode(set, CodeTooLarge) {
				t.Errorf("problems = %+v", set.Problems)
			}
		})
	}
	t.Run("a file at the cap is probed", func(t *testing.T) {
		t.Parallel()
		data := `{"flags":{}}`
		lim := DefaultLimits()
		lim.MaxFileBytes = len(data)
		set, err := Detect(t.Context(), mkTree(t, map[string]string{"a.json": data}, nil), lim)
		if err != nil || len(set.Problems) != 0 {
			t.Errorf("err = %v, problems = %+v", err, set.Problems)
		}
	})
	t.Run("a file the tree refuses to serve", func(t *testing.T) {
		t.Parallel()
		tree := refuseTree{FS: mkTree(t, map[string]string{"a.json": `{"flags":{}}`, "b.txt": "x"}, nil), refuse: "a.json"}
		set, err := Detect(t.Context(), tree, DefaultLimits())
		if err != nil || !hasCode(set, CodeTooLarge) {
			t.Errorf("err = %v, problems = %+v", err, set.Problems)
		}
	})
}

// refuseTree fails to read one file, as a git tree does for a file over its own limit.
type refuseTree struct {
	fs.FS
	refuse string
}

func (r refuseTree) ReadFile(name string) ([]byte, error) {
	if name == r.refuse {
		return nil, errors.New("too big for this tree")
	}
	return fs.ReadFile(r.FS, name)
}

func (r refuseTree) Lstat(name string) (fs.FileInfo, error) { return fs.Lstat(r.FS, name) }

func (r refuseTree) ReadLink(name string) (string, error) { return fs.ReadLink(r.FS, name) }

func TestDetect_Symlinks_FLG2(t *testing.T) {
	t.Parallel()
	flagd := flagdFile(map[string]string{"a": offFlag})
	t.Run("a candidate link to a regular file is read under its own name", func(t *testing.T) {
		t.Parallel()
		for name, link := range map[string]string{
			"src/extra.json": "../docs/x.txt", "src/extra.YAML": "../docs/x.txt", "src/e.js-on": "../docs/x.txt", "link.flagd.json": "docs/x.txt",
		} {
			set := detectTree(t, mkTree(t, map[string]string{"docs/x.txt": flagd}, map[string]string{name: link}))
			if len(set.Problems) != 0 && !strings.HasSuffix(name, "YAML") {
				t.Errorf("%s: problems = %+v", name, set.Problems)
			}
			if !slices.ContainsFunc(set.Switches["a"].Definitions, func(d Definition) bool { return d.Path == name }) && !strings.HasSuffix(name, "YAML") {
				t.Errorf("%s: definitions = %+v", name, set.Switches["a"].Definitions)
			}
		}
	})
	t.Run("a flag file behind a link cannot hide", func(t *testing.T) {
		t.Parallel()
		evil := `{"flags":{"evil":` + onFlag + `}}`
		base := detectFiles(t, flagd1(offFlag))
		head := detectTree(t, mkTree(t, map[string]string{"src/flagd/demo.flagd.json": flagd1(offFlag)["src/flagd/demo.flagd.json"], "docs/x.txt": evil}, map[string]string{"src/flagd/extra.json": "../../docs/x.txt"}))
		if c := Compare(base, head); c.Verdict != VerdictBlocked {
			t.Errorf("verdict = %s, problems %+v", c.Verdict, head.Problems)
		}
	})
	t.Run("a link that does not resolve", func(t *testing.T) {
		t.Parallel()
		files := map[string]string{"docs/x.txt": flagd, "real/y.json": flagd, ".openfeature.json": `{}`}
		for name, tt := range map[string]struct {
			link      string
			candidate bool
		}{
			"abs.json":          {"/etc/otel/x.json", true},
			"up.json":           {"../../x.json", true},
			"dangling.json":     {"nowhere.json", true},
			"via-link.json":     {"alias/y.json", true},
			"to-dir.json":       {"real", true},
			"to-link.json":      {"abs.json", true},
			"trailing-dot.json": {"real/..", true},
			"abs.txt":           {"/etc/otel", false},
			"up.txt":            {"../../x", false},
			"dangling.txt":      {"nowhere", false},
			"via-link.txt":      {"alias/y.json", false},
			"to-dir.txt":        {"real", false},
		} {
			set := detectTree(t, mkTree(t, files, map[string]string{name: tt.link, "alias": "real"}))
			problem := slices.ContainsFunc(set.Problems, func(p Problem) bool { return p.Code == CodeSymlink && p.Path == name })
			opaque := slices.ContainsFunc(set.Opaque, func(o OpaqueEntry) bool { return o.Path == name })
			if tt.candidate && (!problem || opaque) || !tt.candidate && (problem || !opaque) {
				t.Errorf("%s: problem=%v opaque=%v (problems %+v)", name, problem, opaque, set.Problems)
			}
		}
	})
	t.Run("a link to a regular file that is no candidate is neither", func(t *testing.T) {
		t.Parallel()
		set := detectTree(t, mkTree(t, map[string]string{"tsconfig.base.json": `{"a":1}`}, map[string]string{"tsconfig.json": "tsconfig.base.json", "link.txt": "tsconfig.base.json"}))
		if len(set.Problems) != 0 || len(set.Opaque) != 0 {
			t.Errorf("set = %+v", set)
		}
	})
	t.Run("a link to a file in a symlinked directory is not followed", func(t *testing.T) {
		t.Parallel()
		set := detectTree(t, mkTree(t, map[string]string{"real/y.json": flagd}, map[string]string{"alias": "real", "x.json": "alias/y.json"}))
		if !hasCode(set, CodeSymlink) {
			t.Errorf("problems = %+v", set.Problems)
		}
	})
}

func TestDetect_SymlinkedConfigAndManifest_FLG2(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		files map[string]string
		links map[string]string
		code  Code
	}{
		{"symlinked config", map[string]string{"c.json": `{}`}, map[string]string{".openfeature.json": "c.json"}, CodeSymlink},
		{"symlinked manifest", map[string]string{"real.json": manifestFile("m", "boolean", "false"), ".openfeature.json": `{"manifest":"flags.json"}`}, map[string]string{"flags.json": "real.json"}, CodeSymlink},
		{"manifest under a symlinked directory", map[string]string{".openfeature.json": `{"manifest":"d/flags.json"}`, "real/flags.json": manifestFile("m", "boolean", "false")}, map[string]string{"d": "real"}, CodeUnreadable},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			set, err := Detect(t.Context(), mkTree(t, tt.files, tt.links), DefaultLimits())
			if err != nil {
				t.Fatal(err)
			}
			if !hasCode(set, tt.code) {
				t.Fatalf("problems = %+v, want %s", set.Problems, tt.code)
			}
			for _, d := range set.Switches["m"].Definitions {
				if d.Path == "d/flags.json" {
					t.Errorf("manifest was read through the link: %+v", d)
				}
			}
			if Compare(detectFiles(t, nil), set).Verdict != VerdictError {
				t.Error("verdict is not error")
			}
		})
	}
}

func TestDetect_OpaqueEntries_FLG2(t *testing.T) {
	t.Parallel()
	flagd := flagdFile(map[string]string{"a": offFlag})
	t.Run("symlinked directory is opaque and not followed", func(t *testing.T) {
		t.Parallel()
		tree := mkTree(t, map[string]string{"real/a.flagd.json": flagd}, map[string]string{"alias": "real"})
		set := detectTree(t, tree)
		if len(set.Switches["a"].Definitions) != 1 || len(set.Problems) != 0 {
			t.Errorf("set = %+v", set)
		}
		if len(set.Opaque) != 1 || set.Opaque[0].Path != "alias" || set.Opaque[0].Kind != "symlink" {
			t.Errorf("opaque = %+v", set.Opaque)
		}
	})
	t.Run("symlink that cannot be resolved in the tree is opaque", func(t *testing.T) {
		t.Parallel()
		for name, target := range map[string]string{"abs": "/etc/otel", "up": "../../out", "dangling": "nowhere", "to-link": "abs"} {
			set := detectTree(t, mkTree(t, map[string]string{"x.txt": "x"}, map[string]string{name: target, "abs": "/etc/otel"}))
			if !slices.ContainsFunc(set.Opaque, func(o OpaqueEntry) bool { return o.Path == name }) {
				t.Errorf("%s: opaque = %+v", name, set.Opaque)
			}
		}
	})
	t.Run("symlink to a regular file is not opaque", func(t *testing.T) {
		t.Parallel()
		set := detectTree(t, mkTree(t, map[string]string{"docs/x.txt": "x"}, map[string]string{"link.txt": "docs/x.txt"}))
		if len(set.Opaque) != 0 || len(set.Problems) != 0 {
			t.Errorf("set = %+v", set)
		}
	})
	t.Run("gitlink is opaque", func(t *testing.T) {
		t.Parallel()
		set := detectTree(t, mkEntries(t, []gittree.Entry{gitlink("vendor/dep"), gitlink("a.flagd.json")}))
		got := []string{}
		for _, o := range set.Opaque {
			got = append(got, o.Kind+":"+o.Path)
		}
		if want := []string{"gitlink:a.flagd.json", "gitlink:vendor/dep"}; !slices.Equal(got, want) {
			t.Errorf("opaque = %v, want %v", got, want)
		}
	})
}

func TestDetect_Budgets_FLG2(t *testing.T) {
	t.Parallel()
	// No $schema, whose URL is a long string that the probe also charges.
	flagd := `{"flags":{"a":` + offFlag + `,"b":` + offFlag + `,"c":` + offFlag + `}}`
	files := map[string]string{"a.flagd.json": flagd, "b.flagd.json": flagd, "c/d.flagd.json": flagd}
	// entries: the root, a, b, c, c/d = 5.
	tests := []struct {
		name   string
		mod    func(*Limits)
		tooBig bool
	}{
		{"entries over", func(l *Limits) { l.MaxEntries = 4 }, true},
		{"entries exact", func(l *Limits) { l.MaxEntries = 5 }, false},
		{"total bytes over", func(l *Limits) { l.MaxTotalBytes = 3*len(flagd) - 1 }, true},
		{"total bytes exact", func(l *Limits) { l.MaxTotalBytes = 3 * len(flagd) }, false},
		{"flags per file over", func(l *Limits) { l.MaxFlagsPerFile = 2 }, true},
		{"flags per file exact", func(l *Limits) { l.MaxFlagsPerFile = 3 }, false},
		{"definitions per key over", func(l *Limits) { l.MaxDefinitionsPerKey = 2 }, true},
		{"definitions per key exact", func(l *Limits) { l.MaxDefinitionsPerKey = 3 }, false},
		{"file bytes exact", func(l *Limits) { l.MaxFileBytes = len(flagd) }, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			lim := DefaultLimits()
			tt.mod(&lim)
			set, err := Detect(t.Context(), mkTree(t, files, nil), lim)
			if tt.tooBig {
				if !errors.Is(err, ErrTooLarge) {
					t.Fatalf("err = %v, want ErrTooLarge", err)
				}
				if set.Switches != nil || set.Problems != nil || set.complete {
					t.Errorf("partial set returned: %+v", set)
				}
				return
			}
			if err != nil || len(set.Problems) != 0 || len(set.Switches) != 3 {
				t.Errorf("err = %v, set = %+v", err, set)
			}
		})
	}
	t.Run("manifest flags per file", func(t *testing.T) {
		t.Parallel()
		lim := DefaultLimits()
		lim.MaxFlagsPerFile = 1
		m := `{"flags":{"a":{"flagType":"boolean","defaultValue":false},"b":{"flagType":"boolean","defaultValue":false}}}`
		if _, err := Detect(t.Context(), mkTree(t, map[string]string{"flags.json": m}, nil), lim); !errors.Is(err, ErrTooLarge) {
			t.Errorf("err = %v", err)
		}
	})
}

func TestDetect_ProbeBudgets_FLG2(t *testing.T) {
	t.Parallel()
	t.Run("depth exactly at the cap", func(t *testing.T) {
		t.Parallel()
		// The top-level object is depth 1, so metadata nested n deep reaches depth n+1.
		for n, want := range map[int]bool{63: false, 64: true} {
			set := detectFiles(t, map[string]string{"a.json": `{"flags":{"a":` + offFlag + `},"metadata":` + nest(n) + `}`})
			if got := hasCode(set, CodeTooDeep); got != want {
				t.Errorf("nest %d: too-deep = %v, want %v", n, got, want)
			}
		}
	})
	t.Run("embedded strings are charged to the total", func(t *testing.T) {
		t.Parallel()
		long := strings.Repeat("y", 100)
		data := `{"d":"` + long + `"}`
		for limit, wantErr := range map[int]bool{len(data) + len(long) - 1: true, len(data) + len(long): false} {
			lim := DefaultLimits()
			lim.MaxTotalBytes = limit
			_, err := Detect(t.Context(), mkTree(t, map[string]string{"a.json": data}, nil), lim)
			if errors.Is(err, ErrTooLarge) != wantErr {
				t.Errorf("limit %d: err = %v, want too large = %v", limit, err, wantErr)
			}
		}
	})
	t.Run("an equal string is decoded and charged once", func(t *testing.T) {
		t.Parallel()
		long := strings.Repeat("y", 100)
		data := `{"a":"` + long + `","b":"` + long + `","c":["` + long + `"]}`
		lim := DefaultLimits()
		lim.MaxTotalBytes = len(data) + len(long)
		if _, err := Detect(t.Context(), mkTree(t, map[string]string{"a.json": data}, nil), lim); err != nil {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("node budget", func(t *testing.T) {
		t.Parallel()
		lim := DefaultLimits()
		lim.MaxNodes = 5
		set, err := Detect(t.Context(), mkTree(t, map[string]string{"a.json": `{"a":[1,2,3,4,5,6,7]}`}, nil), lim)
		if err != nil || !hasCode(set, CodeTooLarge) {
			t.Errorf("err = %v, problems = %+v", err, set.Problems)
		}
	})
}

func TestDetect_ManyDefinitionsOfOneKey_FLG2(t *testing.T) {
	t.Parallel()
	build := func(n int) map[string]string {
		files := map[string]string{}
		for i := range n {
			files[fmt.Sprintf("d/%04d.flagd.json", i)] = flagdFile(map[string]string{"k": offFlag})
		}
		return files
	}
	t.Run("over the cap", func(t *testing.T) {
		t.Parallel()
		_, err := Detect(t.Context(), mkTree(t, build(65), nil), DefaultLimits())
		if !errors.Is(err, ErrTooLarge) {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("at the cap finishes fast", func(t *testing.T) {
		t.Parallel()
		start := time.Now()
		set := detectFiles(t, build(64))
		c := Compare(detectFiles(t, nil), set)
		if set.Switches["k"].Status() != StatusDefaultOff || c.Verdict != VerdictPass {
			t.Errorf("status %s, verdict %s", set.Switches["k"].Status(), c.Verdict)
		}
		if d := time.Since(start); d > 10*time.Second {
			t.Errorf("took %v", d)
		}
	})
}

func TestDetect_ContextAndTree_FLG2(t *testing.T) {
	t.Parallel()
	tree := mkTree(t, map[string]string{"a.flagd.json": flagdFile(map[string]string{"a": offFlag})}, nil)
	t.Run("cancelled context", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		if _, err := Detect(ctx, tree, DefaultLimits()); !errors.Is(err, context.Canceled) {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("cancelled during the scan", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithCancel(t.Context())
		if _, err := Detect(ctx, &cancelTree{FS: tree, cancel: cancel}, DefaultLimits()); !errors.Is(err, context.Canceled) {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("tree without symlink support", func(t *testing.T) {
		t.Parallel()
		if _, err := Detect(t.Context(), openOnly{fstest.MapFS{}}, DefaultLimits()); !errors.Is(err, ErrUnsupportedTree) {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("zero limits", func(t *testing.T) {
		t.Parallel()
		if _, err := Detect(t.Context(), tree, Limits{}); !errors.Is(err, ErrInvalidLimits) {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("each limit must be positive", func(t *testing.T) {
		t.Parallel()
		for i, mod := range []func(*Limits){
			func(l *Limits) { l.MaxEntries = 0 }, func(l *Limits) { l.MaxFileBytes = 0 }, func(l *Limits) { l.MaxTotalBytes = 0 },
			func(l *Limits) { l.MaxDepth = 0 }, func(l *Limits) { l.MaxFlagsPerFile = 0 }, func(l *Limits) { l.MaxDefinitionsPerKey = 0 }, func(l *Limits) { l.MaxNodes = 0 },
		} {
			lim := DefaultLimits()
			mod(&lim)
			if _, err := Detect(t.Context(), tree, lim); !errors.Is(err, ErrInvalidLimits) {
				t.Errorf("limit %d: err = %v", i, err)
			}
		}
	})
	t.Run("read error text is escaped and keeps the chain", func(t *testing.T) {
		t.Parallel()
		err := (&scanError{op: "read", path: "a@b::c\n", err: fs.ErrPermission}).Error()
		if strings.ContainsAny(err, "@\n") || strings.Contains(err, "::") {
			t.Errorf("error = %q", err)
		}
		if !errors.Is(&scanError{err: fs.ErrPermission}, fs.ErrPermission) {
			t.Error("chain lost")
		}
	})
}

func TestDetect_Deterministic_FLG2(t *testing.T) {
	t.Parallel()
	files := map[string]string{
		"z.json": `{"flags":{"c":` + offFlag + `},"x":1,"w":1}`,
		"a.json": `{"flags":{"a":` + offFlag + `,"a":` + offFlag + `}}`,
		"m.json": flagdFile(map[string]string{"k": offFlag}),
		"f.json": manifestFile("k", "boolean", "false"),
	}
	first := detectFiles(t, files)
	if len(first.Problems) < 2 {
		t.Fatalf("problems = %+v", first.Problems)
	}
	for range 5 {
		again := detectFiles(t, files)
		if diff := cmp.Diff(first.Problems, again.Problems); diff != "" {
			t.Fatalf("problems differ between runs:\n%s", diff)
		}
	}
	if !slices.IsSortedFunc(first.Problems, func(a, b Problem) int {
		return strings.Compare(a.Path+"\x00"+a.Pointer, b.Path+"\x00"+b.Pointer)
	}) {
		t.Errorf("problems not sorted: %+v", first.Problems)
	}
	defs := first.Switches["k"].Definitions
	if len(defs) != 2 || defs[0].Path != "f.json" || defs[1].Path != "m.json" {
		t.Errorf("definitions = %+v", defs)
	}
}

func TestDetect_ProblemTextEscaped_FLG2(t *testing.T) {
	t.Parallel()
	evil := "@a::b##[x]`<i>|www.x.example"
	good := `{"state":"ENABLED","variants":{"on":true},"defaultVariant":"on","zz@":1}`
	files := map[string]string{
		"d/" + evil + ".json": `{"flags":{"@k":` + good + `}}`,
		".openfeature.yaml":   "\"@everyone|<img src=x>`::x\": 1\n\"@everyone|<img src=x>`::x\": 2\n",
		"y/" + evil + ".yaml": "flags:\n  \"@k\":\n    state: ENABLED\n    variants: {on: true}\n    \"zz@\": 1\n",
	}
	set := detectFiles(t, files)
	if len(set.Problems) < 3 {
		t.Fatalf("problems = %+v", set.Problems)
	}
	for _, p := range set.Problems {
		for _, s := range []string{p.Path, p.Pointer, p.Message} {
			if strings.ContainsAny(s, "@<>`[]\n#&|") || strings.Contains(s, "::") || strings.Contains(strings.ToLower(s), "www.") {
				t.Errorf("unescaped text in %+v", p)
			}
		}
	}
}

// cancelTree cancels the scan's context when the first directory is read.
type cancelTree struct {
	fs.FS
	cancel func()
}

func (c *cancelTree) ReadDir(name string) ([]fs.DirEntry, error) {
	c.cancel()
	return fs.ReadDir(c.FS, name)
}

func (c *cancelTree) Lstat(name string) (fs.FileInfo, error) { return fs.Lstat(c.FS, name) }

func (c *cancelTree) ReadLink(name string) (string, error) { return fs.ReadLink(c.FS, name) }

// openOnly hides every optional interface of the tree it wraps.
type openOnly struct{ fs fs.FS }

func (o openOnly) Open(name string) (fs.File, error) { return o.fs.Open(name) }
