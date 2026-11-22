// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

package switches

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func corpus(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "flagd-differential", name))
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestDefaultLimits_FLG2(t *testing.T) {
	t.Parallel()
	want := Limits{
		MaxEntries: 200_000, MaxFileBytes: 16 << 20, MaxTotalBytes: 512 << 20, MaxDepth: 64,
		MaxFlagsPerFile: 10_000, MaxDefinitionsPerKey: 64, MaxNodes: 1_000_000,
	}
	if diff := cmp.Diff(want, DefaultLimits()); diff != "" {
		t.Errorf("DefaultLimits (-want +got):\n%s", diff)
	}
}

func TestCompare_Splices_FLG2(t *testing.T) {
	t.Parallel()
	base := flagd1(offFlag)
	for _, name := range []string{
		"r3-lift.json", "r3-lift.yaml", "r3-order-longs.json", "r3-order-upper.json", "r3-longs-only.json",
		"r3-ext-47.jsoné", "r3-ext-48.jsonſ", "r3-ext-49.json٣", "r3-ext-50.yamlé", "r3-ext-51.ymlß", "r2-N1.json", "r2-L1-odd-extension-extra.js-on",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			head := map[string]string{demoPath: base[demoPath], "src/flagd/" + name: corpus(t, name)}
			if c := compareFiles(t, base, head); c.Verdict == VerdictPass {
				t.Errorf("BYPASS: %s passes", name)
			}
		})
	}
	t.Run("a splice in a config map", func(t *testing.T) {
		t.Parallel()
		head := map[string]string{demoPath: base[demoPath], "k8s/cm.yaml": corpus(t, "r3-cm-lift.yaml")}
		if c := compareFiles(t, base, head); c.Verdict == VerdictPass {
			t.Error("BYPASS: the splice in a config map passes")
		}
	})
}

func TestDetect_Evaluators_FLG2(t *testing.T) {
	t.Parallel()
	evaluated := func(names string) string {
		return `{"$evaluators":{"` + names + `":{"x":1}},"flags":{"a":{"state":"ENABLED","variants":{"on":true,"off":false},"defaultVariant":"off","targeting":{"$ref":"` + names + `"}}}}`
	}
	for _, name := range []string{"a_b", "a-b", "A9", strings.Repeat("a", 64)} {
		set := detectFiles(t, map[string]string{"a.json": evaluated(name)})
		if len(set.Problems) != 0 {
			t.Errorf("evaluator %q: problems = %+v", name, set.Problems)
		}
	}
	for name, doc := range map[string]string{
		"evaluators without flags":       `{"$evaluators":{"x":{"a":1}}}`,
		"upper-case evaluators":          `{"$EVALUATORS":{"x":{"a":1}},"flags":{"a":` + offFlag + `}}`,
		"null evaluators":                `{"$evaluators":null}`,
		"evaluators and variant refs":    `{"$evaluators":{"e":{"x":1}},"flags":{"a":{"state":"ENABLED","variants":{"on":{"$ref":"e"},"off":{"$ref":"e"}},"defaultVariant":"off"}}}`,
		"evaluators and metadata ref":    `{"$evaluators":{"e":{"x":1}},"flags":{"a":{"state":"ENABLED","variants":{"on":true,"off":false},"defaultVariant":"off","metadata":{"$ref":"e"}}}}`,
		"evaluators and top level ref":   `{"$evaluators":{"e":{"x":1}},"metadata":{"$ref":"e"},"flags":{"a":` + offFlag + `}}`,
		"evaluators and ref in an array": `{"$evaluators":{"e":{"x":1}},"flags":{"a":{"state":"ENABLED","variants":{"on":true,"off":false},"defaultVariant":"off","targeting":[{"$ref":"e","x":1}]}}}`,
	} {
		set := detectFiles(t, map[string]string{"a.json": doc})
		if len(set.Problems) == 0 {
			t.Errorf("%s: no problem", name)
		}
	}
}

func TestDetect_EveryYAMLDocument_FLG2(t *testing.T) {
	t.Parallel()
	cm := func(flag string) string {
		return "apiVersion: v1\nkind: Service\nmetadata:\n  name: flagd\n---\napiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: flagd-config\ndata:\n  demo.flagd.json: |\n    " +
			flagdFile(map[string]string{"old": flag}) + "\n"
	}
	base := map[string]string{"k8s/flagd.yaml": cm(offFlag)}
	set := detectFiles(t, base)
	if defs := set.Switches["old"].Definitions; len(set.Problems) != 0 || len(defs) != 1 || defs[0].Path != "k8s/flagd.yaml#/1/data/demo.flagd.json" {
		t.Fatalf("set = %+v", set)
	}
	if c := compareFiles(t, base, map[string]string{"k8s/flagd.yaml": cm(onFlag)}); c.Verdict != VerdictBlocked {
		t.Errorf("flipping the config map to on: %+v", c)
	}
	if c := compareFiles(t, base, base); c.Verdict != VerdictPass {
		t.Errorf("unchanged: %+v", c)
	}
}

func TestDetect_FeatureFlagResources_FLG2(t *testing.T) {
	t.Parallel()
	cr := func(group, key, flag string) string {
		return "apiVersion: " + group + "\nkind: FeatureFlag\nmetadata:\n  name: demo\nspec:\n  " + key + ":\n    flags:\n      old: " + flag + "\n"
	}
	yamlFlag := func(def string) string {
		return `{state: ENABLED, variants: {"on": true, "off": false}, defaultVariant: "` + def + `"}`
	}
	base := map[string]string{"deploy/ff.yaml": cr("core.openfeature.dev/v1beta1", "flagSpec", yamlFlag("off"))}
	set := detectFiles(t, base)
	if defs := set.Switches["old"].Definitions; len(set.Problems) != 0 || len(defs) != 1 || defs[0].Path != "deploy/ff.yaml#/spec/flagSpec" {
		t.Fatalf("set = %+v", set)
	}
	for name, head := range map[string]map[string]string{
		"on":              {"deploy/ff.yaml": cr("core.openfeature.dev/v1beta1", "flagSpec", yamlFlag("on"))},
		"the older key":   {"deploy/ff.yaml": cr("core.openfeature.dev/v1alpha1", "featureFlagSpec", yamlFlag("on"))},
		"second document": {"deploy/ff.yaml": "kind: Service\n---\n" + cr("core.openfeature.dev/v1beta1", "flagSpec", yamlFlag("on"))},
		"a json resource": {"deploy/ff.json": `{"apiVersion":"core.openfeature.dev/v1beta1","kind":"FeatureFlag","spec":{"flagSpec":{"flags":{"evil":` + onFlag + `}}}}`},
		"in a string":     {"deploy/cm.yaml": "data:\n  ff.yaml: |\n    " + strings.ReplaceAll(cr("core.openfeature.dev/v1beta1", "flagSpec", yamlFlag("on")), "\n", "\n    ") + "\n"},
	} {
		if c := compareFiles(t, base, head); c.Verdict == VerdictPass {
			t.Errorf("BYPASS: %s passes", name)
		}
	}
	t.Run("another kind is no source", func(t *testing.T) {
		t.Parallel()
		other := cr("core.openfeature.dev/v1beta1", "flagSpec", yamlFlag("on"))
		other = strings.Replace(other, "kind: FeatureFlag", "kind: Other", 1)
		if c := compareFiles(t, nil, map[string]string{"deploy/ff.yaml": other}); c.Verdict != VerdictPass {
			t.Errorf("verdict = %s", c.Verdict)
		}
	})
	t.Run("another group is no source", func(t *testing.T) {
		t.Parallel()
		other := map[string]string{"deploy/ff.yaml": cr("example.com/v1", "flagSpec", yamlFlag("on"))}
		if c := compareFiles(t, nil, other); c.Verdict != VerdictPass {
			t.Errorf("verdict = %s", c.Verdict)
		}
	})
}

func TestDetect_TopLevelArray_FLG2(t *testing.T) {
	t.Parallel()
	inner := quote(flagdFile(map[string]string{"evil": onFlag}))
	for name, doc := range map[string]string{"array of strings": `[` + inner + `]`, "array of objects": `[{"a":` + inner + `}]`} {
		if c := compareFiles(t, nil, map[string]string{"a.json": doc}); c.Verdict != VerdictBlocked {
			t.Errorf("%s: %+v", name, c)
		}
	}
	yamlList := "- name: x\n  data: " + inner + "\n"
	if c := compareFiles(t, nil, map[string]string{"a.yaml": yamlList}); c.Verdict != VerdictBlocked {
		t.Errorf("yaml list: %+v", c)
	}
}

func TestDetect_EmbeddedBoundary_FLG2(t *testing.T) {
	t.Parallel()
	// "$evaluators: 123" is 16 bytes, so it is not decoded. A 17th byte makes it a source with a problem.
	for s, want := range map[string]bool{"$evaluators: 123": false, "$evaluators: 1234": true} {
		set := detectFiles(t, map[string]string{"a.json": `{"d":` + quote(s) + `}`})
		if got := len(set.Problems) > 0; got != want {
			t.Errorf("%q (%d bytes): problems = %+v, want problem %v", s, len(s), set.Problems, want)
		}
	}
}

func TestDetect_YAMLKeyCollision_FLG2(t *testing.T) {
	t.Parallel()
	file := "x:\n  1.0: a\n  '1': b\n"
	var first []Problem
	for i := range 200 {
		set := detectFiles(t, map[string]string{"a.yaml": file})
		if len(set.Problems) == 0 {
			t.Fatalf("iteration %d: no problem", i)
		}
		if first == nil {
			first = set.Problems
		} else if diff := cmp.Diff(first, set.Problems); diff != "" {
			t.Fatalf("iteration %d differs:\n%s", i, diff)
		}
	}
}

func TestDetect_CancelsInsideAFile_FLG2(t *testing.T) {
	t.Parallel()
	var b strings.Builder
	b.WriteString(`{"a":[`)
	for i := range 5000 {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString("1")
	}
	b.WriteString(`]}`)
	tree := mkTree(t, map[string]string{"a.json": b.String()}, nil)
	// The scan checks the context three times before the file is probed (start, root, file), and the walk checks it
	// every 1,024 nodes, so a context that cancels on the fourth check can only be stopped inside the file.
	ctx := &countdownCtx{Context: t.Context()}
	ctx.left.Store(3)
	if _, err := Detect(ctx, tree, DefaultLimits()); !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v", err)
	}
	ctx2 := &countdownCtx{Context: t.Context()}
	ctx2.left.Store(1 << 20)
	if _, err := Detect(ctx2, tree, DefaultLimits()); err != nil {
		t.Errorf("a context that never cancels: %v", err)
	}
}

// countdownCtx reports cancellation after a number of calls to Err.
type countdownCtx struct {
	context.Context //nolint:containedctx // a test double that wraps a context to cancel it after a number of checks
	left            atomic.Int64
}

func (c *countdownCtx) Err() error {
	if c.left.Add(-1) < 0 {
		return context.Canceled
	}
	return nil
}

func TestDetect_LinkTargets_FLG2(t *testing.T) {
	t.Parallel()
	flagd := flagdFile(map[string]string{"a": offFlag})
	files := map[string]string{"real/y.json": flagd, "real.json": flagd}
	for name, tt := range map[string]struct {
		link    string
		resolve bool
	}{
		"abs.json":   {"/real/y.json", false}, // would resolve if the leading slash were ignored
		"up.json":    {"../real.json", false}, // above the root
		"d/up2.json": {"../../real.json", false},
		"d/ok.json":  {"../real.json", true},
		"d/ok2.json": {"../real/y.json", true},
		"e.json":     {"real/./y.json", true},
		"f.json":     {"real//y.json", true},
	} {
		set := detectTree(t, mkTree(t, files, map[string]string{name: tt.link}))
		problem := slices.ContainsFunc(set.Problems, func(p Problem) bool { return p.Code == CodeSymlink && p.Path == name })
		read := slices.ContainsFunc(set.Switches["a"].Definitions, func(d Definition) bool { return d.Path == name })
		if problem == tt.resolve || read != tt.resolve {
			t.Errorf("%s -> %s: problem=%v read=%v", name, tt.link, problem, read)
		}
	}
}

func TestDetect_RefInVariantsAndMetadata_FLG2(t *testing.T) {
	t.Parallel()
	for name, flag := range map[string]string{
		"variants": `{"state":"ENABLED","variants":{"on":{"$ref":"e"},"off":{"$ref":"e"}},"defaultVariant":"off"}`,
		"metadata": `{"state":"ENABLED","variants":{"on":true,"off":false},"defaultVariant":"off","metadata":{"$ref":"e"}}`,
	} {
		set := detectFiles(t, map[string]string{"a.json": `{"$evaluators":{"e":{"x":1}},"flags":{"a":` + flag + `}}`})
		found := slices.ContainsFunc(set.Problems, func(p Problem) bool { return strings.HasSuffix(p.Pointer, "/$ref") })
		if !found {
			t.Errorf("%s: problems = %+v", name, set.Problems)
		}
	}
}

func TestDetect_YAMLMarshalCharge_FLG2(t *testing.T) {
	t.Parallel()
	file := "flags:\n  a:\n    state: ENABLED\n    variants: {\"on\": true, \"off\": false}\n    defaultVariant: \"off\"\n"
	js, ok := yamlToJSON([]byte(file))
	if !ok {
		t.Fatal("the file does not convert")
	}
	need := len(file) + len(js)
	for limit, wantErr := range map[int]bool{need - 1: true, need: false} {
		lim := DefaultLimits()
		lim.MaxTotalBytes = limit
		_, err := Detect(t.Context(), mkTree(t, map[string]string{"a.yaml": file}, nil), lim)
		if errors.Is(err, ErrTooLarge) != wantErr {
			t.Errorf("limit %d: err = %v, want too large = %v", limit, err, wantErr)
		}
	}
}

func TestCanonicalMatchesEffective_FLG2(t *testing.T) {
	t.Parallel()
	canonical := func(js string) map[string]any {
		doc, perr := parseJSON([]byte(js), 64)
		if perr != nil {
			t.Fatal(perr)
		}
		m, _ := doc.(map[string]any)
		return m
	}
	flag := `{"state":"ENABLED","variants":{"on":true,"off":false},"defaultVariant":"off"}`
	doc := `{"flags":{"a":` + flag + `}}`
	tests := []struct {
		name  string
		other string
		match bool
	}{
		{"same", doc, true},
		{"numbers", `{"flags":{"a":{"state":"ENABLED","variants":{"x":1,"y":2.50},"defaultVariant":"x"}}}`, true},
		{"state", `{"flags":{"a":{"state":"DISABLED","variants":{"on":true,"off":false},"defaultVariant":"off"}}}`, false},
		{"default", `{"flags":{"a":{"state":"ENABLED","variants":{"on":true,"off":false},"defaultVariant":"on"}}}`, false},
		{"variants", `{"flags":{"a":{"state":"ENABLED","variants":{"on":true,"off":true},"defaultVariant":"off"}}}`, false},
		{"targeting", `{"flags":{"a":{"state":"ENABLED","variants":{"on":true,"off":false},"defaultVariant":"off","targeting":{}}}}`, false},
		{"extra flag", `{"flags":{"a":` + flag + `,"b":` + flag + `}}`, false},
		{"other key", `{"flags":{"b":` + flag + `}}`, false},
		{"flagd would not load it", `{"flags":{"a":{"state":"ENABLED","variants":{"on":true},"defaultVariant":"zz"}}}`, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := canonicalMatchesEffective(canonical(doc), tt.other); tt.name != "numbers" && got != tt.match {
				t.Errorf("match = %v, want %v", got, tt.match)
			}
			if tt.name == "numbers" && !canonicalMatchesEffective(canonical(tt.other), tt.other) {
				t.Error("numbers differ between the strict parse and flagd's")
			}
		})
	}
}

func TestCompare_RemovedSorting_FLG2(t *testing.T) {
	t.Parallel()
	both := func(key string) map[string]string {
		return map[string]string{"b.flagd.json": flagdFile(map[string]string{key: offFlag}), "a.flagd.json": flagdFile(map[string]string{key: offFlag})}
	}
	base := map[string]string{
		"b.flagd.json": flagdFile(map[string]string{"z": offFlag, "m": offFlag}), "a.flagd.json": flagdFile(map[string]string{"z": offFlag, "m": offFlag}),
	}
	_ = both
	got := compareFiles(t, base, map[string]string{})
	var order []string
	for _, c := range got.Removed {
		order = append(order, c.Key+"@"+c.Path)
	}
	want := []string{"m@a.flagd.json", "m@b.flagd.json", "z@a.flagd.json", "z@b.flagd.json"}
	if !slices.Equal(order, want) {
		t.Errorf("removed = %v, want %v", order, want)
	}
}

func TestDetect_NoFalsePositives_FLG2(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"package.json":             `{"name":"x","scripts":{"build":"tsc -p tsconfig.json && node scripts/flags.js"},"dependencies":{"react":"^18"}}`,
		"tsconfig.json":            "{\n  // comment\n  \"compilerOptions\": {\"target\": \"es2020\"},\n}\n",
		".vscode/settings.json":    `{"go.buildFlags":["-tags=integration"],"go.testFlags":["-race"]}`,
		"k8s/cm-json.yaml":         "kind: ConfigMap\ndata:\n  config.json: |\n    {\"logLevel\": \"info\", \"flags\": [\"--verbose\"]}\n",
		"k8s/cm-yaml.yaml":         "kind: ConfigMap\ndata:\n  app.yaml: |\n    server:\n      port: 8080\n    flags:\n      newUI: true\n",
		"k8s/cm-codecov.yaml":      "kind: ConfigMap\ndata:\n  settings: |\n    flags:\n      - experimental\n",
		"helm/values-flags.yaml":   "flags:\n  verbose: true\n  logLevel: debug\n",
		"docker-compose.yml":       "services:\n  web:\n    command: [\"flagd\", \"start\", \"--uri\", \"file:./flags.json\"]\n  db: &db\n    image: postgres\n  db2:\n    <<: *db\n    healthcheck: {interval: 1.5s, retries: 3.0}\n",
		".github/workflows/ci.yml": "jobs:\n  build:\n    steps:\n      - uses: codecov/codecov-action@v4\n        with:\n          flags: unittests\n",
		"codecov.yml":              "flags:\n  unit:\n    paths: [src/]\n    carryforward: true\n",
		"openapi.yaml":             "components:\n  schemas:\n    Thing:\n      properties:\n        flags:\n          type: integer\n",
		"i18n/en.json":             `{"menu.flags":"Flags","help.flags":"Flags:\n  -h, --help   help for app"}`,
		"i18n/en2.json":            `{"flags":"Flags","settings":"Settings"}`,
		"main.tf.json":             `{"variable":{"flags":{"type":"list(string)","default":[]}}}`,
		".goreleaser.yaml":         "builds:\n  - flags:\n      - -trimpath\n",
		"plugin/completion.yaml":   "name: env\nflags:\n- global\n",
		"flags-config.json":        `{"flags":{"darkMode":true,"newCheckout":false},"version":2}`,
		"compile_commands.json":    `[{"directory":"/x","command":"cc -O2 -c a.c","file":"a.c"}]`,
	}
	for name, data := range cases {
		set := detectFiles(t, map[string]string{name: data})
		if len(set.Problems) != 0 || len(set.Switches) != 0 {
			t.Errorf("%s: problems = %+v, switches = %v", name, set.Problems, set.Keys())
		}
	}
}
