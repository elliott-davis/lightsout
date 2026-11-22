// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

package switches

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/elliott-davis/lightsout/internal/forge/gittree"
	"github.com/elliott-davis/lightsout/internal/yamlsafe"
)

// spliceFile builds a flagd file in which an $evaluators name, spliced in by flagd's transposeEvaluators (a string
// replacement of {"$ref":"name"} in the marshalled flags), swaps the variants of flag "old" for those of flag "zz".
// It ports the proof of concept that loads in flagd core v0.19.3.
func spliceFile(t *testing.T) string {
	t.Helper()
	flags := `{"old":{"state":"ENABLED","variants":{"on":true,"off":false},"defaultVariant":"off","metadata":{"$ref":"a"}},` +
		`"zz":{"state":"ENABLED","variants":{"on":false,"off":true},"defaultVariant":"on","metadata":{"k":"v"}}}`
	var v any
	if err := json.Unmarshal([]byte(`{"flags":`+flags+`}`), &v); err != nil {
		t.Fatal(err)
	}
	norm, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	s := string(norm)
	start := strings.Index(s, `{"$ref":"`) + len(`{"$ref":"`)
	end := strings.Index(s, `"k":"v"}`) + len(`"k":"v`)
	return `{"$evaluators":{` + quote(s[start:end]) + `:{"x":1}},"flags":` + flags + `}`
}

func TestDetect_EvaluatorSplice_FLG2(t *testing.T) {
	t.Parallel()
	doc := spliceFile(t)
	if !strings.Contains(doc, `\"variants\"`) {
		t.Fatalf("the splice name was not built: %s", doc)
	}
	head := detectFiles(t, map[string]string{"src/flagd/demo.flagd.json": doc})
	if !hasCode(head, CodeSchema) {
		t.Fatalf("problems = %+v", head.Problems)
	}
	for _, base := range []map[string]string{nil, flagd1(offFlag)} {
		if got := Compare(detectFiles(t, base), head).Verdict; got != VerdictError {
			t.Errorf("verdict = %s, want error", got)
		}
	}
}

func TestDetect_DefaultVariantEmpty_FLG2(t *testing.T) {
	t.Parallel()
	for name, dv := range map[string]string{"empty string": `""`, "null": `null`, "absent": ``} {
		body := `{"state":"ENABLED","variants":{"":false,"on":true}`
		if dv != "" {
			body += `,"defaultVariant":` + dv
		}
		body += `}`
		set := detectFiles(t, map[string]string{"a.flagd.json": flagdFile(map[string]string{"evil": body})})
		sw := set.Switches["evil"]
		if len(set.Problems) != 0 || sw.Status() != StatusUnproven || sw.Definitions[0].HasDefaultVariant || sw.Definitions[0].HasDefault {
			t.Errorf("%s: status %s, def %+v, problems %+v", name, sw.Status(), sw.Definitions[0], set.Problems)
		}
	}
	set := detectFiles(t, map[string]string{"a.flagd.json": flagdFile(map[string]string{"s": offFlag})})
	if d := set.Switches["s"].Definitions[0]; !d.HasDefaultVariant || d.DefaultVariant != "off" || !d.HasDefault {
		t.Errorf("definition = %+v", d)
	}
}

func TestDetect_ProbeBounds_FLG2(t *testing.T) {
	t.Parallel()
	t.Run("an alias file is probed in bounded time", func(t *testing.T) {
		t.Parallel()
		inner := `{"flags":{},"p":"` + strings.Repeat("x", 500_000) + `"}`
		y := "a: &s '" + inner + "'\nb: [" + strings.TrimSuffix(strings.Repeat("*s,", 150_000), ",") + "]\n"
		start := time.Now()
		set, err := Detect(t.Context(), mkTree(t, map[string]string{"a.yaml": y}, nil), DefaultLimits())
		if err != nil {
			t.Fatal(err)
		}
		if d := time.Since(start); d > 10*time.Second {
			t.Errorf("took %v, problems %d", d, len(set.Problems))
		}
		if !hasCode(set, CodeTooLarge) || Compare(detectFiles(t, nil), set).Verdict != VerdictError {
			t.Errorf("problems = %+v", set.Problems)
		}
	})
	t.Run("deep json is bounded and a problem", func(t *testing.T) {
		t.Parallel()
		start := time.Now()
		set := detectFiles(t, map[string]string{"a.json": nest(9990)})
		if !hasCode(set, CodeTooDeep) || time.Since(start) > 10*time.Second {
			t.Errorf("problems = %+v, took %v", set.Problems, time.Since(start))
		}
	})
	t.Run("a context cancelled inside a large file stops the walk", func(t *testing.T) {
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
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		if _, err := Detect(ctx, mkTree(t, map[string]string{"a.json": b.String()}, nil), DefaultLimits()); err == nil {
			t.Error("a cancelled scan returned no error")
		}
	})
}

func TestDetect_Extension_FLG2(t *testing.T) {
	t.Parallel()
	for name, want := range map[string]bool{
		"a.json": true, "a.JSON": true, "a.js-on": true, "a.yaml": true, "a.YML": true, "a.y-m-l": true,
		".json": true, "a.txt": false, "a": false, "a.jsonx": false, "json": false, "a.json.bak": false,
	} {
		if got := candidateSuffix(name); got != want {
			t.Errorf("candidateSuffix(%q) = %v, want %v", name, got, want)
		}
	}
	for name, want := range map[string]bool{"a.json": false, "a.JSON": false, "a.js-on": false, "a.yaml": true, "a.YML": true} {
		if got := isYAML(name); got != want {
			t.Errorf("isYAML(%q) = %v, want %v", name, got, want)
		}
	}
	// Duplicate keys are an error in YAML and a problem in JSON, so only a JSON decode reports this one.
	set := detectFiles(t, map[string]string{"a.JSON": `{"flags":{"a":` + offFlag + `,"a":` + offFlag + `}}`})
	if !hasCode(set, CodeDuplicateKey) {
		t.Errorf("problems = %+v", set.Problems)
	}
}

func TestYAMLCode_FLG2(t *testing.T) {
	t.Parallel()
	for in, want := range map[yamlsafe.Code]Code{
		yamlsafe.CodeTooLarge: CodeTooLarge, yamlsafe.CodeSyntax: CodeSyntax,
		yamlsafe.CodeUnsafeYAML: CodeSchema, yamlsafe.CodeSchema: CodeSchema, "other": CodeSchema,
	} {
		if got := yamlCode(in); got != want {
			t.Errorf("yamlCode(%s) = %s, want %s", in, got, want)
		}
	}
}

func TestSwitch_ManifestConflicts_FLG2(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		a, b     string
		conflict bool
	}{
		{"same", manifestFile("s", "boolean", "false"), manifestFile("s", "boolean", "false"), false},
		{"different defaults", manifestFile("s", "boolean", "false"), manifestFile("s", "boolean", "true"), true},
		{"different types", manifestFile("s", "boolean", "false"), manifestFile("s", "string", `"x"`), true},
		{"integer and float agree", manifestFile("s", "integer", "1"), manifestFile("s", "float", "1"), false},
		{"integer and float differ", manifestFile("s", "integer", "1"), manifestFile("s", "float", "2"), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			set := detectFiles(t, map[string]string{"a/flags.json": tt.a, "b/flags.json": tt.b})
			if len(set.Problems) != 0 {
				t.Fatalf("problems: %+v", set.Problems)
			}
			if got := set.Switches["s"].Status() == StatusConflicting; got != tt.conflict {
				t.Errorf("conflicting = %v, want %v (%s)", got, tt.conflict, set.Switches["s"].Status())
			}
		})
	}
}

func TestNewRecord_Sources_FLG3(t *testing.T) {
	t.Parallel()
	sw := Switch{Key: "k", Definitions: []Definition{
		{Path: "b.json", Kind: KindFlagd}, {Path: "a.json", Kind: KindFlagd, Description: "first"}, {Path: "b.json", Kind: KindManifest},
	}}
	rec := NewRecord("o/r", sw, "rev", time.Unix(0, 0), "me")
	if diff := cmp.Diff([]string{"a.json", "b.json"}, rec.Sources); diff != "" {
		t.Errorf("sources (-want +got):\n%s", diff)
	}
	if rec.Description != "first" {
		t.Errorf("description = %q", rec.Description)
	}
}

func TestCompare_RuntimeSignature_FLG2(t *testing.T) {
	t.Parallel()
	withFile := func(extra, flag string) map[string]string {
		return map[string]string{"src/flagd/demo.flagd.json": `{` + extra + `"flags":{"old":` + flag + `}}`}
	}
	onOther := `{"state":"ENABLED","variants":{"on":true,"off":false,"more":true},"defaultVariant":"on"}`
	tests := []struct {
		name    string
		base    map[string]string
		head    map[string]string
		verdict Verdict
	}{
		{"on switch with changed variants blocks", flagd1(onFlag), flagd1(onOther), VerdictBlocked},
		{"on switch with the same definition passes", flagd1(onFlag), flagd1(onFlag), VerdictPass},
		{"description change on an on switch passes", flagd1(onFlag), flagd1(`{"state":"ENABLED","variants":{"on":true,"off":false},"defaultVariant":"on","description":"d"}`), VerdictPass},
		{"evaluators added to an off switch pass", withFile("", offFlag), withFile(`"$evaluators":{"e":{"x":1}},`, offFlag), VerdictPass},
		{"evaluators changed under an on switch block", withFile(`"$evaluators":{"e":{"x":1}},`, onFlag), withFile(`"$evaluators":{"e":{"x":2}},`, onFlag), VerdictBlocked},
		{"flagSetId changed under an on switch blocks", withFile(`"metadata":{"flagSetId":"a"},`, onFlag), withFile(`"metadata":{"flagSetId":"b"},`, onFlag), VerdictBlocked},
		{"flagSetId changed under an off switch passes", withFile(`"metadata":{"flagSetId":"a"},`, offFlag), withFile(`"metadata":{"flagSetId":"b"},`, offFlag), VerdictPass},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := compareFiles(t, tt.base, tt.head); got.Verdict != tt.verdict {
				t.Errorf("verdict = %s, want %s (%+v)", got.Verdict, tt.verdict, got)
			}
		})
	}
}

func TestCompare_PerPathRemoval_FLG2(t *testing.T) {
	t.Parallel()
	one := func(path string) map[string]string {
		return map[string]string{path: flagdFile(map[string]string{"old": offFlag})}
	}
	t.Run("moved to another file", func(t *testing.T) {
		t.Parallel()
		got := compareFiles(t, one("deployed/demo.flagd.json"), one("undeployed/demo.flagd.json"))
		want := []Change{{Key: "old", Path: "deployed/demo.flagd.json", Status: StatusDefaultOff, BaseStatus: StatusDefaultOff, Reason: ReasonRemoval}}
		if got.Verdict != VerdictBlocked || !cmp.Equal(got.Removed, want) {
			t.Errorf("comparison = %+v", got)
		}
	})
	t.Run("one of two sources removed", func(t *testing.T) {
		t.Parallel()
		both := map[string]string{"a.flagd.json": flagdFile(map[string]string{"old": offFlag}), "b.flagd.json": flagdFile(map[string]string{"old": offFlag})}
		got := compareFiles(t, both, one("a.flagd.json"))
		if got.Verdict != VerdictBlocked || len(got.Removed) != 1 || got.Removed[0].Path != "b.flagd.json" {
			t.Errorf("comparison = %+v", got)
		}
	})
	t.Run("a source added is not a removal", func(t *testing.T) {
		t.Parallel()
		both := map[string]string{"a.flagd.json": flagdFile(map[string]string{"old": offFlag}), "b.flagd.json": flagdFile(map[string]string{"old": offFlag})}
		if got := compareFiles(t, one("a.flagd.json"), both); got.Verdict != VerdictPass || len(got.Removed) != 0 {
			t.Errorf("comparison = %+v", got)
		}
	})
}

func TestCompare_OpaqueChange_FLG2(t *testing.T) {
	t.Parallel()
	demo := blob(demoPath, flagdFile(map[string]string{"old": offFlag}))
	link := func(target string) gittree.Entry {
		return gittree.Entry{Path: "alias", Mode: gittree.ModeSymlink, Data: []byte(target)}
	}
	build := func(t *testing.T, entries ...gittree.Entry) Set {
		t.Helper()
		return detectTree(t, mkEntries(t, entries))
	}
	dirs := []gittree.Entry{blob("one/x.txt", "x"), blob("two/x.txt", "x"), demo}
	t.Run("same target", func(t *testing.T) {
		t.Parallel()
		e := append(slices.Clone(dirs), link("one"))
		if c := Compare(build(t, e...), build(t, e...)); c.Verdict != VerdictPass {
			t.Errorf("comparison = %+v", c)
		}
	})
	t.Run("changed target", func(t *testing.T) {
		t.Parallel()
		c := Compare(build(t, append(slices.Clone(dirs), link("one"))...), build(t, append(slices.Clone(dirs), link("two"))...))
		if c.Verdict != VerdictBlocked || len(c.Opaque) != 1 || c.Opaque[0] != "alias" {
			t.Errorf("comparison = %+v", c)
		}
	})
	t.Run("a gitlink replaced by a symlink", func(t *testing.T) {
		t.Parallel()
		c := Compare(build(t, demo, gitlink("alias")), build(t, demo, gittree.Entry{Path: "alias", Mode: gittree.ModeSymlink, Data: []byte("/x")}))
		if c.Verdict != VerdictBlocked {
			t.Errorf("comparison = %+v", c)
		}
	})
	t.Run("a gitlink present at both is unchanged", func(t *testing.T) {
		t.Parallel()
		if c := Compare(build(t, demo, gitlink("alias")), build(t, demo, gitlink("alias"))); c.Verdict != VerdictPass {
			t.Errorf("comparison = %+v", c)
		}
	})
}
