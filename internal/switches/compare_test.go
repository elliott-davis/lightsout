// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

package switches

import (
	"slices"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/elliott-davis/lightsout/internal/forge/gittree"
)

func compareFiles(t *testing.T, base, head map[string]string) Comparison {
	t.Helper()
	return Compare(detectFiles(t, base), detectFiles(t, head))
}

const demoPath = "src/flagd/demo.flagd.json"

func flagd1(body string) map[string]string {
	return map[string]string{"src/flagd/demo.flagd.json": flagdFile(map[string]string{"old": body})}
}

func TestCompare_NewSwitch_FLG2(t *testing.T) {
	t.Parallel()
	flag := func(state, variants, def, extra string) string {
		s := `{"state":"` + state + `","variants":` + variants + extra
		if def != "" {
			s += `,"defaultVariant":` + def
		}
		return s + `}`
	}
	boolVariants := `{"on":true,"off":false}`
	offManifest := manifestFile("s", "boolean", "false")
	f := func(body string) map[string]string {
		return map[string]string{"f.flagd.json": flagdFile(map[string]string{"s": body})}
	}
	tests := []struct {
		name    string
		files   map[string]string
		verdict Verdict
		status  Status
		reason  Reason
	}{
		{"off in flagd and manifest passes", map[string]string{"f.flagd.json": flagdFile(map[string]string{"s": offFlag}), "flags.json": offManifest}, VerdictPass, StatusDefaultOff, ""},
		{"flagd only passes", f(offFlag), VerdictPass, StatusDefaultOff, ""},
		{"manifest only is unproven", map[string]string{"flags.json": offManifest}, VerdictBlocked, StatusUnproven, ReasonNewNotOff},
		{"defaultVariant on", f(flag("ENABLED", boolVariants, `"on"`, "")), VerdictBlocked, StatusDefaultOn, ReasonNewNotOff},
		{"defaultVariant missing", f(flag("ENABLED", boolVariants, "", "")), VerdictBlocked, StatusUnproven, ReasonNewNotOff},
		{"defaultVariant null", f(flag("ENABLED", boolVariants, "null", "")), VerdictBlocked, StatusUnproven, ReasonNewNotOff},
		{"disabled", f(flag("DISABLED", boolVariants, `"off"`, "")), VerdictBlocked, StatusUnproven, ReasonNewNotOff},
		{"targeting present", f(flag("ENABLED", boolVariants, `"off"`, `,"targeting":{"if":[true,"on","off"]}`)), VerdictBlocked, StatusUnproven, ReasonNewNotOff},
		{"empty targeting still blocks", f(flag("ENABLED", boolVariants, `"off"`, `,"targeting":{}`)), VerdictBlocked, StatusUnproven, ReasonNewNotOff},
		{"null targeting still blocks", f(flag("ENABLED", boolVariants, `"off"`, `,"targeting":null`)), VerdictBlocked, StatusUnproven, ReasonNewNotOff},
		{"non-boolean", f(flag("ENABLED", `{"a":"x","b":"y"}`, `"a"`, "")), VerdictBlocked, StatusNotBoolean, ReasonNewNotOff},
		{"manifest default true", map[string]string{"flags.json": manifestFile("s", "boolean", "true")}, VerdictBlocked, StatusDefaultOn, ReasonNewNotOff},
		{"manifest on, flagd off", map[string]string{"f.flagd.json": flagdFile(map[string]string{"s": offFlag}), "flags.json": manifestFile("s", "boolean", "true")}, VerdictBlocked, StatusConflicting, ReasonNewNotOff},
		{"manifest of another type", map[string]string{"f.flagd.json": flagdFile(map[string]string{"s": offFlag}), "flags.json": manifestFile("s", "string", `"off"`)}, VerdictBlocked, StatusConflicting, ReasonNewNotOff},
		{"manifest non-boolean", map[string]string{"flags.json": manifestFile("s", "string", `"off"`)}, VerdictBlocked, StatusNotBoolean, ReasonNewNotOff},
		{"two flagd files disagree", map[string]string{
			"a.flagd.json": flagdFile(map[string]string{"s": offFlag}), "b.flagd.json": flagdFile(map[string]string{"s": onFlag}),
		}, VerdictBlocked, StatusConflicting, ReasonNewNotOff},
		{"two flagd files agree", map[string]string{
			"a.flagd.json": flagdFile(map[string]string{"s": offFlag}), "b.flagd.json": flagdFile(map[string]string{"s": offFlag}),
		}, VerdictPass, StatusDefaultOff, ""},
		{"invalid definition", f(flag("ENABLED", boolVariants, `"off"`, `,"metadata":{"a":[1]}`)), VerdictError, StatusInvalid, ReasonNewNotOff},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			head := detectFiles(t, tt.files)
			got := Compare(detectFiles(t, nil), head)
			if got.Verdict != tt.verdict {
				t.Errorf("verdict = %s, want %s (problems %+v)", got.Verdict, tt.verdict, head.Problems)
			}
			if tt.verdict == VerdictError {
				if len(got.New) != 0 || head.Switches["s"].Status() != tt.status {
					t.Errorf("new = %+v, status %s", got.New, head.Switches["s"].Status())
				}
				return
			}
			if want := []Change{{Key: "s", Status: tt.status, Reason: tt.reason}}; !cmp.Equal(got.New, want) {
				t.Errorf("new = %+v, want %+v", got.New, want)
			}
		})
	}
}

func TestCompare_FlagdSignature_FLG2(t *testing.T) {
	t.Parallel()
	mk := func(extra string) string {
		return `{"state":"ENABLED","variants":{"on":true,"off":false},"defaultVariant":"off"` + extra + `}`
	}
	tests := []struct {
		name     string
		base     string // the first file's flag; mk("") when empty
		other    string
		conflict bool
	}{
		{"same", "", mk(""), false},
		{"description only", "", mk(`,"description":"other words"`), false},
		{"variants", "", `{"state":"ENABLED","variants":{"on":true,"off":false,"extra":true},"defaultVariant":"off"}`, true},
		{"variant values", "", `{"state":"ENABLED","variants":{"on":false,"off":false},"defaultVariant":"off"}`, true},
		{"state", "", `{"state":"DISABLED","variants":{"on":true,"off":false},"defaultVariant":"off"}`, true},
		{"defaultVariant", "", `{"state":"ENABLED","variants":{"on":true,"off":false},"defaultVariant":"on"}`, true},
		{"defaultVariant missing", "", `{"state":"ENABLED","variants":{"on":true,"off":false}}`, true},
		{"type", "", `{"state":"ENABLED","variants":{"on":1,"off":0},"defaultVariant":"off"}`, true},
		{"targeting added", "", mk(`,"targeting":{"a":1}`), true},
		{"targeting differs", mk(`,"targeting":{"a":1}`), mk(`,"targeting":{"a":2}`), true},
		{"metadata added", "", mk(`,"metadata":{"a":1}`), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			base := tt.base
			if base == "" {
				base = mk("")
			}
			set := detectFiles(t, map[string]string{
				"a.flagd.json": flagdFile(map[string]string{"s": base}), "b.flagd.json": flagdFile(map[string]string{"s": tt.other}),
			})
			if len(set.Problems) != 0 {
				t.Fatalf("problems: %+v", set.Problems)
			}
			if got := set.Switches["s"].Status() == StatusConflicting; got != tt.conflict {
				t.Errorf("conflicting = %v, want %v", got, tt.conflict)
			}
		})
	}
}

func TestCompatible_FLG2(t *testing.T) {
	t.Parallel()
	nums := []Type{TypeNumber, TypeInteger, TypeFloat}
	for _, a := range nums {
		for _, b := range nums {
			if !compatible(a, b) {
				t.Errorf("%s and %s should be compatible", a, b)
			}
		}
		for _, other := range []Type{TypeBoolean, TypeString, TypeObject} {
			if compatible(a, other) || compatible(other, a) {
				t.Errorf("%s and %s should not be compatible", a, other)
			}
		}
	}
	for _, a := range []Type{TypeBoolean, TypeString, TypeObject} {
		for _, b := range []Type{TypeBoolean, TypeString, TypeObject} {
			if got := compatible(a, b); got != (a == b) {
				t.Errorf("compatible(%s, %s) = %v", a, b, got)
			}
		}
	}
}

func TestCompare_ExistingSwitches_FLG2(t *testing.T) {
	t.Parallel()
	base := flagd1(offFlag)
	manifestOld := func(v string) map[string]string {
		m := flagd1(offFlag)
		m["flags.json"] = manifestFile("old", "boolean", v)
		return m
	}
	tests := []struct {
		name    string
		base    map[string]string
		head    map[string]string
		verdict Verdict
		changed []Change
		removed []Change
	}{
		{"unchanged", base, base, VerdictPass, nil, nil},
		{"description only is not a change", base, flagd1(`{"state":"ENABLED","variants":{"on":true,"off":false},"defaultVariant":"off","description":"new words"}`), VerdictPass, nil, nil},
		{"existing default-on does not block", flagd1(onFlag), flagd1(onFlag), VerdictPass, nil, nil},
		{"flip to on", base, flagd1(onFlag), VerdictBlocked, []Change{{Key: "old", Status: StatusDefaultOn, BaseStatus: StatusDefaultOff, Reason: ReasonActivation}}, nil},
		{"targeting added", base, flagd1(`{"state":"ENABLED","variants":{"on":true,"off":false},"defaultVariant":"off","targeting":{"if":[true,"on","off"]}}`), VerdictBlocked, []Change{{Key: "old", Status: StatusUnproven, BaseStatus: StatusDefaultOff, Reason: ReasonActivation}}, nil},
		{"disabled", base, flagd1(`{"state":"DISABLED","variants":{"on":true,"off":false},"defaultVariant":"off"}`), VerdictBlocked, []Change{{Key: "old", Status: StatusUnproven, BaseStatus: StatusDefaultOff, Reason: ReasonActivation}}, nil},
		{"default variant dropped", base, flagd1(`{"state":"ENABLED","variants":{"on":true,"off":false}}`), VerdictBlocked, []Change{{Key: "old", Status: StatusUnproven, BaseStatus: StatusDefaultOff, Reason: ReasonActivation}}, nil},
		{"manifest added that disagrees", base, manifestOld("true"), VerdictBlocked, []Change{{Key: "old", Status: StatusConflicting, BaseStatus: StatusDefaultOff, Reason: ReasonActivation}}, nil},
		{"manifest added that agrees", base, manifestOld("false"), VerdictPass, []Change{{Key: "old", Status: StatusDefaultOff, BaseStatus: StatusDefaultOff}}, nil},
		{"metadata change is reported", base, flagd1(`{"state":"ENABLED","variants":{"on":true,"off":false},"defaultVariant":"off","metadata":{"a":1}}`), VerdictPass, []Change{{Key: "old", Status: StatusDefaultOff, BaseStatus: StatusDefaultOff}}, nil},
		{"on to off is reported only", flagd1(onFlag), base, VerdictPass, []Change{{Key: "old", Status: StatusDefaultOff, BaseStatus: StatusDefaultOn}}, nil},
		{"removed entirely", base, map[string]string{}, VerdictBlocked, nil, []Change{{Key: "old", Path: demoPath, Status: StatusDefaultOff, Reason: ReasonRemoval}}},
		{"removed from flagd but kept in the manifest", manifestOld("false"), map[string]string{"flags.json": manifestFile("old", "boolean", "false")}, VerdictBlocked, nil, []Change{{Key: "old", Path: demoPath, Status: StatusUnproven, BaseStatus: StatusDefaultOff, Reason: ReasonRemoval}}},
		{"default-on removal also blocks", flagd1(onFlag), map[string]string{}, VerdictBlocked, nil, []Change{{Key: "old", Path: demoPath, Status: StatusDefaultOn, Reason: ReasonRemoval}}},
		{"manifest-only switch removed is reported only", map[string]string{"flags.json": manifestFile("old", "boolean", "false")}, map[string]string{}, VerdictPass, nil, []Change{{Key: "old", Status: StatusUnproven}}},
		{"manifest-only switch unchanged", map[string]string{"flags.json": manifestFile("old", "boolean", "false")}, map[string]string{"flags.json": manifestFile("old", "boolean", "false")}, VerdictPass, nil, nil},
		{"manifest-only switch changed is reported only", map[string]string{"flags.json": manifestFile("old", "boolean", "false")}, map[string]string{"flags.json": manifestFile("old", "boolean", "true")}, VerdictPass, []Change{{Key: "old", Status: StatusDefaultOn, BaseStatus: StatusUnproven}}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := compareFiles(t, tt.base, tt.head)
			if got.Verdict != tt.verdict {
				t.Errorf("verdict = %s, want %s", got.Verdict, tt.verdict)
			}
			if diff := cmp.Diff(tt.changed, got.StatusChanged); diff != "" {
				t.Errorf("status changed (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(tt.removed, got.Removed); diff != "" {
				t.Errorf("removed (-want +got):\n%s", diff)
			}
			if len(got.New) != 0 {
				t.Errorf("new = %+v", got.New)
			}
		})
	}
}

func TestCompare_ManifestKeyBecomesFlagd_FLG2(t *testing.T) {
	t.Parallel()
	base := map[string]string{"flags.json": manifestFile("s", "boolean", "false")}
	t.Run("off passes as a new switch", func(t *testing.T) {
		t.Parallel()
		head := map[string]string{"flags.json": base["flags.json"], "a.flagd.json": flagdFile(map[string]string{"s": offFlag})}
		got := compareFiles(t, base, head)
		if got.Verdict != VerdictPass || len(got.New) != 1 || got.New[0].Status != StatusDefaultOff {
			t.Errorf("comparison = %+v", got)
		}
	})
	t.Run("on is blocked, not a staged bypass", func(t *testing.T) {
		t.Parallel()
		head := map[string]string{"a.flagd.json": flagdFile(map[string]string{"s": onFlag})}
		got := compareFiles(t, base, head)
		if got.Verdict != VerdictBlocked {
			t.Errorf("comparison = %+v", got)
		}
	})
}

func TestCompare_Reporting_FLG2(t *testing.T) {
	t.Parallel()
	files := func(flags map[string]string) map[string]string {
		return map[string]string{"f.flagd.json": flagdFile(flags)}
	}
	t.Run("lists are reported and sorted", func(t *testing.T) {
		t.Parallel()
		base := files(map[string]string{"zeta": onFlag, "alpha": onFlag, "flip": onFlag, "same": onFlag})
		head := files(map[string]string{"flip": offFlag, "same": onFlag, "brand": offFlag, "also": offFlag})
		got := compareFiles(t, base, head)
		want := Comparison{
			New:           []Change{{Key: "also", Status: StatusDefaultOff}, {Key: "brand", Status: StatusDefaultOff}},
			Removed:       []Change{{Key: "alpha", Path: "f.flagd.json", Status: StatusDefaultOn, Reason: ReasonRemoval}, {Key: "zeta", Path: "f.flagd.json", Status: StatusDefaultOn, Reason: ReasonRemoval}},
			StatusChanged: []Change{{Key: "flip", Status: StatusDefaultOff, BaseStatus: StatusDefaultOn}},
			Verdict:       VerdictBlocked,
		}
		if diff := cmp.Diff(want, got); diff != "" {
			t.Errorf("comparison (-want +got):\n%s", diff)
		}
	})
	t.Run("a problem at the base is an error", func(t *testing.T) {
		t.Parallel()
		base := map[string]string{"a.json": `{"flags":{"a":` + offFlag + `,"a":` + offFlag + `}}`}
		if got := compareFiles(t, base, files(map[string]string{"s": offFlag})).Verdict; got != VerdictError {
			t.Errorf("verdict = %s", got)
		}
	})
	t.Run("a problem at the head is an error even with no new switch", func(t *testing.T) {
		t.Parallel()
		head := map[string]string{"a.json": `{"flags":{"a":` + offFlag + `,"a":` + offFlag + `}}`}
		if got := compareFiles(t, nil, head).Verdict; got != VerdictError {
			t.Errorf("verdict = %s", got)
		}
	})
	t.Run("a set not made by Detect is an error", func(t *testing.T) {
		t.Parallel()
		good := detectFiles(t, flagd1(offFlag))
		for name, c := range map[string]Comparison{
			"zero head": Compare(good, Set{}), "zero base": Compare(Set{}, good), "both zero": Compare(Set{}, Set{}),
			"hand-built": Compare(good, Set{Switches: good.Switches}),
		} {
			if c.Verdict != VerdictError {
				t.Errorf("%s: verdict = %s", name, c.Verdict)
			}
		}
	})
	t.Run("new lists are sorted", func(t *testing.T) {
		t.Parallel()
		got := compareFiles(t, nil, files(map[string]string{"c": offFlag, "a": offFlag, "b": offFlag}))
		if !slices.IsSortedFunc(got.New, func(a, b Change) int { return strings.Compare(a.Key, b.Key) }) || len(got.New) != 3 {
			t.Errorf("new = %+v", got.New)
		}
	})
}

func TestCompare_OpaqueEntries_FLG2(t *testing.T) {
	t.Parallel()
	demo := blob("src/flagd/demo.flagd.json", flagdFile(map[string]string{"old": offFlag}))
	detect := func(t *testing.T, entries ...gittree.Entry) Set {
		t.Helper()
		return detectTree(t, mkEntries(t, entries))
	}
	base := func(t *testing.T) Set {
		t.Helper()
		return detect(t, demo)
	}
	t.Run("new gitlink blocks", func(t *testing.T) {
		t.Parallel()
		c := Compare(base(t), detect(t, demo, gitlink("vendor/flags")))
		if c.Verdict != VerdictBlocked || !slices.Equal(c.Opaque, []string{"vendor/flags"}) {
			t.Errorf("comparison = %+v", c)
		}
	})
	t.Run("unchanged gitlink does not block", func(t *testing.T) {
		t.Parallel()
		both := []gittree.Entry{demo, gitlink("vendor/flags")}
		if c := Compare(detect(t, both...), detect(t, both...)); c.Verdict != VerdictPass || len(c.Opaque) != 0 {
			t.Errorf("comparison = %+v", c)
		}
	})
	t.Run("directory with sources replaced by a gitlink", func(t *testing.T) {
		t.Parallel()
		c := Compare(base(t), detect(t, gitlink("src/flagd")))
		if c.Verdict != VerdictBlocked || !slices.Equal(c.Opaque, []string{"src/flagd"}) {
			t.Errorf("comparison = %+v", c)
		}
	})
	t.Run("directory with sources replaced by a symlink", func(t *testing.T) {
		t.Parallel()
		c := Compare(base(t), detect(t, gittree.Entry{Path: "src/flagd", Mode: gittree.ModeSymlink, Data: []byte("/etc/otel/flagd")}))
		if c.Verdict != VerdictBlocked || !slices.Equal(c.Opaque, []string{"src/flagd"}) {
			t.Errorf("comparison = %+v", c)
		}
	})
	t.Run("new symlinked directory blocks", func(t *testing.T) {
		t.Parallel()
		c := Compare(base(t), detect(t, demo, blob("real/x.txt", "x"), gittree.Entry{Path: "alias", Mode: gittree.ModeSymlink, Data: []byte("real")}))
		if c.Verdict != VerdictBlocked || !slices.Equal(c.Opaque, []string{"alias"}) {
			t.Errorf("comparison = %+v", c)
		}
	})
	t.Run("new symlink to a file does not block", func(t *testing.T) {
		t.Parallel()
		c := Compare(base(t), detect(t, demo, blob("docs/x.txt", "x"), gittree.Entry{Path: "link.txt", Mode: gittree.ModeSymlink, Data: []byte("docs/x.txt")}))
		if c.Verdict != VerdictPass {
			t.Errorf("comparison = %+v", c)
		}
	})
}

func TestCompare_Bypass_FLG2(t *testing.T) {
	t.Parallel()
	bs := string(rune(92))
	evil := `{"flags":{"evil":` + onFlag + `}}`
	escSchema := `"` + bs + `u0024schema":"https://` + bs + `u0066lagd.dev/schema/v0/flags.json"`
	base := flagd1(offFlag)
	with := func(extra map[string]string) map[string]string {
		m := map[string]string{}
		for k, v := range base {
			m[k] = v
		}
		for k, v := range extra {
			m[k] = v
		}
		return m
	}
	blocked := map[string]map[string]string{
		"plain json without a schema":    {"src/flagd/extra.json": evil},
		"upper-case suffix":              {"src/flagd/EXTRA.FLAGD.JSON": evil},
		"yaml":                           {"src/flagd/extra.yaml": "flags:\n  evil:\n    state: ENABLED\n    variants: {on: true, off: false}\n    defaultVariant: on\n"},
		"escaped schema with a dup key":  {"src/flagd/extra.json": `{` + escSchema + `,"flags":{"evil":` + onFlag + `},"flags":{"evil":` + onFlag + `}}`},
		"escaped schema with bad UTF-8":  {"src/flagd/extra.json": `{` + escSchema + `,"flags":{"evil":` + onFlag + `},"metadata":{"x":"` + "\xff" + `"}}`},
		"escaped schema":                 {"src/flagd/extra.json": `{` + escSchema + `,"flags":{"evil":` + onFlag + `}}`},
		"schema url variant":             {"src/flagd/extra.json": `{"$schema":"https://flagd.dev/schema/v0/flags.json#","flags":{"evil":` + onFlag + `}}`},
		"oversized with flags":           {"src/flagd/extra.json": `{` + schema + `,"flags":{"evil":` + onFlag + `}}` + strings.Repeat(" ", 1<<20)},
		"embedded in a config map":       {"k8s/cm.json": `{"data":{"flags.json":` + quote(evil) + `}}`},
		"manifest only, staged":          {"flags.json": manifestFile("evil", "boolean", "false")},
		"flip of an existing switch":     flagd1(onFlag),
		"manifest default true":          {"flags.json": manifestFile("evil", "boolean", "true")},
		"odd extension":                  {"src/flagd/extra.js-on": evil},
		"config file holds flags":        {".openfeature.json": evil},
		"yaml merge key":                 {"src/flagd/extra.yaml": "b: &a {state: ENABLED, variants: {on: true, off: false}, defaultVariant: on}\nflags:\n  evil:\n    <<: *a\n"},
		"yaml quoted flags key":          {"src/flagd/extra.yaml": "'flags':\n  evil:\n    state: ENABLED\n    variants: {on: true, off: false}\n    defaultVariant: on\n"},
		"yaml space before colon":        {"src/flagd/extra.yaml": "flags :\n  evil:\n    state: ENABLED\n    variants: {on: true, off: false}\n    defaultVariant: on\n"},
		"yaml second document is broken": {"src/flagd/extra.yaml": "flags:\n  evil:\n    state: ENABLED\n    variants: {on: true, off: false}\n    defaultVariant: on\n---\nkey: [unclosed\n"},
		"array form":                     {"src/flagd/extra.json": `{"flags":[{"key":"evil","state":"ENABLED","variants":{"on":true,"off":false},"defaultVariant":"on"}]}`},
		"upper-case fields":              {"src/flagd/extra.json": `{"flags":{"evil":{"State":"ENABLED","Variants":{"on":true,"off":false},"DefaultVariant":"on"}}}`},
		"upper-case flags":               {"src/flagd/extra.json": `{"FLAGS":{"evil":` + onFlag + `}}`},
		"ref as a flag entry":            {"src/flagd/extra.json": `{"$evaluators":{"e":{"x":1}},"flags":{"evil":{"$ref":"e"}}}`},
		"empty default variant":          {"src/flagd/extra.json": `{"flags":{"evil":{"state":"ENABLED","variants":{"":false,"on":true},"defaultVariant":""}}}`},
		"no default variant":             {"src/flagd/extra.json": `{"flags":{"evil":{"state":"ENABLED","variants":{"on":true,"off":false}}}}`},
		"symlink named json":             nil, // set below
		"mixed flagd and manifest flags": {"x.json": `{"flags":{"a":` + offFlag + `,"b":{"flagType":"boolean","defaultValue":false}}}`},
	}
	delete(blocked, "symlink named json")
	for name, extra := range blocked {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if name == "flip of an existing switch" {
				if c := compareFiles(t, base, extra); c.Verdict == VerdictPass {
					t.Errorf("BYPASS: %s passes", name)
				}
				return
			}
			if c := compareFiles(t, base, with(extra)); c.Verdict == VerdictPass {
				t.Errorf("BYPASS: %s passes: %+v", name, c)
			}
		})
	}
	t.Run("symlink named json", func(t *testing.T) {
		t.Parallel()
		head := Compare(detectFiles(t, base), detectTree(t, mkTree(t, with(map[string]string{"docs/x.txt": evil}), map[string]string{"src/flagd/extra.json": "../../docs/x.txt"})))
		if head.Verdict == VerdictPass {
			t.Error("BYPASS: symlink passes")
		}
	})
	// A file flagd itself cannot load is not a source.
	for name, extra := range map[string]map[string]string{
		"trailing data": {"src/flagd/extra.json": evil + ` x`},
		"txt":           {"src/flagd/extra.txt": evil},
	} {
		t.Run("skipped: "+name, func(t *testing.T) {
			t.Parallel()
			if c := compareFiles(t, base, with(extra)); c.Verdict != VerdictPass {
				t.Errorf("verdict = %s, want pass", c.Verdict)
			}
		})
	}
}
