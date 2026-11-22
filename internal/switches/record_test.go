// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

package switches

import (
	"bytes"
	"errors"
	"flag"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
)

var update = flag.Bool("update", false, "update golden files")

func records(now time.Time) []Record {
	rec := func(repo, key string, seen time.Time, q Qualification, def Status) Record {
		return Record{
			Key: key, Repo: repo, Description: "does a thing", Sources: []string{"b.flagd.json", "a.flagd.json"},
			Owner: "alice", FirstSeenRevision: "abc123", FirstSeenAt: seen, Default: def, Qualification: q,
		}
	}
	return []Record{
		rec("acme/shop", "zeta", now.Add(-72*time.Hour), Qualification{Status: QualUnionQualified, AcceptanceRun: "run-7", ManifestID: "man-9"}, StatusDefaultOff),
		rec("acme/shop", "alpha", now.Add(-30*time.Minute), Qualification{Status: QualNone}, StatusDefaultOff),
		rec("acme/shop", "mid", now.Add(-5*time.Hour), Qualification{Status: QualAcceptancePassed, AcceptanceRun: "run-1"}, StatusUnproven),
		rec("acme/shop", "fresh", now, Qualification{}, StatusDefaultOn),
		rec("acme/shop", "old", time.Time{}, Qualification{}, "bogus"),
		rec("acme/api", "blocked", now.Add(-49*time.Hour), Qualification{Status: QualUnionBlocked, AcceptanceRun: "run-2", ManifestID: "man-3"}, StatusDefaultOff),
		rec("acme/api", "zeta", now.Add(-time.Hour), Qualification{}, StatusDefaultOff),
	}
}

func TestRender_Golden_FLG3(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	var buf bytes.Buffer
	if err := Render(&buf, records(now), now); err != nil {
		t.Fatal(err)
	}
	const golden = "testdata/render.golden"
	if *update {
		if err := os.WriteFile(golden, buf.Bytes(), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatal(err)
	}
	if diff := cmp.Diff(string(want), buf.String()); diff != "" {
		t.Errorf("render differs from %s (-want +got):\n%s", golden, diff)
	}
}

func TestRender_Fields_FLG3(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	var buf bytes.Buffer
	if err := Render(&buf, records(now), now); err != nil {
		t.Fatal(err)
	}
	rows := strings.Split(strings.TrimSpace(buf.String()), "\n")[4:]
	order := []string{"acme/api | blocked", "acme/api | zeta", "acme/shop | alpha", "acme/shop | fresh", "acme/shop | mid", "acme/shop | old", "acme/shop | zeta"}
	if len(rows) != len(order) {
		t.Fatalf("output:\n%s", buf.String())
	}
	for i, key := range order {
		if !strings.Contains(rows[i], "| "+key+" |") {
			t.Errorf("row %d = %q, want %s (sorted by repo, then key)", i, rows[i], key)
		}
	}
	checks := map[string][]string{
		"acme/shop | zeta":   {"| off |", "passed (run-7), union qualified", "| man-9 |", "alice", "3d", "a.flagd.json, b.flagd.json"},
		"acme/shop | alpha":  {"not passed", "30m", "| - |"},
		"acme/shop | mid":    {"not shown to be off (unproven-default)", "5h", "passed (run-1) |"},
		"acme/shop | fresh":  {"| ON |", "under a minute"},
		"acme/shop | old":    {"unchecked", "unknown"},
		"acme/api | blocked": {"passed (run-2), union blocked", "| man-3 |", "2d"},
	}
	for i, key := range order {
		for _, want := range checks[key] {
			if !strings.Contains(rows[i], want) {
				t.Errorf("%s row %q lacks %q", key, rows[i], want)
			}
		}
	}
}

func TestRender_Escapes_FLG3(t *testing.T) {
	t.Parallel()
	evil := "@team ::error:: ##[group] <img src=x> `tick` | [l](u) https://evil.example/x www.evil.example\nnext"
	var buf bytes.Buffer
	err := Render(&buf, []Record{{
		Key: evil, Repo: evil, Description: evil, Sources: []string{evil}, Owner: evil, FirstSeenRevision: evil,
		FirstSeenAt: time.Unix(0, 0), Default: StatusDefaultOff,
		Qualification: Qualification{Status: QualUnionQualified, AcceptanceRun: evil, ManifestID: evil},
	}}, time.Unix(100, 0))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 5 { // heading, blank, header, rule, one row
		t.Fatalf("newline in input broke the table:\n%s", buf.String())
	}
	row := lines[4]
	for _, bad := range []string{"@", "::", "##[", "<", ">", "`", "[", "]", "://", "www."} {
		if strings.Contains(strings.ToLower(row), bad) {
			t.Errorf("row contains %q: %s", bad, row)
		}
	}
	if got := strings.Count(row, "|"); got != 11 {
		t.Errorf("row has %d pipes, want 11: %s", got, row)
	}
}

func TestRender_InvalidQualification_FLG3(t *testing.T) {
	t.Parallel()
	for name, q := range map[string]Qualification{
		"passed without a run":     {Status: QualAcceptancePassed},
		"union without a manifest": {Status: QualUnionQualified, AcceptanceRun: "r"},
		"union without a run":      {Status: QualUnionBlocked, ManifestID: "m"},
		"unknown status":           {Status: "union-tested"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			var buf bytes.Buffer
			err := Render(&buf, []Record{{Key: "k", Qualification: q}}, time.Now())
			if err == nil || buf.Len() != 0 {
				t.Errorf("err = %v, wrote %q", err, buf.String())
			}
		})
	}
	valid := []Qualification{
		{},
		{Status: QualNone},
		{Status: QualAcceptancePassed, AcceptanceRun: "r"},
		{Status: QualUnionQualified, AcceptanceRun: "r", ManifestID: "m"},
		{Status: QualUnionBlocked, AcceptanceRun: "r", ManifestID: "m"},
	}
	for _, q := range valid {
		if err := q.Validate(); err != nil {
			t.Errorf("%+v: %v", q, err)
		}
	}
}

func TestRender_ManifestOnlyForUnionStates_FLG3(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	err := Render(&buf, []Record{{Key: "k", Qualification: Qualification{Status: QualAcceptancePassed, AcceptanceRun: "r", ManifestID: "stale-id"}}}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), "stale-id") {
		t.Errorf("manifest ID shown for a non-union state:\n%s", buf.String())
	}
}

func TestRender_EmptyAndWriteError_FLG3(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	if err := Render(&buf, nil, time.Now()); err != nil || !strings.Contains(buf.String(), "No feature switches recorded.") {
		t.Errorf("err = %v, out = %q", err, buf.String())
	}
	if err := Render(failWriter{}, nil, time.Now()); !errors.Is(err, errWrite) {
		t.Errorf("err = %v", err)
	}
}

var errWrite = errors.New("write failed")

type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, errWrite }

func TestRender_AgeUsesInjectedNow_FLG3(t *testing.T) {
	t.Parallel()
	seen := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	tests := map[time.Time]string{
		seen.Add(10 * 24 * time.Hour):             "10d",
		seen.Add(-time.Hour):                      "under a minute", // clock skew never shows a negative age
		seen.Add(47*time.Hour + 59*time.Minute):   "47h",
		seen.Add(48 * time.Hour):                  "2d",
		seen.Add(time.Hour):                       "1h",
		seen.Add(time.Minute):                     "1m",
		seen.Add(59*time.Minute + 59*time.Second): "59m",
		seen.Add(time.Minute - time.Nanosecond):   "under a minute",
		seen.Add(time.Hour + 59*time.Minute):      "1h",
	}
	for now, want := range tests {
		if got := ageText(seen, now); got != want {
			t.Errorf("age at %s = %q, want %q", now, got, want)
		}
	}
}

func TestRender_SortIsTotal_FLG3(t *testing.T) {
	t.Parallel()
	a := Record{Key: "k", Repo: "r", Owner: "zed"}
	b := Record{Key: "k", Repo: "r", Owner: "amy"}
	var x, y bytes.Buffer
	if err := Render(&x, []Record{a, b}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := Render(&y, []Record{b, a}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if x.String() != y.String() {
		t.Errorf("order depends on input:\n%s\n%s", x.String(), y.String())
	}
}

func TestNewRecord_FLG3(t *testing.T) {
	t.Parallel()
	at := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	set := detectFiles(t, map[string]string{
		"b.flagd.json": flagdFile(map[string]string{"s": `{"description":"the switch","state":"ENABLED","variants":{"on":true,"off":false},"defaultVariant":"off"}`}),
		"flags.json":   manifestFile("s", "boolean", "false"),
		"a.flagd.json": flagdFile(map[string]string{"t": onFlag}),
	})
	rec := NewRecord("acme/shop", set.Switches["s"], "rev1", at, "alice")
	want := Record{
		Key: "s", Repo: "acme/shop", Description: "the switch", Sources: []string{"b.flagd.json", "flags.json"},
		Owner: "alice", FirstSeenRevision: "rev1", FirstSeenAt: at, Default: StatusDefaultOff,
		Qualification: Qualification{Status: QualNone},
	}
	if diff := cmp.Diff(want, rec); diff != "" {
		t.Errorf("record (-want +got):\n%s", diff)
	}
	if got := NewRecord("acme/shop", set.Switches["t"], "rev1", at, "alice").Default; got != StatusDefaultOn {
		t.Errorf("a default-on switch is recorded as %s", got)
	}
	if err := rec.Qualification.Validate(); err != nil {
		t.Errorf("new record is not valid: %v", err)
	}
}
