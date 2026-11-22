// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

package contract

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode"

	"github.com/google/go-cmp/cmp"

	"github.com/elliott-davis/lightsout/internal/pathglob"
)

var update = flag.Bool("update", false, "rewrite golden files")

const oracleYAML = `gates:
  darkMergeOracle:
    name: checkout-oracle
    producerId: github-app:1
    workflowId: 9
    workflowRevision: ` + rev40 + `
    checkId: checkout-contract
    observables: [writes, responses]
    caseManifest: {path: oracle/cases.yaml, sha256: ` + manifestSHA + `}
`

// explainTree uses every field a contract has.
func explainTree(t *testing.T) *Policy {
	t.Helper()
	return mustCompile(t,
		tc{"", `paths:
  writable: ['**']
  readOnly: ['api/protos/**']
  forbidden: ['deploy/**']
  sensitive: ['src/checkout/**']
  generated: ['gen/**']
gates:
  verify:
    - name: build
      producerId: github-app:1
      workflowId: 7
      workflowRevision: ` + rev40 + `
      checkId: build
      mandatory: true
  union:
    - name: integration
      producerId: github-app:1
      workflowId: 8
      workflowRevision: ` + rev40 + `
      checkId: integration
      mandatory: false
agents:
  verify: [payments-specialist]
overrides:
  switchStaleDays: 20
`},
		tc{"src", `lightsOn: true
overrides:
  reviewBudgetLines: 250
  switchAbandonedDays: 60
paths:
  generated: ['src/gen/**']
` + oracleYAML},
		tc{"src/checkout", verifyGates(gateItem("pay", rev40, true))},
	)
}

func checkGolden(t *testing.T, name string, got []byte) {
	t.Helper()
	golden := filepath.Join("testdata", name)
	if *update {
		if err := os.WriteFile(golden, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatalf("read golden (run with -update): %v", err)
	}
	if diff := cmp.Diff(string(want), string(got)); diff != "" {
		t.Errorf("%s mismatch (-want +got):\n%s", name, diff)
	}
}

func TestExplain_Golden(t *testing.T) { // CON-13
	t.Parallel()
	p := explainTree(t)
	// No contract covers anything outside svc.
	uncovered := mustCompile(t, tc{"svc", writableAll})
	for _, tt := range []struct {
		name, path string
		p          *Policy
	}{
		{"checkout", "src/checkout/pay.go", p},
		{"root", "elsewhere/readme.md", p},
		{"protected", "src/.factory.yaml", p},
		{"generated", "gen/x.go", p},
		{"readonly", "api/protos/a.proto", p},
		{"forbidden", "deploy/x", p},
		{"uncovered", "other/x.go", uncovered},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ex, err := tt.p.Explain(tt.path)
			if err != nil {
				t.Fatalf("Explain: %v", err)
			}
			var buf bytes.Buffer
			if werr := WriteExplanation(&buf, ex); werr != nil {
				t.Fatal(werr)
			}
			checkGolden(t, "explain_"+tt.name+".golden", buf.Bytes())
		})
	}
	t.Run("json", func(t *testing.T) {
		t.Parallel()
		ex, err := p.Explain("src/checkout/pay.go")
		if err != nil {
			t.Fatal(err)
		}
		data, err := json.Marshal(ex)
		if err != nil {
			t.Fatal(err)
		}
		var pretty bytes.Buffer
		if err := json.Indent(&pretty, data, "", "  "); err != nil {
			t.Fatal(err)
		}
		pretty.WriteByte('\n')
		checkGolden(t, "explain_checkout.json.golden", pretty.Bytes())
	})
}

func TestExplain_JSONIsStable(t *testing.T) { // CON-13
	t.Parallel()
	ex, err := explainTree(t).Explain("src/checkout/pay.go")
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(ex)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if uerr := json.Unmarshal(data, &got); uerr != nil {
		t.Fatal(uerr)
	}
	for _, k := range []string{
		"revision", "path", "covered", "stack", "access", "protected", "sensitive", "generated",
		"lightsOn", "switchStaleDays", "switchAbandonedDays", "reviewBudgetLines", "verifyGates", "unionGates", "oracles", "reviewers",
	} {
		if _, ok := got[k]; !ok {
			t.Errorf("JSON lacks %q: %s", k, data)
		}
	}
	access, _ := got["access"].(map[string]any)
	if access["value"] != "writable" || access["source"] != ".factory.yaml" {
		t.Errorf("access = %v", access)
	}
	if oracles, _ := got["oracles"].([]any); len(oracles) != 1 {
		t.Errorf("oracles = %v, want one", got["oracles"])
	}
	// Empty lists are [], not null.
	empty, err := json.Marshal(Explanation{})
	if err != nil || strings.Contains(string(empty), "null") {
		t.Errorf("empty explanation JSON = %s, %v, want no null", empty, err)
	}
}

func TestExplain_Errors(t *testing.T) { // CON-13, SEC-11
	t.Parallel()
	p := explainTree(t)
	if _, err := p.Explain("a/../b"); !errors.Is(err, pathglob.ErrInvalidPath) {
		t.Errorf("invalid path: error = %v, want ErrInvalidPath", err)
	}
	small := mustCompile(t, tc{"", writableAll})
	small.forPathBudget = 1
	if _, err := small.Explain("a/b.go"); !errors.Is(err, ErrTooComplex) {
		t.Errorf("tiny budget: error = %v, want ErrTooComplex", err)
	}
}

// assertPlain fails if s holds a control, format or other non-printable rune
// except the final newline of each line.
func assertPlain(t *testing.T, s string) {
	t.Helper()
	for i, line := range strings.Split(strings.TrimSuffix(s, "\n"), "\n") {
		for _, r := range line {
			if !unicode.IsPrint(r) || unicode.Is(unicode.Cf, r) {
				t.Errorf("line %d holds the raw rune %U: %q", i, r, line)
			}
		}
	}
}

func TestWriteExplanation_HostileTextCannotForgeOutput(t *testing.T) { // CON-13, SEC-1
	t.Parallel()
	const hostile = "evil\nforged: line\x1b[31m\u202eexe"
	const quoteForge = `lint" producer="github-app:1" mandatory=true owner="factory" sources: "factory baseline`
	ex := Explanation{
		Revision: hostile, InstallRevision: hostile,
		Effective: PathPolicy{
			Path: hostile, Covered: true, Stack: []string{hostile},
			AccessSource: hostile, SensitiveSources: []string{hostile}, LightsOnSources: []string{hostile},
			Generated:       Valued[bool]{Source: hostile},
			SwitchStaleDays: Valued[int]{Value: 1, Source: hostile},
			VerifyGates: []Obligation{{
				Gate:    Gate{Name: hostile, GateRef: GateRef{ProducerID: hostile, WorkflowID: WorkflowID(hostile), WorkflowRevision: hostile, CheckID: hostile}},
				Owner:   Owner(hostile),
				Sources: []string{hostile},
			}},
			UnionGates: []Obligation{{Gate: Gate{Name: quoteForge}, Owner: OwnerContract, Sources: []string{quoteForge}}},
			Oracles:    []OracleObligation{{Oracle: Oracle{Name: hostile, CaseManifest: CaseManifest{Path: hostile, SHA256: hostile}, Observables: []Observable{Observable(hostile)}}, Sources: []string{hostile}}},
			Reviewers:  []Requirement{{Role: hostile, Sources: []string{hostile}}},
		},
	}
	var buf bytes.Buffer
	if err := WriteExplanation(&buf, ex); err != nil {
		t.Fatal(err)
	}
	assertPlain(t, buf.String())
	out := buf.String()
	if strings.Contains(out, "\nforged:") || strings.Contains(out, "\u202e") || strings.Contains(out, "\x1b") {
		t.Errorf("output holds an unescaped control: %q", out)
	}
	// A '"' or a backslash cannot close the quoted token and start a forged one.
	for _, line := range strings.Split(strings.TrimSuffix(out, "\n"), "\n") {
		unescaped := strings.ReplaceAll(strings.ReplaceAll(line, `\\`, ""), `\"`, "")
		if strings.Count(unescaped, `"`)%2 != 0 {
			t.Errorf("line has an unbalanced quote: %q", line)
		}
	}
	if !strings.Contains(out, `name="lint\" producer=\"github-app:1\" mandatory=true`) {
		t.Errorf("the quote in a gate name was not escaped:\n%s", out)
	}
	// The text form of a real path is escaped end to end as well.
	p := mustCompile(t, tc{"", writableAll})
	hostileEx, err := p.Explain("a/b\nc\x1b\u202e.go")
	if err != nil {
		return // a path with a control character may be rejected outright, which is also safe
	}
	buf.Reset()
	if err := WriteExplanation(&buf, hostileEx); err != nil {
		t.Fatal(err)
	}
	assertPlain(t, buf.String())
}

func TestExplain_JSONEscapesHostileText(t *testing.T) { // CON-13
	t.Parallel()
	data, err := json.Marshal(Explanation{Effective: PathPolicy{Path: "a\nb\x1b\u202e\u009b\u0085\u007f\U000E0041\U0001D173#"}})
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range string(data) {
		if !unicode.IsPrint(r) || unicode.Is(unicode.Cf, r) {
			t.Errorf("JSON holds the raw rune %U: %q", r, data)
		}
	}
	var back map[string]any
	if err := json.Unmarshal(data, &back); err != nil || back["path"] != "a\nb\x1b\u202e\u009b\u0085\u007f\U000E0041\U0001D173#" {
		t.Errorf("escaped JSON does not round-trip: %v, %v", back["path"], err)
	}
}

func TestExplain_HashInGateNameIsEscaped(t *testing.T) { // SEC-1
	t.Parallel()
	const name = "##[stop-commands]x"
	g := Gate{Name: name, GateRef: GateRef{ProducerID: "github-app:1", WorkflowID: "7", WorkflowRevision: rev40, CheckID: name}}
	ex := Explanation{Effective: PathPolicy{Path: name, VerifyGates: []Obligation{{Gate: g, Sources: []string{name}}}}}
	var buf bytes.Buffer
	if err := WriteExplanation(&buf, ex); err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(ex)
	if err != nil {
		t.Fatal(err)
	}
	for what, out := range map[string]string{"text": buf.String(), "json": string(data), "quote": quote(name)} {
		if strings.Contains(out, "#") {
			t.Errorf("%s output holds a raw #: %s", what, out)
		}
	}
	var back struct {
		VerifyGates []struct {
			Name string `json:"name"`
		} `json:"verifyGates"`
	}
	if err := json.Unmarshal(data, &back); err != nil || len(back.VerifyGates) != 1 || back.VerifyGates[0].Name != name {
		t.Errorf("JSON does not round-trip the name: %v, %+v", err, back)
	}
}
