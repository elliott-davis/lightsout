// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

package contract

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/elliott-davis/lightsout/internal/pathglob"
)

const rev40 = "a4ac7e7ccc7544f12d78ba75fd84289a903511f3"

// manifestSHA and manifestLine are the case manifest pin (PIP-13) of the oracle fixtures.
const (
	manifestSHA  = "5f1c0e3a9b7d2c4e6a8b0d1f3e5a7c9b1d3f5e7a9c0b2d4f6e8a1c3e5b7d9f02"
	manifestLine = "    caseManifest: {path: oracle/cases.yaml, sha256: " + manifestSHA + "}\n"
)

const head = "apiVersion: factory/v1alpha1\nkind: Contract\n"

func newParser(t *testing.T) *Parser {
	t.Helper()
	p, err := NewParser()
	if err != nil {
		t.Fatalf("NewParser: %v", err)
	}
	return p
}

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// problemsOf parses and returns the problems, failing if there are none.
func problemsOf(t *testing.T, p *Parser, doc string) []Problem {
	t.Helper()
	c, err := p.Parse("", []byte(doc))
	if err == nil {
		t.Fatalf("Parse succeeded, want failure; got %+v", c)
	}
	var ve *ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("error %v is not a *ValidationError", err)
	}
	return ve.Problems
}

func hasProblem(ps []Problem, code Code, field string) bool {
	for _, p := range ps {
		if p.Code == code && (field == "" || p.Field == field) {
			return true
		}
	}
	return false
}

func gateYAML(overrides map[string]string, drop string) string {
	fields := []string{"name", "producerId", "workflowId", "workflowRevision", "checkId", "mandatory"}
	vals := map[string]string{
		"name": "build", "producerId": "github-app:12345", "workflowId": "67890",
		"workflowRevision": rev40, "checkId": "build-and-test", "mandatory": "true",
	}
	for k, v := range overrides {
		vals[k] = v
	}
	var b strings.Builder
	b.WriteString(head + "gates:\n  verify:\n")
	first := true
	for _, f := range fields {
		if f == drop {
			continue
		}
		prefix := "      "
		if first {
			prefix = "    - "
			first = false
		}
		b.WriteString(prefix + f + ": " + vals[f] + "\n")
	}
	return b.String()
}

func TestParse_PRDExample(t *testing.T) { // CON-11
	t.Parallel()
	p := newParser(t)
	got, err := p.Parse("", readFixture(t, "prd-example.yaml"))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	ref := GateRef{ProducerID: "github-app:12345", WorkflowID: "67890", WorkflowRevision: rev40}
	withCheck := func(id string) GateRef { r := ref; r.CheckID = id; return r }
	writable := []string{"**"}
	generated := []string{"gen/**"}
	stale, budget := 45, 300
	lightsOn := false
	want := &Contract{
		APIVersion: APIVersion,
		Kind:       Kind,
		Paths: Paths{
			Writable:  &writable,
			ReadOnly:  []string{"api/protos/**"},
			Forbidden: []string{"deploy/**"},
			Sensitive: []string{"src/checkout/payment/**"},
			Generated: &generated,
		},
		Gates: Gates{
			Verify: []Gate{
				{Name: "build-and-test", GateRef: withCheck("build-and-test"), Mandatory: true},
				{Name: "lint", GateRef: withCheck("lint"), Mandatory: false},
			},
			DarkMergeOracle: &Oracle{
				GateRef:      withCheck("checkout-contract"),
				CaseManifest: CaseManifest{Path: "ops/oracle/checkout-cases.yaml", SHA256: manifestSHA},
				Observables:  []Observable{ObservableResponses, ObservableReads, ObservableWrites, ObservableEvents, ObservableQueuedJobs},
			},
		},
		Agents:    Agents{Verify: []string{"security-reviewer"}},
		LightsOn:  &lightsOn,
		Overrides: Overrides{SwitchStaleDays: &stale, ReviewBudgetLines: &budget},
	}
	if diff := cmp.Diff(want, got, cmpopts.IgnoreUnexported(Contract{})); diff != "" {
		t.Errorf("contract mismatch (-want +got):\n%s", diff)
	}
}

func TestParse_DirAndAbsentVsEmpty(t *testing.T) {
	t.Parallel()
	p := newParser(t)
	c, err := p.Parse("src/checkout", readFixture(t, "minimal.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if c.Dir != "src/checkout" {
		t.Errorf("Dir = %q", c.Dir)
	}
	if c.Paths.Writable == nil || len(*c.Paths.Writable) != 0 {
		t.Errorf("declared-empty writable = %v, want non-nil empty", c.Paths.Writable)
	}
	if c.Paths.Generated != nil {
		t.Errorf("absent generated = %v, want nil", c.Paths.Generated)
	}
	if c.LightsOn == nil || !*c.LightsOn {
		t.Errorf("LightsOn = %v, want true", c.LightsOn)
	}
}

func TestParse_BadDir(t *testing.T) {
	t.Parallel()
	p := newParser(t)
	for _, dir := range []string{".", "/a", "a/", "a/../b", "a//b", "a\x00b", "./a"} {
		c, err := p.Parse(dir, []byte(head))
		var ve *ValidationError
		if c != nil || !errors.Is(err, pathglob.ErrInvalidPath) || errors.As(err, &ve) {
			t.Errorf("dir %q: err = %v, want plain wrapped ErrInvalidPath", dir, err)
		}
	}
}

func TestParse_RejectsUnknownFields(t *testing.T) { // CON-11, CON-4
	t.Parallel()
	p := newParser(t)
	gate := "    - {name: b, producerId: 'github-app:1', workflowId: 1, workflowRevision: '" + rev40 + "', checkId: b, mandatory: true%s}\n"
	oracle := "  darkMergeOracle: {producerId: 'github-app:1', workflowId: 1, workflowRevision: '" + rev40 + "', checkId: b, observables: [reads], caseManifest: {path: m.yaml, sha256: " + manifestSHA + "}%s}\n"
	tests := []struct {
		name  string
		doc   string
		field string
	}{
		{"top command", head + "command: make\n", "/command"},
		{"top run", head + "run: make\n", "/run"},
		{"top script", head + "script: x\n", "/script"},
		{"top steps", head + "steps: []\n", "/steps"},
		{"paths", head + "paths:\n  command: x\n", "/paths/command"},
		{"gates", head + "gates:\n  run: x\n", "/gates/run"},
		{"gate command", head + "gates:\n  verify:\n" + strings.Replace(gate, "%s", ", command: make", 1), "/gates/verify/0/command"},
		{"gate run", head + "gates:\n  verify:\n" + strings.Replace(gate, "%s", ", run: make", 1), "/gates/verify/0/run"},
		{"union gate script", head + "gates:\n  union:\n" + strings.Replace(gate, "%s", ", script: x", 1), "/gates/union/0/script"},
		{"gate steps", head + "gates:\n  verify:\n" + strings.Replace(gate, "%s", ", steps: []", 1), "/gates/verify/0/steps"},
		{"oracle command", head + "gates:\n" + strings.Replace(oracle, "%s", ", command: x", 1), "/gates/darkMergeOracle/command"},
		{"oracle mandatory", head + "gates:\n" + strings.Replace(oracle, "%s", ", mandatory: true", 1), "/gates/darkMergeOracle/mandatory"},
		{"agents", head + "agents:\n  run: x\n", "/agents/run"},
		{"overrides", head + "overrides:\n  command: x\n", "/overrides/command"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ps := problemsOf(t, p, tt.doc)
			if !hasProblem(ps, CodeUnknownField, tt.field) {
				t.Errorf("problems = %v, want unknown-field at %s", ps, tt.field)
			}
		})
	}
}

func TestParse_GateIdentityRequired(t *testing.T) { // CON-4
	t.Parallel()
	p := newParser(t)

	if _, err := p.Parse("", []byte(gateYAML(nil, ""))); err != nil {
		t.Fatalf("valid gate rejected: %v", err)
	}

	nameOnly := head + "gates:\n  verify:\n    - name: build\n      mandatory: true\n"
	if ps := problemsOf(t, p, nameOnly); !hasProblem(ps, CodeSchema, "/gates/verify/0") {
		t.Errorf("name-only gate: problems = %v", ps)
	}
	unionOnly := head + "gates:\n  union:\n    - name: smoke\n      mandatory: true\n"
	if ps := problemsOf(t, p, unionOnly); !hasProblem(ps, CodeSchema, "/gates/union/0") {
		t.Errorf("name-only union gate: problems = %v", ps)
	}
	oracleOnly := head + "gates:\n  darkMergeOracle:\n    name: oracle\n"
	if ps := problemsOf(t, p, oracleOnly); !hasProblem(ps, CodeSchema, "/gates/darkMergeOracle") {
		t.Errorf("name-only oracle: problems = %v", ps)
	}

	for _, f := range []string{"name", "producerId", "workflowId", "workflowRevision", "checkId", "mandatory"} {
		t.Run("missing "+f, func(t *testing.T) {
			t.Parallel()
			ps := problemsOf(t, p, gateYAML(nil, f))
			if !hasProblem(ps, CodeSchema, "/gates/verify/0") {
				t.Errorf("problems = %v", ps)
			}
		})
	}

	bad := []struct {
		name  string
		field string
		value string
	}{
		{"short sha", "workflowRevision", "'a4ac7e7'"},
		{"uppercase sha", "workflowRevision", "'A4AC7E7CCC7544F12D78BA75FD84289A903511F3'"},
		{"41 hex", "workflowRevision", "'" + rev40 + "0'"},
		{"producer no kind", "producerId", "'12345'"},
		{"producer uppercase kind", "producerId", "'GitHub:1'"},
		{"producer space", "producerId", "'github-app:1 2'"},
		{"check semicolon", "checkId", "'build; rm -rf /'"},
		{"check subshell", "checkId", "'$(id)'"},
		{"check leading space", "checkId", "' build'"},
		{"workflow zero", "workflowId", "0"},
		{"workflow negative", "workflowId", "-4"},
		{"workflow float", "workflowId", "1.5"},
		{"workflow bad string", "workflowId", "'a b'"},
		{"mandatory string", "mandatory", "'true'"},
		{"name newline", "name", `"a\nb"`},
		{"name bidi override", "name", `"a\u202eb"`},
		{"name zero width", "name", `"a\u200bb"`},
		{"name line separator", "name", `"a\u2028b"`},
		{"name e acute", "name", `"caf\u00e9"`},
		{"name cyrillic", "name", `"a\u0435b"`},
		{"workflow traversal", "workflowId", `'../../user'`},
		{"workflow absolute", "workflowId", `'/abs'`},
		{"workflow empty segment", "workflowId", `'a//b'`},
		{"workflow dot segment", "workflowId", `'a/./b'`},
		{"workflow trailing slash", "workflowId", `'a/'`},
		{"check traversal", "checkId", `'a/../../x'`},
		{"check dot segment", "checkId", `'a/./b'`},
		{"check empty segment", "checkId", `'a//b'`},
	}
	for _, tt := range bad {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ps := problemsOf(t, p, gateYAML(map[string]string{tt.field: tt.value}, ""))
			if !hasProblem(ps, CodeSchema, "/gates/verify/0/"+tt.field) {
				t.Errorf("problems = %v, want schema problem at %s", ps, tt.field)
			}
		})
	}

	for _, ok := range []string{"'build (linux)'", "'ci/build: unit'", "'build (linux, amd64)'", "'a..b'", "'v1.2/x'"} {
		if _, err := p.Parse("", []byte(gateYAML(map[string]string{"checkId": ok}, ""))); err != nil {
			t.Errorf("checkId %s rejected: %v", ok, err)
		}
	}
}

func TestParse_OracleRules(t *testing.T) { // CON-4
	t.Parallel()
	p := newParser(t)
	base := head + "gates:\n  darkMergeOracle:\n    producerId: 'github-app:1'\n    workflowId: 1\n    workflowRevision: '" + rev40 + "'\n    checkId: c\n" + manifestLine
	if ps := problemsOf(t, p, base); !hasProblem(ps, CodeSchema, "/gates/darkMergeOracle") {
		t.Errorf("missing observables: %v", ps)
	}
	noManifest := strings.TrimSuffix(base, manifestLine) + "    observables: [reads]\n"
	if ps := problemsOf(t, p, noManifest); !hasProblem(ps, CodeSchema, "/gates/darkMergeOracle") {
		t.Errorf("missing caseManifest: %v", ps) // PIP-13
	}
	for name, m := range map[string]string{
		"short sha":        "{path: m.yaml, sha256: abc}",
		"uppercase sha":    "{path: m.yaml, sha256: " + strings.ToUpper(manifestSHA) + "}",
		"sha with prefix":  "{path: m.yaml, sha256: 'sha256:" + manifestSHA + "'}",
		"missing sha":      "{path: m.yaml}",
		"missing path":     "{sha256: " + manifestSHA + "}",
		"parent traversal": "{path: ../m.yaml, sha256: " + manifestSHA + "}",
		"inner traversal":  "{path: a/../m.yaml, sha256: " + manifestSHA + "}",
		"absolute path":    "{path: /m.yaml, sha256: " + manifestSHA + "}",
		"trailing slash":   "{path: a/, sha256: " + manifestSHA + "}",
		"extra field":      "{path: m.yaml, sha256: " + manifestSHA + ", mode: x}",
	} {
		text := strings.TrimSuffix(base, manifestLine) + "    observables: [reads]\n    caseManifest: " + m + "\n"
		if ps := problemsOf(t, p, text); !hasProblem(ps, CodeSchema, "/gates/darkMergeOracle/caseManifest") &&
			!hasProblem(ps, CodeSchema, "/gates/darkMergeOracle/caseManifest/path") &&
			!hasProblem(ps, CodeSchema, "/gates/darkMergeOracle/caseManifest/sha256") &&
			!hasProblem(ps, CodeUnknownField, "/gates/darkMergeOracle/caseManifest/mode") {
			t.Errorf("%s: problems = %v, want a schema problem under caseManifest", name, ps) // PIP-13
		}
	}
	if ps := problemsOf(t, p, base+"    observables: []\n"); !hasProblem(ps, CodeSchema, "/gates/darkMergeOracle/observables") {
		t.Errorf("empty observables: %v", ps)
	}
	if ps := problemsOf(t, p, base+"    observables: [reads, reads]\n"); !hasProblem(ps, CodeSchema, "/gates/darkMergeOracle/observables") {
		t.Errorf("duplicate observables: %v", ps)
	}
	if ps := problemsOf(t, p, base+"    observables: [bogus]\n"); !hasProblem(ps, CodeSchema, "/gates/darkMergeOracle/observables/0") {
		t.Errorf("bad observable: %v", ps)
	}
}

func TestParse_PathPatterns(t *testing.T) { // CON-11
	t.Parallel()
	p := newParser(t)
	for _, pat := range []string{`'/abs'`, `'a\b'`, `'a[0]'`, `'a{b,c}'`, `''`, `"a\x01b"`, `"a\u202eb"`, `"a\u200bb"`, `'` + strings.Repeat("a", 513) + `'`} {
		ps := problemsOf(t, p, head+"paths:\n  forbidden: ["+pat+"]\n")
		if !hasProblem(ps, CodeSchema, "/paths/forbidden/0") {
			t.Errorf("pattern %s: problems = %v", pat, ps)
		}
	}
	if ps := problemsOf(t, p, head+"paths:\n  readOnly: [a, a]\n"); !hasProblem(ps, CodeSchema, "/paths/readOnly") {
		t.Errorf("duplicate patterns: %v", ps)
	}
	if _, err := p.Parse("", []byte(head+"paths:\n  writable: ['src/**/*.go', 'a?b']\n")); err != nil {
		t.Errorf("valid patterns rejected: %v", err)
	}
}

func TestParse_UnsafeYAML(t *testing.T) {
	t.Parallel()
	p := newParser(t)
	deep := head + "overrides:\n" + strings.Repeat(" ", 0) + "  x: " + strings.Repeat("[", 20) + strings.Repeat("]", 20) + "\n"
	many := head + "paths:\n  writable: [" + strings.TrimSuffix(strings.Repeat("a, ", 10001), ", ") + "]\n"
	tests := []struct {
		name string
		doc  string
		code Code
		msg  string
	}{
		{"alias", readString(t, "anchors.yaml"), CodeUnsafeYAML, ""},
		{"anchor only", head + "paths:\n  writable: &w [a]\n", CodeUnsafeYAML, "anchors"},
		{"merge key", head + "overrides:\n  <<: {switchStaleDays: 3}\n", CodeUnsafeYAML, "merge"},
		{"duplicate key", head + "lightsOn: true\nlightsOn: false\n", CodeUnsafeYAML, "duplicate"},
		{"nested duplicate", head + "gates:\n  verify: []\n  verify: []\n", CodeUnsafeYAML, "duplicate"},
		{"second document", head + "---\n" + head, CodeUnsafeYAML, "multiple"},
		{"custom tag", head + "lightsOn: !custom true\n", CodeUnsafeYAML, "tag"},
		{"binary", head + "paths:\n  writable: [!!binary aGk=]\n", CodeUnsafeYAML, "tag"},
		{"timestamp", head + "paths:\n  writable: [2001-12-14]\n", CodeUnsafeYAML, "quote"},
		{"int key", head + "1: x\n", CodeUnsafeYAML, "string"},
		{"complex key", head + "? [a]\n: x\n", CodeUnsafeYAML, "string"},
		{"too deep", deep, CodeUnsafeYAML, "nested"},
		{"too many nodes", many, CodeUnsafeYAML, "nodes"},
		{"oversize", head + "# " + strings.Repeat("x", MaxFileSize), CodeTooLarge, ""},
		{"empty", "", CodeSyntax, ""},
		{"whitespace", " \n\t\n", CodeSyntax, ""},
		{"broken syntax", "a: [", CodeSyntax, ""},
		{"top scalar", "hello\n", CodeSchema, "mapping"},
		{"top list", "- a\n", CodeSchema, "mapping"},
		{"nan float", head + "overrides:\n  switchStaleDays: .nan\n", CodeSchema, ""},
		{"exponent", head + "overrides:\n  switchStaleDays: 1e2\n", CodeSchema, ""},
		{"huge int", head + "overrides:\n  switchStaleDays: " + strings.Repeat("9", 31) + "\n", CodeSchema, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ps := problemsOf(t, p, tt.doc)
			if !hasProblem(ps, tt.code, "") {
				t.Fatalf("problems = %v, want code %s", ps, tt.code)
			}
			if tt.msg != "" && !strings.Contains(ps[0].Message, tt.msg) {
				t.Errorf("message %q lacks %q", ps[0].Message, tt.msg)
			}
			if ps[0].File != FileName {
				t.Errorf("File = %q", ps[0].File)
			}
		})
	}
}

func TestParse_UnsafeYAMLHasPosition(t *testing.T) {
	t.Parallel()
	p := newParser(t)
	ps := problemsOf(t, p, head+"lightsOn: true\nlightsOn: false\n")
	if !strings.HasPrefix(ps[0].Message, "4:1:") {
		t.Errorf("message = %q, want line:col prefix 4:1", ps[0].Message)
	}
}

func readString(t *testing.T, name string) string {
	t.Helper()
	return string(readFixture(t, name))
}

func TestParse_Fixtures(t *testing.T) {
	t.Parallel()
	p := newParser(t)
	if ps := problemsOf(t, p, readString(t, "unknown-command.yaml")); !hasProblem(ps, CodeUnknownField, "/gates/verify/0/command") {
		t.Errorf("problems = %v", ps)
	}
}

func TestParse_Scalars(t *testing.T) {
	t.Parallel()
	p := newParser(t)

	if ps := problemsOf(t, p, head+"lightsOn: yes\n"); !hasProblem(ps, CodeSchema, "/lightsOn") {
		t.Errorf("lightsOn: yes: %v", ps)
	}
	if ps := problemsOf(t, p, head+"lightsOn: 'true'\n"); !hasProblem(ps, CodeSchema, "/lightsOn") {
		t.Errorf("lightsOn: 'true': %v", ps)
	}

	exact := func(v string) WorkflowID {
		t.Helper()
		c, err := p.Parse("", []byte(gateYAML(map[string]string{"workflowId": v}, "")))
		if err != nil {
			t.Fatalf("workflowId %s: %v", v, err)
		}
		return c.Gates.Verify[0].WorkflowID
	}
	if got := exact("9007199254740993"); got != "9007199254740993" {
		t.Errorf("large workflowId = %q, lost precision", got)
	}
	if got := exact("'wf/ci.yaml'"); got != "wf/ci.yaml" {
		t.Errorf("string workflowId = %q", got)
	}
	if ps := problemsOf(t, p, gateYAML(map[string]string{"workflowId": "0"}, "")); !hasProblem(ps, CodeSchema, "") {
		t.Errorf("workflowId 0: %v", ps)
	}
	if ps := problemsOf(t, p, gateYAML(map[string]string{"workflowId": "007"}, "")); !hasProblem(ps, CodeSchema, "") {
		t.Errorf("workflowId 007: %v", ps)
	}

	for _, tt := range []struct{ field, val string }{
		{"switchStaleDays", "0"},
		{"switchStaleDays", "3651"},
		{"switchAbandonedDays", "-1"},
		{"reviewBudgetLines", "0"},
		{"reviewBudgetLines", "100001"},
		{"reviewBudgetLines", "'5'"},
	} {
		ps := problemsOf(t, p, head+"overrides:\n  "+tt.field+": "+tt.val+"\n")
		if !hasProblem(ps, CodeSchema, "/overrides/"+tt.field) {
			t.Errorf("%s: %s: %v", tt.field, tt.val, ps)
		}
	}
	c, err := p.Parse("", []byte(head+"overrides:\n  switchStaleDays: 3650\n  switchAbandonedDays: 1\n  reviewBudgetLines: 100000\n"))
	if err != nil || *c.Overrides.SwitchStaleDays != 3650 || *c.Overrides.ReviewBudgetLines != 100000 {
		t.Errorf("boundary overrides: %v %+v", err, c)
	}
}

func TestParse_WrongVersionOrKind(t *testing.T) {
	t.Parallel()
	p := newParser(t)
	for _, doc := range []string{
		"kind: Contract\n",
		"apiVersion: factory/v1alpha1\n",
		"apiVersion: factory/v1\nkind: Contract\n",
		"apiVersion: factory/v1alpha1\nkind: contract\n",
		"apiVersion: 1\nkind: Contract\n",
	} {
		if ps := problemsOf(t, p, doc); !hasProblem(ps, CodeSchema, "") {
			t.Errorf("%q: %v", doc, ps)
		}
	}
}

func TestParse_Agents(t *testing.T) {
	t.Parallel()
	p := newParser(t)
	for _, v := range []string{"[Security]", "[a, a]", "['a b']", "['../x']"} {
		if ps := problemsOf(t, p, head+"agents:\n  verify: "+v+"\n"); !hasProblem(ps, CodeSchema, "") {
			t.Errorf("agents %s: %v", v, ps)
		}
	}
}

func TestParse_ErrorMessagesBounded(t *testing.T) {
	t.Parallel()
	p := newParser(t)
	ps := problemsOf(t, p, head+"paths:\n  forbidden: ['"+strings.Repeat("\\", 5000)+"']\n")
	for _, pr := range ps {
		if len(pr.Message) > 400 || strings.ContainsAny(pr.Message, "\n\r") {
			t.Errorf("unbounded or multi-line message: %d bytes", len(pr.Message))
		}
	}
}

func TestWorkflowID_Unmarshal(t *testing.T) {
	t.Parallel()
	var w WorkflowID
	for _, in := range []string{`1`, `"abc"`, `9007199254740993`} {
		if err := w.UnmarshalJSON([]byte(in)); err != nil {
			t.Errorf("%s: %v", in, err)
		}
	}
	for _, in := range []string{`0`, `01`, `-1`, `1.0`, `1e3`, `true`, `null`, `[]`, ``} {
		if err := w.UnmarshalJSON([]byte(in)); err == nil {
			t.Errorf("%s: want error", in)
		}
	}
}

func TestGateRef_Key(t *testing.T) {
	t.Parallel()
	a := GateRef{ProducerID: "p:1", WorkflowID: "1", WorkflowRevision: rev40, CheckID: "c"}
	b := a
	b.WorkflowRevision = strings.Repeat("b", 40)
	if a.Key() != b.Key() {
		t.Error("keys differ across revisions")
	}
	b.CheckID = "d"
	if a.Key() == b.Key() {
		t.Error("keys equal across check IDs")
	}
}

func TestSchemaJSON(t *testing.T) {
	t.Parallel()
	first := SchemaJSON()
	var v map[string]any
	if err := json.Unmarshal(first, &v); err != nil {
		t.Fatalf("schema is not valid JSON: %v", err)
	}
	if v["$id"] != "urn:lightsout:contract:v1alpha1" {
		t.Errorf("$id = %v", v["$id"])
	}
	first[0] = 'X'
	if SchemaJSON()[0] == 'X' {
		t.Error("SchemaJSON returned shared memory")
	}
}

func FuzzParse(f *testing.F) {
	entries, err := os.ReadDir("testdata")
	if err != nil {
		f.Fatal(err)
	}
	for _, e := range entries {
		if data, rerr := os.ReadFile(filepath.Join("testdata", e.Name())); rerr == nil {
			f.Add(data)
		}
	}
	p, err := NewParser()
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(_ *testing.T, data []byte) {
		_, _ = p.Parse("src", data)
	})
}

func TestParse_RejectsInvalidPatternSyntax(t *testing.T) { // CON-1, CON-11
	t.Parallel()
	p := newParser(t)
	lists := []string{"writable", "readOnly", "forbidden", "sensitive", "generated"}
	// The zero-width space is also caught earlier by the schema, so either code fails closed.
	patterns := []struct {
		name, yaml string
		code       Code
	}{
		{"dotdot prefix", `'../x'`, CodeInvalidPattern},
		{"dotdot middle", `'a/../b'`, CodeInvalidPattern},
		{"dot prefix", `'./a'`, CodeInvalidPattern},
		{"partial doublestar", `'a**b'`, CodeInvalidPattern},
		{"empty segment", `'a//b'`, CodeInvalidPattern},
		{"trailing slash dir", `'deploy/'`, CodeInvalidPattern},
		{"trailing slash", `'x/'`, CodeInvalidPattern},
		{"zero width space", `"a\u200bb"`, CodeSchema},
	}
	for _, list := range lists {
		for _, pat := range patterns {
			t.Run(list+"/"+pat.name, func(t *testing.T) {
				t.Parallel()
				doc := head + "paths:\n  " + list + ": ['ok', " + pat.yaml + "]\n"
				ps := problemsOf(t, p, doc)
				if !hasProblem(ps, pat.code, "/paths/"+list+"/1") {
					t.Errorf("problems = %v, want %s at /paths/%s/1", ps, pat.code, list)
				}
				if hasProblem(ps, "", "/paths/"+list+"/0") {
					t.Errorf("valid pattern flagged: %v", ps)
				}
			})
		}
	}

	t.Run("all failures reported", func(t *testing.T) {
		t.Parallel()
		doc := head + "paths:\n  writable: ['../a']\n  forbidden: ['b//c', './d']\n"
		ps := problemsOf(t, p, doc)
		for _, f := range []string{"/paths/writable/0", "/paths/forbidden/0", "/paths/forbidden/1"} {
			if !hasProblem(ps, CodeInvalidPattern, f) {
				t.Errorf("missing problem at %s: %v", f, ps)
			}
		}
	})

	t.Run("load fails", func(t *testing.T) {
		t.Parallel()
		fsys := validTree()
		fsys["svc/.factory.yaml"] = file(head + "paths:\n  readOnly: ['a/../b']\n  generated: ['x/']\n")
		ps := loadProblems(t, fsys)
		if !hasProblem(ps, CodeInvalidPattern, "/paths/readOnly/0") || !hasProblem(ps, CodeInvalidPattern, "/paths/generated/0") {
			t.Errorf("problems = %v", ps)
		}
	})
}

func assertSafeProblem(t *testing.T, p Problem) {
	t.Helper()
	for name, v := range map[string]string{"File": p.File, "Field": p.Field, "Message": p.Message, "String": p.String()} {
		for _, r := range v {
			if r < 0x20 || r == 0x7f || r == 0x85 {
				t.Errorf("%s of %q contains control rune %U", name, p.String(), r)
			}
		}
		if len(v) > 700 {
			t.Errorf("%s is %d bytes", name, len(v))
		}
	}
}

func TestProblems_SanitizeUntrustedText(t *testing.T) { // SEC-1
	t.Parallel()
	p := newParser(t)
	key := "x\n::error title=OK::contract valid\n\x1b[2J" + strings.Repeat("A", 900)
	doc := head + "\"" + strings.NewReplacer("\n", `\n`, "\x1b", `\x1b`).Replace(key) + "\": 1\n"
	dir := "evil\n::error::fake"
	_, err := p.Parse(dir, []byte(doc))
	var ve *ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("err = %v, want *ValidationError", err)
	}
	if !hasProblem(ve.Problems, CodeUnknownField, "") {
		t.Fatalf("problems = %v", ve.Problems)
	}
	for _, pr := range ve.Problems {
		for name, v := range map[string]string{"File": pr.File, "Field": pr.Field, "Message": pr.Message} {
			for _, r := range v {
				if r < 0x20 || r == 0x7f || r == 0x85 {
					t.Errorf("%s contains control rune %U", name, r)
				}
			}
			if len(v) > 220 {
				t.Errorf("%s is %d bytes, want <= 220", name, len(v))
			}
			if !utf8.ValidString(v) {
				t.Errorf("%s is not valid UTF-8", name)
			}
		}
		if strings.ContainsAny(pr.String(), "\n\r") {
			t.Errorf("String has a line break: %q", pr.String())
		}
	}
	if strings.ContainsAny(ve.Error(), "\n\r\x1b") {
		t.Errorf("Error has control characters: %q", ve.Error())
	}
}

func TestDisplay(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct{ in, want string }{
		{"plain /path-1", "plain /path-1"},
		{"a\nb", `a\u000ab`},
		{"a\u0085b", `a\u0085b`},
		{"a\u202eb", `a\u202eb`},
		{"a\u200bb", `a\u200bb`},
		{"a\u2028b", `a\u2028b`},
		{"a\xffb", `a\xffb`},
		{"a\U000e0001b", `a\U000e0001b`},
		{"héllo", "héllo"},
		{`a\b`, `a\\b`},
		{`\u000a`, `\\u000a`},
	} {
		if got := display(tt.in, noLimit); got != tt.want {
			t.Errorf("display(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
	for _, in := range []string{
		strings.Repeat("é", 300),
		strings.Repeat("a", 300),
		strings.Repeat("\n", 300),
		strings.Repeat("\\", 300),
		strings.Repeat("世", 300),
	} {
		for _, limit := range []int{10, 199, 200, 201, 202, 203} {
			got := display(in, limit)
			if len(got) > limit || !strings.HasSuffix(got, "\u2026") || !utf8.ValidString(got) {
				t.Errorf("display(%.4q..., %d) = %q (%d bytes)", in, limit, got, len(got))
			}
		}
	}
	if got := display(strings.Repeat("a", 200), 200); strings.Contains(got, "\u2026") || len(got) != 200 {
		t.Errorf("exact-fit text was truncated")
	}
	if got := display(strings.Repeat("a", 201), 200); len(got) != 200 || !strings.HasSuffix(got, "a\u2026") {
		t.Errorf("one-over text = %q", got)
	}
}

func TestSchema_PatternsArePortable(t *testing.T) { // CON-11
	t.Parallel()
	var doc any
	if err := json.Unmarshal(schemaJSON, &doc); err != nil {
		t.Fatal(err)
	}
	n := 0
	var walk func(v any, where string)
	walk = func(v any, where string) {
		switch v := v.(type) {
		case map[string]any:
			for k, c := range v {
				if s, ok := c.(string); ok && k == "pattern" {
					n++
					checkPortable(t, where, s)
					continue
				}
				walk(c, where+"/"+k)
			}
		case []any:
			for i, c := range v {
				walk(c, fmt.Sprintf("%s/%d", where, i))
			}
		}
	}
	walk(doc, "")
	if n == 0 {
		t.Fatal("no patterns found")
	}
}

func checkPortable(t *testing.T, where, pat string) {
	t.Helper()
	for _, r := range pat {
		if r > 0x7e || r < 0x20 {
			t.Errorf("%s: pattern %q is not printable ASCII", where, pat)
			break
		}
	}
	for _, bad := range []string{`\p{`, `\P{`, `\x{`, `(?`, `\z`, `\A`} {
		if strings.Contains(pat, bad) {
			t.Errorf("%s: pattern %q uses %s, which is not portable", where, pat, bad)
		}
	}
	if _, err := regexp.Compile(pat); err != nil {
		t.Errorf("%s: pattern %q: %v", where, pat, err)
	}
}

func TestParse_RejectsNonDecimalNumbers(t *testing.T) { // CON-4
	t.Parallel()
	p := newParser(t)
	tests := []struct {
		name, doc, field, msg string
	}{
		{"float override", head + "overrides:\n  switchStaleDays: 45.0\n", "/overrides/switchStaleDays", "use an integer"},
		{"float workflowId", gateYAML(map[string]string{"workflowId": "16.0"}, ""), "/gates/verify/0/workflowId", "use an integer"},
		{"hex workflowId", gateYAML(map[string]string{"workflowId": "0x10"}, ""), "/gates/verify/0/workflowId", "plain decimal"},
		{"octal 0o", head + "overrides:\n  reviewBudgetLines: 0o17\n", "/overrides/reviewBudgetLines", "plain decimal"},
		{"octal leading zero", head + "overrides:\n  reviewBudgetLines: 017\n", "/overrides/reviewBudgetLines", "plain decimal"},
		{"underscores", head + "overrides:\n  reviewBudgetLines: 1_000\n", "/overrides/reviewBudgetLines", "plain decimal"},
		{"plus sign", head + "overrides:\n  switchStaleDays: +5\n", "/overrides/switchStaleDays", "plain decimal"},
		{"exponent", head + "overrides:\n  switchStaleDays: 1e2\n", "/overrides/switchStaleDays", "use an integer"},
		{"float in list", head + "gates:\n  verify: [1.5]\n", "/gates/verify/0", "use an integer"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ps := problemsOf(t, p, tt.doc)
			if !hasProblem(ps, CodeSchema, tt.field) {
				t.Fatalf("problems = %v, want schema problem at %s", ps, tt.field)
			}
			for _, pr := range ps {
				if pr.Field == tt.field && !strings.Contains(pr.Message, tt.msg) {
					t.Errorf("message %q lacks %q", pr.Message, tt.msg)
				}
				for _, goType := range []string{"float64", "int64", "json.Number", "big."} {
					if strings.Contains(pr.Message, goType) {
						t.Errorf("message %q mentions Go type %s", pr.Message, goType)
					}
				}
			}
		})
	}
	c, err := p.Parse("", []byte(head+"overrides:\n  switchStaleDays: 45\n"))
	if err != nil || *c.Overrides.SwitchStaleDays != 45 {
		t.Errorf("plain decimal rejected: %v", err)
	}
}

func TestParse_RejectsBadEncoding(t *testing.T) { // CON-11
	t.Parallel()
	p := newParser(t)
	utf16le := []byte{0xFF, 0xFE}
	for _, r := range head {
		utf16le = append(utf16le, byte(r), 0)
	}
	utf16leNoBOM := utf16le[2:]
	tests := map[string][]byte{
		"utf-8 bom":       append([]byte{0xEF, 0xBB, 0xBF}, head...),
		"utf-16le bom":    utf16le,
		"utf-16le no bom": utf16leNoBOM,
		"utf-16be bom":    append([]byte{0xFE, 0xFF}, 0, 'a'),
		"utf-32be bom":    {0, 0, 0xFE, 0xFF, 0, 0, 0, 'a'},
		"nul byte":        []byte(head + "lightsOn: true\x00\n"),
		"invalid utf-8":   []byte(head + "# \xff\xfe bad\n"),
	}
	for name, data := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, err := p.Parse("", data)
			var ve *ValidationError
			if !errors.As(err, &ve) || !hasProblem(ve.Problems, CodeUnsafeYAML, "") {
				t.Errorf("err = %v, want unsafe-yaml", err)
			}
		})
	}
}

func TestSchema_EveryObjectClosed(t *testing.T) { // CON-11
	t.Parallel()
	var doc any
	if err := json.Unmarshal(SchemaJSON(), &doc); err != nil {
		t.Fatal(err)
	}
	var walk func(path string, v any)
	walk = func(path string, v any) {
		switch n := v.(type) {
		case map[string]any:
			_, hasProps := n["properties"]
			if n["type"] == "object" || hasProps {
				if n["additionalProperties"] != false {
					t.Errorf("schema node %s is not closed (additionalProperties must be false)", path)
				}
			}
			for k, c := range n {
				walk(path+"/"+k, c)
			}
		case []any:
			for i, c := range n {
				walk(fmt.Sprintf("%s/%d", path, i), c)
			}
		}
	}
	walk("#", doc)
}
