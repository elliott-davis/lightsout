// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

package contract

import (
	"errors"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/google/go-cmp/cmp"
)

var revB = strings.Repeat("b", 40)

// tc is a contract at a directory, as YAML (without the apiVersion and kind lines).
type tc struct{ dir, yaml string }

func buildSet(t *testing.T, contracts ...tc) *Set {
	t.Helper()
	p := newParser(t)
	var cs []*Contract
	for _, c := range contracts {
		parsed, err := p.Parse(c.dir, []byte(head+c.yaml))
		if err != nil {
			t.Fatalf("parse %q: %v", c.dir, err)
		}
		cs = append(cs, parsed)
	}
	set, err := NewSet(rev40, cs...)
	if err != nil {
		t.Fatalf("NewSet: %v", err)
	}
	return set
}

func baselineGate(check string) Gate {
	return Gate{
		Name: check,
		GateRef: GateRef{
			ProducerID: "github-app:1", WorkflowID: "900", WorkflowRevision: rev40, CheckID: check,
		},
		Mandatory: true,
	}
}

func testBaseline() Baseline {
	return Baseline{
		Verify:           []Gate{baselineGate("secret-scan")},
		Union:            []Gate{baselineGate("smoke")},
		Reviewers:        []string{"pr-reviewer", "security-reviewer"},
		SecurityReviewer: "security-reviewer",
		PRReviewer:       "pr-reviewer",
		KnownAgents:      []string{"payments-specialist"},
	}
}

func testDefaults() Defaults {
	return Defaults{SwitchStaleDays: 45, SwitchAbandonedDays: 90, ReviewBudgetLines: 400}
}

func compileSet(t *testing.T, contracts ...tc) (*Policy, error) {
	t.Helper()
	return Compile(buildSet(t, contracts...), testBaseline(), testDefaults())
}

func mustCompile(t *testing.T, contracts ...tc) *Policy {
	t.Helper()
	p, err := compileSet(t, contracts...)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	return p
}

// gateItem renders one gate list item at the given revision. The name is the check ID.
func gateItem(check, rev string, mandatory bool) string {
	m := "false"
	if mandatory {
		m = "true"
	}
	return "    - name: " + check + "\n      producerId: github-app:1\n      workflowId: 7\n" +
		"      workflowRevision: " + rev + "\n      checkId: " + check + "\n      mandatory: " + m + "\n"
}

func verifyGates(items ...string) string {
	return "gates:\n  verify:\n" + strings.Join(items, "")
}

const writableAll = "paths:\n  writable: ['**']\n"

func problemsFrom(t *testing.T, err error) []Problem {
	t.Helper()
	var ve *ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("error %v is not a *ValidationError", err)
	}
	return ve.Problems
}

func TestCompile_ChildCannotDropMandatoryGate(t *testing.T) { // CON-3, CON-5
	t.Parallel()
	root := tc{"", writableAll + verifyGates(gateItem("build", rev40, true))}
	tests := []struct {
		name     string
		child    string
		wantCode Code
	}{
		{"advisory redeclare of parent gate", verifyGates(gateItem("build", rev40, false)), CodeLoosening},
		{"advisory redeclare of baseline gate", verifyGates(gateItem("secret-scan", rev40, false)), CodeLoosening},
		{"different revision than parent", verifyGates(gateItem("build", revB, true)), CodeConflict},
		{"different revision than baseline", verifyGates(gateItem("secret-scan", revB, true)), CodeConflict},
		{"mandatory redeclare tightens", verifyGates(gateItem("build", rev40, true)), ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			// The baseline gate shares its identity with a contract gate only when
			// producer, workflow and check all match.
			child := tt.child
			if strings.Contains(tt.name, "baseline") {
				child = strings.ReplaceAll(child, "workflowId: 7", "workflowId: 900")
			}
			_, err := compileSet(t, root, tc{"svc", child})
			if tt.wantCode == "" {
				if err != nil {
					t.Fatalf("Compile: %v", err)
				}
				return
			}
			ps := problemsFrom(t, err)
			if !hasProblem(ps, tt.wantCode, "/gates/verify/0") {
				t.Fatalf("problems = %v, want %s at /gates/verify/0", ps, tt.wantCode)
			}
			if ps[0].File != "svc/.factory.yaml" {
				t.Errorf("File = %q, want the child's contract file", ps[0].File)
			}
		})
	}
	t.Run("baseline named in message", func(t *testing.T) {
		t.Parallel()
		child := strings.ReplaceAll(verifyGates(gateItem("secret-scan", rev40, false)), "workflowId: 7", "workflowId: 900")
		_, err := compileSet(t, root, tc{"svc", child})
		ps := problemsFrom(t, err)
		if !strings.Contains(ps[0].Message, SourceBaseline) {
			t.Errorf("message %q does not name the factory baseline", ps[0].Message)
		}
	})
	t.Run("empty gates list keeps the parent gate", func(t *testing.T) {
		t.Parallel()
		p := mustCompile(t, root, tc{"svc", "gates:\n  verify: []\n"})
		pp, err := p.ForPath("svc/x.go")
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, o := range pp.VerifyGates {
			found = found || (o.Gate.CheckID == "build" && o.Gate.Mandatory)
		}
		if !found {
			t.Errorf("VerifyGates = %+v, want the parent's build gate", pp.VerifyGates)
		}
	})
	t.Run("duplicate identity in one contract", func(t *testing.T) {
		t.Parallel()
		_, err := compileSet(t, tc{"", writableAll + verifyGates(gateItem("a", rev40, true), gateItem("a", rev40, false))})
		if ps := problemsFrom(t, err); !hasProblem(ps, CodeConflict, "/gates/verify/1") {
			t.Errorf("problems = %v, want conflict at /gates/verify/1", ps)
		}
	})
}

func TestCompile_NoSyntaxToRemoveOrWaive(t *testing.T) { // CON-3, CON-5, AGD-3, CON-12
	t.Parallel()
	for _, extra := range []string{
		"gates:\n  verify: []\n  remove: [build]\n",
		"gates:\n  waive: [secret-scan]\n",
		"agents:\n  remove: [security-reviewer]\n",
		"paths:\n  remove: ['deploy']\n",
	} {
		fsys := fstest.MapFS{
			".factory.yaml":     file(head + writableAll),
			"svc/.factory.yaml": file(head + extra),
		}
		ps := loadProblems(t, fsys)
		if !hasProblem(ps, CodeUnknownField, "") {
			t.Errorf("%q: problems = %v, want unknown-field", extra, ps)
		}
	}
	// And a valid child with empty lists inherits everything, end to end.
	fsys := fstest.MapFS{
		".factory.yaml":     file(head + writableAll + verifyGates(gateItem("build", rev40, true))),
		"svc/.factory.yaml": file(head + "gates:\n  verify: []\nagents:\n  verify: []\n"),
	}
	set, err := Load(t.Context(), fsys, newParser(t), rev40)
	if err != nil {
		t.Fatal(err)
	}
	p, err := Compile(set, testBaseline(), testDefaults())
	if err != nil {
		t.Fatal(err)
	}
	pp, err := p.ForPath("svc/a")
	if err != nil {
		t.Fatal(err)
	}
	if len(pp.VerifyGates) != 2 || len(pp.Reviewers) != 2 {
		t.Errorf("gates = %d, reviewers = %d, want 2 and 2", len(pp.VerifyGates), len(pp.Reviewers))
	}
}

func TestCompile_BaselineMustBeMandatory(t *testing.T) { // CON-5, AGD-3
	t.Parallel()
	set := buildSet(t, tc{"", writableAll})
	advisory := baselineGate("scan")
	advisory.Mandatory = false

	tests := []struct {
		name string
		mod  func(*Baseline, *Defaults)
	}{
		{"advisory baseline verify gate", func(b *Baseline, _ *Defaults) { b.Verify = []Gate{advisory} }},
		{"advisory baseline union gate", func(b *Baseline, _ *Defaults) { b.Union = []Gate{advisory} }},
		{"duplicate baseline gate", func(b *Baseline, _ *Defaults) { b.Verify = []Gate{baselineGate("a"), baselineGate("a")} }},
		{"security reviewer not in reviewers", func(b *Baseline, _ *Defaults) { b.SecurityReviewer = "other" }},
		{"zero default", func(_ *Baseline, d *Defaults) { d.ReviewBudgetLines = 0 }},
		{"PR reviewer equals security reviewer", func(b *Baseline, _ *Defaults) { b.PRReviewer = b.SecurityReviewer }},
		{"empty PR reviewer", func(b *Baseline, _ *Defaults) { b.PRReviewer = "" }},
		{"empty reviewer name", func(b *Baseline, _ *Defaults) { b.Reviewers = append(b.Reviewers, "") }},
		{"reviewer name that is not an agent name", func(b *Baseline, _ *Defaults) { b.Reviewers = append(b.Reviewers, "Bad Name") }},
		{"known agent that is not an agent name", func(b *Baseline, _ *Defaults) { b.KnownAgents = []string{"x\ny"} }},
		{"baseline gate with a non-hex revision", func(b *Baseline, _ *Defaults) {
			g := baselineGate("a")
			g.WorkflowRevision = "main"
			b.Verify = []Gate{g}
		}},
		{"baseline gate with an empty producer", func(b *Baseline, _ *Defaults) {
			g := baselineGate("a")
			g.ProducerID = ""
			b.Union = []Gate{g}
		}},
		{"baseline gate name with a newline", func(b *Baseline, _ *Defaults) {
			g := baselineGate("a")
			g.Name = "x\n::error forged"
			b.Verify = []Gate{g}
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			b, d := testBaseline(), testDefaults()
			tt.mod(&b, &d)
			p, err := Compile(set, b, d)
			if err == nil || p != nil {
				t.Fatalf("Compile = %v, %v, want an error and no policy", p, err)
			}
			var ve *ValidationError
			if errors.As(err, &ve) {
				t.Errorf("error %v is a *ValidationError, want a plain error", err)
			}
		})
	}
	if _, err := Compile(nil, testBaseline(), testDefaults()); err == nil {
		t.Error("Compile(nil set) succeeded")
	}
}

func TestCompile_SafetyFieldsOnlyTighten(t *testing.T) { // CON-12
	t.Parallel()
	tests := []struct {
		name      string
		contracts []tc
		wantCode  Code // "" means the set must compile
		wantFile  string
		wantField string
	}{
		{
			"writable widening",
			[]tc{{"", "paths:\n  writable: ['src/*.go']\n"}, {"src", "paths:\n  writable: ['**']\n"}},
			CodeLoosening, "src/.factory.yaml", "/paths/writable/0",
		},
		{
			"writable narrowing",
			[]tc{{"", "paths:\n  writable: ['src/**']\n"}, {"src", "paths:\n  writable: ['*.go']\n"}},
			"", "", "",
		},
		{
			"readOnly outside parent's reach",
			[]tc{{"", "paths:\n  writable: ['src/**']\n"}, {"docs", "paths:\n  readOnly: ['x']\n"}},
			CodeLoosening, "docs/.factory.yaml", "/paths/readOnly/0",
		},
		{
			"readOnly inside parent's writable",
			[]tc{{"", "paths:\n  writable: ['src/**']\n"}, {"src", "paths:\n  readOnly: ['protos/**']\n"}},
			"", "", "",
		},
		{
			"writable inside ancestor forbidden (descendant rule)",
			[]tc{{"", "paths:\n  writable: ['**']\n  forbidden: ['deploy']\n"}, {"deploy/x", "paths:\n  writable: ['**']\n"}},
			CodeLoosening, "deploy/x/.factory.yaml", "/paths/writable/0",
		},
		{
			"readOnly inside ancestor forbidden",
			[]tc{{"", "paths:\n  writable: ['**']\n  forbidden: ['deploy/**']\n"}, {"deploy", "paths:\n  readOnly: ['x']\n"}},
			CodeLoosening, "deploy/.factory.yaml", "/paths/readOnly/0",
		},
		{
			"writable inside ancestor readOnly",
			[]tc{{"", "paths:\n  writable: ['**']\n  readOnly: ['api/**']\n"}, {"api", "paths:\n  writable: ['**']\n"}},
			CodeLoosening, "api/.factory.yaml", "/paths/writable/0",
		},
		{
			"partial overlap with ancestor readOnly is allowed",
			[]tc{{"", "paths:\n  writable: ['**']\n  readOnly: ['src/gen/**']\n"}, {"src", "paths:\n  writable: ['**']\n"}},
			"", "", "",
		},
		{
			"lightsOn false under true",
			[]tc{{"", writableAll + "lightsOn: true\n"}, {"svc", "lightsOn: false\n"}},
			CodeLoosening, "svc/.factory.yaml", "/lightsOn",
		},
		{
			"lightsOn true under false",
			[]tc{{"", writableAll + "lightsOn: false\n"}, {"svc", "lightsOn: true\n"}},
			"", "", "",
		},
		{
			"gates-only root and a child that grants writable",
			[]tc{{"", verifyGates(gateItem("a", rev40, true))}, {"svc", "paths:\n  writable: ['**']\n"}},
			CodeMissingWritable, ".factory.yaml", "/paths/writable",
		},
		{
			"empty writable root and a child that grants writable",
			[]tc{{"", "paths:\n  writable: []\n"}, {"svc", "paths:\n  writable: ['**']\n"}},
			CodeLoosening, "svc/.factory.yaml", "/paths/writable/0",
		},
		{
			"standalone nested contract without writable",
			[]tc{{"svc", verifyGates(gateItem("a", rev40, true))}},
			CodeMissingWritable, "svc/.factory.yaml", "/paths/writable",
		},
		{
			"empty writable at the top is declared",
			[]tc{{"", "paths:\n  writable: []\n"}},
			"", "", "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := compileSet(t, tt.contracts...)
			if tt.wantCode == "" {
				if err != nil {
					t.Fatalf("Compile: %v", err)
				}
				return
			}
			ps := problemsFrom(t, err)
			for _, p := range ps {
				if p.Code == tt.wantCode && p.File == tt.wantFile && p.Field == tt.wantField {
					return
				}
			}
			t.Errorf("problems = %v, want [%s] in %s at %s", ps, tt.wantCode, tt.wantFile, tt.wantField)
		})
	}
}

func TestCompile_LooseningMessages(t *testing.T) { // CON-12
	t.Parallel()
	_, err := compileSet(t, tc{"", "paths:\n  writable: ['src/*.go']\n"}, tc{"src", "paths:\n  writable: ['**']\n"})
	ps := problemsFrom(t, err)
	if len(ps) != 1 || !strings.Contains(ps[0].Message, "for example") {
		t.Errorf("problems = %v, want one problem with a concrete example", ps)
	}
	// "?*.go" is inside "*.go" but the prover cannot show it: no example exists.
	_, err = compileSet(t, tc{"", "paths:\n  writable: ['x/*.go']\n"}, tc{"x", "paths:\n  writable: ['?*.go']\n"})
	ps = problemsFrom(t, err)
	if len(ps) != 1 || !strings.Contains(ps[0].Message, "could not prove") {
		t.Errorf("problems = %v, want one could-not-prove problem", ps)
	}
}

func TestCompile_CollectsEveryProblem(t *testing.T) { // CON-12
	t.Parallel()
	_, err := compileSet(t,
		tc{"", verifyGates(gateItem("a", rev40, true))},
		tc{"a", "agents:\n  verify: [nobody]\nlightsOn: false\n"},
		tc{"b", "agents:\n  verify: [nobody-else]\n"},
	)
	ps := problemsFrom(t, err)
	if !hasProblem(ps, CodeMissingWritable, "") || !hasProblem(ps, CodeUnknownAgent, "/agents/verify/0") || len(ps) != 3 {
		t.Errorf("problems = %v, want missing-writable and two unknown-agent problems", ps)
	}
}

func TestCompile_RejectsHandBuiltContracts(t *testing.T) { // CON-1, CON-11
	t.Parallel()
	writable := []string{"**"}
	valid := func() *Contract {
		return &Contract{APIVersion: APIVersion, Kind: Kind, Paths: Paths{Writable: &writable}}
	}
	tests := []struct {
		name     string
		mod      func(*Contract)
		wantCode Code
		want     string
	}{
		{"traversing forbidden pattern", func(c *Contract) { c.Paths.Forbidden = []string{"../x"} }, CodeInvalidPattern, "/paths/forbidden/0"},
		{"traversing writable pattern", func(c *Contract) { c.Paths.Writable = &[]string{"a/../b"} }, CodeInvalidPattern, "/paths/writable/0"},
		{"wrong apiVersion", func(c *Contract) { c.APIVersion = "factory/v2" }, CodeSchema, "/apiVersion"},
		{"wrong kind", func(c *Contract) { c.Kind = "Other" }, CodeSchema, "/kind"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			c := valid()
			tt.mod(c)
			set, err := NewSet(rev40, c)
			if err != nil {
				t.Fatalf("NewSet: %v", err)
			}
			p, err := Compile(set, testBaseline(), testDefaults())
			if p != nil {
				t.Fatal("Compile returned a policy")
			}
			if ps := problemsFrom(t, err); !hasProblem(ps, tt.wantCode, tt.want) {
				t.Errorf("problems = %v, want %s at %s", ps, tt.wantCode, tt.want)
			}
		})
	}
}

func TestResolve_CoreReviewersAlwaysPresent(t *testing.T) { // AGD-3
	t.Parallel()
	core := []Requirement{
		{Role: "pr-reviewer", Sources: []string{SourceBaseline}},
		{Role: "security-reviewer", Sources: []string{SourceBaseline}},
	}
	p := mustCompile(t, tc{"", writableAll}, tc{"payments", "agents:\n  verify: [payments-specialist, pr-reviewer]\n"})

	eff, err := p.Resolve([]string{"src/x.go"})
	if err != nil {
		t.Fatal(err)
	}
	if diff := cmp.Diff(core, eff.Reviewers); diff != "" {
		t.Errorf("reviewers with no agents declared (-want +got):\n%s", diff)
	}
	eff, err = p.Resolve([]string{"src/x.go", "payments/x.go"})
	if err != nil {
		t.Fatal(err)
	}
	want := []Requirement{
		{Role: "payments-specialist", Sources: []string{"payments/.factory.yaml"}},
		{Role: "pr-reviewer", Sources: []string{SourceBaseline, "payments/.factory.yaml"}},
		{Role: "security-reviewer", Sources: []string{SourceBaseline}},
	}
	if diff := cmp.Diff(want, eff.Reviewers); diff != "" {
		t.Errorf("reviewers (-want +got):\n%s", diff)
	}
	// The specialist applies under payments only.
	pp, err := p.ForPath("src/x.go")
	if err != nil {
		t.Fatal(err)
	}
	if diff := cmp.Diff(core, pp.Reviewers); diff != "" {
		t.Errorf("reviewers for src/x.go (-want +got):\n%s", diff)
	}

	_, err = compileSet(t, tc{"", writableAll + "agents:\n  verify: [made-up-agent]\n"})
	if ps := problemsFrom(t, err); !hasProblem(ps, CodeUnknownAgent, "/agents/verify/0") {
		t.Errorf("problems = %v, want unknown-agent", ps)
	}
	fsys := fstest.MapFS{".factory.yaml": file(head + writableAll + "agents:\n  remove: [security-reviewer]\n")}
	if ps := loadProblems(t, fsys); !hasProblem(ps, CodeUnknownField, "") {
		t.Errorf("problems = %v, want unknown-field", ps)
	}
}
