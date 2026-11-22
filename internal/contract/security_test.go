// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

package contract

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/elliott-davis/lightsout/internal/pathglob"
)

func unionGates(items ...string) string {
	return "gates:\n  union:\n" + strings.Join(items, "")
}

// baselineIdentity renders a gate item with the baseline gates' producer and workflow.
func baselineIdentity(check, rev string, mandatory bool) string {
	return strings.ReplaceAll(gateItem(check, rev, mandatory), "workflowId: 7", "workflowId: 900")
}

func compileWith(t *testing.T, b Baseline, contracts ...tc) (*Policy, error) {
	t.Helper()
	return Compile(buildSet(t, contracts...), b, testDefaults())
}

func TestCompile_ChildCannotDropMandatoryUnionGate(t *testing.T) { // CON-3, CON-5
	t.Parallel()
	root := tc{"", writableAll + unionGates(gateItem("smoke-svc", rev40, true))}
	tests := []struct {
		name     string
		child    string
		wantCode Code
	}{
		{"advisory redeclare of a parent union gate", unionGates(gateItem("smoke-svc", rev40, false)), CodeLoosening},
		{"advisory redeclare of a baseline union gate", unionGates(baselineIdentity("smoke", rev40, false)), CodeLoosening},
		{"different revision than the parent", unionGates(gateItem("smoke-svc", revB, true)), CodeConflict},
		{"different revision than the baseline", unionGates(baselineIdentity("smoke", revB, true)), CodeConflict},
		{"mandatory redeclare tightens", unionGates(gateItem("smoke-svc", rev40, true)), ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := compileSet(t, root, tc{"svc", tt.child})
			if tt.wantCode == "" {
				if err != nil {
					t.Fatalf("Compile: %v", err)
				}
				return
			}
			if ps := problemsFrom(t, err); !hasProblem(ps, tt.wantCode, "/gates/union/0") {
				t.Errorf("problems = %v, want %s at /gates/union/0", ps, tt.wantCode)
			}
		})
	}
}

func TestResolve_CrossStackUnionConflict(t *testing.T) { // CON-3
	t.Parallel()
	p := mustCompile(t,
		tc{"", writableAll},
		tc{"svc/a", unionGates(gateItem("smoke", rev40, true))},
		tc{"svc/b", unionGates(gateItem("smoke", revB, true))},
	)
	eff, err := p.Resolve([]string{"svc/a/x", "svc/b/x"})
	if err != nil {
		t.Fatal(err)
	}
	if len(eff.Conflicts) != 1 || eff.Conflicts[0].Stage != "union" || !slices.Equal(eff.Conflicts[0].Revisions, []string{rev40, revB}) {
		t.Errorf("Conflicts = %+v, want one union conflict", eff.Conflicts)
	}
}

func TestResolve_BaselineOwnershipSurvivesMerge(t *testing.T) { // CON-5
	t.Parallel()
	// The root redeclares the baseline gate's exact identity and revision as mandatory.
	p := mustCompile(t, tc{"", writableAll + "gates:\n  verify:\n" + baselineIdentity("secret-scan", rev40, true)})
	pp, err := p.ForPath("x")
	if err != nil {
		t.Fatal(err)
	}
	if len(pp.VerifyGates) != 1 {
		t.Fatalf("VerifyGates = %+v, want one merged gate", pp.VerifyGates)
	}
	got := pp.VerifyGates[0]
	if got.Owner != OwnerFactory || !slices.Equal(got.Sources, []string{SourceBaseline, ".factory.yaml"}) {
		t.Errorf("owner = %q, sources = %v, want factory owned from the baseline and the root", got.Owner, got.Sources)
	}
}

func TestStack_CaseVariantDirectoryKeepsChildContract(t *testing.T) { // CON-3, CON-7, SEC-5
	t.Parallel()
	child := "paths:\n  forbidden: ['**']\n  sensitive: ['**']\n" +
		"gates:\n  verify:\n" + gateItem("deploy-gate", rev40, true) +
		"agents:\n  verify: [payments-specialist]\nlightsOn: true\n"
	p := mustCompile(t, tc{"", writableAll}, tc{"deploy", child})
	for _, path := range []string{"deploy/prod.yaml", "DEPLOY/prod.yaml", "Deploy/prod.yaml", "dEpLoY/a/b"} {
		pp, err := p.ForPath(path)
		if err != nil {
			t.Fatal(err)
		}
		hasGate := slices.ContainsFunc(pp.VerifyGates, func(o Obligation) bool { return o.Gate.CheckID == "deploy-gate" })
		hasAgent := slices.ContainsFunc(pp.Reviewers, func(r Requirement) bool { return r.Role == "payments-specialist" })
		if pp.Access != AccessForbidden || !pp.Sensitive || !hasGate || !hasAgent || !pp.LightsOn {
			t.Errorf("%s: access=%v sensitive=%v gate=%v agent=%v lightsOn=%v, want the child's rules", path, pp.Access, pp.Sensitive, hasGate, hasAgent, pp.LightsOn)
		}
		eff, err := p.Resolve([]string{path})
		if err != nil {
			t.Fatal(err)
		}
		if !eff.SecuritySignoffRequired || !eff.LightsOn || eff.SecurityReviewer != "security-reviewer" {
			t.Errorf("%s: effective = %+v", path, eff)
		}
	}
	// The child's own writable list is case-sensitive, so a case variant is not writable.
	w := mustCompile(t, tc{"", writableAll}, tc{"deploy", "paths:\n  writable: ['**']\n"})
	for path, want := range map[string]Access{"deploy/x": AccessWritable, "DEPLOY/x": AccessNone} {
		pp, err := w.ForPath(path)
		if err != nil || pp.Access != want {
			t.Errorf("%s: access = %v (%v), want %v", path, pp.Access, err, want)
		}
	}
}

func TestCompile_CaseVariantDirectoryIsAncestorChecked(t *testing.T) { // CON-12
	t.Parallel()
	_, err := compileSet(t,
		tc{"", "paths:\n  writable: ['**']\n  forbidden: ['deploy/**']\n"},
		tc{"DEPLOY", "paths:\n  writable: ['**']\n"},
	)
	if ps := problemsFrom(t, err); !hasProblem(ps, CodeLoosening, "/paths/writable/0") {
		t.Errorf("problems = %v, want loosening", ps)
	}
	// A child at DEPLOY/x is below a root contract at deploy.
	_, err = compileSet(t,
		tc{"", writableAll},
		tc{"deploy", "paths:\n  forbidden: ['x/**']\n"},
		tc{"DEPLOY/x", "paths:\n  writable: ['**']\n"},
	)
	if ps := problemsFrom(t, err); !hasProblem(ps, CodeLoosening, "/paths/writable/0") {
		t.Errorf("problems = %v, want loosening", ps)
	}
}

func TestCompile_RejectsDirectoriesThatFoldTogether(t *testing.T) { // CON-3
	t.Parallel()
	for _, pair := range [][2]string{{"deploy", "DEPLOY"}, {"a/Svc", "A/svc"}, {"ss", "ß"}, {"infra", "ınfra"}} {
		_, err := compileSet(t, tc{"", writableAll}, tc{pair[0], ""}, tc{pair[1], ""})
		ps := problemsFrom(t, err)
		if !hasProblem(ps, CodeConflict, "") || len(ps) != 1 {
			t.Errorf("%v: problems = %v, want one conflict", pair, ps)
		}
	}
}

func TestAccess_FoldedReadOnlyNeverRaisesVerdict(t *testing.T) { // CON-7
	t.Parallel()
	narrow := mustCompile(t, tc{"", "paths:\n  writable: ['src/**']\n  readOnly: ['api/**']\n"})
	wide := mustCompile(t, tc{"", "paths:\n  writable: ['**']\n  readOnly: ['api/**']\n"})
	for _, tt := range []struct {
		p    *Policy
		path string
		want Access
	}{
		{narrow, "API/x", AccessNone},
		{narrow, "api/x", AccessReadOnly},
		{wide, "API/x", AccessReadOnly},
		{wide, "api/x", AccessReadOnly},
		{wide, "src/x", AccessWritable},
	} {
		pp, err := tt.p.ForPath(tt.path)
		if err != nil || pp.Access != tt.want {
			t.Errorf("%s: access = %v (%v), want %v", tt.path, pp.Access, err, tt.want)
		}
	}
}

func TestDeny_FoldedFormsThroughForPath(t *testing.T) { // CON-7, SEC-5
	t.Parallel()
	p := mustCompile(t, tc{"", "paths:\n  writable: ['**']\n  forbidden: ['deploy/?.yaml', 'deploy/?.yml', 'deploy/fi.yaml', 'infra/**', 'keys/**/*.pem', 'caf?/**']\n  sensitive: ['deploy/?.yaml', 'deploy/?.yml', 'deploy/fi.yaml', '**/*.pem']\n"})
	tests := []struct {
		path      string
		sensitive bool
	}{
		{"DEPLOY/\u00df.yaml", true},
		{"\u0131nfra/x", false},
		{"KEYS/a/b.PEM", true},
		{"cafe\u0301/x", false},
		{"dep\u00adloy/a.yaml", true},
		{"deploy./a.yaml", true},
		{"deploy\u200d/a.yaml", true},
		// Combined foldings: each path needs a clean step and a case step together.
		{"deploy./\u00df.yaml", true},
		{"deploy\u200d/\u00df.yaml", true},
		{"deploy./\ufb01.yaml", true},
		{"deploy/\u00df\u200c.yaml", true},
		{"deploy./\u00df.yml", true},
		{"DEPLOY./\u00c9.yaml", true},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			t.Parallel()
			pp, err := p.ForPath(tt.path)
			if err != nil {
				t.Fatal(err)
			}
			if pp.Access != AccessForbidden || tt.sensitive && !pp.Sensitive {
				t.Errorf("access = %v, sensitive = %v, want forbidden and sensitive %v", pp.Access, pp.Sensitive, tt.sensitive)
			}
		})
	}
	if pp, err := p.ForPath("src/ok.go"); err != nil || pp.Access != AccessWritable || pp.Sensitive {
		t.Errorf("src/ok.go = %+v, %v", pp, err)
	}
}

func TestForPath_UncheckableFormIsAnError(t *testing.T) { // CON-7
	t.Parallel()
	p := mustCompile(t, tc{"", writableAll + "  forbidden: ['**/*.pem']\n"}, tc{"deploy", ""})
	// Valid as written, too long once folded, so a deny list can't be checked in every form.
	long := "deploy/" + strings.Repeat("\u023a", 100) + "/KEY.PEM"
	for name, path := range map[string]string{"grows when folded": long, "empty skeleton": "deploy/\u200b/x", "only dots": "a/.../x"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			pp, err := p.ForPath(path)
			if !errors.Is(err, pathglob.ErrInvalidPath) || pp.Protected || pp.Covered {
				t.Errorf("ForPath = %+v, %v, want ErrInvalidPath and no result", pp, err)
			}
			if _, err := p.Resolve([]string{"ok", path}); !errors.Is(err, pathglob.ErrInvalidPath) {
				t.Errorf("Resolve err = %v, want ErrInvalidPath", err)
			}
		})
	}
}

func TestStack_IsAChainOfCanonicalKeys(t *testing.T) { // CON-3, CON-7
	t.Parallel()
	// \u00df\u0131 and ssi are the same directory, and ssi/x is below it: one chain.
	p := mustCompile(t, tc{"", writableAll}, tc{"\u00df\u0131", ""}, tc{"ssi/x", ""})
	pp, err := p.ForPath("\u00dfi/x/f")
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{".factory.yaml", "\u00df\u0131/.factory.yaml", "ssi/x/.factory.yaml"}; !slices.Equal(pp.Stack, want) {
		t.Errorf("Stack = %q, want %q", pp.Stack, want)
	}
	// Spellings that only a normalizing or case-insensitive checkout would merge.
	q := mustCompile(t, tc{"", writableAll}, tc{"deploy", "paths:\n  forbidden: ['**']\n"})
	for _, path := range []string{"deploy\u200d/x", "deploy./x", "deploy /x", "DEPLOY/x", "dep\u00adloy/x", "deploy\u0307/x"} {
		pp, err := q.ForPath(path)
		if err != nil || len(pp.Stack) != 2 || pp.Access != AccessForbidden {
			t.Errorf("%q: %+v, %v, want the deploy contract on the stack", path, pp, err)
		}
	}
	// Directories with the same key collide, however the key is reached.
	for _, pair := range [][2]string{{"deploy", "deploy."}, {"deploy", "dep\u00adloy"}, {"a/b", "A/B "}} {
		_, err := compileSet(t, tc{"", writableAll}, tc{pair[0], ""}, tc{pair[1], ""})
		if ps := problemsFrom(t, err); !hasProblem(ps, CodeConflict, "") {
			t.Errorf("%v: problems = %v, want a collision", pair, ps)
		}
	}
}

func TestCompile_FoldedChainsCannotHideAContract(t *testing.T) { // CON-3, CON-12
	t.Parallel()
	// Two spellings of one 16-deep chain, and a leaf under a third spelling with an
	// unknown agent and an advisory baseline redeclaration.
	spell := func(unit string, depth int) []string {
		var dirs []string
		for i := 1; i <= depth; i++ {
			dirs = append(dirs, strings.TrimSuffix(strings.Repeat(unit+"/", i), "/"))
		}
		return dirs
	}
	cs := []tc{{"", writableAll}}
	for _, d := range spell("i\u0307", 16) {
		cs = append(cs, tc{d, ""})
	}
	for _, d := range spell("i", 16) {
		cs = append(cs, tc{d, ""})
	}
	leaf := "agents:\n  verify: [nobody]\n" + "gates:\n  verify:\n" + baselineIdentity("secret-scan", rev40, false)
	cs = append(cs, tc{strings.Repeat("\u0130/", 16) + "leaf", leaf})
	_, err := compileSet(t, cs...)
	ps := problemsFrom(t, err)
	if !hasProblem(ps, CodeConflict, "") && !hasProblem(ps, CodeTooMany, "") {
		t.Errorf("problems = %v, want a collision or too-many", ps)
	}
}

func TestResolve_BoundsAreErrors(t *testing.T) { // CON-3, CON-7
	t.Parallel()
	p := mustCompile(t, tc{"", writableAll})
	many := make([]string, MaxResolvePaths+1)
	for i := range many {
		many[i] = fmt.Sprintf("p%d", i)
	}
	if _, err := p.Resolve(many); !errors.Is(err, ErrTooComplex) {
		t.Errorf("Resolve(%d paths) err = %v, want ErrTooComplex", len(many), err)
	}
	if _, err := p.Resolve(many[:MaxResolvePaths]); err != nil {
		t.Errorf("Resolve(%d paths): %v", MaxResolvePaths, err)
	}
}

func hostileRoot(tb testing.TB) (*Policy, string) {
	tb.Helper()
	// About 110 near-512-character forbidden patterns of the form **/a/**/a/.../zaa..q
	// and a 255-segment path: the shape that made matching explode.
	var pats []string
	for i := range 110 {
		tail := fmt.Sprintf("z%03d", i) + strings.Repeat("a", 20) + "q"
		pats = append(pats, "**/"+strings.Repeat("a/**/", (500-len(tail)-3)/5)+tail)
	}
	w := []string{"**"}
	c := &Contract{APIVersion: APIVersion, Kind: Kind, Paths: Paths{Writable: &w, Forbidden: pats}}
	set, err := NewSet(rev40, c)
	if err != nil {
		tb.Fatal(err)
	}
	p, err := Compile(set, testBaseline(), testDefaults())
	if err != nil {
		tb.Fatalf("Compile: %v", err)
	}
	return p, strings.Repeat("a/", 254) + "a"
}

func TestForPath_HostilePatternsAreBounded(t *testing.T) { // CON-7
	t.Parallel()
	p, path := hostileRoot(t)
	_, err := p.ForPath(path)
	if err != nil && !errors.Is(err, ErrTooComplex) {
		t.Errorf("ForPath err = %v, want success or ErrTooComplex", err)
	}
}

func TestCompile_HostileContractsAreBounded(t *testing.T) { // CON-12
	t.Parallel()
	set := hostileChain(t)
	p, err := Compile(set, testBaseline(), testDefaults())
	if err != nil {
		var ve *ValidationError
		if !errors.As(err, &ve) || !hasProblem(ve.Problems, CodeTooMany, "") {
			t.Fatalf("Compile err = %v, want success or too-many", err)
		}
		return
	}
	if _, err := p.ForPath(strings.Repeat("d/", 30) + "x"); err != nil && !errors.Is(err, ErrTooComplex) {
		t.Errorf("ForPath err = %v", err)
	}
}

// hostileChain is a 32-deep chain of contracts with 40 patterns of about 500
// characters in each list.
func hostileChain(tb testing.TB) *Set {
	tb.Helper()
	list := func(prefix string) []string {
		out := make([]string, 40)
		for i := range out {
			tail := fmt.Sprintf("%s%03d", prefix, i)
			out[i] = strings.Repeat("a*/", 170)[:490-len(tail)] + tail
		}
		return out
	}
	var cs []*Contract
	var dir []string
	for i := range MaxStackDepth {
		c := &Contract{
			Dir: strings.Join(dir, "/"), APIVersion: APIVersion, Kind: Kind,
			Paths: Paths{ReadOnly: list("r"), Forbidden: list("f"), Sensitive: list("s")},
		}
		if i == 0 {
			w := []string{"**"}
			c.Paths.Writable = &w
		}
		cs = append(cs, c)
		dir = append(dir, "d")
	}
	set, err := NewSet(rev40, cs...)
	if err != nil {
		tb.Fatal(err)
	}
	return set
}

func TestCompile_NormalDeepTreeStillWorks(t *testing.T) { // CON-3
	t.Parallel()
	set, path := deepSet(t, MaxStackDepth-1, 4)
	p, err := Compile(set, testBaseline(), testDefaults())
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	eff, err := p.Resolve([]string{path})
	if err != nil || len(eff.Paths[0].Stack) != MaxStackDepth-1 || eff.Paths[0].Access != AccessWritable {
		t.Errorf("Resolve = %+v, %v", eff, err)
	}
}

func BenchmarkForPath_Hostile512(b *testing.B) {
	p, path := hostileRoot(b)
	b.ResetTimer()
	for range b.N {
		_, _ = p.ForPath(path)
	}
}

func BenchmarkCompile_Hostile(b *testing.B) {
	set := hostileChain(b)
	b.ResetTimer()
	for range b.N {
		_, _ = Compile(set, testBaseline(), testDefaults())
	}
}

func TestPolicy_DoesNotAliasSetContracts(t *testing.T) { // CON-5, CON-12
	t.Parallel()
	yaml := "paths:\n  writable: ['**']\n  generated: ['gen/**']\n  readOnly: ['ro']\n  forbidden: ['fb']\n  sensitive: ['sn']\nlightsOn: true\n" +
		"overrides:\n  reviewBudgetLines: 50\n  switchStaleDays: 5\n  switchAbandonedDays: 6\n" +
		"gates:\n  verify:\n" + gateItem("a", rev40, true) +
		"  union:\n" + gateItem("u", rev40, true) +
		"  darkMergeOracle:\n    producerId: github-app:1\n    workflowId: 7\n    workflowRevision: " + rev40 + "\n    checkId: o\n    observables: [reads, writes]\n" + manifestLine +
		"agents:\n  verify: [payments-specialist]\n"
	parser := newParser(t)
	c, err := parser.Parse("", []byte(head+yaml))
	if err != nil {
		t.Fatal(err)
	}
	set, err := NewSet(rev40, c)
	if err != nil {
		t.Fatal(err)
	}
	p, err := Compile(set, testBaseline(), testDefaults())
	if err != nil {
		t.Fatal(err)
	}
	paths := []string{"x", "gen/y", "ro/z", "fb/w", "sn/v"}
	resolve := func() *Effective {
		eff, err := p.Resolve(paths)
		if err != nil {
			t.Fatal(err)
		}
		return eff
	}
	before := resolve()
	c.Gates.Verify[0].Mandatory = false
	c.Gates.Verify = append(c.Gates.Verify, Gate{Name: "extra"})
	c.Gates.Union[0].Mandatory = false
	*c.LightsOn = false
	*c.Overrides.ReviewBudgetLines = -5
	*c.Overrides.SwitchStaleDays = -5
	*c.Overrides.SwitchAbandonedDays = -5
	c.Agents.Verify[0] = "other"
	c.Agents.Verify = append(c.Agents.Verify, "more")
	c.Gates.DarkMergeOracle.Observables[0] = ObservableEvents
	c.Gates.DarkMergeOracle.CheckID = "changed"
	(*c.Paths.Writable)[0] = "nothing"
	(*c.Paths.Generated)[0] = "other/**"
	c.Paths.ReadOnly[0] = "x"
	c.Paths.Forbidden[0] = "x"
	c.Paths.Sensitive[0] = "x"
	if diff := cmp.Diff(before, resolve()); diff != "" {
		t.Errorf("mutating the source contract changed the policy (-before +after):\n%s", diff)
	}
}

func TestAccess_FoldedReadOnlyWithoutWritable(t *testing.T) { // CON-7
	t.Parallel()
	p := mustCompile(t, tc{"", writableAll}, tc{"src", "paths:\n  readOnly: ['vendor/**']\n"})
	pp, err := p.ForPath("src/VENDOR/x")
	if err != nil {
		t.Fatal(err)
	}
	if pp.Access != AccessReadOnly || pp.AccessSource != "src/.factory.yaml" {
		t.Errorf("access = %v from %q, want read-only from src/.factory.yaml", pp.Access, pp.AccessSource)
	}
}

func TestCompile_HandBuiltNilWritableMeansEmpty(t *testing.T) { // CON-7, CON-12
	t.Parallel()
	var none []string
	c := &Contract{APIVersion: APIVersion, Kind: Kind, Paths: Paths{Writable: &none}}
	set, err := NewSet(rev40, c)
	if err != nil {
		t.Fatal(err)
	}
	p, err := Compile(set, testBaseline(), testDefaults())
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if pp, err := p.ForPath("x"); err != nil || pp.Access != AccessNone {
		t.Errorf("ForPath = %+v, %v, want none (declared empty)", pp, err)
	}
}

func TestCompile_RejectsHandBuiltContractsInFull(t *testing.T) { // CON-4, CON-11
	t.Parallel()
	gate := func(mod func(*Gate)) *Contract {
		g := baselineGate("g")
		g.WorkflowID = "7"
		mod(&g)
		return &Contract{Gates: Gates{Verify: []Gate{g}}}
	}
	oracle := func(mod func(*Oracle)) *Contract {
		o := Oracle{GateRef: baselineGate("o").GateRef, Observables: []Observable{ObservableReads}, CaseManifest: CaseManifest{Path: "m.yaml", SHA256: manifestSHA}}
		mod(&o)
		return &Contract{Gates: Gates{DarkMergeOracle: &o}}
	}
	intp := func(n int) *int { return &n }
	tests := []struct {
		name string
		c    *Contract
	}{
		{"empty producerId", gate(func(g *Gate) { g.ProducerID = "" })},
		{"empty workflowId", gate(func(g *Gate) { g.WorkflowID = "" })},
		{"empty checkId", gate(func(g *Gate) { g.CheckID = "" })},
		{"branch name as revision", gate(func(g *Gate) { g.WorkflowRevision = "main" })},
		{"oracle at HEAD", oracle(func(o *Oracle) { o.WorkflowRevision = "HEAD" })},
		{"forged log line in a gate name", gate(func(g *Gate) { g.Name = "x\n::error forged" })},
		{"unknown observable", oracle(func(o *Oracle) { o.Observables = []Observable{"anything"} })},
		{"no observables", oracle(func(o *Oracle) { o.Observables = nil })},
		{"empty case manifest", oracle(func(o *Oracle) { o.CaseManifest = CaseManifest{} })},
		{"case manifest without a digest", oracle(func(o *Oracle) { o.CaseManifest.SHA256 = "" })},
		{"case manifest with an uppercase digest", oracle(func(o *Oracle) { o.CaseManifest.SHA256 = strings.ToUpper(manifestSHA) })},
		{"case manifest path with ..", oracle(func(o *Oracle) { o.CaseManifest.Path = "../m.yaml" })},
		{"case manifest path with a newline", oracle(func(o *Oracle) { o.CaseManifest.Path = "m.yaml\n::error x" })},
		{"negative review budget", &Contract{Overrides: Overrides{ReviewBudgetLines: intp(-1)}}},
		{"zero stale days", &Contract{Overrides: Overrides{SwitchStaleDays: intp(0)}}},
		{"agent with a bad name", &Contract{Agents: Agents{Verify: []string{"Bad Name"}}}},
		{"duplicate agent", &Contract{Agents: Agents{Verify: []string{"payments-specialist", "payments-specialist"}}}},
		{"duplicate pattern", &Contract{Paths: Paths{Forbidden: []string{"a", "a"}}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			tt.c.APIVersion, tt.c.Kind = APIVersion, Kind
			w := []string{"**"}
			tt.c.Paths.Writable = &w
			set, err := NewSet(rev40, tt.c)
			if err != nil {
				t.Fatal(err)
			}
			p, err := Compile(set, testBaseline(), testDefaults())
			if p != nil {
				t.Fatal("Compile returned a policy")
			}
			if ps := problemsFrom(t, err); !hasProblem(ps, CodeSchema, "") {
				t.Errorf("problems = %v, want a schema problem", ps)
			}
		})
	}
}

func TestSchema_ParsedContractsRoundTrip(t *testing.T) { // CON-11
	t.Parallel()
	parser := newParser(t)
	entries, err := os.ReadDir("testdata")
	if err != nil {
		t.Fatal(err)
	}
	checked := 0
	for _, e := range entries {
		data := readFixture(t, e.Name())
		c, err := parser.Parse("", data)
		if err != nil {
			continue // an invalid fixture
		}
		checked++
		if ps := parser.validateContract(filepath.Join("testdata", e.Name()), c); len(ps) != 0 {
			t.Errorf("%s: marshaled contract has problems %v", e.Name(), ps)
		}
	}
	if checked < 2 {
		t.Errorf("only %d valid fixtures were round-tripped", checked)
	}
	// Both workflow ID spellings survive the round trip.
	for _, wf := range []string{"67890", "'ci/main.yml'"} {
		doc := strings.Replace(gateYAML(map[string]string{"workflowId": wf}, ""), "gates:", "paths:\n  writable: ['**']\ngates:", 1)
		c, err := parser.Parse("", []byte(doc))
		if err != nil {
			t.Fatal(err)
		}
		if ps := parser.validateContract(".factory.yaml", c); len(ps) != 0 {
			t.Errorf("workflowId %s: %v", wf, ps)
		}
	}
}

func TestCompile_BoundsTheWork(t *testing.T) { // CON-12
	t.Parallel()
	codeOf := func(err error) Code {
		var ve *ValidationError
		if errors.As(err, &ve) && len(ve.Problems) > 0 {
			return ve.Problems[0].Code
		}
		return ""
	}
	tests := []struct {
		name            string
		depth, patterns int
		wantFail        bool
	}{
		{"depth over the cap", 40, 128, true},
		{"depth one over the cap", MaxStackDepth + 1, 1, true},
		{"depth at the cap", MaxStackDepth, 1, false},
		{"work budget exhausted", 20, 256, true},
		{"modest tree", 10, 8, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			set, path := deepSet(t, tt.depth, tt.patterns)
			p, err := Compile(set, testBaseline(), testDefaults())
			switch {
			case tt.wantFail && (err == nil || codeOf(err) != CodeTooMany || p != nil):
				t.Fatalf("Compile = %v, %v, want a too-many problem and no policy", p, err)
			case !tt.wantFail && err != nil:
				t.Fatalf("Compile: %v", err)
			}
			if p != nil {
				if _, err := p.ForPath(path); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkCompile_Deep(b *testing.B) {
	set, _ := deepSet(b, MaxStackDepth, 8)
	b.ResetTimer()
	for range b.N {
		if _, err := Compile(set, testBaseline(), testDefaults()); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkForPath_Deep(b *testing.B) {
	set, path := deepSet(b, MaxStackDepth, 8)
	p, err := Compile(set, testBaseline(), testDefaults())
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for range b.N {
		if _, err := p.ForPath(path); err != nil {
			b.Fatal(err)
		}
	}
}

func TestAccess_ProtectedPaths(t *testing.T) { // CON-6, CON-2
	t.Parallel()
	b := testBaseline()
	b.Protected = []string{".github/workflows/**", "CODEOWNERS"}
	p, err := compileWith(t, b, tc{"", writableAll}, tc{"svc", ""})
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{
		".factory.yaml", "svc/.factory.yaml", "SVC/.FACTORY.YAML", "a/b/.factory.yml", ".github/workflows/ci.yml", ".GitHub/Workflows/ci.yml", "CODEOWNERS",
	} {
		pp, err := p.ForPath(path)
		if err != nil {
			t.Fatal(err)
		}
		if pp.Access != AccessForbidden || !pp.Protected || pp.AccessSource != SourceProtected {
			t.Errorf("%s: access = %v protected = %v source = %q", path, pp.Access, pp.Protected, pp.AccessSource)
		}
	}
	for _, path := range []string{"svc/main.go", "factory.yaml", "docs/CODEOWNERS.md"} {
		if pp, err := p.ForPath(path); err != nil || pp.Protected || pp.Access != AccessWritable {
			t.Errorf("%s: %+v, %v, want an ordinary writable path", path, pp, err)
		}
	}
	for _, bad := range []string{"../x", "", "a/[b]"} {
		b := testBaseline()
		b.Protected = []string{bad}
		if _, err := compileWith(t, b, tc{"", writableAll}); err == nil {
			t.Errorf("protected pattern %q was accepted", bad)
		}
	}
}

func TestCompile_BaselineReviewers(t *testing.T) { // AGD-3
	t.Parallel()
	set := buildSet(t, tc{"", writableAll})
	for name, mod := range map[string]func(*Baseline){
		"empty PR reviewer":             func(b *Baseline) { b.PRReviewer = "" },
		"PR reviewer not in reviewers":  func(b *Baseline) { b.PRReviewer = "someone" },
		"empty security reviewer":       func(b *Baseline) { b.SecurityReviewer = "" },
		"reviewers without the PR role": func(b *Baseline) { b.Reviewers = []string{"security-reviewer"} },
	} {
		b := testBaseline()
		mod(&b)
		p, err := Compile(set, b, testDefaults())
		var ve *ValidationError
		if p != nil || err == nil || errors.As(err, &ve) {
			t.Errorf("%s: Compile = %v, %v, want a plain error", name, p, err)
		}
	}
	p := mustCompile(t, tc{"", writableAll})
	eff, err := p.Resolve([]string{"x"})
	if err != nil || eff.SecurityReviewer != "security-reviewer" {
		t.Errorf("SecurityReviewer = %q, %v", eff.SecurityReviewer, err)
	}
}

func TestRules_AccumulateFieldsCannotBeCleared(t *testing.T) { // CON-12
	t.Parallel()
	const svcFile = "svc/.factory.yaml"
	gate := gateItem("g", rev40, true)
	oracle := "gates:\n  darkMergeOracle:\n    producerId: github-app:1\n    workflowId: 7\n    workflowRevision: " + rev40 + "\n    checkId: o\n    observables: [reads]\n" + manifestLine
	tests := map[string]struct {
		parent, child string
		holds         func(PathPolicy) bool
	}{
		"/paths/readOnly": {
			"paths:\n  writable: ['**']\n  readOnly: ['svc/ro/**']\n", "paths:\n  readOnly: []\n",
			func(pp PathPolicy) bool { return pp.Access == AccessReadOnly },
		},
		"/paths/forbidden": {
			"paths:\n  writable: ['**']\n  forbidden: ['svc/ro/**']\n", "paths:\n  forbidden: []\n",
			func(pp PathPolicy) bool { return pp.Access == AccessForbidden },
		},
		"/paths/sensitive": {
			"paths:\n  writable: ['**']\n  sensitive: ['svc/ro/**']\n", "paths:\n  sensitive: []\n",
			func(pp PathPolicy) bool { return pp.Sensitive },
		},
		"/gates/verify": {
			writableAll + "gates:\n  verify:\n" + gate, "gates:\n  verify: []\n",
			func(pp PathPolicy) bool {
				return slices.ContainsFunc(pp.VerifyGates, func(o Obligation) bool { return o.Gate.CheckID == "g" })
			},
		},
		"/gates/union": {
			writableAll + unionGates(gate), "gates:\n  union: []\n",
			func(pp PathPolicy) bool {
				return slices.ContainsFunc(pp.UnionGates, func(o Obligation) bool { return o.Gate.CheckID == "g" })
			},
		},
		// An oracle is one object, so the child has no way to write it empty; it can only omit it.
		"/gates/darkMergeOracle": {
			writableAll + oracle, "gates:\n  verify: []\n",
			func(pp PathPolicy) bool { return len(pp.Oracles) == 1 },
		},
		"/agents/verify": {
			writableAll + "agents:\n  verify: [payments-specialist]\n", "agents:\n  verify: []\n",
			func(pp PathPolicy) bool {
				return slices.ContainsFunc(pp.Reviewers, func(r Requirement) bool { return r.Role == "payments-specialist" })
			},
		},
	}
	for key, class := range fieldRules() {
		if class != RuleSafetyAccumulate {
			continue
		}
		tt, ok := tests[key]
		if !ok {
			t.Errorf("accumulate rule %s has no behavior row", key)
			continue
		}
		parent := tt.parent
		if !strings.HasPrefix(parent, "paths:\n  writable") && !strings.Contains(parent, "writable") {
			parent = writableAll + parent
		}
		p := mustCompile(t, tc{"", parent}, tc{"svc", tt.child})
		pp, err := p.ForPath("svc/ro/x")
		if err != nil {
			t.Fatal(err)
		}
		if !tt.holds(pp) || !slices.Contains(pp.Stack, svcFile) {
			t.Errorf("%s: the parent's entry no longer applies below a child that declares it empty: %+v", key, pp)
		}
	}
	for key := range tests {
		if fieldRules()[key] != RuleSafetyAccumulate {
			t.Errorf("behavior row %s is not an accumulate rule", key)
		}
	}

	// lightsOn (RuleSafetyOnlyOn): an unset middle level does not hide the grandparent.
	if fieldRules()["/lightsOn"] != RuleSafetyOnlyOn {
		t.Fatal("lightsOn is not an only-on rule")
	}
	_, err := compileSet(t, tc{"", writableAll + "lightsOn: true\n"}, tc{"svc", ""}, tc{"svc/a", "lightsOn: false\n"})
	ps := problemsFrom(t, err)
	if len(ps) != 1 || !hasProblem(ps, CodeLoosening, "/lightsOn") || ps[0].File != "svc/a/.factory.yaml" {
		t.Errorf("problems = %v, want one lightsOn loosening on the leaf", ps)
	}
}

func TestCompile_TooManyProblemsStopsWork(t *testing.T) { // CON-12
	t.Parallel()
	// Many contracts each with an unknown agent: validation stops at the problem cap.
	var cs []tc
	cs = append(cs, tc{"", writableAll})
	for i := range 150 {
		cs = append(cs, tc{fmt.Sprintf("d%03d", i), "agents:\n  verify: [nobody]\n"})
	}
	_, err := compileSet(t, cs...)
	ps := problemsFrom(t, err)
	if len(ps) != maxProblems {
		t.Errorf("len(problems) = %d, want %d", len(ps), maxProblems)
	}
}

func TestDeny_QuestionMarkWidensInFoldedForms(t *testing.T) { // CON-7, SEC-5
	t.Parallel()
	p := mustCompile(t,
		tc{"", "paths:\n  writable: ['**']\n  forbidden: ['deploy/?.yaml', 'deploy/???.yaml']\n  sensitive: ['deploy/?.yaml']\n"},
		tc{"deploy", "paths:\n  forbidden: ['?.yml']\n"},
	)
	for _, path := range []string{"deploy/ss.yaml", "deploy/SS.yaml", "deploy/ffi.yml", "deploy/éy.yaml"} {
		pp, err := p.ForPath(path)
		if err != nil || pp.Access != AccessForbidden {
			t.Errorf("%s: access = %v (%v), want forbidden", path, pp.Access, err)
		}
	}
	if pp, err := p.ForPath("deploy/SS.yaml"); err != nil || !pp.Sensitive {
		t.Errorf("deploy/SS.yaml: sensitive = %v (%v)", pp.Sensitive, err)
	}
	// Exact-form matching keeps "?" at one rune, and writable never uses folded forms.
	w := mustCompile(t, tc{"", "paths:\n  writable: ['?.go']\n"})
	for path, want := range map[string]Access{"a.go": AccessWritable, "ab.go": AccessNone, "SS.go": AccessNone} {
		if pp, err := w.ForPath(path); err != nil || pp.Access != want {
			t.Errorf("%s: access = %v (%v), want %v", path, pp.Access, err, want)
		}
	}
}
