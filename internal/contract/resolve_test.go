// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

package contract

import (
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/elliott-davis/lightsout/internal/pathglob"
)

func obligation(check string, owner Owner, sources ...string) Obligation {
	return Obligation{
		Gate: Gate{
			Name:      check,
			GateRef:   GateRef{ProducerID: "github-app:1", WorkflowID: "7", WorkflowRevision: rev40, CheckID: check},
			Mandatory: true,
		},
		Owner:   owner,
		Sources: sources,
	}
}

func baselineObligation(check string) Obligation {
	o := obligation(check, OwnerFactory, SourceBaseline)
	o.Gate.WorkflowID = "900"
	return o
}

func TestResolve_ChangeSpanningTwoOwners(t *testing.T) { // CON-3
	t.Parallel()
	p := mustCompile(t,
		tc{"", writableAll},
		tc{"svc/a", verifyGates(gateItem("build-a", rev40, true))},
		tc{"svc/b", verifyGates(gateItem("build-b", rev40, true))},
	)
	eff, err := p.Resolve([]string{"svc/a/x.go", "svc/b/y.go"})
	if err != nil {
		t.Fatal(err)
	}
	want := []Obligation{
		obligation("build-a", OwnerContract, "svc/a/.factory.yaml"),
		obligation("build-b", OwnerContract, "svc/b/.factory.yaml"),
		baselineObligation("secret-scan"),
	}
	if diff := cmp.Diff(want, eff.VerifyGates); diff != "" {
		t.Errorf("VerifyGates (-want +got):\n%s", diff)
	}
	if len(eff.Conflicts) != 0 || eff.Revision != rev40 {
		t.Errorf("conflicts = %v, revision = %q", eff.Conflicts, eff.Revision)
	}
	one, err := p.Resolve([]string{"svc/a/x.go"})
	if err != nil {
		t.Fatal(err)
	}
	if len(one.VerifyGates) != 2 {
		t.Fatalf("single-owner VerifyGates = %+v, want build-a and the baseline gate", one.VerifyGates)
	}
	if diff := cmp.Diff(want[:1], one.VerifyGates[:1]); diff != "" {
		t.Errorf("single-owner VerifyGates (-want +got):\n%s", diff)
	}
}

func TestResolve_GateMerging(t *testing.T) { // CON-3, CON-5
	t.Parallel()
	// A child tightens an advisory ancestor gate: the merged gate is mandatory
	// below the child and keeps both sources. (Baseline ownership surviving a
	// merge is TestResolve_BaselineOwnershipSurvivesMerge.)
	p := mustCompile(t,
		tc{"", writableAll + verifyGates(gateItem("lint", rev40, false))},
		tc{"svc", verifyGates(gateItem("lint", rev40, true))},
	)
	pp, err := p.ForPath("svc/x")
	if err != nil {
		t.Fatal(err)
	}
	want := []Obligation{
		obligation("lint", OwnerContract, ".factory.yaml", "svc/.factory.yaml"),
		baselineObligation("secret-scan"),
	}
	if diff := cmp.Diff(want, pp.VerifyGates); diff != "" {
		t.Errorf("VerifyGates (-want +got):\n%s", diff)
	}
	root, err := p.ForPath("x")
	if err != nil {
		t.Fatal(err)
	}
	if root.VerifyGates[0].Gate.Mandatory {
		t.Error("root path sees the child's tightened gate")
	}
}

func TestResolve_CrossStackPinConflict(t *testing.T) { // CON-3
	t.Parallel()
	p := mustCompile(t,
		tc{"", writableAll},
		tc{"svc/a", verifyGates(gateItem("build", rev40, true))},
		tc{"svc/b", verifyGates(gateItem("build", revB, true))},
	)
	eff, err := p.Resolve([]string{"svc/a/x", "svc/b/x"})
	if err != nil {
		t.Fatal(err)
	}
	want := []Conflict{{
		Stage:     "verify",
		Key:       GateKey{ProducerID: "github-app:1", WorkflowID: "7", CheckID: "build"},
		Revisions: []string{rev40, revB},
		Sources:   []string{"svc/a/.factory.yaml", "svc/b/.factory.yaml"},
	}}
	if diff := cmp.Diff(want, eff.Conflicts); diff != "" {
		t.Errorf("Conflicts (-want +got):\n%s", diff)
	}
	for _, path := range []string{"svc/a/x", "svc/b/x"} {
		alone, err := p.Resolve([]string{path})
		if err != nil {
			t.Fatal(err)
		}
		if len(alone.Conflicts) != 0 {
			t.Errorf("%s alone: Conflicts = %v, want none", path, alone.Conflicts)
		}
	}
}

func TestResolve_OracleMerging(t *testing.T) { // CON-3
	t.Parallel()
	oracle := func(rev, obs string) string {
		return "gates:\n  darkMergeOracle:\n    producerId: github-app:1\n    workflowId: 7\n    workflowRevision: " + rev +
			"\n    checkId: oracle\n    observables: [" + obs + "]\n"
	}
	p := mustCompile(t,
		tc{"", writableAll},
		tc{"a", oracle(rev40, "writes, reads")},
		tc{"a/deep", oracle(rev40, "events")},
		tc{"b", oracle(revB, "reads")},
	)
	eff, err := p.Resolve([]string{"a/deep/x"})
	if err != nil {
		t.Fatal(err)
	}
	if len(eff.Oracles) != 1 || !slices.Equal(eff.Oracles[0].Oracle.Observables, []Observable{ObservableEvents, ObservableReads, ObservableWrites}) ||
		!slices.Equal(eff.Oracles[0].Sources, []string{"a/.factory.yaml", "a/deep/.factory.yaml"}) {
		t.Errorf("Oracles = %+v, want one merged oracle", eff.Oracles)
	}
	eff, err = p.Resolve([]string{"a/x", "b/x"})
	if err != nil {
		t.Fatal(err)
	}
	if len(eff.Conflicts) != 1 || eff.Conflicts[0].Stage != "darkMergeOracle" {
		t.Errorf("Conflicts = %+v, want one oracle conflict", eff.Conflicts)
	}
	// Re-pinning an ancestor's oracle at another revision is rejected.
	_, err = compileSet(t, tc{"", writableAll + oracle(rev40, "reads")}, tc{"svc", oracle(revB, "reads")})
	if ps := problemsFrom(t, err); !hasProblem(ps, CodeConflict, "/gates/darkMergeOracle") {
		t.Errorf("problems = %v, want conflict", ps)
	}
}

func TestOverrides_LowestLevelWins(t *testing.T) { // CON-9
	t.Parallel()
	p := mustCompile(t,
		tc{"", writableAll + "  generated: ['**/gen/**']\noverrides:\n  switchStaleDays: 10\n  switchAbandonedDays: 11\n  reviewBudgetLines: 12\n"},
		tc{"svc", "paths:\n  generated: []\noverrides:\n  switchAbandonedDays: 21\n"},
		tc{"svc/leaf", "paths:\n  generated: ['**/*.pb.go']\noverrides:\n  switchStaleDays: 5\n  switchAbandonedDays: 6\n  reviewBudgetLines: 7\n"},
	)
	const (
		root = ".factory.yaml"
		svc  = "svc/.factory.yaml"
		leaf = "svc/leaf/.factory.yaml"
	)
	tests := []struct {
		path                 string
		stale, aband, budget Valued[int]
		generated            Valued[bool]
	}{
		{"x/gen/a", Valued[int]{10, root}, Valued[int]{11, root}, Valued[int]{12, root}, Valued[bool]{true, root}},
		{"x/a", Valued[int]{10, root}, Valued[int]{11, root}, Valued[int]{12, root}, Valued[bool]{false, root}},
		// svc sets only abandoned and turns generated off in its subtree.
		{"svc/gen/a", Valued[int]{10, root}, Valued[int]{21, svc}, Valued[int]{12, root}, Valued[bool]{false, svc}},
		{"svc/leaf/gen/a", Valued[int]{5, leaf}, Valued[int]{6, leaf}, Valued[int]{7, leaf}, Valued[bool]{false, leaf}},
		{"svc/leaf/a.pb.go", Valued[int]{5, leaf}, Valued[int]{6, leaf}, Valued[int]{7, leaf}, Valued[bool]{true, leaf}},
		{"svc/leaf/sub/a.pb.go", Valued[int]{5, leaf}, Valued[int]{6, leaf}, Valued[int]{7, leaf}, Valued[bool]{true, leaf}},
	}
	for _, tt := range tests {
		pp, err := p.ForPath(tt.path)
		if err != nil {
			t.Fatal(err)
		}
		if pp.SwitchStaleDays != tt.stale || pp.SwitchAbandonedDays != tt.aband || pp.ReviewBudgetLines != tt.budget || pp.Generated != tt.generated {
			t.Errorf("%s: stale=%v abandoned=%v budget=%v generated=%v", tt.path,
				pp.SwitchStaleDays, pp.SwitchAbandonedDays, pp.ReviewBudgetLines, pp.Generated)
		}
	}

	// Nothing set anywhere: install defaults, attributed as such.
	d := testDefaults()
	bare := mustCompile(t, tc{"", writableAll}, tc{"svc", ""})
	pp, err := bare.ForPath("svc/a")
	if err != nil {
		t.Fatal(err)
	}
	want := Valued[int]{d.SwitchStaleDays, SourceInstallDefault}
	if pp.SwitchStaleDays != want ||
		pp.SwitchAbandonedDays != (Valued[int]{d.SwitchAbandonedDays, SourceInstallDefault}) ||
		pp.ReviewBudgetLines != (Valued[int]{d.ReviewBudgetLines, SourceInstallDefault}) ||
		pp.Generated != (Valued[bool]{false, SourceInstallDefault}) {
		t.Errorf("defaults = %+v", pp)
	}
}

func TestAccess_PathClasses(t *testing.T) { // CON-7, CON-1
	t.Parallel()
	p := mustCompile(t,
		tc{"", "paths:\n  writable: ['src/**', 'docs/**', 'deploy/**']\n  readOnly: ['docs/**', 'api', 'deploy/prod/**']\n  forbidden: ['deploy/prod/**', 'secrets']\n"},
		tc{"src", "paths:\n  readOnly: ['vendor/**']\n"},
	)
	const root = ".factory.yaml"
	tests := []struct {
		name   string
		path   string
		access Access
		source string
	}{
		{"writable", "src/a.go", AccessWritable, root},
		{"readOnly beats writable", "docs/a.md", AccessReadOnly, root},
		{"forbidden beats readOnly", "deploy/prod/x.yaml", AccessForbidden, root},
		{"writable elsewhere in deploy", "deploy/dev/x.yaml", AccessWritable, root},
		{"outside writable is none", "other/x", AccessNone, root},
		{"readOnly via ancestor directory", "api/v1/x.proto", AccessReadOnly, root},
		{"readOnly in a child contract", "src/vendor/lib/x.go", AccessReadOnly, "src/.factory.yaml"},
		{"forbidden via ancestor directory", "secrets/a/b", AccessForbidden, root},
		{"forbidden pattern folded", "DEPLOY/PROD/x", AccessForbidden, root},
		// A folded readOnly match never lifts None: the exact writable list
		// does not contain Docs/a.md, so the level's verdict stays None.
		{"folded readOnly does not raise none", "Docs/a.md", AccessNone, root},
		{"folded forbidden directory", "SECRETS/x", AccessForbidden, root},
		{"case variant of a writable path is not writable", "SRC/a.go", AccessNone, root},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			pp, err := p.ForPath(tt.path)
			if err != nil {
				t.Fatal(err)
			}
			if !pp.Covered || pp.Access != tt.access || pp.AccessSource != tt.source {
				t.Errorf("%s = %v from %q (covered %v), want %v from %q", tt.path, pp.Access, pp.AccessSource, pp.Covered, tt.access, tt.source)
			}
		})
	}

	// Uncovered: only svc has a contract.
	only := mustCompile(t, tc{"svc", writableAll})
	pp, err := only.ForPath("other/x")
	if err != nil {
		t.Fatal(err)
	}
	if pp.Covered || pp.Access != AccessNone || pp.AccessSource != "" || len(pp.Stack) != 0 {
		t.Errorf("uncovered path = %+v", pp)
	}
	eff, err := only.Resolve([]string{"svc/a", "other/x"})
	if err != nil {
		t.Fatal(err)
	}
	if diff := cmp.Diff([]string{"other/x"}, eff.Uncovered); diff != "" {
		t.Errorf("Uncovered (-want +got):\n%s", diff)
	}
}

func TestAccess_String(t *testing.T) { // CON-7
	t.Parallel()
	for a, want := range map[Access]string{
		AccessForbidden: "forbidden", AccessNone: "none", AccessReadOnly: "read-only", AccessWritable: "writable", Access(9): "access(9)",
	} {
		if got := a.String(); got != want {
			t.Errorf("Access(%d).String() = %q, want %q", int(a), got, want)
		}
	}
	if AccessForbidden >= AccessNone || AccessNone >= AccessReadOnly || AccessReadOnly >= AccessWritable {
		t.Error("access order is wrong")
	}
}

func TestForPath_InvalidPathIsError(t *testing.T) { // CON-7
	t.Parallel()
	p := mustCompile(t, tc{"", writableAll})
	for name, path := range map[string]string{
		"traversal":        "../x",
		"257 segments":     strings.Repeat("a/", 256) + "a",
		"empty":            "",
		"leading slash":    "/etc/passwd",
		"embedded dotdot":  "a/../b",
		"trailing slash":   "a/",
		"NUL":              "a\x00b",
		"invalid UTF-8":    "a\xffb",
		"empty segment":    "a//b",
		"current dir only": ".",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			pp, err := p.ForPath(path)
			if !errors.Is(err, pathglob.ErrInvalidPath) {
				t.Errorf("err = %v, want ErrInvalidPath", err)
			}
			if pp.Access != AccessForbidden || pp.Covered || pp.Path != "" {
				t.Errorf("result %+v is not the zero PathPolicy", pp)
			}
			if _, err := p.Resolve([]string{"ok", path}); !errors.Is(err, pathglob.ErrInvalidPath) {
				t.Errorf("Resolve err = %v, want ErrInvalidPath", err)
			}
		})
	}
	if _, err := p.Resolve(nil); err == nil {
		t.Error("Resolve with no paths succeeded")
	}
}

func TestResolve_SensitivePathRequiresSecuritySignoff(t *testing.T) { // SEC-5
	t.Parallel()
	p := mustCompile(t,
		tc{"", writableAll + "  sensitive: ['src/checkout/payment/**', '*.pem']\n"},
		tc{"certs", "paths:\n  sensitive: ['*.key']\n"},
	)
	tests := []struct {
		name      string
		paths     []string
		sensitive []string
	}{
		{"sensitive path", []string{"src/checkout/payment/x.go", "README.md"}, []string{"src/checkout/payment/x.go"}},
		{"only non-sensitive paths", []string{"README.md", "src/a.go"}, nil},
		{"case variant of a sensitive path", []string{"SRC/Checkout/PAYMENT/x.go"}, []string{"SRC/Checkout/PAYMENT/x.go"}},
		{"sensitive directory itself", []string{"src/checkout/payment"}, []string{"src/checkout/payment"}},
		{"root pattern is anchored", []string{"certs/a.pem"}, nil},
		{"root pattern matches at root", []string{"a.pem"}, []string{"a.pem"}},
		{"child contract pattern", []string{"certs/a.key"}, []string{"certs/a.key"}},
	}
	for _, tt := range tests {
		eff, err := p.Resolve(tt.paths)
		if err != nil {
			t.Fatalf("%s: %v", tt.name, err)
		}
		if eff.SecuritySignoffRequired != (len(tt.sensitive) > 0) || !slices.Equal(eff.SensitivePaths, tt.sensitive) {
			t.Errorf("%s: required=%v sensitive=%v, want %v", tt.name, eff.SecuritySignoffRequired, eff.SensitivePaths, tt.sensitive)
		}
		if tt.sensitive != nil && !slices.ContainsFunc(eff.Reviewers, func(r Requirement) bool { return r.Role == testBaseline().SecurityReviewer }) {
			t.Errorf("%s: security reviewer is not among the reviewers", tt.name)
		}
	}
	pp, err := p.ForPath("certs/a.key")
	if err != nil {
		t.Fatal(err)
	}
	if diff := cmp.Diff([]string{"certs/.factory.yaml"}, pp.SensitiveSources); diff != "" {
		t.Errorf("SensitiveSources (-want +got):\n%s", diff)
	}
}

func TestResolve_LightsOn(t *testing.T) { // CON-8 data
	t.Parallel()
	p := mustCompile(t, tc{"", writableAll}, tc{"a", "lightsOn: true\n"}, tc{"b", "lightsOn: true\n"})
	eff, err := p.Resolve([]string{"b/x", "a/x", "c/x"})
	if err != nil {
		t.Fatal(err)
	}
	if !eff.LightsOn || !slices.Equal(eff.LightsOnSources, []string{"a/.factory.yaml", "b/.factory.yaml"}) {
		t.Errorf("LightsOn = %v from %v", eff.LightsOn, eff.LightsOnSources)
	}
	eff, err = p.Resolve([]string{"c/x"})
	if err != nil || eff.LightsOn || eff.LightsOnSources != nil {
		t.Errorf("LightsOn = %v from %v, err %v", eff.LightsOn, eff.LightsOnSources, err)
	}
}

func TestResolve_Deterministic(t *testing.T) { // CON-3
	t.Parallel()
	p := mustCompile(t,
		tc{"", writableAll + "overrides:\n  reviewBudgetLines: 10\n"},
		tc{"svc/a", verifyGates(gateItem("a", rev40, true)) + "agents:\n  verify: [payments-specialist]\noverrides:\n  reviewBudgetLines: 50\n"},
		tc{"svc/b", verifyGates(gateItem("b", rev40, false), gateItem("a", rev40, false)) + "overrides:\n  reviewBudgetLines: 100\n"},
	)
	paths := []string{"svc/b/z", "svc/a/y", "other", "svc/a/y", "svc/b/z", "svc/a/a"}
	want, err := p.Resolve(paths)
	if err != nil {
		t.Fatal(err)
	}
	rev := slices.Clone(paths)
	slices.Reverse(rev)
	got, err := p.Resolve(rev)
	if err != nil {
		t.Fatal(err)
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("reversed input changes the result (-want +got):\n%s", diff)
	}
	if len(want.Paths) != 4 {
		t.Errorf("Paths = %d, want duplicates removed", len(want.Paths))
	}
	if !slices.IsSortedFunc(want.Paths, func(a, b PathPolicy) int { return strings.Compare(a.Path, b.Path) }) {
		t.Error("Paths are not sorted")
	}
	budgets := map[string]int{}
	for _, pp := range want.Paths {
		budgets[pp.Path] = pp.ReviewBudgetLines.Value
	}
	if diff := cmp.Diff(map[string]int{"other": 10, "svc/a/a": 50, "svc/a/y": 50, "svc/b/z": 100}, budgets); diff != "" {
		t.Errorf("per-path budgets (-want +got):\n%s", diff)
	}
	// "a" is declared mandatory by svc/a and advisory by svc/b: the change needs it.
	for _, o := range want.VerifyGates {
		if o.Gate.CheckID == "a" && (!o.Gate.Mandatory || len(o.Sources) != 2) {
			t.Errorf("merged gate a = %+v", o)
		}
	}
}

func TestPolicy_ConcurrentUse(t *testing.T) { // CON-3
	t.Parallel()
	p := mustCompile(t, tc{"", writableAll + "  forbidden: ['deploy']\n"}, tc{"svc", verifyGates(gateItem("a", rev40, true))})
	paths := []string{"svc/a", "DEPLOY/x", "other/y", "svc/é"}
	base, err := p.Resolve(paths)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 20 {
				got, err := p.Resolve(paths)
				if err != nil || !cmp.Equal(base, got) {
					t.Errorf("concurrent Resolve differs: %v", err)
					return
				}
				if _, err := p.ForPath("DEPLOY/x"); err != nil {
					t.Errorf("ForPath: %v", err)
					return
				}
			}
		}()
	}
	wg.Wait()
}

func TestPolicy_ResultsDoNotAliasPolicy(t *testing.T) { // CON-3
	t.Parallel()
	p := mustCompile(t, tc{"", writableAll + verifyGates(gateItem("a", rev40, true))})
	first, err := p.ForPath("x")
	if err != nil {
		t.Fatal(err)
	}
	first.VerifyGates[0].Gate.Mandatory = false
	first.Reviewers[0].Role = "mutated"
	second, err := p.ForPath("x")
	if err != nil {
		t.Fatal(err)
	}
	if !second.VerifyGates[0].Gate.Mandatory || second.Reviewers[0].Role == "mutated" {
		t.Error("mutating a result changed the policy")
	}
}
