// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

package contract

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/elliott-davis/lightsout/internal/pathglob"
)

// validateScoped runs ValidateChanged with a trusted digest that matches b and d,
// so the scope is honored.
func validateScoped(t *testing.T, set *Set, b Baseline, d Defaults, changed []string) (Scope, error) {
	t.Helper()
	return ValidateChanged(t.Context(), set, b, d, ChangeOptions{Changed: changed, TrustedDigest: TrustDigest(b, d)})
}

func vc(dir string) string { return filePath(dir) }

func allFiles(set *Set) []string {
	var out []string
	for _, d := range set.Dirs() {
		out = append(out, filePath(d))
	}
	return out
}

func TestValidateChanged_ScopeIsContractAncestorsDescendants(t *testing.T) { // CON-13
	t.Parallel()
	set := buildSet(t,
		tc{"", writableAll},
		tc{"svc", ""},
		tc{"svc/a", ""},
		tc{"svc/a/x", ""},
		tc{"svc/a/x/deep", ""},
		tc{"svc/b", ""},
		tc{"svc/b/y", ""},
		tc{"Docs", ""},
		tc{"docs", ""},
		tc{"other", ""},
	)
	tests := []struct {
		name    string
		changed []string
		want    []string
	}{
		{
			"contract, ancestors and descendants, not siblings",
			[]string{"svc/a"},
			[]string{vc(""), vc("svc"), vc("svc/a"), vc("svc/a/x"), vc("svc/a/x/deep")},
		},
		{
			"a leaf checks its ancestors only",
			[]string{"svc/b/y"},
			[]string{vc(""), vc("svc"), vc("svc/b"), vc("svc/b/y")},
		},
		{
			"a deleted directory's descendants are checked",
			[]string{"svc/a/gone", "svc/b/y/gone"},
			[]string{vc(""), vc("svc"), vc("svc/a"), vc("svc/b"), vc("svc/b/y")},
		},
		{
			"a deleted contract with descendants",
			[]string{"svc/a/x/deep/never"},
			[]string{vc(""), vc("svc"), vc("svc/a"), vc("svc/a/x"), vc("svc/a/x/deep")},
		},
		{"a colliding partner is checked", []string{"docs"}, []string{vc(""), vc("Docs"), vc("docs")}},
		{"the root checks everything", []string{""}, allFiles(set)},
		{"nothing changed checks nothing", nil, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			sc, err := validateScoped(t, set, testBaseline(), testDefaults(), tt.changed)
			// The Docs/docs pair collides, so any scope holding it fails; the scope is still reported.
			if err != nil && !problemCodes(err)[CodeConflict] {
				t.Fatalf("ValidateChanged: %v", err)
			}
			if diff := cmp.Diff(slices.Sorted(slices.Values(tt.want)), sc.Checked); diff != "" {
				t.Errorf("Checked mismatch (-want +got):\n%s", diff)
			}
		})
	}
	t.Run("changed lists deleted contracts, sorted and deduplicated", func(t *testing.T) {
		t.Parallel()
		sc, _ := validateScoped(t, set, testBaseline(), testDefaults(), []string{"svc/b", "svc/a/gone", "svc/b"})
		if diff := cmp.Diff([]string{vc("svc/a/gone"), vc("svc/b")}, sc.Changed); diff != "" {
			t.Errorf("Changed mismatch (-want +got):\n%s", diff)
		}
	})
}

func TestValidateChanged_OutOfScopeLooseningIsNotReported(t *testing.T) { // CON-13
	t.Parallel()
	set := buildSet(t,
		tc{"", "paths:\n  writable: ['src/**']\n"},
		tc{"a", ""},
		tc{"b", "paths:\n  writable: ['**']\n"}, // wider than the root allows
	)
	if sc, err := validateScoped(t, set, testBaseline(), testDefaults(), []string{"a"}); err != nil {
		t.Errorf("only a changed, ValidateChanged = %v, %v, want no problem", sc, err)
	}
	if _, err := Compile(set, testBaseline(), testDefaults()); !problemCodes(err)[CodeLoosening] {
		t.Errorf("Compile = %v, want the loosening in b", err)
	}
	_, err := validateScoped(t, set, testBaseline(), testDefaults(), []string{"b"})
	ps := problemsFrom(t, err)
	if len(ps) != 1 || ps[0].Code != CodeLoosening || ps[0].File != vc("b") {
		t.Errorf("b changed: problems = %v, want the loosening in b", ps)
	}
}

func TestValidateChanged_ParentRepinConflictsWithDescendant(t *testing.T) { // CON-3, CON-13
	t.Parallel()
	const rev2 = "a111111111111111111111111111111111111111"
	set := buildSet(t,
		tc{"", writableAll},
		tc{"svc", verifyGates(gateItem("build", rev2, true))},        // re-pinned by this change
		tc{"svc/api", verifyGates(gateItem("build", rev40, true))},   // still pins the old revision
		tc{"other/api", verifyGates(gateItem("build", rev40, true))}, // unrelated
		tc{"other", verifyGates(gateItem("build", "b222222222222222222222222222222222222222", true))},
	)
	_, err := validateScoped(t, set, testBaseline(), testDefaults(), []string{"svc"})
	ps := problemsFrom(t, err)
	if len(ps) != 1 || ps[0].Code != CodeConflict || ps[0].File != vc("svc/api") {
		t.Errorf("problems = %v, want one conflict on svc/api", ps)
	}
}

func TestValidateChanged_Errors(t *testing.T) { // CON-13
	t.Parallel()
	set := buildSet(t, tc{"", writableAll})
	bad := testBaseline()
	bad.PRReviewer = bad.SecurityReviewer
	for name, call := range map[string]func() error{
		"nil set":      func() error { _, err := validateScoped(t, nil, testBaseline(), testDefaults(), nil); return err },
		"bad baseline": func() error { _, err := validateScoped(t, set, bad, testDefaults(), nil); return err },
		"bad defaults": func() error { _, err := validateScoped(t, set, testBaseline(), Defaults{}, nil); return err },
		"invalid dir": func() error {
			_, err := validateScoped(t, set, testBaseline(), testDefaults(), []string{"a/../b"})
			return err
		},
	} {
		err := call()
		var ve *ValidationError
		if err == nil || errors.As(err, &ve) {
			t.Errorf("%s: error = %v, want a plain error", name, err)
		}
	}
}

func TestValidateChanged_UnbuildableStackInScopeFailsClosed(t *testing.T) { // CON-12, CON-13
	t.Parallel()
	// A chain of 7 levels of 64 gates and a sibling pair under its deepest
	// level. x crosses the gate cap (7*64 + 64 + the baseline's 1 > 512); y does not.
	chain, _ := gateChain(t, 7, 64)
	var cs []*Contract
	for _, dir := range chain.Dirs() {
		c, _ := chain.Get(dir)
		cs = append(cs, c)
	}
	deepest := strings.TrimSuffix(strings.Repeat("d/", 6), "/")
	x := &Contract{Dir: deepest + "/x", Gates: Gates{Verify: gateList(50, 64, 0)}}
	y := &Contract{Dir: deepest + "/y"}
	set := handSet(t, append(cs, x, y)...)

	// Compile reports the cap on x.
	_, err := Compile(set, testBaseline(), testDefaults())
	if ps := problemsFrom(t, err); len(ps) != 1 || ps[0].File != vc(x.Dir) || ps[0].Code != CodeTooMany {
		t.Fatalf("Compile problems = %v, want the cap on x only", ps)
	}
	// y changed: x is out of scope and not reported, and y is still validated.
	if sc, yerr := validateScoped(t, set, testBaseline(), testDefaults(), []string{y.Dir}); yerr != nil {
		t.Errorf("y changed: %v %v, want no problem", sc, yerr)
	}
	// A loosening in y must be found even though x's stack could not be built.
	y.Gates.Verify = []Gate{func() Gate { g := gateList(0, 1, 0)[0]; g.Mandatory = false; return g }()}
	_, err = validateScoped(t, set, testBaseline(), testDefaults(), []string{y.Dir})
	if ps := problemsFrom(t, err); len(ps) != 1 || ps[0].Code != CodeLoosening || ps[0].File != vc(y.Dir) {
		t.Errorf("y loosened: problems = %v, want one loosening on y", ps)
	}
	// x changed: its own cap problem is reported.
	_, err = validateScoped(t, set, testBaseline(), testDefaults(), []string{x.Dir})
	if ps := problemsFrom(t, err); len(ps) != 1 || ps[0].Code != CodeTooMany || ps[0].File != vc(x.Dir) {
		t.Errorf("x changed: problems = %v, want the cap on x", ps)
	}
}

func TestValidateChanged_ScopedContractsGetFullChecks(t *testing.T) { // CON-13
	t.Parallel()
	set := buildSet(t,
		tc{"", writableAll},
		tc{"svc", "agents:\n  verify: [nobody]\n"},
	)
	_, err := validateScoped(t, set, testBaseline(), testDefaults(), []string{"svc"})
	if !problemCodes(err)[CodeUnknownAgent] {
		t.Errorf("err = %v, want unknown-agent", err)
	}
	// A hand-built contract in scope is schema-checked; one out of scope is not.
	bad := &Contract{Dir: "svc", Paths: Paths{Writable: writableList("**")}} // no apiVersion
	root := &Contract{Dir: "", APIVersion: APIVersion, Kind: Kind, Paths: Paths{Writable: writableList("**")}}
	other := &Contract{Dir: "zzz"} // no apiVersion either, out of scope
	hs, herr := NewSet(rev40, root, bad, other)
	if herr != nil {
		t.Fatal(herr)
	}
	_, err = validateScoped(t, hs, testBaseline(), testDefaults(), []string{"svc"})
	ps := problemsFrom(t, err)
	if len(ps) == 0 || ps[0].Code != CodeSchema || ps[0].File != vc("svc") {
		t.Errorf("problems = %v, want a schema problem on svc only", ps)
	}
	for _, p := range ps {
		if p.File == vc("zzz") {
			t.Errorf("out-of-scope contract reported: %v", p)
		}
	}
}

const otherRev = "c333333333333333333333333333333333333333"

func validateWith(t *testing.T, set *Set, reg GateRegistry, changed ...string) (Scope, error) {
	t.Helper()
	b, d := testBaseline(), testDefaults()
	return ValidateChanged(t.Context(), set, b, d,
		ChangeOptions{Changed: changed, Registry: reg, TrustedDigest: TrustDigest(b, d)})
}

func TestValidateChanged_RejectsUnregisteredGate(t *testing.T) { // CON-4, CON-13
	t.Parallel()
	set := buildSet(t,
		tc{"", writableAll},
		tc{"svc", verifyGates(gateItem("build", rev40, true))},
		tc{"other", verifyGates(gateItem("stable", rev40, true))}, // out of scope, registered
	)
	// Clipped so the parallel subtests' appends below each get their own array (a shared one races).
	base := slices.Clip(append(baselineRefs(), gateRef("stable", rev40)))
	reg := registryOf(append(base, gateRef("build", otherRev))...) // build only at another revision
	_, err := validateWith(t, set, reg, "svc")
	ps := problemsFrom(t, err)
	if len(ps) != 1 || ps[0].Code != CodeUnregisteredGate || ps[0].File != vc("svc") || ps[0].Field != "/gates/verify/0" {
		t.Fatalf("problems = %v, want one unregistered-gate at svc /gates/verify/0", ps)
	}
	t.Run("a foreign producer with the same check name", func(t *testing.T) {
		t.Parallel()
		foreign := gateRef("build", rev40)
		foreign.ProducerID = "github-app:666"
		_, err := validateWith(t, set, registryOf(append(base, foreign)...), "svc")
		if !problemCodes(err)[CodeUnregisteredGate] {
			t.Errorf("err = %v, want unregistered-gate", err)
		}
	})
	t.Run("a registered gate passes", func(t *testing.T) {
		t.Parallel()
		if _, err := validateWith(t, set, registryOf(append(base, gateRef("build", rev40))...), "svc"); err != nil {
			t.Errorf("err = %v, want nil", err)
		}
	})
	t.Run("a registry error fails closed", func(t *testing.T) {
		t.Parallel()
		boom := errors.New("registry down")
		_, err := validateWith(t, set, &fakeRegistry{err: boom}, "svc")
		var ve *ValidationError
		if !errors.Is(err, boom) || errors.As(err, &ve) {
			t.Errorf("err = %v, want the wrapped registry error", err)
		}
	})
	t.Run("the baseline is checked even with nothing changed", func(t *testing.T) {
		t.Parallel()
		_, err := validateWith(t, set, registryOf())
		ps := problemsFrom(t, err)
		n := 0
		for _, p := range ps {
			if p.File == "factory baseline" {
				n++
			}
		}
		if n != 2 {
			t.Errorf("problems = %v, want the two baseline gates among them", ps)
		}
	})
	t.Run("a full validation checks every contract's gates", func(t *testing.T) {
		t.Parallel()
		b, d := testBaseline(), testDefaults()
		sc, err := ValidateChanged(t.Context(), set, b, d, ChangeOptions{Changed: []string{"svc"}, Registry: registryOf(append(baselineRefs(), gateRef("build", rev40))...)})
		if !sc.Full || !problemCodes(err)[CodeUnregisteredGate] {
			t.Errorf("Full = %t, err = %v, want the unregistered gate in other", sc.Full, err)
		}
	})
	t.Run("a cancelled context stops", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		_, err := ValidateChanged(ctx, set, testBaseline(), testDefaults(), ChangeOptions{Registry: registryOf()})
		if !errors.Is(err, context.Canceled) {
			t.Errorf("err = %v, want context.Canceled", err)
		}
	})
}

func TestValidateChanged_ChangedEntriesAreDirectories(t *testing.T) { // CON-13, SEC-11
	t.Parallel()
	set := buildSet(t, tc{"", writableAll}, tc{"svc", ""})
	for _, entry := range []string{
		"svc/.factory.yaml", ".factory.yaml", "svc/.FACTORY.YAML", "svc/.factory.yml", "svc/.factory\u200b.yaml",
	} {
		_, err := validateWith(t, set, nil, entry)
		var ve *ValidationError
		if !errors.Is(err, pathglob.ErrInvalidPath) || errors.As(err, &ve) || !strings.Contains(err.Error(), "contract's directory") {
			t.Errorf("entry %q: err = %v, want ErrInvalidPath telling to pass the directory", entry, err)
		}
	}
	if _, err := validateWith(t, set, nil, "svc", ""); err != nil {
		t.Errorf("directories rejected: %v", err)
	}
}

func TestChangedDirs(t *testing.T) { // CON-13
	t.Parallel()
	got := ChangedDirs([]string{
		"README.md", "svc/a.go", "svc/.factory.yaml", ".factory.yaml", "svc/a/.FACTORY.yml", "svc/.factory.yaml", "x/.factory\u200b.yaml",
		"docs/not.factory.yaml",
	})
	want := []string{"", "svc", "svc/a", "x"}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("ChangedDirs mismatch (-want +got):\n%s", diff)
	}
	if got := ChangedDirs(nil); len(got) != 0 {
		t.Errorf("ChangedDirs(nil) = %v", got)
	}
}

// goldenTrustDigest pins the canonical encoding of testBaseline and
// testDefaults. A change to it is a change to every stored trusted digest.
const goldenTrustDigest = "05b0b1b69fb763381f3322285dca02d244d294977ed034ef96b22a118251adc9"

func TestTrustDigest(t *testing.T) { // CON-13
	t.Parallel()
	b, d := testBaseline(), testDefaults()
	if got := TrustDigest(b, d); got != goldenTrustDigest {
		t.Errorf("TrustDigest = %s, want %s", got, goldenTrustDigest)
	}
	// Every field is covered.
	mutations := map[string]func(*Baseline, *Defaults){
		"verify gate":         func(b *Baseline, _ *Defaults) { b.Verify[0].WorkflowRevision = otherRev },
		"verify mandatory":    func(b *Baseline, _ *Defaults) { b.Verify[0].Mandatory = false },
		"union gate":          func(b *Baseline, _ *Defaults) { b.Union = nil },
		"reviewers":           func(b *Baseline, _ *Defaults) { b.Reviewers = []string{"security-reviewer", "pr-reviewer"} },
		"security reviewer":   func(b *Baseline, _ *Defaults) { b.SecurityReviewer = "pr-reviewer" },
		"pr reviewer":         func(b *Baseline, _ *Defaults) { b.PRReviewer = "security-reviewer" },
		"protected":           func(b *Baseline, _ *Defaults) { b.Protected = []string{"CODEOWNERS"} },
		"known agents":        func(b *Baseline, _ *Defaults) { b.KnownAgents = nil },
		"install revision":    func(b *Baseline, _ *Defaults) { b.InstallRevision = otherRev },
		"stale days":          func(_ *Baseline, d *Defaults) { d.SwitchStaleDays++ },
		"abandoned days":      func(_ *Baseline, d *Defaults) { d.SwitchAbandonedDays++ },
		"review budget lines": func(_ *Baseline, d *Defaults) { d.ReviewBudgetLines++ },
	}
	for name, mutate := range mutations {
		b2, d2 := cloneBaseline(testBaseline()), testDefaults()
		mutate(&b2, &d2)
		if TrustDigest(b2, d2) == goldenTrustDigest {
			t.Errorf("changing %s does not change the digest", name)
		}
	}
	// The validator is covered too.
	if trustDigest(b, d, validatorVersion+1, schemaJSON) == goldenTrustDigest {
		t.Error("changing the validator version does not change the digest")
	}
	if trustDigest(b, d, validatorVersion, append(SchemaJSON(), ' ')) == goldenTrustDigest {
		t.Error("changing the schema does not change the digest")
	}
	if trustDigest(b, d, validatorVersion, schemaJSON) != goldenTrustDigest {
		t.Error("the seam with the real inputs differs from TrustDigest")
	}
	// nil and empty lists are the same baseline.
	b.Protected = []string{}
	if TrustDigest(b, d) != goldenTrustDigest {
		t.Error("nil and empty lists differ")
	}
}

func TestValidateChanged_TrustedDigestDecidesScope(t *testing.T) { // CON-13
	t.Parallel()
	set := buildSet(t,
		tc{"", "paths:\n  writable: ['src/**']\n"},
		tc{"a", ""},
		tc{"b", "paths:\n  writable: ['**']\n"}, // loosening, out of scope when only a changed
	)
	b, d := testBaseline(), testDefaults()
	opts := func(digest string) ChangeOptions {
		return ChangeOptions{Changed: []string{"a"}, TrustedDigest: digest}
	}
	sc, err := ValidateChanged(t.Context(), set, b, d, opts(TrustDigest(b, d)))
	if err != nil || sc.Full || len(sc.Checked) != 2 {
		t.Errorf("matching digest: %+v, %v, want the scoped result", sc, err)
	}
	for name, digest := range map[string]string{"empty": "", "stale": strings.Repeat("0", 64)} {
		sc, err := ValidateChanged(t.Context(), set, b, d, opts(digest))
		ps := problemsFrom(t, err)
		if !sc.Full || len(sc.Checked) != 3 || len(ps) != 1 || ps[0].File != vc("b") {
			t.Errorf("%s digest: %+v, %v, want a full validation that reports b", name, sc, err)
		}
	}
	// A baseline that changed since the trusted digest forces a full validation.
	b2 := testBaseline()
	b2.Protected = []string{"secrets/**"}
	if sc, _ := ValidateChanged(t.Context(), set, b2, d, opts(TrustDigest(b, d))); !sc.Full {
		t.Error("a changed baseline did not force a full validation")
	}
}

func TestValidateChanged_EmptyChangedValidatesNothing(t *testing.T) { // CON-13
	t.Parallel()
	set := buildSet(t, tc{"", "paths:\n  writable: ['src/**']\n"}, tc{"b", "paths:\n  writable: ['**']\n"})
	sc, err := validateScoped(t, set, testBaseline(), testDefaults(), nil)
	if err != nil || len(sc.Checked) != 0 || len(sc.CheckedDirs) != 0 {
		t.Errorf("ValidateChanged = %+v, %v, want nothing checked and no error", sc, err)
	}
}

func TestValidateChanged_ScopeDirsMatchFiles(t *testing.T) { // CON-13
	t.Parallel()
	set := buildSet(t, tc{"", writableAll}, tc{"svc", ""}, tc{"svc/a", ""})
	sc, err := validateScoped(t, set, testBaseline(), testDefaults(), []string{"svc"})
	if err != nil {
		t.Fatal(err)
	}
	if diff := cmp.Diff([]string{"", "svc", "svc/a"}, sc.CheckedDirs); diff != "" {
		t.Errorf("CheckedDirs mismatch (-want +got):\n%s", diff)
	}
}

func TestValidateChanged_OutOfScopeTreeProblemsAreDropped(t *testing.T) { // CON-13
	t.Parallel()
	root := &Contract{Dir: "", APIVersion: APIVersion, Kind: Kind, Paths: Paths{Writable: writableList("**")}}
	svc := &Contract{Dir: "svc", APIVersion: APIVersion, Kind: Kind, Paths: Paths{ReadOnly: []string{"a/../b"}}}
	other := &Contract{Dir: "other", APIVersion: APIVersion, Kind: Kind}
	set, err := NewSet(rev40, root, svc, other)
	if err != nil {
		t.Fatal(err)
	}
	_, err = validateScoped(t, set, testBaseline(), testDefaults(), []string{"svc"})
	if !problemCodes(err)[CodeInvalidPattern] {
		t.Errorf("svc changed: err = %v, want invalid-pattern", err)
	}
	if _, err = validateScoped(t, set, testBaseline(), testDefaults(), []string{"other"}); err != nil {
		t.Errorf("other changed: err = %v, want the svc problem left out", err)
	}
}

// TestValidate_UnbuildableStackInScopeIsReported builds the state the scope
// closure rules out, a contract in scope under an over-cap parent that is not,
// to prove the defense in depth in validate.
func TestValidate_UnbuildableStackInScopeIsReported(t *testing.T) { // CON-12, CON-13
	t.Parallel()
	chain, _ := gateChain(t, 7, 64)
	var cs []*Contract
	for _, dir := range chain.Dirs() {
		c, _ := chain.Get(dir)
		cs = append(cs, c)
	}
	deepest := strings.TrimSuffix(strings.Repeat("d/", 6), "/")
	x := &Contract{Dir: deepest + "/x", Gates: Gates{Verify: gateList(50, 64, 0)}} // over the cap
	z := &Contract{Dir: deepest + "/x/z"}
	set := handSet(t, append(cs, x, z)...)
	p, _, err := analyze(set, testBaseline(), testDefaults(), defaultBudgets(), nil)
	if err != nil {
		t.Fatal(err)
	}
	ps, _ := p.validate([]string{z.Dir})
	if len(ps) != 1 || ps[0].File != vc(z.Dir) || ps[0].Code != CodeTooMany {
		t.Errorf("problems = %v, want one too-many on z", ps)
	}
}

func TestValidateChanged_ScopedRegistryCoversAncestorsAndDescendants(t *testing.T) { // CON-4, CON-13
	t.Parallel()
	set := buildSet(t,
		tc{"", writableAll + verifyGates(gateItem("root-gate", rev40, true))},
		tc{"svc", ""},
		tc{"svc/a", verifyGates(gateItem("leaf-gate", rev40, true))},
		tc{"sibling", verifyGates(gateItem("sibling-gate", rev40, true))},
	)
	sc, err := validateWith(t, set, registryOf(baselineRefs()...), "svc")
	if sc.Full {
		t.Fatal("the scoped run was full")
	}
	ps := problemsFrom(t, err)
	files := map[string]bool{}
	for _, p := range ps {
		files[p.File] = true
	}
	// The registry is checked for every contract, so the sibling's gate is reported too.
	if len(ps) != 3 || !files[".factory.yaml"] || !files["svc/a/.factory.yaml"] || !files["sibling/.factory.yaml"] {
		t.Errorf("problems = %v, want the ancestor's, the descendant's and the sibling's gates", ps)
	}
}

func TestHashInOutputIsEscaped(t *testing.T) { // SEC-1
	t.Parallel()
	const dir = "svc/##[error]approved"
	loose := buildSet(t, tc{"", "paths:\n  writable: ['src/**']\n"}, tc{dir, "paths:\n  writable: ['**']\n"})
	_, err := validateScoped(t, loose, testBaseline(), testDefaults(), []string{dir})
	ps := problemsFrom(t, err)
	if len(ps) == 0 {
		t.Fatal("want a loosening problem")
	}
	for _, p := range ps {
		for name, text := range map[string]string{"String": p.String(), "File": p.File, "Field": p.Field, "Message": p.Message} {
			if strings.Contains(text, "##[") || strings.Contains(text, "#") {
				t.Errorf("%s holds a raw #: %s", name, text)
			}
		}
	}
	if !strings.Contains(ps[0].String(), `svc/\x23\x23[error]approved`) {
		t.Errorf("String = %s, want the escaped directory", ps[0].String())
	}
}

func TestValidateChanged_RevokedOutOfScopeGateIsReported(t *testing.T) { // CON-4, SEC-10
	t.Parallel()
	set := buildSet(t,
		tc{"", writableAll},
		tc{"svc", ""},
		tc{"other", verifyGates(gateItem("revoked", rev40, true))},
	)
	// The registry no longer has revoked@rev40. Only svc changed and the digest matches.
	sc, err := validateWith(t, set, registryOf(baselineRefs()...), "svc")
	if sc.Full || len(sc.Checked) != 2 {
		t.Fatalf("scope = %+v, want the scoped run", sc)
	}
	ps := problemsFrom(t, err)
	if len(ps) != 1 || ps[0].Code != CodeUnregisteredGate || ps[0].File != vc("other") {
		t.Errorf("problems = %v, want the revoked gate in other", ps)
	}
}

func TestValidateChanged_ChangedEntryIsCanonicalized(t *testing.T) { // CON-13
	t.Parallel()
	set := buildSet(t,
		tc{"", writableAll},
		tc{"svc", ""},
		tc{"svc/a", ""},
		tc{"svc/ab", ""},
		tc{"caf\u00e9", ""},
		tc{"caf\u00e9/x", ""},
		tc{"zzz", ""},
	)
	want := []string{vc(""), vc("svc"), vc("svc/a")}
	for name, entry := range map[string]string{
		"a case variant":         "SVC/A",
		"a deleted case variant": "SVC/a/gone",
		"a zero-width spelling":  "s\u200bvc/a",
	} {
		sc, err := validateScoped(t, set, testBaseline(), testDefaults(), []string{entry})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if diff := cmp.Diff(want, sc.Checked); diff != "" {
			t.Errorf("%s: Checked mismatch (-want +got):\n%s", name, diff)
		}
	}
	// svc/ab shares a prefix with svc/a but is not a descendant.
	sc, err := validateScoped(t, set, testBaseline(), testDefaults(), []string{"svc/a"})
	if err != nil {
		t.Fatal(err)
	}
	if slices.Contains(sc.Checked, vc("svc/ab")) {
		t.Errorf("Checked = %v, holds the sibling svc/ab", sc.Checked)
	}
	// An NFD spelling finds the NFC directory and its descendants.
	sc, err = validateScoped(t, set, testBaseline(), testDefaults(), []string{"cafe\u0301"})
	if err != nil {
		t.Fatal(err)
	}
	if diff := cmp.Diff([]string{vc(""), vc("caf\u00e9"), vc("caf\u00e9/x")}, sc.Checked); diff != "" {
		t.Errorf("NFD: Checked mismatch (-want +got):\n%s", diff)
	}
}
