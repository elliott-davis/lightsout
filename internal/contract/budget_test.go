// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

package contract

import (
	"errors"
	"fmt"
	"math/rand/v2"
	"slices"
	"strings"
	"testing"
)

// scaled returns the default budgets divided by n, so a hostile shape reaches
// its limit quickly. The outcome under test is the same: a bounded failure.
func scaled(n int64) budgets {
	d := defaultBudgets()
	return budgets{compile: d.compile / n, forPath: d.forPath, resolve: d.resolve / n}
}

func problemCodes(err error) map[Code]bool {
	out := map[Code]bool{}
	var ve *ValidationError
	if errors.As(err, &ve) {
		for _, p := range ve.Problems {
			out[p.Code] = true
		}
	}
	return out
}

// onlyBounded fails unless err is nil or every problem is one of the allowed codes.
func onlyBounded(t *testing.T, err error, allowed ...Code) {
	t.Helper()
	if err == nil {
		return
	}
	codes := problemCodes(err)
	if len(codes) == 0 {
		t.Fatalf("error %v is not a validation error", err)
	}
	for c := range codes {
		if !slices.Contains(allowed, c) {
			t.Errorf("unexpected problem code %q in %v", c, err)
		}
	}
}

func TestForPath_BudgetFailsClosed(t *testing.T) { // CON-7
	t.Parallel()
	// The root's writable "**" matches first; the child forbids the path. With a
	// budget that covers the first match but not the second, the answer must be an
	// error, never Writable.
	contracts := []tc{{"", writableAll}, {"svc", "paths:\n  forbidden: ['**']\n"}}
	p, err := compileSet(t, contracts...)
	if err != nil {
		t.Fatal(err)
	}
	if got, gerr := p.ForPath("svc/x"); gerr != nil || got.Access != AccessForbidden {
		t.Fatalf("with the default budget: %+v, %v, want forbidden", got, gerr)
	}
	p.forPathBudget = 60
	pp, err := p.ForPath("svc/x")
	if !errors.Is(err, ErrTooComplex) {
		t.Fatalf("ForPath err = %v, want ErrTooComplex", err)
	}
	if pp.Access == AccessWritable || pp.Covered || pp.Path != "" {
		t.Errorf("ForPath returned %+v with an error", pp)
	}
	if _, err := p.Resolve([]string{"svc/x"}); !errors.Is(err, ErrTooComplex) {
		t.Errorf("Resolve err = %v, want ErrTooComplex", err)
	}
}

func TestResolve_CumulativeBudgetFailsClosed(t *testing.T) { // CON-3, CON-7
	t.Parallel()
	p := mustCompile(t, tc{"", writableAll + "  forbidden: ['deploy/**']\n"})
	paths := []string{"a/b", "c/d", "e/f", "g/h"}
	if _, err := p.Resolve(paths); err != nil {
		t.Fatalf("default budget: %v", err)
	}
	// Each path fits the per-path budget, but together they pass the total.
	p.resolveBudget = 100
	if _, err := p.Resolve(paths); !errors.Is(err, ErrTooComplex) {
		t.Errorf("Resolve err = %v, want ErrTooComplex", err)
	}
	p.resolveBudget = 1 << 40
	if _, err := p.Resolve(paths); err != nil {
		t.Errorf("large budget: %v", err)
	}
}

func TestCompile_BudgetFailsClosed(t *testing.T) { // CON-12
	t.Parallel()
	set := shapeWitness(t)
	p, err := compile(set, testBaseline(), testDefaults(), budgets{compile: 1000, forPath: defaultForPathBudget, resolve: defaultResolveBudget})
	if p != nil || !problemCodes(err)[CodeTooMany] {
		t.Errorf("Compile = %v, %v, want too-many and no policy", p, err)
	}
}

func TestShape_DeepForbidden(t *testing.T) { // CON-7
	t.Parallel()
	set, long, split := shapeDeepForbidden(t)
	p, err := Compile(set, testBaseline(), testDefaults())
	if err != nil {
		onlyBounded(t, err, CodeTooMany)
		return
	}
	// A 4000-byte segment is not a path on any supported filesystem.
	if _, err := p.ForPath(long); err == nil {
		t.Error("ForPath accepted a segment over 255 bytes")
	}
	if _, err := p.ForPath(split); !errors.Is(err, ErrTooComplex) {
		t.Errorf("ForPath(split) err = %v, want ErrTooComplex at the default budget", err)
	}
}

func TestShape_LongForbiddenRootManyPaths(t *testing.T) { // CON-7
	t.Parallel()
	p, err := compile(shapeLongForbiddenRoot(t), testBaseline(), testDefaults(), scaled(20))
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	paths := longSegmentPaths(MaxResolvePaths)
	if _, err := p.Resolve(paths); !errors.Is(err, ErrTooComplex) {
		t.Errorf("Resolve err = %v, want ErrTooComplex", err)
	}
	if _, err := p.ForPath(paths[0]); err != nil && !errors.Is(err, ErrTooComplex) {
		t.Errorf("ForPath err = %v", err)
	}
}

func TestShape_CompileIsBounded(t *testing.T) { // CON-12
	t.Parallel()
	shapes := map[string]*Set{
		"writable and readOnly": shapeWritableReadOnly(t),
		"siblings":              shapeSiblings(t),
		"witness":               shapeWitness(t),
		"witness read-only":     shapeWitnessReadOnly(t),
	}
	for name, set := range shapes {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			p, err := compile(set, testBaseline(), testDefaults(), scaled(20))
			onlyBounded(t, err, CodeLoosening, CodeTooMany)
			if err == nil {
				if _, err := p.ForPath("c/x"); err != nil && !errors.Is(err, ErrTooComplex) {
					t.Errorf("ForPath err = %v", err)
				}
			}
		})
	}
}

// realisticPaths returns n deterministic ASCII paths of 3 to 8 segments.
func realisticPaths(n int) []string {
	words := []string{"src", "svc", "api", "handlers", "internal", "cmd", "docs", "pkg", "web", "models", "util", "gen", "testdata", "x", "lib"}
	rng := rand.New(rand.NewPCG(1, 2))
	out := make([]string, n)
	for i := range out {
		segs := make([]string, 3+rng.IntN(6))
		for j := range segs {
			segs[j] = words[rng.IntN(len(words))]
		}
		segs[len(segs)-1] += fmt.Sprintf("%d.go", rng.IntN(1000))
		out[i] = strings.Join(segs, "/")
	}
	return out
}

func TestRealisticTree_StaysFarBelowBudgets(t *testing.T) { // CON-3, CON-7, CON-12
	t.Parallel()
	root, err := newParser(t).Parse("", readFixture(t, "prd-example.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	list := func(format string) []string {
		return nPatterns(20, func(i int) string { return fmt.Sprintf(format, i) })
	}
	cs := []*Contract{root}
	for _, dir := range []string{"src", "src/svc", "src/svc/api"} {
		cs = append(cs, &Contract{Dir: dir, Paths: Paths{
			ReadOnly:  list("ro%d/**"),
			Forbidden: list("forbid%d/*.key"),
			Sensitive: list("**/sens%d/**"),
		}})
	}
	p, err := Compile(handSet(t, cs...), testBaseline(), testDefaults())
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	var maxPath, total int64
	paths := realisticPaths(10000)
	for _, path := range paths {
		b := &workBudget{limit: p.forPathBudget}
		if _, _, err := p.forPath(path, b); err != nil {
			t.Fatalf("ForPath(%q): %v", path, err)
		}
		maxPath = max(maxPath, b.spent)
		total += b.spent
	}
	if _, err := p.Resolve(paths); err != nil {
		t.Fatalf("Resolve(10000 paths): %v", err)
	}
	t.Logf("compile spent %.4f%% of its budget; worst path %.4f%% of the ForPath budget; 10000 paths %.4f%% of the Resolve budget",
		100*float64(p.compileSpent)/float64(p.compileBudget), 100*float64(maxPath)/float64(p.forPathBudget), 100*float64(total)/float64(p.resolveBudget))
	if p.compileSpent*100 > p.compileBudget || maxPath*100 > p.forPathBudget || total*10 > p.resolveBudget {
		t.Errorf("normal use is not far below the budgets: compile %d, worst path %d, total %d", p.compileSpent, maxPath, total)
	}
}
