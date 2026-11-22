// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

package contract

import (
	"errors"
	"fmt"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"
)

// gateList returns n distinct gates for one level of a chain.
func gateList(level, n, idLen int) []Gate {
	out := make([]Gate, n)
	for i := range out {
		id := fmt.Sprintf("g%d-%d-%s", level, i, strings.Repeat("x", idLen))
		out[i] = Gate{
			Name:      "gate",
			GateRef:   GateRef{ProducerID: "github-app:1", WorkflowID: "7", WorkflowRevision: rev40, CheckID: id},
			Mandatory: true,
		}
	}
	return out
}

// gateChain is a chain of contracts: the root and depth-1 nested "d" levels, each with
// gatesPer verify and union gates. Its deepest path is under the last level.
func gateChain(tb testing.TB, depth, gatesPer int) (*Set, string) {
	tb.Helper()
	var cs []*Contract
	var dirs []string
	for i := range depth {
		c := &Contract{
			Dir:   strings.Join(dirs, "/"),
			Gates: Gates{Verify: gateList(i, gatesPer, 0), Union: gateList(100+i, gatesPer, 0)},
		}
		if i == 0 {
			c.Paths.Writable = writableList("**")
		}
		cs = append(cs, c)
		dirs = append(dirs, "d")
	}
	return handSet(tb, cs...), strings.Repeat("d/", depth-1)
}

func manyPaths(prefix string, n int) []string {
	return nPatterns(n, func(i int) string { return fmt.Sprintf("%sf%05d.go", prefix, i) })
}

func TestResolve_ManyPathsShareStacks(t *testing.T) { // CON-3
	t.Parallel()
	// 32 levels with 15 gates per stage: 481 gates per stage on the stack, under the cap.
	set, prefix := gateChain(t, MaxStackDepth, 15)
	p, err := Compile(set, testBaseline(), testDefaults())
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	paths := manyPaths(prefix, MaxResolvePaths)
	eff, err := p.Resolve(paths)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(eff.Stacks) != 1 || len(eff.Stacks[0].VerifyGates) != 32*15+1 || len(eff.VerifyGates) != 32*15+1 {
		t.Fatalf("stacks = %d, verify = %d", len(eff.Stacks), len(eff.VerifyGates))
	}
	for i := range eff.Paths {
		pp := &eff.Paths[i]
		if pp.StackIndex != 0 || pp.VerifyGates != nil || pp.UnionGates != nil || pp.Oracles != nil || pp.Reviewers != nil {
			t.Fatalf("path %s carries per-path obligations or a bad index: %+v", pp.Path, pp.StackIndex)
		}
	}
	// ForPath still fills them, and they agree with the stack's.
	pp, err := p.ForPath(paths[0])
	if err != nil || len(pp.VerifyGates) != 32*15+1 || !slices.EqualFunc(pp.VerifyGates, eff.Stacks[0].VerifyGates, func(a, b Obligation) bool { return a.Gate == b.Gate }) {
		t.Errorf("ForPath gates = %d, %v", len(pp.VerifyGates), err)
	}
}

func TestCompile_StackGateCapIsEnforced(t *testing.T) { // CON-12
	t.Parallel()
	// 32 levels of 64 gates is 2,049 per stage: the review's 15.9 GB shape.
	set, _ := gateChain(t, MaxStackDepth, 64)
	p, err := Compile(set, testBaseline(), testDefaults())
	if p != nil || !problemCodes(err)[CodeTooMany] {
		t.Fatalf("Compile = %v, %v, want too-many and no policy", p, err)
	}
	// Exactly at the cap compiles: 31 levels of 16 gates plus the baseline's one is 497.
	under, _ := gateChain(t, 31, 16)
	if _, uerr := Compile(under, testBaseline(), testDefaults()); uerr != nil {
		t.Errorf("a stack under the cap was rejected: %v", uerr)
	}
	// One contract crossing the cap is reported once, on that contract: 8 levels
	// of 64 gates and the baseline's one make 513.
	set, _ = gateChain(t, 9, 64)
	_, err = Compile(set, testBaseline(), testDefaults())
	var ve *ValidationError
	if !errors.As(err, &ve) || len(ve.Problems) != 1 || ve.Problems[0].File != strings.Repeat("d/", 7)+FileName {
		t.Errorf("problems = %v, want one on the 8th contract", err)
	}
}

func TestResolve_StackMergeIsCharged(t *testing.T) { // CON-3, CON-7
	t.Parallel()
	set, prefix := gateChain(t, MaxStackDepth, 15)
	p, err := Compile(set, testBaseline(), testDefaults())
	if err != nil {
		t.Fatal(err)
	}
	paths := manyPaths(prefix, 20)
	var spent int64
	for _, path := range paths {
		b := &workBudget{limit: p.forPathBudget}
		if _, _, ferr := p.forPath(path, b); ferr != nil {
			t.Fatal(ferr)
		}
		spent += b.spent
	}
	// The change-level work is the copy of the one stack plus the merge of its lists.
	_, data, err := p.forPath(paths[0], &workBudget{limit: p.forPathBudget})
	if err != nil {
		t.Fatal(err)
	}
	size := data.size()
	merge := workUnits(len(data.verify)) + workUnits(len(data.union)) + workUnits(len(data.oracles)) + workUnits(len(data.reviewers))
	for _, tt := range []struct {
		name    string
		budget  int64
		wantErr bool
	}{
		{"covers the copy but not the merge", spent + size + 10, true},
		{"covers the merge but not the copy", spent + merge + 10, true},
		{"covers both", spent + size + merge + 10, false},
	} {
		p.resolveBudget = tt.budget
		if _, err := p.Resolve(paths); errors.Is(err, ErrTooComplex) != tt.wantErr || (!tt.wantErr && err != nil) {
			t.Errorf("%s: Resolve err = %v, want too complex = %v", tt.name, err, tt.wantErr)
		}
	}
	b := &workBudget{limit: p.forPathBudget}
	if _, _, err := p.forPath(paths[0], b); err != nil {
		t.Fatal(err)
	}
	p.forPathBudget = b.spent + 10
	if _, err := p.ForPath(paths[0]); !errors.Is(err, ErrTooComplex) {
		t.Errorf("ForPath err = %v, want ErrTooComplex (copying the stack is charged)", err)
	}
}

func TestCompile_StackMergeIsCharged(t *testing.T) { // CON-12
	t.Parallel()
	// The gate lookups cost about 960 units; merging the stacks costs far more.
	set, _ := gateChain(t, MaxStackDepth, 15)
	p, err := compile(set, testBaseline(), testDefaults(), budgets{compile: 5000, forPath: defaultForPathBudget, resolve: defaultResolveBudget})
	if p != nil || !problemCodes(err)[CodeTooMany] {
		t.Errorf("Compile = %v, %v, want too-many and no policy", p, err)
	}
}

func TestResolve_StacksAreDistinctAndOrdered(t *testing.T) { // CON-3
	t.Parallel()
	p := mustCompile(t,
		tc{"", writableAll},
		tc{"a", verifyGates(gateItem("ga", rev40, true))},
		tc{"a/b", verifyGates(gateItem("gb", rev40, true))},
		tc{"c", verifyGates(gateItem("gc", rev40, true))},
	)
	eff, err := p.Resolve([]string{"c/x", "a/b/x", "a/x", "a/b/y", "z"})
	if err != nil {
		t.Fatal(err)
	}
	var stacks []int
	for _, s := range eff.Stacks {
		stacks = append(stacks, len(s.Stack))
	}
	if !slices.Equal(stacks, []int{1, 2, 2, 3}) {
		t.Fatalf("stack sizes = %v, want root, a, c, a/b in depth order", stacks)
	}
	for i := range eff.Paths {
		if got := eff.Stacks[eff.Paths[i].StackIndex].Stack; !slices.Equal(got, eff.Paths[i].Stack) {
			t.Errorf("%s: StackIndex points at %v, path stack is %v", eff.Paths[i].Path, got, eff.Paths[i].Stack)
		}
	}
	// Mutating a returned stack does not change the policy or later results.
	eff.Stacks[0].VerifyGates[0].Gate.Mandatory = !eff.Stacks[0].VerifyGates[0].Gate.Mandatory
	again, err := p.Resolve([]string{"z"})
	if err != nil || again.Stacks[0].VerifyGates[0].Gate.Mandatory == eff.Stacks[0].VerifyGates[0].Gate.Mandatory {
		t.Errorf("a result aliases the policy: %v", err)
	}
}

func TestCompile_ParsedThenMutatedContractIsRevalidated(t *testing.T) { // CON-4, CON-11
	t.Parallel()
	parser := newParser(t)
	c, err := parser.Parse("", []byte(head+writableAll+verifyGates(gateItem("a", rev40, true))))
	if err != nil {
		t.Fatal(err)
	}
	if !c.digested {
		t.Fatal("Parse did not record a digest")
	}
	set, err := NewSet(rev40, c)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = Compile(set, testBaseline(), testDefaults()); err != nil {
		t.Fatalf("an unchanged parsed contract was rejected: %v", err)
	}
	c.Gates.Verify[0].WorkflowRevision = "main"
	if _, err = Compile(set, testBaseline(), testDefaults()); !problemCodes(err)[CodeSchema] {
		t.Errorf("a contract mutated after Parse was accepted: %v", err)
	}
	// A copy keeps the digest, but not the content it covers.
	c2, err := parser.Parse("", []byte(head+writableAll))
	if err != nil {
		t.Fatal(err)
	}
	cp := *c2
	cp.Agents.Verify = []string{"Bad Name"}
	set2, err := NewSet(rev40, &cp)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Compile(set2, testBaseline(), testDefaults()); !problemCodes(err)[CodeSchema] {
		t.Errorf("a mutated copy was accepted: %v", err)
	}
}

// bigSet is a 31-contract chain plus 969 leaves, the most Load reads: the chain
// has 8 gates per stage and each leaf has 64 verify and 64 union gates with long IDs.
func bigSet(tb testing.TB) *Set {
	tb.Helper()
	var cs []*Contract
	var dirs []string
	for i := range 31 {
		c := &Contract{Dir: strings.Join(dirs, "/"), Gates: Gates{Verify: gateList(i, 8, 100), Union: gateList(100+i, 8, 100)}}
		if i == 0 {
			c.Paths.Writable = writableList("**")
		}
		cs = append(cs, c)
		dirs = append(dirs, "d")
	}
	deepest := strings.Join(dirs, "/")
	for i := range maxContracts - 31 {
		cs = append(cs, &Contract{
			Dir:   fmt.Sprintf("%s/leaf%03d", deepest, i),
			Gates: Gates{Verify: gateList(1000+i, 64, 100), Union: gateList(2000+i, 64, 100)},
		})
	}
	return handSet(tb, cs...)
}

func TestCompile_ThousandContracts(t *testing.T) { // CON-12
	t.Parallel()
	start := time.Now()
	p, err := Compile(bigSet(t), testBaseline(), testDefaults())
	if err != nil {
		onlyBounded(t, err, CodeTooMany)
		return
	}
	t.Logf("1000 contracts compiled in %v, spending %.2f%% of the compile budget", time.Since(start), 100*float64(p.compileSpent)/float64(p.compileBudget))
}

func BenchmarkCompile_ThousandContracts(b *testing.B) {
	set := bigSet(b)
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if _, err := Compile(set, testBaseline(), testDefaults()); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkResolve_ManyPaths(b *testing.B) {
	set, prefix := gateChain(b, MaxStackDepth, 15)
	p, err := Compile(set, testBaseline(), testDefaults())
	if err != nil {
		b.Fatal(err)
	}
	paths := manyPaths(prefix, MaxResolvePaths)
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if _, err := p.Resolve(paths); err != nil {
			b.Fatal(err)
		}
	}
}

func TestMemory_ManyPathsStaysSmall(t *testing.T) { // CON-3
	set, prefix := gateChain(t, MaxStackDepth, 15)
	p, err := Compile(set, testBaseline(), testDefaults())
	if err != nil {
		t.Fatal(err)
	}
	paths := manyPaths(prefix, MaxResolvePaths)
	var before, during, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	start := time.Now()
	eff, err := p.Resolve(paths)
	if err != nil {
		t.Fatal(err)
	}
	runtime.ReadMemStats(&during)
	runtime.GC()
	runtime.ReadMemStats(&after)
	runtime.KeepAlive(eff)
	retained := int64(after.HeapAlloc-before.HeapAlloc) >> 20
	t.Logf("Resolve of %d paths took %v, allocated %d MiB in total and retains %d MiB",
		len(paths), time.Since(start), (during.TotalAlloc-before.TotalAlloc)>>20, retained)
	if retained > 100 {
		t.Errorf("the result retains %d MiB", retained)
	}
}
