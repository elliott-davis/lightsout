// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

package contract

import (
	"context"
	"errors"
	"testing"
)

// fakeRegistry registers the gates in ok and records every lookup.
type fakeRegistry struct {
	ok    map[GateRef]bool
	err   error
	calls []GateRef
	// cancelAfter cancels the context after that many lookups, if cancel is set.
	cancelAfter int
	cancel      context.CancelFunc
}

func (f *fakeRegistry) Registered(_ context.Context, ref GateRef) (bool, error) {
	f.calls = append(f.calls, ref)
	if f.cancel != nil && len(f.calls) >= f.cancelAfter {
		f.cancel()
	}
	if f.err != nil {
		return true, f.err // a lying "true" must still not be trusted
	}
	return f.ok[ref], nil
}

func gateRef(check, rev string) GateRef {
	return GateRef{ProducerID: "github-app:1", WorkflowID: "7", WorkflowRevision: rev, CheckID: check}
}

func registryOf(refs ...GateRef) *fakeRegistry {
	r := &fakeRegistry{ok: map[GateRef]bool{}}
	for _, ref := range refs {
		r.ok[ref] = true
	}
	return r
}

func baselineRefs() []GateRef {
	b := testBaseline()
	return []GateRef{b.Verify[0].GateRef, b.Union[0].GateRef}
}

func gatesPolicy(t *testing.T) *Policy {
	t.Helper()
	return mustCompile(t,
		tc{"", writableAll + verifyGates(gateItem("build", rev40, true)) + oracleYAMLAt("oracle")},
		tc{"svc", "gates:\n  union:\n" + gateItem("deploy", rev40, false)},
	)
}

func oracleYAMLAt(check string) string {
	return "  darkMergeOracle:\n    producerId: github-app:1\n    workflowId: 7\n    workflowRevision: " + rev40 +
		"\n    checkId: " + check + "\n    observables: [writes]\n" + manifestLine
}

func TestCheckGates_RegisteredPasses(t *testing.T) { // CON-4
	t.Parallel()
	reg := registryOf(append(baselineRefs(), gateRef("build", rev40), gateRef("deploy", rev40), gateRef("oracle", rev40))...)
	if err := gatesPolicy(t).CheckGates(t.Context(), reg, nil); err != nil {
		t.Errorf("CheckGates = %v, want nil", err)
	}
}

func TestCheckGates_Denials(t *testing.T) { // CON-4, SEC-11
	t.Parallel()
	all := append(baselineRefs(), gateRef("build", rev40), gateRef("deploy", rev40), gateRef("oracle", rev40))
	without := func(drop GateRef) *fakeRegistry {
		var keep []GateRef
		for _, r := range all {
			if r != drop {
				keep = append(keep, r)
			}
		}
		return registryOf(keep...)
	}
	const otherRev = "c333333333333333333333333333333333333333"
	foreign := gateRef("build", rev40)
	foreign.ProducerID = "github-app:666" // same check name, another producer
	atOtherRev := registryOf(append(baselineRefs(), gateRef("build", otherRev), gateRef("deploy", rev40), gateRef("oracle", rev40))...)

	tests := []struct {
		name      string
		reg       *fakeRegistry
		dirs      []string
		wantFile  string
		wantField string
	}{
		{"unregistered verify producer", func() *fakeRegistry {
			r := without(gateRef("build", rev40))
			r.ok[foreign] = true
			return r
		}(), nil, ".factory.yaml", "/gates/verify/0"},
		{"registered identity at an unregistered revision", atOtherRev, nil, ".factory.yaml", "/gates/verify/0"},
		{"unregistered union gate", without(gateRef("deploy", rev40)), nil, "svc/.factory.yaml", "/gates/union/0"},
		{"unregistered oracle", without(gateRef("oracle", rev40)), nil, ".factory.yaml", "/gates/darkMergeOracle"},
		{"unregistered baseline verify gate", without(baselineRefs()[0]), nil, "factory baseline", "/verify/0"},
		{"unregistered baseline union gate", without(baselineRefs()[1]), nil, "factory baseline", "/union/0"},
		{"baseline is checked when dirs is narrowed", without(baselineRefs()[0]), []string{"svc"}, "factory baseline", "/verify/0"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := gatesPolicy(t).CheckGates(t.Context(), tt.reg, tt.dirs)
			ps := problemsFrom(t, err)
			if len(ps) != 1 || ps[0].Code != CodeUnregisteredGate || ps[0].File != tt.wantFile || ps[0].Field != tt.wantField {
				t.Errorf("problems = %v, want one %s at %s %s", ps, CodeUnregisteredGate, tt.wantFile, tt.wantField)
			}
		})
	}
	t.Run("every unregistered gate is collected", func(t *testing.T) {
		t.Parallel()
		err := gatesPolicy(t).CheckGates(t.Context(), registryOf(), nil)
		if ps := problemsFrom(t, err); len(ps) != 5 {
			t.Errorf("got %d problems, want 5 (2 baseline, build, deploy, oracle): %v", len(ps), ps)
		}
	})
	t.Run("dirs limits the contracts checked", func(t *testing.T) {
		t.Parallel()
		reg := registryOf(append(baselineRefs(), gateRef("build", rev40), gateRef("oracle", rev40))...) // deploy missing
		if err := gatesPolicy(t).CheckGates(t.Context(), reg, []string{""}); err != nil {
			t.Errorf("only the root checked, CheckGates = %v, want nil", err)
		}
		if err := gatesPolicy(t).CheckGates(t.Context(), reg, []string{"svc"}); !problemCodes(err)[CodeUnregisteredGate] {
			t.Errorf("svc checked, CheckGates = %v, want unregistered-gate", err)
		}
	})
}

func TestCheckGates_RegistryErrorFailsClosed(t *testing.T) { // CON-4, SEC-11
	t.Parallel()
	boom := errors.New("registry down")
	reg := &fakeRegistry{err: boom}
	err := gatesPolicy(t).CheckGates(t.Context(), reg, nil)
	var ve *ValidationError
	if !errors.Is(err, boom) || errors.As(err, &ve) {
		t.Errorf("CheckGates = %v, want the wrapped registry error and no problems", err)
	}
	if len(reg.calls) != 1 {
		t.Errorf("registry called %d times, want the check to stop at the first error", len(reg.calls))
	}
}

func TestCheckGates_CancelledContextStops(t *testing.T) { // CON-4
	t.Parallel()
	p := gatesPolicy(t)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	reg := registryOf()
	if err := p.CheckGates(ctx, reg, nil); !errors.Is(err, context.Canceled) || len(reg.calls) != 0 {
		t.Errorf("CheckGates = %v after %d lookups, want context.Canceled and none", err, len(reg.calls))
	}
	// Cancelled while the check runs.
	ctx, cancel = context.WithCancel(t.Context())
	defer cancel()
	reg = registryOf(append(baselineRefs(), gateRef("build", rev40), gateRef("deploy", rev40), gateRef("oracle", rev40))...)
	reg.cancel, reg.cancelAfter = cancel, 2
	if err := p.CheckGates(ctx, reg, nil); !errors.Is(err, context.Canceled) || len(reg.calls) != 2 {
		t.Errorf("CheckGates = %v after %d lookups, want context.Canceled after 2", err, len(reg.calls))
	}
}

func TestCheckGates_NilRegistryIsAnError(t *testing.T) { // CON-4
	t.Parallel()
	if err := gatesPolicy(t).CheckGates(t.Context(), nil, nil); err == nil {
		t.Error("CheckGates with a nil registry passed")
	}
}

func TestCheckGates_AsksOncePerGate(t *testing.T) { // CON-4
	t.Parallel()
	p := mustCompile(t,
		tc{"", writableAll + verifyGates(gateItem("build", rev40, true))},
		tc{"a", "gates:\n  union:\n" + gateItem("build", rev40, true)},
	)
	reg := registryOf(append(baselineRefs(), gateRef("build", rev40))...)
	if err := p.CheckGates(t.Context(), reg, nil); err != nil {
		t.Fatal(err)
	}
	if len(reg.calls) != 3 {
		t.Errorf("registry asked %d times, want 3 (two baseline gates and build)", len(reg.calls))
	}
}

func TestCheckGates_UnknownDirIsAnError(t *testing.T) { // CON-4, SEC-11
	t.Parallel()
	p := mustCompile(t, tc{"", writableAll}, tc{"svc", ""}, tc{"café", ""}) // NFC
	reg := registryOf(baselineRefs()...)
	for name, dir := range map[string]string{
		"a contract file path": "svc/.factory.yaml",
		"a case variant":       "SVC",
		"an NFD variant":       "café",
		"an unknown dir":       "nonexistent",
		"a trailing slash":     "svc/",
	} {
		err := p.CheckGates(t.Context(), reg, []string{"svc", dir})
		if !errors.Is(err, ErrUnknownContractDir) {
			t.Errorf("%s: error = %v, want ErrUnknownContractDir", name, err)
		}
	}
	if len(reg.calls) != 0 {
		t.Errorf("the registry was asked %d times before the dirs were checked", len(reg.calls))
	}
	if err := p.CheckGates(t.Context(), reg, []string{"", "svc", "café"}); err != nil {
		t.Errorf("valid dirs: %v", err)
	}
}

func TestCheckGates_ReportsEveryDeclaration(t *testing.T) { // CON-4
	t.Parallel()
	same := mustCompile(t,
		tc{"", writableAll},
		tc{"a", verifyGates(gateItem("build", rev40, true))},
		tc{"b", verifyGates(gateItem("build", rev40, true))},
	)
	err := same.CheckGates(t.Context(), registryOf(baselineRefs()...), nil)
	ps := problemsFrom(t, err)
	if len(ps) != 2 || ps[0].File != "a/.factory.yaml" || ps[1].File != "b/.factory.yaml" ||
		ps[0].Field != "/gates/verify/0" || ps[1].Field != "/gates/verify/0" {
		t.Errorf("problems = %v, want one per declaration", ps)
	}
	// The same identity at two revisions in sibling contracts: only the registered one passes.
	differ := mustCompile(t,
		tc{"", writableAll},
		tc{"a", verifyGates(gateItem("build", rev40, true))},
		tc{"b", verifyGates(gateItem("build", otherRev, true))},
	)
	err = differ.CheckGates(t.Context(), registryOf(append(baselineRefs(), gateRef("build", rev40))...), nil)
	ps = problemsFrom(t, err)
	if len(ps) != 1 || ps[0].File != "b/.factory.yaml" {
		t.Errorf("problems = %v, want one on b only", ps)
	}
}
