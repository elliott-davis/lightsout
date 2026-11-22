// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

package oracle_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/elliott-davis/lightsout/internal/contract"
	"github.com/elliott-davis/lightsout/internal/forge"
	"github.com/elliott-davis/lightsout/internal/gate"
	"github.com/elliott-davis/lightsout/internal/oracle"
	"github.com/elliott-davis/lightsout/internal/switches"
)

const (
	repo       = forge.RepoID("acme/app")
	wfRepo     = forge.RepoID("4242")
	wfPath     = ".github/workflows/oracle.yml"
	pin        = "111111111111111111111111111111111111111a"
	baseSHA    = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	candSHA    = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	headSHA    = "cccccccccccccccccccccccccccccccccccccccc"
	keyID      = "harness-1"
	defaults   = "sha256:0000000000000000000000000000000000000000000000000000000000000001"
	producer   = "15368"
	checkID    = "oracle"
	jobID      = "job-oracle"
	fixtureA   = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	fixtureB   = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	digest1    = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	digest2    = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
	srcPath    = "src/checkout/cart.go"
	reportName = oracle.ReportArtifactName
)

// harnessSeed makes a deterministic key; tests only.
func harnessKey(seed string) ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte(seed), ed25519.SeedSize)[:ed25519.SeedSize])
}

// harnessReg is the registration of a test key for the test repo and oracle.
func harnessReg(seed string) oracle.HarnessKey {
	return oracle.HarnessKey{
		Public: ed25519.PublicKey(harnessKey(seed)[ed25519.SeedSize:]),
		Repo:   repo,
		Oracle: refFor(checkID).Key(),
	}
}

var t0 = time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)

var fiveBoundaries = []struct {
	name string
	obs  contract.Observable
}{
	{"http-api", contract.ObservableResponses},
	{"db-read", contract.ObservableReads},
	{"db-write", contract.ObservableWrites},
	{"event-bus", contract.ObservableEvents},
	{"job-queue", contract.ObservableQueuedJobs},
}

func obj(v any) map[string]any {
	m, ok := v.(map[string]any)
	if !ok {
		panic(fmt.Sprintf("test bug: %T is not an object", v))
	}
	return m
}

func list(v any) []any {
	l, ok := v.([]any)
	if !ok {
		panic(fmt.Sprintf("test bug: %T is not a list", v))
	}
	return l
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func sum(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// manifestYAML builds a manifest with cases c1 and c2 and the given boundaries.
func manifestYAML(covers []string, bounds ...int) []byte {
	var b strings.Builder
	b.WriteString("schema: lightsout.oracle-cases/v1\ncases:\n")
	fmt.Fprintf(&b, "  - {id: c1, fixture: '%s'}\n  - {id: c2, fixture: '%s'}\n", fixtureA, fixtureB)
	b.WriteString("boundaries:\n")
	for _, i := range bounds {
		fmt.Fprintf(&b, "  - {name: %s, observable: %s}\n", fiveBoundaries[i].name, fiveBoundaries[i].obs)
	}
	b.WriteString("covers:\n")
	for _, c := range covers {
		fmt.Fprintf(&b, "  - '%s'\n", c)
	}
	return []byte(b.String())
}

var all5 = []int{0, 1, 2, 3, 4}

func observablesOf(bounds []int) []contract.Observable {
	var out []contract.Observable
	for _, i := range bounds {
		out = append(out, fiveBoundaries[i].obs)
	}
	return out
}

func refFor(check string) contract.GateRef {
	return contract.GateRef{
		ProducerID:       "github-app:" + producer,
		WorkflowID:       contract.WorkflowID(string(wfRepo) + "/" + wfPath),
		WorkflowRevision: pin,
		CheckID:          check,
	}
}

func obligationFor(check string, manifest []byte, bounds []int) contract.OracleObligation {
	return contract.OracleObligation{
		Oracle: contract.Oracle{
			GateRef:      refFor(check),
			Observables:  observablesOf(bounds),
			CaseManifest: contract.CaseManifest{Path: "oracle/cases.yaml", SHA256: sum(manifest)},
		},
		Sources: []string{".factory.yaml"},
	}
}

func execFor(check string, mod ...func(*forge.JobExecution)) forge.JobExecution {
	e := forge.JobExecution{
		Repo: repo, CandidateSHA: candSHA, Event: "merge_group", ProducerAppID: producer,
		WorkflowRepo: wfRepo, WorkflowPath: wfPath, WorkflowCommit: pin,
		JobKey: check, RunID: "run1", RunAttempt: "1", JobID: "job-" + check,
		Started: t0, Completed: t0.Add(time.Minute), Conclusion: forge.ConclusionSuccess,
		Provenance: forge.ProvenanceComplete,
	}
	for _, m := range mod {
		m(&e)
	}
	return e
}

// env is one oracle, one stack, one changed path, and a complete passing report.
type env struct {
	t        *testing.T
	eff      *contract.Effective
	in       oracle.Input
	manifest []byte
	report   map[string]any
	raw      []byte // when set, the report bytes instead of report
	// artifacts, when set, replace the single artifact built from the report.
	artifacts []oracle.Artifact
	mutDigest bool               // artifact digest does not match the bytes
	signer    ed25519.PrivateKey // signs the report; default is the registered key
	signKeyID string
	noSig     bool   // no signature artifact
	sigRaw    []byte // when set, the signature artifact bytes
}

func newEnv(t *testing.T) *env {
	t.Helper()
	m := manifestYAML([]string{"src/**"}, all5...)
	ob := obligationFor(checkID, m, all5)
	e := &env{t: t, manifest: m}
	e.eff = &contract.Effective{
		Revision: "pol1", InstallRevision: "inst1",
		Paths:   []contract.PathPolicy{{Path: srcPath, Covered: true, StackIndex: 0}},
		Stacks:  []contract.StackPolicy{{Stack: []string{".factory.yaml"}, Oracles: []contract.OracleObligation{ob}}},
		Oracles: []contract.OracleObligation{ob},
	}
	e.in = oracle.Input{
		Target:          gate.Target{Forge: "github", Repo: repo, PR: 7, HeadSHA: headSHA, CandidateSHA: candSHA},
		Evidence:        gate.Evidence{Executions: []forge.JobExecution{execFor(checkID)}, Complete: true},
		BaselineSHA:     baseSHA,
		Kind:            oracle.KindTask,
		Issue:           12,
		ReleaseDefaults: defaults,
		Switches:        switches.Comparison{Verdict: switches.VerdictPass},
		HarnessKeys:     map[string]oracle.HarnessKey{keyID: harnessReg("k")},
	}
	e.report = e.goodReport(nil)
	return e
}

// goodReport is a report with every observation completed and equal. overrides are the first-introduction overrides.
func (e *env) goodReport(overrides map[string]string) map[string]any {
	var observations []any
	for _, c := range []struct{ id, fixture string }{{"c1", fixtureA}, {"c2", fixtureB}} {
		for _, b := range fiveBoundaries {
			side := func() map[string]any {
				return map[string]any{"status": "completed", "fixture": c.fixture, "digest": digest1}
			}
			observations = append(observations, map[string]any{
				"case": c.id, "boundary": b.name, "baseline": side(), "candidate": side(),
				"differencesComplete": true, "differences": []any{},
			})
		}
	}
	ov := map[string]any{}
	for k, v := range overrides {
		ov[k] = v
	}
	cand := oracle.DeriveConfig(defaults, overrides)
	return map[string]any{
		"schema": "lightsout.oracle/v1", "repo": string(repo),
		"job":         map[string]any{"runId": "run1", "runAttempt": "1", "jobId": jobID},
		"baselineSHA": baseSHA, "candidateSHA": candSHA, "oracleRevision": pin,
		"comparison": "exact/v1", "caseManifest": "sha256:" + sum(e.manifest),
		"switchOverrides": ov,
		"configs": map[string]any{
			"requested": map[string]any{"baseline": defaults, "candidate": cand},
			"loaded":    map[string]any{"baseline": defaults, "candidate": cand},
		},
		"observations": observations,
	}
}

// firstIntroduction makes the change introduce key, default off, with the matching report.
func (e *env) firstIntroduction() {
	const key = "new-key"
	e.in.Switches = switches.Comparison{Verdict: switches.VerdictPass, New: []switches.Change{{Key: key, Status: switches.StatusDefaultOff}}}
	e.report = e.goodReport(map[string]string{key: "off"})
}

func (e *env) obs(caseID, boundary string) map[string]any {
	e.t.Helper()
	for _, o := range list(e.report["observations"]) {
		m := obj(o)
		if m["case"] == caseID && m["boundary"] == boundary {
			return m
		}
	}
	e.t.Fatalf("no observation %s/%s", caseID, boundary)
	return nil
}

func (e *env) dropObs(caseID, boundary string) {
	var keep []any
	for _, o := range list(e.report["observations"]) {
		m := obj(o)
		if m["case"] != caseID || m["boundary"] != boundary {
			keep = append(keep, o)
		}
	}
	e.report["observations"] = keep
}

// differ makes (case, boundary) differ with the given differences.
func (e *env) differ(caseID, boundary string, diffs ...map[string]any) {
	o := e.obs(caseID, boundary)
	obj(o["candidate"])["digest"] = digest2
	var list []any
	for _, d := range diffs {
		list = append(list, d)
	}
	o["differences"] = list
}

func diff(record, op, field string, before, after any) map[string]any {
	return map[string]any{"record": record, "operation": op, "field": field, "before": before, "after": after}
}

// sign returns the signature artifact bytes of the registered harness key over data.
func (e *env) sign(data []byte) []byte {
	e.t.Helper()
	sig, err := oracle.SignReport(keyID, harnessKey("k"), data)
	if err != nil {
		e.t.Fatal(err)
	}
	return sig
}

func (e *env) eval() oracle.Decision {
	e.t.Helper()
	data := e.raw
	if data == nil {
		data = mustJSON(e.t, e.report)
	}
	arts := e.artifacts
	if arts == nil {
		d := sum(data)
		if e.mutDigest {
			d = strings.Repeat("0", 64)
		}
		arts = []oracle.Artifact{{Name: reportName, SHA256: d, Bytes: data}}
		if !e.noSig {
			sig := e.sigRaw
			if sig == nil {
				key, id := e.signer, e.signKeyID
				if key == nil {
					key = harnessKey("k")
				}
				if id == "" {
					id = keyID
				}
				var err error
				if sig, err = oracle.SignReport(id, key, data); err != nil {
					e.t.Fatal(err)
				}
			}
			arts = append(arts, oracle.Artifact{Name: oracle.SignatureArtifactName, SHA256: sum(sig), Bytes: sig})
		}
	}
	e.in.Reports = map[contract.GateRef]oracle.Report{refFor(checkID): {Manifest: e.manifest, Artifacts: arts}}
	return oracle.Evaluate(e.eff, e.in)
}

// want checks the overall disposition and the one oracle's reason.
func want(t *testing.T, d oracle.Decision, disp oracle.Disposition, reason oracle.Reason) oracle.Result {
	t.Helper()
	if d.Disposition != disp {
		t.Fatalf("disposition = %s, want %s (reasons %v, oracles %+v)", d.Disposition, disp, d.Reasons, d.Oracles)
	}
	if len(d.Oracles) != 1 {
		t.Fatalf("oracles = %d, want 1", len(d.Oracles))
	}
	r := d.Oracles[0]
	if r.Reason != reason {
		t.Fatalf("reason = %q (%v), want %q", r.Reason, r.Evidence, reason)
	}
	return r
}

// wantChange checks a change-level failure.
func wantChange(t *testing.T, d oracle.Decision, disp oracle.Disposition, reason oracle.Reason) {
	t.Helper()
	if d.Disposition != disp || !slices.Contains(d.Reasons, reason) {
		t.Fatalf("decision = %s %v, want %s [%s]", d.Disposition, d.Reasons, disp, reason)
	}
}
