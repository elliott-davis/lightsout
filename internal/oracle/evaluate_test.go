// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

package oracle_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/elliott-davis/lightsout/internal/contract"
	"github.com/elliott-davis/lightsout/internal/forge"
	"github.com/elliott-davis/lightsout/internal/gate"
	"github.com/elliott-davis/lightsout/internal/oracle"
	"github.com/elliott-davis/lightsout/internal/switches"
)

func num(s string) json.Number { return json.Number(s) }

func TestEvaluate_TaskExactEqualityPasses(t *testing.T) { // PIP-4
	t.Parallel()
	e := newEnv(t)
	d := e.eval()
	r := want(t, d, oracle.Pass, oracle.ReasonNone)
	data := mustJSON(t, e.report)
	wantResult := oracle.Result{
		Gate: refFor(checkID), Disposition: oracle.Pass, RunID: "run1", RunAttempt: "1", JobID: jobID,
		ManifestSHA256: sum(e.manifest), ReportSHA256: sum(data), KeyID: keyID, Observations: 10,
		RequestedBaseline: defaults, RequestedCandidate: defaults, LoadedBaseline: defaults, LoadedCandidate: defaults,
		SwitchOverrides: []oracle.Override{},
	}
	if diff := cmp.Diff(wantResult, r, cmpopts.EquateEmpty()); diff != "" {
		t.Errorf("result (-want +got):\n%s", diff)
	}
	wantBinding := oracle.Decision{
		Target:      gate.Target{Forge: "github", Repo: repo, PR: 7, HeadSHA: headSHA, CandidateSHA: candSHA},
		BaselineSHA: baseSHA, PolicyRevision: "pol1", InstallRevision: "inst1", Kind: oracle.KindTask, Issue: 12,
		ReleaseDefaults: defaults, CandidateConfig: defaults, Disposition: oracle.Pass, Oracles: d.Oracles,
	}
	if diff := cmp.Diff(wantBinding, d, cmpopts.EquateEmpty()); diff != "" {
		t.Errorf("binding (-want +got):\n%s", diff)
	}
}

func TestEvaluate_FeatureDarkFirstIntroduction(t *testing.T) { // PIP-13
	t.Parallel()
	e := newEnv(t)
	e.in.Kind = oracle.KindFeatureDark
	e.firstIntroduction()
	d := e.eval()
	r := want(t, d, oracle.Pass, oracle.ReasonNone)
	wantOv := []oracle.Override{{Key: "new-key", Value: "off"}}
	if diff := cmp.Diff(wantOv, r.SwitchOverrides); diff != "" {
		t.Errorf("SwitchOverrides (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(wantOv, d.ExpectedOverrides); diff != "" {
		t.Errorf("ExpectedOverrides (-want +got):\n%s", diff)
	}
	if r.RequestedCandidate != d.CandidateConfig || r.LoadedCandidate != d.CandidateConfig || r.RequestedBaseline != defaults {
		t.Errorf("configs = %+v", r)
	}
	if d.CandidateConfig == defaults || d.CandidateConfig != oracle.DeriveConfig(defaults, map[string]string{"new-key": "off"}) {
		t.Errorf("CandidateConfig = %s", d.CandidateConfig)
	}
}

func TestEvaluate_DifferenceBlocksTaskAndFeatureDark(t *testing.T) { // PIP-4
	t.Parallel()
	for _, k := range []oracle.Kind{oracle.KindTask, oracle.KindFeatureDark} {
		e := newEnv(t)
		e.in.Kind = k
		e.differ("c1", "http-api", diff("cart/1", "GET /cart", "/status", num("404"), num("200")))
		r := want(t, e.eval(), oracle.Blocked, oracle.ReasonDifference)
		if r.Differences != 1 {
			t.Errorf("%s: Differences = %d", k, r.Differences)
		}
	}
}

func TestEvaluate_IdenticalResponsesWithNewQueuedJobBlocks(t *testing.T) { // PIP-13
	t.Parallel()
	e := newEnv(t)
	e.in.Kind = oracle.KindFeatureDark
	e.firstIntroduction() // the new switch is forced off, yet the change enqueues a job
	e.differ("c1", "job-queue", diff("queue/emails", "enqueue", "/count", num("0"), num("1")))
	r := want(t, e.eval(), oracle.Blocked, oracle.ReasonDifference)
	if r.Differences != 1 {
		t.Errorf("Differences = %d", r.Differences)
	}
}

func fixEnv(t *testing.T, deltas ...oracle.Delta) *env {
	t.Helper()
	e := newEnv(t)
	e.in.Kind = oracle.KindFix
	e.in.Fix = e.fix(deltas...)
	return e
}

// fix is an authorization for e's contract revision, oracle, oracle revision and manifest.
func (e *env) fix(deltas ...oracle.Delta) *oracle.FixAuthorization {
	return &oracle.FixAuthorization{
		ID: "auth-1", Repo: repo, Issue: 12, ContractRevision: e.eff.Revision,
		Oracle: e.eff.Oracles[0].Oracle.Key(), OracleRevision: pin, CaseManifest: sum(e.manifest), Deltas: deltas,
	}
}

func delta(record, field string, before, after any) oracle.Delta {
	return oracle.Delta{Case: "c1", Boundary: "http-api", Record: record, Operation: "GET /cart", Field: field, Before: before, After: after}
}

func TestEvaluate_FixDeltas(t *testing.T) { // INT-10
	t.Parallel()
	t.Run("each difference matched by a distinct delta passes", func(t *testing.T) {
		t.Parallel()
		e := fixEnv(t, delta("cart/1", "/status", num("404"), num("200")), delta("cart/2", "/status", num("404"), num("200")),
			delta("cart/9", "/status", num("1"), num("2"))) // an unused delta is fine
		e.differ("c1", "http-api",
			diff("cart/1", "GET /cart", "/status", num("404"), num("200")),
			diff("cart/2", "GET /cart", "/status", num("404.0"), num("200"))) // 404.0 is the number 404
		r := want(t, e.eval(), oracle.Pass, oracle.ReasonNone)
		if r.Differences != 2 {
			t.Errorf("Differences = %d", r.Differences)
		}
	})
	t.Run("a second matching difference on another record with one delta blocks", func(t *testing.T) {
		t.Parallel()
		e := fixEnv(t, delta("cart/1", "/status", num("404"), num("200")))
		e.differ("c1", "http-api",
			diff("cart/1", "GET /cart", "/status", num("404"), num("200")),
			diff("cart/2", "GET /cart", "/status", num("404"), num("200")))
		want(t, e.eval(), oracle.Blocked, oracle.ReasonUnauthorizedDifference)
	})
	t.Run("a delta is consumed once", func(t *testing.T) {
		t.Parallel()
		e := fixEnv(t, delta("cart/1", "/status", num("404"), num("200")))
		e.differ("c1", "http-api",
			diff("cart/1", "GET /cart", "/status", num("404"), num("200")),
			diff("cart/1", "GET /cart", "/status", num("404"), num("200")))
		want(t, e.eval(), oracle.Blocked, oracle.ReasonUnauthorizedDifference)
	})
	t.Run("the right field with an extra changed field blocks", func(t *testing.T) {
		t.Parallel()
		e := fixEnv(t, delta("cart/1", "/status", num("404"), num("200")))
		e.differ("c1", "http-api",
			diff("cart/1", "GET /cart", "/status", num("404"), num("200")),
			diff("cart/1", "GET /cart", "/accountId", "a1", "a2"))
		want(t, e.eval(), oracle.Blocked, oracle.ReasonUnauthorizedDifference)
	})
	t.Run("another after value blocks", func(t *testing.T) {
		t.Parallel()
		e := fixEnv(t, delta("cart/1", "/status", num("404"), num("200")))
		e.differ("c1", "http-api", diff("cart/1", "GET /cart", "/status", num("404"), num("500")))
		want(t, e.eval(), oracle.Blocked, oracle.ReasonUnauthorizedDifference)
	})
	t.Run("another case blocks", func(t *testing.T) {
		t.Parallel()
		e := fixEnv(t, delta("cart/1", "/status", num("404"), num("200")))
		e.differ("c2", "http-api", diff("cart/1", "GET /cart", "/status", num("404"), num("200")))
		want(t, e.eval(), oracle.Blocked, oracle.ReasonUnauthorizedDifference)
	})
	t.Run("a string is not the number with the same text", func(t *testing.T) {
		t.Parallel()
		e := fixEnv(t, delta("cart/1", "/status", "404", "200"))
		e.differ("c1", "http-api", diff("cart/1", "GET /cart", "/status", num("404"), num("200")))
		want(t, e.eval(), oracle.Blocked, oracle.ReasonUnauthorizedDifference)
	})
	t.Run("an authorization for another oracle key blocks", func(t *testing.T) {
		t.Parallel()
		e := fixEnv(t, delta("cart/1", "/status", num("404"), num("200")))
		e.in.Fix.Oracle.CheckID = "another-oracle"
		e.differ("c1", "http-api", diff("cart/1", "GET /cart", "/status", num("404"), num("200")))
		want(t, e.eval(), oracle.Blocked, oracle.ReasonUnauthorizedDifference)
	})
	t.Run("an empty delta means equivalence", func(t *testing.T) {
		t.Parallel()
		e := fixEnv(t)
		e.differ("c1", "http-api", diff("cart/1", "GET /cart", "/status", num("404"), num("200")))
		want(t, e.eval(), oracle.Blocked, oracle.ReasonUnauthorizedDifference)
		e = fixEnv(t)
		want(t, e.eval(), oracle.Pass, oracle.ReasonNone)
	})
}

func TestEvaluate_InvalidInput(t *testing.T) { // INT-10, SEC-10
	t.Parallel()
	tests := map[string]func(e *env){
		"fix authorization for another issue": func(e *env) { e.in.Fix.Issue = 13 },
		"fix authorization for another repo":  func(e *env) { e.in.Fix.Repo = "acme/other" },
		"fix without an authorization":        func(e *env) { e.in.Fix = nil },
		"authorization on a task":             func(e *env) { e.in.Kind = oracle.KindTask },
		"authorization without an ID":         func(e *env) { e.in.Fix.ID = "" },
		"delta with a non-scalar value":       func(e *env) { e.in.Fix.Deltas = []oracle.Delta{delta("r", "f", map[string]any{}, nil)} },
		"unknown kind":                        func(e *env) { e.in.Kind = "chore"; e.in.Fix = nil },
		"short baseline SHA":                  func(e *env) { e.in.BaselineSHA = "abc" },
		"short candidate SHA":                 func(e *env) { e.in.Target.CandidateSHA = "abc" },
		"no release defaults":                 func(e *env) { e.in.ReleaseDefaults = "" },
		"no issue":                            func(e *env) { e.in.Issue = 0 },
		"no revision":                         func(e *env) { e.eff.Revision = "" },
		"no install revision":                 func(e *env) { e.eff.InstallRevision = "" },
		"stack index out of range":            func(e *env) { e.eff.Paths[0].StackIndex = 5 },
	}
	for name, mod := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			e := fixEnv(t, delta("cart/1", "/status", num("404"), num("200")))
			mod(e)
			d := e.eval()
			wantChange(t, d, oracle.Error, oracle.ReasonInvalidInput)
			if len(d.Oracles) != 0 {
				t.Errorf("oracles = %+v, want none", d.Oracles)
			}
		})
	}
	t.Run("nil contract", func(t *testing.T) {
		t.Parallel()
		d := oracle.Evaluate(nil, oracle.Input{})
		wantChange(t, d, oracle.Error, oracle.ReasonInvalidInput)
	})
}

func TestEvaluate_GateMustPass(t *testing.T) { // PIP-13
	t.Parallel()
	t.Run("a missing gate is oracle-not-run", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t)
		e.in.Evidence.Executions = nil
		want(t, e.eval(), oracle.Blocked, oracle.ReasonOracleNotRun)
	})
	t.Run("a failed gate is oracle-not-run", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t)
		e.in.Evidence.Executions = []forge.JobExecution{execFor(checkID, func(x *forge.JobExecution) { x.Conclusion = forge.ConclusionFailure })}
		want(t, e.eval(), oracle.Blocked, oracle.ReasonOracleNotRun)
	})
	t.Run("a pending gate is pending", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t)
		e.in.Evidence.Executions = []forge.JobExecution{execFor(checkID, func(x *forge.JobExecution) {
			x.Conclusion = forge.ConclusionNone
			x.Completed = x.Started
		})}
		want(t, e.eval(), oracle.Pending, oracle.ReasonOracleNotRun)
	})
	t.Run("incomplete evidence is an error", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t)
		e.in.Evidence.Complete = false
		want(t, e.eval(), oracle.Error, oracle.ReasonOracleNotRun)
	})
	t.Run("a gate of another workflow revision is not run", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t)
		e.in.Evidence.Executions = []forge.JobExecution{execFor(checkID, func(x *forge.JobExecution) { x.WorkflowCommit = strings.Repeat("c", 40) })}
		want(t, e.eval(), oracle.Blocked, oracle.ReasonOracleNotRun)
	})
	t.Run("a candidate-written gate on another SHA is not run", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t)
		e.in.Evidence.Executions = []forge.JobExecution{execFor(checkID, func(x *forge.JobExecution) { x.CandidateSHA = baseSHA })}
		want(t, e.eval(), oracle.Blocked, oracle.ReasonOracleNotRun)
	})
	t.Run("malformed evidence elsewhere in the snapshot blocks a passing oracle job", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t)
		e.in.Evidence.Executions = append(e.in.Evidence.Executions, execFor("other", func(x *forge.JobExecution) { x.RunID = "" }))
		r := want(t, e.eval(), oracle.Error, oracle.ReasonOracleNotRun)
		if r.ReportSHA256 != "" {
			t.Errorf("a report was read despite the gate: %+v", r)
		}
	})
	t.Run("a pin conflict blocks", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t)
		e.eff.Conflicts = []contract.Conflict{{Stage: "darkMergeOracle", Key: e.eff.Oracles[0].Oracle.Key(), Revisions: []string{"a@x", "a@y"}}}
		want(t, e.eval(), oracle.Blocked, oracle.ReasonOracleNotRun)
	})
}

func TestEvaluate_ManifestPin(t *testing.T) { // PIP-13
	t.Parallel()
	t.Run("bytes that do not match the pin", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t)
		e.manifest = append(bytes.Clone(e.manifest), '\n') // a different digest
		want(t, e.eval(), oracle.Error, oracle.ReasonManifestInvalid)
	})
	t.Run("no manifest bytes", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t)
		e.manifest = nil
		want(t, e.eval(), oracle.Error, oracle.ReasonManifestInvalid)
	})
	t.Run("a pinned manifest that does not validate", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t)
		e.manifest = []byte("schema: lightsout.oracle-cases/v1\n")
		e.eff.Oracles[0].Oracle.CaseManifest.SHA256 = sum(e.manifest)
		e.eff.Stacks[0].Oracles = e.eff.Oracles
		d := e.eval()
		// The invalid manifest covers nothing, so the path is uncovered too.
		if d.Oracles[0].Reason != oracle.ReasonManifestInvalid || d.Oracles[0].Disposition != oracle.Error {
			t.Errorf("result = %+v", d.Oracles[0])
		}
		if len(d.Reasons) == 0 || d.Reasons[0] != oracle.ReasonOracleMissing {
			t.Errorf("Reasons = %v, want oracle-missing", d.Reasons)
		}
	})
	t.Run("a manifest whose boundaries differ from the declared observables", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t)
		e.eff.Oracles[0].Oracle.Observables = observablesOf([]int{0, 1})
		e.eff.Stacks[0].Oracles = e.eff.Oracles
		want(t, e.eval(), oracle.Error, oracle.ReasonManifestInvalid)
	})
}

func TestEvaluate_ReportArtifact(t *testing.T) { // PIP-13
	t.Parallel()
	t.Run("two artifacts with the report name", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t)
		data := mustJSON(t, e.report)
		a := oracle.Artifact{Name: reportName, SHA256: sum(data), Bytes: data}
		e.artifacts = []oracle.Artifact{a, a}
		want(t, e.eval(), oracle.Blocked, oracle.ReasonReportAmbiguous)
	})
	t.Run("no artifact with the report name", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t)
		e.artifacts = []oracle.Artifact{{Name: "coverage.xml", SHA256: sum(nil)}}
		want(t, e.eval(), oracle.Blocked, oracle.ReasonReportMissing)
	})
	t.Run("an unrelated artifact next to the report is ignored", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t)
		data := mustJSON(t, e.report)
		sig := e.sign(data)
		e.artifacts = []oracle.Artifact{
			{Name: "logs", SHA256: sum(nil)},
			{Name: reportName, SHA256: sum(data), Bytes: data},
			{Name: oracle.SignatureArtifactName, SHA256: sum(sig), Bytes: sig},
		}
		want(t, e.eval(), oracle.Pass, oracle.ReasonNone)
	})
	t.Run("sha mismatch", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t)
		e.mutDigest = true
		want(t, e.eval(), oracle.Blocked, oracle.ReasonReportUnbound)
	})
}

func TestEvaluate_ReportBinding(t *testing.T) { // PIP-13
	t.Parallel()
	tests := map[string]func(r map[string]any){
		"wrong job":              func(r map[string]any) { obj(r["job"])["jobId"] = "job-other" },
		"wrong run":              func(r map[string]any) { obj(r["job"])["runId"] = "run9" },
		"wrong attempt":          func(r map[string]any) { obj(r["job"])["runAttempt"] = "2" },
		"wrong repo":             func(r map[string]any) { r["repo"] = "acme/other" },
		"wrong baseline SHA":     func(r map[string]any) { r["baselineSHA"] = strings.Repeat("d", 40) },
		"wrong candidate SHA":    func(r map[string]any) { r["candidateSHA"] = strings.Repeat("d", 40) },
		"wrong oracle revision":  func(r map[string]any) { r["oracleRevision"] = strings.Repeat("d", 40) },
		"wrong manifest digest":  func(r map[string]any) { r["caseManifest"] = "sha256:" + strings.Repeat("d", 64) },
		"comparison not exact":   func(r map[string]any) { r["comparison"] = "fuzzy/v1" },
		"comparison with tolera": func(r map[string]any) { r["comparison"] = "exact/v2" },
	}
	for name, mod := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			e := newEnv(t)
			mod(e.report)
			want(t, e.eval(), oracle.Blocked, oracle.ReasonReportUnbound)
		})
	}
}

func TestEvaluate_ReportMalformed(t *testing.T) { // PIP-13, SEC-1
	t.Parallel()
	withDiff := func(e *env, before any) []byte {
		e.differ("c1", "http-api", diff("r", "o", "f", before, nil))
		return mustJSON(e.t, e.report)
	}
	tests := map[string]func(e *env, good []byte) []byte{
		"duplicate key": func(_ *env, good []byte) []byte {
			return bytes.Replace(good, []byte(`"comparison":"exact/v1"`), []byte(`"comparison":"exact/v1","comparison":"exact/v1"`), 1)
		},
		"duplicate key in a nested object": func(_ *env, good []byte) []byte {
			return bytes.Replace(good, []byte(`"jobId":"job-oracle"`), []byte(`"jobId":"job-oracle","jobId":"job-oracle"`), 1)
		},
		"unknown field": func(_ *env, good []byte) []byte {
			return bytes.Replace(good, []byte(`{"baselineSHA"`), []byte(`{"extra":1,"baselineSHA"`), 1)
		},
		"unknown field in an observation": func(_ *env, good []byte) []byte {
			return bytes.Replace(good, []byte(`{"baseline":`), []byte(`{"note":"x","baseline":`), 1)
		},
		"key in another case": func(_ *env, good []byte) []byte {
			return bytes.Replace(good, []byte(`"comparison"`), []byte(`"Comparison"`), 1)
		},
		"missing field": func(_ *env, good []byte) []byte {
			return bytes.Replace(good, []byte(`"comparison":"exact/v1",`), nil, 1)
		},
		"trailing data":  func(_ *env, good []byte) []byte { return append(good, []byte(` {}`)...) },
		"not JSON":       func(*env, []byte) []byte { return []byte("<xml/>") },
		"top-level list": func(*env, []byte) []byte { return []byte("[]") },
		"too deep": func(*env, []byte) []byte {
			return []byte(strings.Repeat(`{"a":`, 20) + "1" + strings.Repeat("}", 20))
		},
		"invalid UTF-8": func(_ *env, good []byte) []byte {
			return bytes.Replace(good, []byte(`"acme/app"`), []byte("\"acme/\xff\""), 1)
		},
		"byte-order mark": func(_ *env, good []byte) []byte { return append([]byte{0xEF, 0xBB, 0xBF}, good...) },
		"before is an object": func(e *env, _ []byte) []byte {
			return withDiff(e, map[string]any{"a": 1})
		},
		"before is a float with an exponent": func(e *env, _ []byte) []byte {
			return withDiff(e, num("1e999999999"))
		},
		"before is over 1 KiB": func(e *env, _ []byte) []byte {
			return withDiff(e, strings.Repeat("x", 1025))
		},
		"oversized": func(_ *env, good []byte) []byte {
			return append(good, bytes.Repeat([]byte(" "), oracle.MaxReportSize)...)
		},
	}
	for name, mk := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			e := newEnv(t)
			e.raw = mk(e, mustJSON(t, e.report))
			want(t, e.eval(), oracle.Error, oracle.ReasonReportMalformed)
		})
	}
}

func TestEvaluate_ReportScalarBoundary(t *testing.T) { // PIP-13
	t.Parallel()
	e := newEnv(t)
	e.in.Kind = oracle.KindFix
	e.in.Fix = e.fix(delta("r", "f", strings.Repeat("x", 1024), nil))
	e.differ("c1", "http-api", diff("r", "GET /cart", "f", strings.Repeat("x", 1024), nil))
	want(t, e.eval(), oracle.Pass, oracle.ReasonNone) // exactly 1 KiB is accepted
}

func TestEvaluate_FirstIntroduction(t *testing.T) { // PIP-13
	t.Parallel()
	t.Run("a blocked switch comparison with an empty New blocks", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t)
		e.in.Switches = switches.Comparison{Verdict: switches.VerdictBlocked, Removed: []switches.Change{{Key: "k", Path: "flags.json"}}}
		want(t, e.eval(), oracle.Blocked, oracle.ReasonFirstIntroduction)
	})
	t.Run("an error verdict blocks", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t)
		e.in.Switches = switches.Comparison{Verdict: switches.VerdictError}
		want(t, e.eval(), oracle.Blocked, oracle.ReasonFirstIntroduction)
	})
	t.Run("a zero comparison blocks", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t)
		e.in.Switches = switches.Comparison{}
		want(t, e.eval(), oracle.Blocked, oracle.ReasonFirstIntroduction)
	})
	t.Run("overrides missing a new key", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t)
		e.firstIntroduction()
		e.in.Switches.New = append(e.in.Switches.New, switches.Change{Key: "second-key", Status: switches.StatusDefaultOff})
		want(t, e.eval(), oracle.Blocked, oracle.ReasonFirstIntroduction)
	})
	t.Run("an extra override key", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t)
		e.in.Switches = switches.Comparison{Verdict: switches.VerdictPass}
		e.report = e.goodReport(map[string]string{"sneaky": "off"})
		want(t, e.eval(), oracle.Blocked, oracle.ReasonFirstIntroduction)
	})
	t.Run("a new switch forced on", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t)
		e.in.Switches = switches.Comparison{Verdict: switches.VerdictPass, New: []switches.Change{{Key: "new-key", Status: switches.StatusDefaultOff}}}
		e.report = e.goodReport(map[string]string{"new-key": "on"})
		want(t, e.eval(), oracle.Blocked, oracle.ReasonFirstIntroduction)
	})
	t.Run("a new switch run without the override", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t)
		e.in.Switches = switches.Comparison{Verdict: switches.VerdictPass, New: []switches.Change{{Key: "new-key", Status: switches.StatusDefaultOff}}}
		want(t, e.eval(), oracle.Blocked, oracle.ReasonFirstIntroduction)
	})
}

func TestEvaluate_Configs(t *testing.T) { // PIP-13
	t.Parallel()
	other := "sha256:" + strings.Repeat("9", 64)
	tests := map[string]func(r map[string]any){
		"loaded baseline differs": func(r map[string]any) {
			obj(obj(r["configs"])["loaded"])["baseline"] = other
		},
		"loaded candidate differs": func(r map[string]any) {
			obj(obj(r["configs"])["loaded"])["candidate"] = other
		},
		"requested baseline is not the release defaults": func(r map[string]any) {
			c := obj(r["configs"])
			obj(c["requested"])["baseline"] = other
			obj(c["loaded"])["baseline"] = other
		},
		"requested candidate is not derived": func(r map[string]any) {
			c := obj(r["configs"])
			obj(c["requested"])["candidate"] = other
			obj(c["loaded"])["candidate"] = other
		},
	}
	for name, mod := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			e := newEnv(t)
			mod(e.report)
			want(t, e.eval(), oracle.Blocked, oracle.ReasonConfigMismatch)
		})
	}
	t.Run("requested candidate ignoring the overrides", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t)
		e.firstIntroduction()
		c := obj(e.report["configs"])
		obj(c["requested"])["candidate"] = defaults
		obj(c["loaded"])["candidate"] = defaults
		want(t, e.eval(), oracle.Blocked, oracle.ReasonConfigMismatch)
	})
}

func TestEvaluate_Coverage(t *testing.T) { // PIP-13
	t.Parallel()
	tests := map[string]func(e *env){
		"missing observation": func(e *env) { e.dropObs("c2", "event-bus") },
		"duplicate observation": func(e *env) {
			e.report["observations"] = append(list(e.report["observations"]), e.obs("c1", "http-api"))
		},
		"extra observation of an unknown case": func(e *env) {
			o := map[string]any{}
			for k, v := range e.obs("c1", "http-api") {
				o[k] = v
			}
			o["case"] = "c3"
			e.report["observations"] = append(list(e.report["observations"]), o)
		},
		"extra observation replacing one": func(e *env) {
			e.dropObs("c1", "http-api")
			o := map[string]any{}
			for k, v := range e.obs("c1", "db-read") {
				o[k] = v
			}
			o["boundary"] = "elsewhere"
			e.report["observations"] = append(list(e.report["observations"]), o)
		},
		"denied on the baseline": func(e *env) { obj(e.obs("c1", "http-api")["baseline"])["status"] = "denied" },
		"denied on the candidate": func(e *env) {
			obj(e.obs("c1", "job-queue")["candidate"])["status"] = "denied"
		},
		"denied on both sides": func(e *env) {
			o := e.obs("c2", "db-read")
			obj(o["baseline"])["status"] = "denied"
			obj(o["candidate"])["status"] = "denied"
		},
		"candidate fixture substituted": func(e *env) { obj(e.obs("c1", "http-api")["candidate"])["fixture"] = fixtureB },
		"baseline fixture substituted":  func(e *env) { obj(e.obs("c2", "http-api")["baseline"])["fixture"] = fixtureA },
		"no observations":               func(e *env) { e.report["observations"] = []any{} },
		"malformed digest":              func(e *env) { obj(e.obs("c1", "http-api")["baseline"])["digest"] = "md5:abc" },
	}
	for name, mod := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			e := newEnv(t)
			mod(e)
			want(t, e.eval(), oracle.Blocked, oracle.ReasonCoverage)
		})
	}
}

func TestEvaluate_DiffIntegrity(t *testing.T) { // PIP-13
	t.Parallel()
	tests := map[string]func(e *env){
		"unequal digests with no differences": func(e *env) {
			obj(e.obs("c1", "http-api")["candidate"])["digest"] = digest2
		},
		"equal digests with differences": func(e *env) {
			e.obs("c1", "http-api")["differences"] = []any{diff("r", "o", "f", nil, num("1"))}
		},
		"differences incomplete": func(e *env) { e.obs("c1", "http-api")["differencesComplete"] = false },
		"differences incomplete with a difference": func(e *env) {
			e.differ("c1", "http-api", diff("r", "o", "f", nil, num("1")))
			e.obs("c1", "http-api")["differencesComplete"] = false
		},
	}
	for name, mod := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			e := newEnv(t)
			mod(e)
			want(t, e.eval(), oracle.Blocked, oracle.ReasonReportInconsistent)
		})
	}
	t.Run("a fix cannot hide a difference behind an incomplete list", func(t *testing.T) {
		t.Parallel()
		e := fixEnv(t, delta("r", "f", nil, num("1")))
		e.differ("c1", "http-api", diff("r", "GET /cart", "f", nil, num("1")))
		e.obs("c1", "http-api")["differencesComplete"] = false
		want(t, e.eval(), oracle.Blocked, oracle.ReasonReportInconsistent)
	})
}

func TestEvaluate_PerPathCoverage(t *testing.T) { // PIP-13
	t.Parallel()
	build := func(paths []string, stacks ...[]contract.OracleObligation) *contract.Effective {
		eff := &contract.Effective{Revision: "pol1", InstallRevision: "inst1"}
		for _, s := range stacks {
			eff.Stacks = append(eff.Stacks, contract.StackPolicy{Stack: []string{".factory.yaml"}, Oracles: s})
			eff.Oracles = append(eff.Oracles, s...)
		}
		for i, p := range paths {
			eff.Paths = append(eff.Paths, contract.PathPolicy{Path: p, Covered: true, StackIndex: min(i, len(stacks)-1)})
		}
		return eff
	}
	run := func(eff *contract.Effective, manifests map[string][]byte) oracle.Decision {
		e := newEnv(t)
		reports := map[contract.GateRef]oracle.Report{}
		for i := range eff.Oracles {
			ref := eff.Oracles[i].Oracle.GateRef
			reports[ref] = oracle.Report{Manifest: manifests[ref.CheckID]}
		}
		in := e.in
		in.Reports = reports
		return oracle.Evaluate(eff, in)
	}
	t.Run("a changed path no oracle covers", func(t *testing.T) {
		t.Parallel()
		m := manifestYAML([]string{"src/checkout/**"}, all5...)
		eff := build([]string{"src/checkout/a.go", "src/billing/b.go"}, []contract.OracleObligation{obligationFor("checkout", m, all5)})
		d := run(eff, map[string][]byte{"checkout": m})
		wantChange(t, d, oracle.Blocked, oracle.ReasonOracleMissing)
	})
	t.Run("an oracle that lacks queued-jobs where another stack has all five", func(t *testing.T) {
		t.Parallel()
		mCheckout := manifestYAML([]string{"src/checkout/**"}, all5...)
		mBilling := manifestYAML([]string{"src/billing/**"}, 0, 1, 2, 3) // no queued-jobs
		eff := build([]string{"src/checkout/a.go", "src/billing/b.go"},
			[]contract.OracleObligation{obligationFor("checkout", mCheckout, all5)},
			[]contract.OracleObligation{obligationFor("billing", mBilling, []int{0, 1, 2, 3})})
		d := run(eff, map[string][]byte{"checkout": mCheckout, "billing": mBilling})
		wantChange(t, d, oracle.Blocked, oracle.ReasonOracleIncomplete)
	})
	t.Run("two oracles on a stack together observe all five", func(t *testing.T) {
		t.Parallel()
		m1 := manifestYAML([]string{"src/**"}, 0, 1, 2)
		m2 := manifestYAML([]string{"src/**"}, 3, 4)
		eff := build([]string{"src/a.go"}, []contract.OracleObligation{obligationFor("one", m1, []int{0, 1, 2}), obligationFor("two", m2, []int{3, 4})})
		d := run(eff, map[string][]byte{"one": m1, "two": m2})
		for _, r := range d.Reasons {
			if r == oracle.ReasonOracleIncomplete || r == oracle.ReasonOracleMissing {
				t.Errorf("Reasons = %v, want no coverage reason", d.Reasons)
			}
		}
	})
	t.Run("an oracle of another stack does not cover the path", func(t *testing.T) {
		t.Parallel()
		m := manifestYAML([]string{"**"}, all5...) // claims everything, but is on the other stack
		eff := &contract.Effective{
			Revision: "pol1", InstallRevision: "inst1",
			Paths:   []contract.PathPolicy{{Path: "svc/a.go", Covered: true, StackIndex: 0}},
			Stacks:  []contract.StackPolicy{{Stack: []string{"svc/.factory.yaml"}}, {Stack: []string{"other/.factory.yaml"}, Oracles: []contract.OracleObligation{obligationFor("greedy", m, all5)}}},
			Oracles: []contract.OracleObligation{obligationFor("greedy", m, all5)},
		}
		d := run(eff, map[string][]byte{"greedy": m})
		wantChange(t, d, oracle.Blocked, oracle.ReasonOracleMissing)
	})
	t.Run("an uncovered path of the contract set", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t)
		e.eff.Uncovered = []string{"docs/x.md"}
		wantChange(t, e.eval(), oracle.Blocked, oracle.ReasonOracleMissing)
	})
	t.Run("no oracles", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t)
		e.eff.Oracles, e.eff.Stacks[0].Oracles = nil, nil
		d := e.eval()
		wantChange(t, d, oracle.Blocked, oracle.ReasonOracleMissing)
		if len(d.Oracles) != 0 {
			t.Errorf("Oracles = %+v", d.Oracles)
		}
	})
	t.Run("no paths", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t)
		e.eff.Paths = nil
		wantChange(t, e.eval(), oracle.Blocked, oracle.ReasonOracleMissing)
	})
	t.Run("a path outside the manifest's covers", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t)
		e.eff.Paths[0].Path = "lib/other.go"
		wantChange(t, e.eval(), oracle.Blocked, oracle.ReasonOracleMissing)
	})
}

func TestEvaluate_EscapesUntrustedText(t *testing.T) { // SEC-1
	t.Parallel()
	bidi := string(rune(0x202e))
	hostile := "evil\n::error::forged\x1b[31m" + bidi
	bad := "\n\x1b" + bidi
	e := newEnv(t)
	e.report["observations"] = append(list(e.report["observations"]), map[string]any{
		"case": hostile, "boundary": hostile,
		"baseline":            map[string]any{"status": "completed", "fixture": fixtureA, "digest": digest1},
		"candidate":           map[string]any{"status": "completed", "fixture": fixtureA, "digest": digest1},
		"differencesComplete": true, "differences": []any{},
	})
	e.report["switchOverrides"] = map[string]any{hostile: "off"}
	d := e.eval()
	r := want(t, d, oracle.Blocked, oracle.ReasonFirstIntroduction)
	for _, s := range r.Evidence {
		if strings.ContainsAny(s, bad) {
			t.Errorf("unescaped evidence %q", s)
		}
	}
	// Binding fields are raw, so the caller can compare and store them; the renderer escapes.
	if diff := cmp.Diff([]oracle.Override{{Key: hostile, Value: "off"}}, r.SwitchOverrides); diff != "" {
		t.Errorf("SwitchOverrides (-want +got):\n%s", diff)
	}
	// The same text in an extra observation is escaped in the evidence.
	e = newEnv(t)
	e.report["observations"] = append(list(e.report["observations"]), map[string]any{
		"case": hostile, "boundary": hostile,
		"baseline":            map[string]any{"status": "completed", "fixture": fixtureA, "digest": digest1},
		"candidate":           map[string]any{"status": "completed", "fixture": fixtureA, "digest": digest1},
		"differencesComplete": true, "differences": []any{},
	})
	r = want(t, e.eval(), oracle.Blocked, oracle.ReasonCoverage)
	if len(r.Evidence) == 0 || strings.ContainsAny(r.Evidence[0], bad) {
		t.Errorf("evidence = %q", r.Evidence)
	}
	// A hostile difference is escaped in the evidence.
	e = newEnv(t)
	e.differ("c1", "http-api", diff(hostile, "o", hostile, nil, num("1")))
	r = want(t, e.eval(), oracle.Blocked, oracle.ReasonDifference)
	for _, s := range r.Evidence {
		if strings.ContainsAny(s, bad) {
			t.Errorf("unescaped evidence %q", s)
		}
	}
}

func TestEvaluate_DoesNotModifyInputs(t *testing.T) {
	t.Parallel()
	e := fixEnv(t, delta("cart/1", "/status", num("404"), num("200")))
	e.differ("c1", "http-api", diff("cart/1", "GET /cart", "/status", num("404"), num("200")))
	before := cloneEff(e.eff)
	d1 := e.eval()
	d2 := e.eval()
	if diff := cmp.Diff(d1, d2); diff != "" {
		t.Errorf("not deterministic (-first +second):\n%s", diff)
	}
	if diff := cmp.Diff(before, cloneEff(e.eff)); diff != "" {
		t.Errorf("effective contract modified:\n%s", diff)
	}
}

func cloneEff(e *contract.Effective) contract.Effective {
	c := *e
	c.Oracles = append([]contract.OracleObligation(nil), e.Oracles...)
	return c
}
