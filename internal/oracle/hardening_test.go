// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

package oracle_test

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/elliott-davis/lightsout/internal/contract"
	"github.com/elliott-davis/lightsout/internal/oracle"
	"github.com/elliott-davis/lightsout/internal/switches"
)

// setManifest re-pins the oracle to new manifest bytes and rebuilds the report.
func (e *env) setManifest(m []byte) {
	e.t.Helper()
	e.manifest = m
	ob := obligationFor(checkID, m, all5)
	e.eff.Oracles = []contract.OracleObligation{ob}
	e.eff.Stacks[0].Oracles = []contract.OracleObligation{ob}
	e.report = e.goodReport(nil)
}

func TestEvaluate_ReportSignature(t *testing.T) { // PIP-13, SEC-1
	t.Parallel()
	t.Run("a correctly signed report passes and records the key", func(t *testing.T) {
		t.Parallel()
		r := want(t, newEnv(t).eval(), oracle.Pass, oracle.ReasonNone)
		if r.KeyID != keyID {
			t.Errorf("KeyID = %q", r.KeyID)
		}
	})
	t.Run("an unsigned report blocks", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t)
		e.noSig = true
		want(t, e.eval(), oracle.Blocked, oracle.ReasonReportMissing)
	})
	t.Run("a squatted report name with no signature blocks", func(t *testing.T) {
		t.Parallel()
		// A step of the run uploads a well-bound report first. Every binding field is computable, but it cannot sign.
		e := newEnv(t)
		e.noSig = true
		e.report["observations"] = []any{}
		want(t, e.eval(), oracle.Blocked, oracle.ReasonReportMissing)
	})
	t.Run("an attacker report with the genuine signature of another report blocks", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t)
		genuine := mustJSON(t, e.report)
		e.sigRaw = e.sign(genuine)
		e.report["repo"] = string(repo) // same fields, different bytes
		e.report["extra"] = 1
		want(t, e.eval(), oracle.Blocked, oracle.ReasonReportUnsigned)
	})
	t.Run("a signature by an unregistered key blocks", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t)
		e.signer, e.signKeyID = harnessKey("x"), "harness-2"
		want(t, e.eval(), oracle.Blocked, oracle.ReasonReportUnsigned)
	})
	t.Run("a registered key ID signed by another key blocks", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t)
		e.signer = harnessKey("x")
		want(t, e.eval(), oracle.Blocked, oracle.ReasonReportUnsigned)
	})
	t.Run("a signature over other bytes blocks", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t)
		e.sigRaw = e.sign([]byte("something else"))
		want(t, e.eval(), oracle.Blocked, oracle.ReasonReportUnsigned)
	})
	t.Run("a signature without the domain blocks", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t)
		data := mustJSON(t, e.report)
		sig := ed25519.Sign(harnessKey("k"), data) // not over the domain-separated digest
		e.sigRaw = mustJSON(t, map[string]any{"schema": oracle.SignatureSchema, "keyId": keyID, "signature": b64(sig)})
		want(t, e.eval(), oracle.Blocked, oracle.ReasonReportUnsigned)
	})
	t.Run("two signature artifacts are ambiguous", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t)
		data := mustJSON(t, e.report)
		sig := e.sign(data)
		s := oracle.Artifact{Name: oracle.SignatureArtifactName, SHA256: sum(sig), Bytes: sig}
		e.artifacts = []oracle.Artifact{{Name: reportName, SHA256: sum(data), Bytes: data}, s, s}
		want(t, e.eval(), oracle.Blocked, oracle.ReasonReportAmbiguous)
	})
	t.Run("a signature artifact that does not match its digest is unbound", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t)
		data := mustJSON(t, e.report)
		sig := e.sign(data)
		e.artifacts = []oracle.Artifact{
			{Name: reportName, SHA256: sum(data), Bytes: data},
			{Name: oracle.SignatureArtifactName, SHA256: strings.Repeat("0", 64), Bytes: sig},
		}
		want(t, e.eval(), oracle.Blocked, oracle.ReasonReportUnbound)
	})
	good := func() map[string]any {
		return map[string]any{"schema": oracle.SignatureSchema, "keyId": keyID, "signature": b64(make([]byte, ed25519.SignatureSize))}
	}
	for name, mod := range map[string]func(m map[string]any){
		"wrong schema":   func(m map[string]any) { m["schema"] = "lightsout.oracle-sig/v2" },
		"unknown field":  func(m map[string]any) { m["extra"] = "x" },
		"missing field":  func(m map[string]any) { delete(m, "keyId") },
		"bad base64":     func(m map[string]any) { m["signature"] = "!!!" },
		"key id not str": func(m map[string]any) { m["keyId"] = 1 },
	} {
		t.Run("malformed signature artifact: "+name, func(t *testing.T) {
			t.Parallel()
			e := newEnv(t)
			m := good()
			mod(m)
			e.sigRaw = mustJSON(t, m)
			want(t, e.eval(), oracle.Error, oracle.ReasonReportMalformed)
		})
	}
	t.Run("a signature with a duplicate key is malformed", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t)
		e.sigRaw = []byte(`{"schema":"lightsout.oracle-sig/v1","keyId":"a","keyId":"b","signature":""}`)
		want(t, e.eval(), oracle.Error, oracle.ReasonReportMalformed)
	})
	t.Run("an oversized signature is malformed", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t)
		e.sigRaw = append(e.sign(mustJSON(t, e.report)), bytes.Repeat([]byte(" "), 5000)...) // valid, so only the size can fail
		r := want(t, e.eval(), oracle.Error, oracle.ReasonReportMalformed)
		if len(r.Evidence) == 0 || !strings.Contains(r.Evidence[0], "limit") {
			t.Errorf("evidence = %q, want the size limit", r.Evidence)
		}
	})
	t.Run("a signature is checked before the report is parsed", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t)
		e.raw = []byte("not json")
		e.signer = harnessKey("x")
		want(t, e.eval(), oracle.Blocked, oracle.ReasonReportUnsigned) // not report-malformed: nothing unsigned is parsed
	})
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func TestEvaluate_FixAuthorizationBinding(t *testing.T) { // INT-10
	t.Parallel()
	t.Run("an authorization replayed after the manifest is re-pinned", func(t *testing.T) {
		t.Parallel()
		e := fixEnv(t, delta("cart/1", "/status", num("404"), num("200")))
		other := "sha256:" + strings.Repeat("c", 64)
		e.setManifest(bytes.Replace(e.manifest, []byte(fixtureA), []byte(other), 1)) // c1 runs another input now
		for _, o := range list(e.report["observations"]) {
			if m := obj(o); m["case"] == "c1" {
				obj(m["baseline"])["fixture"], obj(m["candidate"])["fixture"] = other, other
			}
		}
		e.differ("c1", "http-api", diff("cart/1", "GET /cart", "/status", num("404"), num("200")))
		want(t, e.eval(), oracle.Blocked, oracle.ReasonUnauthorizedDifference)
	})
	t.Run("another case manifest digest", func(t *testing.T) {
		t.Parallel()
		e := fixEnv(t, delta("cart/1", "/status", num("404"), num("200")))
		e.in.Fix.CaseManifest = strings.Repeat("c", 64)
		e.differ("c1", "http-api", diff("cart/1", "GET /cart", "/status", num("404"), num("200")))
		want(t, e.eval(), oracle.Blocked, oracle.ReasonUnauthorizedDifference)
	})
	t.Run("another workflow revision", func(t *testing.T) {
		t.Parallel()
		e := fixEnv(t, delta("cart/1", "/status", num("404"), num("200")))
		e.in.Fix.OracleRevision = strings.Repeat("c", 40)
		e.differ("c1", "http-api", diff("cart/1", "GET /cart", "/status", num("404"), num("200")))
		want(t, e.eval(), oracle.Blocked, oracle.ReasonUnauthorizedDifference)
	})
	t.Run("another contract revision is invalid input", func(t *testing.T) {
		t.Parallel()
		e := fixEnv(t, delta("cart/1", "/status", num("404"), num("200")))
		e.in.Fix.ContractRevision = "pol0"
		wantChange(t, e.eval(), oracle.Error, oracle.ReasonInvalidInput)
	})
	t.Run("a bound authorization still passes", func(t *testing.T) {
		t.Parallel()
		e := fixEnv(t, delta("cart/1", "/status", num("404"), num("200")))
		e.differ("c1", "http-api", diff("cart/1", "GET /cart", "/status", num("404"), num("200")))
		d := e.eval()
		want(t, d, oracle.Pass, oracle.ReasonNone)
		if d.AuthorizationID != "auth-1" {
			t.Errorf("AuthorizationID = %q", d.AuthorizationID)
		}
	})
}

func TestEvaluate_InvalidInputRound2(t *testing.T) { // PIP-13, SEC-10
	t.Parallel()
	tests := map[string]func(e *env){
		"baseline equals candidate":     func(e *env) { e.in.BaselineSHA = candSHA },
		"head SHA is not a full SHA":    func(e *env) { e.in.Target.HeadSHA = "head" },
		"no PR":                         func(e *env) { e.in.Target.PR = 0 },
		"release defaults not a digest": func(e *env) { e.in.ReleaseDefaults = "latest" },
		"release defaults uppercase":    func(e *env) { e.in.ReleaseDefaults = "sha256:" + strings.Repeat("A", 64) },
		"no harness keys":               func(e *env) { e.in.HarnessKeys = nil },
		"a harness key of the wrong size": func(e *env) {
			e.in.HarnessKeys["short"] = oracle.HarnessKey{Public: ed25519.PublicKey("abc"), Repo: repo, Oracle: refFor(checkID).Key()}
		},
		"no issue":       func(e *env) { e.in.Issue = 0 },
		"negative issue": func(e *env) { e.in.Issue = -1 },
	}
	for name, mod := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			e := newEnv(t)
			mod(e)
			wantChange(t, e.eval(), oracle.Error, oracle.ReasonInvalidInput)
		})
	}
	t.Run("a fix delta with an empty case", func(t *testing.T) {
		t.Parallel()
		e := fixEnv(t, oracle.Delta{Boundary: "http-api"})
		wantChange(t, e.eval(), oracle.Error, oracle.ReasonInvalidInput)
	})
	t.Run("a fix delta with an empty boundary", func(t *testing.T) {
		t.Parallel()
		e := fixEnv(t, oracle.Delta{Case: "c1"})
		wantChange(t, e.eval(), oracle.Error, oracle.ReasonInvalidInput)
	})
	t.Run("a fix delta with an oversized record", func(t *testing.T) {
		t.Parallel()
		e := fixEnv(t, oracle.Delta{Case: "c1", Boundary: "http-api", Record: strings.Repeat("x", oracle.MaxScalar+1)})
		wantChange(t, e.eval(), oracle.Error, oracle.ReasonInvalidInput)
	})
	t.Run("a delta record of exactly the limit is valid", func(t *testing.T) {
		t.Parallel()
		e := fixEnv(t, oracle.Delta{Case: "c1", Boundary: "http-api", Record: strings.Repeat("x", oracle.MaxScalar)})
		want(t, e.eval(), oracle.Pass, oracle.ReasonNone)
	})
}

func TestEvaluate_ProtectedPath(t *testing.T) { // CON-6
	t.Parallel()
	e := newEnv(t)
	e.eff.Paths[0].Protected = true
	d := e.eval()
	wantChange(t, d, oracle.Blocked, oracle.ReasonProtectedPath)
	e = newEnv(t)
	e.eff.Paths[0].Sensitive = true // security sign-off is another work item's
	want(t, e.eval(), oracle.Pass, oracle.ReasonNone)
}

func TestEvaluate_PathReasonsAreCollected(t *testing.T) { // PIP-13
	t.Parallel()
	// One path is covered by an oracle lacking queued-jobs, another by none, a third is protected.
	m := manifestYAML([]string{"src/checkout/**"}, 0, 1, 2, 3)
	ob := obligationFor("checkout", m, []int{0, 1, 2, 3})
	eff := &contract.Effective{
		Revision: "pol1", InstallRevision: "inst1",
		Paths: []contract.PathPolicy{
			{Path: "src/billing/b.go", Covered: true},
			{Path: "src/checkout/a.go", Covered: true},
			{Path: "src/checkout/p.go", Covered: true, Protected: true},
		},
		Stacks:  []contract.StackPolicy{{Oracles: []contract.OracleObligation{ob}}},
		Oracles: []contract.OracleObligation{ob},
	}
	e := newEnv(t)
	in := e.in
	in.Reports = map[contract.GateRef]oracle.Report{ob.Oracle.GateRef: {Manifest: m}}
	d := oracle.Evaluate(eff, in)
	want := []oracle.Reason{oracle.ReasonOracleIncomplete, oracle.ReasonOracleMissing, oracle.ReasonProtectedPath}
	if diff := cmp.Diff(want, d.Reasons); diff != "" || d.Disposition != oracle.Blocked {
		t.Errorf("Reasons (-want +got):\n%s\ndisposition %s", diff, d.Disposition)
	}
	e = newEnv(t)
	e.eff.Paths[0].Covered = false // not in Uncovered, but still not covered
	wantChange(t, e.eval(), oracle.Blocked, oracle.ReasonOracleMissing)
}

func TestEvaluate_NewSwitchMustBeDefaultOff(t *testing.T) { // PIP-13, FLG-2
	t.Parallel()
	for _, st := range []switches.Status{switches.StatusDefaultOn, ""} {
		e := newEnv(t)
		e.firstIntroduction()
		e.in.Switches.New[0].Status = st // a pass verdict alone is not trusted
		want(t, e.eval(), oracle.Blocked, oracle.ReasonFirstIntroduction)
	}
}

func TestEvaluate_BindingFieldsAreRaw(t *testing.T) { // PIP-13
	t.Parallel()
	a, b := strings.Repeat("x", 250)+"-A#", strings.Repeat("x", 250)+"-B#"
	var ids []string
	for _, id := range []string{a, b} {
		e := fixEnv(t)
		e.in.Fix.ID = id
		ids = append(ids, e.eval().AuthorizationID)
	}
	if ids[0] != a || ids[1] != b {
		t.Errorf("AuthorizationID is not the raw ID: %q", ids)
	}
	e := newEnv(t)
	e.in.Switches = switches.Comparison{Verdict: switches.VerdictPass, New: []switches.Change{
		{Key: "b-key", Status: switches.StatusDefaultOff}, {Key: "a-key", Status: switches.StatusDefaultOff},
	}}
	e.report = e.goodReport(map[string]string{"b-key": "off", "a-key": "off"})
	d := e.eval()
	want(t, d, oracle.Pass, oracle.ReasonNone)
	wantOv := []oracle.Override{{Key: "a-key", Value: "off"}, {Key: "b-key", Value: "off"}}
	if diff := cmp.Diff(wantOv, d.ExpectedOverrides); diff != "" {
		t.Errorf("ExpectedOverrides (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(wantOv, d.Oracles[0].SwitchOverrides); diff != "" {
		t.Errorf("SwitchOverrides (-want +got):\n%s", diff)
	}
}

func TestEvaluate_ReportBoundsAreIsolated(t *testing.T) { // PIP-13
	t.Parallel()
	t.Run("1025 differences in one observation", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t)
		var ds []map[string]any
		for i := range 1025 {
			ds = append(ds, diff(fmt.Sprintf("r%d", i), "o", "f", nil, num("1")))
		}
		e.differ("c1", "http-api", ds...)
		want(t, e.eval(), oracle.Error, oracle.ReasonReportMalformed)
	})
	t.Run("1024 differences in one observation are parsed", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t)
		var ds []map[string]any
		for i := range 1024 {
			ds = append(ds, diff(fmt.Sprintf("r%d", i), "o", "f", nil, num("1")))
		}
		e.differ("c1", "http-api", ds...)
		r := want(t, e.eval(), oracle.Blocked, oracle.ReasonDifference)
		if r.Differences != 1024 {
			t.Errorf("Differences = %d", r.Differences)
		}
	})
	t.Run("an object with too many keys", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t)
		ov := map[string]any{}
		for i := range 257 {
			ov[fmt.Sprintf("k%d", i)] = "off"
		}
		e.report["switchOverrides"] = ov
		want(t, e.eval(), oracle.Error, oracle.ReasonReportMalformed)
	})
	t.Run("an array longer than the matrix", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t)
		e.report["observations"] = make([]any, oracle.MaxMatrix+1)
		want(t, e.eval(), oracle.Error, oracle.ReasonReportMalformed)
	})
	t.Run("nesting deeper than the limit is named", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t)
		e.raw = []byte(strings.Repeat(`{"a":`, 20) + "1" + strings.Repeat("}", 20))
		r := want(t, e.eval(), oracle.Error, oracle.ReasonReportMalformed)
		if len(r.Evidence) == 0 || !strings.Contains(r.Evidence[0], "deeper") {
			t.Errorf("evidence = %q, want the depth error", r.Evidence)
		}
	})
	t.Run("-0 equals 0", func(t *testing.T) {
		t.Parallel()
		e := fixEnv(t, delta("r", "f", num("0"), num("1")))
		e.differ("c1", "http-api", diff("r", "GET /cart", "f", num("-0"), num("1.50")))
		want(t, e.eval(), oracle.Blocked, oracle.ReasonUnauthorizedDifference) // 1.50 is 1.5, not 1
		e = fixEnv(t, delta("r", "f", num("0"), num("1.5")))
		e.differ("c1", "http-api", diff("r", "GET /cart", "f", num("-0"), num("1.50")))
		want(t, e.eval(), oracle.Pass, oracle.ReasonNone)
	})
	t.Run("a manifest over the size limit with a matching pin", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t)
		e.setManifest(append(bytes.Clone(e.manifest), []byte("# "+strings.Repeat("x", oracle.MaxManifestSize))...))
		d := e.eval() // it covers nothing, and does not validate
		if d.Oracles[0].Reason != oracle.ReasonManifestInvalid || !slices.Contains(d.Reasons, oracle.ReasonOracleMissing) {
			t.Errorf("reason = %q, reasons = %v", d.Oracles[0].Reason, d.Reasons)
		}
	})
}

// A report padded with empty values must fail fast, with bounded allocation (parse amplification).
func TestEvaluate_ParseAmplificationIsBounded(t *testing.T) { // SEC-1
	for name, item := range map[string]string{"objects": "{},", "arrays": "[],", "numbers": "0,", "strings": `"",`} {
		var b bytes.Buffer
		b.WriteString(`{"schema":"lightsout.oracle/v1","pad":[`)
		for b.Len() < oracle.MaxReportSize-16 {
			b.WriteString(item)
		}
		b.Truncate(b.Len() - 1)
		b.WriteString("]}")
		e := newEnv(t)
		e.raw = b.Bytes()
		runtime.GC()
		var m0, m1 runtime.MemStats
		runtime.ReadMemStats(&m0)
		d := e.eval()
		runtime.ReadMemStats(&m1)
		if r := d.Oracles[0]; r.Reason != oracle.ReasonReportMalformed {
			t.Errorf("%s: reason = %q", name, r.Reason)
		}
		// Hashing and signing the 8 MiB report is not parsing; the cap is generous for them plus a bounded tree.
		if alloc := m1.TotalAlloc - m0.TotalAlloc; alloc > 64<<20 {
			t.Errorf("%s: allocated %d MiB, want under 64", name, alloc>>20)
		}
	}
}

func TestEvaluate_StrictParserEdgeCases(t *testing.T) { // SEC-1
	t.Parallel()
	good := func(e *env) []byte { return mustJSON(e.t, e.report) }
	tests := map[string]func(e *env) []byte{
		"duplicate key spelled with an escape": func(e *env) []byte {
			return bytes.Replace(good(e), []byte(`"comparison":"exact/v1"`), []byte(`"comparison":"exact/v1","\u0063omparison":"exact/v1"`), 1)
		},
		"escaped NUL in a field": func(e *env) []byte {
			return bytes.Replace(good(e), []byte(`"acme/app"`), []byte(`"acme/app\u0000"`), 1)
		},
		"raw NUL in a field": func(e *env) []byte {
			return bytes.Replace(good(e), []byte(`"acme/app"`), []byte("\"acme/app\x00\""), 1)
		},
		"keys that collide as lone surrogates": func(e *env) []byte {
			return bytes.Replace(good(e), []byte(`{"baselineSHA"`), []byte(`{"\ud800":1,"\udbff":2,"baselineSHA"`), 1)
		},
		"NUL in an override": func(e *env) []byte {
			return bytes.Replace(good(e), []byte(`"switchOverrides":{}`), []byte(`"switchOverrides":{"k":"of\u0000f"}`), 1)
		},
		"missing comma": func(e *env) []byte {
			return bytes.Replace(good(e), []byte(`"comparison":"exact/v1",`), []byte(`"comparison":"exact/v1" `), 1)
		},
		"trailing comma": func(e *env) []byte {
			return bytes.Replace(good(e), []byte(`"comparison":"exact/v1",`), []byte(`"comparison":"exact/v1",,`), 1)
		},
	}
	for name, mk := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			e := newEnv(t)
			e.raw = mk(e)
			want(t, e.eval(), oracle.Error, oracle.ReasonReportMalformed)
		})
	}
}

// Every failure must be the same whichever order a map happens to iterate in.
func TestEvaluate_IsDeterministic(t *testing.T) { // SEC-1
	t.Parallel()
	inputs := map[string]func(e *env) []byte{
		"two unknown root fields": func(e *env) []byte {
			e.report["zeta"], e.report["alpha"], e.report["mid"] = 1, 2, 3
			return mustJSON(e.t, e.report)
		},
		"two bad job fields": func(e *env) []byte {
			j := obj(e.report["job"])
			j["runId"], j["jobId"] = 1, 2
			return mustJSON(e.t, e.report)
		},
		"two bad sides": func(e *env) []byte {
			o := e.obs("c1", "http-api")
			obj(o["baseline"])["status"], obj(o["candidate"])["digest"] = 1, 2
			obj(o["baseline"])["digest"], obj(o["candidate"])["status"] = 3, 4
			return mustJSON(e.t, e.report)
		},
		"two bad configs": func(e *env) []byte {
			c := obj(e.report["configs"])
			obj(c["requested"])["baseline"], obj(c["loaded"])["baseline"] = 1, 2
			return mustJSON(e.t, e.report)
		},
	}
	for name, mk := range inputs {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			var first oracle.Decision
			for i := range 50 {
				e := newEnv(t)
				e.raw = mk(e)
				d := e.eval()
				if d.Oracles[0].Reason != oracle.ReasonReportMalformed {
					t.Fatalf("reason = %q", d.Oracles[0].Reason)
				}
				if i == 0 {
					first = d
				} else if diff := cmp.Diff(first, d); diff != "" {
					t.Fatalf("run %d differs (-first +got):\n%s", i, diff)
				}
			}
		})
	}
}

func cloneEffective(e *contract.Effective) *contract.Effective {
	c := *e
	c.Paths = slices.Clone(e.Paths)
	c.Uncovered = slices.Clone(e.Uncovered)
	c.Conflicts = slices.Clone(e.Conflicts)
	c.Oracles = cloneOracles(e.Oracles)
	c.Stacks = make([]contract.StackPolicy, len(e.Stacks))
	for i, s := range e.Stacks {
		s.Oracles = cloneOracles(s.Oracles)
		c.Stacks[i] = s
	}
	return &c
}

func cloneOracles(in []contract.OracleObligation) []contract.OracleObligation {
	out := slices.Clone(in)
	for i := range out {
		out[i].Oracle.Observables = slices.Clone(out[i].Oracle.Observables)
		out[i].Sources = slices.Clone(out[i].Sources)
	}
	return out
}

func cloneInput(in oracle.Input) oracle.Input {
	c := in
	c.Evidence.Executions = slices.Clone(in.Evidence.Executions)
	c.Switches.New = slices.Clone(in.Switches.New)
	c.Switches.Removed = slices.Clone(in.Switches.Removed)
	c.HarnessKeys = map[string]oracle.HarnessKey{}
	for k, v := range in.HarnessKeys {
		v.Public = slices.Clone(v.Public)
		c.HarnessKeys[k] = v
	}
	if in.Fix != nil {
		f := *in.Fix
		f.Deltas = slices.Clone(in.Fix.Deltas)
		c.Fix = &f
	}
	c.Reports = map[contract.GateRef]oracle.Report{}
	for k, r := range in.Reports {
		r.Manifest = slices.Clone(r.Manifest)
		r.Artifacts = slices.Clone(r.Artifacts)
		for i := range r.Artifacts {
			r.Artifacts[i].Bytes = slices.Clone(r.Artifacts[i].Bytes)
		}
		c.Reports[k] = r
	}
	return c
}

func TestEvaluate_DoesNotModifyInputsDeep(t *testing.T) {
	t.Parallel()
	e := fixEnv(t, delta("cart/1", "/status", num("404"), num("200")))
	e.firstIntroduction()
	e.differ("c1", "http-api", diff("cart/1", "GET /cart", "/status", num("404"), num("200")))
	e.in.Fix.Deltas[0].Before = json.Number("404")
	e.in.Reports = nil
	_ = e.eval() // fills e.in.Reports
	effBefore, inBefore := cloneEffective(e.eff), cloneInput(e.in)
	d1 := oracle.Evaluate(e.eff, e.in)
	d2 := oracle.Evaluate(e.eff, e.in)
	if diff := cmp.Diff(d1, d2); diff != "" {
		t.Errorf("not deterministic (-first +second):\n%s", diff)
	}
	if diff := cmp.Diff(effBefore, e.eff); diff != "" {
		t.Errorf("Effective modified:\n%s", diff)
	}
	if diff := cmp.Diff(inBefore, e.in, cmpopts.EquateEmpty()); diff != "" {
		t.Errorf("Input modified:\n%s", diff)
	}
}

func TestValidateManifest_BoundsAreIsolated(t *testing.T) { // PIP-13
	t.Parallel()
	reads := []contract.Observable{contract.ObservableReads}
	build := func(cases, bounds, covers int) []byte {
		var b strings.Builder
		b.WriteString("schema: lightsout.oracle-cases/v1\ncases:\n")
		for i := range cases {
			fmt.Fprintf(&b, "  - {id: c%d, fixture: '%s'}\n", i, fixtureA)
		}
		b.WriteString("boundaries:\n")
		for i := range bounds {
			fmt.Fprintf(&b, "  - {name: b%d, observable: reads}\n", i)
		}
		b.WriteString("covers:\n")
		for i := range covers {
			fmt.Fprintf(&b, "  - 'd%d/**'\n", i)
		}
		return []byte(b.String())
	}
	tests := []struct {
		name                  string
		cases, bounds, covers int
		ok                    bool
	}{
		{"a product over 4096 with each side in range", 100, 41, 1, false},
		{"a product of exactly 4096", 64, 64, 1, true},
		{"257 covers", 1, 1, 257, false},
		{"256 covers", 1, 1, 256, true},
		{"4097 cases", 4097, 1, 1, false},
		{"65 boundaries", 1, 65, 1, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := oracle.ValidateManifest(build(tt.cases, tt.bounds, tt.covers), reads)
			if (err == nil) != tt.ok {
				t.Errorf("err = %v, want ok=%t", err, tt.ok)
			}
		})
	}
}

func TestEvaluate_HarnessKeys(t *testing.T) { // PIP-13, SEC-1
	t.Parallel()
	t.Run("another oracle's key blocks", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t)
		reg := harnessReg("z")
		reg.Oracle.CheckID = "other-oracle"
		e.in.HarnessKeys = map[string]oracle.HarnessKey{"other": reg}
		e.signer, e.signKeyID = harnessKey("z"), "other"
		want(t, e.eval(), oracle.Blocked, oracle.ReasonReportUnsigned)
	})
	t.Run("another repo's key blocks", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t)
		reg := harnessReg("z")
		reg.Repo = "acme/other"
		e.in.HarnessKeys = map[string]oracle.HarnessKey{"other": reg}
		e.signer, e.signKeyID = harnessKey("z"), "other"
		want(t, e.eval(), oracle.Blocked, oracle.ReasonReportUnsigned)
	})
	t.Run("a key scoped to this repo and oracle passes", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t)
		e.in.HarnessKeys["second"] = harnessReg("z")
		e.signer, e.signKeyID = harnessKey("z"), "second"
		want(t, e.eval(), oracle.Pass, oracle.ReasonNone)
	})
	t.Run("a key without a scope is invalid input", func(t *testing.T) {
		t.Parallel()
		for _, mod := range []func(k *oracle.HarnessKey){
			func(k *oracle.HarnessKey) { k.Repo = "" },
			func(k *oracle.HarnessKey) { k.Oracle = contract.GateKey{} },
			func(k *oracle.HarnessKey) { k.Oracle.CheckID = "" },
		} {
			e := newEnv(t)
			k := e.in.HarnessKeys[keyID]
			mod(&k)
			e.in.HarnessKeys[keyID] = k
			wantChange(t, e.eval(), oracle.Error, oracle.ReasonInvalidInput)
		}
	})
	t.Run("a small-order key can not forge a report", func(t *testing.T) {
		t.Parallel()
		identity := make([]byte, ed25519.PublicKeySize)
		identity[0] = 1
		forged := make([]byte, ed25519.SignatureSize)
		copy(forged, identity) // R = identity, S = 0 verifies for every message under the identity key
		e := newEnv(t)
		reg := harnessReg("k")
		reg.Public = identity
		e.in.HarnessKeys = map[string]oracle.HarnessKey{"weak": reg}
		e.sigRaw = mustJSON(t, map[string]any{"schema": oracle.SignatureSchema, "keyId": "weak", "signature": b64(forged)})
		wantChange(t, e.eval(), oracle.Error, oracle.ReasonInvalidInput)
	})
}

func TestValidHarnessKey(t *testing.T) { // SEC-1
	t.Parallel()
	hexKey := func(h string) ed25519.PublicKey {
		b, err := hex.DecodeString(h)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	ff := strings.Repeat("ff", 30)
	bad := map[string]ed25519.PublicKey{
		"zero":                    hexKey(strings.Repeat("00", 32)),
		"zero with sign bit":      hexKey(strings.Repeat("00", 31) + "80"),
		"identity":                hexKey("01" + strings.Repeat("00", 31)),
		"identity with sign bit":  hexKey("01" + strings.Repeat("00", 30) + "80"),
		"y = -1":                  hexKey("ec" + ff + "7f"),
		"y = -1 with sign bit":    hexKey("ec" + ff + "ff"),
		"y = p (non-canonical)":   hexKey("ed" + ff + "7f"),
		"y = p+1 (non-canonical)": hexKey("ee" + ff + "7f"),
		"order 8 a":               hexKey("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05"),
		"order 8 a, sign bit":     hexKey("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85"),
		"order 8 b":               hexKey("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a"),
		"order 8 b, sign bit":     hexKey("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa"),
		"short":                   hexKey("0102"),
		"nil":                     nil,
	}
	for name, k := range bad {
		if err := oracle.ValidHarnessKey(k); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if err := oracle.ValidHarnessKey(harnessReg("k").Public); err != nil {
		t.Errorf("a real key: %v", err)
	}
}

func TestSignReport_Errors(t *testing.T) { // SEC-1
	t.Parallel()
	good := harnessKey("k")
	tests := map[string]struct {
		id  string
		key ed25519.PrivateKey
	}{
		"nil key":          {keyID, nil},
		"short key":        {keyID, good[:10]},
		"public key only":  {keyID, good[ed25519.SeedSize:]},
		"empty key ID":     {"", good},
		"oversized key ID": {strings.Repeat("k", oracle.MaxScalar+1), good},
	}
	for name, tt := range tests {
		if _, err := oracle.SignReport(tt.id, tt.key, []byte("x")); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
	if _, err := oracle.SignReport(strings.Repeat("k", oracle.MaxScalar), good, []byte("x")); err != nil {
		t.Errorf("a key ID of exactly the limit: %v", err)
	}
}

// Each parser bound is isolated by the error it produces, and allocation stays bounded.
func TestEvaluate_ParserBoundsEachDenied(t *testing.T) { // SEC-1
	zeros := func(n int) string { return "[" + strings.TrimSuffix(strings.Repeat("0,", n), ",") + "]" }
	var many strings.Builder
	many.WriteString(`{"schema":"lightsout.oracle/v1","pad":[`)
	for i := range 500 { // 500 arrays of 4096 values: each within the array cap, together far over the value cap
		if i > 0 {
			many.WriteString(",")
		}
		many.WriteString(zeros(oracle.MaxMatrix))
	}
	many.WriteString("]}")
	tests := []struct {
		name string
		body func(e *env) []byte
		text string
	}{
		{"the total value cap", func(*env) []byte { return []byte(many.String()) }, "JSON values"},
		{"the array cap alone", func(*env) []byte {
			return []byte(`{"schema":"lightsout.oracle/v1","pad":` + zeros(oracle.MaxMatrix+1) + "}")
		}, "items"},
		{"the total difference cap", func(e *env) []byte {
			var ds []map[string]any
			for i := range 1024 {
				ds = append(ds, diff(fmt.Sprintf("r%d", i), "o", "f", nil, num("1")))
			}
			e.differ("c1", "http-api", ds...)
			for range 16 { // 17 observations of 1024 differences each; duplicates parse before coverage is judged
				e.report["observations"] = append(list(e.report["observations"]), e.obs("c1", "http-api"))
			}
			return mustJSON(e.t, e.report)
		}, "differences"},
	}
	for _, tt := range tests { // not parallel: it reads the allocation counters
		e := newEnv(t)
		e.raw = tt.body(e)
		runtime.GC()
		var m0, m1 runtime.MemStats
		runtime.ReadMemStats(&m0)
		d := e.eval()
		runtime.ReadMemStats(&m1)
		r := d.Oracles[0]
		if r.Reason != oracle.ReasonReportMalformed || len(r.Evidence) == 0 || !strings.Contains(r.Evidence[0], tt.text) {
			t.Errorf("%s: reason %q, evidence %q, want malformed mentioning %q", tt.name, r.Reason, r.Evidence, tt.text)
		}
		if alloc := m1.TotalAlloc - m0.TotalAlloc; alloc > 64<<20 {
			t.Errorf("%s: allocated %d MiB, want under 64", tt.name, alloc>>20)
		}
	}
}

func TestEvaluate_CoverageFailureIsDeterministic(t *testing.T) { // SEC-1
	t.Parallel()
	var first oracle.Decision
	for i := range 50 {
		e := newEnv(t)
		o := e.obs("c1", "http-api")
		obj(o["baseline"])["status"] = "denied"
		obj(o["candidate"])["status"] = "skipped"
		d := e.eval()
		if d.Oracles[0].Reason != oracle.ReasonCoverage {
			t.Fatalf("reason = %q", d.Oracles[0].Reason)
		}
		if i == 0 {
			first = d
		} else if diff := cmp.Diff(first, d); diff != "" {
			t.Fatalf("run %d differs:\n%s", i, diff)
		}
	}
	if ev := first.Oracles[0].Evidence; len(ev) == 0 || !strings.Contains(ev[0], "baseline status is denied") {
		t.Errorf("evidence = %q, want the baseline first", ev)
	}
}
