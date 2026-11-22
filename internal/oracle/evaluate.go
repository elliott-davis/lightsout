// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

package oracle

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/elliott-davis/lightsout/internal/contract"
	"github.com/elliott-davis/lightsout/internal/gate"
	"github.com/elliott-davis/lightsout/internal/switches"
)

var (
	fullSHA   = regexp.MustCompile(`^([0-9a-f]{40}|[0-9a-f]{64})$`)
	hexSHA256 = regexp.MustCompile(`^[0-9a-f]{64}$`)
	// configDigest is the form of a config digest: "sha256:" and 64 lowercase hex digits.
	configDigest = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

func rank(d Disposition) int {
	switch d {
	case Pass:
		return 0
	case Pending:
		return 1
	case Blocked:
		return 2
	case Error:
		return 3
	default:
		return 3 // an unknown disposition is as bad as an error
	}
}

func (d *Decision) raise(to Disposition) {
	if rank(to) > rank(d.Disposition) {
		d.Disposition = to
	}
}

func (d *Decision) addReason(r Reason) {
	if !slices.Contains(d.Reasons, r) {
		d.Reasons = append(d.Reasons, r)
	}
}

// prepared is one oracle obligation with its manifest, when the manifest bytes are valid.
type prepared struct {
	ob       *contract.OracleObligation
	manifest Manifest
	valid    bool
	input    Report
}

type oracleID struct {
	key           contract.GateKey
	rev, sha, obs string
}

// idOf matches the contract's oracle identity: key, revision, manifest digest and the sorted declared observables.
func idOf(o *contract.Oracle) oracleID {
	obs := slices.Clone(o.Observables)
	slices.Sort(obs)
	obs = slices.Compact(obs)
	names := make([]string, len(obs))
	for i, ob := range obs {
		names[i] = string(ob)
	}
	return oracleID{o.Key(), o.WorkflowRevision, o.CaseManifest.SHA256, strings.Join(names, ",")}
}

// Evaluate decides the dark-merge oracle for one change (PIP-13, PIP-4, INT-10). It is deterministic, does no I/O
// and does not modify its inputs. It fails closed: empty evidence, a missing oracle or any doubt never passes.
//
// The rules run in the order of docs/design/oracle.md, and the first failure of an oracle is its reason. Failures of
// the change as a whole (invalid input, a changed path no oracle covers) are in Decision.Reasons. Evidence lines are
// escaped; the binding fields are raw (see [Result]).
func Evaluate(eff *contract.Effective, in Input) Decision {
	d := Decision{
		Target: in.Target, BaselineSHA: in.BaselineSHA, Kind: in.Kind, Issue: in.Issue,
		ReleaseDefaults: in.ReleaseDefaults, Disposition: Pass,
	}
	if in.Fix != nil {
		d.AuthorizationID = in.Fix.ID
	}
	if eff != nil {
		d.PolicyRevision, d.InstallRevision = eff.Revision, eff.InstallRevision
	}
	if !validInput(eff, in) {
		d.Disposition = Error
		d.Reasons = []Reason{ReasonInvalidInput}
		return d
	}
	expected := expectedRaw(&in)
	d.ExpectedOverrides = sortedOverrides(expected)
	d.CandidateConfig = DeriveConfig(in.ReleaseDefaults, expected)

	preps := make([]prepared, len(eff.Oracles))
	byID := map[oracleID]*prepared{}
	for i := range eff.Oracles {
		p := &preps[i]
		p.ob = &eff.Oracles[i]
		p.input = in.Reports[p.ob.Oracle.GateRef]
		p.manifest, p.valid = loadManifest(p.ob, p.input.Manifest)
		byID[idOf(&p.ob.Oracle)] = p
	}

	// Rule 2.
	for _, r := range pathCoverage(eff, byID) {
		d.addReason(r)
		d.raise(Blocked)
	}

	// Rule 3.
	gd := gateDecision(eff, in)

	for i := range preps {
		r := evaluateOracle(&preps[i], &d, &in, &gd)
		d.Oracles = append(d.Oracles, r)
		d.raise(r.Disposition)
	}
	if len(d.Oracles) == 0 {
		d.addReason(ReasonOracleMissing)
		d.raise(Blocked)
	}
	return d
}

func sortedOverrides(m map[string]string) []Override {
	out := make([]Override, 0, len(m))
	for k, v := range m {
		out = append(out, Override{k, v})
	}
	slices.SortFunc(out, func(a, b Override) int { return strings.Compare(a.Key, b.Key) })
	return out
}

// validInput is rule 1.
func validInput(eff *contract.Effective, in Input) bool {
	if eff == nil || eff.Revision == "" || eff.InstallRevision == "" ||
		in.Target.Forge == "" || in.Target.Repo == "" || in.Target.PR <= 0 ||
		!fullSHA.MatchString(in.Target.CandidateSHA) || !fullSHA.MatchString(in.Target.HeadSHA) ||
		!fullSHA.MatchString(in.BaselineSHA) || in.BaselineSHA == in.Target.CandidateSHA ||
		!configDigest.MatchString(in.ReleaseDefaults) || in.Issue <= 0 || len(in.HarnessKeys) == 0 {
		return false
	}
	for id, k := range in.HarnessKeys {
		g := k.Oracle
		if id == "" || len(id) > MaxScalar || ValidHarnessKey(k.Public) != nil || k.Repo == "" ||
			g.ProducerID == "" || g.WorkflowID == "" || g.CheckID == "" {
			return false
		}
	}
	for i := range eff.Paths {
		if si := eff.Paths[i].StackIndex; si < 0 || si >= len(eff.Stacks) {
			return false
		}
	}
	switch in.Kind {
	case KindFeatureDark, KindTask:
		return in.Fix == nil
	case KindFix:
		return in.Fix != nil && validFix(in.Fix, eff, in)
	default:
		return false
	}
}

func validFix(f *FixAuthorization, eff *contract.Effective, in Input) bool {
	if f.ID == "" || f.Repo != in.Target.Repo || f.Issue != in.Issue || len(f.Deltas) > maxDeltas ||
		f.ContractRevision != eff.Revision {
		return false
	}
	for i := range f.Deltas {
		dl := &f.Deltas[i]
		if dl.Case == "" || dl.Boundary == "" || len(dl.Record) > MaxScalar || len(dl.Operation) > MaxScalar || len(dl.Field) > MaxScalar {
			return false
		}
		if _, ok := canon(dl.Before); !ok {
			return false
		}
		if _, ok := canon(dl.After); !ok {
			return false
		}
	}
	return true
}

// loadManifest returns the manifest when the bytes match the contract's pin and validate. Otherwise the oracle
// covers nothing.
func loadManifest(ob *contract.OracleObligation, data []byte) (Manifest, bool) {
	if sha256Hex(data) != ob.Oracle.CaseManifest.SHA256 {
		return Manifest{}, false
	}
	m, err := ValidateManifest(data, ob.Oracle.Observables)
	if err != nil {
		return Manifest{}, false
	}
	return m, true
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// pathCoverage is rule 2: each changed path needs at least one oracle of its stack whose manifest covers it, and the
// covering oracles together must observe all five categories. A protected path blocks. It returns every reason that
// applies, sorted.
func pathCoverage(eff *contract.Effective, byID map[oracleID]*prepared) []Reason {
	missing := len(eff.Uncovered) > 0 || len(eff.Paths) == 0 || len(eff.Oracles) == 0
	incomplete, protected := false, false
	for i := range eff.Paths {
		p := &eff.Paths[i]
		if p.Protected {
			protected = true // protected paths never ride the oracle
		}
		if !p.Covered {
			missing = true
			continue
		}
		var have []contract.Observable
		covered := false
		stack := eff.Stacks[p.StackIndex].Oracles
		for j := range stack {
			prep := byID[idOf(&stack[j].Oracle)]
			if prep == nil || !prep.valid || !prep.manifest.Covers(p.Path) {
				continue
			}
			covered = true
			have = append(have, prep.manifest.Observables()...)
		}
		if !covered {
			missing = true
			continue
		}
		for _, o := range allObservables() {
			if !slices.Contains(have, o) {
				incomplete = true
			}
		}
	}
	var out []Reason // sorted: incomplete, missing, protected
	if incomplete {
		out = append(out, ReasonOracleIncomplete)
	}
	if missing {
		out = append(out, ReasonOracleMissing)
	}
	if protected {
		out = append(out, ReasonProtectedPath)
	}
	return out
}

// gateDecision is rule 3's input: the gate decision for the change's oracle refs, all mandatory. Conflicts are
// copied, so a pin conflict blocks.
func gateDecision(eff *contract.Effective, in Input) gate.Decision {
	synth := &contract.Effective{Revision: eff.Revision, InstallRevision: eff.InstallRevision, Conflicts: eff.Conflicts}
	seen := map[contract.GateRef]bool{}
	for i := range eff.Oracles {
		o := &eff.Oracles[i]
		if seen[o.Oracle.GateRef] {
			continue
		}
		seen[o.Oracle.GateRef] = true
		synth.VerifyGates = append(synth.VerifyGates, contract.Obligation{
			Gate:    contract.Gate{Name: o.Oracle.Name, GateRef: o.Oracle.GateRef, Mandatory: true},
			Owner:   contract.OwnerContract,
			Sources: o.Sources,
		})
	}
	return gate.Evaluate(synth, in.Target, in.Evidence)
}

func failf(r *Result, disp Disposition, reason Reason, format string, args ...any) {
	r.Disposition, r.Reason = disp, reason
	if format != "" && len(r.Evidence) < maxEvidence {
		r.Evidence = append(r.Evidence, esc(fmt.Sprintf(format, args...)))
	}
}

// evaluateOracle runs rules 3 to 10 for one oracle.
func evaluateOracle(p *prepared, d *Decision, in *Input, gd *gate.Decision) Result {
	o := &p.ob.Oracle
	r := Result{Gate: o.GateRef, ManifestSHA256: o.CaseManifest.SHA256, Disposition: Pass}

	// Rule 3: the whole gate decision must pass, so snapshot-wide reasons block.
	var ob *gate.ObligationResult
	for i := range gd.Obligations {
		if gd.Obligations[i].Gate == o.GateRef {
			ob = &gd.Obligations[i]
			break
		}
	}
	if ob != nil {
		r.RunID, r.RunAttempt, r.JobID = ob.RunID, ob.RunAttempt, ob.JobID
	}
	if gd.Disposition != gate.Pass || ob == nil || ob.Disposition != gate.Pass {
		disp := gd.Disposition
		if disp == gate.Pass {
			disp = gate.Blocked
		}
		failf(&r, disp, ReasonOracleNotRun, "gate decision %s", gd.Disposition)
		for _, gr := range gd.Reasons {
			r.Evidence = append(r.Evidence, esc("gate reason "+string(gr)))
		}
		if ob != nil && ob.Reason != gate.ReasonNone {
			r.Evidence = append(r.Evidence, esc("oracle gate "+string(ob.Disposition)+" "+string(ob.Reason)))
		}
		r.Evidence = r.Evidence[:min(len(r.Evidence), maxEvidence)]
		return r
	}

	// Rule 4.
	if !p.valid {
		failf(&r, Error, ReasonManifestInvalid, "manifest does not match its pin or does not validate")
		return r
	}

	// Rule 5.
	rep := bindReport(&r, p, in)
	if rep == nil {
		return r
	}
	r.RequestedBaseline, r.RequestedCandidate = rep.RequestedBaseline, rep.RequestedCandidate
	r.LoadedBaseline, r.LoadedCandidate = rep.LoadedBaseline, rep.LoadedCandidate
	r.SwitchOverrides = sortedOverrides(rep.SwitchOverrides)
	r.Observations = len(rep.Observations)
	for i := range rep.Observations {
		r.Differences += len(rep.Observations[i].Diffs)
	}

	// Rule 6.
	if in.Switches.Verdict != switches.VerdictPass {
		failf(&r, Blocked, ReasonFirstIntroduction, "switch comparison verdict is %q", string(in.Switches.Verdict))
		return r
	}
	for i := range in.Switches.New {
		if in.Switches.New[i].Status != switches.StatusDefaultOff {
			failf(&r, Blocked, ReasonFirstIntroduction, "new switch %s is not default-off", in.Switches.New[i].Key)
			return r
		}
	}
	if !sameOverrides(rep.SwitchOverrides, expectedRaw(in)) {
		failf(&r, Blocked, ReasonFirstIntroduction, "switch overrides are not exactly the new switches, off")
		return r
	}

	// Rule 7.
	switch {
	case rep.RequestedBaseline != in.ReleaseDefaults:
		failf(&r, Blocked, ReasonConfigMismatch, "requested baseline config is not the release defaults")
		return r
	case rep.RequestedCandidate != d.CandidateConfig:
		failf(&r, Blocked, ReasonConfigMismatch, "requested candidate config is not the derived config")
		return r
	case rep.LoadedBaseline != rep.RequestedBaseline:
		failf(&r, Blocked, ReasonConfigMismatch, "loaded baseline config differs from the requested one")
		return r
	case rep.LoadedCandidate != rep.RequestedCandidate:
		failf(&r, Blocked, ReasonConfigMismatch, "loaded candidate config differs from the requested one")
		return r
	}

	// Rule 8.
	if msg := checkCoverage(rep, &p.manifest); msg != "" {
		failf(&r, Blocked, ReasonCoverage, "%s", msg)
		return r
	}

	// Rule 9.
	for i := range rep.Observations {
		ob := &rep.Observations[i]
		equal := ob.Baseline.Digest == ob.Candidate.Digest
		switch {
		case !ob.DiffsComplete:
			failf(&r, Blocked, ReasonReportInconsistent, "case %s boundary %s: differences are incomplete", ob.Case, ob.Boundary)
			return r
		case equal && len(ob.Diffs) > 0:
			failf(&r, Blocked, ReasonReportInconsistent, "case %s boundary %s: equal digests but differences", ob.Case, ob.Boundary)
			return r
		case !equal && len(ob.Diffs) == 0:
			failf(&r, Blocked, ReasonReportInconsistent, "case %s boundary %s: unequal digests but no differences", ob.Case, ob.Boundary)
			return r
		}
	}

	// Rule 10.
	checkDifferences(&r, rep, in, o)
	return r
}

// expectedRaw returns the overrides a first-introduction run must have: each new switch, off.
func expectedRaw(in *Input) map[string]string {
	out := make(map[string]string, len(in.Switches.New))
	for i := range in.Switches.New {
		out[in.Switches.New[i].Key] = "off"
	}
	return out
}

func sameOverrides(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if w, ok := b[k]; !ok || w != v {
			return false
		}
	}
	return true
}

// findOne returns the one artifact of the given name. Otherwise it sets r (report-missing or report-ambiguous).
func findOne(r *Result, arts []Artifact, name string) (Artifact, bool) {
	var found []Artifact
	for _, a := range arts {
		if a.Name == name {
			found = append(found, a)
		}
	}
	switch {
	case len(found) == 0:
		failf(r, Blocked, ReasonReportMissing, "no artifact named %s", name)
	case len(found) > 1:
		failf(r, Blocked, ReasonReportAmbiguous, "%d artifacts named %s", len(found), name)
	default:
		return found[0], true
	}
	return Artifact{}, false
}

// verifySignature checks the harness signature artifact over the report bytes. The key registry is Input.HarnessKeys:
// any step of the oracle job can upload an artifact with the report's name, but only the harness holds a key.
func verifySignature(r *Result, sig Artifact, report []byte, in *Input, oracleKey contract.GateKey) bool {
	if len(sig.Bytes) > maxSignatureSize {
		failf(r, Error, ReasonReportMalformed, "signature is %d bytes, the limit is %d", len(sig.Bytes), maxSignatureSize)
		return false
	}
	if got := sha256Hex(sig.Bytes); !hexSHA256.MatchString(sig.SHA256) || got != sig.SHA256 {
		failf(r, Blocked, ReasonReportUnbound, "signature bytes do not match the artifact digest")
		return false
	}
	tree, err := parseJSON(sig.Bytes, 2)
	var obj map[string]any
	if err == nil {
		obj, err = exactObject(tree, "schema", "keyId", "signature")
	}
	var keyID string
	var raw []byte
	if err == nil {
		if sch, _ := obj["schema"].(string); sch != SignatureSchema {
			err = errors.New("unsupported signature schema")
		} else if keyID, err = str(obj, "keyId"); err == nil {
			var enc string
			if enc, err = str(obj, "signature"); err == nil {
				raw, err = base64.StdEncoding.DecodeString(enc)
			}
		}
	}
	if err != nil {
		failf(r, Error, ReasonReportMalformed, "signature artifact: %v", err)
		return false
	}
	hk, ok := in.HarnessKeys[keyID]
	key := hk.Public
	if !ok || len(key) != ed25519.PublicKeySize || len(raw) != ed25519.SignatureSize {
		failf(r, Blocked, ReasonReportUnsigned, "signature key %s is not registered or the signature is malformed", keyID)
		return false
	}
	// A key signs for the one repo and oracle it was registered for.
	if hk.Repo != in.Target.Repo || hk.Oracle != oracleKey {
		failf(r, Blocked, ReasonReportUnsigned, "key %s is not registered for this repo and oracle", keyID)
		return false
	}
	digest := sha256.Sum256(report)
	if !ed25519.Verify(key, append([]byte(signatureDomain), digest[:]...), raw) {
		failf(r, Blocked, ReasonReportUnsigned, "signature by key %s does not verify", keyID)
		return false
	}
	r.KeyID = keyID
	return true
}

// SignReport returns the signature artifact content for report: the bytes the harness uploads as
// [SignatureArtifactName]. The message is the domain "lightsout.oracle-report/v1\x00" followed by the SHA-256 of the
// report bytes.
func SignReport(keyID string, key ed25519.PrivateKey, report []byte) ([]byte, error) {
	if len(key) != ed25519.PrivateKeySize {
		return nil, errors.New("sign report: private key has the wrong size")
	}
	if keyID == "" || len(keyID) > MaxScalar {
		return nil, fmt.Errorf("sign report: key ID must be 1 to %d bytes", MaxScalar)
	}
	digest := sha256.Sum256(report)
	sig := ed25519.Sign(key, append([]byte(signatureDomain), digest[:]...))
	out, err := json.Marshal(struct {
		Schema    string `json:"schema"`
		KeyID     string `json:"keyId"`
		Signature string `json:"signature"`
	}{SignatureSchema, keyID, base64.StdEncoding.EncodeToString(sig)})
	if err != nil {
		return nil, fmt.Errorf("encode signature: %w", err)
	}
	return out, nil
}

// bindReport is rule 5. It returns the parsed report, or nil after setting r. The report is authenticated before it
// is parsed.
func bindReport(r *Result, p *prepared, in *Input) *parsedReport {
	a, ok := findOne(r, p.input.Artifacts, ReportArtifactName)
	if !ok {
		return nil
	}
	sig, ok := findOne(r, p.input.Artifacts, SignatureArtifactName)
	if !ok {
		return nil
	}
	if len(a.Bytes) > MaxReportSize {
		failf(r, Error, ReasonReportMalformed, "report is %d bytes, the limit is %d", len(a.Bytes), MaxReportSize)
		return nil
	}
	if sum := sha256Hex(a.Bytes); !hexSHA256.MatchString(a.SHA256) || sum != a.SHA256 {
		failf(r, Blocked, ReasonReportUnbound, "report bytes do not match the artifact digest")
		return nil
	}
	r.ReportSHA256 = a.SHA256
	if !verifySignature(r, sig, a.Bytes, in, p.ob.Oracle.Key()) {
		return nil
	}
	rep, err := parseReport(a.Bytes)
	if err != nil {
		failf(r, Error, ReasonReportMalformed, "%v", err)
		return nil
	}
	o := &p.ob.Oracle
	bad := ""
	switch {
	case rep.RunID != r.RunID || rep.RunAttempt != r.RunAttempt || rep.JobID != r.JobID:
		bad = "job"
	case rep.Repo != string(in.Target.Repo):
		bad = "repo"
	case rep.BaselineSHA != in.BaselineSHA:
		bad = "baselineSHA"
	case rep.CandidateSHA != in.Target.CandidateSHA:
		bad = "candidateSHA"
	case rep.OracleRevision != o.WorkflowRevision:
		bad = "oracleRevision"
	case rep.CaseManifest != "sha256:"+o.CaseManifest.SHA256:
		bad = "caseManifest"
	case rep.Comparison != ComparisonExact:
		bad = "comparison"
	}
	if bad != "" {
		failf(r, Blocked, ReasonReportUnbound, "report %s does not match the gate execution or the comparison", bad)
		return nil
	}
	return rep
}

type caseBoundary struct{ c, b string }

// checkCoverage is rule 8. It returns a message for the first failure, or "".
func checkCoverage(rep *parsedReport, m *Manifest) string {
	fixture := make(map[string]string, len(m.Cases))
	for _, c := range m.Cases {
		fixture[c.ID] = c.Fixture
	}
	bounds := make(map[string]bool, len(m.Boundaries))
	for _, b := range m.Boundaries {
		bounds[b.Name] = true
	}
	seen := make(map[caseBoundary]bool, len(rep.Observations))
	for i := range rep.Observations {
		ob := &rep.Observations[i]
		want, ok := fixture[ob.Case]
		if !ok || !bounds[ob.Boundary] {
			return fmt.Sprintf("extra observation: case %s boundary %s", ob.Case, ob.Boundary)
		}
		k := caseBoundary{ob.Case, ob.Boundary}
		if seen[k] {
			return fmt.Sprintf("duplicate observation: case %s boundary %s", ob.Case, ob.Boundary)
		}
		seen[k] = true
		for _, sd := range []struct {
			name string
			s    side
		}{{"baseline", ob.Baseline}, {"candidate", ob.Candidate}} {
			name, s := sd.name, sd.s
			switch {
			case s.Status != StatusCompleted:
				return fmt.Sprintf("case %s boundary %s: %s status is %s", ob.Case, ob.Boundary, name, s.Status)
			case s.Fixture != want:
				return fmt.Sprintf("case %s boundary %s: %s ran another fixture", ob.Case, ob.Boundary, name)
			case !fixturePattern.MatchString(s.Digest):
				return fmt.Sprintf("case %s boundary %s: %s digest is malformed", ob.Case, ob.Boundary, name)
			}
		}
	}
	if len(seen) != len(m.Cases)*len(m.Boundaries) {
		return fmt.Sprintf("%d observations, want %d (one per case and boundary)", len(seen), len(m.Cases)*len(m.Boundaries))
	}
	return ""
}

// deltaKey is a difference or a delta in canonical form, so equal ones compare equal.
type deltaKey struct {
	c, b, rec, op, field, before, after string
}

func keyOfDelta(d *Delta) deltaKey {
	before, _ := canon(d.Before)
	after, _ := canon(d.After)
	return deltaKey{d.Case, d.Boundary, d.Record, d.Operation, d.Field, before, after}
}

func keyOfDifference(c, b string, d *difference) (deltaKey, bool) {
	before, ok1 := canon(d.Before)
	after, ok2 := canon(d.After)
	return deltaKey{c, b, d.Record, d.Operation, d.Field, before, after}, ok1 && ok2
}

// checkDifferences is rule 10.
func checkDifferences(r *Result, rep *parsedReport, in *Input, o *contract.Oracle) {
	if r.Differences == 0 {
		return
	}
	if in.Kind != KindFix {
		failf(r, Blocked, ReasonDifference, "%d differences", r.Differences)
		for i := range rep.Observations {
			ob := &rep.Observations[i]
			for j := range ob.Diffs {
				if len(r.Evidence) < maxEvidence {
					r.Evidence = append(r.Evidence, esc(fmt.Sprintf("case %s boundary %s record %s field %s", ob.Case, ob.Boundary, ob.Diffs[j].Record, ob.Diffs[j].Field)))
				}
			}
		}
		return
	}
	pool := map[deltaKey]int{}
	if in.Fix.Oracle == o.Key() && in.Fix.OracleRevision == o.WorkflowRevision && in.Fix.CaseManifest == o.CaseManifest.SHA256 {
		for i := range in.Fix.Deltas {
			pool[keyOfDelta(&in.Fix.Deltas[i])]++
		}
	}
	unauthorized := 0
	for i := range rep.Observations {
		ob := &rep.Observations[i]
		for j := range ob.Diffs {
			k, ok := keyOfDifference(ob.Case, ob.Boundary, &ob.Diffs[j])
			if ok && pool[k] > 0 {
				pool[k]--
				continue
			}
			unauthorized++
			if len(r.Evidence) < maxEvidence {
				r.Evidence = append(r.Evidence, esc(fmt.Sprintf("unauthorized: case %s boundary %s record %s field %s", ob.Case, ob.Boundary, ob.Diffs[j].Record, ob.Diffs[j].Field)))
			}
		}
	}
	if unauthorized > 0 {
		r.Disposition, r.Reason = Blocked, ReasonUnauthorizedDifference
		r.Evidence = append([]string{fmt.Sprintf("%d of %d differences are not authorized", unauthorized, r.Differences)}, r.Evidence...)
		r.Evidence = r.Evidence[:min(len(r.Evidence), maxEvidence)]
	}
}
