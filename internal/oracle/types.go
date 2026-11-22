// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

package oracle

import (
	"crypto/ed25519"

	"github.com/elliott-davis/lightsout/internal/contract"
	"github.com/elliott-davis/lightsout/internal/forge"
	"github.com/elliott-davis/lightsout/internal/gate"
	"github.com/elliott-davis/lightsout/internal/switches"
)

// Limits. They bound untrusted input and the work done on it.
const (
	// MaxReportSize is the largest accepted report in bytes. A complete report for the largest manifest fits.
	MaxReportSize = 8 << 20
	// MaxManifestSize is the largest accepted case manifest in bytes.
	MaxManifestSize = 1 << 20
	// MaxCases, MaxBoundaries and MaxMatrix bound a manifest: cases, boundaries, and cases times boundaries.
	MaxCases      = 4096
	MaxBoundaries = 64
	MaxMatrix     = 4096
	// MaxCovers is the most coverage globs in a manifest.
	MaxCovers = 256
	// MaxScalar is the largest scalar (a string or the text of a number) in a report difference or a delta.
	MaxScalar = 1024
	// maxDifferences bounds the differences of one observation, and maxTotalDifferences those of a whole report.
	maxDifferences      = 1024
	maxTotalDifferences = 16384
	// maxOverrides bounds the keys of an object in a report; only switchOverrides can have more than a handful.
	maxOverrides = 256
	// maxSignatureSize bounds the signature artifact.
	maxSignatureSize = 4 << 10
	// maxValues bounds the JSON values of a report, so the parser's memory is bounded by construction. One
	// observation is 13 values (the object, case, boundary, baseline and candidate with 3 fields each,
	// differencesComplete, and the differences array); one difference is 6 (the object and 5 fields); the fixed part
	// is 277 (the root, 7 strings, job with 3 fields, switchOverrides with at most 256 entries, configs with 2
	// objects of 2 fields, and the observations array). An array longer than MaxMatrix is rejected while parsing.
	maxValues = 13*MaxMatrix + 6*maxTotalDifferences + 277
	// maxEvidence bounds the evidence lines in one result.
	maxEvidence = 16
	// maxDeltas bounds a fix authorization.
	maxDeltas = 65536
	// maxReportDepth is the deepest nesting of a report.
	maxReportDepth = 8
	// escapeLimit bounds one escaped string from a report or manifest.
	escapeLimit = 200
)

// Names fixed by the report and manifest schemas.
const (
	// ReportArtifactName is the name of the report among the oracle job's artifacts.
	ReportArtifactName = "lightsout-oracle-report"
	// ReportSchema is the schema field of a report.
	ReportSchema = "lightsout.oracle/v1"
	// ManifestSchema is the schema field of a case manifest.
	ManifestSchema = "lightsout.oracle-cases/v1"
	// ComparisonExact is the only comparison v1 supports: exact equality, no ignore rules or tolerances.
	ComparisonExact = "exact/v1"
	// SignatureArtifactName is the name of the harness signature over the report among the oracle job's artifacts.
	SignatureArtifactName = "lightsout-oracle-report.sig"
	// SignatureSchema is the schema field of a signature artifact.
	SignatureSchema = "lightsout.oracle-sig/v1"
	// signatureDomain prefixes the signed message: domain, a NUL byte, then SHA-256 of the report bytes.
	signatureDomain = "lightsout.oracle-report/v1\x00"
	// StatusCompleted is the only observation status that counts.
	StatusCompleted = "completed"
)

// Kind is the work kind, from the issue type (INT-3).
type Kind string

// Work kinds.
const (
	KindFeatureDark Kind = "feature-dark"
	KindTask        Kind = "task"
	KindFix         Kind = "fix"
)

// Disposition is the outcome of an oracle or of the whole change. It is the gate package's type and ordering:
// error over blocked over pending over pass.
type Disposition = gate.Disposition

// Dispositions.
const (
	Pass    = gate.Pass
	Pending = gate.Pending
	Blocked = gate.Blocked
	Error   = gate.Error
)

// Reason says why an oracle, or the change, did not pass.
type Reason string

// Reasons. ReasonNone is the reason of a pass.
const (
	ReasonNone Reason = ""
	// ReasonInvalidInput: the input is malformed, so nothing can be said. A change-level reason.
	ReasonInvalidInput Reason = "invalid-input"
	// ReasonOracleMissing: a changed path has no oracle whose manifest covers it, or no oracle exists. Change-level.
	ReasonOracleMissing Reason = "oracle-missing"
	// ReasonOracleIncomplete: the oracles covering a changed path do not together observe all five categories.
	// Change-level.
	ReasonOracleIncomplete Reason = "oracle-incomplete"
	// ReasonOracleNotRun: the oracle gate is not a pass, or the gate decision is not a pass as a whole.
	ReasonOracleNotRun Reason = "oracle-not-run"
	// ReasonManifestInvalid: the manifest bytes do not match the contract's pin or do not validate.
	ReasonManifestInvalid Reason = "manifest-invalid"
	// ReasonReportMissing: the oracle job's run attempt has no report artifact.
	ReasonReportMissing Reason = "report-missing"
	// ReasonReportAmbiguous: the run attempt has more than one artifact with the report's name.
	ReasonReportAmbiguous Reason = "report-ambiguous"
	// ReasonReportUnbound: the report does not match its artifact digest, the gate execution or this comparison.
	ReasonReportUnbound Reason = "report-unbound"
	// ReasonReportUnsigned: the signature is by a key the install did not register, or does not verify.
	ReasonReportUnsigned Reason = "report-unsigned"
	// ReasonProtectedPath: a changed path is protected. Protected paths never ride the oracle. Change-level.
	ReasonProtectedPath Reason = "protected-path"
	// ReasonReportMalformed: the report is oversized or fails strict parsing.
	ReasonReportMalformed Reason = "report-malformed"
	// ReasonFirstIntroduction: a switch change is not a pass, or the overrides are not exactly the new switches, off.
	ReasonFirstIntroduction Reason = "first-introduction"
	// ReasonConfigMismatch: requested or loaded configs are not the expected ones.
	ReasonConfigMismatch Reason = "config-mismatch"
	// ReasonCoverage: an observation is missing, duplicated, extra, not completed or ran another fixture.
	ReasonCoverage Reason = "coverage"
	// ReasonReportInconsistent: the digests and the difference lists disagree, or the lists are incomplete.
	ReasonReportInconsistent Reason = "report-inconsistent"
	// ReasonDifference: a feature-dark or task change differs from the baseline.
	ReasonDifference Reason = "difference"
	// ReasonUnauthorizedDifference: a fix differs in a way no distinct delta authorizes.
	ReasonUnauthorizedDifference Reason = "unauthorized-difference"
)

// Artifact is one artifact of the oracle job's run attempt, as the forge lists it. SHA256 is the forge's digest of
// the artifact (lowercase hex). Bytes is the content the caller fetched.
type Artifact struct {
	Name   string
	SHA256 string
	Bytes  []byte
}

// Report is what the caller fetched for one oracle: the case manifest read at Effective.Revision, and every
// artifact of the oracle job's run attempt.
type Report struct {
	Manifest  []byte
	Artifacts []Artifact
}

// Delta authorizes exactly one difference. Before and After are JSON scalars: nil, bool, string or json.Number.
type Delta struct {
	Case, Boundary, Record, Operation, Field string
	Before, After                            any
}

// FixAuthorization is the authorized delta of a fix (INT-17), produced and authz-bound by WI-22.
//
// An authorization is bound to the contract revision, oracle revision and case manifest it was approved for, so it
// cannot be replayed after the oracle is re-pinned or the cases change.
type FixAuthorization struct {
	ID    string
	Repo  forge.RepoID
	Issue int
	// ContractRevision must equal the Effective's Revision, otherwise the input is invalid.
	ContractRevision string
	// Oracle, OracleRevision and CaseManifest (the manifest's hex SHA-256) name the oracle the deltas are for. A
	// difference of any other oracle, revision or manifest is not authorized (INT-10).
	Oracle         contract.GateKey
	OracleRevision string
	CaseManifest   string
	Deltas         []Delta
}

// HarnessKey is a registered harness public key (WI-12). It signs for one repo and one oracle only.
type HarnessKey struct {
	Public ed25519.PublicKey
	Repo   forge.RepoID
	Oracle contract.GateKey
}

// Input is everything Evaluate needs besides the effective contract.
type Input struct {
	// Target and Evidence are the job executions at the candidate, as for [gate.Evaluate].
	Target   gate.Target
	Evidence gate.Evidence
	// BaselineSHA is the previous queue member's candidate, or the group base for the first member (WI-18).
	BaselineSHA string
	Kind        Kind
	// Issue is the issue number the change implements.
	Issue int
	// Fix is required for KindFix and forbidden otherwise.
	Fix *FixAuthorization
	// ReleaseDefaults is the release-defaults config digest, "sha256:<64 hex>".
	ReleaseDefaults string
	// HarnessKeys are the registered harness keys by key ID (WI-12). A key counts only for its Repo and Oracle, and
	// must pass [ValidHarnessKey]. The harness signs each report, so a
	// report any other step of the run uploaded never verifies. The harness key must never enter either sandbox or
	// any step of the oracle job that runs candidate code. Empty is invalid input.
	HarnessKeys map[string]HarnessKey
	// Switches compares the switch sets Detect read at BaselineSHA and at the candidate.
	Switches switches.Comparison
	// Reports holds the manifest and artifacts of each oracle, by GateRef.
	Reports map[contract.GateRef]Report
}

// Override is one switch override of a first-introduction run.
type Override struct{ Key, Value string }

// Result is the verdict for one oracle obligation.
//
// Escaping. Evidence lines are already escaped for control characters, bidi overrides and ANSI sequences, but NOT
// for Markdown (mentions, links, HTML): a renderer must show them in a code span or block. Every other string field
// is raw, because it is a binding that callers compare and store; a field that came from the report (the configs and
// SwitchOverrides) is untrusted text, and a renderer must escape it (for example with yamlsafe.Escape) before display.
type Result struct {
	Gate        contract.GateRef
	Disposition Disposition
	// Reason is empty on a pass.
	Reason Reason
	// Evidence holds escaped detail lines, at most 16.
	Evidence []string
	// RunID, RunAttempt and JobID identify the gate execution, from the gate decision.
	RunID, RunAttempt, JobID string
	// ManifestSHA256 is the pinned manifest digest, hex.
	ManifestSHA256 string
	// ReportSHA256 is the digest of the report artifact, hex. It is set once the artifact matched its bytes.
	ReportSHA256 string
	// KeyID is the harness key that signed the report, set once the signature verified.
	KeyID string
	// Observations is the number of observations in the report, and Differences the number of differences.
	Observations, Differences int
	// RequestedBaseline, RequestedCandidate, LoadedBaseline and LoadedCandidate are the config digests the report
	// states. SwitchOverrides are the report's overrides, sorted by key.
	RequestedBaseline, RequestedCandidate string
	LoadedBaseline, LoadedCandidate       string
	SwitchOverrides                       []Override
}

// Decision is the result of [Evaluate]. It binds to the repo, PR and head, both SHAs, the config digests, the
// policy and install revisions, the work kind, the issue, the authorization and the manifest digests.
//
// Escaping: see [Result]. The binding fields here are raw values from the caller, except that nothing in Decision
// comes from a report.
type Decision struct {
	gate.Target
	BaselineSHA     string
	PolicyRevision  string
	InstallRevision string
	Kind            Kind
	Issue           int
	// AuthorizationID is the fix authorization's ID, empty without one.
	AuthorizationID string
	// ReleaseDefaults is the baseline config digest, and CandidateConfig the candidate's expected one:
	// [DeriveConfig] of ReleaseDefaults and the new switches, off.
	ReleaseDefaults string
	CandidateConfig string
	// ExpectedOverrides are the new switches, each "off", sorted by key.
	ExpectedOverrides []Override
	Disposition       Disposition
	// Reasons are change-level reasons, sorted: invalid-input, oracle-missing, oracle-incomplete and protected-path.
	Reasons []Reason
	// Oracles are the oracle obligations in the contract's order.
	Oracles []Result
}
