// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

package holdout

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/elliott-davis/lightsout/internal/forge"
)

// Bounds (design: Model).
const (
	MaxFiles        = 1024
	MaxFileBytes    = 4 << 20
	MaxBundleBytes  = 64 << 20
	MaxScenarios    = 256
	MaxPrivateCases = 256 // per scenario
	maxFieldBytes   = 256
	maxReasonBytes  = 2048
	maxIntentBytes  = 128
)

// SuiteID names one suite: one per feature issue (or authorized fix).
type SuiteID struct {
	Repo  forge.RepoID
	Issue int
}

// Revision is "sha256:<hex>" over the canonical encoding of a [Bundle].
type Revision string

// Credential is an opaque proof of workload identity, meaningful only to the [Verifier].
type Credential string

// Role is a workload role. Anything not listed here is denied.
type Role string

// Roles allowed to reach the store.
const (
	RoleQE                  Role = "qe"
	RoleScenarioReviewer    Role = "scenario-reviewer"
	RoleAcceptanceScheduler Role = "acceptance-scheduler"
	RoleAcceptanceRunner    Role = "acceptance-runner"
)

// Workload is a verified workload identity. It comes only from the [Verifier].
type Workload struct {
	Role            Role
	Repo            forge.RepoID
	Principal       string // stable identity of the agent or service
	Session         string // the session or run this credential belongs to
	Assignment      string // the assignment the runner or scheduler was given; required for runners
	TemplateVersion string // agent template version for the audit log (RUN-5)
}

// FileKind says what a private file is for.
type FileKind string

// File kinds.
const (
	KindTest      FileKind = "test"
	KindFixture   FileKind = "fixture"
	KindAssertion FileKind = "assertion"
)

// File is one private file in a bundle.
type File struct {
	Path  string
	Mode  uint32 // 0o644 or 0o755
	Kind  FileKind
	Bytes []byte
}

// Binding binds one public scenario to private executable material.
type Binding struct {
	ScenarioID string
	Layer      string   // test layer, for example go-integration or cypress
	Entry      string   // the private entry-point case ID
	Private    []string // extra private case IDs
}

// FileMeta describes a stored private file without its bytes. The bytes live in an immutable blob keyed by
// revision, so a backend transaction does not copy them.
type FileMeta struct {
	Path   string
	Mode   uint32
	Kind   FileKind
	Size   int
	SHA256 string // lowercase hex of the file bytes
}

// Correction marks a bundle as the correction of a frozen revision (INT-9). It preserves the original failure by
// naming the failed run.
type Correction struct {
	Replaces  Revision
	FailedRun string
	Reason    string
}

// Bundle is the private content of a suite revision. It must never be rendered, logged or sent to an issue.
type Bundle struct {
	Suite          SuiteID
	Parent         Revision // "" for the first revision; otherwise the suite's current head
	IntentRevision string   // the exact ideator-approved scenario revision
	Scenarios      []Binding
	Files          []File
	Correction     *Correction
}

// Status is the state of a revision.
type Status string

// Revision states.
const (
	StatusProposed   Status = "proposed"
	StatusActive     Status = "active"
	StatusRejected   Status = "rejected"
	StatusStale      Status = "stale" // the approved intent moved on (ineligible)
	StatusFrozen     Status = "frozen-after-failure"
	StatusSuperseded Status = "superseded"
)

// usable reports whether runs may use a revision in this state. A frozen revision stays usable: PIP-15 reruns the
// same suite revision across repair attempts.
func (s Status) usable() bool { return s == StatusActive || s == StatusFrozen }

// RunRecord pins everything one Acceptance run is about (INT-7). The scheduler supplies it.
type RunRecord struct {
	RunID              string
	Suite              SuiteID
	SuiteRevision      Revision
	IntentRevision     string
	CandidateSHA       string // 40 or 64 lowercase hex
	ArtifactDigest     string // "sha256:<hex>"
	SwitchConfigDigest string // "sha256:<hex>"
	Assignment         string // the runner assignment for this attempt
}

// Grant is the right to open one suite revision for one attempt of one run.
type Grant struct {
	RunID     string
	Attempt   int
	ExpiresAt time.Time
}

// Outcome is the recorded result of one attempt. It holds public data only.
type Outcome struct {
	Passed          bool
	FailedScenarios []string // public scenario IDs
}

// Verdict is a scenario reviewer's decision.
type Verdict string

// Verdicts.
const (
	VerdictApprove Verdict = "approve"
	VerdictReject  Verdict = "reject"
)

// normalized returns a deep copy of b with scenarios sorted by ID, private case IDs and files sorted.
func (b Bundle) normalized() Bundle {
	n := b
	n.Scenarios = make([]Binding, len(b.Scenarios))
	for i, s := range b.Scenarios {
		s.Private = slices.Sorted(slices.Values(s.Private))
		n.Scenarios[i] = s
	}
	slices.SortFunc(n.Scenarios, func(x, y Binding) int { return compareStr(x.ScenarioID, y.ScenarioID) })
	n.Files = make([]File, len(b.Files))
	for i, f := range b.Files {
		f.Bytes = bytes.Clone(f.Bytes)
		n.Files[i] = f
	}
	slices.SortFunc(n.Files, func(x, y File) int { return compareStr(x.Path, y.Path) })
	if b.Correction != nil {
		c := *b.Correction
		n.Correction = &c
	}
	return n
}

func compareStr(a, b string) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

const canonicalMagic = "lightsout-holdout-bundle-v1"

// Canonical returns the canonical encoding that [Bundle.Revision] hashes. Scenarios are ordered by ID and files
// by path, so the order the caller listed them in does not matter. Every variable-length field is written as an
// unsigned varint length followed by its bytes, and every list is preceded by its element count, so no two
// different bundles share an encoding. The layout is: magic, repo, issue, parent, intent revision, scenarios (ID,
// layer, entry, private case IDs), files (path, mode, kind, bytes), then a presence byte and the correction (replaces,
// failed run, reason).
func (b Bundle) Canonical() []byte {
	n := b.normalized()
	var buf bytes.Buffer
	str := func(s string) {
		buf.Write(binary.AppendUvarint(nil, uint64(len(s))))
		buf.WriteString(s)
	}
	num := func(v uint64) { buf.Write(binary.AppendUvarint(nil, v)) }
	str(canonicalMagic)
	str(string(n.Suite.Repo))
	num(uint64(max(n.Suite.Issue, 0)))
	str(string(n.Parent))
	str(n.IntentRevision)
	num(uint64(len(n.Scenarios)))
	for _, s := range n.Scenarios {
		str(s.ScenarioID)
		str(s.Layer)
		str(s.Entry)
		num(uint64(len(s.Private)))
		for _, p := range s.Private {
			str(p)
		}
	}
	num(uint64(len(n.Files)))
	for _, f := range n.Files {
		str(f.Path)
		num(uint64(f.Mode))
		str(string(f.Kind))
		str(string(f.Bytes))
	}
	if c := n.Correction; c != nil {
		num(1)
		str(string(c.Replaces))
		str(c.FailedRun)
		str(c.Reason)
	} else {
		num(0)
	}
	return buf.Bytes()
}

// Revision returns the content address of b. The same bundle always gives the same revision, and any change to a
// byte of any field gives a different one.
func (b Bundle) Revision() Revision {
	sum := sha256.Sum256(b.Canonical())
	return Revision("sha256:" + hex.EncodeToString(sum[:]))
}

// ScenarioIDs returns the bound public scenario IDs in order.
func (b Bundle) ScenarioIDs() []string {
	ids := make([]string, 0, len(b.Scenarios))
	for _, s := range b.Scenarios {
		ids = append(ids, s.ScenarioID)
	}
	slices.Sort(ids)
	return ids
}

func (id SuiteID) valid() bool { return id.Repo != "" && id.Issue > 0 && len(id.Repo) <= maxFieldBytes }

// Assignment is the canonical assignment string WI-30 issues to the QE and scenario reviewer sessions that work on
// this suite. Repo scope alone is not enough for them (INT-6).
func (id SuiteID) Assignment() string {
	return "suite:" + string(id.Repo) + "#" + strconv.Itoa(id.Issue)
}

func (id SuiteID) String() string { return string(id.Repo) + "#" + strconv.Itoa(id.Issue) }

// validToken accepts a short identifier of ASCII letters, digits and . _ - (first byte alphanumeric).
func validToken(s string, limit int) bool {
	if s == "" || len(s) > limit {
		return false
	}
	for i := range len(s) {
		c := s[i]
		alnum := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
		if !alnum && (i == 0 || (c != '.' && c != '_' && c != '-')) {
			return false
		}
	}
	return true
}

func validText(s string, limit int) bool {
	if s == "" || len(s) > limit || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

func validDigest(s, prefix string) bool {
	h, ok := strings.CutPrefix(s, prefix)
	return ok && validHex(h, 64)
}

func validHex(s string, n ...int) bool {
	if len(n) > 0 && !slices.Contains(n, len(s)) {
		return false
	}
	if s == "" {
		return false
	}
	for i := range len(s) {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func validRevision(r Revision) bool { return validDigest(string(r), "sha256:") }

// validate checks a normalized bundle. Errors name fields, never private content.
func (b Bundle) validate() error {
	if !b.Suite.valid() {
		return invalidf("suite")
	}
	if b.Parent != "" && !validRevision(b.Parent) {
		return invalidf("parent")
	}
	if !validText(b.IntentRevision, maxIntentBytes) {
		return invalidf("intent revision")
	}
	if err := b.validateScenarios(); err != nil {
		return err
	}
	if err := b.validateFiles(); err != nil {
		return err
	}
	return b.validateCorrection()
}

func (b Bundle) validateScenarios() error {
	if len(b.Scenarios) == 0 || len(b.Scenarios) > MaxScenarios {
		return invalidf("scenario count must be 1..%d", MaxScenarios)
	}
	scenarios := map[string]bool{}
	cases := map[string]bool{}
	for i, s := range b.Scenarios {
		if !validToken(s.ScenarioID, 64) || scenarios[s.ScenarioID] {
			return invalidf("scenario %d: bad or duplicate id", i)
		}
		scenarios[s.ScenarioID] = true
		if !validToken(s.Layer, 32) {
			return invalidf("scenario %d: layer", i)
		}
		if len(s.Private) > MaxPrivateCases {
			return invalidf("scenario %d: too many private cases", i)
		}
		for _, c := range append([]string{s.Entry}, s.Private...) {
			if !validToken(c, maxFieldBytes) || cases[c] {
				return invalidf("scenario %d: bad or duplicate case id", i)
			}
			cases[c] = true
		}
	}
	return nil
}

func (b Bundle) validateFiles() error {
	if len(b.Files) > MaxFiles {
		return invalidf("more than %d files", MaxFiles)
	}
	total := 0
	paths := make([]string, 0, len(b.Files))
	for i := range b.Files {
		f := &b.Files[i]
		if err := validFilePath(f.Path); err != nil {
			return invalidf("file %d: bad path", i)
		}
		paths = append(paths, f.Path)
		switch f.Kind {
		case KindTest:
			if f.Mode != 0o644 && f.Mode != 0o755 { // only tests may be executable
				return invalidf("file %d: mode", i)
			}
		case KindFixture, KindAssertion:
			if f.Mode != 0o644 {
				return invalidf("file %d: mode", i)
			}
		default:
			return invalidf("file %d: kind", i)
		}
		if len(f.Bytes) > MaxFileBytes {
			return invalidf("file %d: larger than %d bytes", i, MaxFileBytes)
		}
		total += len(f.Bytes)
		if total > MaxBundleBytes {
			return invalidf("bundle larger than %d bytes", MaxBundleBytes)
		}
	}
	return checkPathCollisions(paths)
}

func (b Bundle) validateCorrection() error {
	c := b.Correction
	if c == nil {
		return nil
	}
	switch {
	case !validRevision(c.Replaces):
		return invalidf("correction: replaces")
	case !validToken(c.FailedRun, maxFieldBytes):
		return invalidf("correction: failed run")
	case !validText(c.Reason, maxReasonBytes):
		return invalidf("correction: reason")
	case b.Parent != c.Replaces:
		return invalidf("correction: must replace the parent")
	}
	return nil
}

func (r RunRecord) validate() error {
	switch {
	case !validToken(r.RunID, maxFieldBytes):
		return invalidf("run id")
	case !r.Suite.valid():
		return invalidf("suite")
	case !validRevision(r.SuiteRevision):
		return invalidf("suite revision")
	case !validText(r.IntentRevision, maxIntentBytes):
		return invalidf("intent revision")
	case !validHex(r.CandidateSHA, 40, 64):
		return invalidf("candidate sha")
	case !validDigest(r.ArtifactDigest, "sha256:"):
		return invalidf("artifact digest")
	case !validDigest(r.SwitchConfigDigest, "sha256:"):
		return invalidf("switch config digest")
	case !validText(r.Assignment, maxFieldBytes):
		return invalidf("assignment")
	}
	return nil
}

// samePin reports whether two run records pin the same inputs (the assignment may differ between attempts).
func (r RunRecord) samePin(o RunRecord) bool {
	r.Assignment, o.Assignment = "", ""
	return r == o
}
