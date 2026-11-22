// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

package review

import (
	"bytes"
	"cmp"
	"crypto/ed25519"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/elliott-davis/lightsout/internal/audit"
	"github.com/elliott-davis/lightsout/internal/authz"
	"github.com/elliott-davis/lightsout/internal/contract"
	"github.com/elliott-davis/lightsout/internal/forge"
	"github.com/elliott-davis/lightsout/internal/gate"
	"github.com/elliott-davis/lightsout/internal/pathglob"
)

var (
	fullSHA     = regexp.MustCompile(`^([0-9a-f]{40}|[0-9a-f]{64})$`)
	sha256Digit = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	claimIDForm = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)
)

// Size caps. A snapshot over a cap is invalid input, so a flood of records can't make Evaluate do unbounded work.
const (
	maxRecords = 10000 // per kind of snapshot list, and per list inside a record
	maxClaims  = 100   // claims in one attestation
	maxItems   = 10000 // items in one manifest
)

// allowedKind reports whether kind is reviewer context (AGT-3). The set is closed: coder-reasoning, transcript,
// private-holdout and every unknown kind are forbidden.
func allowedKind(kind string) bool {
	switch kind {
	case KindSpec, KindDiff, KindRepoFile, KindCaller, KindContract, KindHistory, KindPublicTest:
		return true
	}
	return false
}

// Evaluate decides whether the reviews of t are complete. It is pure and deterministic and modifies none of its
// inputs. now is the injected clock: it times out claims, and it bounds how far in the future a signed record may be
// dated.
//
// It fails closed. Each of these gives Error with [ReasonInvalidInput]:
//   - a nil eff, an empty revision or install revision, a bad target, a zero config or a zero now
//   - no keys, no reviewers, or a PR reviewer or security reviewer that is missing, the same role or not required
//   - SecuritySignoffRequired and SensitivePaths that disagree
//   - a snapshot with no changed paths, one that effective doesn't cover, an invalid changed path, round or
//     approval, or one over a size cap
//   - a key of no kind
//   - a lights-on change whose approval data or owner areas are incomplete
//   - invalid UTF-8 in a string that is signed or digested
//
// A snapshot that is not Complete gives Error with [ReasonIncompleteEvidence], even when every visible verdict
// approves. A record whose signature verifies under a trusted key but that doesn't fit the snapshot gives Error with
// [ReasonInconsistentEvidence]: a signed record is never silently dropped (see [evaluator.admit]).
func Evaluate(eff *contract.Effective, t Target, s Snapshot, cfg Config, keys Keys, now time.Time) Decision {
	d := Decision{Target: t, StateVersion: s.StateVersion, Disposition: Error}
	if eff != nil {
		d.PolicyRevision, d.InstallRevision = eff.Revision, eff.InstallRevision
	}
	if !validStatic(eff, t, cfg, keys, now) {
		d.Reasons = []Reason{ReasonInvalidInput}
		return d
	}
	if !s.Complete {
		d.Reasons = []Reason{ReasonIncompleteEvidence}
		return d
	}
	e := &evaluator{eff: eff, t: t, s: s, cfg: cfg, keys: keys, now: now}
	if !e.index() {
		d.Reasons = []Reason{ReasonInvalidInput}
		return d
	}
	e.verifyAttestations()
	e.verifyResolutions()
	if e.inconsistent {
		// A record signed by a trusted key that doesn't fit the snapshot: the writer dropped or altered the context
		// it signs for. Nothing can be said about the change.
		d.Reasons = []Reason{ReasonInconsistentEvidence}
		d.Rejected = e.sortedRejections()
		return d
	}
	return e.decide(d)
}

func validSHA(s string) bool { return fullSHA.MatchString(s) }

// utf8s reports whether every string is valid UTF-8. JSON encoding would replace an invalid byte with U+FFFD, so two
// different strings could sign or digest the same.
func utf8s(ss ...string) bool {
	for _, s := range ss {
		if !utf8.ValidString(s) {
			return false
		}
	}
	return true
}

func validStatic(eff *contract.Effective, t Target, cfg Config, keys Keys, now time.Time) bool {
	if eff == nil || eff.Revision == "" || eff.InstallRevision == "" || now.IsZero() {
		return false
	}
	if !utf8s(eff.Revision, eff.InstallRevision, t.Forge, string(t.Repo), cfg.SizeGateID, cfg.PRReviewer, eff.SecurityReviewer) {
		return false
	}
	if t.Forge == "" || t.Repo == "" || t.PR <= 0 || !validSHA(t.HeadSHA) {
		return false
	}
	if cfg.ReviewRounds <= 0 || cfg.VerifyAttempts <= 0 || cfg.VerifyTimeout <= 0 || cfg.SizeGateID == "" {
		return false
	}
	for _, k := range keys {
		if k.Kind != KeyReviewer && k.Kind != KeyVerifier && k.Kind != KeyCoder {
			return false
		}
	}
	if len(keys) == 0 || len(eff.Reviewers) == 0 || len(eff.Reviewers) > maxRecords || len(eff.SensitivePaths) > maxRecords {
		return false
	}
	// The effective contract doesn't name the PR reviewer, so the install config does (Baseline.PRReviewer).
	roles := requiredRoles(eff)
	if slices.Contains(roles, "") || cfg.PRReviewer == "" || eff.SecurityReviewer == "" || cfg.PRReviewer == eff.SecurityReviewer {
		return false
	}
	if !slices.Contains(roles, cfg.PRReviewer) || !slices.Contains(roles, eff.SecurityReviewer) {
		return false
	}
	for _, r := range roles {
		if !utf8s(r) {
			return false
		}
	}
	if eff.SecuritySignoffRequired != (len(eff.SensitivePaths) > 0) {
		return false
	}
	for _, p := range eff.SensitivePaths {
		if pathglob.ValidatePath(p) != nil {
			return false
		}
	}
	return true
}

// requiredRoles returns the distinct required reviewer roles, sorted.
func requiredRoles(eff *contract.Effective) []string {
	roles := make([]string, 0, len(eff.Reviewers))
	for _, r := range eff.Reviewers {
		roles = append(roles, r.Role)
	}
	slices.Sort(roles)
	return slices.Compact(roles)
}

// verdictRec is a valid attestation with its assignment and the sequence of its round.
type verdictRec struct {
	Attestation
	As  Assignment
	Seq int
	// Invalid is why the verdict is invalid, or "". An invalid verdict never approves.
	Invalid Reason
}

// claimKey names a claim instance: role, ID and content digest.
type claimKey = ClaimRef

// claimInfo is everything known about one claim instance across rounds.
type claimInfo struct {
	first    time.Time // the first-seen attestation's At
	firstSeq int       // and its round's Seq
	firstID  string    // and its assignment, to break ties
	sessions map[string]bool
	atts     []string
}

type evaluator struct {
	eff  *contract.Effective
	t    Target
	s    Snapshot
	cfg  Config
	keys Keys
	now  time.Time

	asg          map[string]Assignment
	ambiguous    map[string]bool
	rounds       map[string]Round
	coders       map[string]bool
	rejected     []Rejection
	inconsistent bool // a key-verified record doesn't fit the snapshot

	atts   []*verdictRec // valid verdicts
	bad    []*verdictRec // admitted verdicts that are invalid, which still count against their role
	claims map[claimKey]*claimInfo
	res    map[claimKey][]*Resolution // valid resolutions, ascending
}

func (e *evaluator) reject(kind RecordKind, id string, r Reason) {
	e.rejected = append(e.rejected, Rejection{kind, id, r})
}

func (e *evaluator) sortedRejections() []Rejection {
	out := slices.Clone(e.rejected)
	slices.SortFunc(out, func(a, b Rejection) int {
		return cmp.Or(cmp.Compare(a.Kind, b.Kind), cmp.Compare(a.ID, b.ID), cmp.Compare(a.Reason, b.Reason))
	})
	return slices.Compact(out)
}

// validChanged reports whether a changed path is well formed: a known status, a valid path, and an old path exactly
// when the status is a rename or a copy.
func validChanged(c ChangedPath) bool {
	if !utf8s(c.Path, c.OldPath) || pathglob.ValidatePath(c.Path) != nil {
		return false
	}
	switch c.Status {
	case forge.FileRenamed, forge.FileCopied:
		return pathglob.ValidatePath(c.OldPath) == nil
	case forge.FileAdded, forge.FileModified, forge.FileRemoved, forge.FileModeChanged:
		return c.OldPath == ""
	case forge.FileStatusUnknown:
		return false
	}
	return false
}

// index builds the lookups and checks the snapshot's own structure. It returns false for invalid input.
func (e *evaluator) index() bool {
	s := &e.s
	if len(s.Assignments) > maxRecords || len(s.Attestations) > maxRecords || len(s.Resolutions) > maxRecords ||
		len(s.Rounds) > maxRecords || len(s.Manifests) > maxRecords || len(s.CoderSessions) > maxRecords ||
		len(s.ChangedPaths) > maxRecords || len(s.OwnerAreas) > maxRecords {
		return false
	}
	for i := range s.Attestations {
		a := &s.Attestations[i]
		if len(a.Claims) > maxClaims || len(a.SensitiveSignoff) > maxRecords || len(a.Repaired) > maxRecords {
			return false
		}
	}
	for _, m := range s.Manifests {
		if len(m.Items) > maxItems {
			return false
		}
	}
	if !e.indexRounds() {
		return false
	}
	e.coders = map[string]bool{}
	for _, c := range s.CoderSessions {
		if !utf8s(c) {
			return false
		}
		e.coders[c] = true
	}
	e.asg, e.ambiguous = map[string]Assignment{}, map[string]bool{}
	for i := range s.Assignments {
		a := s.Assignments[i] // Assignment is comparable
		if a.ID == "" || !utf8s(a.ID, a.Forge, string(a.Repo), a.HeadSHA, a.RoundID, a.Role, a.Profile, a.ManifestDigest,
			string(a.Purpose), a.ClaimRef.Role, a.ClaimRef.ID, a.ClaimRef.Digest, a.Session) {
			e.reject(RecordAssignment, a.ID, ReasonBadAssignment)
			continue
		}
		if old, ok := e.asg[a.ID]; ok && old != a {
			e.ambiguous[a.ID] = true
			e.reject(RecordAssignment, a.ID, ReasonDuplicateAssignment)
			continue
		}
		e.asg[a.ID] = a
	}
	seen := map[string]bool{}
	covered := map[string]bool{}
	for i := range e.eff.Paths {
		covered[e.eff.Paths[i].Path] = true
	}
	for _, c := range s.ChangedPaths {
		if !validChanged(c) || seen[c.Path] || !covered[c.Path] || (c.OldPath != "" && !covered[c.OldPath]) {
			return false // effective must cover old paths too, or the contract of a path left behind is never asked
		}
		seen[c.Path] = true
	}
	return len(s.ChangedPaths) > 0 && e.lightsOnInputOK()
}

func (e *evaluator) indexRounds() bool {
	e.rounds = map[string]Round{}
	seqs := map[int]string{}
	for _, r := range e.s.Rounds {
		if r.ID == "" || r.Seq <= 0 || !validSHA(r.HeadSHA) || len(r.Roles) > maxRecords || slices.Contains(r.Roles, "") ||
			!utf8s(append([]string{r.ID}, r.Roles...)...) {
			return false
		}
		if r.State != RoundDispatched && r.State != RoundCompleted && r.State != RoundSuperseded {
			return false
		}
		r.Roles = sortedUnique(r.Roles)
		if old, ok := e.rounds[r.ID]; ok && (old.Seq != r.Seq || old.HeadSHA != r.HeadSHA || old.State != r.State || !slices.Equal(old.Roles, r.Roles)) {
			return false // the same round ID with different content is ambiguous
		}
		if id, ok := seqs[r.Seq]; ok && id != r.ID {
			return false // two rounds can't share a sequence number
		}
		seqs[r.Seq] = r.ID
		e.rounds[r.ID] = r
	}
	return true
}

func (e *evaluator) lightsOn() bool { return e.eff.LightsOn || e.s.NonSwitchable != nil }

// approval returns the approval data: the non-switchable declaration if there is one, else the lights-on data.
func (e *evaluator) approval() *Approval {
	if e.s.NonSwitchable != nil {
		return e.s.NonSwitchable
	}
	return e.s.LightsOn
}

func (a *Approval) equal(b *Approval) bool {
	return a.Generation == b.Generation && a.ImpactRevision == b.ImpactRevision && a.RecoveryRevision == b.RecoveryRevision &&
		slices.Equal(sortedUnique(a.Callers), sortedUnique(b.Callers)) && slices.Equal(a.RolloutOrder, b.RolloutOrder)
}

// lightsOnInputOK checks the approval data and that the owner areas partition every changed path, old paths of
// renames and copies included, exactly.
func (e *evaluator) lightsOnInputOK() bool {
	if !e.lightsOn() {
		return true
	}
	a := e.approval()
	if a == nil || a.Generation < 0 || !sha256Digit.MatchString(a.ImpactRevision) || !sha256Digit.MatchString(a.RecoveryRevision) {
		return false
	}
	if e.s.NonSwitchable != nil && e.s.LightsOn != nil && !e.s.NonSwitchable.equal(e.s.LightsOn) {
		return false // two declarations of the approval data that disagree
	}
	if len(sortedUnique(a.Callers)) != len(a.Callers) {
		return false // a caller listed twice
	}
	if len(a.Callers) > maxRecords || len(a.RolloutOrder) > maxRecords || !utf8s(append(slices.Clone(a.Callers), a.RolloutOrder...)...) {
		return false
	}
	universe := map[string]bool{}
	for _, c := range e.s.ChangedPaths {
		universe[c.Path] = true
		if c.OldPath != "" {
			universe[c.OldPath] = true
		}
	}
	seen := map[string]bool{}
	for _, area := range e.s.OwnerAreas {
		if len(area) == 0 {
			return false
		}
		for _, p := range area {
			if !universe[p] || seen[p] {
				return false // not a changed path, or in two areas (or twice in one)
			}
			seen[p] = true
		}
	}
	return len(seen) == len(universe)
}

// verified checks only the signature. It returns the key that made it.
func (e *evaluator) verified(payload []byte, keyID string, sig []byte) (Key, bool) {
	k, ok := e.keys[keyID]
	if !ok || len(k.Pub) != ed25519.PublicKeySize || len(sig) != ed25519.SignatureSize || !ed25519.Verify(k.Pub, payload, sig) {
		return Key{}, false
	}
	return k, true
}

// clockSkew is how far past now a record's timestamp may be.
const clockSkew = 5 * time.Minute

// admit applies the rule that a signed record is never silently dropped. The writer that builds the snapshot is
// untrusted, so every way it could make a key-verified record vanish is an error:
//   - A record signed by a coder's key is rejected outright. It can't force an error.
//   - A record with invalid UTF-8, a timestamp after now plus five minutes, an unknown or ambiguous assignment, a
//     signed assignment digest, key session or key kind that doesn't match the assignment, a target for another
//     forge, repo or PR, or a round that the snapshot lists differently, makes the evidence inconsistent.
//
// It returns true when the record may go on to its own checks. Deleting a record or corrupting
// its signature is out of scope: that is for WI-10's audited store to prove complete.
func (e *evaluator) admit(kind RecordKind, payload []byte, keyID string, sig []byte, id, signedDigest string, at time.Time, stringsOK bool) bool {
	key, ok := e.verified(payload, keyID, sig)
	if !ok {
		e.reject(kind, id, ReasonBadSignature)
		return false
	}
	if key.Kind == KeyCoder {
		e.reject(kind, id, ReasonCoderSession)
		return false
	}
	inconsistent := func(r Reason) bool {
		e.inconsistent = true
		e.reject(kind, id, r)
		return false
	}
	if e.coders[key.Session] {
		// CoderSessions comes from the snapshot, so it can't be allowed to drop a signed record. Only a trusted key of
		// kind KeyCoder does that.
		return inconsistent(ReasonCoderSession)
	}
	if !stringsOK {
		return inconsistent(ReasonMalformed)
	}
	if at.After(e.now.Add(clockSkew)) {
		return inconsistent(ReasonFromFuture)
	}
	as, ok := e.assignment(id)
	if !ok {
		return inconsistent(ReasonUnknownAssignment)
	}
	want := KeyReviewer
	if as.Purpose == PurposeVerify {
		want = KeyVerifier
	}
	if key.Session == "" || key.Session != as.Session || signedDigest != as.Digest() || key.Kind != want ||
		(as.Purpose != PurposeReview && as.Purpose != PurposeVerify) {
		return inconsistent(ReasonBadBinding)
	}
	if !e.targetOK(as) {
		return inconsistent(ReasonWrongTarget)
	}
	if r, ok := e.rounds[as.RoundID]; !ok || r.Seq != as.RoundSeq || r.HeadSHA != as.HeadSHA {
		return inconsistent(ReasonRoundMismatch)
	}
	return true
}

func (e *evaluator) assignment(id string) (Assignment, bool) {
	if e.ambiguous[id] {
		return Assignment{}, false
	}
	a, ok := e.asg[id]
	return a, ok
}

func (e *evaluator) targetOK(a Assignment) bool {
	return a.Forge == e.t.Forge && a.Repo == e.t.Repo && a.PR == e.t.PR
}

func attestationStringsOK(a *Attestation) bool {
	ss := append([]string{a.AssignmentID, a.AssignmentDigest, a.Verdict, a.SplitGateID, a.KeyID}, a.SensitiveSignoff...)
	ss = append(ss, a.Repaired...)
	for _, c := range a.Claims {
		ss = append(ss, c.ID, c.Path, c.Invariant, c.Consequence, c.VerificationPlan)
	}
	return utf8s(ss...)
}

// verifyAttestations sorts the key-verified attestations (AGT-3, AGT-4, INT-20) into valid and invalid verdicts.
//
// An attestation that passes [evaluator.admit] but is invalid for another reason never approves, but it still
// counts against its role: it competes with the role's other verdicts at the same head, and when it is the newest
// the role is blocked, so a malformed block can't be shed by sending it wrong. Each of its well-formed claims
// contributes on its own.
func (e *evaluator) verifyAttestations() {
	byAsg := map[string][]*Attestation{}
	for i := range e.s.Attestations {
		a := &e.s.Attestations[i]
		if e.admit(RecordAttestation, a.SigningPayload(), a.KeyID, a.Signature, a.AssignmentID, a.AssignmentDigest, a.At, attestationStringsOK(a)) {
			byAsg[a.AssignmentID] = append(byAsg[a.AssignmentID], a)
		}
	}
	ids := make([]string, 0, len(byAsg))
	for id := range byAsg {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	e.claims = map[claimKey]*claimInfo{}
	for _, id := range ids {
		as := e.asg[id]
		distinct := []*Attestation{byAsg[id][0]}
		for _, a := range byAsg[id][1:] {
			if !slices.ContainsFunc(distinct, func(d *Attestation) bool { return bytes.Equal(d.SigningPayload(), a.SigningPayload()) }) {
				distinct = append(distinct, a)
			}
		}
		seq := e.rounds[as.RoundID].Seq
		for _, a := range distinct {
			e.addClaims(a, as)
			reason := e.checkAttestation(a, as)
			if len(distinct) > 1 {
				e.reject(RecordAttestation, id, ReasonConflictingRecords)
				reason = ReasonConflictingRecords
			}
			rec := &verdictRec{Attestation: *a, As: as, Seq: seq, Invalid: reason}
			if reason != "" {
				e.reject(RecordAttestation, id, reason)
				e.bad = append(e.bad, rec)
				continue
			}
			e.atts = append(e.atts, rec)
		}
	}
}

// addClaims records the claim instances of an attestation, each well-formed claim on its own, whatever the
// attestation's verdict. The first-seen attestation of an instance sets its time, round and head.
func (e *evaluator) addClaims(a *Attestation, as Assignment) {
	seq := e.rounds[as.RoundID].Seq
	seen := map[string]bool{}
	for _, c := range a.Claims {
		if !claimOK(c) || seen[c.ID] {
			continue
		}
		seen[c.ID] = true
		k := claimKey{Role: as.Role, ID: c.ID, Digest: c.Digest()}
		ci := e.claims[k]
		if ci == nil {
			ci = &claimInfo{first: a.At, firstSeq: seq, firstID: as.ID, sessions: map[string]bool{}}
			e.claims[k] = ci
		}
		if a.At.Before(ci.first) || (a.At.Equal(ci.first) && as.ID < ci.firstID) {
			ci.first, ci.firstSeq, ci.firstID = a.At, seq, as.ID
		}
		ci.sessions[as.Session] = true
		ci.atts = append(ci.atts, as.ID)
	}
}

// checkAttestation applies the validity rules to an admitted attestation. It returns the reason the verdict is
// invalid, or "".
func (e *evaluator) checkAttestation(a *Attestation, as Assignment) Reason {
	if as.Purpose != PurposeReview {
		return ReasonWrongPurpose
	}
	m, ok := e.s.Manifests[as.ID]
	switch {
	case !ok:
		return ReasonManifestMissing
	case !manifestKindsOK(m):
		return ReasonForbiddenContext
	case m.HeadSHA != as.HeadSHA:
		return ReasonManifestHead
	case m.Digest() != as.ManifestDigest:
		return ReasonManifestMismatch
	case !slices.Contains(e.rounds[as.RoundID].Roles, as.Role):
		return ReasonRoleNotInRound
	case a.At.IsZero():
		return ReasonMalformed
	}
	switch a.Verdict {
	case VerdictApprove:
		if len(a.Claims) != 0 {
			return ReasonBadClaim
		}
		if !hasKind(m, KindSpec) || !e.diffCoversChange(m) {
			return ReasonManifestIncomplete
		}
	case VerdictBlock:
		if len(a.Claims) == 0 {
			return ReasonBadClaim
		}
	case VerdictRequestSplit:
		if a.SplitGateID != e.cfg.SizeGateID {
			return ReasonWrongSplitGate
		}
		if len(a.Claims) != 0 {
			return ReasonBadClaim
		}
	default:
		return ReasonBadVerdict
	}
	if a.Verdict != VerdictRequestSplit && a.SplitGateID != "" {
		return ReasonWrongSplitGate
	}
	if !claimsOK(a.Claims) {
		return ReasonBadClaim
	}
	for _, c := range a.Claims {
		// A claim must point into what the claimant was shown.
		if !slices.ContainsFunc(m.Items, func(it Item) bool {
			return it.Path == c.Path && (it.Kind == KindDiff || it.Kind == KindRepoFile)
		}) {
			return ReasonBadClaim
		}
	}
	return ""
}

// diffCoversChange reports whether the manifest holds the diff of every changed path (AGT-3): the head side (or no
// side) of each path that still exists, and the base side of a removed path and of every old path.
func (e *evaluator) diffCoversChange(m Manifest) bool {
	has := func(p string, base bool) bool {
		return slices.ContainsFunc(m.Items, func(it Item) bool {
			return it.Kind == KindDiff && it.Path == p && (it.Side == SideBase) == base && (base || it.Side == "" || it.Side == SideHead)
		})
	}
	for _, c := range e.s.ChangedPaths {
		switch c.Status {
		case forge.FileRemoved:
			if !has(c.Path, true) {
				return false
			}
		case forge.FileRenamed, forge.FileCopied:
			if !has(c.Path, false) || !has(c.OldPath, true) {
				return false
			}
		case forge.FileStatusUnknown, forge.FileAdded, forge.FileModified, forge.FileModeChanged:
			if !has(c.Path, false) {
				return false
			}
		}
	}
	return len(e.s.ChangedPaths) > 0
}

func hasKind(m Manifest, kind string) bool {
	return slices.ContainsFunc(m.Items, func(it Item) bool { return it.Kind == kind })
}

func manifestKindsOK(m Manifest) bool {
	for _, it := range m.Items {
		if !allowedKind(it.Kind) || it.Digest == "" || !utf8s(it.Path, it.Side, it.Digest) {
			return false
		}
		if it.Side != "" && it.Side != SideBase && it.Side != SideHead {
			return false
		}
	}
	return true
}

// claimOK reports whether one claim is well formed (AGT-4).
func claimOK(c Claim) bool {
	blank := func(s string) bool { return strings.TrimSpace(s) == "" }
	return claimIDForm.MatchString(c.ID) && !blank(c.Invariant) && !blank(c.Consequence) && !blank(c.VerificationPlan) &&
		pathglob.ValidatePath(c.Path) == nil && c.StartLine >= 1 && c.EndLine >= c.StartLine
}

// claimsOK reports whether every claim is well formed and no ID repeats.
func claimsOK(claims []Claim) bool {
	ids := map[string]bool{}
	for _, c := range claims {
		if !claimOK(c) || ids[c.ID] {
			return false
		}
		ids[c.ID] = true
	}
	return true
}

func resolutionStringsOK(r *Resolution) bool {
	ss := []string{
		r.AssignmentID, r.AssignmentDigest, r.Claim.Role, r.Claim.ID, r.Claim.Digest, r.ReviewedRevision, r.Procedure,
		r.Expected, r.Outcome, r.Evidence.ProofDigest, r.KeyID,
	}
	if g := r.Evidence.Gate; g != nil {
		ss = append(ss, g.Gate.ProducerID, string(g.Gate.WorkflowID), g.Gate.WorkflowRevision, g.Gate.CheckID,
			g.RunID, g.RunAttempt, g.JobID, g.CandidateSHA)
	}
	return utf8s(ss...)
}

// verifyResolutions keeps the resolutions that count (AGT-4). A resolution that fails [evaluator.admit] makes the
// evidence inconsistent like an attestation. Any other invalid dismissal is only rejected, because ignoring a
// dismissal fails closed. A well-formed confirmation always counts: ignoring it would let a confirmed defect pass.
// Of two differing resolutions for one assignment, only a confirmation counts.
func (e *evaluator) verifyResolutions() {
	e.res = map[claimKey][]*Resolution{}
	byAsg := map[string][]*Resolution{}
	for i := range e.s.Resolutions {
		r := &e.s.Resolutions[i]
		if e.admit(RecordResolution, r.SigningPayload(), r.KeyID, r.Signature, r.AssignmentID, r.AssignmentDigest, r.At, resolutionStringsOK(r)) {
			byAsg[r.AssignmentID] = append(byAsg[r.AssignmentID], r)
		}
	}
	ids := make([]string, 0, len(byAsg))
	for id := range byAsg {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	for _, id := range ids {
		distinct := []*Resolution{byAsg[id][0]}
		for _, r := range byAsg[id][1:] {
			if !slices.ContainsFunc(distinct, func(d *Resolution) bool { return bytes.Equal(d.SigningPayload(), r.SigningPayload()) }) {
				distinct = append(distinct, r)
			}
		}
		for _, r := range distinct {
			counted, reason := e.checkResolution(r, e.asg[id])
			if reason == "" && len(distinct) > 1 && counted.Outcome != OutcomeConfirmed {
				reason = ReasonConflictingRecords
			}
			if reason != "" {
				e.reject(RecordResolution, id, reason)
				continue
			}
			e.res[counted.Claim] = append(e.res[counted.Claim], counted)
		}
	}
	for _, rs := range e.res {
		slices.SortFunc(rs, func(a, b *Resolution) int {
			return cmp.Or(a.At.Compare(b.At), cmp.Compare(a.AssignmentID, b.AssignmentID))
		})
	}
}

// checkResolution returns the resolution as it counts, or the reason it doesn't. A confirmation needs only to be
// well formed and for a known claim: it counts even if its gate evidence can't be checked against the current gate
// decision, and its head is the assignment's. A dismissal must be independent, current and backed by real evidence.
func (e *evaluator) checkResolution(r *Resolution, as Assignment) (*Resolution, Reason) {
	if as.Purpose != PurposeVerify {
		return nil, ReasonWrongPurpose
	}
	k := as.ClaimRef // signed in the assignment digest, so it proves what the verifier was asked about
	if k.Role == "" || k.ID == "" || k.Digest == "" {
		return nil, ReasonUnknownClaim
	}
	confirmation := r.Outcome == OutcomeConfirmed || e.malformedResolution(r)
	ci := e.claims[k]
	if ci == nil {
		if confirmation {
			// The claim instance this verifier was asked about isn't in the snapshot: its block was dropped.
			e.inconsistent = true
		}
		return nil, ReasonUnknownClaim
	}
	if confirmation {
		// Any resolution that isn't a well-formed dismissal counts as a confirmation of its claim: more signed negative
		// evidence must never produce a pass. It counts even if its gate evidence can't be rechecked, and its head is
		// its assignment's.
		c := *r
		c.Claim, c.Outcome, c.ReviewedRevision = k, OutcomeConfirmed, as.HeadSHA
		return &c, ""
	}
	if r.Claim != k {
		return nil, ReasonUnknownClaim
	}
	round := e.rounds[as.RoundID]
	switch {
	case ci.sessions[as.Session]:
		return nil, ReasonVerifierNotIndep
	case r.ReviewedRevision != as.HeadSHA:
		return nil, ReasonMalformed
	case !r.At.After(ci.first):
		return nil, ReasonBeforeClaim
	case round.State == RoundSuperseded && as.HeadSHA == e.t.HeadSHA:
		// Superseded at the current head (the spec or the contract changed): nothing in that round counts. A round
		// superseded by a push is, for a dismissal, the same as a completed round at an old head: the dismissal was
		// valid for the claim's content when it was made.
		return nil, ReasonRoundSuperseded
	case round.Seq < ci.firstSeq:
		return nil, ReasonRoundBeforeClaim
	}
	if r.Evidence.Gate != nil {
		if reason := e.gateEvidenceOK(r); reason != "" {
			return nil, reason
		}
	}
	return r, ""
}

// malformedResolution reports whether a resolution is not a well-formed confirmation or dismissal: an unknown
// outcome, no time, a blank procedure or expectation, or evidence that isn't exactly one well-shaped kind.
func (e *evaluator) malformedResolution(r *Resolution) bool {
	return (r.Outcome != OutcomeConfirmed && r.Outcome != OutcomeDismissed) || r.At.IsZero() ||
		strings.TrimSpace(r.Procedure) == "" || strings.TrimSpace(r.Expected) == "" || e.evidenceShape(r) != ""
}

// evidenceShape checks that exactly one kind of evidence is cited. A proof digest alone decides nothing: the signed
// procedure and expectation travel with it.
func (e *evaluator) evidenceShape(r *Resolution) Reason {
	ev := r.Evidence
	switch {
	case (ev.ProofDigest == "") == (ev.Gate == nil):
		return ReasonBadEvidence
	case ev.Gate == nil && !sha256Digit.MatchString(ev.ProofDigest):
		return ReasonBadEvidence
	}
	return ""
}

// gateEvidenceOK checks a dismissal's gate evidence: this change's mandatory gate, passed, at the reviewed head
// (P4).
func (e *evaluator) gateEvidenceOK(r *Resolution) Reason {
	g, d := r.Evidence.Gate, e.s.Gate
	if d == nil || g.RunID == "" || g.RunAttempt == "" || g.JobID == "" || g.CandidateSHA == "" {
		return ReasonGateEvidenceMismatch
	}
	if d.Forge != e.t.Forge || d.Repo != e.t.Repo || d.PR != e.t.PR || d.CandidateSHA != g.CandidateSHA ||
		d.HeadSHA != r.ReviewedRevision ||
		d.PolicyRevision != e.eff.Revision || d.InstallRevision != e.eff.InstallRevision {
		return ReasonGateEvidenceMismatch
	}
	inContract := slices.ContainsFunc(e.eff.VerifyGates, func(o contract.Obligation) bool {
		return o.Gate.Mandatory && o.Gate.GateRef == g.Gate
	})
	if !inContract {
		return ReasonGateEvidenceMismatch
	}
	for i := range d.Obligations {
		o := &d.Obligations[i]
		if o.Mandatory && o.Gate == g.Gate && o.RunID == g.RunID && o.RunAttempt == g.RunAttempt && o.JobID == g.JobID {
			if o.Disposition != gate.Pass {
				return ReasonGateEvidenceMismatch
			}
			return ""
		}
	}
	return ReasonGateEvidenceMismatch
}

// current returns the latest verdict of role at the target head: by round sequence, then time, then block over other verdicts, then assignment ID. An invalid verdict competes like any
// other, so a newer invalid one hides an older approval.
func (e *evaluator) current(role string) (*verdictRec, bool) {
	var best *verdictRec
	for _, v := range slices.Concat(e.atts, e.bad) {
		if v.As.Role != role || v.As.HeadSHA != e.t.HeadSHA {
			continue
		}
		// A superseded round hides only its approvals. A block, a split or an invalid verdict in it still competes, so
		// that more negative evidence can't make an older approval current again.
		if v.Invalid == "" && v.Verdict == VerdictApprove && e.rounds[v.As.RoundID].State == RoundSuperseded {
			continue
		}
		if best == nil || newer(v, best) {
			best = v
		}
	}
	return best, best != nil
}

func newer(a, b *verdictRec) bool {
	br := func(v *verdictRec) int {
		if v.Verdict == VerdictBlock {
			return 1
		}
		return 0
	}
	return cmp.Or(
		cmp.Compare(a.Seq, b.Seq), a.At.Compare(b.At), cmp.Compare(br(a), br(b)),
		cmp.Compare(a.As.ID, b.As.ID),
	) > 0
}

func (e *evaluator) decide(d Decision) Decision {
	var obs []Obligation
	roles := requiredRoles(e.eff)
	picked := map[string]*verdictRec{}
	for _, role := range roles {
		if v, ok := e.current(role); ok {
			picked[role] = v
		}
	}
	// Independence: a session may stand behind one required role only (AGD-3).
	users := map[string][]string{}
	for role, v := range picked {
		if v.Invalid != "" {
			continue
		}
		users[v.As.Session] = append(users[v.As.Session], role)
	}
	reused := map[string]bool{}
	for _, rs := range users {
		if len(rs) > 1 {
			for _, r := range rs {
				reused[r] = true
				e.reject(RecordAttestation, picked[r].As.ID, ReasonSessionReuse)
			}
		}
	}
	approved := map[string]*verdictRec{}
	var splits []string
	for _, role := range roles {
		o := Obligation{ID: "role:" + role, Kind: KindRole}
		v, ok := picked[role]
		switch {
		case !ok:
			o.Disposition, o.Reason, o.Action = Pending, ReasonNoApproval, ActionDispatch
		case v.Invalid != "":
			o.Disposition, o.Reason, o.Action, o.Evidence = Blocked, ReasonInvalidVerdict, ActionRepair, []string{v.As.ID}
		case reused[role]:
			o.Disposition, o.Reason, o.Action, o.Evidence = Blocked, ReasonSessionReuse, ActionReassign, []string{v.As.ID}
		case v.Verdict == VerdictBlock:
			o.Disposition, o.Reason, o.Action, o.Evidence = Blocked, ReasonReviewerBlocked, ActionRepair, []string{v.As.ID}
		case v.Verdict == VerdictRequestSplit:
			o.Disposition, o.Reason, o.Action, o.Evidence = Pending, ReasonSplitRequested, ActionDispatch, []string{v.As.ID}
			splits = append(splits, v.As.ID)
		default:
			o.Disposition, o.Reason, o.Evidence = Pass, ReasonSatisfied, []string{v.As.ID}
			approved[role] = v
		}
		obs = append(obs, o)
	}
	if e.eff.SecuritySignoffRequired {
		obs = append(obs, e.signoffObligation(approved))
	}
	obs = append(obs, e.claimObligations()...)

	converged := true
	for _, o := range obs {
		converged = converged && o.Disposition == Pass
	}
	if !converged && e.roundCount() >= e.cfg.ReviewRounds {
		obs = append(obs, Obligation{
			ID: "rounds", Kind: KindRounds, Disposition: Escalated,
			Reason: ReasonRoundsExhausted, Action: ActionAssignOwner,
		})
	}
	if len(splits) > 0 {
		// A split request counts only while it is its role's current verdict (INT-20).
		slices.Sort(splits)
		obs = append(obs, Obligation{
			ID: "split", Kind: KindSplit, Disposition: Replan, Reason: ReasonSplitRequested,
			Evidence: splits, Action: ActionReplan,
		})
	}
	if e.lightsOn() {
		lo, targets := e.lightsOnObligations()
		obs = append(obs, lo...)
		d.RequiredApprovals = targets
	}

	slices.SortFunc(obs, func(a, b Obligation) int { return cmp.Compare(a.ID, b.ID) })
	d.Obligations = obs
	d.Disposition = Pass
	for _, o := range obs {
		if o.Disposition.rank() > d.Disposition.rank() {
			d.Disposition = o.Disposition
		}
	}
	d.Rejected = e.sortedRejections()
	return d
}

// roundCount is the number of distinct rounds that were finished: completed or superseded. A retry inside a round
// reuses its ID, and a round that is only dispatched hasn't used up a review yet.
func (e *evaluator) roundCount() int {
	n := 0
	for _, r := range e.rounds {
		if r.State == RoundCompleted || r.State == RoundSuperseded {
			n++
		}
	}
	return n
}

// signoffObligation checks SEC-5: the security reviewer's manifest covers the sensitive diff, and its attestation
// signs off exactly that set.
func (e *evaluator) signoffObligation(approved map[string]*verdictRec) Obligation {
	o := Obligation{ID: "signoff:sensitive", Kind: KindSignoff}
	v, ok := approved[e.eff.SecurityReviewer]
	if !ok {
		o.Disposition, o.Reason, o.Action = Pending, ReasonSignoffMissing, ActionDispatch
		return o
	}
	o.Evidence = []string{v.As.ID}
	signoff, head := e.sensitiveSets()
	m := e.s.Manifests[v.As.ID]
	ok = slices.Equal(sortedUnique(v.SensitiveSignoff), signoff)
	for _, p := range head {
		// The head side (or no side) of the diff: a base-only item doesn't show what the change made of the file. The
		// base side of an old path is already part of every approving manifest (see diffCoversChange).
		ok = ok && slices.ContainsFunc(m.Items, func(it Item) bool {
			return it.Kind == KindDiff && it.Path == p && (it.Side == "" || it.Side == SideHead)
		})
	}
	if !ok {
		o.Disposition, o.Reason, o.Action = Blocked, ReasonSignoffMissing, ActionSignoff
		return o
	}
	o.Disposition, o.Reason = Pass, ReasonSatisfied
	return o
}

// sensitiveSets returns the exact sign-off set and the sensitive paths whose head side the manifest must show
// (SEC-5). The sign-off set is the sensitive paths plus the old path of every removed, renamed or copied file that
// touches one. A path that is only an old path, or removed, has no head side.
func (e *evaluator) sensitiveSets() (signoff, head []string) {
	sensitive := sortedUnique(e.eff.SensitivePaths)
	var old []string
	for _, c := range e.s.ChangedPaths {
		o := ""
		switch c.Status {
		case forge.FileRemoved:
			o = c.Path
		case forge.FileRenamed, forge.FileCopied:
			o = c.OldPath
		case forge.FileStatusUnknown, forge.FileAdded, forge.FileModified, forge.FileModeChanged:
			// no old side
		}
		if o != "" && (slices.Contains(sensitive, c.Path) || slices.Contains(sensitive, o)) {
			old = append(old, o)
		}
	}
	old = sortedUnique(old)
	for _, p := range sensitive {
		if !slices.Contains(old, p) {
			head = append(head, p)
		}
	}
	return sortedUnique(append(slices.Clone(sensitive), old...)), head
}

func sortedUnique(s []string) []string {
	out := slices.Clone(s)
	slices.Sort(out)
	return slices.Compact(out)
}

// claimObligations returns one obligation per claim instance (AGT-4). The ID is [ClaimObligationID].
func (e *evaluator) claimObligations() []Obligation {
	keys := make([]claimKey, 0, len(e.claims))
	for k := range e.claims {
		keys = append(keys, k)
	}
	slices.SortFunc(keys, func(a, b claimKey) int {
		return cmp.Or(cmp.Compare(a.Role, b.Role), cmp.Compare(a.ID, b.ID), cmp.Compare(a.Digest, b.Digest))
	})
	var out []Obligation
	for _, k := range keys {
		ci := e.claims[k]
		o := Obligation{ID: ClaimObligationID(k), Kind: KindClaim}
		ev := slices.Clone(ci.atts)
		for _, r := range e.res[k] {
			ev = append(ev, r.AssignmentID)
		}
		o.Evidence = sortedUnique(ev)
		state := e.claimState(k)
		if state.closed {
			o.Disposition, o.Reason = Pass, ReasonSatisfied
			out = append(out, o)
			continue
		}
		o.Disposition, o.Reason, o.Action = Blocked, state.reason, state.action
		if e.verifyAttempts(k) > e.cfg.VerifyAttempts || e.now.Sub(ci.first) > e.cfg.VerifyTimeout {
			o.Disposition, o.Reason, o.Action = Escalated, ReasonClaimEscalated, ActionAssignOwner
		}
		out = append(out, o)
	}
	return out
}

type claimResult struct {
	closed bool
	reason Reason
	action string
}

// claimState decides one claim instance from its valid resolutions.
//
// A claim with no resolution is open. If every valid resolution dismisses it, it is closed. Once any valid resolution
// confirms it, it stays blocked, even if another verifier dismissed it, until both a later attestation of the
// claimant role at a newer head than the confirmed one records it as repaired at the current head, and a fresh
// dismissal reviewed at the current head follows that attestation.
func (e *evaluator) claimState(k claimKey) claimResult {
	rs := e.res[k]
	if len(rs) == 0 {
		return claimResult{false, ReasonClaimOpen, ActionVerify}
	}
	var latest time.Time // of the confirmations
	heads := map[string]bool{}
	for _, r := range rs {
		if r.Outcome == OutcomeConfirmed {
			heads[r.ReviewedRevision] = true
			if r.At.After(latest) {
				latest = r.At
			}
		}
	}
	if len(heads) == 0 {
		return claimResult{closed: true}
	}
	// A repair must be at the target head and at a head no confirmation was at, so a confirmation at the target head
	// can't be repaired: more confirmations never help a claim close.
	var repairedAt time.Time
	repaired := false
	for _, v := range e.atts {
		if v.As.Role != k.Role || v.As.HeadSHA != e.t.HeadSHA || heads[v.As.HeadSHA] ||
			e.rounds[v.As.RoundID].State == RoundSuperseded ||
			!slices.Contains(v.Repaired, RepairedRef(k)) || !v.At.After(latest) {
			continue
		}
		if !repaired || v.At.Before(repairedAt) {
			repairedAt, repaired = v.At, true
		}
	}
	if !repaired {
		return claimResult{false, ReasonClaimConfirmed, ActionRepair}
	}
	for _, r := range rs {
		if r.Outcome == OutcomeDismissed && r.ReviewedRevision == e.t.HeadSHA && r.At.After(repairedAt) {
			return claimResult{closed: true}
		}
	}
	return claimResult{false, ReasonClaimReverify, ActionVerify}
}

// verifyAttempts counts the verify assignments issued for a claim instance.
func (e *evaluator) verifyAttempts(k claimKey) int {
	n := 0
	seen := map[string]bool{}
	for i := range e.s.Assignments {
		a := &e.s.Assignments[i]
		if seen[a.ID] || e.ambiguous[a.ID] || a.ID == "" {
			continue
		}
		seen[a.ID] = true
		if a.Purpose == PurposeVerify && a.ClaimRef == k && e.targetOK(*a) {
			n++
		}
	}
	return n
}

// lightsOnObligations returns one obligation and one authz target per owner area (CON-8, PIP-9). This package can
// never satisfy them: nothing in the snapshot claims an authorization, and WI-18 authorizes at execution time.
func (e *evaluator) lightsOnObligations() ([]Obligation, []authz.Target) {
	a := e.approval()
	rev := ApprovalManifest{
		Forge: e.t.Forge, Repo: string(e.t.Repo), PR: e.t.PR, Generation: a.Generation, HeadSHA: e.t.HeadSHA,
		ImpactRevision: a.ImpactRevision, RecoveryRevision: a.RecoveryRevision,
		Callers: a.Callers, RolloutOrder: a.RolloutOrder,
	}.Digest()
	type area struct {
		digest string
		paths  []string
	}
	areas := make([]area, 0, len(e.s.OwnerAreas))
	for _, p := range e.s.OwnerAreas {
		areas = append(areas, area{areaDigest(p), sortedCopy(p)})
	}
	slices.SortFunc(areas, func(x, y area) int { return cmp.Compare(x.digest, y.digest) })
	var obs []Obligation
	var targets []authz.Target
	for _, ar := range areas {
		obs = append(obs, Obligation{
			ID: "lights-on:" + ar.digest, Kind: KindApproval, Disposition: NeedsAuthorization,
			Reason: ReasonLightsOn, Action: ActionAuthorize,
		})
		targets = append(targets, authz.Target{
			Operation: authz.OpApproveLightsOn,
			Scope:     authz.Scope{Kind: authz.ScopeRepo, ID: string(e.t.Repo)},
			Subject:   audit.Subject{Kind: audit.SubjectChange, Repo: string(e.t.Repo), ID: strconv.Itoa(e.t.PR)},
			Revision:  rev,
			Paths:     ar.paths,
		})
	}
	return obs, targets
}

// ClaimObligationID is the ID of a claim instance's obligation: "claim:<role>/<id>#<claim digest in hex>". It is
// stable, and it tells two instances of one ID apart.
func ClaimObligationID(k ClaimRef) string {
	return "claim:" + k.Role + "/" + k.ID + "#" + strings.TrimPrefix(k.Digest, "sha256:")
}
