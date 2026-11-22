// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

package review_test

import (
	"crypto/ed25519"
	"crypto/sha256"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/elliott-davis/lightsout/internal/contract"
	"github.com/elliott-davis/lightsout/internal/forge"
	"github.com/elliott-davis/lightsout/internal/gate"
	"github.com/elliott-davis/lightsout/internal/review"
)

const (
	repo  = forge.RepoID("acme/app")
	head1 = "1111111111111111111111111111111111111111"
	head2 = "2222222222222222222222222222222222222222"
	cand  = "cccccccccccccccccccccccccccccccccccccccc"

	rolePR   = "pr-reviewer"
	roleSec  = "security-reviewer"
	roleGo   = "go-reviewer"
	sizeGate = "shape/review-budget"
)

var base = time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)

func keyPair(seed string) (ed25519.PublicKey, ed25519.PrivateKey) {
	sum := sha256.Sum256([]byte(seed))
	priv := ed25519.NewKeyFromSeed(sum[:])
	return ed25519.PublicKey(priv[32:]), priv
}

// env is one change under review with a hand-built snapshot.
type env struct {
	t    *testing.T
	eff  *contract.Effective
	tgt  review.Target
	cfg  review.Config
	keys review.Keys
	snap review.Snapshot
	now  time.Time
	priv map[string]ed25519.PrivateKey
	n    int
}

var gref = contract.GateRef{ProducerID: "github-app:1", WorkflowID: "42/.github/workflows/v.yml", WorkflowRevision: head1, CheckID: "unit"}

func newEnv(t *testing.T) *env {
	t.Helper()
	e := &env{
		t: t,
		eff: &contract.Effective{
			Revision: "pol-1", InstallRevision: "inst-1",
			Reviewers:        []contract.Requirement{{Role: rolePR}, {Role: roleSec}, {Role: roleGo}},
			SecurityReviewer: roleSec,
			VerifyGates:      []contract.Obligation{{Gate: contract.Gate{Name: "unit", GateRef: gref, Mandatory: true}}},
		},
		tgt:  review.Target{Forge: "github", Repo: repo, PR: 7, HeadSHA: head1},
		cfg:  review.Config{ReviewRounds: 3, VerifyAttempts: 3, VerifyTimeout: 24 * time.Hour, SizeGateID: sizeGate, PRReviewer: rolePR},
		keys: review.Keys{},
		snap: review.Snapshot{
			Manifests: map[string]review.Manifest{}, CoderSessions: []string{"coder-1"},
			StateVersion: "sv-1", Complete: true,
		},
		now:  base.Add(2 * time.Hour),
		priv: map[string]ed25519.PrivateKey{},
	}
	e.addKey("k-fallback", "fallback-session")
	e.setChanged(review.ChangedPath{Path: "internal/x.go", Status: forge.FileModified})
	e.snap.Gate = &gate.Decision{
		Target:         gate.Target{Forge: "github", Repo: repo, PR: 7, HeadSHA: head1, CandidateSHA: cand},
		PolicyRevision: "pol-1", InstallRevision: "inst-1", Disposition: gate.Pass,
		Obligations: []gate.ObligationResult{{
			Gate: gref, Mandatory: true, Disposition: gate.Pass, RunID: "100", RunAttempt: "1", JobID: "200",
		}},
	}
	return e
}

func (e *env) eval() review.Decision {
	e.t.Helper()
	return review.Evaluate(e.eff, e.tgt, e.snap, e.cfg, e.keys, e.now)
}

// addKey registers a trusted reviewer key that signs for one session.
func (e *env) addKey(id, session string) { e.addKeyKind(id, session, review.KeyReviewer) }

func (e *env) addKeyKind(id, session string, kind review.KeyKind) {
	pub, priv := keyPair(id)
	e.keys[id] = review.Key{Pub: pub, Session: session, Kind: kind}
	e.priv[id] = priv
}

// setChanged sets the changed paths and makes the effective contract cover them, old paths included.
func (e *env) setChanged(cps ...review.ChangedPath) {
	e.snap.ChangedPaths = cps
	e.eff.Paths = nil
	for _, c := range cps {
		e.eff.Paths = append(e.eff.Paths, contract.PathPolicy{Path: c.Path})
		if c.OldPath != "" {
			e.eff.Paths = append(e.eff.Paths, contract.PathPolicy{Path: c.OldPath})
		}
	}
}

// fullItems is what an approving reviewer is shown: the spec and the diff of every changed path, and the file the
// default claims point at.
func (e *env) fullItems() []review.Item {
	items := []review.Item{
		{Kind: review.KindSpec, Digest: "sha256:s"},
		{Kind: review.KindRepoFile, Path: "internal/x.go", Digest: "sha256:r"},
	}
	for _, c := range e.snap.ChangedPaths {
		switch c.Status {
		case forge.FileRemoved:
			items = append(items, review.Item{Kind: review.KindDiff, Path: c.Path, Side: review.SideBase, Digest: "sha256:b"})
		case forge.FileRenamed, forge.FileCopied:
			items = append(items,
				review.Item{Kind: review.KindDiff, Path: c.Path, Side: review.SideHead, Digest: "sha256:h"},
				review.Item{Kind: review.KindDiff, Path: c.OldPath, Side: review.SideBase, Digest: "sha256:b"})
		case forge.FileStatusUnknown, forge.FileAdded, forge.FileModified, forge.FileModeChanged:
			items = append(items, review.Item{Kind: review.KindDiff, Path: c.Path, Digest: "sha256:d"})
		}
	}
	return items
}

func (e *env) setRound(id string, seq int, head, state string) {
	r := review.Round{ID: id, Seq: seq, HeadSHA: head, State: state, Roles: []string{rolePR, roleSec, roleGo}}
	for i := range e.snap.Rounds {
		if e.snap.Rounds[i].ID == id {
			e.snap.Rounds[i] = r
			return
		}
	}
	e.snap.Rounds = append(e.snap.Rounds, r)
}

func (e *env) roundSeq(id string) int {
	for _, r := range e.snap.Rounds {
		if r.ID == id {
			return r.Seq
		}
	}
	return 0
}

func (e *env) ensureRound(id, head string) {
	for _, r := range e.snap.Rounds {
		if r.ID == id {
			return
		}
	}
	e.setRound(id, len(e.snap.Rounds)+1, head, review.RoundDispatched)
}

// rv describes one review assignment and its attestation. Zero fields take a sensible default.
type rv struct {
	id, role, session, round, head, verdict, split, key, digest, mhead, forgeName string
	repo                                                                          forge.RepoID
	pr                                                                            int
	claims                                                                        []review.Claim
	signoff, repaired                                                             []string
	items, extra                                                                  []review.Item
	at                                                                            time.Duration
	noAttest                                                                      bool
}

func (e *env) sign(keyID string, payload []byte) []byte {
	priv, ok := e.priv[keyID]
	if !ok {
		priv = e.priv["k-fallback"] // an unknown key ID still gets a signature, so only the key lookup fails
	}
	return ed25519.Sign(priv, payload)
}

// review adds the assignment, its manifest and a signed attestation. It returns the assignment ID.
func (e *env) review(r rv) string {
	e.t.Helper()
	e.n++
	if r.id == "" {
		r.id = fmt.Sprintf("a%d", e.n)
	}
	if r.session == "" {
		r.session = r.role + "-s"
	}
	if r.round == "" {
		r.round = "r1"
	}
	if r.head == "" {
		r.head = e.tgt.HeadSHA
	}
	if r.verdict == "" {
		r.verdict = review.VerdictApprove
	}
	if r.key == "" {
		r.key = "k-" + r.session
		if _, ok := e.keys[r.key]; !ok {
			e.addKey(r.key, r.session)
		}
	}
	if r.pr == 0 {
		r.pr = e.tgt.PR
	}
	if r.forgeName == "" {
		r.forgeName = e.tgt.Forge
	}
	if r.repo == "" {
		r.repo = e.tgt.Repo
	}
	if r.items == nil {
		r.items = e.fullItems()
	}
	r.items = append(slices.Clone(r.items), r.extra...)
	if r.mhead == "" {
		r.mhead = r.head
	}
	if r.at == 0 {
		r.at = time.Duration(e.n) * time.Minute
	}
	e.ensureRound(r.round, r.head)
	m := review.Manifest{HeadSHA: r.mhead, Items: r.items}
	if r.digest == "" {
		r.digest = m.Digest()
	}
	e.snap.Manifests[r.id] = m
	as := review.Assignment{
		ID: r.id, Forge: r.forgeName, Repo: r.repo, PR: r.pr, HeadSHA: r.head, RoundID: r.round, Role: r.role,
		Profile: "profile", ManifestDigest: r.digest, Purpose: review.PurposeReview, Session: r.session,
		RoundSeq: e.roundSeq(r.round),
	}
	e.snap.Assignments = append(e.snap.Assignments, as)
	if !r.noAttest {
		a := review.Attestation{
			AssignmentID: r.id, AssignmentDigest: as.Digest(), Verdict: r.verdict, Claims: r.claims, SplitGateID: r.split,
			SensitiveSignoff: r.signoff, Repaired: r.repaired, At: base.Add(r.at), KeyID: r.key,
		}
		a.Signature = e.sign(r.key, a.SigningPayload())
		e.snap.Attestations = append(e.snap.Attestations, a)
	}
	return r.id
}

// approveAll adds an approval for every required role at the target head, each from its own session.
func (e *env) approveAll() {
	e.t.Helper()
	for _, role := range []string{rolePR, roleSec, roleGo} {
		e.review(rv{role: role})
	}
}

const (
	impRev  = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	recRev  = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
	impRev2 = "sha256:3333333333333333333333333333333333333333333333333333333333333333"
	recRev2 = "sha256:4444444444444444444444444444444444444444444444444444444444444444"
)

func claim(id string) review.Claim {
	return review.Claim{
		ID: id, Path: "internal/x.go", StartLine: 3, EndLine: 9, Invariant: "inv", Consequence: "cons", VerificationPlan: "plan",
	}
}

var proof = review.Evidence{ProofDigest: "sha256:" + strings.Repeat("a", 64)}

// vf describes one verify assignment and, unless none is set, its signed resolution.
type vf struct {
	id, session, head, outcome, key string
	claim                           review.ClaimRef
	round                           string
	ev                              *review.Evidence
	at                              time.Duration
	none                            bool // no resolution yet
	noAssignment                    bool // a resolution without an assignment
}

func (e *env) verify(v vf) {
	e.t.Helper()
	e.n++
	if v.id == "" {
		v.id = fmt.Sprintf("v%d", e.n)
	}
	if v.session == "" {
		v.session = "verifier-" + v.id
	}
	if v.head == "" {
		v.head = e.tgt.HeadSHA
	}
	if v.outcome == "" {
		v.outcome = review.OutcomeDismissed
	}
	if v.key == "" {
		v.key = "kv-" + v.session
		if _, ok := e.keys[v.key]; !ok {
			e.addKeyKind(v.key, v.session, review.KeyVerifier)
		}
	}
	if v.round == "" {
		v.round = e.roundAt(v.head)
	}
	if v.ev == nil {
		v.ev = &proof
	}
	if v.at == 0 {
		v.at = time.Duration(e.n) * time.Minute
	}
	as := review.Assignment{
		ID: v.id, Forge: e.tgt.Forge, Repo: e.tgt.Repo, PR: e.tgt.PR, HeadSHA: v.head, RoundID: v.round, RoundSeq: e.roundSeq(v.round),
		Role: "verifier", Profile: "profile", Purpose: review.PurposeVerify, ClaimRef: v.claim, Session: v.session,
	}
	if !v.noAssignment {
		e.snap.Assignments = append(e.snap.Assignments, as)
	}
	if !v.none {
		r := review.Resolution{
			AssignmentID: v.id, AssignmentDigest: as.Digest(), Claim: v.claim, ReviewedRevision: v.head, Procedure: "run repro", Expected: "no panic",
			Outcome: v.outcome, Evidence: *v.ev, At: base.Add(v.at), KeyID: v.key,
		}
		r.Signature = e.sign(v.key, r.SigningPayload())
		e.snap.Resolutions = append(e.snap.Resolutions, r)
	}
}

// roundAt returns a live round at head for a verifier, adding one if there is none.
func (e *env) roundAt(head string) string {
	for _, r := range e.snap.Rounds {
		if r.HeadSHA == head && r.State != review.RoundSuperseded {
			return r.ID
		}
	}
	id := "rv-" + head[:4]
	e.setRound(id, len(e.snap.Rounds)+1, head, review.RoundDispatched)
	return id
}

func find(d review.Decision, id string) (review.Obligation, bool) {
	for _, o := range d.Obligations {
		if o.ID == id {
			return o, true
		}
	}
	return review.Obligation{}, false
}

func wantDisp(t *testing.T, d review.Decision, want review.Disposition) {
	t.Helper()
	if d.Disposition != want {
		t.Fatalf("disposition = %s, want %s\n%+v", d.Disposition, want, d)
	}
}

func wantOb(t *testing.T, d review.Decision, id string, disp review.Disposition, reason review.Reason) {
	t.Helper()
	o, ok := find(d, id)
	if !ok {
		t.Fatalf("no obligation %q in %+v", id, d.Obligations)
	}
	if o.Disposition != disp || o.Reason != reason {
		t.Fatalf("obligation %s = %s/%s, want %s/%s", id, o.Disposition, o.Reason, disp, reason)
	}
}

func wantRejected(t *testing.T, d review.Decision, kind review.RecordKind, id string, reason review.Reason) {
	t.Helper()
	for _, r := range d.Rejected {
		if r.Kind == kind && r.ID == id && r.Reason == reason {
			return
		}
	}
	t.Fatalf("no rejection %s %s %s in %+v", kind, id, reason, d.Rejected)
}

// resignAtt signs attestation i again with its own key, after a test changed it.
func (e *env) resignAtt(i int) {
	a := &e.snap.Attestations[i]
	a.Signature = e.sign(a.KeyID, a.SigningPayload())
}

// resignRes signs resolution i again with its own key.
func (e *env) resignRes(i int) {
	r := &e.snap.Resolutions[i]
	r.Signature = e.sign(r.KeyID, r.SigningPayload())
}

// resolve adds a signed resolution for an existing assignment, by the key of that assignment's session.
func (e *env) resolve(assignmentID string, r review.Resolution) {
	e.t.Helper()
	for i := range e.snap.Assignments {
		as := &e.snap.Assignments[i]
		if as.ID != assignmentID {
			continue
		}
		key, kind := "k-"+as.Session, review.KeyReviewer
		if as.Purpose == review.PurposeVerify {
			key, kind = "kv-"+as.Session, review.KeyVerifier
		}
		if _, ok := e.keys[key]; !ok {
			e.addKeyKind(key, as.Session, kind)
		}
		r.AssignmentID, r.AssignmentDigest, r.KeyID = as.ID, as.Digest(), key
		r.Signature = e.sign(key, r.SigningPayload())
		e.snap.Resolutions = append(e.snap.Resolutions, r)
		return
	}
	e.t.Fatalf("no assignment %s", assignmentID)
}

// cobl is the obligation ID of claim id raised by role in the default shape.
func cobl(role, id string) string {
	return review.ClaimObligationID(review.ClaimRef{Role: role, ID: id, Digest: claim(id).Digest()})
}

// wantInconsistent asserts the decision is an error because a key-verified record doesn't fit the snapshot.
func wantInconsistent(t *testing.T, d review.Decision) {
	t.Helper()
	wantDisp(t, d, review.Error)
	if !slices.Equal(d.Reasons, []review.Reason{review.ReasonInconsistentEvidence}) {
		t.Fatalf("reasons = %v, want inconsistent-evidence", d.Reasons)
	}
}
