// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

package review

import (
	"bytes"
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"slices"
	"time"
)

// Domain prefixes keep a signature or digest of one record type from being valid for another.
const (
	attestationDomain = "lightsout/review-attestation/v1\n"
	resolutionDomain  = "lightsout/review-resolution/v1\n"
	manifestDomain    = "lightsout/review-manifest/v1\n"
	approvalDomain    = "lightsout/approval-manifest/v1\n"
	areaDomain        = "lightsout/review-area/v1\n"
	assignmentDomain  = "lightsout/review-assignment/v1\n"
	claimDomain       = "lightsout/review-claim/v1\n"
)

// canonical returns domain followed by the JSON encoding of v without HTML escaping. Field order is the struct's
// declaration order, so every encoded type below lists its fields in a fixed order.
func canonical(domain string, v any) []byte {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		panic("review: marshal " + domain + ": " + err.Error()) // cannot happen: only strings, ints and slices
	}
	return append([]byte(domain), bytes.TrimSuffix(buf.Bytes(), []byte("\n"))...)
}

func hexSum(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// sortedCopy returns a sorted copy of s, never nil, so an empty list encodes as [] and not null.
func sortedCopy(s []string) []string {
	out := slices.Clone(s)
	if out == nil {
		out = []string{}
	}
	slices.Sort(out)
	return out
}

func stamp(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }

type jsonItem struct {
	Kind   string `json:"kind"`
	Path   string `json:"path"`
	Side   string `json:"side"`
	Digest string `json:"digest"`
}

// Digest returns "sha256:" and the hex digest of the manifest. It is domain-separated and canonical: the items are
// sorted by (kind, path, side, digest), so the order they were listed in does not matter.
func (m Manifest) Digest() string {
	items := slices.Clone(m.Items)
	slices.SortFunc(items, func(a, b Item) int {
		return cmp.Or(
			cmp.Compare(a.Kind, b.Kind), cmp.Compare(a.Path, b.Path),
			cmp.Compare(a.Side, b.Side), cmp.Compare(a.Digest, b.Digest),
		)
	})
	out := make([]jsonItem, len(items))
	for i, it := range items {
		out[i] = jsonItem(it)
	}
	return "sha256:" + hexSum(canonical(manifestDomain, struct {
		HeadSHA string     `json:"headSha"`
		Items   []jsonItem `json:"items"`
	}{m.HeadSHA, out}))
}

type jsonClaim struct {
	ID               string `json:"id"`
	Path             string `json:"path"`
	StartLine        int    `json:"startLine"`
	EndLine          int    `json:"endLine"`
	Invariant        string `json:"invariant"`
	Consequence      string `json:"consequence"`
	VerificationPlan string `json:"verificationPlan"`
}

// SigningPayload returns the bytes the runtime signs: the domain "lightsout/review-attestation/v1\n" and the fixed-order
// JSON of every field except Signature. Claims, SensitiveSignoff and Repaired are sorted, because their order carries
// no meaning.
func (a Attestation) SigningPayload() []byte {
	claims := slices.Clone(a.Claims)
	slices.SortFunc(claims, func(x, y Claim) int {
		return cmp.Or(
			cmp.Compare(x.ID, y.ID), cmp.Compare(x.Path, y.Path), cmp.Compare(x.StartLine, y.StartLine),
			cmp.Compare(x.EndLine, y.EndLine), cmp.Compare(x.Invariant, y.Invariant),
			cmp.Compare(x.Consequence, y.Consequence), cmp.Compare(x.VerificationPlan, y.VerificationPlan),
		)
	})
	jc := make([]jsonClaim, len(claims))
	for i, c := range claims {
		jc[i] = jsonClaim(c)
	}
	return canonical(attestationDomain, struct {
		AssignmentID     string      `json:"assignmentId"`
		AssignmentDigest string      `json:"assignmentDigest"`
		Verdict          string      `json:"verdict"`
		Claims           []jsonClaim `json:"claims"`
		SplitGateID      string      `json:"splitGateId"`
		SensitiveSignoff []string    `json:"sensitiveSignoff"`
		Repaired         []string    `json:"repaired"`
		At               string      `json:"at"`
		KeyID            string      `json:"keyId"`
	}{a.AssignmentID, a.AssignmentDigest, a.Verdict, jc, a.SplitGateID, sortedCopy(a.SensitiveSignoff), sortedCopy(a.Repaired), stamp(a.At), a.KeyID})
}

// SigningPayload returns the bytes the runtime signs: the domain "lightsout/review-resolution/v1\n" and the
// fixed-order JSON of every field except Signature.
func (r Resolution) SigningPayload() []byte {
	type gateEv struct {
		ProducerID       string `json:"producerId"`
		WorkflowID       string `json:"workflowId"`
		WorkflowRevision string `json:"workflowRevision"`
		CheckID          string `json:"checkId"`
		RunID            string `json:"runId"`
		RunAttempt       string `json:"runAttempt"`
		JobID            string `json:"jobId"`
		CandidateSHA     string `json:"candidateSha"`
	}
	var g *gateEv
	if e := r.Evidence.Gate; e != nil {
		g = &gateEv{
			e.Gate.ProducerID, string(e.Gate.WorkflowID), e.Gate.WorkflowRevision, e.Gate.CheckID,
			e.RunID, e.RunAttempt, e.JobID, e.CandidateSHA,
		}
	}
	return canonical(resolutionDomain, struct {
		AssignmentID     string  `json:"assignmentId"`
		AssignmentDigest string  `json:"assignmentDigest"`
		ClaimRole        string  `json:"claimRole"`
		ClaimID          string  `json:"claimId"`
		ClaimDigest      string  `json:"claimDigest"`
		ReviewedRevision string  `json:"reviewedRevision"`
		Procedure        string  `json:"procedure"`
		Expected         string  `json:"expected"`
		Outcome          string  `json:"outcome"`
		Proof            string  `json:"proofDigest"`
		Gate             *gateEv `json:"gate"`
		At               string  `json:"at"`
		KeyID            string  `json:"keyId"`
	}{
		r.AssignmentID, r.AssignmentDigest, r.Claim.Role, r.Claim.ID, r.Claim.Digest, r.ReviewedRevision, r.Procedure, r.Expected, r.Outcome,
		r.Evidence.ProofDigest, g, stamp(r.At), r.KeyID,
	})
}

// ApprovalManifest is what a human approves for a lights-on (CON-8) or non-switchable (PIP-9) change. It is shared
// with WI-17, which builds the same value from the proposal. Its digest is the Revision of the authz target, so
// editing and then restoring any input (which needs a new Generation) invalidates an earlier approval.
type ApprovalManifest struct {
	Forge            string
	Repo             string
	PR               int
	Generation       int
	HeadSHA          string
	ImpactRevision   string
	RecoveryRevision string
	// Callers are the affected callers (PIP-9). Their order carries no meaning.
	Callers []string
	// RolloutOrder is the order callers roll out in (PIP-9). Its order is part of the plan.
	RolloutOrder []string
}

// Digest returns 64 lowercase hex characters, the form [authz.Target].Revision requires.
func (m ApprovalManifest) Digest() string {
	rollout := slices.Clone(m.RolloutOrder)
	if rollout == nil {
		rollout = []string{}
	}
	return hexSum(canonical(approvalDomain, struct {
		Forge            string   `json:"forge"`
		Repo             string   `json:"repo"`
		PR               int      `json:"pr"`
		Generation       int      `json:"generation"`
		HeadSHA          string   `json:"headSha"`
		ImpactRevision   string   `json:"impactRevision"`
		RecoveryRevision string   `json:"recoveryRevision"`
		Callers          []string `json:"callers"`
		RolloutOrder     []string `json:"rolloutOrder"`
	}{
		m.Forge, m.Repo, m.PR, m.Generation, m.HeadSHA, m.ImpactRevision, m.RecoveryRevision,
		sortedCopy(m.Callers), rollout,
	}))
}

// areaDigest identifies one owner area in an obligation ID.
func areaDigest(paths []string) string {
	return hexSum(canonical(areaDomain, sortedCopy(paths)))
}

// Digest returns "sha256:" and the hex digest of every field of the assignment, under its own domain. Attestations and
// resolutions sign it, so a signature is bound to the exact head, PR, manifest, role, session and claim.
func (a Assignment) Digest() string {
	return "sha256:" + hexSum(canonical(assignmentDomain, struct {
		ID             string `json:"id"`
		Forge          string `json:"forge"`
		Repo           string `json:"repo"`
		PR             int    `json:"pr"`
		HeadSHA        string `json:"headSha"`
		RoundID        string `json:"roundId"`
		RoundSeq       int    `json:"roundSeq"`
		Role           string `json:"role"`
		Profile        string `json:"profile"`
		ManifestDigest string `json:"manifestDigest"`
		Purpose        string `json:"purpose"`
		ClaimRole      string `json:"claimRole"`
		ClaimID        string `json:"claimId"`
		ClaimDigest    string `json:"claimDigest"`
		Session        string `json:"session"`
	}{
		a.ID, a.Forge, string(a.Repo), a.PR, a.HeadSHA, a.RoundID, a.RoundSeq, a.Role, a.Profile, a.ManifestDigest, string(a.Purpose),
		a.ClaimRef.Role, a.ClaimRef.ID, a.ClaimRef.Digest, a.Session,
	}))
}

// Digest returns "sha256:" and the hex digest of the claim's content: its location, invariant, consequence and
// verification plan. The ID is not part of it: a claim instance is the role, the ID and this digest.
func (c Claim) Digest() string {
	return "sha256:" + hexSum(canonical(claimDomain, struct {
		Path             string `json:"path"`
		StartLine        int    `json:"startLine"`
		EndLine          int    `json:"endLine"`
		Invariant        string `json:"invariant"`
		Consequence      string `json:"consequence"`
		VerificationPlan string `json:"verificationPlan"`
	}{c.Path, c.StartLine, c.EndLine, c.Invariant, c.Consequence, c.VerificationPlan}))
}

// RepairedRef returns the entry of [Attestation].Repaired that repairs one claim instance: "<id>#<claim digest>".
func RepairedRef(c ClaimRef) string { return c.ID + "#" + c.Digest }
