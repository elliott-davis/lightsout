// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

package install

import (
	"bytes"
	"cmp"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"slices"
	"time"

	"github.com/elliott-davis/lightsout/internal/yamlsafe"
)

// Domain separators of the two canonical encodings. Bump the version in the text when an encoding changes, so a
// digest or signature made under the old one can never verify under the new one.
const (
	tupleDomain  = "lightsout/qualification-tuple/v2\n"
	recordDomain = "lightsout/qualification-record/v1\n"
)

// maxRecordSize is the largest qualification record Admit reads, in bytes.
const maxRecordSize = 64 << 10

// maxEvidence is the most evidence digests a record may carry.
const maxEvidence = 64

// ResultPass is the only result that admits a role.
const (
	ResultPass = "pass"
	ResultFail = "fail"
)

// ErrNotAdmitted is wrapped by every [*AdmissionError]. Anything that is not nil from Admit means the role must not run.
var ErrNotAdmitted = errors.New("install: role is not admitted")

// ErrRecordNotFound is what a [QualificationStore] returns for a digest it does not hold.
var ErrRecordNotFound = errors.New("install: qualification record not found")

// Reason says why a role was not admitted.
type Reason string

// Admission denial reasons.
const (
	ReasonUnknownRole    Reason = "unknown-role"    // the role is not enabled
	ReasonMissing        Reason = "missing"         // the store has no record for the configured digest
	ReasonDigestMismatch Reason = "digest-mismatch" // the bytes do not hash to the configured digest
	ReasonMalformed      Reason = "malformed"       // the record is not strict JSON of the record shape
	ReasonUnsigned       Reason = "unsigned"        // the record carries no signature
	ReasonUnknownKey     Reason = "unknown-key"     // keyId is not a configured qualifier key
	ReasonBadSignature   Reason = "bad-signature"   // the signature does not verify
	ReasonFailed         Reason = "failed"          // the qualification result is not a pass
	ReasonTupleMismatch  Reason = "tuple-mismatch"  // the record qualified a different tuple
)

// AdmissionError is the typed denial of [Config.Admit]. It wraps [ErrNotAdmitted].
type AdmissionError struct {
	Role   string
	Reason Reason
	Detail string // escaped and bounded
}

// Error implements error.
func (e *AdmissionError) Error() string {
	s := fmt.Sprintf("role %s is not admitted: %s", yamlsafe.Quote(e.Role), e.Reason)
	if e.Detail != "" {
		s += ": " + e.Detail
	}
	return s
}

// Unwrap returns [ErrNotAdmitted].
func (e *AdmissionError) Unwrap() error { return ErrNotAdmitted }

func deny(role string, reason Reason, format string, args ...any) *AdmissionError {
	return &AdmissionError{Role: role, Reason: reason, Detail: yamlsafe.Sanitize(fmt.Sprintf(format, args...))}
}

// QualificationStore is a content-addressed store of qualification records, such as an offline bundle or a local
// store. Get returns the bytes stored under digest ("sha256:" and 64 hex digits), or [ErrRecordNotFound]. Admit
// re-hashes what it gets, so the store is not trusted.
type QualificationStore interface {
	Get(ctx context.Context, digest string) ([]byte, error)
}

// QualificationRecord is the signed result of qualifying one role's tuple (NFR-2).
type QualificationRecord struct {
	// TupleDigest is the [RoleProfile.TupleDigest] that was qualified.
	TupleDigest string `json:"tupleDigest"`
	// SuiteRevision is the revision (40 or 64 hex digits) of the qualification suite that ran.
	SuiteRevision string `json:"suiteRevision"`
	// Result is "pass" or "fail".
	Result string `json:"result"`
	// Evidence are digests of the evidence the run produced.
	Evidence []string `json:"evidence"`
	// QualifiedAt is an RFC 3339 time.
	QualifiedAt string `json:"qualifiedAt"`
	// KeyID names the configured qualifier key that signed the record.
	KeyID string `json:"keyId"`
	// Signature is the base64 ed25519 signature over [QualificationRecord.SigningBytes].
	Signature string `json:"signature"`
}

// SigningBytes returns the canonical bytes the signature covers: a domain prefix and the JSON of every field except
// the signature, in the order of the struct. It does not depend on how the record was spelled in the store.
func (r QualificationRecord) SigningBytes() []byte {
	evidence := r.Evidence
	if evidence == nil {
		evidence = []string{}
	}
	data, err := json.Marshal(struct {
		TupleDigest   string   `json:"tupleDigest"`
		SuiteRevision string   `json:"suiteRevision"`
		Result        string   `json:"result"`
		Evidence      []string `json:"evidence"`
		QualifiedAt   string   `json:"qualifiedAt"`
		KeyID         string   `json:"keyId"`
	}{r.TupleDigest, r.SuiteRevision, r.Result, evidence, r.QualifiedAt, r.KeyID})
	if err != nil {
		panic("install: marshal qualification record: " + err.Error()) // cannot happen: only strings
	}
	return append([]byte(recordDomain), data...)
}

// Marshal returns the record as stored: JSON with every field. Its digest is [RecordDigest].
func (r QualificationRecord) Marshal() ([]byte, error) {
	if r.Evidence == nil {
		r.Evidence = []string{}
	}
	return json.Marshal(r)
}

// RecordDigest returns the digest a role's qualification field holds for the record bytes: "sha256:" and hex.
func RecordDigest(record []byte) string {
	sum := sha256.Sum256(record)
	return "sha256:" + hex.EncodeToString(sum[:])
}

var (
	digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	keyIDPattern  = regexp.MustCompile(`^[a-z][a-z0-9-]{0,63}$`)
)

// recordFields are the keys of a record, all required.
func recordFields() []string {
	return []string{"tupleDigest", "suiteRevision", "result", "evidence", "qualifiedAt", "keyId", "signature"}
}

// decodeRecord decodes a record strictly: one JSON object with exactly the record's fields, no duplicate key, no
// unknown field, no trailing data and well-formed values.
func decodeRecord(data []byte) (QualificationRecord, error) {
	var rec QualificationRecord
	if len(data) > maxRecordSize {
		return rec, fmt.Errorf("record is %d bytes, limit is %d", len(data), maxRecordSize)
	}
	if err := checkTopLevelKeys(data); err != nil {
		return rec, err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&rec); err != nil {
		return rec, fmt.Errorf("decode record: %w", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return rec, errors.New("unexpected data after the record")
	}
	switch {
	case !digestPattern.MatchString(rec.TupleDigest):
		return rec, errors.New("tupleDigest is not a sha256 digest")
	case !revisionPattern.MatchString(rec.SuiteRevision):
		return rec, errors.New("suiteRevision is not a full commit ID")
	case rec.Result != ResultPass && rec.Result != ResultFail:
		return rec, errors.New(`result must be "pass" or "fail"`)
	case len(rec.Evidence) > maxEvidence:
		return rec, fmt.Errorf("record has more than %d evidence digests", maxEvidence)
	case !keyIDPattern.MatchString(rec.KeyID):
		return rec, errors.New("keyId is not a key ID")
	}
	for _, e := range rec.Evidence {
		if !digestPattern.MatchString(e) {
			return rec, errors.New("evidence entry is not a sha256 digest")
		}
	}
	if _, err := time.Parse(time.RFC3339, rec.QualifiedAt); err != nil {
		return rec, errors.New("qualifiedAt is not an RFC 3339 time")
	}
	return rec, nil
}

// checkTopLevelKeys requires the record to be an object whose keys are exactly recordFields, each once. The JSON
// decoder keeps the last of a duplicate key, which would let two readers see different records.
func checkTopLevelKeys(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return errors.New("record is not a JSON object")
	}
	seen := map[string]bool{}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return fmt.Errorf("read record: %w", err)
		}
		key, _ := tok.(string)
		if !slices.Contains(recordFields(), key) {
			return fmt.Errorf("unknown field %s", yamlsafe.Quote(key))
		}
		if seen[key] {
			return fmt.Errorf("duplicate field %s", yamlsafe.Quote(key))
		}
		seen[key] = true
		var skip json.RawMessage
		if err := dec.Decode(&skip); err != nil {
			return fmt.Errorf("read record: %w", err)
		}
	}
	for _, f := range recordFields() {
		if !seen[f] {
			return fmt.Errorf("missing field %s", yamlsafe.Quote(f))
		}
	}
	return nil
}

// TupleDigest returns the versioned digest of everything that identifies what was qualified: the role name, the
// deployment manifest digest, the template digest, the runtime image, the harness name, version and digest, the model
// name and revision, the endpoint digest, each tool's name, version and permissions, the egress hosts and the gateway
// credentials. It is "sha256:" and hex over
//
//	"lightsout/qualification-tuple/v2\n" + JSON
//
// where the JSON is one object with the fields in the order below, no whitespace, and no HTML escaping:
//
//	{"role":…,"manifest":…,"template":…,"image":…,"harness":{"name":…,"version":…,"digest":…},
//	 "model":{"name":…,"revision":…},"endpoint":…,"tools":[{"name":…,"version":…,"permissions":[…]}],
//	 "egress":[…],"credentials":[{"host":…,"name":…,"operations":[…]}]}
//
// Tools are sorted by name, then version, then permissions; permissions, egress hosts and credential operations are
// sorted; credentials are sorted by host, then name, then operations. Listing order therefore never matters and
// changing any element does. Only the qualification digest itself is outside the tuple.
func (r RoleProfile) TupleDigest() string {
	type tool struct {
		Name        string   `json:"name"`
		Version     string   `json:"version"`
		Permissions []string `json:"permissions"`
	}
	type credential struct {
		Host       string   `json:"host"`
		Name       string   `json:"name"`
		Operations []string `json:"operations"`
	}
	sorted := func(in []string) []string {
		out := slices.Clone(in)
		if out == nil {
			out = []string{}
		}
		slices.Sort(out)
		return out
	}
	tools := make([]tool, len(r.Profile.Tools))
	for i, t := range r.Profile.Tools {
		tools[i] = tool{t.Name, t.Version, sorted(t.Permissions)}
	}
	slices.SortFunc(tools, func(a, b tool) int {
		return cmp.Or(cmp.Compare(a.Name, b.Name), cmp.Compare(a.Version, b.Version),
			slices.Compare(a.Permissions, b.Permissions))
	})
	creds := make([]credential, len(r.GatewayCredentials))
	for i, g := range r.GatewayCredentials {
		creds[i] = credential{g.Host, g.Name, sorted(g.Operations)}
	}
	slices.SortFunc(creds, func(a, b credential) int {
		return cmp.Or(cmp.Compare(a.Host, b.Host), cmp.Compare(a.Name, b.Name), slices.Compare(a.Operations, b.Operations))
	})
	p := r.Profile
	type harness struct {
		Name    string `json:"name"`
		Version string `json:"version"`
		Digest  string `json:"digest"`
	}
	type model struct {
		Name     string `json:"name"`
		Revision string `json:"revision"`
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	err := enc.Encode(struct {
		Role     string       `json:"role"`
		Manifest string       `json:"manifest"`
		Tmpl     string       `json:"template"`
		Image    string       `json:"image"`
		Harness  harness      `json:"harness"`
		Model    model        `json:"model"`
		Endpoint string       `json:"endpoint"`
		Tools    []tool       `json:"tools"`
		Egress   []string     `json:"egress"`
		Creds    []credential `json:"credentials"`
	}{
		Role: r.Name, Manifest: r.Manifest, Tmpl: p.Template.Digest, Image: p.Runtime.Image,
		Harness:  harness{p.Harness.Name, p.Harness.Version, p.Harness.Digest},
		Model:    model{p.Model.Name, p.Model.Revision},
		Endpoint: p.Endpoint.Digest, Tools: tools, Egress: sorted(r.Egress.Hosts), Creds: creds,
	})
	if err != nil {
		panic("install: marshal tuple: " + err.Error()) // cannot happen: only strings
	}
	sum := sha256.Sum256(append([]byte(tupleDomain), bytes.TrimSuffix(buf.Bytes(), []byte("\n"))...))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// Admit decides whether role may be scheduled (NFR-2). It returns nil only for a genuine, current pass, and a
// [*AdmissionError] (wrapping [ErrNotAdmitted]) for every denial. Any other non-nil error, such as a store failure
// or a cancelled context, also means the role is not admitted: callers must treat every non-nil result as a denial.
//
//  1. Fetch the record by the role's configured qualification digest and re-hash the bytes.
//  2. Decode the record strictly.
//  3. Verify its ed25519 signature with the configured qualifier key it names.
//  4. Recompute the role's tuple digest from the current config.
//  5. Require result "pass" and an equal tuple digest.
//
// Changing any part of the tuple, such as one tool permission or the role template, therefore invalidates a genuine
// pass: the record still verifies but qualified a different tuple.
func (c *Config) Admit(ctx context.Context, role string, store QualificationStore) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("admit role: %w", err)
	}
	if store == nil {
		return errors.New("admit role: nil qualification store")
	}
	profile, ok := c.Role(role)
	if !ok {
		return deny(role, ReasonUnknownRole, "the role is not enabled")
	}

	data, err := store.Get(ctx, profile.Qualification)
	switch {
	case errors.Is(err, ErrRecordNotFound):
		return deny(role, ReasonMissing, "no qualification record for %s", profile.Qualification)
	case err != nil:
		return fmt.Errorf("admit role: fetch qualification record: %w", err)
	}
	if len(data) > maxRecordSize {
		// Checked before hashing: a hostile store must not make Admit hash an unbounded blob.
		return deny(role, ReasonMalformed, "record is %d bytes, limit is %d", len(data), maxRecordSize)
	}
	if got := RecordDigest(data); got != profile.Qualification {
		return deny(role, ReasonDigestMismatch, "the record hashes to %s, the config pins %s", got, profile.Qualification)
	}

	rec, err := decodeRecord(data)
	if err != nil {
		return deny(role, ReasonMalformed, "%s", err.Error())
	}
	if rec.Signature == "" {
		return deny(role, ReasonUnsigned, "the record carries no signature")
	}
	pub, ok := c.keys[rec.KeyID]
	if !ok {
		return deny(role, ReasonUnknownKey, "%s is not a configured qualifier key", yamlsafe.Quote(rec.KeyID))
	}
	sig, err := base64.StdEncoding.Strict().DecodeString(rec.Signature)
	if !sigBase64.MatchString(rec.Signature) || err != nil || len(sig) != ed25519.SignatureSize || !ed25519.Verify(pub, rec.SigningBytes(), sig) {
		return deny(role, ReasonBadSignature, "the signature does not verify under key %s", yamlsafe.Quote(rec.KeyID))
	}

	if rec.Result != ResultPass {
		return deny(role, ReasonFailed, "the qualification result is %s", yamlsafe.Quote(rec.Result))
	}
	if want := profile.TupleDigest(); rec.TupleDigest != want {
		return deny(role, ReasonTupleMismatch, "the record qualified tuple %s, the config's tuple is %s", rec.TupleDigest, want)
	}
	return nil
}
