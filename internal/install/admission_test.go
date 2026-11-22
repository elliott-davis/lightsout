// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

package install_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/elliott-davis/lightsout/internal/install"
	"github.com/elliott-davis/lightsout/internal/install/installtest"
)

// qualDigest returns the qualification digest the fixture holds for role.
func qualDigest(t *testing.T, doc, role string) string {
	t.Helper()
	cfg := mustParse(t, doc)
	r, ok := cfg.Role(role)
	if !ok {
		t.Fatalf("no role %s", role)
	}
	return r.Qualification
}

// fixtureStore holds the genuine signed pass record of every fixture role.
func fixtureStore(t *testing.T) *installtest.Store {
	t.Helper()
	cfg := mustParse(t, validYAML(t))
	store := installtest.NewStore()
	for _, name := range fixtureRoles {
		r, _ := cfg.Role(name)
		data, _ := installtest.Encode(qualifier().Record(r.TupleDigest(), install.ResultPass))
		store.Put(data)
	}
	return store
}

// wantDenied asserts err is a typed admission denial with reason.
func wantDenied(t *testing.T, err error, reason install.Reason) {
	t.Helper()
	var ae *install.AdmissionError
	if !errors.As(err, &ae) || !errors.Is(err, install.ErrNotAdmitted) {
		t.Fatalf("err = %v, want an admission denial %q", err, reason)
	}
	if ae.Reason != reason {
		t.Errorf("reason = %q, want %q (%v)", ae.Reason, reason, err)
	}
}

// configWithRecord returns a config whose coder role pins the digest of data, and a store holding data.
func configWithRecord(t *testing.T, doc string, data []byte) (*install.Config, *installtest.Store) {
	t.Helper()
	store := installtest.NewStore()
	digest := store.Put(data)
	doc = strings.Replace(doc, qualDigest(t, doc, "coder"), digest, 1)
	return mustParse(t, doc), store
}

func TestAdmit_GenuinePass(t *testing.T) { // NFR-2
	t.Parallel()
	cfg := mustParse(t, validYAML(t))
	store := fixtureStore(t)
	for _, role := range fixtureRoles {
		if err := cfg.Admit(t.Context(), role, store); err != nil {
			t.Errorf("Admit(%s) = %v", role, err)
		}
	}
}

func TestAdmit_Denials(t *testing.T) { // NFR-2, SEC-11
	t.Parallel()
	valid := validYAML(t)
	cfg := mustParse(t, valid)
	coder, _ := cfg.Role("coder")
	tuple := coder.TupleDigest()

	tests := map[string]struct {
		run    func(t *testing.T) error
		reason install.Reason
	}{
		"missing record": {func(t *testing.T) error {
			t.Helper()
			return cfg.Admit(t.Context(), "coder", installtest.NewStore())
		}, install.ReasonMissing},
		"role that is not enabled": {func(t *testing.T) error {
			t.Helper()
			return cfg.Admit(t.Context(), "ghost", fixtureStore(t))
		}, install.ReasonUnknownRole},
		"self-signed pass under an unknown key": {func(t *testing.T) error {
			t.Helper()
			rogue := installtest.NewSigner("rogue", "rogue")
			data, _ := installtest.Encode(rogue.Record(tuple, install.ResultPass))
			c, store := configWithRecord(t, valid, data)
			return c.Admit(t.Context(), "coder", store)
		}, install.ReasonUnknownKey},
		"tampered record": {func(t *testing.T) error {
			t.Helper()
			good, digest := installtest.Encode(qualifier().Record(tuple, install.ResultFail))
			tampered := bytes.Replace(good, []byte(`"result":"fail"`), []byte(`"result":"pass"`), 1)
			if bytes.Equal(tampered, good) {
				t.Fatal("the tamper did not change the record")
			}
			store := installtest.NewStore()
			store.PutAs(digest, tampered) // a store that returns other bytes under the old digest
			c := mustParse(t, strings.Replace(valid, qualDigest(t, valid, "coder"), digest, 1))
			return c.Admit(t.Context(), "coder", store)
		}, install.ReasonDigestMismatch},
		"bad signature": {func(t *testing.T) error {
			t.Helper()
			forger := installtest.NewSigner("q1", "not-the-fixture-key") // a known key ID, someone else's key
			data, _ := installtest.Encode(forger.Record(tuple, install.ResultPass))
			c, store := configWithRecord(t, valid, data)
			return c.Admit(t.Context(), "coder", store)
		}, install.ReasonBadSignature},
		"signature over another record": {func(t *testing.T) error {
			t.Helper()
			rec := qualifier().Record(tuple, install.ResultPass)
			other := qualifier().Record(tuple, install.ResultFail)
			rec.Signature = other.Signature // a genuine signature, of a different record
			data, _ := installtest.Encode(rec)
			c, store := configWithRecord(t, valid, data)
			return c.Admit(t.Context(), "coder", store)
		}, install.ReasonBadSignature},
		"signature not base64": {func(t *testing.T) error {
			t.Helper()
			rec := qualifier().Record(tuple, install.ResultPass)
			rec.Signature = "not base64!"
			data, _ := installtest.Encode(rec)
			c, store := configWithRecord(t, valid, data)
			return c.Admit(t.Context(), "coder", store)
		}, install.ReasonBadSignature},
		"unsigned": {func(t *testing.T) error {
			t.Helper()
			rec := qualifier().Record(tuple, install.ResultPass)
			rec.Signature = ""
			data, _ := installtest.Encode(rec)
			c, store := configWithRecord(t, valid, data)
			return c.Admit(t.Context(), "coder", store)
		}, install.ReasonUnsigned},
		"failed result": {func(t *testing.T) error {
			t.Helper()
			data, _ := installtest.Encode(qualifier().Record(tuple, install.ResultFail))
			c, store := configWithRecord(t, valid, data)
			return c.Admit(t.Context(), "coder", store)
		}, install.ReasonFailed},
		"fields changed after signing": {func(t *testing.T) error {
			t.Helper()
			rec := qualifier().Record(tuple, install.ResultFail)
			rec.Result = install.ResultPass // flipped without re-signing
			data, _ := installtest.Encode(rec)
			c, store := configWithRecord(t, valid, data)
			return c.Admit(t.Context(), "coder", store)
		}, install.ReasonBadSignature},
		"template-only change": {func(t *testing.T) error {
			t.Helper()
			store := fixtureStore(t)
			doc := replaceOnce(t, valid, "sha256:1111111111111111111111111111111111111111111111111111111111111111", "sha256:9999999999999999999999999999999999999999999999999999999999999999")
			return mustParse(t, doc).Admit(t.Context(), "coder", store)
		}, install.ReasonTupleMismatch},
		"tool-permission-only change": {func(t *testing.T) error {
			t.Helper()
			store := fixtureStore(t)
			doc := replaceOnce(t, valid, `permissions: ["repo:read", "branch:push-own"]`, `permissions: ["repo:read", "branch:push-own", "issues:read"]`)
			return mustParse(t, doc).Admit(t.Context(), "coder", store)
		}, install.ReasonTupleMismatch},
		"image-only change": {func(t *testing.T) error {
			t.Helper()
			store := fixtureStore(t)
			doc := strings.Replace(valid, "@sha256:2222222222222222222222222222222222222222222222222222222222222222", "@sha256:8888888888888888888888888888888888888888888888888888888888888888", 1)
			return mustParse(t, doc).Admit(t.Context(), "coder", store)
		}, install.ReasonTupleMismatch},
		"model-only change": {func(t *testing.T) error {
			t.Helper()
			store := fixtureStore(t)
			doc := strings.Replace(valid, `model: { name: "model-a", revision: "2026-10-01" }`, `model: { name: "model-a", revision: "2026-11-01" }`, 1)
			return mustParse(t, doc).Admit(t.Context(), "coder", store)
		}, install.ReasonTupleMismatch},
		"another role's genuine pass": {func(t *testing.T) error {
			t.Helper()
			// The pr-reviewer's genuine record, pinned by the coder: it qualified another tuple.
			r, _ := cfg.Role("pr-reviewer")
			data, _ := installtest.Encode(qualifier().Record(r.TupleDigest(), install.ResultPass))
			c, store := configWithRecord(t, valid, data)
			return c.Admit(t.Context(), "coder", store)
		}, install.ReasonTupleMismatch},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			wantDenied(t, tt.run(t), tt.reason)
		})
	}
}

func TestAdmit_MalformedRecords(t *testing.T) { // NFR-2, SEC-1
	t.Parallel()
	valid := validYAML(t)
	cfg := mustParse(t, valid)
	coder, _ := cfg.Role("coder")
	good, _ := installtest.Encode(qualifier().Record(coder.TupleDigest(), install.ResultPass))
	goodText := string(good)
	if err := admitRecord(t, valid, good); err != nil {
		t.Fatalf("the base record is rejected: %v", err)
	}
	tests := map[string]string{
		"not json":              "pass",
		"empty":                 "",
		"array":                 "[]",
		"empty object":          "{}",
		"trailing data":         goodText + ` {}`,
		"trailing garbage":      goodText + "x",
		"unknown field":         strings.Replace(goodText, `{"tupleDigest"`, `{"admin":true,"tupleDigest"`, 1),
		"duplicate field":       strings.Replace(goodText, `"result":"pass"`, `"result":"fail","result":"pass"`, 1),
		"duplicate key id":      strings.Replace(goodText, `"keyId":"q1"`, `"keyId":"q1","keyId":"q1"`, 1),
		"missing signature":     strings.Replace(goodText, `,"signature":`+goodText[strings.Index(goodText, `"signature":`)+len(`"signature":`):strings.LastIndex(goodText, "}")], "", 1),
		"result not pass/fail":  strings.Replace(goodText, `"result":"pass"`, `"result":"PASS"`, 1),
		"bad tuple digest":      strings.Replace(goodText, `"tupleDigest":"sha256:`, `"tupleDigest":"sha256:zz`, 1),
		"bad time":              strings.Replace(goodText, `2026-11-21T00:00:00Z`, `yesterday`, 1),
		"bad suite revision":    strings.Replace(goodText, installtest.SuiteRevision, "main", 1),
		"bad evidence":          strings.Replace(goodText, `"evidence":["sha256:`, `"evidence":["md5:`, 1),
		"evidence not an array": strings.Replace(goodText, `"evidence":["sha256:`+strings.Repeat("e", 64)+`"]`, `"evidence":"x"`, 1),
		"huge":                  `{"tupleDigest":"` + strings.Repeat("x", 100<<10) + `"}`,
		"bad key id":            strings.Replace(goodText, `"keyId":"q1"`, `"keyId":"Q1 !"`, 1),
		"empty key id":          strings.Replace(goodText, `"keyId":"q1"`, `"keyId":""`, 1),
		"65 evidence": strings.Replace(goodText, `"evidence":["sha256:`+strings.Repeat("e", 64)+`"]`,
			`"evidence":["sha256:`+strings.Join(slices.Repeat([]string{strings.Repeat("e", 64)}, 65), `","sha256:`)+`"]`, 1),
	}
	for name, text := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if name != "empty" && name != "not json" && name != "array" && text == goodText {
				t.Fatal("the mutation did not change the record")
			}
			wantDenied(t, admitRecord(t, valid, []byte(text)), install.ReasonMalformed)
		})
	}
}

// admitRecord admits the coder role of doc with its qualification pinned to record.
func admitRecord(t *testing.T, doc string, record []byte) error {
	t.Helper()
	c, store := configWithRecord(t, doc, record)
	err := c.Admit(t.Context(), "coder", store)
	return err
}

type failingStore struct{ err error }

func (s failingStore) Get(context.Context, string) ([]byte, error) { return nil, s.err }

func TestAdmit_StoreFailureIsNotAdmitted(t *testing.T) { // NFR-2
	t.Parallel()
	cfg := mustParse(t, validYAML(t))
	boom := errors.New("disk on fire")
	err := cfg.Admit(t.Context(), "coder", failingStore{boom})
	if err == nil || !errors.Is(err, boom) {
		t.Errorf("Admit = %v, want the store's error", err)
	}
	var ae *install.AdmissionError
	if errors.As(err, &ae) {
		t.Errorf("a store failure is not a verdict on the record: %v", err)
	}
	if err := cfg.Admit(t.Context(), "coder", nil); err == nil {
		t.Error("Admit with a nil store succeeded")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := cfg.Admit(ctx, "coder", fixtureStore(t)); err == nil {
		t.Error("Admit with a cancelled context succeeded")
	}
}

func TestAdmit_ErrorTextIsEscaped(t *testing.T) { // SEC-1
	t.Parallel()
	cfg := mustParse(t, validYAML(t))
	err := cfg.Admit(t.Context(), "evil\n##[error]x", installtest.NewStore())
	wantDenied(t, err, install.ReasonUnknownRole)
	if strings.ContainsAny(err.Error(), "\n#") {
		t.Errorf("error text %q carries a newline or '#'", err)
	}
}

// tupleGolden pins the tuple digest of the fixture's coder role: its canonical encoding is a stored format.
const tupleGolden = "sha256:224c5c90be84a5ca40d74e60563a057fe9eb1cc40667d6e9c0b94a7f175edd3a"

func TestTupleDigest_Golden(t *testing.T) { // NFR-2, AGT-7
	t.Parallel()
	cfg := mustParse(t, validYAML(t))
	coder, _ := cfg.Role("coder")
	if got := coder.TupleDigest(); got != tupleGolden {
		t.Errorf("coder tuple digest = %s, want %s: the canonical encoding changed, which invalidates every qualification record", got, tupleGolden)
	}
	// The documented encoding, written out by hand: a domain line, then compact JSON with the fields in this
	// order, tools sorted by name and permissions sorted.
	h := func(c string) string { return "sha256:" + strings.Repeat(c, 64) }
	encoding := `{"role":"coder","manifest":"` + h("a") + `","template":"` + h("1") + `","image":"registry.internal/agent@` + h("2") +
		`","harness":{"name":"claude-code","version":"2.1.0","digest":"` + h("3") + `"},` +
		`"model":{"name":"model-a","revision":"2026-10-01"},"endpoint":"` + h("4") + `",` +
		`"tools":[{"name":"git","version":"2.47.0","permissions":["branch:push-own","repo:read"]},` +
		`{"name":"go","version":"1.27","permissions":["repo:read"]}],` +
		`"egress":["models.internal:443"],` +
		`"credentials":[{"host":"models.internal:443","name":"model-key","operations":["POST /v1/messages"]}]}`
	sum := sha256.Sum256([]byte("lightsout/qualification-tuple/v2\n" + encoding))
	if want := "sha256:" + hex.EncodeToString(sum[:]); coder.TupleDigest() != want {
		t.Errorf("the tuple digest is not sha256 of the documented encoding: got %s, want %s", coder.TupleDigest(), want)
	}
}

func TestTupleDigest_EveryFieldChangesIt(t *testing.T) { // NFR-2, AGT-7
	t.Parallel()
	cfg := mustParse(t, validYAML(t))
	base, _ := cfg.Role("coder")
	want := base.TupleDigest()
	other := "sha256:" + strings.Repeat("7", 64)
	mutations := map[string]func(r *install.RoleProfile){
		"role name":       func(r *install.RoleProfile) { r.Name = "coder2" },
		"template digest": func(r *install.RoleProfile) { r.Profile.Template.Digest = other },
		"runtime image":   func(r *install.RoleProfile) { r.Profile.Runtime.Image = "registry.internal/agent@" + other },
		"harness name":    func(r *install.RoleProfile) { r.Profile.Harness.Name = "codex" },
		"harness version": func(r *install.RoleProfile) { r.Profile.Harness.Version = "2.1.1" },
		"harness digest":  func(r *install.RoleProfile) { r.Profile.Harness.Digest = other },
		"model name":      func(r *install.RoleProfile) { r.Profile.Model.Name = "model-b" },
		"model revision":  func(r *install.RoleProfile) { r.Profile.Model.Revision = "2026-10-02" },
		"endpoint digest": func(r *install.RoleProfile) { r.Profile.Endpoint.Digest = other },
		"tool name":       func(r *install.RoleProfile) { r.Profile.Tools[0].Name = "hg" },
		"tool version":    func(r *install.RoleProfile) { r.Profile.Tools[0].Version = "2.47.1" },
		"tool permission": func(r *install.RoleProfile) { r.Profile.Tools[0].Permissions[1] = "branch:push-any" },
		"tool permission +": func(r *install.RoleProfile) {
			r.Profile.Tools[0].Permissions = append(r.Profile.Tools[0].Permissions, "x:y")
		},
		"tool permission -": func(r *install.RoleProfile) { r.Profile.Tools[0].Permissions = r.Profile.Tools[0].Permissions[:1] },
		"tool added": func(r *install.RoleProfile) {
			r.Profile.Tools = append(r.Profile.Tools, install.Tool{Name: "make", Version: "4", Permissions: []string{}})
		},
		"tool removed": func(r *install.RoleProfile) { r.Profile.Tools = r.Profile.Tools[:1] },
		"permission moved": func(r *install.RoleProfile) {
			r.Profile.Tools[0].Permissions, r.Profile.Tools[1].Permissions = r.Profile.Tools[1].Permissions, r.Profile.Tools[0].Permissions
		},
		"tool version swap": func(r *install.RoleProfile) {
			r.Profile.Tools[0].Version, r.Profile.Tools[1].Version = r.Profile.Tools[1].Version, r.Profile.Tools[0].Version
		},
		"version into model": func(r *install.RoleProfile) {
			r.Profile.Harness.Version, r.Profile.Model.Revision = r.Profile.Model.Revision, r.Profile.Harness.Version
		},
	}
	for name, mutate := range mutations {
		r, _ := cfg.Role("coder")
		mutate(&r)
		if r.TupleDigest() == want {
			t.Errorf("changing the %s does not change the tuple digest", name)
		}
	}
	// The network profile and the deployment manifest are in the tuple (NFR-2 "pinned deployment profile").
	for name, mutate := range map[string]func(r *install.RoleProfile){
		"egress host":        func(r *install.RoleProfile) { r.Egress.Hosts = []string{"elsewhere.internal:443"} },
		"egress host added":  func(r *install.RoleProfile) { r.Egress.Hosts = append(r.Egress.Hosts, "extra.internal:443") },
		"credential removed": func(r *install.RoleProfile) { r.GatewayCredentials = nil },
		"credential host":    func(r *install.RoleProfile) { r.GatewayCredentials[0].Host = "elsewhere.internal:443" },
		"credential name":    func(r *install.RoleProfile) { r.GatewayCredentials[0].Name = "other-key" },
		"credential op":      func(r *install.RoleProfile) { r.GatewayCredentials[0].Operations = []string{"GET /v1/models"} },
		"credential op +": func(r *install.RoleProfile) {
			r.GatewayCredentials[0].Operations = append(r.GatewayCredentials[0].Operations, "GET /v1/models")
		},
		"deployment manifest": func(r *install.RoleProfile) { r.Manifest = other },
	} {
		r, _ := cfg.Role("coder")
		mutate(&r)
		if r.TupleDigest() == want {
			t.Errorf("changing the %s does not change the tuple digest", name)
		}
	}
	// Only the qualification digest is outside the tuple.
	r, _ := cfg.Role("coder")
	r.Qualification = other
	if r.TupleDigest() != want {
		t.Error("the qualification digest changed the tuple digest")
	}
	// Egress hosts and credential operations are sets: their order does not matter.
	r, _ = cfg.Role("coder")
	r.Egress.Hosts = []string{"models.internal:443"}
	r.GatewayCredentials = append(r.GatewayCredentials, install.GatewayCredential{Name: "a", Host: "models.internal:443", Operations: []string{"GET /b", "GET /a"}})
	r2 := r
	r2.GatewayCredentials = []install.GatewayCredential{r.GatewayCredentials[1], r.GatewayCredentials[0]}
	r2.GatewayCredentials[0].Operations = []string{"GET /a", "GET /b"}
	if r.TupleDigest() != r2.TupleDigest() {
		t.Error("the order of credentials or their operations changed the tuple digest")
	}
	// Order of tools and permissions does not matter.
	r, _ = cfg.Role("coder")
	slices.Reverse(r.Profile.Tools)
	slices.Reverse(r.Profile.Tools[1].Permissions)
	if r.TupleDigest() != want {
		t.Error("the order of tools or permissions changed the tuple digest")
	}
	// Egress hosts are a set: their order does not matter, their content does.
	two, swapped := base, base
	two.Egress.Hosts = []string{"a.internal:443", "b.internal:443"}
	swapped.Egress.Hosts = []string{"b.internal:443", "a.internal:443"}
	if two.TupleDigest() != swapped.TupleDigest() {
		t.Error("the order of egress hosts changed the tuple digest")
	}
	// Nil and empty lists are the same: no egress, no credentials, no operations, no tools.
	n1, n2 := base, base
	n1.Egress.Hosts, n1.GatewayCredentials, n1.Profile.Tools = nil, nil, nil
	n2.Egress.Hosts, n2.GatewayCredentials, n2.Profile.Tools = []string{}, []install.GatewayCredential{}, []install.Tool{}
	if n1.TupleDigest() != n2.TupleDigest() {
		t.Error("nil and empty egress, credentials or tools differ")
	}
	c1, c2 := base, base
	c1.GatewayCredentials = []install.GatewayCredential{{Name: "k", Host: "h:1", Operations: nil}}
	c2.GatewayCredentials = []install.GatewayCredential{{Name: "k", Host: "h:1", Operations: []string{}}}
	if c1.TupleDigest() != c2.TupleDigest() {
		t.Error("nil and empty credential operations differ")
	}
	// A nil and an empty permission list are the same tool.
	e1, e2 := base, base
	e1.Profile.Tools = []install.Tool{{Name: "t", Version: "1", Permissions: nil}}
	e2.Profile.Tools = []install.Tool{{Name: "t", Version: "1", Permissions: []string{}}}
	if e1.TupleDigest() != e2.TupleDigest() {
		t.Error("nil and empty permissions differ")
	}
}

func TestSigningBytes(t *testing.T) { // NFR-2
	t.Parallel()
	rec := qualifier().Record("sha256:"+strings.Repeat("a", 64), install.ResultPass)
	base := string(rec.SigningBytes())
	if !strings.HasPrefix(base, "lightsout/qualification-record/v1\n{") || strings.Contains(base, "signature") {
		t.Errorf("SigningBytes = %q", base)
	}
	for name, mutate := range map[string]func(r *install.QualificationRecord){
		"tuple":    func(r *install.QualificationRecord) { r.TupleDigest = "sha256:" + strings.Repeat("b", 64) },
		"suite":    func(r *install.QualificationRecord) { r.SuiteRevision = strings.Repeat("1", 40) },
		"result":   func(r *install.QualificationRecord) { r.Result = install.ResultFail },
		"evidence": func(r *install.QualificationRecord) { r.Evidence = nil },
		"time":     func(r *install.QualificationRecord) { r.QualifiedAt = "2026-11-22T00:00:00Z" },
		"key":      func(r *install.QualificationRecord) { r.KeyID = "q2" },
	} {
		r := rec
		mutate(&r)
		if string(r.SigningBytes()) == base {
			t.Errorf("the signature does not cover %s", name)
		}
	}
	r := rec
	r.Signature = "different"
	if diff := cmp.Diff(base, string(r.SigningBytes())); diff != "" {
		t.Error("the signature covers itself")
	}
}
