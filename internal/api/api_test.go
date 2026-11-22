// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

package api_test

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/elliott-davis/lightsout/internal/api"
	"github.com/elliott-davis/lightsout/internal/audit"
	"github.com/elliott-davis/lightsout/internal/forge"
	"github.com/elliott-davis/lightsout/internal/forge/github"
	"github.com/elliott-davis/lightsout/internal/store"
	"github.com/elliott-davis/lightsout/internal/store/memstore"
)

const (
	secretA = "secret-current"
	secretB = "secret-rotated-in"
	marker  = "ATTACKER-MARKER-7f3a"
)

var fixedNow = time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)

const issueBody = `{"action":"opened","installation":{"id":42},"repository":{"id":7},"issue":{"id":1001,"number":5}}`

type fakeSecrets struct {
	secrets [][]byte
	err     error
	// panics, when set, makes that many calls panic, to test that a panicking backend can't leak a slot.
	panics *atomic.Int32
}

func (f fakeSecrets) WebhookSecrets(_ context.Context, name string) ([][]byte, error) {
	if name != "github" {
		return nil, errors.New("fakeSecrets: unexpected forge " + name)
	}
	if f.panics != nil && f.panics.Add(-1) >= 0 {
		panic("fakeSecrets: injected panic")
	}
	return f.secrets, f.err
}

// fakeScope is strict: an empty repository ID is answered from the installation list alone and never matches a
// repository entry, and a repository is allowed only under an allowed installation.
type fakeScope struct {
	mu    sync.Mutex
	allow bool
	err   error
	// installs and repos are the in-scope IDs. Nil means the defaults: installation 42 and repository 7.
	installs, repos map[string]bool
	calls           [][3]string
}

func (f *fakeScope) Allowed(_ context.Context, name, inst, repo string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, [3]string{name, inst, repo})
	installs, repos := f.installs, f.repos
	if installs == nil {
		installs = map[string]bool{"42": true}
	}
	if repos == nil {
		repos = map[string]bool{"7": true}
	}
	if repo == "" {
		return f.allow && installs[inst], f.err
	}
	return f.allow && installs[inst] && repos[repo], f.err
}

// fakeClock is a manual clock. After registers a timer and announces it on timers, and fire releases every
// registered timer.
type fakeClock struct {
	mu     sync.Mutex
	chans  []chan time.Time
	timers chan struct{}
}

func newFakeClock() *fakeClock { return &fakeClock{timers: make(chan struct{}, 1024)} }

func (c *fakeClock) Now() time.Time { return fixedNow }

func (c *fakeClock) After(time.Duration) <-chan time.Time {
	ch := make(chan time.Time, 1)
	c.mu.Lock()
	c.chans = append(c.chans, ch)
	c.mu.Unlock()
	c.timers <- struct{}{}
	return ch
}

func (c *fakeClock) fire() {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, ch := range c.chans {
		ch <- fixedNow
	}
	c.chans = nil
}

// waitTimers blocks until n timers were registered since the last call.
func (c *fakeClock) waitTimers(t *testing.T, n int) {
	t.Helper()
	for range n {
		select {
		case <-c.timers:
		case <-time.After(5 * time.Second):
			t.Fatal("timer was not registered")
		}
	}
}

type fakeReady struct{ err error }

func (f fakeReady) Ready(context.Context) error { return f.err }

// failingReceipts always fails with err.
type failingReceipts struct{ err error }

func (f failingReceipts) RecordDelivery(context.Context, string, string, store.Digest, store.WorkItem) (bool, error) {
	return false, f.err
}

// failingAudit fails every append.
type failingAudit struct{}

func (failingAudit) Append(context.Context, audit.Record) (audit.Entry, error) {
	return audit.Entry{}, errors.New("audit down")
}

type harness struct {
	t       *testing.T
	handler http.Handler
	store   *memstore.Store
	audit   *audit.Log
	scope   *fakeScope
	logs    *bytes.Buffer
	clock   *fakeClock
}

type option func(*config)

type config struct {
	secrets   fakeSecrets
	ready     fakeReady
	scope     *fakeScope
	receipts  func(*memstore.Store) api.Receipts
	auditor   func(*audit.Log) api.Auditor
	maxBodies int
	parsers   map[string]forge.EventParser
	// realClock uses the system clock, for tests of real read deadlines.
	realClock   bool
	bodyTimeout time.Duration
}

func newHarness(t *testing.T, opts ...option) *harness {
	t.Helper()
	cfg := &config{
		secrets: fakeSecrets{secrets: [][]byte{[]byte(secretA)}},
		scope:   &fakeScope{allow: true},
		receipts: func(s *memstore.Store) api.Receipts {
			return api.StoreReceipts{Store: s}
		},
		auditor: func(l *audit.Log) api.Auditor { return l },
	}
	for _, o := range opts {
		o(cfg)
	}
	st, err := memstore.New(func() time.Time { return fixedNow })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	log, err := audit.New(audit.NewMemory(), func() time.Time { return fixedNow })
	if err != nil {
		t.Fatal(err)
	}
	logs := &bytes.Buffer{}
	clock := newFakeClock()
	parsers := map[string]forge.EventParser{"github": github.Parse}
	if cfg.parsers != nil {
		parsers = cfg.parsers
	}
	var depClock api.Clock = clock
	if cfg.realClock {
		depClock = nil
	}
	h, err := api.New(api.Deps{
		Logger:    slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
		Receipts:  cfg.receipts(st),
		Readiness: cfg.ready,
		Secrets:   cfg.secrets,
		Scope:     cfg.scope,
		Audit:     cfg.auditor(log),
		Identity:  "factory-test",
		Version:   "test",
		Parsers:   parsers,
		Clock:     depClock,

		BodyReadTimeout: cfg.bodyTimeout,

		MaxConcurrentBodies: cfg.maxBodies,
	})
	if err != nil {
		t.Fatal(err)
	}
	return &harness{t: t, handler: h, store: st, audit: log, scope: cfg.scope, logs: logs, clock: clock}
}

func newRequest(method, target string, body io.Reader) *http.Request {
	return httptest.NewRequestWithContext(context.Background(), method, target, body)
}

func sign(secret string, body []byte) string {
	m := hmac.New(sha256.New, []byte(secret))
	m.Write(body)
	return "sha256=" + hex.EncodeToString(m.Sum(nil))
}

// delivery describes a webhook request; zero values mean "a valid issues delivery signed with secretA".
type delivery struct {
	forge, event, id, contentType, signature string
	body                                     string
	omitSignature                            bool
	rawBody                                  io.Reader
	contentLength                            int64
}

func (d delivery) request() *http.Request {
	name := d.forge
	if name == "" {
		name = "github"
	}
	body := d.body
	if body == "" && d.rawBody == nil {
		body = issueBody
	}
	var r io.Reader = strings.NewReader(body)
	if d.rawBody != nil {
		r = d.rawBody
	}
	req := newRequest(http.MethodPost, "/v1/webhooks/"+name, r)
	if d.rawBody != nil {
		req.ContentLength = d.contentLength
	}
	ct := d.contentType
	if ct == "" {
		ct = "application/json"
	}
	req.Header.Set("Content-Type", ct)
	event, id := d.event, d.id
	if event == "" {
		event = "issues"
	}
	if id == "" {
		id = "11111111-2222-3333-4444-555555555555"
	}
	req.Header.Set("X-Github-Event", event)
	req.Header.Set("X-Github-Delivery", id)
	sig := d.signature
	if sig == "" {
		sig = sign(secretA, []byte(body))
	}
	if !d.omitSignature {
		req.Header.Set("X-Hub-Signature-256", sig)
	}
	return req
}

func (h *harness) do(req *http.Request) *httptest.ResponseRecorder {
	h.t.Helper()
	rec := httptest.NewRecorder()
	h.handler.ServeHTTP(rec, req)
	return rec
}

func (h *harness) pending() []store.Lease {
	h.t.Helper()
	ls, err := h.store.Lease(h.t.Context(), "test", 100, time.Minute)
	if err != nil {
		h.t.Fatal(err)
	}
	return ls
}

func (h *harness) auditEntries() []audit.Entry {
	h.t.Helper()
	es, err := h.audit.Read(h.t.Context(), 1, 100)
	if err != nil {
		h.t.Fatal(err)
	}
	return es
}

func TestNewRejectsMissingDeps(t *testing.T) {
	t.Parallel()
	if h, err := api.New(api.Deps{}); err == nil {
		t.Fatalf("New(Deps{}) = %v, want an error", h)
	}
}

func TestWebhookAccepted(t *testing.T) { // NFR-5, NFR-4
	t.Parallel()
	h := newHarness(t)
	rec := h.do(delivery{}.request())
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202; body %s", rec.Code, rec.Body)
	}
	items := h.pending()
	if len(items) != 1 {
		t.Fatalf("work items = %d, want 1", len(items))
	}
	it := items[0]
	sum := sha256.Sum256([]byte(issueBody))
	if it.Key != "delivery/github/sha256-"+hex.EncodeToString(sum[:]) || it.Kind != api.WorkKind {
		t.Errorf("work item = %q/%q", it.Key, it.Kind)
	}
	var got map[string]any
	if err := json.Unmarshal(it.Payload, &got); err != nil {
		t.Fatal(err)
	}
	want := map[string]any{
		"v": float64(1), "forge": "github", "delivery_id": "11111111-2222-3333-4444-555555555555",
		"hint": map[string]any{
			"event": "issues", "action": "opened", "installation_id": "42", "repository_id": "7",
			"subject": map[string]any{"id": "1001", "number": "5"},
		},
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("payload (-want +got):\n%s", diff)
	}
	if bytes.Contains(it.Payload, []byte(issueBody)) {
		t.Error("payload contains the raw body")
	}
	if len(h.scope.calls) != 1 || h.scope.calls[0] != [3]string{"github", "42", "7"} {
		t.Errorf("scope calls = %v", h.scope.calls)
	}
}

func TestWebhookRedeliveryIsIdempotent(t *testing.T) { // NFR-4, NFR-5
	t.Parallel()
	h := newHarness(t)
	if rec := h.do(delivery{}.request()); rec.Code != http.StatusAccepted {
		t.Fatalf("first status = %d", rec.Code)
	}
	if rec := h.do(delivery{}.request()); rec.Code != http.StatusOK {
		t.Fatalf("redelivery status = %d, want 200", rec.Code)
	}
	if n := len(h.pending()); n != 1 {
		t.Fatalf("work items = %d, want 1", n)
	}
	if n := len(h.auditEntries()); n != 0 {
		t.Errorf("audit entries = %d, want 0", n)
	}
}

// conflictReceipts reports a digest conflict for every delivery: the store contract allows it, but with receipts
// keyed by body digest it can only mean a SHA-256 collision.
type conflictReceipts struct{}

func (conflictReceipts) RecordDelivery(context.Context, string, string, store.Digest, store.WorkItem) (bool, error) {
	return false, store.ErrDeliveryConflict
}

func TestWebhookReceiptConflictIsAudited(t *testing.T) { // NFR-4, NFR-5
	t.Parallel()
	h := newHarness(t, func(c *config) { c.receipts = func(*memstore.Store) api.Receipts { return conflictReceipts{} } })
	rec := h.do(delivery{}.request())
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409", rec.Code)
	}
	if got := rec.Header().Get("Content-Type"); got != "application/problem+json" {
		t.Errorf("content type = %q", got)
	}
	es := h.auditEntries()
	if len(es) != 1 {
		t.Fatalf("audit entries = %d, want 1", len(es))
	}
	sum := sha256.Sum256([]byte(issueBody))
	want := audit.Record{
		Actor:           audit.Actor{Kind: audit.ActorFactory, ID: "factory-test"},
		TemplateVersion: "test",
		Subject:         audit.Subject{Kind: audit.SubjectInstall, ID: "42"},
		Action:          audit.ActionAdmin,
		Target:          "webhook-delivery-conflict",
		Outcome:         "rejected",
		Attrs: map[string]string{
			"forge": "github", "delivery": "11111111-2222-3333-4444-555555555555", "event": "issues",
			"new_digest": hex.EncodeToString(sum[:]),
		},
	}
	if diff := cmp.Diff(want, es[0].Record); diff != "" {
		t.Errorf("audit record (-want +got):\n%s", diff)
	}
}

func TestWebhookConflictAuditFailureFailsClosed(t *testing.T) { // NFR-4
	t.Parallel()
	h := newHarness(t, func(c *config) {
		c.receipts = func(*memstore.Store) api.Receipts { return conflictReceipts{} }
		c.auditor = func(*audit.Log) api.Auditor { return failingAudit{} }
	})
	if rec := h.do(delivery{}.request()); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
}

// duplicateWork reports that another producer already holds the work key.
type duplicateWork struct{}

func (duplicateWork) RecordDelivery(context.Context, string, string, store.Digest, store.WorkItem) (bool, error) {
	return false, store.ErrDuplicateWork
}

func TestWebhookWorkKeyTakenIs409(t *testing.T) { // NFR-4
	t.Parallel()
	h := newHarness(t, func(c *config) { c.receipts = func(*memstore.Store) api.Receipts { return duplicateWork{} } })
	rec := h.do(delivery{}.request())
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409", rec.Code)
	}
	if !strings.Contains(h.logs.String(), "webhook_work_key_taken") {
		t.Error("work key conflict not logged")
	}
}

// Receipts are keyed by the digest of the signed bytes, because the delivery and event headers are unsigned.

func TestWebhookReplayUnderFreshIDsEnqueuesOnce(t *testing.T) { // NFR-4, NFR-5, SEC-1
	t.Parallel()
	h := newHarness(t)
	for i, id := range []string{"aaaaaaaa-0001", "aaaaaaaa-0002", "aaaaaaaa-0003", "aaaaaaaa-0004"} {
		want := http.StatusOK
		if i == 0 {
			want = http.StatusAccepted
		}
		if rec := h.do(delivery{id: id}.request()); rec.Code != want {
			t.Fatalf("delivery %q status = %d, want %d", id, rec.Code, want)
		}
	}
	if n := len(h.pending()); n != 1 {
		t.Fatalf("work items = %d, want 1", n)
	}
}

func TestWebhookReplayWithSwappedEventHeaderEnqueuesOnce(t *testing.T) { // NFR-4, NFR-5, SEC-1
	t.Parallel()
	h := newHarness(t)
	body := `{"action":"opened","installation":{"id":42},"repository":{"id":7},"issue":{"id":1,"number":5},"pull_request":{"id":2,"number":6}}`
	sig := sign(secretA, []byte(body))
	if rec := h.do(delivery{event: "issues", body: body, signature: sig}.request()); rec.Code != http.StatusAccepted {
		t.Fatalf("first status = %d", rec.Code)
	}
	if rec := h.do(delivery{event: "pull_request", id: "bbbbbbbb-0002", body: body, signature: sig}.request()); rec.Code != http.StatusOK {
		t.Fatalf("swapped-event replay status = %d, want 200", rec.Code)
	}
	if n := len(h.pending()); n != 1 {
		t.Fatalf("work items = %d, want 1", n)
	}
}

func TestWebhookSquattedDeliveryIDDoesNotBlockRealDelivery(t *testing.T) { // NFR-4, SEC-1
	t.Parallel()
	h := newHarness(t)
	squat := strings.Replace(issueBody, `"number":5`, `"number":99`, 1)
	if rec := h.do(delivery{body: squat, signature: sign(secretA, []byte(squat))}.request()); rec.Code != http.StatusAccepted {
		t.Fatalf("squat status = %d", rec.Code)
	}
	rec := h.do(delivery{}.request()) // the real delivery, same ID, different bytes
	if rec.Code != http.StatusAccepted {
		t.Fatalf("real delivery status = %d, want 202", rec.Code)
	}
	if n := len(h.pending()); n != 2 {
		t.Fatalf("work items = %d, want 2 (squat and real)", n)
	}
	if n := len(h.auditEntries()); n != 0 {
		t.Errorf("audit entries = %d, want 0", n)
	}
}

func TestWebhookReusedIDCannotAmplifyAuditLog(t *testing.T) { // NFR-4
	t.Parallel()
	h := newHarness(t)
	for i := range 20 {
		body := strings.Replace(issueBody, `"number":5`, `"number":`+strconv.Itoa(100+i), 1)
		if rec := h.do(delivery{body: body, signature: sign(secretA, []byte(body))}.request()); rec.Code != http.StatusAccepted {
			t.Fatalf("status = %d", rec.Code)
		}
	}
	if n := len(h.auditEntries()); n > 1 {
		t.Errorf("audit entries = %d, want at most 1", n)
	}
}

func TestWebhookSignatureRejected(t *testing.T) { // NFR-5, SEC-1 negative
	t.Parallel()
	valid := sign(secretA, []byte(issueBody))
	tests := []struct {
		name string
		d    delivery
	}{
		{"missing header", delivery{omitSignature: true}},
		{"no prefix", delivery{signature: strings.TrimPrefix(valid, "sha256=")}},
		{"wrong algorithm", delivery{signature: "sha1=" + strings.TrimPrefix(valid, "sha256=")[:40]}},
		{"short", delivery{signature: valid[:len(valid)-2]}},
		{"not hex", delivery{signature: "sha256=" + strings.Repeat("zz", 32)}},
		{"uppercase hex", delivery{signature: "sha256=" + strings.ToUpper(strings.TrimPrefix(valid, "sha256="))}},
		{"wrong secret", delivery{signature: sign("other-secret", []byte(issueBody))}},
		{"over different bytes", delivery{signature: sign(secretA, []byte(issueBody+" "))}},
		{"rotated-out secret", delivery{signature: sign("secret-rotated-out", []byte(issueBody))}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			h := newHarness(t)
			rec := h.do(tt.d.request())
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401", rec.Code)
			}
			if n := len(h.pending()); n != 0 {
				t.Errorf("work items = %d, want 0", n)
			}
			if len(h.scope.calls) != 0 {
				t.Errorf("scope consulted for an unverified delivery: %v", h.scope.calls)
			}
		})
	}
}

func TestWebhookDuplicateSignatureHeaderRejected(t *testing.T) { // NFR-5 negative
	t.Parallel()
	h := newHarness(t)
	req := delivery{}.request()
	req.Header.Add("X-Hub-Signature-256", sign("other-secret", []byte(issueBody)))
	if rec := h.do(req); rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func TestWebhookEmptySecretNeverVerifies(t *testing.T) { // NFR-5 negative
	t.Parallel()
	h := newHarness(t, func(c *config) { c.secrets = fakeSecrets{secrets: [][]byte{{}}} })
	rec := h.do(delivery{signature: sign("", []byte(issueBody))}.request())
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func TestWebhookSecretRotation(t *testing.T) { // NFR-5
	t.Parallel()
	h := newHarness(t, func(c *config) {
		c.secrets = fakeSecrets{secrets: [][]byte{[]byte(secretA), []byte(secretB)}}
	})
	rec := h.do(delivery{signature: sign(secretB, []byte(issueBody))}.request())
	if rec.Code != http.StatusAccepted {
		t.Fatalf("rotated-in secret status = %d, want 202", rec.Code)
	}
}

func TestWebhookSecretsErrorFailsClosed(t *testing.T) { // NFR-5
	t.Parallel()
	h := newHarness(t, func(c *config) { c.secrets = fakeSecrets{err: errors.New("vault down " + marker)} })
	rec := h.do(delivery{}.request())
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
	if strings.Contains(rec.Body.String(), marker) {
		t.Error("response echoes internal error text")
	}
	if n := len(h.pending()); n != 0 {
		t.Errorf("work items = %d", n)
	}
}

func TestWebhookBodyTooLarge(t *testing.T) { // NFR-5
	t.Parallel()
	big := bytes.Repeat([]byte("a"), api.MaxBodyBytes+1)
	tests := []struct {
		name string
		d    delivery
	}{
		{"declared length", delivery{rawBody: bytes.NewReader(big), contentLength: int64(len(big)), signature: sign(secretA, big)}},
		{"understated length", delivery{rawBody: io.MultiReader(bytes.NewReader(big)), contentLength: 1 << 20, signature: sign(secretA, big)}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			h := newHarness(t)
			rec := h.do(tt.d.request())
			if rec.Code != http.StatusRequestEntityTooLarge {
				t.Fatalf("status = %d, want 413", rec.Code)
			}
			if n := len(h.pending()); n != 0 {
				t.Errorf("work items = %d", n)
			}
		})
	}
}

func TestWebhookBodyAtLimitIsRead(t *testing.T) { // NFR-5 boundary
	t.Parallel()
	pad := strings.Repeat("a", api.MaxBodyBytes-len(`{"x":""}`))
	body := `{"x":"` + pad + `"}`
	h := newHarness(t)
	rec := h.do(delivery{event: "star", body: body, signature: sign(secretA, []byte(body))}.request())
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202 (unsupported event, nothing recorded)", rec.Code)
	}
}

func TestWebhookWrongContentType(t *testing.T) { // NFR-5 negative
	t.Parallel()
	for _, ct := range []string{"text/plain", "application/x-www-form-urlencoded", "application/jsonx", "text/" + marker, "application/json; charset=\"", ""} {
		t.Run(ct, func(t *testing.T) {
			t.Parallel()
			h := newHarness(t)
			req := delivery{}.request()
			if ct == "" {
				req.Header.Del("Content-Type")
			} else {
				req.Header.Set("Content-Type", ct)
			}
			rec := h.do(req)
			if rec.Code != http.StatusUnsupportedMediaType {
				t.Fatalf("status = %d, want 415", rec.Code)
			}
			if strings.Contains(rec.Body.String(), marker) {
				t.Error("response echoes the content type")
			}
			if n := len(h.pending()); n != 0 {
				t.Errorf("work items = %d", n)
			}
		})
	}
}

func TestWebhookJSONContentTypeWithCharsetAccepted(t *testing.T) { // NFR-5
	t.Parallel()
	h := newHarness(t)
	if rec := h.do(delivery{contentType: "application/json; charset=utf-8"}.request()); rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202", rec.Code)
	}
}

func TestWebhookUnknownForge(t *testing.T) { // NFR-5 negative
	t.Parallel()
	for _, forge := range []string{"gitlab", "GitHub", marker} {
		t.Run(forge, func(t *testing.T) {
			t.Parallel()
			h := newHarness(t)
			rec := h.do(delivery{forge: forge}.request())
			if rec.Code != http.StatusNotFound {
				t.Fatalf("status = %d, want 404", rec.Code)
			}
			if strings.Contains(rec.Body.String(), marker) {
				t.Error("response echoes the forge")
			}
			if n := len(h.pending()); n != 0 {
				t.Errorf("work items = %d", n)
			}
		})
	}
}

func TestWebhookPing(t *testing.T) { // NFR-5
	t.Parallel()
	h := newHarness(t)
	body := `{"zen":"Keep it logically awesome.","hook_id":1}`
	rec := h.do(delivery{event: "ping", body: body, signature: sign(secretA, []byte(body))}.request())
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if n := len(h.pending()); n != 0 {
		t.Errorf("work items = %d, want 0", n)
	}
}

func TestWebhookUnsupportedEvent(t *testing.T) { // NFR-5
	t.Parallel()
	h := newHarness(t)
	rec := h.do(delivery{event: "star"}.request())
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202", rec.Code)
	}
	if n := len(h.pending()); n != 0 {
		t.Errorf("work items = %d, want 0", n)
	}
	if len(h.scope.calls) != 0 {
		t.Errorf("scope calls = %v, want none", h.scope.calls)
	}
}

func TestWebhookMalformedPayloads(t *testing.T) { // NFR-5 negative
	t.Parallel()
	tests := []struct{ name, body string }{
		{"missing repository", `{"installation":{"id":42},"issue":{"id":1}}`},
		{"missing installation", `{"repository":{"id":7},"issue":{"id":1}}`},
		{"not json", `not json ` + marker},
		{"string id", `{"installation":{"id":"42"},"repository":{"id":7},"issue":{"id":1}}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			h := newHarness(t)
			rec := h.do(delivery{body: tt.body, signature: sign(secretA, []byte(tt.body))}.request())
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400", rec.Code)
			}
			if strings.Contains(rec.Body.String(), marker) {
				t.Error("response echoes the body")
			}
			if n := len(h.pending()); n != 0 {
				t.Errorf("work items = %d", n)
			}
		})
	}
}

func TestWebhookBadHeaderShapes(t *testing.T) { // NFR-5 negative
	t.Parallel()
	tests := []struct {
		name string
		d    delivery
	}{
		{"delivery id with spaces", delivery{id: "a b " + marker}},
		{"delivery id too long", delivery{id: strings.Repeat("a", 65)}},
		{"delivery id with slash", delivery{id: "../" + marker}},
		{"event with uppercase", delivery{event: "Issues"}},
		{"event with marker", delivery{event: "issues-" + marker}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			h := newHarness(t)
			rec := h.do(tt.d.request())
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400", rec.Code)
			}
			if strings.Contains(rec.Body.String(), marker) {
				t.Error("response echoes a header")
			}
			if n := len(h.pending()); n != 0 {
				t.Errorf("work items = %d", n)
			}
		})
	}
}

func TestWebhookMissingRoutingHeaders(t *testing.T) { // NFR-5 negative
	t.Parallel()
	for _, hdr := range []string{"X-Github-Event", "X-Github-Delivery"} {
		t.Run(hdr, func(t *testing.T) {
			t.Parallel()
			h := newHarness(t)
			req := delivery{}.request()
			req.Header.Del(hdr)
			if rec := h.do(req); rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400", rec.Code)
			}
		})
	}
}

func TestWebhookScope(t *testing.T) { // NFR-5, SEC-10 negative
	t.Parallel()
	t.Run("denied", func(t *testing.T) {
		t.Parallel()
		h := newHarness(t, func(c *config) { c.scope = &fakeScope{allow: false} })
		rec := h.do(delivery{}.request())
		if rec.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403", rec.Code)
		}
		if n := len(h.pending()); n != 0 {
			t.Errorf("work items = %d", n)
		}
	})
	t.Run("foreign installation", func(t *testing.T) {
		t.Parallel()
		h := newHarness(t)
		body := strings.Replace(issueBody, `"id":42`, `"id":43`, 1)
		rec := h.do(delivery{body: body, signature: sign(secretA, []byte(body))}.request())
		if rec.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403", rec.Code)
		}
		if n := len(h.pending()); n != 0 {
			t.Errorf("work items = %d", n)
		}
	})
	t.Run("error fails closed", func(t *testing.T) {
		t.Parallel()
		h := newHarness(t, func(c *config) { c.scope = &fakeScope{allow: true, err: errors.New("db down " + marker)} })
		rec := h.do(delivery{}.request())
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("status = %d, want 503", rec.Code)
		}
		if strings.Contains(rec.Body.String(), marker) {
			t.Error("response echoes the error")
		}
		if n := len(h.pending()); n != 0 {
			t.Errorf("work items = %d", n)
		}
	})
}

func TestWebhookStoreError(t *testing.T) { // NFR-4
	t.Parallel()
	h := newHarness(t, func(c *config) {
		c.receipts = func(*memstore.Store) api.Receipts { return failingReceipts{err: errors.New("disk " + marker)} }
	})
	rec := h.do(delivery{}.request())
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
	if strings.Contains(rec.Body.String(), marker) {
		t.Error("response echoes the error")
	}
	if n := strings.Count(h.logs.String(), "webhook_record_failed"); n != 1 {
		t.Errorf("store error logged %d times, want 1", n)
	}
}

func TestProblemResponsesAreFixed(t *testing.T) { // SEC-1
	t.Parallel()
	h := newHarness(t)
	req := delivery{id: marker + " bad", event: marker, body: marker, signature: "sha256=" + marker}.request()
	req.Header.Set("X-Extra", marker)
	rec := h.do(req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	for name, vs := range rec.Header() {
		if strings.Contains(strings.Join(vs, ","), marker) {
			t.Errorf("header %s echoes input", name)
		}
	}
	if strings.Contains(rec.Body.String(), marker) {
		t.Errorf("body echoes input: %s", rec.Body)
	}
	var p struct {
		Type   string `json:"type"`
		Title  string `json:"title"`
		Status int    `json:"status"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &p); err != nil || p.Status != 401 || p.Title == "" {
		t.Errorf("problem body = %s (%v)", rec.Body, err)
	}
	if got := rec.Header().Get("Content-Type"); got != "application/problem+json" {
		t.Errorf("content type = %q", got)
	}
}

func TestLogsNeverContainSecretsSignaturesOrBodies(t *testing.T) { // SEC-1
	t.Parallel()
	h := newHarness(t)
	d := delivery{}
	h.do(d.request())
	bad := delivery{signature: sign("other", []byte(issueBody))}
	h.do(bad.request())
	logs := h.logs.String()
	for _, s := range []string{secretA, sign(secretA, []byte(issueBody)), sign("other", []byte(issueBody)), "opened", "1001"} {
		if strings.Contains(logs, s) {
			t.Errorf("logs contain %q", s)
		}
	}
}

func TestHealthAndReadiness(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name, path string
		ready      error
		want       int
	}{
		{"healthz", "/healthz", nil, http.StatusOK},
		{"healthz while not ready", "/healthz", errors.New("x"), http.StatusOK},
		{"readyz ready", "/readyz", nil, http.StatusOK},
		{"readyz not ready", "/readyz", errors.New("db down " + marker), http.StatusServiceUnavailable},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			h := newHarness(t, func(c *config) { c.ready = fakeReady{err: tt.ready} })
			rec := h.do(newRequest(http.MethodGet, tt.path, http.NoBody))
			if rec.Code != tt.want {
				t.Fatalf("status = %d, want %d", rec.Code, tt.want)
			}
			if strings.Contains(rec.Body.String(), marker) {
				t.Error("response echoes the readiness error")
			}
		})
	}
}

func TestUnknownRouteAndMethod(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	if rec := h.do(newRequest(http.MethodGet, "/v1/webhooks/github", http.NoBody)); rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET webhook status = %d, want 405", rec.Code)
	}
	rec := h.do(newRequest(http.MethodGet, "/nope/"+marker, http.NoBody))
	if rec.Code != http.StatusNotFound || strings.Contains(rec.Body.String(), marker) {
		t.Errorf("unknown route: status %d body %s", rec.Code, rec.Body)
	}
}
