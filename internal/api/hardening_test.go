// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

package api_test

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"go.yaml.in/yaml/v3"

	"github.com/elliott-davis/lightsout/internal/api"
	"github.com/elliott-davis/lightsout/internal/forge"
	"github.com/elliott-davis/lightsout/internal/forge/github"
	"github.com/elliott-davis/lightsout/internal/store"
	"github.com/elliott-davis/lightsout/internal/store/memstore"
)

// countingReader counts the bytes read from it.
type countingReader struct {
	r io.Reader
	n atomic.Int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n.Add(int64(n))
	return n, err
}

func TestUnauthenticatedRequestsReadNoBody(t *testing.T) { // NFR-5, SEC-1
	t.Parallel()
	body := strings.Repeat("x", 1<<20)
	tests := []struct {
		name string
		opt  option
		sig  string
		want int
	}{
		{"malformed signature", nil, "sha256=zz", http.StatusUnauthorized},
		{"missing prefix", nil, strings.Repeat("a", 64), http.StatusUnauthorized},
		{"no usable secret", func(c *config) { c.secrets = fakeSecrets{secrets: [][]byte{{}}} }, sign(secretA, []byte(body)), http.StatusUnauthorized},
		{"too many secrets", func(c *config) {
			c.secrets = fakeSecrets{secrets: [][]byte{[]byte("1"), []byte("2"), []byte("3"), []byte("4"), []byte("5")}}
		}, sign(secretA, []byte(body)), http.StatusServiceUnavailable},
		{"secrets error", func(c *config) { c.secrets = fakeSecrets{err: io.ErrUnexpectedEOF} }, sign(secretA, []byte(body)), http.StatusServiceUnavailable},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var opts []option
			if tt.opt != nil {
				opts = append(opts, tt.opt)
			}
			h := newHarness(t, opts...)
			cr := &countingReader{r: strings.NewReader(body)}
			rec := h.do(delivery{rawBody: cr, contentLength: int64(len(body)), signature: tt.sig}.request())
			if rec.Code != tt.want {
				t.Fatalf("status = %d, want %d", rec.Code, tt.want)
			}
			if n := cr.n.Load(); n != 0 {
				t.Errorf("read %d body bytes before authenticating, want 0", n)
			}
		})
	}
}

func TestSecretsErrorTextNotLogged(t *testing.T) { // SEC-1
	t.Parallel()
	h := newHarness(t, func(c *config) { c.secrets = fakeSecrets{err: stringError("backend said " + marker)} })
	h.do(delivery{}.request())
	if strings.Contains(h.logs.String(), marker) {
		t.Error("logs contain the secrets backend's error text")
	}
	if !strings.Contains(h.logs.String(), "webhook_secrets_unavailable") {
		t.Error("secrets failure not logged")
	}
}

type stringError string

func (e stringError) Error() string { return string(e) }

// Not parallel on purpose: it measures process-wide allocation.
func TestBadSignatureAllocationIsBounded(t *testing.T) { // NFR-5, SEC-1
	h := newHarness(t)
	body := bytes.Repeat([]byte("a"), 4<<20)
	req := delivery{rawBody: bytes.NewReader(body), contentLength: int64(len(body)), signature: sign("other", body)}.request()
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	rec := h.do(req)
	runtime.ReadMemStats(&after)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	if got := after.TotalAlloc - before.TotalAlloc; got > uint64(len(body))*3/2 {
		t.Errorf("allocated %d bytes for a %d byte body, want at most 1.5x", got, len(body))
	}
}

// gateReader blocks its first Read until released, reporting concurrency.
type gateReader struct {
	started chan<- struct{}
	release <-chan struct{}
	active  *atomic.Int32
	peak    *atomic.Int32
	once    sync.Once
}

func (g *gateReader) Read([]byte) (int, error) {
	g.once.Do(func() {
		n := g.active.Add(1)
		for {
			p := g.peak.Load()
			if n <= p || g.peak.CompareAndSwap(p, n) {
				break
			}
		}
		g.started <- struct{}{}
	})
	<-g.release
	return 0, io.EOF
}

func (g *gateReader) done() { g.active.Add(-1) }

func TestBodySemaphoreLimitsConcurrentReads(t *testing.T) { // NFR-5, SEC-1
	t.Parallel()
	const limit, total = 2, 6
	h := newHarness(t, func(c *config) { c.maxBodies = limit })
	started := make(chan struct{}, total)
	release := make(chan struct{})
	var active, peak atomic.Int32
	var wg sync.WaitGroup
	codes := make(chan int, total)
	for range total {
		g := &gateReader{started: started, release: release, active: &active, peak: &peak}
		req := delivery{rawBody: g, contentLength: 10}.request()
		wg.Go(func() {
			defer g.done()
			rec := httptest.NewRecorder()
			h.handler.ServeHTTP(rec, req)
			codes <- rec.Code
		})
	}
	for range limit {
		select {
		case <-started:
		case <-time.After(5 * time.Second):
			t.Fatal("readers did not start")
		}
	}
	// The other requests are blocked on the full semaphore: each has registered its wait timer, and none can
	// have started reading. Firing the timers refuses them.
	h.clock.waitTimers(t, total-limit)
	if n := len(started); n != 0 {
		t.Fatalf("%d readers started beyond the semaphore limit", n)
	}
	h.clock.fire()
	for range total - limit {
		if code := <-codes; code != http.StatusServiceUnavailable {
			t.Errorf("refused request status = %d, want 503", code)
		}
	}
	close(release)
	wg.Wait()
	if p := peak.Load(); p > limit {
		t.Errorf("peak concurrent body reads = %d, want at most %d", p, limit)
	}
}

// An idle unauthenticated connection holds the only slot. A signed delivery waits for the bounded time, gets a
// prompt 503, and is accepted once the idle connection is gone.
func TestIdleConnectionCannotLockOutSignedDeliveries(t *testing.T) { // NFR-5, SEC-1
	t.Parallel()
	h := newHarness(t, func(c *config) { c.maxBodies = 1 })
	started := make(chan struct{}, 1)
	release := make(chan struct{})
	var active, peak atomic.Int32
	var wg sync.WaitGroup
	idle := &gateReader{started: started, release: release, active: &active, peak: &peak}
	wg.Go(func() {
		h.handler.ServeHTTP(httptest.NewRecorder(), delivery{rawBody: idle, contentLength: 10}.request())
	})
	<-started

	got := make(chan int, 1)
	go func() { got <- h.do(delivery{}.request()).Code }()
	h.clock.waitTimers(t, 1)
	h.clock.fire()
	if code := <-got; code != http.StatusServiceUnavailable {
		t.Fatalf("waiting delivery status = %d, want 503", code)
	}
	close(release)
	wg.Wait()
	if rec := h.do(delivery{}.request()); rec.Code != http.StatusAccepted {
		t.Fatalf("delivery after the idle connection ended: status = %d, want 202", rec.Code)
	}
}

func TestBodySemaphoreHonorsContext(t *testing.T) { // NFR-5, SEC-1
	t.Parallel()
	h := newHarness(t, func(c *config) { c.maxBodies = 1 })
	started := make(chan struct{}, 1)
	release := make(chan struct{})
	var active, peak atomic.Int32
	var wg sync.WaitGroup
	g := &gateReader{started: started, release: release, active: &active, peak: &peak}
	wg.Go(func() {
		h.handler.ServeHTTP(httptest.NewRecorder(), delivery{rawBody: g, contentLength: 10}.request())
	})
	<-started

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	rec := httptest.NewRecorder()
	h.handler.ServeHTTP(rec, delivery{}.request().WithContext(ctx))
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("status with a full semaphore and a done context = %d, want 503", rec.Code)
	}
	close(release)
	wg.Wait()
}

// blockingReceipts blocks its first call until released.
type blockingReceipts struct {
	inner   api.Receipts
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (b *blockingReceipts) RecordDelivery(ctx context.Context, forgeName, id string, d store.Digest, w store.WorkItem) (bool, error) {
	b.once.Do(func() {
		b.entered <- struct{}{}
		<-b.release
	})
	return b.inner.RecordDelivery(ctx, forgeName, id, d, w)
}

func TestSlotIsReleasedBeforeStoreWork(t *testing.T) { // NFR-5, SEC-1
	t.Parallel()
	br := &blockingReceipts{entered: make(chan struct{}, 1), release: make(chan struct{})}
	h := newHarness(t, func(c *config) {
		c.maxBodies = 1
		c.receipts = func(s *memstore.Store) api.Receipts {
			br.inner = api.StoreReceipts{Store: s}
			return br
		}
	})
	first := make(chan int, 1)
	go func() { first <- h.do(delivery{}.request()).Code }()
	<-br.entered // the first delivery is authenticated and stuck in the store

	second := make(chan int, 1)
	go func() { second <- h.do(delivery{event: "star"}.request()).Code }()
	select {
	case code := <-second:
		if code != http.StatusAccepted {
			t.Errorf("second delivery status = %d, want 202", code)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the slot was held during store work")
	}
	close(br.release)
	if code := <-first; code != http.StatusAccepted {
		t.Errorf("first delivery status = %d, want 202", code)
	}
}

func TestPanickingAuthenticationReleasesItsSlot(t *testing.T) { // NFR-5, SEC-1
	t.Parallel()
	panics := &atomic.Int32{}
	panics.Store(1)
	h := newHarness(t, func(c *config) {
		c.maxBodies = 1
		c.secrets.panics = panics
	})
	func() {
		defer func() {
			if recover() == nil {
				t.Error("the injected panic did not happen")
			}
		}()
		h.do(delivery{}.request())
	}()

	// With the only slot leaked, the next delivery would wait on the fake clock forever.
	done := make(chan int, 1)
	go func() { done <- h.do(delivery{event: "star"}.request()).Code }()
	select {
	case code := <-done:
		if code != http.StatusAccepted {
			t.Errorf("status after a panic = %d, want 202", code)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a panic during authentication leaked the slot")
	}
}

func TestSlowBodyHitsReadDeadline(t *testing.T) { // NFR-5, SEC-1
	t.Parallel()
	h := newHarness(t, func(c *config) {
		c.maxBodies = 1
		c.realClock = true
		c.bodyTimeout = 100 * time.Millisecond
	})
	srv := httptest.NewServer(h.handler)
	t.Cleanup(srv.Close)

	var d net.Dialer
	conn, err := d.DialContext(t.Context(), "tcp", srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	req := "POST /v1/webhooks/github HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: 1000\r\n" +
		"X-Github-Event: issues\r\nX-Github-Delivery: abc\r\nX-Hub-Signature-256: " + sign(secretA, []byte("x")) + "\r\n\r\nabc"
	if _, err = io.WriteString(conn, req); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("no response to a stalled body: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 after the read deadline", resp.StatusCode)
	}
}

func TestContentLengthRequired(t *testing.T) { // NFR-5 negative
	t.Parallel()
	h := newHarness(t)
	rec := h.do(delivery{rawBody: strings.NewReader(issueBody), contentLength: -1}.request())
	if rec.Code != http.StatusLengthRequired {
		t.Fatalf("status = %d, want 411", rec.Code)
	}
	if n := len(h.pending()); n != 0 {
		t.Errorf("work items = %d", n)
	}
}

func TestExactlyMaxSecretsAccepted(t *testing.T) { // NFR-5
	t.Parallel()
	secrets := [][]byte{[]byte("s1"), []byte("s2"), []byte("s3"), []byte(secretA)}
	h := newHarness(t, func(c *config) { c.secrets = fakeSecrets{secrets: secrets} })
	if rec := h.do(delivery{}.request()); rec.Code != http.StatusAccepted {
		t.Fatalf("status with %d secrets = %d, want 202", api.MaxSecrets, rec.Code)
	}
}

func TestSignedPayloadWithInvalidUTF8InUnreadStringsIsAccepted(t *testing.T) { // NFR-5
	t.Parallel()
	for name, comment := range map[string]string{
		"lone surrogate escape": `"\ud800"`,
		"raw 0xff byte":         "\"a\xffb\"",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			h := newHarness(t)
			body := `{"action":"created","installation":{"id":42},"repository":{"id":7},"issue":{"number":5},"comment":{"id":99,"body":` + comment + `}}`
			rec := h.do(delivery{event: "issue_comment", body: body, signature: sign(secretA, []byte(body))}.request())
			if rec.Code != http.StatusAccepted {
				t.Fatalf("status = %d, want 202", rec.Code)
			}
			if n := len(h.pending()); n != 1 {
				t.Errorf("work items = %d, want 1", n)
			}
		})
	}
}

func TestRejectedSignedPayloadIsLoggedAtWarn(t *testing.T) { // NFR-5
	t.Parallel()
	h := newHarness(t)
	body := `{"installation":{"id":42},"issue":{"id":1},"x":"` + marker + `"}`
	rec := h.do(delivery{body: body, signature: sign(secretA, []byte(body))}.request())
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d", rec.Code)
	}
	logs := h.logs.String()
	if !strings.Contains(logs, "level=WARN msg=webhook_payload_rejected") {
		t.Errorf("rejection not logged at warn: %s", logs)
	}
	if strings.Contains(logs, marker) {
		t.Error("logs contain payload content")
	}
}

func TestNewCopiesParsersAndRequiresEveryForge(t *testing.T) { // NFR-5
	t.Parallel()
	parsers := map[string]forge.EventParser{"github": github.Parse}
	h := newHarness(t, func(c *config) { c.parsers = parsers })
	delete(parsers, "github") // must not reach the server
	if rec := h.do(delivery{}.request()); rec.Code != http.StatusAccepted {
		t.Fatalf("status after mutating the caller's map = %d, want 202", rec.Code)
	}
	_, err := api.New(api.Deps{
		Logger: slog.New(slog.DiscardHandler), Receipts: failingReceipts{}, Readiness: fakeReady{},
		Secrets: fakeSecrets{}, Scope: &fakeScope{}, Audit: failingAudit{}, Identity: "i", Version: "v",
		Parsers: map[string]forge.EventParser{},
	})
	if err == nil {
		t.Fatal("New accepted Deps without a github parser")
	}
}

func TestInstallationEventsAreScopedByInstallationOnly(t *testing.T) { // NFR-5, SEC-10
	t.Parallel()
	// Installation 42 is in scope and no repository is: an empty repository ID must be answered from the
	// installation alone and must never match a repository entry.
	h := newHarness(t, func(c *config) { c.scope = &fakeScope{allow: true, repos: map[string]bool{}} })
	inst := `{"action":"suspend","installation":{"id":42},"repositories":[{"id":7}]}`
	if rec := h.do(delivery{event: "installation", body: inst, signature: sign(secretA, []byte(inst))}.request()); rec.Code != http.StatusAccepted {
		t.Fatalf("installation event status = %d, want 202", rec.Code)
	}
	if rec := h.do(delivery{}.request()); rec.Code != http.StatusForbidden {
		t.Fatalf("repository event status = %d, want 403 (no repository in scope)", rec.Code)
	}
	for _, c := range h.scope.calls {
		if c[2] == "7" && c[1] != "42" {
			t.Errorf("unexpected scope call %v", c)
		}
	}
}

func TestSubIssueWithoutItsRepositoryIsRejected(t *testing.T) { // NFR-5, SEC-10 negative
	t.Parallel()
	const inst = `"installation":{"id":42},"repository":{"id":7}`
	tests := []struct{ name, body string }{
		{"sub issue without repo", `{` + inst + `,"parent_issue_id":1,"sub_issue_id":2,"parent_issue_repo":{"id":7}}`},
		{"parent issue without repo", `{` + inst + `,"parent_issue_id":1,"sub_issue_id":2,"sub_issue_repo":{"id":7}}`},
		{"nested sub issue without repo", `{` + inst + `,"parent_issue":{"id":1},"sub_issue":{"id":2},"parent_issue_repo":{"id":7}}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			h := newHarness(t)
			rec := h.do(delivery{event: "sub_issues", body: tt.body, signature: sign(secretA, []byte(tt.body))}.request())
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400", rec.Code)
			}
			if n := len(h.pending()); n != 0 {
				t.Errorf("work items = %d", n)
			}
		})
	}
}

func TestHeaderPatternsMatchSpec(t *testing.T) { // API first
	t.Parallel()
	raw, err := os.ReadFile("../../api/openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var spec struct {
		Paths map[string]map[string]struct {
			Parameters []struct {
				Name   string `yaml:"name"`
				Schema struct {
					Pattern string `yaml:"pattern"`
				} `yaml:"schema"`
			} `yaml:"parameters"`
		} `yaml:"paths"`
	}
	if err = yaml.Unmarshal(raw, &spec); err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, p := range spec.Paths["/v1/webhooks/{forge}"]["post"].Parameters {
		got[p.Name] = p.Schema.Pattern
	}
	want := map[string]string{
		"forge":               "",
		"X-GitHub-Event":      api.EventPattern,
		"X-GitHub-Delivery":   api.DeliveryPattern,
		"X-Hub-Signature-256": api.SignaturePattern,
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("header patterns differ from the Go constants (-go +spec):\n%s", diff)
	}
}

func TestWebhookScopeNamedRepositories(t *testing.T) { // NFR-5, SEC-10 negative
	t.Parallel()
	const inst = `"installation":{"id":42}`
	tests := []struct {
		name, event, body string
		want              int
		items             int
	}{
		{
			"foreign repository, valid installation", "issues",
			`{"action":"opened",` + inst + `,"repository":{"id":8},"issue":{"id":1,"number":5}}`, http.StatusForbidden, 0,
		},
		{
			"foreign sub-issue repository", "sub_issues",
			`{"action":"sub_issue_added",` + inst + `,"repository":{"id":7},"parent_issue_id":1,"sub_issue_id":2,"parent_issue_repo":{"id":7},"sub_issue_repo":{"id":31337}}`, http.StatusForbidden, 0,
		},
		{
			"foreign parent-issue repository", "sub_issues",
			`{"action":"sub_issue_added",` + inst + `,"repository":{"id":7},"parent_issue_id":1,"sub_issue_id":2,"parent_issue_repo":{"id":31337},"sub_issue_repo":{"id":7}}`, http.StatusForbidden, 0,
		},
		{
			"sub-issues in scope", "sub_issues",
			`{"action":"sub_issue_added",` + inst + `,"repository":{"id":7},"parent_issue_id":1,"sub_issue_id":2,"parent_issue_repo":{"id":7},"sub_issue_repo":{"id":7}}`, http.StatusAccepted, 1,
		},
		{
			"installation deleted, no repository", "installation",
			`{"action":"deleted",` + inst + `,"repositories":[{"id":7},{"id":8}]}`, http.StatusAccepted, 1,
		},
		{
			"installation of another install", "installation",
			`{"action":"deleted","installation":{"id":43}}`, http.StatusForbidden, 0,
		},
		{
			"repositories removed are recorded, not scoped", "installation_repositories",
			`{"action":"removed",` + inst + `,"repositories_removed":[{"id":31337}],"repositories_added":[]}`, http.StatusAccepted, 1,
		},
		{"membership", "membership", `{"action":"removed",` + inst + `,"member":{"id":5},"team":{"id":6}}`, http.StatusAccepted, 1},
		{"member needs a repository", "member", `{"action":"removed",` + inst + `,"member":{"id":5}}`, http.StatusBadRequest, 0},
		{"repository renamed", "repository", `{"action":"renamed",` + inst + `,"repository":{"id":7}}`, http.StatusAccepted, 1},
		{"repository of another install", "repository", `{"action":"transferred",` + inst + `,"repository":{"id":9}}`, http.StatusForbidden, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			h := newHarness(t)
			rec := h.do(delivery{event: tt.event, body: tt.body, signature: sign(secretA, []byte(tt.body))}.request())
			if rec.Code != tt.want {
				t.Fatalf("status = %d, want %d", rec.Code, tt.want)
			}
			if n := len(h.pending()); n != tt.items {
				t.Errorf("work items = %d, want %d", n, tt.items)
			}
		})
	}
}

func TestRevocationHintRecordsRepositories(t *testing.T) { // NFR-5
	t.Parallel()
	h := newHarness(t)
	body := `{"action":"removed","installation":{"id":42},"repositories_removed":[{"id":31337}],"repositories_added":[{"id":7}]}`
	if rec := h.do(delivery{event: "installation_repositories", body: body, signature: sign(secretA, []byte(body))}.request()); rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d", rec.Code)
	}
	items := h.pending()
	if len(items) != 1 || !strings.Contains(string(items[0].Payload), `"removed_repository_ids":["31337"]`) ||
		!strings.Contains(string(items[0].Payload), `"added_repository_ids":["7"]`) {
		t.Fatalf("payload does not record the repositories: %v", items)
	}
}

func TestWebhookStrictJSON(t *testing.T) { // NFR-5, SEC-1 negative
	t.Parallel()
	tests := []struct{ name, body string }{
		{"duplicate top-level key", `{"installation":{"id":42},"installation":{"id":43},"repository":{"id":7},"issue":{"id":1}}`},
		{"duplicate nested key", `{"installation":{"id":42,"id":43},"repository":{"id":7},"issue":{"id":1}}`},
		{"duplicate deep key", `{"installation":{"id":42},"repository":{"id":7},"issue":{"id":1,"number":1,"number":2}}`},
		{"wrongly cased installation", `{"Installation":{"id":42},"repository":{"id":7},"issue":{"id":1}}`},
		{"wrongly cased repository", `{"installation":{"id":42},"Repository":{"id":7},"issue":{"id":1}}`},
		{"wrongly cased id", `{"installation":{"ID":42},"repository":{"id":7},"issue":{"id":1}}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			h := newHarness(t)
			rec := h.do(delivery{body: tt.body, signature: sign(secretA, []byte(tt.body))}.request())
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400", rec.Code)
			}
			if n := len(h.pending()); n != 0 {
				t.Errorf("work items = %d", n)
			}
		})
	}
}
