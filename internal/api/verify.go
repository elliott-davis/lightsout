// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"mime"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/elliott-davis/lightsout/internal/api/gen"
)

// MaxBodyBytes is GitHub's own payload limit (25 MiB). A larger delivery is refused and recovered by redelivery.
const MaxBodyBytes = 25 << 20

// MaxSecrets bounds how many current webhook secrets are tried. More is a configuration error.
const MaxSecrets = 4

// Defaults for [Deps].
const (
	DefaultMaxConcurrentBodies = 16
	DefaultSlotWait            = time.Second
	DefaultBodyReadTimeout     = 10 * time.Second
)

// Header patterns. They are the patterns in api/openapi.yaml, and a test keeps the two equal.
const (
	EventPattern     = `^[a-z_]{1,64}$`
	DeliveryPattern  = `^[A-Za-z0-9-]{1,64}$`
	SignaturePattern = `^sha256=[0-9a-f]{64}$`
)

const signaturePrefix = "sha256="

var (
	eventRE     = regexp.MustCompile(EventPattern)
	deliveryRE  = regexp.MustCompile(DeliveryPattern)
	signatureRE = regexp.MustCompile(SignaturePattern)
)

type verifiedKey struct{}

// verifiedBody returns the bytes the signature middleware verified. The handler uses exactly these bytes.
func verifiedBody(ctx context.Context) ([]byte, bool) {
	b, ok := ctx.Value(verifiedKey{}).([]byte)
	return b, ok
}

// unsigned reports whether the route takes no signed payload.
func unsigned(pattern string) bool { return pattern == "/healthz" || pattern == "/readyz" }

// verifySignature is the raw-body middleware (NFR-5, SEC-1). It runs before the generated code decodes the body.
//
// It does the cheap checks first, so an unauthenticated sender cannot make the server do work for nothing: the
// forge is known (404), the content type is JSON (415), the request has a Content-Length (411) within
// [MaxBodyBytes] (413), and the signature header is well formed (401, with no body byte read). Then it takes a
// slot from the semaphore, waiting at most Deps.SlotWait (503), and under the slot it looks up the secrets, sets
// a read deadline, streams the body into a buffer while computing every secret's HMAC incrementally, and compares
// each in constant time (401 on no match). The slot is released before anything else happens, so idle or slow
// unauthenticated connections hold one only for the read deadline. The request body is then replaced by the
// verified bytes and the same bytes are put in the context.
func (s *server) verifySignature(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The generated router applies middleware to every operation. Health and readiness carry no payload
		// and are exempted by name, so any route added later is verified until it is listed here.
		if unsigned(chi.RouteContext(r.Context()).RoutePattern()) {
			next.ServeHTTP(w, r)
			return
		}
		ctx := r.Context()
		forge := chi.URLParam(r, "forge")
		if !gen.Forge(forge).Valid() {
			writeProblem(w, http.StatusNotFound)
			return
		}
		if !isJSON(r.Header.Get("Content-Type")) {
			writeProblem(w, http.StatusUnsupportedMediaType)
			return
		}
		if r.ContentLength < 0 {
			writeProblem(w, http.StatusLengthRequired)
			return
		}
		if r.ContentLength > MaxBodyBytes {
			writeProblem(w, http.StatusRequestEntityTooLarge)
			return
		}
		got, ok := parseSignature(r.Header.Get("X-Hub-Signature-256"))
		if !ok {
			s.log.DebugContext(ctx, "webhook_signature_rejected", "reason", "malformed")
			writeProblem(w, http.StatusUnauthorized)
			return
		}
		if !s.acquire(ctx) {
			writeProblem(w, http.StatusServiceUnavailable)
			return
		}
		// The slot is released when authentication ends, before scope and store work, and also if it panics: a
		// leaked slot would shrink ingestion capacity until a restart.
		body, status := func() ([]byte, int) {
			defer func() { <-s.slots }()
			return s.authenticate(w, r, forge, got)
		}()
		if status != 0 {
			writeProblem(w, status)
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		next.ServeHTTP(w, r.WithContext(context.WithValue(ctx, verifiedKey{}, body)))
	})
}

// acquire takes a slot, waiting at most SlotWait. It reports false if the wait ended or the request was canceled.
func (s *server) acquire(ctx context.Context) bool {
	select {
	case s.slots <- struct{}{}:
		return true
	default:
	}
	select {
	case s.slots <- struct{}{}:
		return true
	case <-s.Clock.After(s.SlotWait):
		return false
	case <-ctx.Done():
		return false
	}
}

// authenticate runs under a slot: secrets lookup, read deadline, streaming read and HMAC comparison. It returns
// the verified body, or a status for a refusal.
func (s *server) authenticate(w http.ResponseWriter, r *http.Request, forge string, got []byte) ([]byte, int) {
	ctx := r.Context()
	secrets, err := s.Secrets.WebhookSecrets(ctx, forge)
	if err != nil {
		// Only the error's type is logged: a backend error's text is not ours to vouch for, and might carry
		// secret material.
		s.log.ErrorContext(ctx, "webhook_secrets_unavailable", "forge", forge, "error_type", errType(err))
		return nil, http.StatusServiceUnavailable
	}
	if len(secrets) > MaxSecrets {
		s.log.ErrorContext(ctx, "webhook_secrets_misconfigured", "forge", forge, "count", len(secrets))
		return nil, http.StatusServiceUnavailable
	}
	macs := newMACs(secrets)
	if len(macs) == 0 {
		// No usable secret: nothing can verify, so don't read the body.
		s.log.DebugContext(ctx, "webhook_signature_rejected", "reason", "no_secret")
		return nil, http.StatusUnauthorized
	}
	// A slow or idle body ends at the deadline instead of holding the slot. A writer that cannot set deadlines
	// (a test recorder) is fine; any other failure is not.
	err = http.NewResponseController(w).SetReadDeadline(s.Clock.Now().Add(s.BodyReadTimeout))
	if err != nil && !errors.Is(err, http.ErrNotSupported) {
		s.log.ErrorContext(ctx, "webhook_read_deadline_failed", "error_type", errType(err))
		return nil, http.StatusServiceUnavailable
	}
	body, status := readBody(w, r, macs)
	if status != 0 {
		return nil, status
	}
	if !anyMatch(macs, got) {
		s.log.DebugContext(ctx, "webhook_signature_rejected", "reason", "mismatch")
		return nil, http.StatusUnauthorized
	}
	return body, 0
}

// errType names an error's dynamic type without its text.
func errType(err error) string {
	var b strings.Builder
	for e := err; e != nil; e = errors.Unwrap(e) {
		if b.Len() > 0 {
			b.WriteByte('>')
		}
		fmt.Fprintf(&b, "%T", e)
	}
	return b.String()
}

func isJSON(contentType string) bool {
	mt, _, err := mime.ParseMediaType(contentType)
	return err == nil && mt == "application/json"
}

// parseSignature decodes "sha256=<64 lowercase hex>". Anything else is malformed.
func parseSignature(h string) ([]byte, bool) {
	if !signatureRE.MatchString(h) {
		return nil, false
	}
	sig, err := hex.DecodeString(strings.TrimPrefix(h, signaturePrefix))
	return sig, err == nil
}

// newMACs returns one HMAC-SHA256 per non-empty secret. An empty secret never verifies: the MAC under an empty
// key is computable by anyone.
func newMACs(secrets [][]byte) []hash.Hash {
	var macs []hash.Hash
	for _, secret := range secrets {
		if len(secret) > 0 {
			macs = append(macs, hmac.New(sha256.New, secret))
		}
	}
	return macs
}

// readBody streams the body, at most [MaxBodyBytes], into a buffer sized from Content-Length and feeds every
// MAC as it goes, so the body is neither read twice nor copied twice. It returns a status for a refusal.
func readBody(w http.ResponseWriter, r *http.Request, macs []hash.Hash) ([]byte, int) {
	buf := &sliceWriter{}
	if n := r.ContentLength; n > 0 {
		buf.b = make([]byte, 0, min(n, MaxBodyBytes))
	}
	writers := make([]io.Writer, 0, len(macs)+1)
	writers = append(writers, buf)
	for _, m := range macs {
		writers = append(writers, m)
	}
	_, err := io.Copy(io.MultiWriter(writers...), http.MaxBytesReader(w, r.Body, MaxBodyBytes))
	if err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			return nil, http.StatusRequestEntityTooLarge
		}
		return nil, http.StatusBadRequest
	}
	return buf.b, 0
}

// sliceWriter appends to a slice that may be pre-sized, so a body of the declared length is stored once.
type sliceWriter struct{ b []byte }

func (w *sliceWriter) Write(p []byte) (int, error) {
	w.b = append(w.b, p...)
	return len(p), nil
}

// anyMatch reports whether got is any MAC's sum. It checks every MAC without stopping early, and compares with
// [hmac.Equal].
func anyMatch(macs []hash.Hash, got []byte) bool {
	matched := false
	for _, m := range macs {
		if hmac.Equal(m.Sum(nil), got) {
			matched = true
		}
	}
	return matched
}
