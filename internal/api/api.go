// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

// Package api serves the factory's HTTP surface. The contract is api/openapi.yaml and the handler interface is
// generated from it into internal/api/gen.
//
// The webhook endpoint (NFR-5) verifies the signature over the bounded raw bytes before anything is decoded,
// checks that the signed installation and repository belong to this install, and records the delivery and its
// work item atomically (NFR-4). The work item is a hint to re-read, never authority.
package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/elliott-davis/lightsout/internal/api/gen"
	"github.com/elliott-davis/lightsout/internal/audit"
	"github.com/elliott-davis/lightsout/internal/forge"
	"github.com/elliott-davis/lightsout/internal/store"
)

// WorkKind is the kind of the work item a delivery enqueues.
const WorkKind = "forge-event"

// Receipts records a delivery and enqueues its work item in one transaction. The receipt ID is derived from the
// body digest ("sha256-<hex>"), not from the unsigned delivery header. It returns false for an idempotent repeat
// and an error wrapping [store.ErrDeliveryConflict] for a receipt ID seen with a different digest.
type Receipts interface {
	RecordDelivery(ctx context.Context, forge, receiptID string, digest store.Digest, work store.WorkItem) (bool, error)
}

// Readiness says whether the server can take traffic.
type Readiness interface {
	Ready(ctx context.Context) error
}

// Secrets returns the current webhook secrets for a forge. More than one allows rotation. Callers never log them.
type Secrets interface {
	WebhookSecrets(ctx context.Context, forge string) ([][]byte, error)
}

// Scope says whether the signed installation and repository belong to this install. An error fails closed.
//
// An empty repositoryID means installation-only: it asks whether the installation belongs to this install and
// must never match a repository-level entry. Scope comes only from the install config, never from a payload.
type Scope interface {
	Allowed(ctx context.Context, forge, installationID, repositoryID string) (bool, error)
}

// Auditor appends to the audit log. [audit.Log] implements it.
type Auditor interface {
	Append(ctx context.Context, r audit.Record) (audit.Entry, error)
}

// Deps are the server's explicit dependencies. All are required.
type Deps struct {
	Logger    *slog.Logger
	Receipts  Receipts
	Readiness Readiness
	Secrets   Secrets
	Scope     Scope
	Audit     Auditor
	// Identity is the factory's workload identity and Version its build version (RUN-5). Audit entries for
	// conflicts name them.
	Identity string
	Version  string
	// Parsers maps a forge name to its payload parser. It must have an entry for every forge in the spec.
	Parsers map[string]forge.EventParser
	// MaxConcurrentBodies bounds how many webhook requests may be in the authentication step (secrets lookup, body
	// read and HMAC) at once. Zero means [DefaultMaxConcurrentBodies].
	MaxConcurrentBodies int
	// SlotWait bounds how long a request waits for one of those slots before getting 503, so idle unauthenticated
	// connections cannot lock signed deliveries out. Zero means [DefaultSlotWait].
	SlotWait time.Duration
	// BodyReadTimeout is the read deadline set before the body is read. Zero means [DefaultBodyReadTimeout].
	BodyReadTimeout time.Duration
	// Clock supplies the time and timers. Nil means the system clock.
	Clock Clock
}

// Clock is the time source, injected so timeouts are testable without sleeping.
type Clock interface {
	Now() time.Time
	// After returns a channel that receives once after d.
	After(d time.Duration) <-chan time.Time
}

type systemClock struct{}

func (systemClock) Now() time.Time                         { return time.Now() }
func (systemClock) After(d time.Duration) <-chan time.Time { return time.After(d) }

type server struct {
	Deps
	log   *slog.Logger
	slots chan struct{} // authentication-step semaphore
}

var _ gen.StrictServerInterface = (*server)(nil)

// New returns the HTTP handler for the OpenAPI document, built on chi.
func New(d Deps) (http.Handler, error) {
	switch {
	case d.Logger == nil:
		return nil, errors.New("api: nil logger")
	case d.Receipts == nil:
		return nil, errors.New("api: nil receipts")
	case d.Readiness == nil:
		return nil, errors.New("api: nil readiness")
	case d.Secrets == nil:
		return nil, errors.New("api: nil secrets")
	case d.Scope == nil:
		return nil, errors.New("api: nil scope")
	case d.Audit == nil:
		return nil, errors.New("api: nil audit")
	case d.Identity == "" || d.Version == "":
		return nil, errors.New("api: identity and version are required")
	}
	// Every forge in the spec's enum needs a parser. Add new enum values here.
	for _, f := range []gen.Forge{gen.Github} {
		if d.Parsers[string(f)] == nil {
			return nil, fmt.Errorf("api: no parser for forge %s", f)
		}
	}
	d.Parsers = maps.Clone(d.Parsers) // the caller's map must not change the server's parsers later
	if d.MaxConcurrentBodies < 0 || d.SlotWait < 0 || d.BodyReadTimeout < 0 {
		return nil, errors.New("api: negative limit")
	}
	if d.SlotWait == 0 {
		d.SlotWait = DefaultSlotWait
	}
	if d.BodyReadTimeout == 0 {
		d.BodyReadTimeout = DefaultBodyReadTimeout
	}
	if d.Clock == nil {
		d.Clock = systemClock{}
	}
	n := d.MaxConcurrentBodies
	if n == 0 {
		n = DefaultMaxConcurrentBodies
	}
	s := &server{Deps: d, log: d.Logger, slots: make(chan struct{}, n)}
	strict := gen.NewStrictHandlerWithOptions(s, nil, gen.StrictHTTPServerOptions{
		RequestErrorHandlerFunc: func(w http.ResponseWriter, _ *http.Request, _ error) {
			writeProblem(w, http.StatusBadRequest)
		},
		ResponseErrorHandlerFunc: func(w http.ResponseWriter, r *http.Request, err error) {
			s.log.ErrorContext(r.Context(), "response_failed", "error_type", errType(err))
			writeProblem(w, http.StatusServiceUnavailable)
		},
	})
	router := chi.NewRouter()
	router.NotFound(func(w http.ResponseWriter, _ *http.Request) { writeProblem(w, http.StatusNotFound) })
	router.MethodNotAllowed(func(w http.ResponseWriter, _ *http.Request) { writeProblem(w, http.StatusMethodNotAllowed) })
	return gen.HandlerWithOptions(strict, gen.ChiServerOptions{
		BaseRouter:  router,
		Middlewares: []gen.MiddlewareFunc{s.verifySignature},
		ErrorHandlerFunc: func(w http.ResponseWriter, _ *http.Request, err error) {
			writeProblem(w, paramErrorStatus(err))
		},
	}), nil
}

// paramErrorStatus maps a header or path binding failure to a status without echoing it. A missing, duplicated
// or malformed signature header is an authentication failure.
func paramErrorStatus(err error) int {
	var (
		missing *gen.RequiredHeaderError
		many    *gen.TooManyValuesForParamError
		format  *gen.InvalidParamFormatError
	)
	const sigHeader = "X-Hub-Signature-256"
	switch {
	case errors.As(err, &missing) && missing.ParamName == sigHeader,
		errors.As(err, &many) && many.ParamName == sigHeader,
		errors.As(err, &format) && format.ParamName == sigHeader:
		return http.StatusUnauthorized
	default:
		return http.StatusBadRequest
	}
}

// GetHealth is liveness: the process answers.
func (s *server) GetHealth(context.Context, gen.GetHealthRequestObject) (gen.GetHealthResponseObject, error) {
	return gen.GetHealth200Response{}, nil
}

// GetReady reports readiness. The error is logged, never returned to the client.
func (s *server) GetReady(ctx context.Context, _ gen.GetReadyRequestObject) (gen.GetReadyResponseObject, error) {
	if err := s.Readiness.Ready(ctx); err != nil {
		s.log.WarnContext(ctx, "not_ready", "error", err)
		return gen.GetReady503ApplicationProblemPlusJSONResponse{
			ProblemApplicationProblemPlusJSONResponse: gen.ProblemApplicationProblemPlusJSONResponse(problem(http.StatusServiceUnavailable)),
		}, nil
	}
	return gen.GetReady200Response{}, nil
}

// ReceiveWebhook handles a delivery whose signature the middleware already verified. NFR-5.
func (s *server) ReceiveWebhook(ctx context.Context, req gen.ReceiveWebhookRequestObject) (gen.ReceiveWebhookResponseObject, error) {
	body, ok := verifiedBody(ctx)
	if !ok {
		// Unreachable through the router: the middleware always sets it. Fail closed.
		return nil, errors.New("api: webhook body was not verified")
	}
	forgeName, event, delivery := string(req.Forge), req.Params.XGitHubEvent, req.Params.XGitHubDelivery
	if !eventRE.MatchString(event) || !deliveryRE.MatchString(delivery) {
		return badRequest(), nil
	}
	log := s.log.With("forge", forgeName, "event", event, "delivery_id", delivery)

	hint, err := s.Parsers[forgeName](event, body)
	switch {
	case errors.Is(err, forge.ErrPing):
		log.DebugContext(ctx, "webhook_ping")
		return gen.ReceiveWebhook200Response{}, nil
	case errors.Is(err, forge.ErrUnsupportedEvent):
		log.DebugContext(ctx, "webhook_event_ignored")
		return gen.ReceiveWebhook202Response{}, nil
	case errors.Is(err, forge.ErrMalformedEvent), errors.Is(err, forge.ErrMissingScope):
		// A validly signed payload we cannot use is worth an operator's attention. No content is logged.
		log.WarnContext(ctx, "webhook_payload_rejected")
		return badRequest(), nil
	case err != nil:
		log.ErrorContext(ctx, "webhook_parse_failed", "error_type", errType(err))
		return unavailable(), nil
	}

	// Every repository the payload names must be in scope, and an installation-level event is checked by
	// installation alone (empty repository ID).
	repos := hint.ScopedRepositoryIDs()
	if len(repos) == 0 {
		repos = []string{""}
	}
	for _, repo := range repos {
		allowed, scopeErr := s.Scope.Allowed(ctx, forgeName, hint.InstallationID, repo)
		if scopeErr != nil {
			log.ErrorContext(ctx, "webhook_scope_check_failed", "error_type", errType(scopeErr))
			return unavailable(), nil
		}
		if !allowed {
			log.InfoContext(ctx, "webhook_out_of_scope", "installation_id", hint.InstallationID, "repository_id", repo)
			return gen.ReceiveWebhook403ApplicationProblemPlusJSONResponse(problem(http.StatusForbidden)), nil
		}
	}

	// The receipt is keyed by the digest of the verified body, not by the delivery ID: the delivery and event
	// headers are not signed, so anyone holding one signed body could replay it under fresh IDs, or squat a
	// real delivery's ID with a different body. The GitHub GUID is kept as metadata only.
	digest := store.Digest(sha256.Sum256(body))
	receiptID := "sha256-" + hex.EncodeToString(digest[:])
	work, err := workItem(forgeName, receiptID, delivery, hint)
	if err != nil {
		log.ErrorContext(ctx, "webhook_work_item_failed", "error_type", errType(err))
		return unavailable(), nil
	}
	isNew, err := s.Receipts.RecordDelivery(ctx, forgeName, receiptID, digest, work)
	switch {
	case errors.Is(err, store.ErrDeliveryConflict):
		return s.conflict(ctx, log, forgeName, delivery, event, hint.InstallationID, digest), nil
	case errors.Is(err, store.ErrDuplicateWork):
		// Another producer already holds this work key. Ingest owns the "delivery/" prefix, so this is a
		// conflict to look at, not a retry.
		log.WarnContext(ctx, "webhook_work_key_taken")
		return gen.ReceiveWebhook409ApplicationProblemPlusJSONResponse(problem(http.StatusConflict)), nil
	case err != nil:
		log.ErrorContext(ctx, "webhook_record_failed", "error", err)
		return unavailable(), nil
	case !isNew:
		log.InfoContext(ctx, "webhook_duplicate")
		return gen.ReceiveWebhook200Response{}, nil
	}
	log.InfoContext(ctx, "webhook_accepted")
	return gen.ReceiveWebhook202Response{}, nil
}

func unavailable() gen.ReceiveWebhookResponseObject {
	return gen.ReceiveWebhook503ApplicationProblemPlusJSONResponse(problem(http.StatusServiceUnavailable))
}

func badRequest() gen.ReceiveWebhookResponseObject {
	return gen.ReceiveWebhook400ApplicationProblemPlusJSONResponse{ProblemApplicationProblemPlusJSONResponse: gen.ProblemApplicationProblemPlusJSONResponse(problem(http.StatusBadRequest))}
}

// conflict audits a receipt whose key was seen with a different digest, then answers 409. Receipts are keyed by
// the body digest, so this means a SHA-256 collision and is unreachable in practice; the path stays because the
// store contract allows it. The store reports only that the
// digests differ, so the entry carries the new digest. If the audit append fails the request fails closed with
// 503, so the sender retries and the conflict is recorded the next time.
func (s *server) conflict(ctx context.Context, log *slog.Logger, forgeName, delivery, event, installation string, digest store.Digest) gen.ReceiveWebhookResponseObject {
	_, err := s.Audit.Append(ctx, audit.Record{
		Actor:           audit.Actor{Kind: audit.ActorFactory, ID: s.Identity},
		TemplateVersion: s.Version,
		Subject:         audit.Subject{Kind: audit.SubjectInstall, ID: installation},
		Action:          audit.ActionAdmin,
		Target:          "webhook-delivery-conflict",
		Outcome:         "rejected",
		Attrs: map[string]string{
			"forge":      forgeName,
			"delivery":   delivery,
			"event":      event,
			"new_digest": hex.EncodeToString(digest[:]),
		},
	})
	if err != nil {
		log.ErrorContext(ctx, "webhook_conflict_audit_failed", "error", err)
		return gen.ReceiveWebhook503ApplicationProblemPlusJSONResponse(problem(http.StatusServiceUnavailable))
	}
	log.WarnContext(ctx, "webhook_delivery_conflict")
	return gen.ReceiveWebhook409ApplicationProblemPlusJSONResponse(problem(http.StatusConflict))
}

// workPayload is the stored hint. It is a "re-read X" pointer, never authority, and never the raw body.
// DeliveryID is the forge's unsigned delivery header, kept as metadata for operators only.
type workPayload struct {
	Version    int             `json:"v"`
	Forge      string          `json:"forge"`
	DeliveryID string          `json:"delivery_id"`
	Hint       forge.EventHint `json:"hint"`
}

// WorkKeyPrefix is reserved for webhook ingest: no other producer may enqueue a work item whose key starts with
// it. The key is "delivery/<forge>/<receipt ID>", where the receipt ID is "sha256-<hex body digest>", so a
// redelivery of the same bytes cannot enqueue twice whatever its headers say.
const WorkKeyPrefix = "delivery/"

func workKey(forgeName, receiptID string) string { return WorkKeyPrefix + forgeName + "/" + receiptID }

func workItem(forgeName, receiptID, delivery string, h forge.EventHint) (store.WorkItem, error) {
	payload, err := json.Marshal(workPayload{Version: 1, Forge: forgeName, DeliveryID: delivery, Hint: h})
	if err != nil {
		return store.WorkItem{}, fmt.Errorf("marshal work payload: %w", err)
	}
	return store.WorkItem{Key: workKey(forgeName, receiptID), Kind: WorkKind, Payload: payload}, nil
}
