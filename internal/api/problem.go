// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"encoding/json"
	"net/http"

	"github.com/elliott-davis/lightsout/internal/api/gen"
)

// title returns the fixed problem title for status, or ok=false for a status the API does not use. A problem
// response never carries request content or internal error text, so nothing an attacker sends can be reflected
// back (SEC-1).
func title(status int) (string, bool) {
	switch status {
	case http.StatusBadRequest:
		return "Bad request", true
	case http.StatusUnauthorized:
		return "Signature verification failed", true
	case http.StatusForbidden:
		return "Forbidden", true
	case http.StatusNotFound:
		return "Not found", true
	case http.StatusMethodNotAllowed:
		return "Method not allowed", true
	case http.StatusConflict:
		return "Conflict", true
	case http.StatusLengthRequired:
		return "Length required", true
	case http.StatusRequestEntityTooLarge:
		return "Payload too large", true
	case http.StatusUnsupportedMediaType:
		return "Unsupported media type", true
	case http.StatusServiceUnavailable:
		return "Service unavailable", true
	}
	return "", false
}

// problem builds the fixed RFC 9457 body for status.
func problem(status int) gen.Problem {
	t, ok := title(status)
	if !ok {
		status = http.StatusServiceUnavailable
		t, _ = title(status)
	}
	return gen.Problem{Type: "about:blank", Title: t, Status: status}
}

// writeProblem writes the fixed problem for status. It is used outside the generated response types: by the
// signature middleware and by the generated code's error hooks.
func writeProblem(w http.ResponseWriter, status int) {
	p := problem(status)
	body, err := json.Marshal(p)
	if err != nil {
		w.WriteHeader(p.Status)
		return
	}
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(p.Status)
	_, _ = w.Write(body) // the client went away; there is nobody to tell
}
