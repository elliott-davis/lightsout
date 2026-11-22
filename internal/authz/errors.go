// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

package authz

import (
	"errors"
	"fmt"
)

// Errors.
var (
	// ErrDenied is wrapped by every [DeniedError].
	ErrDenied = errors.New("authz: denied")
	// ErrReplayed is returned by [Tx.Consume] when the decision ID was already consumed.
	ErrReplayed = errors.New("authz: decision already consumed")
)

// Reason is a short, closed code saying why a decision was denied.
type Reason string

// Denial reasons, in the order the checks run.
const (
	ReasonUnauthenticated Reason = "unauthenticated"
	ReasonNotAPerson      Reason = "not-a-person"
	ReasonWrongOperation  Reason = "wrong-operation"
	ReasonWrongPlace      Reason = "wrong-place"
	// ReasonMalformed covers input the adapter should never send: a revision that isn't a hex digest, an unknown
	// channel, unknown integrity, a decision ID or principal ID that isn't plain ASCII of 1 to 256 bytes, a choice
	// that isn't a digest, and a zero or future creation time.
	ReasonMalformed   Reason = "malformed"
	ReasonStale       Reason = "stale"
	ReasonWrongChoice Reason = "wrong-choice"
	ReasonEdited      Reason = "edited"
	ReasonQuoted      Reason = "quoted"
	ReasonExpired     Reason = "expired"
	ReasonNoRole      Reason = "no-role"
	ReasonRoleError   Reason = "role-error"
	ReasonReplayed    Reason = "replayed"
)

// DeniedError says a decision was denied. It carries no client-supplied text. It wraps [ErrDenied].
type DeniedError struct {
	Reason Reason
}

func (e *DeniedError) Error() string { return fmt.Sprintf("authz: denied: %s", e.Reason) }

// Unwrap returns [ErrDenied].
func (e *DeniedError) Unwrap() error { return ErrDenied }
