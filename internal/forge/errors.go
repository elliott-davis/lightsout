// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

package forge

import (
	"errors"
	"fmt"
	"time"
)

// Sentinel errors. Adapters wrap them with context, and callers match them with [errors.Is].
var (
	// ErrNotFound means the object does not exist, or is not visible to the caller.
	ErrNotFound = errors.New("forge: not found")
	// ErrForbidden means the caller is not allowed to do this. Pusher scoping denials are ErrForbidden (SEC-2, SEC-3).
	ErrForbidden = errors.New("forge: forbidden")
	// ErrConflict means a compare-and-swap lost: a stale parent or head SHA.
	ErrConflict = errors.New("forge: conflict")
	// ErrTooLarge means a size or entry-count limit was exceeded.
	ErrTooLarge = errors.New("forge: too large")
	// ErrIncomplete means the forge could not return a complete answer. Consumers block.
	ErrIncomplete = errors.New("forge: incomplete result")
	// ErrSymlink means a path has a symlink in one of its components.
	ErrSymlink = errors.New("forge: symlink in path")
	// ErrInvalid means the input is malformed: an empty change, a duplicate path, a delete of a missing file.
	ErrInvalid = errors.New("forge: invalid input")
	// ErrUnsupported means the forge or the object does not support the operation, such as opening a gitlink.
	ErrUnsupported = errors.New("forge: unsupported")
	// ErrRateLimited is wrapped by [RateLimitError].
	ErrRateLimited = errors.New("forge: rate limited")
)

// RateLimitError says the forge asked the caller to back off.
type RateLimitError struct {
	RetryAfter time.Duration
}

func (e *RateLimitError) Error() string {
	return fmt.Sprintf("forge: rate limited, retry after %s", e.RetryAfter)
}

// Unwrap lets errors.Is(err, ErrRateLimited) match.
func (e *RateLimitError) Unwrap() error { return ErrRateLimited }
