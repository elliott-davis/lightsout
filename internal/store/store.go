// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

// Package store is the control plane's durable state (NFR-4, NFR-5, SEC-10).
//
// One [Store.Tx] is one transaction at READ COMMITTED isolation. The caller's state change, [authz.Tx.Consume],
// the grant's audit append and the audit head advance commit or roll back together. Invariants come from explicit
// conditions, not from isolation: the consumed-decision key is unique, a state update is a compare-and-swap on the
// row version and the current revision, and each audit chain has a head row that serializes its appends.
//
// There are two audit chains. The decision chain is written inside state transactions through [Txn.Append]. The
// denial chain is written by [Store.Denials] in its own transactions on a reserved connection pool, so a denial
// persists even when the caller's transaction rolls back or every worker connection is busy.
//
// Nothing here retries. A callback may do live lookups and write denials, so it is not pure: the caller retries
// the whole operation explicitly.
//
// Implementations: [github.com/elliott-davis/lightsout/internal/store/memstore] for tests and
// [github.com/elliott-davis/lightsout/internal/store/pgstore] for production. Both pass
// [github.com/elliott-davis/lightsout/internal/store/storetest].
package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"
	"unicode/utf8"

	"github.com/elliott-davis/lightsout/internal/audit"
	"github.com/elliott-davis/lightsout/internal/authz"
)

// Audit chain IDs.
const (
	ChainDecision = "decision" // written in state transactions
	ChainDenial   = "denial"   // written in its own transactions on the reserved pool
)

// Chains lists both chain IDs.
func Chains() []string { return []string{ChainDecision, ChainDenial} }

// Errors.
var (
	// ErrConflict means a compare-and-swap lost: the row version or the current revision is not what the caller
	// observed, or the row already exists.
	ErrConflict = errors.New("store: conflict")
	// ErrNotFound means the row does not exist.
	ErrNotFound = errors.New("store: not found")
	// ErrLeaseLost means the lease generation is no longer current (expired and re-leased, or already completed).
	ErrLeaseLost = errors.New("store: lease lost")
	// ErrDeliveryConflict means a delivery ID was seen before with a different body digest.
	ErrDeliveryConflict = errors.New("store: delivery ID reused with a different digest")
	// ErrDuplicateWork means a work item with the same key already exists.
	ErrDuplicateWork = errors.New("store: duplicate work item key")
	// ErrInvalid is wrapped by every input validation failure.
	ErrInvalid = errors.New("store: invalid input")
	// ErrReadOnly is returned when a read-only backend is asked to append.
	ErrReadOnly = errors.New("store: read-only audit backend")
	// ErrTxDone means a [Txn] was used after its transaction function returned.
	ErrTxDone = errors.New("store: transaction finished")
	// ErrRetry means the database aborted the transaction as a deadlock victim (40P01), a serialization failure
	// (40001) or a lock timeout (55P03). Nothing was committed and the store did not retry: the caller may run the
	// whole operation again, including its authorization.
	ErrRetry = errors.New("store: transaction aborted, retry the operation")
	// ErrNoCheckpoint means a chain has entries but no external checkpoint, and bootstrap was not requested.
	ErrNoCheckpoint = errors.New("store: chain has entries but no checkpoint")
)

// Kind is the kind of a state row.
type Kind string

// Row kinds.
const (
	KindIssue   Kind = "issue"
	KindChange  Kind = "change"
	KindFeature Kind = "feature"
	KindTrain   Kind = "train"
)

// Version is a row's compare-and-swap counter. It starts at 1 when the row is created. It is distinct from the
// payload schema version, from the current revision and from the approved revision.
type Version int64

// Size bounds.
const (
	MaxKeyBytes     = 256
	MaxPayloadBytes = 1 << 20
)

// Row is one piece of state. Invariants live in the columns and the evolving payload is versioned JSON.
type Row struct {
	Kind Kind
	// ID is the stable forge node ID (for an issue, its node ID, which survives a transfer).
	ID string
	// Repo is the current repository. It may change when an issue is transferred.
	Repo string
	// Version is set on read. It is ignored by [Txn.Put], which takes the expected version separately.
	Version Version
	// CurrentRevision is the subject's current proposal or head revision digest (40 or 64 lowercase hex), or empty
	// if it has none yet. An action handler resolves authz.Target.Revision from it in the same [Txn] that applies
	// the grant, and [Txn.Put] compares it, so an approval binds to the exact current proposal and a revision that
	// moved after the check is a [ErrConflict] (CON-8, SEC-10).
	CurrentRevision string
	// ApprovedRevision is the last approved revision digest (same format), or empty if none was approved. It is
	// recorded, not compared: it is the evidence of what was approved, whereas CurrentRevision is the CAS guard.
	ApprovedRevision string
	// SchemaVersion is the payload schema version, at least 1.
	SchemaVersion int
	// Payload is a JSON object.
	Payload json.RawMessage
}

// Validate checks the row's own invariants. The error wraps [ErrInvalid].
func (r Row) Validate() error {
	switch r.Kind {
	case KindIssue, KindChange, KindFeature, KindTrain:
	default:
		return invalidf("row kind %q", string(r.Kind))
	}
	if err := checkKey("row id", r.ID); err != nil {
		return err
	}
	if err := checkKey("row repo", r.Repo); err != nil {
		return err
	}
	if r.CurrentRevision != "" && !validDigest(r.CurrentRevision) {
		return invalidf("current revision is not a 40- or 64-digit lowercase hex digest")
	}
	if r.ApprovedRevision != "" && !validDigest(r.ApprovedRevision) {
		return invalidf("approved revision is not a 40- or 64-digit lowercase hex digest")
	}
	if r.SchemaVersion < 1 {
		return invalidf("schema version %d, want at least 1", r.SchemaVersion)
	}
	return checkObject("row payload", r.Payload, false)
}

// Digest is a SHA-256 digest of a delivery body.
type Digest [32]byte

// WorkItem is something the event loop must do. It says only "re-read X": events are hints, never authority.
type WorkItem struct {
	// Key is unique for the life of the installation. Derive it from the delivery (forge and delivery ID) so a
	// redelivery cannot enqueue twice.
	Key  string
	Kind string
	// Payload is a JSON object, or empty for {}.
	Payload json.RawMessage
	// Attempts is how many times the item was rescheduled. It is set on read and ignored on enqueue.
	Attempts int
}

// Validate checks the item. The error wraps [ErrInvalid].
func (w WorkItem) Validate() error {
	if err := checkKey("work key", w.Key); err != nil {
		return err
	}
	if err := checkKey("work kind", w.Kind); err != nil {
		return err
	}
	return checkObject("work payload", w.Payload, true)
}

// Lease is a time-limited, fenced claim on a work item. Generation increases on every lease of the item, so a
// holder whose lease expired and was taken over cannot complete it (fencing).
type Lease struct {
	WorkItem
	Owner      string
	Generation int64
	Expires    time.Time
}

// Store is the control plane's durable state.
type Store interface {
	// Tx runs fn in one READ COMMITTED transaction. It commits if fn returns nil and rolls back otherwise. It
	// never retries. The Txn must not be used after fn returns, and is not safe for concurrent use: use it from
	// the goroutine that runs fn.
	Tx(ctx context.Context, fn func(ctx context.Context, tx Txn) error) error
	// Denials is the denial chain, written in its own short transactions over a reserved pool. Wrap it in an
	// [audit.Log] and pass that to authz as the Auditor.
	Denials() audit.Backend
	// Decisions is a read-only view of the decision chain, for verification and checkpoints. Its AppendNext
	// always fails with [ErrReadOnly]: the decision chain is written only through [Txn.Append].
	Decisions() audit.Backend
	// Lease claims up to max pending items for owner for ttl, bumping each item's generation. Items another
	// leaser holds, or whose lease has not expired, are skipped (SKIP LOCKED semantics). Oldest first.
	Lease(ctx context.Context, owner string, maxItems int, ttl time.Duration) ([]Lease, error)
	// Close releases the store's resources.
	Close() error
}

// Txn is one transaction. Consume and Append come from [authz.Tx].
//
// A transaction that authorizes several decisions must Consume every decision ID, in sorted order, before its
// first Append. Append takes the decision chain's head lock until the transaction ends, so a transaction that
// appends before it finishes consuming can deadlock with one that consumed an ID it still needs. PostgreSQL would
// abort one of them with a deadlock error. Consuming first, in one global order, makes the waits acyclic.
//
// Two [authz.Authorizer.Authorize] calls in one transaction cannot follow that rule, because each one consumes and
// then appends before returning. Such a transaction can deadlock with another one. PostgreSQL then aborts one of
// them (40P01), the store reports [ErrRetry], and nothing of it is committed: it fails closed. The caller may run
// the whole operation again. Prefer one Authorize per transaction.
type Txn interface {
	// RecordDelivery records (forge, deliveryID, digest) and enqueues work in this transaction. It returns
	// false, with no new work item, if the same ID and digest were already recorded (an idempotent repeat). The
	// same ID with a different digest returns [ErrDeliveryConflict].
	RecordDelivery(ctx context.Context, forge, deliveryID string, digest Digest, work WorkItem) (bool, error)
	// Get returns the row, or [ErrNotFound].
	Get(ctx context.Context, kind Kind, id string) (Row, error)
	// Put writes row. With expect 0 it creates the row and fails with [ErrConflict] if it exists; expectRevision
	// must then be empty ([ErrInvalid] otherwise). Otherwise it updates only if the stored version is expect and the stored current revision is expectRevision (empty
	// means none), else [ErrConflict]. It returns the new version.
	Put(ctx context.Context, row Row, expect Version, expectRevision string) (Version, error)
	// Enqueue adds a work item, or returns [ErrDuplicateWork] if the key exists.
	Enqueue(ctx context.Context, w WorkItem) error
	// Complete marks the leased item done. It returns [ErrLeaseLost] unless the lease's generation is current and
	// the lease has not expired: once the store's clock reaches Lease.Expires the holder is fenced out even if the
	// item has not been leased again, so a slow holder cannot act on an item another worker may be about to take.
	Complete(ctx context.Context, l Lease) error
	// Reschedule gives the item back for a later retry: fenced like [Txn.Complete], it clears the lease, makes the
	// item leasable again only from notBefore on, and increments its attempt count. The generation is not reset.
	Reschedule(ctx context.Context, l Lease, notBefore time.Time) error
	// DeadLetter parks the item for good: fenced like [Txn.Complete], it marks the item dead with a short reason
	// code and it is never leased again.
	DeadLetter(ctx context.Context, l Lease, reason string) error
	authz.Tx
}

func invalidf(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, args...))
}

func checkKey(name, s string) error {
	if s == "" || len(s) > MaxKeyBytes {
		return invalidf("%s must be 1..%d bytes", name, MaxKeyBytes)
	}
	for i := range len(s) {
		if s[i] < 0x20 || s[i] > 0x7e {
			return invalidf("%s must be printable ASCII", name)
		}
	}
	return nil
}

// checkObject requires raw to be a JSON object (or empty if allowEmpty) that PostgreSQL's jsonb accepts too, so
// every store rejects the same payloads: no NUL or unpaired surrogate escapes, valid UTF-8, and numbers that fit
// numeric.
func checkObject(name string, raw json.RawMessage, allowEmpty bool) error {
	if len(raw) == 0 {
		if allowEmpty {
			return nil
		}
		return invalidf("%s is required", name)
	}
	if len(raw) > MaxPayloadBytes {
		return invalidf("%s longer than %d bytes", name, MaxPayloadBytes)
	}
	if !utf8.Valid(raw) {
		return invalidf("%s is not valid UTF-8", name)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil || m == nil {
		return invalidf("%s is not a JSON object", name)
	}
	if err := scanJSON(raw); err != nil {
		return invalidf("%s: %v", name, err)
	}
	return nil
}

// maxNumberBytes, maxExponent and maxScale keep number literals inside PostgreSQL's numeric limits (131072 digits
// before the decimal point, 16383 after it), more conservatively on the integer side. A payload that passes here
// is not refused by jsonb for its numbers; the pgstore error mapping is the backstop for anything this misses.
const (
	maxNumberBytes = 4096
	maxExponent    = 100000
	maxScale       = 16383
)

// scanJSON walks syntactically valid JSON and rejects what jsonb would: \u0000, unpaired surrogate escapes and
// out-of-range numbers.
func scanJSON(raw []byte) error {
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		switch {
		case c == '"':
			end, err := scanString(raw, i+1)
			if err != nil {
				return err
			}
			i = end
		case c == '-' || (c >= '0' && c <= '9'):
			j := i
			for j < len(raw) && (raw[j] == '-' || raw[j] == '+' || raw[j] == '.' || raw[j] == 'e' || raw[j] == 'E' || (raw[j] >= '0' && raw[j] <= '9')) {
				j++
			}
			if err := checkNumber(raw[i:j]); err != nil {
				return err
			}
			i = j - 1
		}
	}
	return nil
}

// scanString checks a string body that starts at i, after its opening quote, and returns the index of its
// closing quote.
func scanString(raw []byte, i int) (int, error) {
	for ; i < len(raw); i++ {
		switch raw[i] {
		case '"':
			return i, nil
		case '\\':
			i++
			if raw[i] != 'u' {
				continue
			}
			end, err := checkUnicodeEscape(raw, i+1)
			if err != nil {
				return 0, err
			}
			i = end
		}
	}
	return i, nil
}

// checkUnicodeEscape checks the escape whose four hex digits start at i, and its trailing low surrogate if it is
// a high one. It returns the index of the last byte it consumed.
func checkUnicodeEscape(raw []byte, i int) (int, error) {
	v := hex4(raw[i:])
	i += 3
	switch {
	case v == 0:
		return 0, errors.New("contains a \\u0000 escape")
	case v >= 0xd800 && v <= 0xdbff:
		if i+6 >= len(raw) || raw[i+1] != '\\' || raw[i+2] != 'u' {
			return 0, errors.New("contains an unpaired surrogate escape")
		}
		if lo := hex4(raw[i+3:]); lo < 0xdc00 || lo > 0xdfff {
			return 0, errors.New("contains an unpaired surrogate escape")
		}
		return i + 6, nil
	case v >= 0xdc00 && v <= 0xdfff:
		return 0, errors.New("contains an unpaired surrogate escape")
	}
	return i, nil
}

// hex4 parses four hex digits of a string already known to be valid JSON.
func hex4(b []byte) int {
	v := 0
	for _, c := range b[:4] {
		switch {
		case c >= '0' && c <= '9':
			v = v<<4 | int(c-'0')
		case c >= 'a' && c <= 'f':
			v = v<<4 | int(c-'a'+10)
		default:
			v = v<<4 | int(c-'A'+10)
		}
	}
	return v
}

func checkNumber(tok []byte) error {
	if len(tok) > maxNumberBytes {
		return errors.New("contains an oversized number")
	}
	fraction, exp, expSign, inFraction, inExp := 0, 0, 1, false, false
	for _, c := range tok {
		switch {
		case c == '.':
			inFraction = true
		case c == 'e' || c == 'E':
			inFraction, inExp = false, true
		case c == '-' && inExp:
			expSign = -1
		case c >= '0' && c <= '9':
			switch {
			case inExp:
				exp = exp*10 + int(c-'0')
				if exp >= maxExponent {
					return errors.New("contains a number with an out-of-range exponent")
				}
			case inFraction:
				fraction++
			}
		}
	}
	if fraction-expSign*exp > maxScale {
		return errors.New("contains a number with too many fraction digits")
	}
	return nil
}

func validDigest(s string) bool {
	if len(s) != 40 && len(s) != 64 {
		return false
	}
	for i := range len(s) {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// ValidateKey checks a delivery forge or ID. The error wraps [ErrInvalid].
func ValidateKey(name, s string) error { return checkKey(name, s) }

// ValidateRowKey checks the kind and ID of a row lookup. The error wraps [ErrInvalid].
func ValidateRowKey(kind Kind, id string) error {
	switch kind {
	case KindIssue, KindChange, KindFeature, KindTrain:
	default:
		return invalidf("row kind %q", string(kind))
	}
	return checkKey("row id", id)
}

// ValidateTime checks that t is a real instant in years 1970 to 9999. The error wraps [ErrInvalid].
func ValidateTime(name string, t time.Time) error {
	if y := t.UTC().Year(); t.IsZero() || y < 1970 || y > 9999 {
		return invalidf("%s outside years 1970..9999", name)
	}
	return nil
}
