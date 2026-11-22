// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"errors"
	"fmt"
	"time"
)

const (
	// MaxReadLimit is the largest page [Log.Read] returns.
	MaxReadLimit = 1000
	verifyPage   = 500
)

// SealFunc builds the next entry from the current head. A backend calls it exactly once per append while holding
// whatever serializes appends (a mutex, a file lock, a database transaction), and stores the result atomically.
type SealFunc func(prev Head) (Entry, error)

// Backend stores entries. It has no update, delete or truncate operation (NFR-4). Holding a Backend is a write
// capability: it can append entries with any seal, so only the [Log]'s owner should hold it.
type Backend interface {
	// AppendNext seals and stores the next entry. It must verify that the sealed entry extends the current head.
	AppendNext(ctx context.Context, seal SealFunc) (Entry, error)
	// Read returns up to limit entries in ascending order starting at fromSeq (1-based). It returns an empty
	// slice past the end.
	Read(ctx context.Context, fromSeq uint64, limit int) ([]Entry, error)
	// Head returns the head of the chain.
	Head(ctx context.Context) (Head, error)
}

// Log is the append-only audit log. It is safe for concurrent use if its backend is.
type Log struct {
	b     Backend
	clock func() time.Time
}

// New returns a log over b. The clock is injected so tests need not sleep.
func New(b Backend, clock func() time.Time) (*Log, error) {
	if b == nil {
		return nil, errors.New("audit: nil backend")
	}
	if clock == nil {
		return nil, errors.New("audit: nil clock")
	}
	return &Log{b: b, clock: clock}, nil
}

// Append validates r, seals it as the next entry and stores it. The record is deep-copied, so later changes by
// the caller do not affect the log. The entry time is the clock's value as given (UTC, truncated to
// microseconds): it is not clamped, so entries are ordered by Seq and times may go backwards if the clock does.
// A time outside years 1970..9999 is rejected with [ErrInvalidRecord].
//
// Callers must redact secrets from the record first: the log keeps everything it is given.
func (l *Log) Append(ctx context.Context, r Record) (Entry, error) {
	if err := validateRecord(r); err != nil {
		return Entry{}, err
	}
	rec := cloneRecord(r)
	e, err := l.b.AppendNext(ctx, func(prev Head) (Entry, error) {
		t := l.clock().UTC().Truncate(time.Microsecond)
		if !validTime(t) {
			return Entry{}, &RecordError{Field: "time", Reason: "outside years 1970..9999"}
		}
		e := Entry{
			Format:   FormatVersion,
			Seq:      prev.Seq + 1,
			Time:     t,
			Record:   cloneRecord(rec),
			PrevHash: prev.Hash,
		}
		e.Hash = computeHash(e)
		return e, nil
	})
	if err != nil {
		return Entry{}, fmt.Errorf("append audit entry: %w", err)
	}
	return cloneEntry(e), nil
}

// Read returns up to limit (1..MaxReadLimit) entries in ascending order starting at fromSeq. fromSeq 0 means 1.
// The result is a deep copy.
func (l *Log) Read(ctx context.Context, fromSeq uint64, limit int) ([]Entry, error) {
	if limit < 1 || limit > MaxReadLimit {
		return nil, fmt.Errorf("audit: read limit %d out of range 1..%d", limit, MaxReadLimit)
	}
	if fromSeq == 0 {
		fromSeq = 1
	}
	es, err := l.b.Read(ctx, fromSeq, limit)
	if err != nil {
		return nil, fmt.Errorf("read audit entries: %w", err)
	}
	return cloneEntries(es), nil
}

// Head returns the current head. Save it outside the log's storage (another system, a signed release record) and
// pass it to [Log.VerifyAgainst] later. A saved head detects tail truncation and full rewrites, which local
// verification cannot: a chain with its last entries removed is still a valid chain, and an unkeyed chain
// recomputed from some entry onward is still consistent.
func (l *Log) Head(ctx context.Context) (Head, error) {
	h, err := l.b.Head(ctx)
	if err != nil {
		return Head{}, fmt.Errorf("read audit head: %w", err)
	}
	return h, nil
}

// Verify walks the whole chain in pages and checks the format, contiguous sequence numbers from 1, previous-hash
// links, recomputed hashes and record validity. At the first bad entry it returns a *[ChainError] wrapping
// [ErrBrokenChain]. It returns the verified head.
//
// Verify detects corruption and inconsistent edits only. The chain is unkeyed, so a deliberate rewrite that
// recomputes every hash from the edit point onward passes, as does a log whose last entries were removed. Use
// [Log.VerifyAgainst] with a checkpoint kept outside the log's storage to detect those.
func (l *Log) Verify(ctx context.Context) (Head, error) {
	return l.verify(ctx, nil)
}

// VerifyAgainst is [Log.Verify] plus a check that the chain contains checkpoint.Seq with exactly
// checkpoint.Hash. A shorter chain (tail truncation) or a different hash (rewrite) fails with [ErrBrokenChain].
func (l *Log) VerifyAgainst(ctx context.Context, checkpoint Head) error {
	if checkpoint.Seq == 0 && checkpoint.Hash != (Hash{}) {
		return &ChainError{Reason: "checkpoint has a hash but no sequence number"}
	}
	_, err := l.verify(ctx, &checkpoint)
	return err
}

func (l *Log) verify(ctx context.Context, cp *Head) (Head, error) {
	var prev Head
	for {
		page, err := l.b.Read(ctx, prev.Seq+1, verifyPage)
		if err != nil {
			return Head{}, fmt.Errorf("read audit entries: %w", err)
		}
		if len(page) == 0 {
			break
		}
		for i := range page {
			e := &page[i]
			if err := checkLink(prev, *e); err != nil {
				return Head{}, err
			}
			if cp != nil && e.Seq == cp.Seq && e.Hash != cp.Hash {
				return Head{}, &ChainError{Seq: e.Seq, Reason: "hash differs from checkpoint"}
			}
			prev = headOf(*e)
		}
	}
	if cp != nil && cp.Seq > prev.Seq {
		return Head{}, &ChainError{Seq: cp.Seq, Reason: fmt.Sprintf("chain ends at seq %d, before checkpoint", prev.Seq)}
	}
	return prev, nil
}

func validTime(t time.Time) bool {
	y := t.UTC().Year()
	return y >= 1970 && y <= 9999
}

// checkLink verifies that e is the valid successor of prev. Failures are reported at position prev.Seq+1.
func checkLink(prev Head, e Entry) error {
	pos := prev.Seq + 1
	bad := func(format string, args ...any) error {
		return &ChainError{Seq: pos, Reason: fmt.Sprintf(format, args...)}
	}
	switch {
	case e.Seq != pos:
		return bad("found seq %d, want %d", e.Seq, pos)
	case e.Format != FormatVersion:
		return bad("unsupported format %d", e.Format)
	case e.PrevHash != prev.Hash:
		return bad("prev hash does not match the previous entry")
	case !e.Time.Equal(e.Time.UTC().Truncate(time.Microsecond)):
		return bad("time is not truncated to microseconds")
	case !validTime(e.Time):
		return bad("time outside years 1970..9999")
	}
	if err := validateRecord(e.Record); err != nil {
		return bad("%v", err)
	}
	if computeHash(e) != e.Hash {
		return bad("hash does not match entry contents")
	}
	return nil
}
