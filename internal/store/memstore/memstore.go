// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

// Package memstore is the in-memory [store.Store] for tests and ephemeral use.
//
// It matches the PostgreSQL store's observable semantics, as asserted by storetest: compare-and-swap, unique
// consumption, atomic rollback, lease generation fencing and exclusion between leasers. Transactions are
// serialized (one writer at a time) and work on a copy of the committed state, so a rollback discards everything.
// Readers of the committed state do not wait for an open transaction. The one difference from PostgreSQL is that
// [Store.Lease] waits for an open transaction instead of skipping rows that transaction holds.
//
// Two more differences are deliberate. PostgreSQL aborts a transaction after any SQL-level error, so every later
// statement fails; memstore keeps going, so a caller that swallows an error and commits keeps the earlier work in
// both stores only where each operation is atomic on its own (which the suite asserts). And because transactions
// are serialized, a nested [Store.Tx], or a [Store.Lease] inside a transaction, blocks until its context is done
// instead of failing at once; do neither.
package memstore

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"sync"
	"time"

	"github.com/elliott-davis/lightsout/internal/audit"
	"github.com/elliott-davis/lightsout/internal/authz"
	"github.com/elliott-davis/lightsout/internal/store"
)

type rowKey struct {
	kind store.Kind
	id   string
}

type deliveryKey struct{ forge, id string }

type workRec struct {
	item        store.WorkItem
	seq         int
	generation  int64
	owner       string
	leasedUntil time.Time // zero if not leased
	notBefore   time.Time // zero if no backoff
	attempts    int
	completed   bool
	dead        bool
	deadReason  string
}

type state struct {
	rows       map[rowKey]store.Row
	consumed   map[string]struct{}
	deliveries map[deliveryKey]store.Digest
	work       map[string]workRec
	nextSeq    int
	decisions  []audit.Entry
}

func newState() *state {
	return &state{
		rows:       map[rowKey]store.Row{},
		consumed:   map[string]struct{}{},
		deliveries: map[deliveryKey]store.Digest{},
		work:       map[string]workRec{},
	}
}

// clone copies the state. Rows, work payloads and audit entries are never mutated in place, so sharing them
// between a state and its clone is safe; only the containers are copied.
func (s *state) clone() *state {
	return &state{
		rows:       maps.Clone(s.rows),
		consumed:   maps.Clone(s.consumed),
		deliveries: maps.Clone(s.deliveries),
		work:       maps.Clone(s.work),
		nextSeq:    s.nextSeq,
		decisions:  slices.Clone(s.decisions),
	}
}

// Store is an in-memory [store.Store].
type Store struct {
	clock   func() time.Time
	writer  chan struct{} // capacity 1: held by the one open transaction
	mu      sync.RWMutex
	current *state
	denials *audit.Memory
}

var _ store.Store = (*Store)(nil)

// New returns an empty store. The clock is used for lease expiry and audit times.
func New(clock func() time.Time) (*Store, error) {
	if clock == nil {
		return nil, errors.New("memstore: nil clock")
	}
	return &Store{
		clock:   clock,
		writer:  make(chan struct{}, 1),
		current: newState(),
		denials: audit.NewMemory(),
	}, nil
}

// now is the store's time: UTC, at the microsecond precision PostgreSQL keeps.
func (s *Store) now() time.Time { return s.clock().UTC().Truncate(time.Microsecond) }

func (s *Store) acquire(ctx context.Context) error {
	select {
	case s.writer <- struct{}{}:
		if err := ctx.Err(); err != nil {
			<-s.writer
			return err
		}
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *Store) release() { <-s.writer }

func (s *Store) snapshot() *state {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.current.clone()
}

func (s *Store) commit(st *state) {
	s.mu.Lock()
	s.current = st
	s.mu.Unlock()
}

// Tx implements [store.Store].
func (s *Store) Tx(ctx context.Context, fn func(ctx context.Context, tx store.Txn) error) error {
	if err := s.acquire(ctx); err != nil {
		return err
	}
	defer s.release()
	work := s.snapshot()
	tx := &txn{s: s, st: work}
	err := fn(ctx, tx)
	tx.done = true
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	s.commit(work)
	return nil
}

// Denials implements [store.Store]. The denial chain has its own lock and is never rolled back.
func (s *Store) Denials() audit.Backend { return s.denials }

// Decisions implements [store.Store].
func (s *Store) Decisions() audit.Backend { return decisionReader{s} }

// Close implements [store.Store].
func (s *Store) Close() error { return nil }

// Lease implements [store.Store].
func (s *Store) Lease(ctx context.Context, owner string, maxItems int, ttl time.Duration) ([]store.Lease, error) {
	if err := store.ValidateKey("lease owner", owner); err != nil {
		return nil, err
	}
	if maxItems < 1 || ttl <= 0 {
		return nil, fmt.Errorf("%w: lease max %d ttl %s", store.ErrInvalid, maxItems, ttl)
	}
	if err := s.acquire(ctx); err != nil {
		return nil, err
	}
	defer s.release()
	st := s.snapshot()
	now := s.now()
	var ready []workRec
	for k := range st.work {
		w := st.work[k]
		if !w.completed && !w.dead && !now.Before(w.leasedUntil) && !now.Before(w.notBefore) {
			ready = append(ready, w)
		}
	}
	slices.SortFunc(ready, func(a, b workRec) int { return a.seq - b.seq })
	if len(ready) > maxItems {
		ready = ready[:maxItems]
	}
	out := make([]store.Lease, 0, len(ready))
	for i := range ready {
		w := ready[i]
		w.generation++
		w.owner = owner
		w.leasedUntil = now.Add(ttl).Truncate(time.Microsecond)
		st.work[w.item.Key] = w
		item := cloneWork(w.item)
		item.Attempts = w.attempts
		out = append(out, store.Lease{WorkItem: item, Owner: owner, Generation: w.generation, Expires: w.leasedUntil})
	}
	s.commit(st)
	return out, nil
}

func cloneWork(w store.WorkItem) store.WorkItem {
	w.Payload = slices.Clone(w.Payload)
	return w
}

func cloneRow(r store.Row) store.Row {
	r.Payload = slices.Clone(r.Payload)
	return r
}

type txn struct {
	s    *Store
	st   *state
	done bool
	log  *audit.Log
}

func (t *txn) check(ctx context.Context) error {
	if t.done {
		return store.ErrTxDone
	}
	return ctx.Err()
}

func (t *txn) Consume(ctx context.Context, decisionID string) error {
	if err := t.check(ctx); err != nil {
		return err
	}
	if err := store.ValidateKey("decision id", decisionID); err != nil {
		return err
	}
	if _, ok := t.st.consumed[decisionID]; ok {
		return authz.ErrReplayed
	}
	t.st.consumed[decisionID] = struct{}{}
	return nil
}

func (t *txn) Append(ctx context.Context, r audit.Record) (audit.Entry, error) {
	if err := t.check(ctx); err != nil {
		return audit.Entry{}, err
	}
	if t.log == nil {
		l, err := audit.New(txChain{t}, t.s.now)
		if err != nil {
			return audit.Entry{}, err
		}
		t.log = l
	}
	return t.log.Append(ctx, r)
}

func (t *txn) RecordDelivery(ctx context.Context, forge, deliveryID string, digest store.Digest, work store.WorkItem) (bool, error) {
	if err := t.check(ctx); err != nil {
		return false, err
	}
	if err := store.ValidateKey("delivery forge", forge); err != nil {
		return false, err
	}
	if err := store.ValidateKey("delivery id", deliveryID); err != nil {
		return false, err
	}
	if err := work.Validate(); err != nil {
		return false, err
	}
	k := deliveryKey{forge, deliveryID}
	if have, ok := t.st.deliveries[k]; ok {
		if have != digest {
			return false, store.ErrDeliveryConflict
		}
		return false, nil
	}
	if err := t.enqueue(work); err != nil {
		return false, err
	}
	t.st.deliveries[k] = digest
	return true, nil
}

func (t *txn) Get(ctx context.Context, kind store.Kind, id string) (store.Row, error) {
	if err := t.check(ctx); err != nil {
		return store.Row{}, err
	}
	if err := store.ValidateRowKey(kind, id); err != nil {
		return store.Row{}, err
	}
	r, ok := t.st.rows[rowKey{kind, id}]
	if !ok {
		return store.Row{}, store.ErrNotFound
	}
	return cloneRow(r), nil
}

func (t *txn) Put(ctx context.Context, row store.Row, expect store.Version, expectRevision string) (store.Version, error) {
	if err := t.check(ctx); err != nil {
		return 0, err
	}
	if err := row.Validate(); err != nil {
		return 0, err
	}
	if expectRevision != "" && !isDigest(expectRevision) {
		return 0, fmt.Errorf("%w: expected revision is not a digest", store.ErrInvalid)
	}
	if expect < 0 {
		return 0, fmt.Errorf("%w: expected version %d", store.ErrInvalid, expect)
	}
	if expect == 0 && expectRevision != "" {
		return 0, fmt.Errorf("%w: an expected revision with a create", store.ErrInvalid)
	}
	k := rowKey{row.Kind, row.ID}
	have, ok := t.st.rows[k]
	if expect == 0 {
		if ok {
			return 0, store.ErrConflict
		}
		row.Version = 1
	} else {
		if !ok || have.Version != expect || have.CurrentRevision != expectRevision {
			return 0, store.ErrConflict
		}
		row.Version = have.Version + 1
	}
	row.Payload = canonical(row.Payload)
	t.st.rows[k] = cloneRow(row)
	return row.Version, nil
}

// canonical re-encodes JSON compactly so memstore returns what PostgreSQL's jsonb would (same value, normalized
// whitespace), which is all callers may rely on.
func canonical(raw json.RawMessage) json.RawMessage {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber() // keep numbers exactly as written, as jsonb's numeric does
	var v any
	if err := dec.Decode(&v); err != nil {
		return slices.Clone(raw)
	}
	b, err := json.Marshal(v)
	if err != nil {
		return slices.Clone(raw)
	}
	return b
}

func isDigest(s string) bool {
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

func (t *txn) Enqueue(ctx context.Context, w store.WorkItem) error {
	if err := t.check(ctx); err != nil {
		return err
	}
	if err := w.Validate(); err != nil {
		return err
	}
	return t.enqueue(w)
}

func (t *txn) enqueue(w store.WorkItem) error {
	if _, ok := t.st.work[w.Key]; ok {
		return store.ErrDuplicateWork
	}
	w = cloneWork(w)
	w.Payload = canonicalOrEmpty(w.Payload)
	t.st.nextSeq++
	t.st.work[w.Key] = workRec{item: w, seq: t.st.nextSeq}
	return nil
}

func canonicalOrEmpty(raw json.RawMessage) json.RawMessage {
	if len(raw) == 0 {
		return json.RawMessage(`{}`)
	}
	return canonical(raw)
}

func (t *txn) Complete(ctx context.Context, l store.Lease) error {
	w, err := t.fenced(ctx, l)
	if err != nil {
		return err
	}
	w.completed = true
	w.leasedUntil = time.Time{}
	t.st.work[l.Key] = w
	return nil
}

func (t *txn) Reschedule(ctx context.Context, l store.Lease, notBefore time.Time) error {
	if err := store.ValidateTime("reschedule time", notBefore); err != nil {
		return err
	}
	w, err := t.fenced(ctx, l)
	if err != nil {
		return err
	}
	w.attempts++
	w.notBefore = notBefore.UTC().Truncate(time.Microsecond)
	w.leasedUntil = time.Time{}
	w.owner = ""
	t.st.work[l.Key] = w
	return nil
}

func (t *txn) DeadLetter(ctx context.Context, l store.Lease, reason string) error {
	if err := store.ValidateKey("dead letter reason", reason); err != nil {
		return err
	}
	w, err := t.fenced(ctx, l)
	if err != nil {
		return err
	}
	w.dead = true
	w.deadReason = reason
	w.leasedUntil = time.Time{}
	t.st.work[l.Key] = w
	return nil
}

// fenced returns the item if l is its current, unexpired lease.
func (t *txn) fenced(ctx context.Context, l store.Lease) (workRec, error) {
	if err := t.check(ctx); err != nil {
		return workRec{}, err
	}
	if err := store.ValidateKey("lease key", l.Key); err != nil {
		return workRec{}, err
	}
	w, ok := t.st.work[l.Key]
	if !ok || w.completed || w.dead || l.Generation < 1 || w.generation != l.Generation || !t.s.now().Before(w.leasedUntil) {
		return workRec{}, store.ErrLeaseLost
	}
	return w, nil
}

// txChain is the decision chain as seen inside one transaction.
type txChain struct{ t *txn }

func (c txChain) head() audit.Head {
	es := c.t.st.decisions
	if len(es) == 0 {
		return audit.Head{}
	}
	return audit.Head{Seq: es[len(es)-1].Seq, Hash: es[len(es)-1].Hash}
}

func (c txChain) AppendNext(ctx context.Context, seal audit.SealFunc) (audit.Entry, error) {
	if err := ctx.Err(); err != nil {
		return audit.Entry{}, err
	}
	prev := c.head()
	e, err := seal(prev)
	if err != nil {
		return audit.Entry{}, err
	}
	if err := audit.CheckSuccessor(prev, e); err != nil {
		return audit.Entry{}, fmt.Errorf("sealed entry rejected: %w", err)
	}
	e = cloneEntry(e)
	c.t.st.decisions = append(c.t.st.decisions, e)
	return cloneEntry(e), nil
}

func (c txChain) Read(ctx context.Context, from uint64, limit int) ([]audit.Entry, error) {
	return readEntries(ctx, c.t.st.decisions, from, limit)
}

func (c txChain) Head(ctx context.Context) (audit.Head, error) { return c.head(), ctx.Err() }

// decisionReader is the read-only committed view of the decision chain.
type decisionReader struct{ s *Store }

func (r decisionReader) AppendNext(context.Context, audit.SealFunc) (audit.Entry, error) {
	return audit.Entry{}, store.ErrReadOnly
}

func (r decisionReader) Read(ctx context.Context, from uint64, limit int) ([]audit.Entry, error) {
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()
	return readEntries(ctx, r.s.current.decisions, from, limit)
}

func (r decisionReader) Head(ctx context.Context) (audit.Head, error) {
	if err := ctx.Err(); err != nil {
		return audit.Head{}, err
	}
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()
	es := r.s.current.decisions
	if len(es) == 0 {
		return audit.Head{}, nil
	}
	return audit.Head{Seq: es[len(es)-1].Seq, Hash: es[len(es)-1].Hash}, nil
}

func readEntries(ctx context.Context, es []audit.Entry, from uint64, limit int) ([]audit.Entry, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if from == 0 {
		from = 1
	}
	if from > uint64(len(es)) || limit < 1 {
		return []audit.Entry{}, nil
	}
	end := min(uint64(len(es)), from-1+uint64(limit))
	out := make([]audit.Entry, 0, end-from+1)
	for i := from - 1; i < end; i++ {
		out = append(out, cloneEntry(es[i]))
	}
	return out, nil
}

func cloneEntry(e audit.Entry) audit.Entry {
	if e.Decision != nil {
		d := *e.Decision
		e.Decision = &d
	}
	if e.Link != nil {
		l := *e.Link
		e.Link = &l
	}
	if len(e.Attrs) == 0 {
		e.Attrs = nil
	} else {
		e.Attrs = maps.Clone(e.Attrs)
	}
	return e
}
