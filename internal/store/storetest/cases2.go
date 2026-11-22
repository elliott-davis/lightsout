// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

package storetest

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/elliott-davis/lightsout/internal/audit"
	"github.com/elliott-davis/lightsout/internal/authz"
	"github.com/elliott-davis/lightsout/internal/store"
	"github.com/elliott-davis/lightsout/internal/store/checkpoint"
)

func (e *Env) enqueueAll(keys ...string) {
	e.T.Helper()
	if err := e.Tx(func(tx store.Txn) error {
		for _, k := range keys {
			if err := tx.Enqueue(e.T.Context(), Work(k)); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		e.T.Fatal(err)
	}
}

func keysOf(ls []store.Lease) []string {
	out := make([]string, len(ls))
	for i, l := range ls {
		out[i] = l.Key
	}
	return out
}

// badPayloads are valid JSON objects that PostgreSQL's jsonb refuses, or that would not round-trip. Every store
// must reject them the same way.
func badPayloads() map[string]json.RawMessage {
	return map[string]json.RawMessage{
		"NUL escape in a value":      json.RawMessage(`{"a":"x\u0000y"}`),
		"NUL escape in a key":        json.RawMessage(`{"\u0000":1}`),
		"lone high surrogate":        json.RawMessage(`{"a":"\ud800"}`),
		"lone low surrogate":         json.RawMessage(`{"a":"\udc00"}`),
		"high surrogate then letter": json.RawMessage(`{"a":"\ud800x"}`),
		"exponent overflows numeric": json.RawMessage(`{"a":1e999999}`),
		"huge number":                json.RawMessage(`{"a":` + string(bytes.Repeat([]byte("9"), 5000)) + `}`),
		"invalid UTF-8":              json.RawMessage("{\"a\":\"\xff\"}"),
		"scale just past numeric":    json.RawMessage(`{"a":1e-16384}`),
		"fraction plus exponent":     json.RawMessage(`{"a":0.5e-16383}`),
		"tiny exponent":              json.RawMessage(`{"a":1e-17000}`),
	}
}

func payloadsRejected(e *Env) { // SEC-1: untrusted payloads that jsonb would refuse are refused identically everywhere
	ctx := e.T.Context()
	for name, p := range badPayloads() {
		r := NewRow("i1")
		r.Payload = p
		err := e.Tx(func(tx store.Txn) error { _, err := tx.Put(ctx, r, 0, ""); return err })
		if !errors.Is(err, store.ErrInvalid) {
			e.T.Errorf("Put with %s: err = %v, want ErrInvalid", name, err)
		}
		w := Work("k")
		w.Payload = p
		err = e.Tx(func(tx store.Txn) error { return tx.Enqueue(ctx, w) })
		if !errors.Is(err, store.ErrInvalid) {
			e.T.Errorf("Enqueue with %s: err = %v, want ErrInvalid", name, err)
		}
		err = e.Tx(func(tx store.Txn) error {
			_, rerr := tx.RecordDelivery(ctx, "github", "d", digestOf(1), w)
			return rerr
		})
		if !errors.Is(err, store.ErrInvalid) {
			e.T.Errorf("RecordDelivery with %s: err = %v, want ErrInvalid", name, err)
		}
	}
	// Nothing was left behind, and the legitimate escapes still work.
	if isNew, err := e.record("github", "d", digestOf(1), store.WorkItem{Key: "k", Kind: "x", Payload: json.RawMessage(`{"a":"😀 é \\u0000 \n","n":1e300,"m":-0.5}`)}); err != nil || !isNew {
		e.T.Fatalf("a payload with valid escapes: new = %v err = %v", isNew, err)
	}
}

func jsonPrecision(e *Env) { // NFR-5: a number larger than a float64 round-trips exactly
	ctx := e.T.Context()
	r := NewRow("i1")
	r.Payload = json.RawMessage(`{"id":12345678901234567891,"price":1.50,"big":1e300}`)
	if err := e.Tx(func(tx store.Txn) error { _, err := tx.Put(ctx, r, 0, ""); return err }); err != nil {
		e.T.Fatal(err)
	}
	got := e.get()
	dec := json.NewDecoder(bytes.NewReader(got.Payload))
	dec.UseNumber()
	var m map[string]any
	if err := dec.Decode(&m); err != nil {
		e.T.Fatal(err)
	}
	if id, _ := m["id"].(json.Number); id.String() != "12345678901234567891" {
		e.T.Errorf("row payload id = %v, want 12345678901234567891 exactly", m["id"])
	}
	w := store.WorkItem{Key: "k", Kind: "x", Payload: json.RawMessage(`{"id":12345678901234567891}`)}
	if _, err := e.record("github", "d", digestOf(1), w); err != nil {
		e.T.Fatal(err)
	}
	ls := e.lease("w", 1)
	if len(ls) != 1 || !bytes.Contains(ls[0].Payload, []byte("12345678901234567891")) {
		e.T.Errorf("work payload = %s, want the id exactly", ls[0].Payload)
	}
}

func completeGenerationZero(e *Env) { // NFR-5: a swallowed error must not finish an item nobody leased
	ctx := e.T.Context()
	e.enqueueAll("k")
	err := e.Tx(func(tx store.Txn) error {
		for _, l := range []store.Lease{{WorkItem: store.WorkItem{Key: "k"}}, {WorkItem: store.WorkItem{Key: "k"}, Generation: -1}} {
			if err := tx.Complete(ctx, l); !errors.Is(err, store.ErrLeaseLost) {
				e.T.Errorf("complete with generation %d: err = %v, want ErrLeaseLost", l.Generation, err)
			}
		}
		return nil // the caller swallowed the errors and commits
	})
	if err != nil {
		e.T.Fatal(err)
	}
	if got := e.lease("w", 5); len(got) != 1 {
		e.T.Fatalf("leased %d items, want the never-leased item still pending", len(got))
	}
}

func deliveryCommitAfterError(e *Env) { // NFR-5: even a caller that commits after an error gets no receipt without work
	ctx := e.T.Context()
	e.enqueueAll("taken")
	if err := e.Tx(func(tx store.Txn) error {
		_, err := tx.RecordDelivery(ctx, "github", "d-2", digestOf(2), Work("taken"))
		if !errors.Is(err, store.ErrDuplicateWork) {
			e.T.Errorf("err = %v, want ErrDuplicateWork", err)
		}
		return nil // swallowed: the transaction commits
	}); err != nil {
		e.T.Fatal(err)
	}
	if isNew, err := e.record("github", "d-2", digestOf(2), Work("k2")); err != nil || !isNew {
		e.T.Fatalf("redelivery: new = %v err = %v, want a fresh receipt", isNew, err)
	}
	// And a digest conflict swallowed by the caller changes nothing either.
	if err := e.Tx(func(tx store.Txn) error {
		if _, err := tx.RecordDelivery(ctx, "github", "d-2", digestOf(9), Work("k3")); !errors.Is(err, store.ErrDeliveryConflict) {
			e.T.Errorf("err = %v, want ErrDeliveryConflict", err)
		}
		return nil
	}); err != nil {
		e.T.Fatal(err)
	}
	if got := len(e.lease("w", 10)); got != 2 { // "taken" and "k2"
		e.T.Fatalf("leased %d items, want 2", got)
	}
}

// tamperBackend wraps a backend and counts and alters the entries its log seals, to show the backend refuses a
// seal that does not extend its head.
type tamperBackend struct {
	inner  audit.Backend
	mutate func(*audit.Entry)
	seals  int
}

func (b *tamperBackend) AppendNext(ctx context.Context, seal audit.SealFunc) (audit.Entry, error) {
	return b.inner.AppendNext(ctx, func(prev audit.Head) (audit.Entry, error) {
		b.seals++
		e, err := seal(prev)
		if err == nil && b.mutate != nil {
			b.mutate(&e)
		}
		return e, err
	})
}

func (b *tamperBackend) Read(ctx context.Context, from uint64, limit int) ([]audit.Entry, error) {
	return b.inner.Read(ctx, from, limit)
}
func (b *tamperBackend) Head(ctx context.Context) (audit.Head, error) { return b.inner.Head(ctx) }

func sealChecks(e *Env) { // NFR-4: the backend calls seal once and refuses an entry that does not extend its head
	ctx := e.T.Context()
	tb := &tamperBackend{inner: e.Store.Denials()}
	l, err := audit.New(tb, e.Clock.Now)
	if err != nil {
		e.T.Fatal(err)
	}
	if _, err := l.Append(ctx, Record("first")); err != nil {
		e.T.Fatal(err)
	}
	if tb.seals != 1 {
		e.T.Fatalf("seal called %d times for one append, want 1", tb.seals)
	}
	for name, mut := range map[string]func(*audit.Entry){
		"gap":          func(x *audit.Entry) { x.Seq += 2 },
		"replayed seq": func(x *audit.Entry) { x.Seq-- },
		"wrong prev":   func(x *audit.Entry) { x.PrevHash[0] ^= 1 },
		"bad hash":     func(x *audit.Entry) { x.Hash[0] ^= 1 },
		"altered record": func(x *audit.Entry) {
			x.Target = "something else" // the hash no longer matches the contents
		},
		"bad format":     func(x *audit.Entry) { x.Format = 9 },
		"ns time":        func(x *audit.Entry) { x.Time = x.Time.Add(time.Nanosecond) },
		"invalid record": func(x *audit.Entry) { x.Actor.ID = "" },
	} {
		tb.mutate, tb.seals = mut, 0
		if _, err := l.Append(ctx, Record("tampered")); !errors.Is(err, audit.ErrBrokenChain) {
			e.T.Errorf("%s: err = %v, want ErrBrokenChain", name, err)
		}
		if tb.seals != 1 {
			e.T.Errorf("%s: seal called %d times, want 1", name, tb.seals)
		}
		if h := e.head(e.Denials()); h.Seq != 1 {
			e.T.Fatalf("%s: head seq = %d after a refused seal, want 1", name, h.Seq)
		}
	}
	tb.mutate = nil
	if _, err := l.Append(ctx, Record("again")); err != nil {
		e.T.Fatalf("append after refusals: %v", err)
	}
	if _, err := e.Denials().Verify(ctx); err != nil {
		e.T.Fatal(err)
	}
}

func revisionBinding(e *Env) { // CON-8, SEC-10: a grant's CAS binds to the exact current revision
	ctx := e.T.Context()
	e.seedRow(Rev(1))
	seen := e.get() // the grant handler resolved Target.Revision = R1 from this
	// Meanwhile the proposal moves to R2.
	if err := e.Tx(func(tx store.Txn) error {
		r := NewRow("i1")
		r.CurrentRevision = Rev(2)
		_, err := tx.Put(ctx, r, seen.Version, Rev(1))
		return err
	}); err != nil {
		e.T.Fatal(err)
	}
	// The grant's own CAS is for the current version but the revision it approved, R1.
	err := e.Tx(func(tx store.Txn) error {
		r := NewRow("i1")
		r.CurrentRevision, r.ApprovedRevision = Rev(1), Rev(1)
		_, err := tx.Put(ctx, r, seen.Version+1, Rev(1))
		return err
	})
	e.wantErr(err, store.ErrConflict, "grant for a revision that moved")
	if got := e.get(); got.CurrentRevision != Rev(2) || got.ApprovedRevision != "" {
		e.T.Fatalf("row = %+v, want it unchanged by the lost grant", got)
	}
	// A row with no current revision cannot be approved against one the caller imagines.
	if err = e.Tx(func(tx store.Txn) error { _, perr := tx.Put(ctx, NewRow("j"), 0, ""); return perr }); err != nil {
		e.T.Fatal(err)
	}
	err = e.Tx(func(tx store.Txn) error { _, perr := tx.Put(ctx, NewRow("j"), 1, Rev(1)); return perr })
	e.wantErr(err, store.ErrConflict, "expected revision against an empty current revision")
}

func transferPut(e *Env) { // NFR-5: a transfer changes the repo, not the ID
	ctx := e.T.Context()
	e.seedRow("")
	if err := e.Tx(func(tx store.Txn) error {
		r := NewRow("i1")
		r.Repo = "repo-2"
		v, err := tx.Put(ctx, r, 1, "")
		if err == nil && v != 2 {
			e.T.Errorf("version = %d, want 2", v)
		}
		return err
	}); err != nil {
		e.T.Fatal(err)
	}
	if got := e.get(); got.ID != "i1" || got.Repo != "repo-2" || got.Version != 2 {
		e.T.Fatalf("row = %+v", got)
	}
}

func leaseOrder(e *Env) { // NFR-5: oldest first, and max is honored
	e.enqueueAll("k0", "k1", "k2", "k3", "k4")
	if diff := cmp.Diff([]string{"k0", "k1"}, keysOf(e.lease("a", 2))); diff != "" {
		e.T.Fatalf("first lease (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff([]string{"k2", "k3"}, keysOf(e.lease("b", 2))); diff != "" {
		e.T.Fatalf("second lease (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff([]string{"k4"}, keysOf(e.lease("c", 2))); diff != "" {
		e.T.Fatalf("third lease (-want +got):\n%s", diff)
	}
}

func leaseTime(e *Env) { // NFR-5: lease times are UTC at microsecond precision, whatever the clock's zone
	e.Clock.Advance(123456789 * time.Nanosecond)
	e.enqueueAll("k")
	ls, err := e.Store.Lease(e.T.Context(), "w", 1, 1500*time.Millisecond)
	if err != nil || len(ls) != 1 {
		e.T.Fatalf("lease: %v %v", ls, err)
	}
	want := e.Clock.Now().Add(1500 * time.Millisecond).UTC().Truncate(time.Microsecond)
	if !ls[0].Expires.Equal(want) || ls[0].Expires.Location() != time.UTC {
		e.T.Errorf("Expires = %v (%v), want %v in UTC", ls[0].Expires, ls[0].Expires.Location(), want)
	}
}

func leaseExpiryFences(e *Env) { // NFR-5: an expired holder cannot complete even if nobody re-leased the item
	ctx := e.T.Context()
	e.enqueueAll("k")
	l := e.lease("a", 1)[0]
	e.Clock.Advance(time.Minute) // exactly at Expires: expired
	err := e.Tx(func(tx store.Txn) error { return tx.Complete(ctx, l) })
	e.wantErr(err, store.ErrLeaseLost, "complete at expiry")
	err = e.Tx(func(tx store.Txn) error { return tx.Reschedule(ctx, l, e.Clock.Now().Add(time.Hour)) })
	e.wantErr(err, store.ErrLeaseLost, "reschedule at expiry")
	err = e.Tx(func(tx store.Txn) error { return tx.DeadLetter(ctx, l, "late") })
	e.wantErr(err, store.ErrLeaseLost, "dead letter at expiry")
	if got := e.lease("b", 1); len(got) != 1 || got[0].Generation != 2 {
		e.T.Fatalf("expired item was not leasable again: %+v", got)
	}
}

func leaseReschedule(e *Env) { // NFR-5: a rescheduled item waits, counts the attempt and fences the old holder
	ctx := e.T.Context()
	e.enqueueAll("k")
	l := e.lease("a", 1)[0]
	if l.Attempts != 0 {
		e.T.Fatalf("attempts = %d, want 0", l.Attempts)
	}
	at := e.Clock.Now().Add(10 * time.Minute)
	if err := e.Tx(func(tx store.Txn) error { return tx.Reschedule(ctx, l, at) }); err != nil {
		e.T.Fatal(err)
	}
	err := e.Tx(func(tx store.Txn) error { return tx.Reschedule(ctx, l, at) })
	e.wantErr(err, store.ErrLeaseLost, "second reschedule by the same holder")
	err = e.Tx(func(tx store.Txn) error { return tx.Complete(ctx, l) })
	e.wantErr(err, store.ErrLeaseLost, "complete after reschedule")
	err = e.Tx(func(tx store.Txn) error {
		return tx.Reschedule(ctx, store.Lease{WorkItem: l.WorkItem, Generation: 7}, at)
	})
	e.wantErr(err, store.ErrLeaseLost, "reschedule with a wrong generation")
	err = e.Tx(func(tx store.Txn) error { return tx.Reschedule(ctx, l, time.Time{}) })
	e.wantErr(err, store.ErrInvalid, "reschedule at the zero time")
	e.Clock.Advance(5 * time.Minute)
	if got := e.lease("b", 1); len(got) != 0 {
		e.T.Fatalf("leased before not_before: %+v", got)
	}
	e.Clock.Advance(5 * time.Minute)
	got := e.lease("b", 1)
	if len(got) != 1 || got[0].Attempts != 1 || got[0].Generation != 2 {
		e.T.Fatalf("lease after not_before = %+v, want attempts 1 and generation 2", got)
	}
	// A rolled back reschedule changes nothing.
	err = e.Tx(func(tx store.Txn) error {
		if rerr := tx.Reschedule(ctx, got[0], e.Clock.Now().Add(time.Hour)); rerr != nil {
			return rerr
		}
		return errBoom
	})
	e.wantErr(err, errBoom, "rolled back reschedule")
	if err := e.Tx(func(tx store.Txn) error { return tx.Complete(ctx, got[0]) }); err != nil {
		e.T.Fatalf("complete after a rolled back reschedule: %v", err)
	}
}

func leaseDeadLetter(e *Env) { // NFR-5: a dead-lettered item is never leased again
	ctx := e.T.Context()
	e.enqueueAll("k")
	l := e.lease("a", 1)[0]
	err := e.Tx(func(tx store.Txn) error {
		return tx.DeadLetter(ctx, store.Lease{WorkItem: l.WorkItem, Generation: 5}, "x")
	})
	e.wantErr(err, store.ErrLeaseLost, "dead letter with a wrong generation")
	err = e.Tx(func(tx store.Txn) error { return tx.DeadLetter(ctx, l, "") })
	e.wantErr(err, store.ErrInvalid, "dead letter without a reason")
	if err = e.Tx(func(tx store.Txn) error { return tx.DeadLetter(ctx, l, "poison") }); err != nil {
		e.T.Fatal(err)
	}
	err = e.Tx(func(tx store.Txn) error { return tx.Complete(ctx, l) })
	e.wantErr(err, store.ErrLeaseLost, "complete after dead letter")
	err = e.Tx(func(tx store.Txn) error { return tx.DeadLetter(ctx, l, "poison") })
	e.wantErr(err, store.ErrLeaseLost, "second dead letter")
	e.Clock.Advance(1000 * time.Hour)
	if got := e.lease("b", 5); len(got) != 0 {
		e.T.Fatalf("a dead item was leased: %+v", got)
	}
}

func chainsNeedCheckpoint(e *Env) { // NFR-4 negative: a deleted checkpoint is not an invitation to start from nothing
	ctx := e.T.Context()
	dir := e.T.TempDir()
	sink, err := checkpoint.NewFile(dir)
	if err != nil {
		e.T.Fatal(err)
	}
	e.appendBoth(2)
	if err := store.VerifyChains(ctx, e.Store, sink, store.VerifyOptions{}); !errors.Is(err, store.ErrNoCheckpoint) {
		e.T.Fatalf("chains with entries and no checkpoint: err = %v, want ErrNoCheckpoint", err)
	}
	if err := store.WriteCheckpoints(ctx, e.Store, sink, store.VerifyOptions{}); !errors.Is(err, store.ErrNoCheckpoint) {
		e.T.Fatalf("WriteCheckpoints without a checkpoint: err = %v, want ErrNoCheckpoint", err)
	}
	if err := store.WriteCheckpoints(ctx, e.Store, sink, store.VerifyOptions{Bootstrap: true}); err != nil {
		e.T.Fatal(err)
	}
	if err := store.VerifyChains(ctx, e.Store, sink, store.VerifyOptions{}); err != nil {
		e.T.Fatal(err)
	}
	for _, chain := range store.Chains() {
		p, err := sink.Path(chain)
		if err != nil {
			e.T.Fatal(err)
		}
		if err := os.Remove(p); err != nil {
			e.T.Fatal(err)
		}
	}
	if err := store.VerifyChains(ctx, e.Store, sink, store.VerifyOptions{}); !errors.Is(err, store.ErrNoCheckpoint) {
		e.T.Fatalf("after deleting the checkpoints: err = %v, want ErrNoCheckpoint", err)
	}
	if err := store.VerifyChains(ctx, e.Store, sink, store.VerifyOptions{Bootstrap: true}); err != nil {
		e.T.Fatalf("explicit bootstrap: %v", err)
	}
}

// switching serves chain a's head, then chain b for everything after: a rewrite that lands between the verifier's
// read of the head and its read of the entries.
type switching struct {
	mu      sync.Mutex
	a, b    audit.Backend
	flipped bool
}

func (s *switching) cur() audit.Backend {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.flipped {
		return s.b
	}
	return s.a
}

func (s *switching) AppendNext(context.Context, audit.SealFunc) (audit.Entry, error) {
	return audit.Entry{}, store.ErrReadOnly
}

func (s *switching) Read(ctx context.Context, from uint64, limit int) ([]audit.Entry, error) {
	return s.cur().Read(ctx, from, limit)
}

func (s *switching) Head(ctx context.Context) (audit.Head, error) {
	h, err := s.cur().Head(ctx)
	s.mu.Lock()
	s.flipped = true
	s.mu.Unlock()
	return h, err
}

type fakeStore struct {
	dec audit.Backend
	den audit.Backend
}

func (f fakeStore) Tx(context.Context, func(context.Context, store.Txn) error) error { return nil }
func (f fakeStore) Denials() audit.Backend                                           { return f.den }

func (f fakeStore) Decisions() audit.Backend { return f.dec }

func (f fakeStore) Lease(context.Context, string, int, time.Duration) ([]store.Lease, error) {
	return nil, nil
}
func (f fakeStore) Close() error { return nil }

func memChain(e *Env, prefix string, n int) *audit.Memory {
	m := audit.NewMemory()
	l, err := audit.New(m, e.Clock.Now)
	if err != nil {
		e.T.Fatal(err)
	}
	for i := range n {
		if _, err := l.Append(e.T.Context(), Record(prefix+strconv.Itoa(i))); err != nil {
			e.T.Fatal(err)
		}
	}
	return m
}

func checkpointRewriteRace(e *Env) { // NFR-4 negative: a chain rewritten between reads cannot capture the checkpoint
	ctx := e.T.Context()
	orig, forged := memChain(e, "orig", 3), memChain(e, "forged", 5)
	sink, err := checkpoint.NewFile(e.T.TempDir())
	if err != nil {
		e.T.Fatal(err)
	}
	oh, _ := orig.Head(ctx)
	if err = sink.Save(ctx, checkpoint.Checkpoint{Chain: store.ChainDecision, Seq: oh.Seq, Hash: oh.Hash}); err != nil {
		e.T.Fatal(err)
	}
	bootstrap := store.VerifyOptions{Bootstrap: true}
	if err = store.VerifyChains(ctx, fakeStore{dec: forged, den: audit.NewMemory()}, sink, bootstrap); err == nil {
		e.T.Fatal("a forged chain verified against the honest checkpoint")
	}
	st := fakeStore{dec: &switching{a: orig, b: forged}, den: audit.NewMemory()}
	if err = store.WriteCheckpoints(ctx, st, sink, bootstrap); !errors.Is(err, audit.ErrBrokenChain) {
		e.T.Errorf("WriteCheckpoints over a chain that changed mid-run: err = %v, want ErrBrokenChain", err)
	}
	cp, ok, err := sink.Load(ctx, store.ChainDecision)
	if err != nil || !ok || cp.Seq != oh.Seq || cp.Hash != oh.Hash {
		e.T.Fatalf("checkpoint = %+v ok=%v err=%v, want it untouched at the honest head", cp, ok, err)
	}
	// A head row that disagrees with the last entry fails too.
	lying := fakeStore{dec: headLiar{orig, audit.Head{Seq: 9, Hash: audit.Hash{9}}}, den: audit.NewMemory()}
	if err = store.VerifyChains(ctx, lying, sink, bootstrap); !errors.Is(err, audit.ErrBrokenChain) {
		e.T.Errorf("head moved forward: err = %v, want ErrBrokenChain", err)
	}
	// An entry planted beyond the head, with the head left where it was, is detected without any checkpoint.
	two, _ := orig.Read(ctx, 2, 1)
	planted := fakeStore{dec: headLiar{orig, audit.Head{Seq: 2, Hash: two[0].Hash}}, den: audit.NewMemory()}
	emptySink, err := checkpoint.NewFile(e.T.TempDir())
	if err != nil {
		e.T.Fatal(err)
	}
	if err := store.VerifyChains(ctx, planted, emptySink, bootstrap); !errors.Is(err, audit.ErrBrokenChain) {
		e.T.Errorf("entry beyond the head: err = %v, want ErrBrokenChain", err)
	}
	rewound := fakeStore{dec: headLiar{orig, audit.Head{Seq: 2, Hash: audit.Hash{2}}}, den: audit.NewMemory()}
	if err := store.VerifyChains(ctx, rewound, sink, bootstrap); !errors.Is(err, audit.ErrBrokenChain) {
		e.T.Errorf("head rewound: err = %v, want ErrBrokenChain", err)
	}
}

// headLiar reports a head that its entries do not support.
type headLiar struct {
	audit.Backend
	head audit.Head
}

func (h headLiar) Head(context.Context) (audit.Head, error) { return h.head, nil }

type allRoles struct{}

func (allRoles) HasRole(context.Context, authz.Principal, authz.Role, authz.Target) (bool, error) {
	return true, nil
}

// Authorizer returns a real authorizer that audits denials to the store's denial chain and gives every principal
// every role.
func (e *Env) Authorizer() *authz.Authorizer {
	e.T.Helper()
	a, err := authz.New(authz.Config{Forge: "github", InstallID: "install-1"}, allRoles{}, e.Denials(), e.Clock.Now)
	if err != nil {
		e.T.Fatal(err)
	}
	return a
}

// GrantInputs returns a decision with the given ID and the target it approves, for [Env.Authorizer].
func GrantInputs(id string, now time.Time) (authz.Decision, authz.Target) {
	scope := authz.Scope{Kind: authz.ScopeRepo, ID: TestRepo}
	subject := audit.Subject{Kind: audit.SubjectIssue, Repo: TestRepo, ID: "7"}
	d := authz.Decision{
		ID: id, Channel: authz.ChannelIssueComment,
		Principal:     authz.Principal{Forge: "github", ID: "42", Login: "octocat", Kind: authz.PrincipalUser},
		Authenticated: true, Location: authz.Location{Scope: scope, Subject: subject},
		Operation: authz.OpApproveScenarios, Revision: Rev(1), Integrity: authz.IntegrityOriginal, Created: now,
	}
	return d, authz.Target{Operation: authz.OpApproveScenarios, Scope: scope, Subject: subject, Revision: Rev(1)}
}

func authorizeIntegration(e *Env) { // SEC-10: the real authz path over the store, including a replay denial
	ctx := e.T.Context()
	e.seedRow(Rev(1))
	a := e.Authorizer()
	d, target := GrantInputs("github/issue_comment/1001", e.Clock.Now())
	grantTx := func(tx store.Txn) error {
		g, aerr := a.Authorize(ctx, tx, d, target)
		if aerr != nil {
			return aerr
		}
		r := NewRow("i1")
		r.CurrentRevision, r.ApprovedRevision = g.Target.Revision, g.Target.Revision
		_, perr := tx.Put(ctx, r, 1, g.Target.Revision)
		return perr
	}
	err := e.Tx(grantTx)
	if err != nil {
		e.T.Fatalf("first execution of the decision: %v", err)
	}
	if got := e.get(); got.Version != 2 || got.ApprovedRevision != Rev(1) {
		e.T.Fatalf("row = %+v, want the approval recorded", got)
	}
	err = e.Tx(grantTx)
	var de *authz.DeniedError
	if !errors.As(err, &de) || de.Reason != authz.ReasonReplayed {
		e.T.Fatalf("second execution: err = %v, want a replayed denial", err)
	}
	if h := e.head(e.DecisionLog()); h.Seq != 1 {
		e.T.Errorf("decision chain seq = %d, want 1 (the replay granted nothing)", h.Seq)
	}
	if h := e.head(e.Denials()); h.Seq != 1 {
		e.T.Errorf("denial chain seq = %d, want 1 (the replay was audited)", h.Seq)
	}
	sink, err := checkpoint.NewFile(e.T.TempDir())
	if err != nil {
		e.T.Fatal(err)
	}
	if err = store.WriteCheckpoints(ctx, e.Store, sink, store.VerifyOptions{Bootstrap: true}); err != nil {
		e.T.Fatal(err)
	}
	if err = store.VerifyChains(ctx, e.Store, sink, store.VerifyOptions{}); err != nil {
		e.T.Fatal(err)
	}
	es, err := e.DecisionLog().Read(ctx, 1, 10)
	if err != nil || len(es) != 1 || es[0].Decision == nil || es[0].Decision.Verdict != audit.VerdictGranted {
		e.T.Fatalf("decision entries = %+v err %v", es, err)
	}
}

func leaseSubMicrosecondTTL(e *Env) { // NFR-5: expiry is a microsecond instant in every store
	ctx := e.T.Context()
	e.enqueueAll("k")
	start := e.Clock.Now()
	ls, err := e.Store.Lease(ctx, "a", 1, time.Second+500*time.Nanosecond)
	if err != nil || len(ls) != 1 {
		e.T.Fatalf("lease: %v %v", ls, err)
	}
	if want := start.Add(time.Second).UTC().Truncate(time.Microsecond); !ls[0].Expires.Equal(want) {
		e.T.Fatalf("Expires = %v, want %v", ls[0].Expires, want)
	}
	e.Clock.Advance(time.Second) // exactly the truncated expiry: the lease is over
	err = e.Tx(func(tx store.Txn) error { return tx.Complete(ctx, ls[0]) })
	e.wantErr(err, store.ErrLeaseLost, "complete at the truncated expiry")
}

func keyValidation(e *Env) { // SEC-1: keys from untrusted input are validated before any lookup, in every store
	ctx := e.T.Context()
	long := string(bytes.Repeat([]byte("a"), store.MaxKeyBytes+1))
	for name, c := range map[string]struct {
		kind store.Kind
		id   string
	}{
		"unknown kind": {"nope", "i1"}, "empty kind": {"", "i1"}, "empty id": {store.KindIssue, ""},
		"oversized id": {store.KindIssue, long}, "control character": {store.KindIssue, controlID}, "NUL": {store.KindIssue, "a\x00b"},
	} {
		err := e.Tx(func(tx store.Txn) error { _, err := tx.Get(ctx, c.kind, c.id); return err })
		if !errors.Is(err, store.ErrInvalid) {
			e.T.Errorf("Get with %s: err = %v, want ErrInvalid", name, err)
		}
	}
	e.enqueueAll("k")
	l := e.lease("a", 1)[0]
	for name, key := range map[string]string{"empty": "", "oversized": long, "control character": controlID, "NUL": "k\x00"} {
		bad := l
		bad.Key = key
		for op, f := range map[string]func(store.Txn) error{
			"Complete":   func(tx store.Txn) error { return tx.Complete(ctx, bad) },
			"Reschedule": func(tx store.Txn) error { return tx.Reschedule(ctx, bad, e.Clock.Now().Add(time.Hour)) },
			"DeadLetter": func(tx store.Txn) error { return tx.DeadLetter(ctx, bad, "x") },
		} {
			if err := e.Tx(f); !errors.Is(err, store.ErrInvalid) {
				e.T.Errorf("%s with a %s lease key: err = %v, want ErrInvalid", op, name, err)
			}
		}
	}
	for name, at := range map[string]time.Time{
		"zero": {}, "year 1969": time.Date(1969, 12, 31, 0, 0, 0, 0, time.UTC), "year 10000": time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC),
	} {
		err := e.Tx(func(tx store.Txn) error { return tx.Reschedule(ctx, l, at) })
		if !errors.Is(err, store.ErrInvalid) {
			e.T.Errorf("Reschedule at %s: err = %v, want ErrInvalid", name, err)
		}
	}
	if err := e.Tx(func(tx store.Txn) error { return tx.Complete(ctx, l) }); err != nil {
		e.T.Fatalf("the lease is still good after the refusals: %v", err)
	}
}

// goodPayloads are valid JSON objects at the edge of what is allowed. Every store must accept them, so the checks
// cannot be stricter than the database.
func goodPayloads() map[string]json.RawMessage {
	return map[string]json.RawMessage{
		"escaped emoji":                json.RawMessage(`{"a":"\ud83d\ude00"}`),
		"smallest scale":               json.RawMessage(`{"a":1e-16383}`),
		"scale from fraction digits":   json.RawMessage(`{"a":9.9e-16382}`),
		"large exponent":               json.RawMessage(`{"a":1e99999}`),
		"4096-digit integer":           json.RawMessage(`{"a":` + string(bytes.Repeat([]byte("9"), 4096)) + `}`),
		"escaped backslash then u0000": json.RawMessage(`{"a":"\\u0000"}`),
	}
}

func payloadsAccepted(e *Env) { // SEC-1: the checks do not over-reject
	ctx := e.T.Context()
	i := 0
	for name, p := range goodPayloads() {
		i++
		r := NewRow("ok" + strconv.Itoa(i))
		r.Payload = p
		if err := e.Tx(func(tx store.Txn) error { _, err := tx.Put(ctx, r, 0, ""); return err }); err != nil {
			e.T.Errorf("Put with %s: %v", name, err)
		}
		w := store.WorkItem{Key: "w" + strconv.Itoa(i), Kind: "x", Payload: p}
		if err := e.Tx(func(tx store.Txn) error { return tx.Enqueue(ctx, w) }); err != nil {
			e.T.Errorf("Enqueue with %s: %v", name, err)
		}
	}
}

// controlID is an ID with a control character, which every store must refuse.
const controlID = "a\nb"
