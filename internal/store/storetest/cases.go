// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

package storetest

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"sync"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/elliott-davis/lightsout/internal/audit"
	"github.com/elliott-davis/lightsout/internal/authz"
	"github.com/elliott-davis/lightsout/internal/store"
	"github.com/elliott-davis/lightsout/internal/store/checkpoint"
)

var errBoom = errors.New("boom")

func (e *Env) seedRow(rev string) {
	e.T.Helper()
	r := NewRow("i1")
	r.CurrentRevision = rev
	if err := e.Tx(func(tx store.Txn) error {
		_, err := tx.Put(e.T.Context(), r, 0, "")
		return err
	}); err != nil {
		e.T.Fatalf("seed row: %v", err)
	}
}

func (e *Env) get() store.Row {
	e.T.Helper()
	var r store.Row
	if err := e.Tx(func(tx store.Txn) error {
		var err error
		r, err = tx.Get(e.T.Context(), store.KindIssue, "i1")
		return err
	}); err != nil {
		e.T.Fatalf("get row: %v", err)
	}
	return r
}

func (e *Env) head(l *audit.Log) audit.Head {
	e.T.Helper()
	h, err := l.Head(e.T.Context())
	if err != nil {
		e.T.Fatal(err)
	}
	return h
}

func (e *Env) lease(owner string, n int) []store.Lease {
	e.T.Helper()
	ls, err := e.Store.Lease(e.T.Context(), owner, n, time.Minute)
	if err != nil {
		e.T.Fatalf("lease: %v", err)
	}
	return ls
}

func (e *Env) wantErr(err, want error, what string) {
	e.T.Helper()
	if !errors.Is(err, want) {
		e.T.Fatalf("%s: err = %v, want %v", what, err, want)
	}
}

func casVersion(e *Env) { // NFR-5: a state update is conditional on the observed version
	ctx := e.T.Context()
	e.seedRow("")
	if err := e.Tx(func(tx store.Txn) error {
		r := NewRow("i1")
		r.Payload = json.RawMessage(`{"state":"one"}`)
		v, err := tx.Put(ctx, r, 1, "")
		if err == nil && v != 2 {
			e.T.Errorf("new version = %d, want 2", v)
		}
		return err
	}); err != nil {
		e.T.Fatal(err)
	}
	err := e.Tx(func(tx store.Txn) error {
		r := NewRow("i1")
		r.Payload = json.RawMessage(`{"state":"stale"}`)
		_, err := tx.Put(ctx, r, 1, "") // stale: the row is at version 2
		return err
	})
	e.wantErr(err, store.ErrConflict, "stale version")
	got := e.get()
	if got.Version != 2 {
		e.T.Errorf("row after conflict = %+v", got)
	}
	if diff := cmp.Diff(json.RawMessage(`{"state":"one"}`), got.Payload, normalizeJSON()); diff != "" {
		e.T.Errorf("payload after conflict (-want +got):\n%s", diff)
	}
	err = e.Tx(func(tx store.Txn) error {
		_, err = tx.Put(ctx, NewRow("missing"), 3, "")
		return err
	})
	e.wantErr(err, store.ErrConflict, "update of a missing row")
}

func casRevision(e *Env) { // SEC-10: the update is conditional on the current revision too
	ctx := e.T.Context()
	e.seedRow(Rev(1))
	for name, rev := range map[string]string{"other revision": Rev(2), "no revision": ""} {
		err := e.Tx(func(tx store.Txn) error {
			r := NewRow("i1")
			r.CurrentRevision = Rev(9)
			_, err := tx.Put(ctx, r, 1, rev)
			return err
		})
		e.wantErr(err, store.ErrConflict, name)
	}
	if got := e.get(); got.CurrentRevision != Rev(1) || got.Version != 1 {
		e.T.Fatalf("row changed by a lost CAS: %+v", got)
	}
	if err := e.Tx(func(tx store.Txn) error {
		r := NewRow("i1")
		r.CurrentRevision = Rev(3)
		_, err := tx.Put(ctx, r, 1, Rev(1))
		return err
	}); err != nil {
		e.T.Fatalf("matching CAS: %v", err)
	}
	if got := e.get(); got.CurrentRevision != Rev(3) || got.Version != 2 {
		e.T.Fatalf("row = %+v", got)
	}
}

func casCreate(e *Env) { // NFR-5
	e.seedRow("")
	err := e.Tx(func(tx store.Txn) error {
		_, err := tx.Put(e.T.Context(), NewRow("i1"), 0, "")
		return err
	})
	e.wantErr(err, store.ErrConflict, "create of an existing row")
	err = e.Tx(func(tx store.Txn) error {
		_, err = tx.Get(e.T.Context(), store.KindIssue, "nope")
		return err
	})
	e.wantErr(err, store.ErrNotFound, "get of a missing row")
}

func rollbackAppend(e *Env) { // SEC-10: Consume, the state change and the grant's append commit together
	ctx := e.T.Context()
	e.seedRow(Rev(1))
	err := e.Tx(func(tx store.Txn) error {
		if err := tx.Consume(ctx, "decision-1"); err != nil {
			return err
		}
		if _, err := tx.Append(ctx, Record("grant")); err != nil {
			return err
		}
		r := NewRow("i1")
		r.CurrentRevision = Rev(2)
		if _, err := tx.Put(ctx, r, 1, Rev(1)); err != nil {
			return err
		}
		_, err := tx.Append(ctx, BadRecord()) // the audit append fails: everything above must roll back
		return err
	})
	e.wantErr(err, audit.ErrInvalidRecord, "append of an invalid record")
	if got := e.get(); got.Version != 1 || got.CurrentRevision != Rev(1) {
		e.T.Fatalf("state change survived the failed append: %+v", got)
	}
	if h := e.head(e.DecisionLog()); h.Seq != 0 {
		e.T.Fatalf("decision chain head seq = %d after rollback, want 0", h.Seq)
	}
	// The decision stayed unconsumed, so the retry of the same decision ID succeeds.
	if err := e.Tx(func(tx store.Txn) error {
		if err := tx.Consume(ctx, "decision-1"); err != nil {
			return err
		}
		if _, err := tx.Append(ctx, Record("grant")); err != nil {
			return err
		}
		r := NewRow("i1")
		r.CurrentRevision = Rev(2)
		_, err := tx.Put(ctx, r, 1, Rev(1))
		return err
	}); err != nil {
		e.T.Fatalf("retry of the same decision ID: %v", err)
	}
	if h := e.head(e.DecisionLog()); h.Seq != 1 {
		e.T.Fatalf("decision chain head seq = %d, want 1", h.Seq)
	}
	if _, err := e.DecisionLog().Verify(ctx); err != nil {
		e.T.Fatal(err)
	}
}

func replayOneWinner(e *Env) { // SEC-10: exactly one of several racing transactions consumes the ID
	const n = 8
	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := range n {
		wg.Go(func() {
			errs[i] = e.Store.Tx(e.T.Context(), func(ctx context.Context, tx store.Txn) error {
				return tx.Consume(ctx, "decision-race")
			})
		})
	}
	wg.Wait()
	wins, replays := 0, 0
	for _, err := range errs {
		switch {
		case err == nil:
			wins++
		case errors.Is(err, authz.ErrReplayed):
			replays++
		default:
			e.T.Errorf("unexpected error: %v", err)
		}
	}
	if wins != 1 || replays != n-1 {
		e.T.Fatalf("wins = %d, replays = %d, want 1 and %d", wins, replays, n-1)
	}
}

func replayForever(e *Env) { // SEC-10: the consumed set is never purged
	ctx := e.T.Context()
	if err := e.Tx(func(tx store.Txn) error { return tx.Consume(ctx, "d") }); err != nil {
		e.T.Fatal(err)
	}
	e.Clock.Advance(100000 * time.Hour)
	err := e.Tx(func(tx store.Txn) error { return tx.Consume(ctx, "d") })
	e.wantErr(err, authz.ErrReplayed, "second consume")
}

func denialsSurviveRollback(e *Env) { // NFR-4, SEC-10: a denial commits even if the state transaction rolls back
	ctx := e.T.Context()
	den := e.Denials()
	err := e.Tx(func(tx store.Txn) error {
		if _, err := tx.Append(ctx, Record("grant")); err != nil {
			return err
		}
		if _, err := den.Append(ctx, Record("deny")); err != nil {
			return err
		}
		return errBoom
	})
	e.wantErr(err, errBoom, "rolled back transaction")
	if h := e.head(e.DecisionLog()); h.Seq != 0 {
		e.T.Errorf("decision head seq = %d, want 0 (rolled back)", h.Seq)
	}
	if h := e.head(den); h.Seq != 1 {
		e.T.Errorf("denial head seq = %d, want 1 (committed)", h.Seq)
	}
	if _, err := den.Verify(ctx); err != nil {
		e.T.Error(err)
	}
}

func denialsWhileHeadHeld(e *Env) { // NFR-4: the two chains never block each other (authz notes for WI-10)
	ctx := e.T.Context()
	den := e.Denials()
	if err := e.Tx(func(tx store.Txn) error {
		if _, err := tx.Append(ctx, Record("grant-owner-1")); err != nil { // holds the decision head
			return err
		}
		var wg sync.WaitGroup
		var derr error
		wg.Go(func() { _, derr = den.Append(ctx, Record("deny-owner-2")) })
		wg.Wait()
		return derr
	}); err != nil {
		e.T.Fatal(err)
	}
	if e.head(den).Seq != 1 || e.head(e.DecisionLog()).Seq != 1 {
		e.T.Fatal("expected one entry on each chain")
	}
}

func decisionsReadOnly(e *Env) { // NFR-4: the decision chain is written only inside a transaction
	_, err := e.Store.Decisions().AppendNext(e.T.Context(), func(audit.Head) (audit.Entry, error) {
		e.T.Error("seal called on a read-only backend")
		return audit.Entry{}, nil
	})
	e.wantErr(err, store.ErrReadOnly, "append through the read-only view")
}

func digestOf(b byte) store.Digest {
	var d store.Digest
	for i := range d {
		d[i] = b
	}
	return d
}

func (e *Env) record(forge, id string, d store.Digest, w store.WorkItem) (bool, error) {
	var isNew bool
	err := e.Tx(func(tx store.Txn) error {
		var err error
		isNew, err = tx.RecordDelivery(e.T.Context(), forge, id, d, w)
		return err
	})
	return isNew, err
}

func deliveriesIdempotent(e *Env) { // NFR-5: a repeat delivery is an idempotent success with one work item
	for i, want := range []bool{true, false, false} {
		got, err := e.record("github", "d-1", digestOf(1), Work("github/d-1/"+strconv.Itoa(i)))
		if err != nil || got != want {
			e.T.Fatalf("delivery %d: new = %v err = %v, want new = %v", i, got, err, want)
		}
	}
	keys := map[string]bool{}
	for range 3 {
		for _, l := range e.lease("w", 10) {
			keys[l.Key] = true
		}
		e.Clock.Advance(time.Hour)
	}
	if diff := cmp.Diff(map[string]bool{"github/d-1/0": true}, keys); diff != "" {
		e.T.Fatalf("work items (-want +got):\n%s", diff)
	}
}

func deliveriesConflict(e *Env) { // SEC-1: a reused delivery ID with another body is rejected
	if _, err := e.record("github", "d-1", digestOf(1), Work("k1")); err != nil {
		e.T.Fatal(err)
	}
	_, err := e.record("github", "d-1", digestOf(2), Work("k2"))
	e.wantErr(err, store.ErrDeliveryConflict, "same ID, different digest")
	if isNew, err := e.record("other-forge", "d-1", digestOf(2), Work("k3")); err != nil || !isNew {
		e.T.Fatalf("same ID on another forge: new = %v err = %v", isNew, err)
	}
	if n := len(e.lease("w", 10)); n != 2 {
		e.T.Fatalf("leased %d items, want 2 (the rejected delivery enqueued nothing)", n)
	}
}

func deliveriesAtomic(e *Env) { // NFR-5: receipt and enqueue commit together
	ctx := e.T.Context()
	// A failure after the receipt leaves neither the receipt nor the work item.
	err := e.Tx(func(tx store.Txn) error {
		if isNew, err := tx.RecordDelivery(ctx, "github", "d-1", digestOf(1), Work("k1")); err != nil || !isNew {
			e.T.Errorf("record: new = %v err = %v", isNew, err)
		}
		return errBoom
	})
	e.wantErr(err, errBoom, "rolled back receipt")
	if n := len(e.lease("w", 10)); n != 0 {
		e.T.Fatalf("leased %d items from a rolled back receipt", n)
	}
	if isNew, err2 := e.record("github", "d-1", digestOf(1), Work("k1")); err2 != nil || !isNew {
		e.T.Fatalf("redelivery after rollback: new = %v err = %v, want it treated as new", isNew, err2)
	}
	// A failing enqueue (duplicate key) after the receipt insert leaves no receipt.
	if err = e.Tx(func(tx store.Txn) error { return tx.Enqueue(ctx, Work("taken")) }); err != nil {
		e.T.Fatal(err)
	}
	_, err = e.record("github", "d-2", digestOf(2), Work("taken"))
	e.wantErr(err, store.ErrDuplicateWork, "duplicate work key")
	if isNew, err := e.record("github", "d-2", digestOf(2), Work("k2")); err != nil || !isNew {
		e.T.Fatalf("delivery whose enqueue failed: new = %v err = %v, want no receipt left", isNew, err)
	}
}

func leasesExclusive(e *Env) { // NFR-5: two leasers never get the same item
	ctx := e.T.Context()
	const items = 20
	if err := e.Tx(func(tx store.Txn) error {
		for i := range items {
			if err := tx.Enqueue(ctx, Work("k"+strconv.Itoa(i))); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		e.T.Fatal(err)
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	seen := map[string]int{}
	for _, owner := range []string{"a", "b", "c", "d"} {
		wg.Go(func() {
			for {
				ls, err := e.Store.Lease(ctx, owner, 3, time.Hour)
				if err != nil {
					e.T.Errorf("lease: %v", err)
					return
				}
				if len(ls) == 0 {
					return
				}
				mu.Lock()
				for _, l := range ls {
					seen[l.Key]++
				}
				mu.Unlock()
			}
		})
	}
	wg.Wait()
	if len(seen) != items {
		e.T.Errorf("leased %d distinct items, want %d", len(seen), items)
	}
	for k, n := range seen {
		if n != 1 {
			e.T.Errorf("item %s leased %d times", k, n)
		}
	}
}

func leasesExpire(e *Env) { // NFR-5: an expired lease is re-leased with a bumped generation
	if _, err := e.record("github", "d", digestOf(1), Work("k")); err != nil {
		e.T.Fatal(err)
	}
	first := e.lease("a", 5)
	if len(first) != 1 || first[0].Generation != 1 || first[0].Owner != "a" {
		e.T.Fatalf("first lease = %+v", first)
	}
	if got := e.lease("b", 5); len(got) != 0 {
		e.T.Fatalf("leased a held item: %+v", got)
	}
	e.Clock.Advance(2 * time.Minute)
	second := e.lease("b", 5)
	if len(second) != 1 || second[0].Generation != 2 || second[0].Owner != "b" || second[0].Key != "k" {
		e.T.Fatalf("second lease = %+v", second)
	}
	if !second[0].Expires.After(e.Clock.Now()) {
		e.T.Errorf("lease expires %v, not after now %v", second[0].Expires, e.Clock.Now())
	}
	if diff := cmp.Diff(json.RawMessage(`{"n":1}`), second[0].Payload, normalizeJSON()); diff != "" {
		e.T.Errorf("payload (-want +got):\n%s", diff)
	}
}

func leasesFenced(e *Env) { // NFR-5: Complete by a holder whose lease was taken over fails
	ctx := e.T.Context()
	if _, err := e.record("github", "d", digestOf(1), Work("k")); err != nil {
		e.T.Fatal(err)
	}
	old := e.lease("a", 1)[0]
	e.Clock.Advance(2 * time.Minute)
	cur := e.lease("b", 1)[0]
	err := e.Tx(func(tx store.Txn) error { return tx.Complete(ctx, old) })
	e.wantErr(err, store.ErrLeaseLost, "complete by the old holder")
	forged := cur
	forged.Generation = 99
	err = e.Tx(func(tx store.Txn) error { return tx.Complete(ctx, forged) })
	e.wantErr(err, store.ErrLeaseLost, "complete with a future generation")
	if err = e.Tx(func(tx store.Txn) error { return tx.Complete(ctx, cur) }); err != nil {
		e.T.Fatalf("complete by the current holder: %v", err)
	}
	err = e.Tx(func(tx store.Txn) error { return tx.Complete(ctx, cur) })
	e.wantErr(err, store.ErrLeaseLost, "second complete")
	e.Clock.Advance(time.Hour)
	if got := e.lease("c", 5); len(got) != 0 {
		e.T.Fatalf("a completed item was leased again: %+v", got)
	}
}

func leasesCompleteRollback(e *Env) { // NFR-5: Complete is part of the transaction
	ctx := e.T.Context()
	if _, err := e.record("github", "d", digestOf(1), Work("k")); err != nil {
		e.T.Fatal(err)
	}
	l := e.lease("a", 1)[0]
	err := e.Tx(func(tx store.Txn) error {
		if err := tx.Complete(ctx, l); err != nil {
			return err
		}
		return errBoom
	})
	e.wantErr(err, errBoom, "rolled back complete")
	if err := e.Tx(func(tx store.Txn) error { return tx.Complete(ctx, l) }); err != nil {
		e.T.Fatalf("complete after a rolled back complete: %v", err)
	}
}

func (e *Env) appendBoth(n int) {
	e.T.Helper()
	ctx := e.T.Context()
	den := e.Denials()
	for i := range n {
		if err := e.Tx(func(tx store.Txn) error {
			_, err := tx.Append(ctx, Record("grant"+strconv.Itoa(i)))
			return err
		}); err != nil {
			e.T.Fatal(err)
		}
		if _, err := den.Append(ctx, Record("deny"+strconv.Itoa(i))); err != nil {
			e.T.Fatal(err)
		}
	}
}

func chainsVerify(e *Env) { // NFR-4: both chains verify, and checkpoints advance with them
	ctx := e.T.Context()
	sink, err := checkpoint.NewFile(e.T.TempDir())
	if err != nil {
		e.T.Fatal(err)
	}
	if err := store.VerifyChains(ctx, e.Store, sink, store.VerifyOptions{}); err != nil {
		e.T.Fatalf("empty chains: %v", err)
	}
	e.appendBoth(3)
	if err := store.WriteCheckpoints(ctx, e.Store, sink, store.VerifyOptions{Bootstrap: true}); err != nil {
		e.T.Fatal(err)
	}
	e.appendBoth(2)
	if err := store.VerifyChains(ctx, e.Store, sink, store.VerifyOptions{}); err != nil {
		e.T.Fatalf("chains grew past the checkpoint: %v", err)
	}
	for chain, l := range map[string]*audit.Log{store.ChainDecision: e.DecisionLog(), store.ChainDenial: e.Denials()} {
		h, err := l.Verify(ctx)
		if err != nil || h.Seq != 5 {
			e.T.Fatalf("chain %s: head %+v err %v, want seq 5", chain, h, err)
		}
		es, err := l.Read(ctx, 1, 10)
		if err != nil || len(es) != 5 {
			e.T.Fatalf("chain %s: read %d entries err %v", chain, len(es), err)
		}
		cp, ok, err := sink.Load(ctx, chain)
		if err != nil || !ok || cp.Seq != 3 || cp.Hash != es[2].Hash {
			e.T.Fatalf("chain %s checkpoint = %+v ok=%v err=%v, want seq 3", chain, cp, ok, err)
		}
	}
}

func chainsTruncated(e *Env) { // NFR-4 negative: a chain shorter than, or different from, its checkpoint fails
	ctx := e.T.Context()
	e.appendBoth(3)
	h, err := e.DecisionLog().Verify(ctx)
	if err != nil {
		e.T.Fatal(err)
	}
	for name, cp := range map[string]checkpoint.Checkpoint{
		"truncated: checkpoint beyond the head": {Chain: store.ChainDecision, Seq: h.Seq + 2, Hash: audit.Hash{7}},
		"rewritten: wrong hash at seq 2":        {Chain: store.ChainDecision, Seq: 2, Hash: audit.Hash{7}},
		"truncated denial chain":                {Chain: store.ChainDenial, Seq: 9, Hash: audit.Hash{7}},
	} {
		sink, err := checkpoint.NewFile(e.T.TempDir())
		if err != nil {
			e.T.Fatal(err)
		}
		if err = sink.Save(ctx, cp); err != nil {
			e.T.Fatal(err)
		}
		err = store.VerifyChains(ctx, e.Store, sink, store.VerifyOptions{Bootstrap: true})
		if !errors.Is(err, audit.ErrBrokenChain) {
			e.T.Errorf("%s: VerifyChains err = %v, want ErrBrokenChain", name, err)
		}
		if err := store.WriteCheckpoints(ctx, e.Store, sink, store.VerifyOptions{Bootstrap: true}); !errors.Is(err, audit.ErrBrokenChain) {
			e.T.Errorf("%s: WriteCheckpoints err = %v, want ErrBrokenChain", name, err)
		}
	}
}

func inputsValidated(e *Env) { // SEC-1: untrusted-derived values are bounded and checked
	ctx := e.T.Context()
	bad := map[string]func(*store.Row){
		"kind":           func(r *store.Row) { r.Kind = "other" },
		"empty id":       func(r *store.Row) { r.ID = "" },
		"empty repo":     func(r *store.Row) { r.Repo = "" },
		"revision":       func(r *store.Row) { r.ApprovedRevision = "HEAD" },
		"schema version": func(r *store.Row) { r.SchemaVersion = 0 },
		"array payload":  func(r *store.Row) { r.Payload = json.RawMessage(`[1]`) },
		"no payload":     func(r *store.Row) { r.Payload = nil },
		"control char":   func(r *store.Row) { r.ID = controlID },
	}
	for name, mut := range bad {
		r := NewRow("i1")
		mut(&r)
		err := e.Tx(func(tx store.Txn) error { _, err := tx.Put(ctx, r, 0, ""); return err })
		if !errors.Is(err, store.ErrInvalid) {
			e.T.Errorf("row with bad %s: err = %v, want ErrInvalid", name, err)
		}
	}
	err := e.Tx(func(tx store.Txn) error { _, err := tx.Put(ctx, NewRow("i1"), 1, "nothex"); return err })
	e.wantErr(err, store.ErrInvalid, "expected revision")
	err = e.Tx(func(tx store.Txn) error { _, perr := tx.Put(ctx, NewRow("i1"), 0, Rev(1)); return perr })
	e.wantErr(err, store.ErrInvalid, "create with an expected revision")
	for name, w := range map[string]store.WorkItem{
		"empty key":     {Key: "", Kind: "k"},
		"empty kind":    {Key: "k"},
		"array payload": {Key: "k", Kind: "k", Payload: json.RawMessage(`[]`)},
	} {
		err := e.Tx(func(tx store.Txn) error { return tx.Enqueue(ctx, w) })
		if !errors.Is(err, store.ErrInvalid) {
			e.T.Errorf("work with %s: err = %v, want ErrInvalid", name, err)
		}
	}
	if err := e.Tx(func(tx store.Txn) error { return tx.Consume(ctx, "") }); !errors.Is(err, store.ErrInvalid) {
		e.T.Errorf("empty decision ID: err = %v, want ErrInvalid", err)
	}
	if _, err := e.Store.Lease(ctx, "w", 0, time.Minute); !errors.Is(err, store.ErrInvalid) {
		e.T.Errorf("lease max 0: err = %v", err)
	}
	if _, err := e.Store.Lease(ctx, "w", 1, 0); !errors.Is(err, store.ErrInvalid) {
		e.T.Errorf("lease ttl 0: err = %v", err)
	}
}

func txUseAfterReturn(e *Env) { // NFR-5: a Txn is dead once its function returns
	var kept store.Txn
	if err := e.Tx(func(tx store.Txn) error { kept = tx; return nil }); err != nil {
		e.T.Fatal(err)
	}
	e.wantErr(kept.Consume(e.T.Context(), "late"), store.ErrTxDone, "consume after the transaction")
	if _, err := kept.Append(e.T.Context(), Record("late")); !errors.Is(err, store.ErrTxDone) {
		e.T.Errorf("append after the transaction: err = %v", err)
	}
}

// normalizeJSON compares JSON values, not bytes: jsonb normalizes whitespace and key order.
func normalizeJSON() cmp.Option {
	return cmp.Transformer("json", func(b json.RawMessage) any {
		var v any
		if err := json.Unmarshal(b, &v); err != nil {
			return string(b)
		}
		return v
	})
}

func chainsRich(e *Env) { // NFR-4: every record field survives storage, so the hashes still verify
	ctx := e.T.Context()
	grant := Record("grant")
	grant.Action = audit.ActionDecision
	grant.Actor = audit.Actor{Kind: audit.ActorHuman, ID: "github:1", Display: "octocat"}
	grant.Subject = audit.Subject{Kind: audit.SubjectIssue, Repo: TestRepo, ID: "7"}
	grant.Outcome = "granted"
	grant.Decision = &audit.Decision{Operation: "approve-scenarios", Role: "ideator", Revision: Rev(1), Verdict: audit.VerdictGranted, Reason: "ok"}
	grant.Attrs = map[string]string{"decision_id": "d-1", "note": "é \x00 nul and unicode"}
	link := Record("link")
	link.Action = audit.ActionLink
	link.Subject = audit.Subject{Kind: audit.SubjectChange, Repo: TestRepo, ID: "9"}
	link.Link = &audit.Subject{Kind: audit.SubjectIssue, Repo: TestRepo, ID: "7"}
	var want []audit.Entry
	if err := e.Tx(func(tx store.Txn) error {
		recs := []audit.Record{grant, link, Record("plain")}
		for i := range recs {
			got, err := tx.Append(ctx, recs[i])
			if err != nil {
				return err
			}
			want = append(want, got)
		}
		return nil
	}); err != nil {
		e.T.Fatal(err)
	}
	got, err := e.DecisionLog().Read(ctx, 1, 10)
	if err != nil {
		e.T.Fatal(err)
	}
	if diff := cmp.Diff(want, got); diff != "" {
		e.T.Fatalf("stored entries differ (-want +got):\n%s", diff)
	}
	if _, err := e.DecisionLog().Verify(ctx); err != nil {
		e.T.Fatal(err)
	}
}
