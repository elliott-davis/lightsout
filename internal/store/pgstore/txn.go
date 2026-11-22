// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

package pgstore

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/elliott-davis/lightsout/internal/audit"
	"github.com/elliott-davis/lightsout/internal/authz"
	"github.com/elliott-davis/lightsout/internal/store"
)

type txn struct {
	s    *Store
	tx   pgx.Tx
	done bool
	log  *audit.Log
}

func (t *txn) check(ctx context.Context) error {
	if t.done {
		return store.ErrTxDone
	}
	return ctx.Err()
}

// Consume inserts the decision ID into a table whose primary key is the ID. Only a conflict on that key is a
// replay, so the statement names it as the arbiter. A concurrent transaction that inserted the same ID first makes
// this one wait until it commits (replay) or rolls back (this insert succeeds).
func (t *txn) Consume(ctx context.Context, decisionID string) error {
	if err := t.check(ctx); err != nil {
		return err
	}
	if err := store.ValidateKey("decision id", decisionID); err != nil {
		return err
	}
	tag, err := t.tx.Exec(ctx,
		`INSERT INTO consumed_decisions (decision_id, consumed_at) VALUES ($1, $2) ON CONFLICT (decision_id) DO NOTHING`,
		decisionID, t.s.now())
	if err != nil {
		return mapErr("consume decision", err)
	}
	if tag.RowsAffected() == 0 {
		return authz.ErrReplayed
	}
	return nil
}

// Append appends to the decision chain inside this transaction.
func (t *txn) Append(ctx context.Context, r audit.Record) (audit.Entry, error) {
	if err := t.check(ctx); err != nil {
		return audit.Entry{}, err
	}
	if t.log == nil {
		l, err := audit.New(txChain{id: store.ChainDecision, tx: t.tx}, t.s.now)
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
	// A savepoint makes the receipt and the enqueue one unit even if the caller swallows an error and commits: if
	// the enqueue fails, the receipt insert is rolled back with it.
	sp, err := t.tx.Begin(ctx)
	if err != nil {
		return false, fmt.Errorf("begin delivery savepoint: %w", err)
	}
	tag, err := sp.Exec(ctx,
		`INSERT INTO deliveries (forge, delivery_id, digest, received_at) VALUES ($1, $2, $3, $4)
		 ON CONFLICT (forge, delivery_id) DO NOTHING`,
		forge, deliveryID, digest[:], t.s.now())
	if err != nil {
		_ = sp.Rollback(ctx)
		return false, mapErr("record delivery", err)
	}
	if tag.RowsAffected() == 0 {
		var have []byte
		err = sp.QueryRow(ctx, `SELECT digest FROM deliveries WHERE forge = $1 AND delivery_id = $2`, forge, deliveryID).Scan(&have)
		if err != nil {
			_ = sp.Rollback(ctx)
			return false, mapErr("read delivery", err)
		}
		if err = sp.Commit(ctx); err != nil {
			return false, fmt.Errorf("release delivery savepoint: %w", err)
		}
		if !bytes.Equal(have, digest[:]) {
			return false, store.ErrDeliveryConflict
		}
		return false, nil
	}
	if err = enqueue(ctx, sp, work); err != nil {
		_ = sp.Rollback(ctx)
		return false, err
	}
	if err = sp.Commit(ctx); err != nil {
		return false, fmt.Errorf("release delivery savepoint: %w", err)
	}
	return true, nil
}

func (t *txn) Get(ctx context.Context, kind store.Kind, id string) (store.Row, error) {
	if err := t.check(ctx); err != nil {
		return store.Row{}, err
	}
	if err := store.ValidateRowKey(kind, id); err != nil {
		return store.Row{}, err
	}
	r := store.Row{Kind: kind, ID: id}
	err := t.tx.QueryRow(ctx,
		`SELECT repo, version, current_revision, approved_revision, schema_version, payload FROM state_rows WHERE kind = $1 AND id = $2`,
		string(kind), id).Scan(&r.Repo, &r.Version, &r.CurrentRevision, &r.ApprovedRevision, &r.SchemaVersion, &r.Payload)
	if errors.Is(err, pgx.ErrNoRows) {
		return store.Row{}, store.ErrNotFound
	}
	if err != nil {
		return store.Row{}, mapErr("get row", err)
	}
	return r, nil
}

func (t *txn) Put(ctx context.Context, row store.Row, expect store.Version, expectRevision string) (store.Version, error) {
	if err := t.check(ctx); err != nil {
		return 0, err
	}
	if err := row.Validate(); err != nil {
		return 0, err
	}
	if expect < 0 {
		return 0, fmt.Errorf("%w: expected version %d", store.ErrInvalid, expect)
	}
	if expect == 0 && expectRevision != "" {
		return 0, fmt.Errorf("%w: an expected revision with a create", store.ErrInvalid)
	}
	if expectRevision != "" {
		if err := (store.Row{Kind: store.KindIssue, ID: "x", Repo: "x", CurrentRevision: expectRevision, SchemaVersion: 1, Payload: []byte(`{}`)}).Validate(); err != nil {
			return 0, fmt.Errorf("%w: expected revision is not a digest", store.ErrInvalid)
		}
	}
	var v store.Version
	var err error
	if expect == 0 {
		err = t.tx.QueryRow(ctx,
			`INSERT INTO state_rows (kind, id, repo, version, current_revision, approved_revision, schema_version, payload)
			 VALUES ($1, $2, $3, 1, $4, $5, $6, $7) ON CONFLICT (kind, id) DO NOTHING RETURNING version`,
			string(row.Kind), row.ID, row.Repo, row.CurrentRevision, row.ApprovedRevision, row.SchemaVersion, []byte(row.Payload)).Scan(&v)
	} else {
		err = t.tx.QueryRow(ctx,
			`UPDATE state_rows SET repo = $3, version = version + 1, current_revision = $4, approved_revision = $5, schema_version = $6, payload = $7
			 WHERE kind = $1 AND id = $2 AND version = $8 AND current_revision = $9 RETURNING version`,
			string(row.Kind), row.ID, row.Repo, row.CurrentRevision, row.ApprovedRevision, row.SchemaVersion, []byte(row.Payload), int64(expect), expectRevision).Scan(&v)
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, store.ErrConflict
	}
	if err != nil {
		return 0, mapErr("put row", err)
	}
	return v, nil
}

func (t *txn) Enqueue(ctx context.Context, w store.WorkItem) error {
	if err := t.check(ctx); err != nil {
		return err
	}
	if err := w.Validate(); err != nil {
		return err
	}
	return enqueue(ctx, t.tx, w)
}

// enqueue inserts the work item. A duplicate key is [store.ErrDuplicateWork].
func enqueue(ctx context.Context, q queryer, w store.WorkItem) error {
	payload := []byte(w.Payload)
	if len(payload) == 0 {
		payload = []byte(`{}`)
	}
	tag, err := q.Exec(ctx,
		`INSERT INTO work_items (key, kind, payload) VALUES ($1, $2, $3) ON CONFLICT (key) DO NOTHING`,
		w.Key, w.Kind, payload)
	if err != nil {
		return mapErr("enqueue work", err)
	}
	if tag.RowsAffected() == 0 {
		return store.ErrDuplicateWork
	}
	return nil
}

// fence is the condition every lease-holder operation must satisfy: the current generation, not finished, and
// not expired by the store's own clock.
const fence = `key = $1 AND generation = $2 AND NOT completed AND NOT dead AND leased_until > $3`

func (t *txn) fenced(ctx context.Context, l store.Lease, set string, args ...any) error {
	if err := t.check(ctx); err != nil {
		return err
	}
	if err := store.ValidateKey("lease key", l.Key); err != nil {
		return err
	}
	if l.Generation < 1 {
		return store.ErrLeaseLost
	}
	args = append([]any{l.Key, l.Generation, t.s.now()}, args...)
	tag, err := t.tx.Exec(ctx, `UPDATE work_items SET `+set+` WHERE `+fence, args...)
	if err != nil {
		return mapErr("update work item", err)
	}
	if tag.RowsAffected() == 0 {
		return store.ErrLeaseLost
	}
	return nil
}

func (t *txn) Complete(ctx context.Context, l store.Lease) error {
	return t.fenced(ctx, l, `completed = true, leased_until = NULL`)
}

func (t *txn) Reschedule(ctx context.Context, l store.Lease, notBefore time.Time) error {
	if err := store.ValidateTime("reschedule time", notBefore); err != nil {
		return err
	}
	return t.fenced(ctx, l, `attempts = attempts + 1, not_before = $4, leased_until = NULL, owner = ''`, notBefore.UTC().Truncate(time.Microsecond))
}

func (t *txn) DeadLetter(ctx context.Context, l store.Lease, reason string) error {
	if err := store.ValidateKey("dead letter reason", reason); err != nil {
		return err
	}
	return t.fenced(ctx, l, `dead = true, dead_reason = $4, leased_until = NULL`, reason)
}

// mapErr classifies a database error. A refusal of the value itself becomes [store.ErrInvalid], as a backstop for
// what the store's own validation should already have rejected: an unsupported escape or surrogate in jsonb
// (22P05, 22P02), invalid UTF-8 (22021) and numeric overflow (22003). A deadlock victim (40P01), a serialization
// failure (40001) and a lock timeout (55P03) become [store.ErrRetry]. Anything else is wrapped unchanged.
func mapErr(what string, err error) error {
	var pe *pgconn.PgError
	if errors.As(err, &pe) {
		switch pe.Code {
		case "22P05", "22P02", "22021", "22003":
			return fmt.Errorf("%w: %s: %s", store.ErrInvalid, what, pe.Message)
		case "40P01", "40001", "55P03":
			return fmt.Errorf("%w: %s: %w", store.ErrRetry, what, err)
		}
	}
	return fmt.Errorf("%s: %w", what, err)
}
