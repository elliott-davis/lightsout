// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

package pgstore

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/elliott-davis/lightsout/internal/audit"
	"github.com/elliott-davis/lightsout/internal/store"
)

// queryer is what both a pool and a transaction offer.
type queryer interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// appendNext is [audit.Backend.AppendNext] over a transaction: lock the chain's head row, call seal exactly once
// with the head, check that the entry extends it, insert it and advance the head. The head lock serializes every
// writer of the chain until the transaction ends.
func appendNext(ctx context.Context, q queryer, chain string, seal audit.SealFunc) (audit.Entry, error) {
	var prev audit.Head
	var hash []byte
	if err := q.QueryRow(ctx, `SELECT head_seq, head_hash FROM audit_lock_head($1)`, chain).Scan(&prev.Seq, &hash); err != nil {
		return audit.Entry{}, mapErr("lock chain head", err)
	}
	if err := toHash(&prev.Hash, hash); err != nil {
		return audit.Entry{}, err
	}
	e, err := seal(prev)
	if err != nil {
		return audit.Entry{}, err
	}
	if err = audit.CheckSuccessor(prev, e); err != nil {
		return audit.Entry{}, fmt.Errorf("sealed entry rejected: %w", err)
	}
	rec, err := json.Marshal(toRecordJSON(e.Record))
	if err != nil {
		return audit.Entry{}, fmt.Errorf("encode audit record: %w", err)
	}
	// One call inserts the entry and advances the head, and refuses an entry that does not extend it.
	if _, err := q.Exec(ctx, `SELECT audit_append($1, $2, $3, $4, $5, $6, $7)`,
		chain, int64(e.Seq), e.Format, e.Time, rec, e.PrevHash[:], e.Hash[:]); err != nil { //nolint:gosec // seq is far below 2^63
		return audit.Entry{}, mapErr("append audit entry", err)
	}
	return e, nil
}

func toHash(dst *audit.Hash, b []byte) error {
	if len(b) != len(dst) {
		return fmt.Errorf("stored hash has %d bytes, want %d", len(b), len(dst))
	}
	copy(dst[:], b)
	return nil
}

func readEntries(ctx context.Context, q queryer, chain string, from uint64, limit int) ([]audit.Entry, error) {
	if from == 0 {
		from = 1
	}
	if limit < 1 {
		return []audit.Entry{}, nil
	}
	rows, err := q.Query(ctx,
		`SELECT seq, format, at, record, prev_hash, hash FROM ONLY audit_entries WHERE chain = $1 AND seq >= $2 ORDER BY seq LIMIT $3`,
		chain, int64(min(from, 1<<62)), limit)
	if err != nil {
		return nil, fmt.Errorf("read audit entries: %w", err)
	}
	defer rows.Close()
	out := []audit.Entry{}
	for rows.Next() {
		var (
			e       audit.Entry
			seq     int64
			at      time.Time
			rec     []byte
			prev, h []byte
		)
		if err := rows.Scan(&seq, &e.Format, &at, &rec, &prev, &h); err != nil {
			return nil, fmt.Errorf("scan audit entry: %w", err)
		}
		e.Seq = uint64(seq) //nolint:gosec // constrained >= 1 by the schema
		e.Time = at.UTC()
		dec := json.NewDecoder(bytes.NewReader(rec))
		dec.DisallowUnknownFields()
		var rj recordJSON
		if err := dec.Decode(&rj); err != nil {
			return nil, fmt.Errorf("decode audit record at seq %d: %w", e.Seq, err)
		}
		e.Record = rj.record()
		if err := toHash(&e.PrevHash, prev); err != nil {
			return nil, err
		}
		if err := toHash(&e.Hash, h); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read audit entries: %w", err)
	}
	return out, nil
}

func chainHead(ctx context.Context, q queryer, chain string) (audit.Head, error) {
	var h audit.Head
	var seq int64
	var hash []byte
	if err := q.QueryRow(ctx, `SELECT seq, hash FROM ONLY audit_chain_heads WHERE chain = $1`, chain).Scan(&seq, &hash); err != nil {
		return audit.Head{}, fmt.Errorf("read chain head: %w", err)
	}
	h.Seq = uint64(seq) //nolint:gosec // constrained >= 0 by the schema
	if err := toHash(&h.Hash, hash); err != nil {
		return audit.Head{}, err
	}
	return h, nil
}

// txChain is a chain inside a caller's transaction: the decision chain.
type txChain struct {
	id string
	tx pgx.Tx
}

func (c txChain) AppendNext(ctx context.Context, seal audit.SealFunc) (audit.Entry, error) {
	return appendNext(ctx, c.tx, c.id, seal)
}

func (c txChain) Read(ctx context.Context, from uint64, limit int) ([]audit.Entry, error) {
	return readEntries(ctx, c.tx, c.id, from, limit)
}

func (c txChain) Head(ctx context.Context) (audit.Head, error) { return chainHead(ctx, c.tx, c.id) }

// readChain is a committed, read-only view.
type readChain struct {
	id string
	q  queryer
}

func (c readChain) AppendNext(context.Context, audit.SealFunc) (audit.Entry, error) {
	return audit.Entry{}, store.ErrReadOnly
}

func (c readChain) Read(ctx context.Context, from uint64, limit int) ([]audit.Entry, error) {
	return readEntries(ctx, c.q, c.id, from, limit)
}

func (c readChain) Head(ctx context.Context) (audit.Head, error) { return chainHead(ctx, c.q, c.id) }

// denialChain is the denial chain: every append is its own transaction on the reserved pool, so it commits no
// matter what happens to any state transaction. Reads go over the worker pool, so verification never competes
// with denials for the reserved connections.
type denialChain struct{ reserved, pool *pgxpool.Pool }

func (c denialChain) AppendNext(ctx context.Context, seal audit.SealFunc) (audit.Entry, error) {
	tx, err := c.reserved.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return audit.Entry{}, fmt.Errorf("begin denial transaction: %w", err)
	}
	e, err := appendNext(ctx, tx, store.ChainDenial, seal)
	if err != nil {
		rollback(ctx, tx)
		return audit.Entry{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		// The commit's outcome is unknown: report it the way the audit package defines.
		return audit.Entry{}, &audit.StoreError{Seq: e.Seq, Hash: e.Hash, Err: errors.Join(errors.New("commit denial"), err)}
	}
	return e, nil
}

func (c denialChain) Read(ctx context.Context, from uint64, limit int) ([]audit.Entry, error) {
	return readEntries(ctx, c.pool, store.ChainDenial, from, limit)
}

func (c denialChain) Head(ctx context.Context) (audit.Head, error) {
	return chainHead(ctx, c.pool, store.ChainDenial)
}

// recordJSON is the stored form of an [audit.Record]. It is spelled out so the stored bytes do not depend on the
// audit package's Go field names, and unknown fields in the database are an error on read.
type recordJSON struct {
	ActorKind       string            `json:"actor_kind"`
	ActorID         string            `json:"actor_id"`
	ActorDisplay    string            `json:"actor_display"`
	TemplateVersion string            `json:"template_version"`
	Subject         subjectJSON       `json:"subject"`
	Action          string            `json:"action"`
	Target          string            `json:"target"`
	Outcome         string            `json:"outcome"`
	Decision        *decisionJSON     `json:"decision"`
	Link            *subjectJSON      `json:"link"`
	Attrs           map[string]string `json:"attrs"`
}

type subjectJSON struct {
	Kind string `json:"kind"`
	Repo string `json:"repo"`
	ID   string `json:"id"`
}

type decisionJSON struct {
	Operation string `json:"operation"`
	Role      string `json:"role"`
	Revision  string `json:"revision"`
	Verdict   string `json:"verdict"`
	Reason    string `json:"reason"`
}

func toRecordJSON(r audit.Record) recordJSON {
	j := recordJSON{
		ActorKind: string(r.Actor.Kind), ActorID: r.Actor.ID, ActorDisplay: r.Actor.Display,
		TemplateVersion: r.TemplateVersion,
		Subject:         subjectJSON{Kind: string(r.Subject.Kind), Repo: r.Subject.Repo, ID: r.Subject.ID},
		Action:          string(r.Action), Target: r.Target, Outcome: r.Outcome,
		Attrs: r.Attrs,
	}
	if d := r.Decision; d != nil {
		j.Decision = &decisionJSON{Operation: d.Operation, Role: d.Role, Revision: d.Revision, Verdict: string(d.Verdict), Reason: d.Reason}
	}
	if l := r.Link; l != nil {
		j.Link = &subjectJSON{Kind: string(l.Kind), Repo: l.Repo, ID: l.ID}
	}
	return j
}

func (j recordJSON) record() audit.Record {
	r := audit.Record{
		Actor:           audit.Actor{Kind: audit.ActorKind(j.ActorKind), ID: j.ActorID, Display: j.ActorDisplay},
		TemplateVersion: j.TemplateVersion,
		Subject:         audit.Subject{Kind: audit.SubjectKind(j.Subject.Kind), Repo: j.Subject.Repo, ID: j.Subject.ID},
		Action:          audit.Action(j.Action), Target: j.Target, Outcome: j.Outcome,
	}
	if len(j.Attrs) > 0 {
		r.Attrs = j.Attrs
	}
	if d := j.Decision; d != nil {
		r.Decision = &audit.Decision{Operation: d.Operation, Role: d.Role, Revision: d.Revision, Verdict: audit.Verdict(d.Verdict), Reason: d.Reason}
	}
	if l := j.Link; l != nil {
		r.Link = &audit.Subject{Kind: audit.SubjectKind(l.Kind), Repo: l.Repo, ID: l.ID}
	}
	return r
}
