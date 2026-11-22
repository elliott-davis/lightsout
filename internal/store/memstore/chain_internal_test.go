// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

package memstore

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/elliott-davis/lightsout/internal/audit"
)

type tamper struct {
	inner  txChain
	mutate func(*audit.Entry)
	seals  int
}

func (b *tamper) AppendNext(ctx context.Context, seal audit.SealFunc) (audit.Entry, error) {
	return b.inner.AppendNext(ctx, func(prev audit.Head) (audit.Entry, error) {
		b.seals++
		e, err := seal(prev)
		if err == nil && b.mutate != nil {
			b.mutate(&e)
		}
		return e, err
	})
}

func (b *tamper) Read(ctx context.Context, from uint64, limit int) ([]audit.Entry, error) {
	return b.inner.Read(ctx, from, limit)
}
func (b *tamper) Head(ctx context.Context) (audit.Head, error) { return b.inner.Head(ctx) }

func TestDecisionChainRefusesBadSeal(t *testing.T) { // NFR-4: the decision chain checks every sealed entry itself
	t.Parallel()
	st, err := New(time.Now)
	if err != nil {
		t.Fatal(err)
	}
	tb := &tamper{inner: txChain{&txn{s: st, st: newState()}}}
	l, err := audit.New(tb, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	rec := audit.Record{
		Actor: audit.Actor{Kind: audit.ActorFactory, ID: "w"}, TemplateVersion: "t",
		Subject: audit.Subject{Kind: audit.SubjectInstall, ID: "i"}, Action: audit.ActionAdmin, Outcome: "ok",
	}
	if _, err := l.Append(t.Context(), rec); err != nil {
		t.Fatal(err)
	}
	for name, mut := range map[string]func(*audit.Entry){
		"gap":          func(e *audit.Entry) { e.Seq += 2 },
		"replayed seq": func(e *audit.Entry) { e.Seq-- },
		"wrong prev":   func(e *audit.Entry) { e.PrevHash[0] ^= 1 },
		"bad hash":     func(e *audit.Entry) { e.Hash[0] ^= 1 },
		"altered":      func(e *audit.Entry) { e.Target = "x" },
	} {
		tb.mutate, tb.seals = mut, 0
		if _, err := l.Append(t.Context(), rec); !errors.Is(err, audit.ErrBrokenChain) {
			t.Errorf("%s: err = %v, want ErrBrokenChain", name, err)
		}
		if tb.seals != 1 {
			t.Errorf("%s: seal called %d times, want 1", name, tb.seals)
		}
		if n := len(tb.inner.t.st.decisions); n != 1 {
			t.Fatalf("%s: chain has %d entries after a refused seal, want 1", name, n)
		}
	}
}
