// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"fmt"

	"github.com/elliott-davis/lightsout/internal/audit"
	"github.com/elliott-davis/lightsout/internal/store/checkpoint"
)

const verifyPage = 500

// VerifyOptions tunes [VerifyChains] and [WriteCheckpoints].
type VerifyOptions struct {
	// Bootstrap lets a chain that already has entries pass, or be checkpointed, without a checkpoint. It is a
	// deliberate operator action for the first start after enabling checkpoints, or for adopting a database: without
	// it, an attacker who can delete the checkpoint file could roll the chain back to any consistent state.
	Bootstrap bool
}

func chainBackend(st Store, chain string) (audit.Backend, error) {
	switch chain {
	case ChainDecision:
		return st.Decisions(), nil
	case ChainDenial:
		return st.Denials(), nil
	}
	return nil, fmt.Errorf("unknown audit chain %q", chain)
}

// walk verifies b from the start up to and including seq limit in one pass: every link with
// [audit.CheckSuccessor], and, if cp is not nil, that the chain contains cp.Seq with exactly cp.Hash. It returns
// the head it verified. Entries beyond limit (appended since the head was read) are not looked at.
func walk(ctx context.Context, b audit.Backend, limit uint64, cp *audit.Head) (audit.Head, error) {
	var prev audit.Head
	for prev.Seq < limit {
		n := int(min(uint64(verifyPage), limit-prev.Seq))
		page, err := b.Read(ctx, prev.Seq+1, n)
		if err != nil {
			return audit.Head{}, fmt.Errorf("read audit entries: %w", err)
		}
		if len(page) == 0 {
			return audit.Head{}, &audit.ChainError{Seq: prev.Seq + 1, Reason: fmt.Sprintf("chain ends at seq %d, before the head at %d", prev.Seq, limit)}
		}
		for i := range page {
			e := page[i]
			if err := audit.CheckSuccessor(prev, e); err != nil {
				return audit.Head{}, err
			}
			if cp != nil && e.Seq == cp.Seq && e.Hash != cp.Hash {
				return audit.Head{}, &audit.ChainError{Seq: e.Seq, Reason: "hash differs from checkpoint"}
			}
			prev = audit.Head{Seq: e.Seq, Hash: e.Hash}
		}
	}
	if cp != nil && cp.Seq > prev.Seq {
		return audit.Head{}, &audit.ChainError{Seq: cp.Seq, Reason: fmt.Sprintf("chain ends at seq %d, before checkpoint", prev.Seq)}
	}
	return prev, nil
}

// verifyChain reads the backend's head first, then verifies the chain once up to that head's sequence number
// against the checkpoint (if any), and requires the last verified entry's hash to equal the head's. Entries
// appended after the head was read are ignored, so it works under load. It returns the verified head.
func verifyChain(ctx context.Context, st Store, sink checkpoint.Sink, chain string, opts VerifyOptions) (audit.Head, error) {
	b, err := chainBackend(st, chain)
	if err != nil {
		return audit.Head{}, err
	}
	cp, ok, err := sink.Load(ctx, chain)
	if err != nil {
		return audit.Head{}, fmt.Errorf("load checkpoint for chain %s: %w", chain, err)
	}
	var want *audit.Head
	if ok {
		want = &audit.Head{Seq: cp.Seq, Hash: cp.Hash}
	}
	head, err := b.Head(ctx)
	if err != nil {
		return audit.Head{}, fmt.Errorf("read head of chain %s: %w", chain, err)
	}
	verified, err := walk(ctx, b, head.Seq, want)
	if err != nil {
		return audit.Head{}, fmt.Errorf("verify chain %s: %w", chain, err)
	}
	// An entry beyond the head is planted unless the head has moved to cover it since: appends insert the entry and
	// advance the head together, so any committed entry ahead of the current head did not come from an append.
	extra, err := b.Read(ctx, head.Seq+1, 1)
	if err != nil {
		return audit.Head{}, fmt.Errorf("read entries of chain %s: %w", chain, err)
	}
	if len(extra) > 0 {
		now, err := b.Head(ctx)
		if err != nil {
			return audit.Head{}, fmt.Errorf("read head of chain %s: %w", chain, err)
		}
		if now.Seq < extra[0].Seq {
			return audit.Head{}, fmt.Errorf("verify chain %s: %w", chain, &audit.ChainError{
				Seq: extra[0].Seq, Reason: "entry beyond the head of the chain",
			})
		}
	}
	if verified != head {
		return audit.Head{}, fmt.Errorf("verify chain %s: %w", chain, &audit.ChainError{
			Seq: head.Seq, Reason: "head does not match the last verified entry",
		})
	}
	if !ok && head.Seq > 0 && !opts.Bootstrap {
		return audit.Head{}, fmt.Errorf("verify chain %s: %w", chain, ErrNoCheckpoint)
	}
	return head, nil
}

// VerifyChains verifies both chains (NFR-4): each in one walk against its checkpoint in sink, with every link
// checked by the audit package's own rules, up to the head read first, whose hash must equal the last entry's. A
// chain that has entries but no checkpoint is refused with [ErrNoCheckpoint] unless opts.Bootstrap is set. Only
// the checkpointed prefix is protected against deliberate truncation or rewrite.
//
// WI-10c runs this at startup and refuses to start on an error.
func VerifyChains(ctx context.Context, st Store, sink checkpoint.Sink, opts VerifyOptions) error {
	for _, chain := range Chains() {
		if _, err := verifyChain(ctx, st, sink, chain, opts); err != nil {
			return err
		}
	}
	return nil
}

// WriteCheckpoints saves each chain's head. Each chain is walked exactly once, against its previous checkpoint,
// and the head that walk verified is the one saved, so the saved head always extends the previous checkpoint (same
// seq and hash at its position) and a chain rewritten between two reads cannot move the checkpoint onto itself.
// WI-10c schedules it every N entries and at shutdown.
func WriteCheckpoints(ctx context.Context, st Store, sink checkpoint.Sink, opts VerifyOptions) error {
	for _, chain := range Chains() {
		h, err := verifyChain(ctx, st, sink, chain, opts)
		if err != nil {
			return err
		}
		if err := sink.Save(ctx, checkpoint.Checkpoint{Chain: chain, Seq: h.Seq, Hash: h.Hash}); err != nil {
			return fmt.Errorf("save checkpoint for chain %s: %w", chain, err)
		}
	}
	return nil
}
