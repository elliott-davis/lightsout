// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"fmt"

	"github.com/elliott-davis/lightsout/internal/store"
)

// StoreReceipts adapts a [store.Store] to [Receipts]: each delivery is one transaction, so the receipt and its
// work item commit or roll back together (NFR-4).
type StoreReceipts struct {
	Store store.Store
}

// RecordDelivery records the delivery and enqueues work in one transaction.
func (r StoreReceipts) RecordDelivery(ctx context.Context, forge, receiptID string, digest store.Digest, work store.WorkItem) (bool, error) {
	var isNew bool
	err := r.Store.Tx(ctx, func(ctx context.Context, tx store.Txn) error {
		var err error
		isNew, err = tx.RecordDelivery(ctx, forge, receiptID, digest, work)
		return err
	})
	if err != nil {
		return false, fmt.Errorf("record delivery: %w", err)
	}
	return isNew, nil
}
