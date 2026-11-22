// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

package memstore_test

import (
	"testing"
	"time"

	"github.com/elliott-davis/lightsout/internal/store"
	"github.com/elliott-davis/lightsout/internal/store/memstore"
	"github.com/elliott-davis/lightsout/internal/store/storetest"
)

func TestConformance(t *testing.T) { // NFR-4, NFR-5, SEC-10
	storetest.Run(t, func(t *testing.T, clock func() time.Time) store.Store {
		t.Helper()
		st, err := memstore.New(clock)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = st.Close() })
		return st
	})
}

func TestNewRejectsNilClock(t *testing.T) { // NFR-4 negative
	t.Parallel()
	if st, err := memstore.New(nil); err == nil {
		t.Fatalf("New(nil) = %v, want an error", st)
	}
}
