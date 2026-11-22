// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

package memholdout_test

import (
	"testing"

	"github.com/elliott-davis/lightsout/internal/holdout"
	"github.com/elliott-davis/lightsout/internal/holdout/backendtest"
	"github.com/elliott-davis/lightsout/internal/holdout/memholdout"
)

func TestConformance(t *testing.T) {
	t.Parallel()
	backendtest.Run(t,
		func(*testing.T) holdout.Backend { return memholdout.New() },
		func(_ *testing.T, b holdout.Backend) holdout.Backend { return b }, // memory has no storage to reopen
	)
}
