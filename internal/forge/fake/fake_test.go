// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

package fake_test

import (
	"context"
	"testing"
	"time"

	"github.com/elliott-davis/lightsout/internal/forge"
	"github.com/elliott-davis/lightsout/internal/forge/fake"
	"github.com/elliott-davis/lightsout/internal/forge/forgetest"
)

// harness adapts the fake to forgetest.Harness: only Pusher differs, because the fake returns its concrete type.
type harness struct{ *fake.Forge }

func (h harness) Pusher(ctx context.Context, principal forge.Actor, repo forge.RepoID, ref string, policy forge.PushPolicy) (forge.BranchPusher, error) {
	p, err := h.Forge.Pusher(ctx, principal, repo, ref, policy)
	if err != nil {
		return nil, err
	}
	return p, nil
}

// The fake implements every optional interface of the suite, so no subtest is skipped.
var (
	_ forgetest.Editor        = (*fake.Forge)(nil)
	_ forgetest.Identities    = (*fake.Forge)(nil)
	_ forgetest.Permissions   = (*fake.Forge)(nil)
	_ forgetest.TreeSetup     = (*fake.Forge)(nil)
	_ forgetest.QueueSetup    = (*fake.Forge)(nil)
	_ forgetest.FaultInjector = (*fake.Forge)(nil)
)

func TestConformance(t *testing.T) { // INTG-1
	t.Parallel()
	forgetest.Run(t, func(*testing.T) forgetest.Harness {
		now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
		return harness{fake.New(func() time.Time { return now })}
	})
}
