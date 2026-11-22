// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"fmt"
	"sync"
)

// Memory is an in-memory [Backend] for tests and ephemeral use. Holding a Memory is a write capability: it can
// append entries with any seal, so only the [Log]'s owner should hold it.
type Memory struct {
	mu      sync.Mutex
	entries []Entry
}

// NewMemory returns an empty in-memory backend.
func NewMemory() *Memory { return &Memory{} }

func (m *Memory) head() Head {
	if len(m.entries) == 0 {
		return Head{}
	}
	return headOf(m.entries[len(m.entries)-1])
}

// AppendNext implements [Backend].
func (m *Memory) AppendNext(ctx context.Context, seal SealFunc) (Entry, error) {
	if err := ctx.Err(); err != nil {
		return Entry{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := ctx.Err(); err != nil { // the context may have ended while waiting for the lock
		return Entry{}, err
	}
	prev := m.head()
	e, err := seal(prev)
	if err != nil {
		return Entry{}, err
	}
	if err := checkLink(prev, e); err != nil {
		return Entry{}, fmt.Errorf("sealed entry rejected: %w", err)
	}
	e = cloneEntry(e)
	m.entries = append(m.entries, e)
	return cloneEntry(e), nil
}

// Read implements [Backend].
func (m *Memory) Read(ctx context.Context, fromSeq uint64, limit int) ([]Entry, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if fromSeq == 0 {
		fromSeq = 1
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if fromSeq > uint64(len(m.entries)) || limit < 1 {
		return []Entry{}, nil
	}
	end := min(uint64(len(m.entries)), fromSeq-1+uint64(limit))
	return cloneEntries(m.entries[fromSeq-1 : end]), nil
}

// Head implements [Backend].
func (m *Memory) Head(ctx context.Context) (Head, error) {
	if err := ctx.Err(); err != nil {
		return Head{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.head(), nil
}
