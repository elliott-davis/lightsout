// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

// Package memholdout is the in-memory [holdout.Backend] for tests and development only.
//
// It loses everything on restart, so a production configuration must not use it: a durable backend that keeps
// suites, reviews, grant redemptions, outcomes and audit across restarts is a prerequisite for the first real
// Acceptance run. All calls are serialized by one mutex, so the global run and assignment indexes are always
// consistent with the state a function sees. An update works on a copy of the suite's state, so one that returns an
// error stores nothing. File bytes live in separate immutable blobs, so an update does not copy them.
package memholdout

import (
	"bytes"
	"context"
	"fmt"
	"sync"

	"github.com/elliott-davis/lightsout/internal/holdout"
)

type attemptKey struct {
	run     string
	attempt int
}

type blobKey struct {
	suite holdout.SuiteID
	rev   holdout.Revision
}

// Backend is an in-memory backend. The zero value is not usable; call [New].
type Backend struct {
	mu          sync.Mutex
	suites      map[holdout.SuiteID]holdout.State
	runs        map[string]holdout.SuiteID
	assignments map[string]attemptKey
	blobs       map[blobKey][]holdout.File
}

// New returns an empty backend.
func New() *Backend {
	return &Backend{
		suites:      map[holdout.SuiteID]holdout.State{},
		runs:        map[string]holdout.SuiteID{},
		assignments: map[string]attemptKey{},
		blobs:       map[blobKey][]holdout.File{},
	}
}

type readTx struct {
	b     *Backend
	suite holdout.SuiteID
}

func (t readTx) RunSuite(runID string) (holdout.SuiteID, bool) {
	s, ok := t.b.runs[runID]
	return s, ok
}

func (t readTx) AssignmentBound(a string) bool {
	_, ok := t.b.assignments[a]
	return ok
}

func (t readTx) Files(rev holdout.Revision) ([]holdout.File, bool) {
	f, ok := t.b.blobs[blobKey{t.suite, rev}]
	return f, ok
}

type writeTx struct {
	readTx
	pending map[holdout.Revision][]holdout.File
}

func (t *writeTx) Files(rev holdout.Revision) ([]holdout.File, bool) {
	if f, ok := t.pending[rev]; ok {
		return f, true
	}
	return t.readTx.Files(rev)
}

func (t *writeTx) PutFiles(rev holdout.Revision, files []holdout.File) error {
	if _, ok := t.Files(rev); ok {
		return fmt.Errorf("files of %s already stored: %w", rev, holdout.ErrConflict)
	}
	cp := make([]holdout.File, len(files))
	for i, f := range files {
		f.Bytes = bytes.Clone(f.Bytes)
		cp[i] = f
	}
	t.pending[rev] = cp
	return nil
}

// View implements [holdout.Backend]. It holds the lock while fn runs, so fn sees a stable state.
func (b *Backend) View(ctx context.Context, suite holdout.SuiteID, fn func(*holdout.State, holdout.ReadTx) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	st := b.suites[suite]
	return fn(&st, readTx{b, suite})
}

// Update implements [holdout.Backend].
func (b *Backend) Update(ctx context.Context, suite holdout.SuiteID, fn func(*holdout.State, holdout.WriteTx) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	st := b.suites[suite].Clone()
	tx := &writeTx{readTx: readTx{b, suite}, pending: map[holdout.Revision][]holdout.File{}}
	if err := fn(&st, tx); err != nil {
		return err
	}
	runs, assignments, err := b.indexes(suite, &st)
	if err != nil {
		return err
	}
	for id := range runs {
		b.runs[id] = suite
	}
	for a, k := range assignments {
		b.assignments[a] = k
	}
	for rev, files := range tx.pending {
		b.blobs[blobKey{suite, rev}] = files
	}
	b.suites[suite] = st
	return nil
}

// indexes checks the global uniqueness rules for the state about to commit and returns the entries to add.
func (b *Backend) indexes(suite holdout.SuiteID, st *holdout.State) (map[string]bool, map[string]attemptKey, error) {
	runs := map[string]bool{}
	assignments := map[string]attemptKey{}
	for id, run := range st.Runs {
		if owner, ok := b.runs[id]; ok && owner != suite {
			return nil, nil, fmt.Errorf("run %q belongs to another suite: %w", id, holdout.ErrConflict)
		}
		runs[id] = true
		for _, at := range run.Attempts {
			k := attemptKey{id, at.Number}
			if owner, ok := b.assignments[at.Assignment]; ok && owner != k {
				return nil, nil, fmt.Errorf("assignment is already bound: %w", holdout.ErrConflict)
			}
			if prev, ok := assignments[at.Assignment]; ok && prev != k {
				return nil, nil, fmt.Errorf("assignment is bound twice: %w", holdout.ErrConflict)
			}
			assignments[at.Assignment] = k
		}
	}
	return runs, assignments, nil
}

// SuiteOfRun implements [holdout.Backend].
func (b *Backend) SuiteOfRun(ctx context.Context, runID string) (suite holdout.SuiteID, ok bool, err error) {
	if cerr := ctx.Err(); cerr != nil {
		return holdout.SuiteID{}, false, cerr
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	suite, ok = b.runs[runID]
	return suite, ok, nil
}

var _ holdout.Backend = (*Backend)(nil)
