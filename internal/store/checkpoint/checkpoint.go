// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

// Package checkpoint saves audit chain heads outside the log's own storage (NFR-4).
//
// An unkeyed hash chain cannot detect removal of its last entries or a deliberate rewrite. A saved head can. The
// sink should live somewhere the database's writers cannot reach: another disk, another system, a signed release
// record. The file sink here is the minimum: it makes the checkpoint atomic and durable, but it is only as
// trustworthy as the directory's permissions.
package checkpoint

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"

	"github.com/elliott-davis/lightsout/internal/audit"
)

// Errors.
var (
	// ErrRegression means a save would move a chain's checkpoint backwards or change a hash at the same sequence.
	ErrRegression = errors.New("checkpoint: would regress")
	// ErrInvalid means a checkpoint or chain name is malformed.
	ErrInvalid = errors.New("checkpoint: invalid")
)

// Checkpoint is a chain's committed head.
type Checkpoint struct {
	Chain string     `json:"chain"`
	Seq   uint64     `json:"seq"`
	Hash  audit.Hash `json:"hash"`
}

// Sink stores checkpoints, one per chain.
type Sink interface {
	// Save durably records c. It fails with [ErrRegression] if it would lower the saved sequence or change the hash at the
	// same sequence.
	Save(ctx context.Context, c Checkpoint) error
	// Load returns the saved checkpoint, or false if none was saved.
	Load(ctx context.Context, chain string) (Checkpoint, bool, error)
}

var chainName = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)

// File is a [Sink] that keeps one JSON file per chain in a directory. It assumes a single writer process: Save is
// a read-compare-write, so two processes saving at once can race. Keep the directory out of reach of whoever can
// write the database.
type File struct {
	dir string
}

// NewFile returns a file sink over dir, which must already exist.
func NewFile(dir string) (*File, error) {
	fi, err := os.Stat(dir)
	if err != nil {
		return nil, fmt.Errorf("checkpoint directory: %w", err)
	}
	if !fi.IsDir() {
		return nil, fmt.Errorf("checkpoint directory %s: %w", dir, ErrInvalid)
	}
	return &File{dir: dir}, nil
}

// Path returns the file that holds the chain's checkpoint.
func (f *File) Path(chain string) (string, error) { return f.path(chain) }

func (f *File) path(chain string) (string, error) {
	if !chainName.MatchString(chain) {
		return "", fmt.Errorf("%w: chain name %q", ErrInvalid, chain)
	}
	return filepath.Join(f.dir, chain+".checkpoint.json"), nil
}

// Load implements [Sink].
func (f *File) Load(ctx context.Context, chain string) (Checkpoint, bool, error) {
	if err := ctx.Err(); err != nil {
		return Checkpoint{}, false, err
	}
	p, err := f.path(chain)
	if err != nil {
		return Checkpoint{}, false, err
	}
	b, err := os.ReadFile(p)
	if errors.Is(err, os.ErrNotExist) {
		return Checkpoint{}, false, nil
	}
	if err != nil {
		return Checkpoint{}, false, fmt.Errorf("read checkpoint: %w", err)
	}
	var c Checkpoint
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return Checkpoint{}, false, fmt.Errorf("%w: %s: %w", ErrInvalid, p, err)
	}
	if c.Chain != chain {
		return Checkpoint{}, false, fmt.Errorf("%w: %s names chain %q", ErrInvalid, p, c.Chain)
	}
	if c.Seq == 0 && c.Hash != (audit.Hash{}) {
		return Checkpoint{}, false, fmt.Errorf("%w: %s has a hash but no sequence number", ErrInvalid, p)
	}
	return c, true, nil
}

// Save implements [Sink]. It writes a temp file, fsyncs it, renames it over the old one and fsyncs the directory.
func (f *File) Save(ctx context.Context, c Checkpoint) error {
	p, err := f.path(c.Chain)
	if err != nil {
		return err
	}
	if c.Seq == 0 && c.Hash != (audit.Hash{}) {
		return fmt.Errorf("%w: hash without sequence number", ErrInvalid)
	}
	old, ok, err := f.Load(ctx, c.Chain)
	if err != nil {
		return err
	}
	if ok && (c.Seq < old.Seq || (c.Seq == old.Seq && c.Hash != old.Hash)) {
		return fmt.Errorf("%w: chain %s saved at seq %d, new seq %d", ErrRegression, c.Chain, old.Seq, c.Seq)
	}
	b, err := json.Marshal(c)
	if err != nil {
		return fmt.Errorf("encode checkpoint: %w", err)
	}
	tmp, err := os.CreateTemp(f.dir, "."+c.Chain+".tmp-*")
	if err != nil {
		return fmt.Errorf("create temp checkpoint: %w", err)
	}
	tmpName := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpName) }
	if _, err = tmp.Write(append(b, '\n')); err != nil {
		_ = tmp.Close()
		cleanup()
		return fmt.Errorf("write checkpoint: %w", err)
	}
	if err = tmp.Sync(); err != nil {
		_ = tmp.Close()
		cleanup()
		return fmt.Errorf("sync checkpoint: %w", err)
	}
	if err = tmp.Close(); err != nil {
		cleanup()
		return fmt.Errorf("close checkpoint: %w", err)
	}
	if err = os.Rename(tmpName, p); err != nil {
		cleanup()
		return fmt.Errorf("rename checkpoint: %w", err)
	}
	d, err := os.Open(f.dir)
	if err != nil {
		return fmt.Errorf("open checkpoint directory: %w", err)
	}
	defer d.Close()
	if err := d.Sync(); err != nil {
		return fmt.Errorf("sync checkpoint directory: %w", err)
	}
	return nil
}
