// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

package install

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"strings"

	"github.com/elliott-davis/lightsout/internal/forge"
	"github.com/elliott-davis/lightsout/internal/pathglob"
)

// TreeReader is the part of the forge Load reads. Read the install file only at a full commit SHA.
type TreeReader interface {
	Tree(ctx context.Context, repo forge.RepoID, sha string) (fs.FS, error)
}

// Load reads the install config at path from the tree of repo at sha, which must be a full commit SHA (40 or 64
// lowercase hex digits), checked before the forge is called. It is the production entry point: it sets the install
// revision from sha, so the baseline, every Effective contract and the trust digest bind to it (RUN-1). The tree must
// report symlinks without following them ([fs.ReadLinkFS]); a symlink at path or on its way is [forge.ErrSymlink], and
// a directory, an oversized file or any other read error is an error. Problems with the content are a
// [*ValidationError].
func Load(ctx context.Context, tr TreeReader, repo forge.RepoID, sha, path string) (*Config, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !revisionPattern.MatchString(sha) {
		return nil, fmt.Errorf("load install config: %s is not a full commit SHA: %w", q(sha), forge.ErrInvalid)
	}
	if err := pathglob.ValidatePath(path); err != nil {
		return nil, fmt.Errorf("load install config: %w", err)
	}
	tree, err := tr.Tree(ctx, repo, sha)
	if err != nil {
		return nil, fmt.Errorf("load install config at %s: %w", sha, err)
	}
	if _, ok := tree.(fs.ReadLinkFS); !ok {
		return nil, fmt.Errorf("load install config at %s: tree cannot report symlinks (no Lstat): %w", sha, forge.ErrUnsupported)
	}
	segs := strings.Split(path, "/")
	for i := range segs {
		prefix := strings.Join(segs[:i+1], "/")
		info, lerr := fs.Lstat(tree, prefix)
		if lerr != nil {
			return nil, fmt.Errorf("load install config %s at %s: %w", q(prefix), sha, lerr)
		}
		if info.Mode()&fs.ModeSymlink != 0 {
			return nil, fmt.Errorf("load install config %s at %s: %w", q(prefix), sha, forge.ErrSymlink)
		}
		if i == len(segs)-1 {
			if !info.Mode().IsRegular() {
				return nil, fmt.Errorf("load install config %s at %s: not a regular file: %w", q(prefix), sha, forge.ErrInvalid)
			}
			if info.Size() > MaxFileSize {
				return nil, fmt.Errorf("load install config %s at %s: %w", q(prefix), sha, forge.ErrTooLarge)
			}
		}
	}
	f, err := tree.Open(path)
	if err != nil {
		return nil, fmt.Errorf("load install config %s at %s: %w", q(path), sha, err)
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, MaxFileSize+1))
	if err != nil {
		return nil, fmt.Errorf("load install config %s at %s: %w", q(path), sha, err)
	}
	if len(data) > MaxFileSize {
		return nil, fmt.Errorf("load install config %s at %s: %w", q(path), sha, forge.ErrTooLarge)
	}
	cfg, err := Parse(data)
	if err != nil {
		return nil, err
	}
	return cfg.WithRevision(sha)
}
