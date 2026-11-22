// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

package codeowners

import (
	"context"
	"errors"
	"fmt"
	"io/fs"

	"github.com/elliott-davis/lightsout/internal/forge"
)

// TreeReader is the part of the forge this package reads. Read the file only at a full commit SHA.
type TreeReader interface {
	Tree(ctx context.Context, repo forge.RepoID, sha string) (fs.FS, error)
}

// Locations returns where CODEOWNERS may live, in the order GitHub looks. The first one found is used.
func Locations() []string { return []string{".github/CODEOWNERS", "CODEOWNERS", "docs/CODEOWNERS"} }

// Load reads and parses CODEOWNERS from the tree at sha, which must be a full commit SHA (40 or 64 lowercase hex),
// checked before the forge is called. The tree must report symlinks without following them ([fs.ReadLinkFS]), or
// Load refuses it. It records repo on the file. It uses the first location that exists. No file at all is valid and owns nothing. A symlink anywhere on a location's path
// ([forge.ErrSymlink]), a directory, an oversized file or any other read error is an error, never "no file", and
// so is a syntax error ([*ParseError]).
func Load(ctx context.Context, tr TreeReader, repo forge.RepoID, sha string) (*File, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !fullSHA(sha) {
		return nil, fmt.Errorf("load codeowners: %s is not a full commit SHA: %w", echo(sha), forge.ErrInvalid)
	}
	tree, err := tr.Tree(ctx, repo, sha)
	if err != nil {
		return nil, fmt.Errorf("load codeowners at %s: %w", sha, err)
	}
	if _, ok := tree.(fs.ReadLinkFS); !ok {
		return nil, fmt.Errorf("load codeowners at %s: tree cannot report symlinks (no Lstat): %w", sha, forge.ErrUnsupported)
	}
	for _, loc := range Locations() {
		info, err := fs.Lstat(tree, loc)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("load codeowners %s at %s: %w", loc, sha, err)
		}
		if info.Mode()&fs.ModeSymlink != 0 {
			return nil, fmt.Errorf("load codeowners %s at %s: %w", loc, sha, forge.ErrSymlink)
		}
		if !info.Mode().IsRegular() {
			return nil, fmt.Errorf("load codeowners %s at %s: not a regular file: %w", loc, sha, forge.ErrInvalid)
		}
		if info.Size() >= MaxFileBytes {
			return nil, fmt.Errorf("load codeowners %s at %s: %w", loc, sha, forge.ErrTooLarge)
		}
		data, err := fs.ReadFile(tree, loc)
		if err != nil {
			return nil, fmt.Errorf("load codeowners %s at %s: %w", loc, sha, err)
		}
		f, err := Parse(loc, data)
		if err != nil {
			return nil, fmt.Errorf("load codeowners at %s: %w", sha, err)
		}
		f.revision, f.repo = sha, repo
		return f, nil
	}
	return &File{revision: sha, repo: repo}, nil
}

func fullSHA(s string) bool {
	if len(s) != 40 && len(s) != 64 {
		return false
	}
	for i := range len(s) {
		if c := s[i]; (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}
