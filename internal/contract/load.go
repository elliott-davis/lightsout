// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

package contract

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"path"
	"regexp"
	"slices"
	"strings"

	"github.com/elliott-davis/lightsout/internal/pathglob"
)

// maxContracts is the most contract files one Load reads.
const maxContracts = 1000

// misnamedFile is the near-miss spelling that is reported rather than skipped.
const misnamedFile = ".factory.yml"

// foreignTreeMessage explains a .git entry below the root.
const foreignTreeMessage = "nested repository or submodule metadata; contracts must be read from the tracked tree"

// revisionPattern is a full lowercase commit ID, SHA-1 or SHA-256.
var revisionPattern = regexp.MustCompile(`^([0-9a-f]{40}|[0-9a-f]{64})$`)

func checkRevision(revision string) error {
	if !revisionPattern.MatchString(revision) {
		return fmt.Errorf("revision %s is not a full commit ID", quote(revision))
	}
	return nil
}

// Set is the collection of contracts read from one revision of a repo. The
// contracts it returns are shared: treat them as read-only.
type Set struct {
	revision string
	byDir    map[string]*Contract
}

// NewSet builds a Set for revision, a full commit ID. It rejects a nil
// contract, an invalid Dir and two contracts in one directory.
func NewSet(revision string, contracts ...*Contract) (*Set, error) {
	if err := checkRevision(revision); err != nil {
		return nil, fmt.Errorf("new contract set: %w", err)
	}
	s := &Set{revision: revision, byDir: make(map[string]*Contract, len(contracts))}
	for _, c := range contracts {
		if c == nil {
			return nil, errors.New("new contract set: nil contract")
		}
		if c.Dir != "" {
			if err := pathglob.ValidatePath(c.Dir); err != nil {
				return nil, fmt.Errorf("new contract set: %w", err)
			}
		}
		if _, dup := s.byDir[c.Dir]; dup {
			return nil, fmt.Errorf("new contract set: duplicate contract for directory %s", quote(c.Dir))
		}
		s.byDir[c.Dir] = c
	}
	return s, nil
}

// Revision is the commit the set was read from, which is the policy revision.
func (s *Set) Revision() string { return s.revision }

// Get returns the contract in dir ("" for the repo root). The result is
// shared with the Set: do not modify it.
func (s *Set) Get(dir string) (*Contract, bool) {
	c, ok := s.byDir[dir]
	return c, ok
}

// Dirs returns the directories that hold a contract, sorted.
func (s *Set) Dirs() []string {
	return slices.Sorted(maps.Keys(s.byDir))
}

// Load discovers and parses every contract in fsys (CON-1). fsys must be the
// repository's tracked tree at revision, a full commit ID: production callers
// pass a git-tree reader, never a working tree, because a working tree holds
// untracked and ignored files that were never reviewed. As a second line of
// defense, any .git entry below the root (a submodule or nested repository)
// is a problem: its contracts are another trust domain, and skipping them
// would silently loosen access.
//
// Load fails closed: if any file is invalid it returns a *ValidationError
// listing the problems (at most 100, the last possibly a note of how many were
// omitted) and no Set. At most 1000 contract files are read.
func Load(ctx context.Context, fsys fs.FS, p *Parser, revision string) (*Set, error) {
	if err := checkRevision(revision); err != nil {
		return nil, fmt.Errorf("load contracts: %w", err)
	}
	var (
		problems  []Problem
		contracts []*Contract
		files     int
	)
	err := fs.WalkDir(fsys, ".", func(name string, d fs.DirEntry, err error) error {
		if cerr := ctx.Err(); cerr != nil {
			return cerr
		}
		if err != nil {
			return fmt.Errorf("walk %q: %w", name, err)
		}
		if d.Name() == ".git" {
			ps, serr := foreignTree(name, d)
			problems = append(problems, ps...)
			return serr
		}
		if d.IsDir() {
			return nil
		}
		switch {
		case d.Name() == FileName:
			files++
			if files > maxContracts {
				problems = append(problems, Problem{Code: CodeTooMany, Message: fmt.Sprintf("more than %d contract files", maxContracts)})
				return fs.SkipAll
			}
			c, ps, err := loadFile(fsys, p, name, d)
			if err != nil {
				return err
			}
			problems = append(problems, ps...)
			if c != nil {
				contracts = append(contracts, c)
			}
		case strings.EqualFold(d.Name(), FileName) || strings.EqualFold(d.Name(), misnamedFile):
			problems = append(problems, Problem{File: name, Code: CodeMisnamed, Message: "rename to " + FileName})
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("load contracts: %w", err)
	}
	if len(problems) > 0 {
		return nil, newValidationError(problems)
	}
	set, err := NewSet(revision, contracts...)
	if err != nil {
		return nil, fmt.Errorf("load contracts: %w", err)
	}
	return set, nil
}

// foreignTree handles a .git entry. The root's own .git is skipped. Below the
// root it is a problem, because skipping a contract can only loosen access.
func foreignTree(name string, d fs.DirEntry) ([]Problem, error) {
	var ps []Problem
	if name != ".git" {
		ps = []Problem{{File: name, Code: CodeForeignTree, Message: foreignTreeMessage}}
	}
	if d.IsDir() {
		return ps, fs.SkipDir
	}
	return ps, nil
}

// loadFile reads and parses one contract file. Contract problems come back as
// Problems; only I/O failures are errors.
func loadFile(fsys fs.FS, p *Parser, name string, d fs.DirEntry) (*Contract, []Problem, error) {
	one := func(code Code, msg string) (*Contract, []Problem, error) {
		return nil, []Problem{{File: name, Code: code, Message: msg}}, nil
	}
	typ := d.Type()
	if typ&fs.ModeSymlink != 0 {
		return one(CodeSymlink, "contract file must not be a symlink")
	}
	if !typ.IsRegular() {
		return one(CodeNotRegular, "contract file must be a regular file")
	}
	f, err := fsys.Open(name)
	if err != nil {
		return nil, nil, fmt.Errorf("open %q: %w", name, err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, nil, fmt.Errorf("stat %q: %w", name, err)
	}
	if !info.Mode().IsRegular() {
		return one(CodeNotRegular, "contract file must be a regular file")
	}
	data, err := io.ReadAll(io.LimitReader(f, MaxFileSize+1))
	if err != nil {
		return nil, nil, fmt.Errorf("read %q: %w", name, err)
	}
	if len(data) > MaxFileSize {
		return one(CodeTooLarge, fmt.Sprintf("contract exceeds %d bytes", MaxFileSize))
	}
	dir := path.Dir(name)
	if dir == "." {
		dir = ""
	}
	if dir != "" {
		if err := pathglob.ValidatePath(dir); err != nil {
			return one(CodeInvalidPath, sanitize(err.Error()))
		}
	}
	c, ps := p.parse(dir, data)
	return c, ps, nil
}
