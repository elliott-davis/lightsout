// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

package fake

import (
	"bytes"
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/elliott-davis/lightsout/internal/forge"
	"github.com/elliott-davis/lightsout/internal/forge/gittree"
)

// DeclareRename records that, in the comparison ending at headSHA, the file at from became the file at to. The
// fake never guesses similarity: Compare reports a rename only for a declared pair that it also sees as a
// removal plus an addition.
func (f *Forge) DeclareRename(ctx context.Context, repo forge.RepoID, headSHA, from, to string) error {
	release, err := f.acquire(ctx)
	if err != nil {
		return err
	}
	defer release()
	r, err := f.repo(repo)
	if err != nil {
		return err
	}
	if _, ok := r.commits[headSHA]; !ok {
		return fmt.Errorf("commit %s: %w", headSHA, forge.ErrNotFound)
	}
	r.renames[headSHA] = append(r.renames[headSHA], rename{from: from, to: to})
	return nil
}

func files(c *commit) map[string]gittree.Entry {
	m := make(map[string]gittree.Entry, len(c.entries))
	for _, e := range c.entries {
		if e.Mode != gittree.ModeTree {
			m[e.Path] = e
		}
	}
	return m
}

// sameContent decides equality by bytes, never by a stored SHA, so a no-op rewrite is not a modification. A
// gitlink has no bytes: its commit SHA is its content.
func sameContent(a, b gittree.Entry) bool {
	if a.Mode == gittree.ModeGitlink || b.Mode == gittree.ModeGitlink {
		return a.Mode == b.Mode && a.SHA == b.SHA
	}
	return bytes.Equal(a.Data, b.Data)
}

// ancestors returns sha and every commit reachable from it.
func (r *repoRec) ancestors(sha string) map[string]bool {
	anc := map[string]bool{}
	for queue := []string{sha}; len(queue) > 0; queue = queue[1:] {
		if anc[queue[0]] {
			continue
		}
		anc[queue[0]] = true
		queue = append(queue, r.commits[queue[0]].parents...)
	}
	return anc
}

// mergeBase computes git's best common ancestor: the common ancestors of a and b, minus any that is an ancestor of
// another. A criss-cross history can leave several, and the one whose SHA sorts first is used, so the answer is
// deterministic. It reports false when the commits share no history.
func (r *repoRec) mergeBase(a, b string) (string, bool) {
	ancB := r.ancestors(b)
	var common []string
	for sha := range r.ancestors(a) {
		if ancB[sha] {
			common = append(common, sha)
		}
	}
	dominated := map[string]bool{}
	for _, c := range common {
		for sha := range r.ancestors(c) {
			if sha != c {
				dominated[sha] = true
			}
		}
	}
	best := ""
	for _, c := range common {
		if !dominated[c] && (best == "" || c < best) {
			best = c
		}
	}
	return best, best != ""
}

// Compare implements [forge.DiffReader]. It diffs the merge base of baseSHA and headSHA against headSHA, as
// GitHub's three-dot compare does, from the stored trees. With no common ancestor it is ErrNotFound.
func (f *Forge) Compare(ctx context.Context, repo forge.RepoID, baseSHA, headSHA string) ([]forge.ChangedFile, error) {
	release, err := f.acquire(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	err = f.incomplete("Compare")
	if err != nil {
		return nil, err
	}
	r, err := f.repo(repo)
	if err != nil {
		return nil, err
	}
	if _, ok := r.commits[baseSHA]; !ok {
		return nil, fmt.Errorf("commit %s: %w", baseSHA, forge.ErrNotFound)
	}
	head, ok := r.commits[headSHA]
	if !ok {
		return nil, fmt.Errorf("commit %s: %w", headSHA, forge.ErrNotFound)
	}
	mb, ok := r.mergeBase(baseSHA, headSHA)
	if !ok {
		return nil, fmt.Errorf("commits %s and %s have no common ancestor: %w", baseSHA, headSHA, forge.ErrNotFound)
	}
	base := r.commits[mb]
	old, cur := files(base), files(head)
	byPath := map[string]forge.ChangedFile{}
	for p, n := range cur {
		o, existed := old[p]
		switch {
		case !existed:
			byPath[p] = forge.ChangedFile{Path: p, Status: forge.FileAdded, NewMode: n.Mode.FileMode()}
		case !sameContent(o, n):
			byPath[p] = forge.ChangedFile{Path: p, Status: forge.FileModified, OldMode: o.Mode.FileMode(), NewMode: n.Mode.FileMode()}
		case o.Mode != n.Mode:
			byPath[p] = forge.ChangedFile{Path: p, Status: forge.FileModeChanged, OldMode: o.Mode.FileMode(), NewMode: n.Mode.FileMode()}
		}
	}
	for p, o := range old {
		if _, still := cur[p]; !still {
			byPath[p] = forge.ChangedFile{Path: p, Status: forge.FileRemoved, OldMode: o.Mode.FileMode()}
		}
	}
	for _, rn := range r.renames[headSHA] {
		from, gone := byPath[rn.from]
		to, added := byPath[rn.to]
		if gone && added && from.Status == forge.FileRemoved && to.Status == forge.FileAdded {
			delete(byPath, rn.from)
			byPath[rn.to] = forge.ChangedFile{
				Path: rn.to, PreviousPath: rn.from, Status: forge.FileRenamed, OldMode: from.OldMode, NewMode: to.NewMode,
			}
		}
	}
	out := make([]forge.ChangedFile, 0, len(byPath))
	for _, c := range byPath {
		out = append(out, c)
	}
	slices.SortFunc(out, func(a, b forge.ChangedFile) int { return strings.Compare(a.Path, b.Path) })
	return out, nil
}

// Commits implements [forge.DiffReader]: every commit reachable from headSHA through any parent and not
// reachable from baseSHA, oldest first (parents before children). Commits with no common ancestor are ErrNotFound.
func (f *Forge) Commits(ctx context.Context, repo forge.RepoID, baseSHA, headSHA string) ([]forge.Commit, error) {
	release, err := f.acquire(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	err = f.incomplete("Commits")
	if err != nil {
		return nil, err
	}
	r, err := f.repo(repo)
	if err != nil {
		return nil, err
	}
	for _, sha := range []string{baseSHA, headSHA} {
		if _, ok := r.commits[sha]; !ok {
			return nil, fmt.Errorf("commit %s: %w", sha, forge.ErrNotFound)
		}
	}
	if _, ok := r.mergeBase(baseSHA, headSHA); !ok {
		return nil, fmt.Errorf("commits %s and %s have no common ancestor: %w", baseSHA, headSHA, forge.ErrNotFound)
	}
	excluded := map[string]bool{}
	for queue := []string{baseSHA}; len(queue) > 0; queue = queue[1:] {
		if excluded[queue[0]] {
			continue
		}
		excluded[queue[0]] = true
		queue = append(queue, r.commits[queue[0]].parents...)
	}
	var out []forge.Commit
	seen := map[string]bool{}
	var visit func(sha string)
	visit = func(sha string) {
		if seen[sha] || excluded[sha] {
			return
		}
		seen[sha] = true
		c := r.commits[sha]
		for _, p := range c.parents {
			visit(p)
		}
		out = append(out, forge.Commit{
			SHA: c.sha, Parents: slices.Clone(c.parents), Author: c.author, Committer: c.committer, Message: c.message,
		})
	}
	visit(headSHA)
	return out, nil
}
