// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

package fake

import (
	"context"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/elliott-davis/lightsout/internal/forge"
)

const typeLabelPrefix = "type:"

func cloneIssue(i *forge.Issue) forge.Issue {
	c := *i
	c.Labels = slices.Clone(i.Labels)
	return c
}

func (f *Forge) issue(r *repoRec, number int) (*forge.Issue, error) {
	node, ok := r.issues[number]
	if !ok {
		return nil, fmt.Errorf("issue %s#%d: %w", r.id, number, forge.ErrNotFound)
	}
	return f.issues[node], nil
}

// GetIssue implements [forge.IssueReader]. After a transfer the old number is ErrNotFound.
func (f *Forge) GetIssue(ctx context.Context, repo forge.RepoID, number int) (forge.Issue, error) {
	release, err := f.acquire(ctx)
	if err != nil {
		return forge.Issue{}, err
	}
	defer release()
	r, err := f.repo(repo)
	if err != nil {
		return forge.Issue{}, err
	}
	i, err := f.issue(r, number)
	if err != nil {
		return forge.Issue{}, err
	}
	return cloneIssue(i), nil
}

// GetIssueByNodeID implements [forge.IssueReader]. The node ID survives a transfer.
func (f *Forge) GetIssueByNodeID(ctx context.Context, nodeID string) (forge.Issue, error) {
	release, err := f.acquire(ctx)
	if err != nil {
		return forge.Issue{}, err
	}
	defer release()
	i, ok := f.issues[nodeID]
	if !ok {
		return forge.Issue{}, fmt.Errorf("issue node %q: %w", nodeID, forge.ErrNotFound)
	}
	return cloneIssue(i), nil
}

// setType records an issue type natively or, on a repo without issue types, as a "type:<t>" label.
func (r *repoRec) setType(i *forge.Issue, t forge.IssueType) forge.TypeMechanism {
	if r.issueTypes {
		i.Type = t
		return forge.TypeNative
	}
	i.Labels = slices.DeleteFunc(i.Labels, func(l string) bool { return strings.HasPrefix(l, typeLabelPrefix) })
	i.Labels = append(i.Labels, typeLabelPrefix+string(t))
	return forge.TypeLabel
}

func (f *Forge) newIssue(r *repoRec, author forge.Actor, title, body string) *forge.Issue {
	n := r.nextNumber
	r.nextNumber++
	return f.registerIssue(r, n, author, title, body)
}

// registerIssue creates the issue record of number n. A pull request is an issue of the same number, as in
// GitHub's issues API, so labels and types work on it.
func (f *Forge) registerIssue(r *repoRec, n int, author forge.Actor, title, body string) *forge.Issue {
	now := f.clock()
	i := &forge.Issue{
		Repo: r.id, Number: n, NodeID: fmt.Sprintf("I_%d", f.next()), Author: author, Title: title, Body: body,
		State: forge.IssueOpen, Created: now, Updated: now, Edit: forge.EditOriginal,
	}
	f.issues[i.NodeID] = i
	r.issues[n] = i.NodeID
	return i
}

// CreateIssue implements [forge.IssueWriter], idempotent on (repo, key). Keys are per repo and follow the issue
// across a transfer, so a retry returns the issue wherever it lives now.
func (f *Forge) CreateIssue(ctx context.Context, in forge.NewIssue, key string) (forge.Issue, error) {
	release, err := f.acquire(ctx)
	if err != nil {
		return forge.Issue{}, err
	}
	defer release()
	r, err := f.repo(in.Repo)
	if err != nil {
		return forge.Issue{}, err
	}
	if key != "" {
		if node, ok := r.keys[key]; ok {
			return cloneIssue(f.issues[node]), nil
		}
	}
	i := f.newIssue(r, f.factory, in.Title, in.Body)
	i.Labels = slices.Clone(in.Labels)
	if in.Type != "" {
		r.setType(i, in.Type)
	}
	if in.Parent != 0 {
		if err := f.link(r, in.Parent, i.Number); err != nil {
			delete(r.issues, i.Number)
			delete(f.issues, i.NodeID)
			return forge.Issue{}, err
		}
	}
	if key != "" {
		r.keys[key] = i.NodeID
	}
	return cloneIssue(i), nil
}

// AddIssue opens an issue authored by any actor, such as a human.
func (f *Forge) AddIssue(ctx context.Context, repo forge.RepoID, author forge.Actor, title, body string) (forge.Issue, error) {
	release, err := f.acquire(ctx)
	if err != nil {
		return forge.Issue{}, err
	}
	defer release()
	r, err := f.repo(repo)
	if err != nil {
		return forge.Issue{}, err
	}
	return cloneIssue(f.newIssue(r, author, title, body)), nil
}

// EditIssue changes an issue's body as its author would, and marks it edited.
func (f *Forge) EditIssue(ctx context.Context, repo forge.RepoID, number int, body string) error {
	release, err := f.acquire(ctx)
	if err != nil {
		return err
	}
	defer release()
	r, err := f.repo(repo)
	if err != nil {
		return err
	}
	i, err := f.issue(r, number)
	if err != nil {
		return err
	}
	i.Body, i.Edit, i.Updated = body, forge.EditEdited, f.clock()
	return nil
}

func (f *Forge) mutate(ctx context.Context, repo forge.RepoID, number int, fn func(*repoRec, *forge.Issue) error) error {
	release, err := f.acquire(ctx)
	if err != nil {
		return err
	}
	defer release()
	r, err := f.repo(repo)
	if err != nil {
		return err
	}
	i, err := f.issue(r, number)
	if err != nil {
		return err
	}
	if err := fn(r, i); err != nil {
		return err
	}
	i.Updated = f.clock()
	return nil
}

// UpdateIssueBody implements [forge.IssueWriter]. The issue then reads as edited.
func (f *Forge) UpdateIssueBody(ctx context.Context, repo forge.RepoID, number int, body string) error {
	return f.mutate(ctx, repo, number, func(_ *repoRec, i *forge.Issue) error {
		i.Body, i.Edit = body, forge.EditEdited
		return nil
	})
}

// SetIssueType implements [forge.IssueWriter]. A repo without issue types gets a "type:<t>" label instead.
func (f *Forge) SetIssueType(ctx context.Context, repo forge.RepoID, number int, t forge.IssueType) (forge.TypeMechanism, error) {
	mech := forge.TypeMechanismUnknown
	err := f.mutate(ctx, repo, number, func(r *repoRec, i *forge.Issue) error {
		mech = r.setType(i, t)
		return nil
	})
	return mech, err
}

// AddLabels implements [forge.IssueWriter]. Adding a label twice keeps one.
func (f *Forge) AddLabels(ctx context.Context, repo forge.RepoID, number int, labels ...string) error {
	return f.mutate(ctx, repo, number, func(_ *repoRec, i *forge.Issue) error {
		for _, l := range labels {
			if !slices.Contains(i.Labels, l) {
				i.Labels = append(i.Labels, l)
			}
		}
		return nil
	})
}

// RemoveLabel implements [forge.IssueWriter].
func (f *Forge) RemoveLabel(ctx context.Context, repo forge.RepoID, number int, label string) error {
	return f.mutate(ctx, repo, number, func(_ *repoRec, i *forge.Issue) error {
		i.Labels = slices.DeleteFunc(i.Labels, func(l string) bool { return l == label })
		return nil
	})
}

// link makes child a sub-issue of parent, moving it from any previous parent. The parent link is the issue's
// Parent field, so there is nothing else to keep in step.
func (f *Forge) link(r *repoRec, parent, child int) error {
	c, err := f.issue(r, child)
	if err != nil {
		return err
	}
	if _, err := f.issue(r, parent); err != nil {
		return err
	}
	if parent == child {
		return fmt.Errorf("issue %d cannot be its own parent: %w", parent, forge.ErrInvalid)
	}
	for p, seen := parent, 0; p != 0; seen++ {
		if p == child || seen > len(r.issues) {
			return fmt.Errorf("issue %d under %d would make a cycle: %w", child, parent, forge.ErrInvalid)
		}
		pi, err := f.issue(r, p)
		if err != nil {
			return err
		}
		p = pi.Parent
	}
	c.Parent = parent
	return nil
}

// AddSubIssue implements [forge.IssueWriter]: idempotent, moves a re-parented child, rejects self-parenting and
// cycles. Both issues must be in the same repo.
func (f *Forge) AddSubIssue(ctx context.Context, repo forge.RepoID, parent, child int) error {
	release, err := f.acquire(ctx)
	if err != nil {
		return err
	}
	defer release()
	r, err := f.repo(repo)
	if err != nil {
		return err
	}
	return f.link(r, parent, child)
}

// ListSubIssues implements [forge.IssueReader], by number.
func (f *Forge) ListSubIssues(ctx context.Context, repo forge.RepoID, parent int) ([]forge.Issue, error) {
	release, err := f.acquire(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	r, err := f.repo(repo)
	if err != nil {
		return nil, err
	}
	if _, err := f.issue(r, parent); err != nil {
		return nil, err
	}
	var out []forge.Issue
	for _, node := range r.issues {
		if i := f.issues[node]; i.Parent == parent {
			out = append(out, cloneIssue(i))
		}
	}
	slices.SortFunc(out, func(a, b forge.Issue) int { return a.Number - b.Number })
	return out, nil
}

// TransferIssue moves an issue to another repo (the same repo, or a pull request, is ErrInvalid). It gets a new number there, keeps its node ID and records
// TransferredFrom. Its comments move with it, and its sub-issue links, in both directions, are removed.
func (f *Forge) TransferIssue(ctx context.Context, repo forge.RepoID, number int, to forge.RepoID) (forge.Issue, error) {
	release, err := f.acquire(ctx)
	if err != nil {
		return forge.Issue{}, err
	}
	defer release()
	from, err := f.repo(repo)
	if err != nil {
		return forge.Issue{}, err
	}
	dst, err := f.repo(to)
	if err != nil {
		return forge.Issue{}, err
	}
	if from == dst {
		return forge.Issue{}, fmt.Errorf("issue %d is already in %s: %w", number, repo, forge.ErrInvalid)
	}
	if _, isPR := from.prs[number]; isPR {
		return forge.Issue{}, fmt.Errorf("%s#%d is a pull request, which cannot be transferred: %w", repo, number, forge.ErrInvalid)
	}
	i, err := f.issue(from, number)
	if err != nil {
		return forge.Issue{}, err
	}
	for _, node := range from.issues {
		if c := f.issues[node]; c.Parent == number {
			c.Parent = 0
		}
	}
	delete(from.issues, number)
	n := dst.nextNumber
	dst.nextNumber++
	dst.issues[n] = i.NodeID
	for id, c := range from.comments {
		if c.Issue == number {
			c.Repo, c.Issue = dst.id, n
			dst.comments[id] = c
			delete(from.comments, id)
		}
	}
	i.TransferredFrom, i.Repo, i.Number, i.Parent = from.id, dst.id, n, 0
	i.Updated = f.clock()
	return cloneIssue(i), nil
}

func (f *Forge) addComment(r *repoRec, issue int, author forge.Actor, body string) (forge.Comment, error) {
	if err := f.parentExists(r, issue); err != nil {
		return forge.Comment{}, err
	}
	c := &forge.Comment{
		ID: fmt.Sprintf("c%d", f.next()), Repo: r.id, Issue: issue, Author: author, Body: body,
		Created: f.clock(), Edit: forge.EditOriginal,
	}
	r.comments[c.ID] = c
	return *c, nil
}

// parentExists checks that number is an issue or a pull request of r.
func (f *Forge) parentExists(r *repoRec, number int) error {
	if _, ok := r.issues[number]; ok {
		return nil
	}
	if _, ok := r.prs[number]; ok {
		return nil
	}
	return fmt.Errorf("issue or pull request %s#%d: %w", r.id, number, forge.ErrNotFound)
}

// CreateComment implements [forge.IssueWriter]. The author is the factory identity.
func (f *Forge) CreateComment(ctx context.Context, repo forge.RepoID, issue int, body string) (forge.Comment, error) {
	release, err := f.acquire(ctx)
	if err != nil {
		return forge.Comment{}, err
	}
	defer release()
	r, err := f.repo(repo)
	if err != nil {
		return forge.Comment{}, err
	}
	return f.addComment(r, issue, f.factory, body)
}

// AddComment adds a comment authored by any actor.
func (f *Forge) AddComment(ctx context.Context, repo forge.RepoID, issue int, author forge.Actor, body string) (forge.Comment, error) {
	release, err := f.acquire(ctx)
	if err != nil {
		return forge.Comment{}, err
	}
	defer release()
	r, err := f.repo(repo)
	if err != nil {
		return forge.Comment{}, err
	}
	return f.addComment(r, issue, author, body)
}

func (f *Forge) comment(r *repoRec, id string) (*forge.Comment, error) {
	c, ok := r.comments[id]
	if !ok {
		return nil, fmt.Errorf("comment %q: %w", id, forge.ErrNotFound)
	}
	return c, nil
}

// EditComment changes a comment's body and marks it edited.
func (f *Forge) EditComment(ctx context.Context, repo forge.RepoID, id, body string) error {
	release, err := f.acquire(ctx)
	if err != nil {
		return err
	}
	defer release()
	r, err := f.repo(repo)
	if err != nil {
		return err
	}
	c, err := f.comment(r, id)
	if err != nil {
		return err
	}
	c.Body, c.Edit = body, forge.EditEdited
	return nil
}

// DeleteComment removes a comment. Reads then return ErrNotFound, as on GitHub.
func (f *Forge) DeleteComment(ctx context.Context, repo forge.RepoID, id string) error {
	release, err := f.acquire(ctx)
	if err != nil {
		return err
	}
	defer release()
	r, err := f.repo(repo)
	if err != nil {
		return err
	}
	if _, err := f.comment(r, id); err != nil {
		return err
	}
	delete(r.comments, id)
	return nil
}

// ListComments implements [forge.IssueReader], in creation order. A missing issue or pull request is ErrNotFound.
func (f *Forge) ListComments(ctx context.Context, repo forge.RepoID, issue int) ([]forge.Comment, error) {
	release, err := f.acquire(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	err = f.incomplete("ListComments")
	if err != nil {
		return nil, err
	}
	r, err := f.repo(repo)
	if err != nil {
		return nil, err
	}
	if err := f.parentExists(r, issue); err != nil {
		return nil, err
	}
	var out []forge.Comment
	for _, c := range r.comments {
		if c.Issue == issue {
			out = append(out, *c)
		}
	}
	slices.SortFunc(out, func(a, b forge.Comment) int { return idOrder(a.ID, b.ID) })
	return out, nil
}

// GetComment implements [forge.IssueReader]. It always returns the current state.
func (f *Forge) GetComment(ctx context.Context, repo forge.RepoID, id string) (forge.Comment, error) {
	release, err := f.acquire(ctx)
	if err != nil {
		return forge.Comment{}, err
	}
	defer release()
	r, err := f.repo(repo)
	if err != nil {
		return forge.Comment{}, err
	}
	c, err := f.comment(r, id)
	if err != nil {
		return forge.Comment{}, err
	}
	return *c, nil
}

// idOrder orders IDs of the form <letter><number> by their number.
func idOrder(a, b string) int {
	x, _ := strconv.Atoi(a[1:])
	y, _ := strconv.Atoi(b[1:])
	return x - y
}
