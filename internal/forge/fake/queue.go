// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

package fake

import (
	"context"
	"fmt"
	"slices"

	"github.com/elliott-davis/lightsout/internal/forge"
	"github.com/elliott-davis/lightsout/internal/forge/gittree"
)

// queueRef is the gh-readonly-queue ref of a member's candidate commit.
func queueRef(base string, m forge.QueueMember) string {
	return fmt.Sprintf("refs/heads/gh-readonly-queue/%s/pr-%d-%s", base, m.PR, m.HeadSHA)
}

// dropRefs deletes the candidate refs of members of g, as GitHub does once a group is done.
func (r *repoRec) dropRefs(g *forge.MergeGroup, members []forge.QueueMember) {
	for _, m := range members {
		delete(r.refs, queueRef(r.groupBase[g.CandidateSHA], m))
	}
}

// failGroup fails g. Its members other than except, who are in the group, go back to queued.
func (r *repoRec) failGroup(g *forge.MergeGroup, except int) {
	g.State = forge.GroupFailed
	r.dropRefs(g, g.Members)
	for _, m := range g.Members {
		if o, ok := r.queue[m.PR]; ok && m.PR != except && o.State == forge.QueueInGroup {
			o.State = forge.QueueQueued
		}
	}
}

// removeFromQueue takes a pull request out of the queue, as GitHub does when its head moves, it is retargeted or it
// is dequeued. A group it was in fails, and the group's other members go back to queued.
func (r *repoRec) removeFromQueue(pr int) {
	e, ok := r.queue[pr]
	if !ok || (e.State != forge.QueueQueued && e.State != forge.QueueInGroup) {
		return
	}
	e.State = forge.QueueRemoved
	for _, g := range r.groups {
		if g.State == forge.GroupActive && slices.ContainsFunc(g.Members, func(m forge.QueueMember) bool { return m.PR == pr }) {
			r.failGroup(g, pr)
		}
	}
}

// Enqueue implements [forge.MergeQueue]. The pull request must be open and its head must be expectedHeadSHA, or it
// is ErrConflict, and so is a draft. Enqueueing a pull request that is already queued returns its entry.
func (f *Forge) Enqueue(ctx context.Context, repo forge.RepoID, pr int, expectedHeadSHA string) (forge.QueueEntry, error) {
	release, err := f.acquire(ctx)
	if err != nil {
		return forge.QueueEntry{}, err
	}
	defer release()
	r, err := f.repo(repo)
	if err != nil {
		return forge.QueueEntry{}, err
	}
	p, ok := r.prs[pr]
	if !ok {
		return forge.QueueEntry{}, fmt.Errorf("pull request %s#%d: %w", repo, pr, forge.ErrNotFound)
	}
	if p.State != forge.PROpen || p.Draft {
		return forge.QueueEntry{}, fmt.Errorf("pull request %s#%d is %s (draft: %t): %w", repo, pr, p.State, p.Draft, forge.ErrConflict)
	}
	if p.HeadSHA != expectedHeadSHA {
		return forge.QueueEntry{}, fmt.Errorf("pull request %s#%d head is %s, not %s: %w", repo, pr, p.HeadSHA, expectedHeadSHA, forge.ErrConflict)
	}
	if e, ok := r.queue[pr]; ok && e.State != forge.QueueRemoved && e.State != forge.QueueMerged {
		return *e, nil
	}
	e := &forge.QueueEntry{Repo: r.id, PR: pr, HeadSHA: p.HeadSHA, State: forge.QueueQueued}
	r.queue[pr] = e
	return *e, nil
}

// Dequeue implements [forge.MergeQueue]. Dequeueing a grouped pull request removes it and fails its group, and
// dequeueing an entry that is already removed or merged is ErrInvalid.
func (f *Forge) Dequeue(ctx context.Context, repo forge.RepoID, pr int) error {
	release, err := f.acquire(ctx)
	if err != nil {
		return err
	}
	defer release()
	r, err := f.repo(repo)
	if err != nil {
		return err
	}
	e, ok := r.queue[pr]
	if !ok {
		return fmt.Errorf("queue entry %s#%d: %w", repo, pr, forge.ErrNotFound)
	}
	if e.State == forge.QueueRemoved || e.State == forge.QueueMerged {
		return fmt.Errorf("queue entry %s#%d is already %s: %w", repo, pr, e.State, forge.ErrInvalid)
	}
	r.removeFromQueue(pr)
	return nil
}

// QueueEntries implements [forge.MergeQueue], ordered by pull request number.
func (f *Forge) QueueEntries(ctx context.Context, repo forge.RepoID) ([]forge.QueueEntry, error) {
	release, err := f.acquire(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	r, err := f.repo(repo)
	if err != nil {
		return nil, err
	}
	out := make([]forge.QueueEntry, 0, len(r.queue))
	for _, e := range r.queue {
		out = append(out, *e)
	}
	slices.SortFunc(out, func(a, b forge.QueueEntry) int { return a.PR - b.PR })
	return out, nil
}

func cloneGroup(g *forge.MergeGroup) forge.MergeGroup {
	c := *g
	c.Members = slices.Clone(g.Members)
	return c
}

// MergeGroups implements [forge.MergeQueue], in creation order.
func (f *Forge) MergeGroups(ctx context.Context, repo forge.RepoID) ([]forge.MergeGroup, error) {
	release, err := f.acquire(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	r, err := f.repo(repo)
	if err != nil {
		return nil, err
	}
	out := make([]forge.MergeGroup, 0, len(r.groups))
	for _, g := range r.groups {
		out = append(out, cloneGroup(g))
	}
	return out, nil
}

// ObservedMerges implements [forge.MergeQueue].
func (f *Forge) ObservedMerges(ctx context.Context, repo forge.RepoID) ([]forge.ObservedMerge, error) {
	release, err := f.acquire(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	r, err := f.repo(repo)
	if err != nil {
		return nil, err
	}
	return slices.Clone(r.merges), nil
}

// chain builds the candidate commits for members, each a two-parent merge of the previous candidate (prev for the
// first) and the member's head, with the tree the caller supplied for it, and a gh-readonly-queue ref. The trees are
// validated before anything is stored.
func (f *Forge) chain(r *repoRec, base, prev string, members []forge.QueueMember, trees [][]gittree.Entry) ([]forge.QueueMember, error) {
	for _, t := range trees {
		if err := checkEntries(t); err != nil {
			return nil, fmt.Errorf("candidate tree: %w", err)
		}
	}
	out := slices.Clone(members)
	for i := range out {
		sha := f.addCommit(r, []string{prev, out[i].HeadSHA}, fmt.Sprintf("Merge pull request #%d", out[i].PR), f.sig(f.factory), copyEntries(trees[i]))
		r.refs[queueRef(base, out[i])] = sha
		out[i].CandidateSHA = sha
		prev = sha
	}
	return out, nil
}

// FormGroup groups queued pull requests of one base branch into a merge group. The caller supplies one cumulative
// tree per member, and each becomes a real candidate commit: candidate_i is a two-parent merge of candidate_(i-1)
// (the base's head for the first) and member i's head, so Tree and Compare work at every candidate. The group's
// CandidateSHA is the last member's. An empty or duplicate member list, or a different number of trees, is
// ErrInvalid, and every member must be queued.
func (f *Forge) FormGroup(ctx context.Context, repo forge.RepoID, prs []int, trees [][]gittree.Entry) (forge.MergeGroup, error) {
	release, err := f.acquire(ctx)
	if err != nil {
		return forge.MergeGroup{}, err
	}
	defer release()
	r, err := f.repo(repo)
	if err != nil {
		return forge.MergeGroup{}, err
	}
	if len(prs) == 0 || len(trees) != len(prs) {
		return forge.MergeGroup{}, fmt.Errorf("a merge group needs one tree per member (%d members, %d trees): %w", len(prs), len(trees), forge.ErrInvalid)
	}
	var members []forge.QueueMember
	seen := map[int]bool{}
	bb := ""
	for _, n := range prs {
		if seen[n] {
			return forge.MergeGroup{}, fmt.Errorf("pull request %d listed twice: %w", n, forge.ErrInvalid)
		}
		seen[n] = true
		e, ok := r.queue[n]
		if !ok || e.State != forge.QueueQueued {
			return forge.MergeGroup{}, fmt.Errorf("pull request %s#%d is not queued: %w", repo, n, forge.ErrConflict)
		}
		if p := r.prs[n]; bb == "" {
			bb = p.BaseRef
		} else if p.BaseRef != bb {
			return forge.MergeGroup{}, fmt.Errorf("pull request %d targets %q, not %q: %w", n, p.BaseRef, bb, forge.ErrInvalid)
		}
		members = append(members, forge.QueueMember{PR: n, HeadSHA: e.HeadSHA})
	}
	base, ok := r.refs["refs/heads/"+bb]
	if !ok {
		return forge.MergeGroup{}, fmt.Errorf("base branch %q: %w", bb, forge.ErrNotFound)
	}
	built, err := f.chain(r, bb, base, members, trees)
	if err != nil {
		return forge.MergeGroup{}, err
	}
	g := &forge.MergeGroup{
		Repo: r.id, CandidateSHA: built[len(built)-1].CandidateSHA, BaseSHA: base, Members: built, State: forge.GroupActive,
	}
	r.groups = append(r.groups, g)
	r.groupBase[g.CandidateSHA] = bb
	for _, m := range built {
		r.queue[m.PR].State = forge.QueueInGroup
	}
	return cloneGroup(g), nil
}

// EjectMember removes a pull request from the active group with the given candidate SHA. The group fails. Members
// before the ejected one keep their candidates, and the members after it are rebuilt as a new chain from the
// caller's trees, one per rebuilt member, so the new group has a new candidate SHA, which is returned. Ejecting the
// last remaining member fails the group and creates no new one: the result is the zero MergeGroup.
func (f *Forge) EjectMember(ctx context.Context, repo forge.RepoID, candidateSHA string, pr int, suffixTrees [][]gittree.Entry) (forge.MergeGroup, error) {
	release, err := f.acquire(ctx)
	if err != nil {
		return forge.MergeGroup{}, err
	}
	defer release()
	r, err := f.repo(repo)
	if err != nil {
		return forge.MergeGroup{}, err
	}
	for _, old := range r.groups {
		if old.CandidateSHA != candidateSHA || old.State != forge.GroupActive {
			continue
		}
		idx := slices.IndexFunc(old.Members, func(m forge.QueueMember) bool { return m.PR == pr })
		if idx < 0 {
			return forge.MergeGroup{}, fmt.Errorf("pull request %d is not in group %s: %w", pr, candidateSHA, forge.ErrNotFound)
		}
		prefix := slices.Clone(old.Members[:idx])
		suffix := slices.Clone(old.Members[idx+1:])
		if len(suffix) != len(suffixTrees) {
			return forge.MergeGroup{}, fmt.Errorf("%d members to rebuild, %d trees: %w", len(suffix), len(suffixTrees), forge.ErrInvalid)
		}
		bb := r.groupBase[old.CandidateSHA]
		prev := old.BaseSHA
		if len(prefix) > 0 {
			prev = prefix[len(prefix)-1].CandidateSHA
		}
		rebuilt, err := f.chain(r, bb, prev, suffix, suffixTrees)
		if err != nil {
			return forge.MergeGroup{}, err
		}
		old.State = forge.GroupFailed
		r.queue[pr].State = forge.QueueRemoved
		delete(r.refs, queueRef(bb, old.Members[idx])) // the others' refs live on in the new group
		members := slices.Concat(prefix, rebuilt)
		if len(members) == 0 {
			return forge.MergeGroup{}, nil
		}
		g := &forge.MergeGroup{
			Repo: r.id, CandidateSHA: members[len(members)-1].CandidateSHA, BaseSHA: old.BaseSHA, Members: members, State: forge.GroupActive,
		}
		r.groups = append(r.groups, g)
		r.groupBase[g.CandidateSHA] = bb
		return cloneGroup(g), nil
	}
	return forge.MergeGroup{}, fmt.Errorf("active group %s: %w", candidateSHA, forge.ErrNotFound)
}

// checkMerge checks that a merge is consistent with the repo: the base only moves forward, the pull request's head
// is part of what merged, and a merge of a group's candidate is of a member that candidate includes.
func (r *repoRec) checkMerge(p *forge.PullRequest, g *forge.MergeGroup, m forge.ObservedMerge) error {
	anc := r.ancestors(m.MergedCommit)
	head := r.refs["refs/heads/"+p.BaseRef]
	if m.MergedCommit == head || !anc[head] {
		return fmt.Errorf("merged commit %s does not move %s forward from %s: %w", m.MergedCommit, p.BaseRef, head, forge.ErrInvalid)
	}
	if !anc[p.HeadSHA] {
		return fmt.Errorf("merged commit %s does not contain the head %s of pull request %d: %w", m.MergedCommit, p.HeadSHA, m.PR, forge.ErrInvalid)
	}
	if g == nil {
		return nil
	}
	if i := slices.IndexFunc(g.Members, func(q forge.QueueMember) bool { return q.CandidateSHA == m.MergedCommit }); i >= 0 &&
		!slices.ContainsFunc(g.Members[:i+1], func(q forge.QueueMember) bool { return q.PR == m.PR }) {
		return fmt.Errorf("pull request %d is not in the members merged by candidate %s: %w", m.PR, m.MergedCommit, forge.ErrInvalid)
	}
	return nil
}

// landedMembers returns the members a merge lands. A merge that lands one of the group's candidate commits lands
// every member up to that candidate, as GitHub does when it fast-forwards the base to a merge group's commit.
// Otherwise it lands only the recorded pull request.
func landedMembers(g *forge.MergeGroup, m forge.ObservedMerge) []forge.QueueMember {
	own := forge.QueueMember{PR: m.PR, HeadSHA: m.HeadSHA, CandidateSHA: m.MergedCommit}
	if g == nil {
		return []forge.QueueMember{own}
	}
	i := slices.IndexFunc(g.Members, func(q forge.QueueMember) bool { return q.CandidateSHA == m.MergedCommit })
	if i < 0 {
		return []forge.QueueMember{own}
	}
	landed := slices.Clone(g.Members[:i+1])
	if !slices.ContainsFunc(landed, func(x forge.QueueMember) bool { return x.PR == m.PR }) {
		landed = append(landed, own)
	}
	return landed
}

// RecordMerge records a merge the forge performed. The pull request must be open and its head must be m.HeadSHA
// (ErrConflict), and MergedCommit must exist (ErrNotFound). The base branch moves to MergedCommit, the pull request
// and its queue entry become merged, and the group it was in settles: merged when every member has merged (landing
// the group's last candidate merges them all, each with its own observed merge), otherwise failed with the
// remaining members back in the queue. Any other active group on that base fails, because
// the base moved.
func (f *Forge) RecordMerge(ctx context.Context, repo forge.RepoID, m forge.ObservedMerge) error {
	release, err := f.acquire(ctx)
	if err != nil {
		return err
	}
	defer release()
	r, err := f.repo(repo)
	if err != nil {
		return err
	}
	p, ok := r.prs[m.PR]
	if !ok {
		return fmt.Errorf("pull request %s#%d: %w", repo, m.PR, forge.ErrNotFound)
	}
	if p.State != forge.PROpen || p.HeadSHA != m.HeadSHA {
		return fmt.Errorf("pull request %s#%d is %s at %s, not open at %s: %w", repo, m.PR, p.State, p.HeadSHA, m.HeadSHA, forge.ErrConflict)
	}
	if _, ok := r.commits[m.MergedCommit]; !ok {
		return fmt.Errorf("merged commit %q: %w", m.MergedCommit, forge.ErrNotFound)
	}
	var settling *forge.MergeGroup
	for _, g := range r.groups {
		if g.State == forge.GroupActive && slices.ContainsFunc(g.Members, func(q forge.QueueMember) bool { return q.PR == m.PR }) {
			settling = g
		}
	}
	err = r.checkMerge(p, settling, m)
	if err != nil {
		return err
	}
	f.moveRefOpt(r, "refs/heads/"+p.BaseRef, m.MergedCommit, true)
	for _, g := range r.groups {
		if g != settling && g.State == forge.GroupActive && r.groupBase[g.CandidateSHA] == p.BaseRef {
			r.failGroup(g, 0)
		}
	}
	now := f.clock()
	for _, q := range landedMembers(settling, m) {
		om := forge.ObservedMerge{Repo: r.id, PR: q.PR, HeadSHA: q.HeadSHA, MergedCommit: q.CandidateSHA, MergedBy: m.MergedBy, At: now}
		if q.PR == m.PR {
			om = m
			om.Repo = r.id
			if om.At.IsZero() {
				om.At = now
			}
		}
		r.merges = append(r.merges, om)
		r.prs[q.PR].State = forge.PRMerged
		if e, ok := r.queue[q.PR]; ok {
			e.State = forge.QueueMerged
		}
	}
	if settling != nil {
		if slices.ContainsFunc(settling.Members, func(q forge.QueueMember) bool { return r.queue[q.PR].State != forge.QueueMerged }) {
			r.failGroup(settling, 0)
		} else {
			settling.State = forge.GroupMerged
			r.dropRefs(settling, settling.Members)
		}
	}
	return nil
}
