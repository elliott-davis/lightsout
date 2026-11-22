// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

package fake

import (
	"context"
	"fmt"
	"slices"

	"github.com/elliott-davis/lightsout/internal/forge"
)

// AddPullRequest opens a pull request in repo from headRef in headRepo (the same repo, or a fork made with
// [Forge.ForkRepo]) to baseRef (branch names or full refs). It is pinned to the SHAs they resolve to now, and
// follows the head branch after that. The head's commits become readable in repo. A head and base with no common
// history are ErrInvalid, as GitHub's 422. The pull request is also an issue of the same number.
func (f *Forge) AddPullRequest(ctx context.Context, repo forge.RepoID, author forge.Actor, headRepo forge.RepoID, headRef, baseRef string) (forge.PullRequest, error) {
	release, err := f.acquire(ctx)
	if err != nil {
		return forge.PullRequest{}, err
	}
	defer release()
	r, err := f.repo(repo)
	if err != nil {
		return forge.PullRequest{}, err
	}
	hr, err := f.repo(headRepo)
	if err != nil {
		return forge.PullRequest{}, err
	}
	head, err := hr.resolve(headRef)
	if err != nil {
		return forge.PullRequest{}, err
	}
	base, err := r.resolve(baseRef)
	if err != nil {
		return forge.PullRequest{}, err
	}
	copyCommits(r, hr, head)
	if _, ok := r.mergeBase(base, head); !ok {
		return forge.PullRequest{}, fmt.Errorf("%s and %s have no common history: %w", baseRef, headRef, forge.ErrInvalid)
	}
	n := r.nextNumber
	r.nextNumber++
	f.registerIssue(r, n, author, "", "")
	r.headHist[n] = map[string]bool{head: true}
	pr := &forge.PullRequest{
		Repo: r.id, Number: n, Author: author, HeadRepo: hr.id, HeadRef: shortBranch(headRef), HeadSHA: head,
		BaseRef: shortBranch(baseRef), BaseSHA: base, State: forge.PROpen,
	}
	r.prs[n] = pr
	return *pr, nil
}

// ClosePullRequest closes an open pull request (any other state is ErrConflict). It leaves the queue and stops following its head branch.
func (f *Forge) ClosePullRequest(ctx context.Context, repo forge.RepoID, number int) error {
	return f.withPR(ctx, repo, number, func(r *repoRec, pr *forge.PullRequest) error {
		if pr.State != forge.PROpen {
			return fmt.Errorf("pull request %s#%d is %s: %w", pr.Repo, number, pr.State, forge.ErrConflict)
		}
		pr.State = forge.PRClosed
		r.removeFromQueue(number)
		return nil
	})
}

// SetPullRequestDraft marks a pull request as a draft or ready for review. A draft cannot be enqueued, and
// converting a queued pull request to a draft removes it from the queue, as GitHub does.
func (f *Forge) SetPullRequestDraft(ctx context.Context, repo forge.RepoID, number int, draft bool) error {
	return f.withPR(ctx, repo, number, func(r *repoRec, pr *forge.PullRequest) error {
		pr.Draft = draft
		if draft {
			r.removeFromQueue(number)
		}
		return nil
	})
}

// RetargetPullRequest changes a pull request's base branch. A queued one leaves the queue.
func (f *Forge) RetargetPullRequest(ctx context.Context, repo forge.RepoID, number int, newBase string) error {
	return f.withPR(ctx, repo, number, func(r *repoRec, pr *forge.PullRequest) error {
		sha, err := r.resolve(newBase)
		if err != nil {
			return err
		}
		pr.BaseRef, pr.BaseSHA = shortBranch(newBase), sha
		r.removeFromQueue(number)
		return nil
	})
}

func (f *Forge) withPR(ctx context.Context, repo forge.RepoID, number int, fn func(*repoRec, *forge.PullRequest) error) error {
	release, err := f.acquire(ctx)
	if err != nil {
		return err
	}
	defer release()
	r, err := f.repo(repo)
	if err != nil {
		return err
	}
	pr, ok := r.prs[number]
	if !ok {
		return fmt.Errorf("pull request %s#%d: %w", repo, number, forge.ErrNotFound)
	}
	return fn(r, pr)
}

// SetPullRequestHead moves the pull request's head branch to another commit of the head repo, as a push would.
// Every pull request on that branch follows it, and a queued one leaves the queue.
func (f *Forge) SetPullRequestHead(ctx context.Context, repo forge.RepoID, number int, sha string) error {
	release, err := f.acquire(ctx)
	if err != nil {
		return err
	}
	defer release()
	r, err := f.repo(repo)
	if err != nil {
		return err
	}
	pr, ok := r.prs[number]
	if !ok {
		return fmt.Errorf("pull request %s#%d: %w", repo, number, forge.ErrNotFound)
	}
	hr, err := f.repo(pr.HeadRepo)
	if err != nil {
		return err
	}
	if _, ok := hr.commits[sha]; !ok {
		return fmt.Errorf("commit %s: %w", sha, forge.ErrNotFound)
	}
	f.moveRef(hr, "refs/heads/"+pr.HeadRef, sha)
	return nil
}

// GetPullRequest implements [forge.PRReader].
func (f *Forge) GetPullRequest(ctx context.Context, repo forge.RepoID, number int) (forge.PullRequest, error) {
	release, err := f.acquire(ctx)
	if err != nil {
		return forge.PullRequest{}, err
	}
	defer release()
	r, err := f.repo(repo)
	if err != nil {
		return forge.PullRequest{}, err
	}
	pr, ok := r.prs[number]
	if !ok {
		return forge.PullRequest{}, fmt.Errorf("pull request %s#%d: %w", repo, number, forge.ErrNotFound)
	}
	return *pr, nil
}

// AddReview records a review of commitSHA by author, as the forge would accept it: the state must be approved,
// changes requested or commented (ErrInvalid), commitSHA must have been a head of the pull request (ErrInvalid),
// and the pull request's author cannot approve it (ErrForbidden).
func (f *Forge) AddReview(ctx context.Context, repo forge.RepoID, pr int, author forge.Actor, commitSHA string, state forge.ReviewState) (forge.Review, error) {
	release, err := f.acquire(ctx)
	if err != nil {
		return forge.Review{}, err
	}
	defer release()
	r, err := f.repo(repo)
	if err != nil {
		return forge.Review{}, err
	}
	p, ok := r.prs[pr]
	if !ok {
		return forge.Review{}, fmt.Errorf("pull request %s#%d: %w", repo, pr, forge.ErrNotFound)
	}
	if state != forge.ReviewApproved && state != forge.ReviewChangesRequested && state != forge.ReviewCommented {
		return forge.Review{}, fmt.Errorf("a review cannot be submitted as %s: %w", state, forge.ErrInvalid)
	}
	if !r.headHist[pr][commitSHA] {
		return forge.Review{}, fmt.Errorf("%s was never a head of pull request %d: %w", commitSHA, pr, forge.ErrInvalid)
	}
	if state == forge.ReviewApproved && author.Forge == p.Author.Forge && author.ID == p.Author.ID {
		return forge.Review{}, fmt.Errorf("the author of pull request %d cannot approve it: %w", pr, forge.ErrForbidden)
	}
	rv := &forge.Review{
		ID: fmt.Sprintf("v%d", f.next()), Repo: r.id, PR: pr, Author: author, CommitSHA: commitSHA,
		State: state, Submitted: f.clock(), Edit: forge.EditOriginal,
	}
	r.reviews[rv.ID] = rv
	return *rv, nil
}

func (f *Forge) review(repo forge.RepoID, pr int, id string) (*forge.Review, error) {
	r, err := f.repo(repo)
	if err != nil {
		return nil, err
	}
	rv, ok := r.reviews[id]
	if !ok || rv.PR != pr {
		return nil, fmt.Errorf("review %q: %w", id, forge.ErrNotFound)
	}
	return rv, nil
}

// EditReview changes a review's body and marks it edited. The verdict cannot change, as on GitHub.
func (f *Forge) EditReview(ctx context.Context, repo forge.RepoID, pr int, id, body string) error {
	release, err := f.acquire(ctx)
	if err != nil {
		return err
	}
	defer release()
	rv, err := f.review(repo, pr, id)
	if err != nil {
		return err
	}
	rv.Body, rv.Edit = body, forge.EditEdited
	return nil
}

// DismissReview sets a review's state to dismissed. The original verdict is gone, as on GitHub.
func (f *Forge) DismissReview(ctx context.Context, repo forge.RepoID, pr int, id string) error {
	release, err := f.acquire(ctx)
	if err != nil {
		return err
	}
	defer release()
	rv, err := f.review(repo, pr, id)
	if err != nil {
		return err
	}
	if rv.State == forge.ReviewCommented {
		return fmt.Errorf("a commented review cannot be dismissed: %w", forge.ErrInvalid)
	}
	rv.State = forge.ReviewDismissed
	return nil
}

// ListReviews implements [forge.PRReader], in submission order. A missing pull request is ErrNotFound.
func (f *Forge) ListReviews(ctx context.Context, repo forge.RepoID, pr int) ([]forge.Review, error) {
	release, err := f.acquire(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	err = f.incomplete("ListReviews")
	if err != nil {
		return nil, err
	}
	r, err := f.repo(repo)
	if err != nil {
		return nil, err
	}
	if _, ok := r.prs[pr]; !ok {
		return nil, fmt.Errorf("pull request %s#%d: %w", repo, pr, forge.ErrNotFound)
	}
	var out []forge.Review
	for _, rv := range r.reviews {
		if rv.PR == pr {
			out = append(out, *rv)
		}
	}
	slices.SortFunc(out, func(a, b forge.Review) int { return idOrder(a.ID, b.ID) })
	return out, nil
}

// GetReview implements [forge.PRReader]. It always returns the current state.
func (f *Forge) GetReview(ctx context.Context, repo forge.RepoID, pr int, id string) (forge.Review, error) {
	release, err := f.acquire(ctx)
	if err != nil {
		return forge.Review{}, err
	}
	defer release()
	rv, err := f.review(repo, pr, id)
	if err != nil {
		return forge.Review{}, err
	}
	return *rv, nil
}
