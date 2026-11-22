// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

// Package fake is a deterministic, in-memory forge for tests. It implements every capability in
// [forge], with an injected clock and monotonic IDs, and is checked by the shared conformance
// suite in internal/forge/forgetest.
//
// The fake never produces evidence or reaches a state GitHub cannot. Job executions are stored as given
// (a "complete" one must really be complete), renames are reported only when a helper declares them, and
// incomplete provenance stays incomplete. Helpers (the exported methods that are not part of a capability)
// set the world up, and return an error for an unknown repo or object.
package fake

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"maps"
	"math"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/elliott-davis/lightsout/internal/forge"
	"github.com/elliott-davis/lightsout/internal/forge/gittree"
)

// ForgeName is the Forge field of every actor the fake creates.
const ForgeName = "fake"

// Compile-time checks that Forge implements every capability, and Pusher the push capability.
var (
	_ forge.IdentityReader = (*Forge)(nil)
	_ forge.IssueReader    = (*Forge)(nil)
	_ forge.IssueWriter    = (*Forge)(nil)
	_ forge.PRReader       = (*Forge)(nil)
	_ forge.DiffReader     = (*Forge)(nil)
	_ forge.CheckReader    = (*Forge)(nil)
	_ forge.CheckWriter    = (*Forge)(nil)
	_ forge.MergeQueue     = (*Forge)(nil)
	_ forge.RulesReader    = (*Forge)(nil)
	_ forge.TreeReader     = (*Forge)(nil)
	_ forge.BranchPusher   = (*Pusher)(nil)
)

var fullSHA = regexp.MustCompile(`^([0-9a-f]{40}|[0-9a-f]{64})$`)

type actorRec struct {
	forge.Actor
	revoked  bool
	reviewer bool // read-only: may not push
}

type commit struct {
	sha       string
	parents   []string
	author    forge.GitSignature
	committer forge.GitSignature
	message   string
	entries   []gittree.Entry
}

type rename struct{ from, to string }

type teamKey struct{ org, team string }

type repoRec struct {
	id         forge.RepoID
	name       string
	issueTypes bool
	defaultRef string
	commits    map[string]*commit
	refs       map[string]string
	protected  map[string]bool
	assigned   map[string]assignment // change ID -> the one principal that may push it
	nextNumber int
	issues     map[int]string // number -> node ID
	keys       map[string]string
	comments   map[string]*forge.Comment
	prs        map[int]*forge.PullRequest
	reviews    map[string]*forge.Review
	checks     []*forge.CheckRun
	jobs       []*forge.JobExecution
	rules      map[string]forge.BranchRules
	queue      map[int]*forge.QueueEntry
	groups     []*forge.MergeGroup
	merges     []forge.ObservedMerge
	renames    map[string][]rename
	groupBase  map[string]string       // candidate SHA -> the short name of the group's base branch
	headHist   map[int]map[string]bool // PR number -> every head SHA it has had
}

// Forge is the in-memory forge. It is safe for concurrent use.
type Forge struct {
	mu         sync.Mutex
	clock      func() time.Time
	seq        int
	factory    forge.Actor
	factoryApp string
	actors     map[string]*actorRec
	teams      map[teamKey]map[string]bool
	repos      map[forge.RepoID]*repoRec
	issues     map[string]*forge.Issue // by node ID
	limits     gittree.Limits
	faults     map[string]bool
	trees      map[string]*gittree.FS // built trees by repo and commit, reset when the limits change
}

// New returns an empty forge that reads time from clock. It has one bot account and one app, which together are
// the factory: see [Forge.FactoryActor] and [Forge.FactoryAppID].
func New(clock func() time.Time) *Forge {
	f := &Forge{
		clock:  clock,
		actors: map[string]*actorRec{},
		teams:  map[teamKey]map[string]bool{},
		repos:  map[forge.RepoID]*repoRec{},
		issues: map[string]*forge.Issue{},
		faults: map[string]bool{},
		trees:  map[string]*gittree.FS{},
	}
	f.factory = f.newActor("lightsout[bot]", forge.ActorBot)
	f.factoryApp = fmt.Sprintf("app%d", f.next())
	return f
}

func (f *Forge) next() int {
	f.seq++
	return f.seq
}

func (f *Forge) newActor(login string, kind forge.ActorKind) forge.Actor {
	a := forge.Actor{Forge: ForgeName, ID: fmt.Sprintf("a%d", f.next()), Login: login, Kind: kind}
	f.actors[a.ID] = &actorRec{Actor: a}
	return a
}

// newSHA returns a unique full SHA-1-length hex ID derived from seed.
func (f *Forge) newSHA(seed string) string {
	sum := sha256.Sum256(fmt.Appendf(nil, "%d|%s", f.next(), seed))
	return hex.EncodeToString(sum[:20])
}

func (f *Forge) sig(a forge.Actor) forge.GitSignature {
	return forge.GitSignature{Name: a.Login, Email: a.Login + "@users.noreply.invalid", When: f.clock()}
}

// acquire checks ctx and takes the lock. Callers defer the returned release.
func (f *Forge) acquire(ctx context.Context) (func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("fake forge: %w", err)
	}
	f.mu.Lock()
	return f.mu.Unlock, nil
}

func (f *Forge) repo(id forge.RepoID) (*repoRec, error) {
	r, ok := f.repos[id]
	if !ok {
		return nil, fmt.Errorf("repo %q: %w", id, forge.ErrNotFound)
	}
	return r, nil
}

// InjectIncomplete makes every later call of the named operation fail with ErrIncomplete and a nil result, as a
// truncated forge answer would. The operations are the method names ListComments, ListReviews, Compare, Commits,
// ListJobExecutions and Tree.
func (f *Forge) InjectIncomplete(ctx context.Context, op string) error {
	release, err := f.acquire(ctx)
	if err != nil {
		return err
	}
	defer release()
	f.faults[op] = true
	return nil
}

func (f *Forge) incomplete(op string) error {
	if f.faults[op] {
		return fmt.Errorf("%s: injected truncation: %w", op, forge.ErrIncomplete)
	}
	return nil
}

// FactoryActor is the factory's bot account: the author of issues and comments it creates.
func (f *Forge) FactoryActor() forge.Actor { return f.factory }

// FactoryAppID is the factory's integration (App) ID, the producer of every check run it creates. It is a
// different namespace from FactoryActor().ID.
func (f *Forge) FactoryAppID() string { return f.factoryApp }

// AddRepo creates a repo with an empty initial commit on its default branch. When issueTypes is false the
// repo has no native issue types, so a type is recorded as a label.
func (f *Forge) AddRepo(ctx context.Context, name string, issueTypes bool) (forge.RepoID, error) {
	release, err := f.acquire(ctx)
	if err != nil {
		return "", err
	}
	defer release()
	id := forge.RepoID(fmt.Sprintf("r%d", f.next()))
	r := f.newRepoRec(id, name, issueTypes)
	f.repos[id] = r
	r.refs[r.defaultRef] = f.addCommit(r, nil, "initial commit", f.sig(f.factory), nil)
	return id, nil
}

func (f *Forge) newRepoRec(id forge.RepoID, name string, issueTypes bool) *repoRec {
	return &repoRec{
		id: id, name: name, issueTypes: issueTypes, defaultRef: "refs/heads/main",
		commits: map[string]*commit{}, refs: map[string]string{}, protected: map[string]bool{},
		assigned: map[string]assignment{}, nextNumber: 1, issues: map[int]string{}, keys: map[string]string{},
		comments: map[string]*forge.Comment{}, prs: map[int]*forge.PullRequest{}, reviews: map[string]*forge.Review{},
		rules: map[string]forge.BranchRules{}, queue: map[int]*forge.QueueEntry{}, renames: map[string][]rename{},
		groupBase: map[string]string{}, headHist: map[int]map[string]bool{},
	}
}

// DefaultBranch returns the repo's default branch as a full ref name.
func (f *Forge) DefaultBranch(ctx context.Context, repo forge.RepoID) (string, error) {
	release, err := f.acquire(ctx)
	if err != nil {
		return "", err
	}
	defer release()
	r, err := f.repo(repo)
	if err != nil {
		return "", err
	}
	return r.defaultRef, nil
}

// AddActor creates a user, bot or app account.
func (f *Forge) AddActor(ctx context.Context, login string, kind forge.ActorKind) (forge.Actor, error) {
	release, err := f.acquire(ctx)
	if err != nil {
		return forge.Actor{}, err
	}
	defer release()
	return f.newActor(login, kind), nil
}

func (f *Forge) actorRec(id string) (*actorRec, error) {
	a, ok := f.actors[id]
	if !ok {
		return nil, fmt.Errorf("actor %q: %w", id, forge.ErrNotFound)
	}
	return a, nil
}

// RenameActor changes an actor's login. The ID is stable.
func (f *Forge) RenameActor(ctx context.Context, id, login string) error {
	release, err := f.acquire(ctx)
	if err != nil {
		return err
	}
	defer release()
	a, err := f.actorRec(id)
	if err != nil {
		return err
	}
	a.Login = login
	return nil
}

// RevokeActor makes the actor unknown to GetActor, a non-member of every team, and unable to push.
func (f *Forge) RevokeActor(ctx context.Context, id string) error {
	release, err := f.acquire(ctx)
	if err != nil {
		return err
	}
	defer release()
	a, err := f.actorRec(id)
	if err != nil {
		return err
	}
	a.revoked = true
	return nil
}

// MarkReviewer makes the actor read-only: its pushes are forbidden.
func (f *Forge) MarkReviewer(ctx context.Context, id string) error {
	release, err := f.acquire(ctx)
	if err != nil {
		return err
	}
	defer release()
	a, err := f.actorRec(id)
	if err != nil {
		return err
	}
	a.reviewer = true
	return nil
}

// AddTeamMember adds an actor to a team, creating the team if needed.
func (f *Forge) AddTeamMember(ctx context.Context, org, team, actorID string) error {
	release, err := f.acquire(ctx)
	if err != nil {
		return err
	}
	defer release()
	if _, err := f.actorRec(actorID); err != nil {
		return err
	}
	k := teamKey{org, team}
	if f.teams[k] == nil {
		f.teams[k] = map[string]bool{}
	}
	f.teams[k][actorID] = true
	return nil
}

// RemoveTeamMember removes an actor from a team.
func (f *Forge) RemoveTeamMember(ctx context.Context, org, team, actorID string) error {
	release, err := f.acquire(ctx)
	if err != nil {
		return err
	}
	defer release()
	delete(f.teams[teamKey{org, team}], actorID)
	return nil
}

// GetActor implements [forge.IdentityReader]. A revoked actor is ErrNotFound.
func (f *Forge) GetActor(ctx context.Context, id string) (forge.Actor, error) {
	release, err := f.acquire(ctx)
	if err != nil {
		return forge.Actor{}, err
	}
	defer release()
	a, err := f.actorRec(id)
	if err != nil || a.revoked {
		return forge.Actor{}, fmt.Errorf("actor %q: %w", id, forge.ErrNotFound)
	}
	return a.Actor, nil
}

// IsTeamMember implements [forge.IdentityReader]. Membership is read live, and a revoked actor is never a member.
func (f *Forge) IsTeamMember(ctx context.Context, org, team, actorID string) (bool, error) {
	release, err := f.acquire(ctx)
	if err != nil {
		return false, err
	}
	defer release()
	if a, ok := f.actors[actorID]; ok && a.revoked {
		return false, nil
	}
	return f.teams[teamKey{org, team}][actorID], nil
}

// SetTreeLimits sets the limits Tree applies. The default is gittree's.
func (f *Forge) SetTreeLimits(ctx context.Context, lim gittree.Limits) error {
	release, err := f.acquire(ctx)
	if err != nil {
		return err
	}
	defer release()
	f.limits = lim
	f.trees = map[string]*gittree.FS{}
	return nil
}

// lenient is the limit used when validating committed trees, so that limits set later can be exercised.
func lenient() gittree.Limits {
	return gittree.Limits{MaxFileBytes: math.MaxInt, MaxEntries: math.MaxInt, MaxPathBytes: math.MaxInt, MaxTotalBytes: math.MaxInt}
}

func (f *Forge) addCommit(r *repoRec, parents []string, message string, author forge.GitSignature, entries []gittree.Entry) string {
	sha := f.newSHA(string(r.id) + message)
	r.commits[sha] = &commit{sha: sha, parents: parents, author: author, committer: author, message: message, entries: entries}
	return sha
}

// copyEntries deep-copies entries so that later mutation of the caller's slices cannot change stored content.
func copyEntries(entries []gittree.Entry) []gittree.Entry {
	out := make([]gittree.Entry, len(entries))
	for i, e := range entries {
		out[i] = e
		if e.Data != nil {
			out[i].Data = append([]byte(nil), e.Data...)
		}
	}
	return out
}

// checkEntries validates a whole tree the factory is about to store. A ".git" segment is forbidden, because a
// nested repository's metadata is another trust domain.
func checkEntries(entries []gittree.Entry) error {
	for _, e := range entries {
		if hasDotGit(e.Path) {
			return fmt.Errorf("path %q has a .git segment: %w", e.Path, forge.ErrForbidden)
		}
	}
	if _, err := gittree.New(entries, lenient()); err != nil {
		return fmt.Errorf("%w: %w", forge.ErrInvalid, err)
	}
	return nil
}

// CommitTree stores a commit whose whole tree is entries (deep-copied), and returns its SHA. Parents must exist.
// It moves no ref. A path with a .git segment is ErrForbidden.
func (f *Forge) CommitTree(ctx context.Context, repo forge.RepoID, parents []string, message string, entries []gittree.Entry) (string, error) {
	release, err := f.acquire(ctx)
	if err != nil {
		return "", err
	}
	defer release()
	r, err := f.repo(repo)
	if err != nil {
		return "", err
	}
	for _, p := range parents {
		if _, ok := r.commits[p]; !ok {
			return "", fmt.Errorf("parent %s: %w", p, forge.ErrNotFound)
		}
	}
	if err := checkEntries(entries); err != nil {
		return "", fmt.Errorf("commit tree: %w", err)
	}
	return f.addCommit(r, append([]string(nil), parents...), message, f.sig(f.factory), copyEntries(entries)), nil
}

// shortBranch strips a refs/heads/ prefix.
func shortBranch(ref string) string { return strings.TrimPrefix(ref, "refs/heads/") }

// copyCommits makes sha and its ancestry available in dst, as GitHub does for the head of a fork's pull request.
func copyCommits(dst, src *repoRec, sha string) {
	for queue := []string{sha}; len(queue) > 0; queue = queue[1:] {
		if _, ok := dst.commits[queue[0]]; ok {
			continue
		}
		c, ok := src.commits[queue[0]]
		if !ok {
			continue
		}
		dst.commits[c.sha] = c
		queue = append(queue, c.parents...)
	}
}

// moveRef points ref at sha. Every open pull request whose head is that branch follows it (a closed or merged
// one does not), and one that was in the merge queue leaves it, as on GitHub. Moving a base branch fails every
// active merge group on it, because the group's candidates were built on the old base.
func (f *Forge) moveRef(r *repoRec, ref, sha string) { f.moveRefOpt(r, ref, sha, false) }

// moveRefOpt is moveRef, except that keepGroups leaves merge groups to the caller, who settles them.
func (f *Forge) moveRefOpt(r *repoRec, ref, sha string, keepGroups bool) {
	r.refs[ref] = sha
	branch, ok := strings.CutPrefix(ref, "refs/heads/")
	if !ok {
		return
	}
	if !keepGroups {
		for _, g := range r.groups {
			if g.State == forge.GroupActive && r.groupBase[g.CandidateSHA] == branch {
				r.failGroup(g, 0)
			}
		}
	}
	for _, rr := range f.repos {
		for _, pr := range rr.prs {
			if pr.State == forge.PROpen && pr.HeadRepo == r.id && pr.HeadRef == branch && pr.HeadSHA != sha {
				copyCommits(rr, r, sha)
				pr.HeadSHA = sha
				rr.headHist[pr.Number][sha] = true
				rr.removeFromQueue(pr.Number)
			}
		}
	}
}

// ForkRepo creates a repo that shares src's commits and branches, as a GitHub fork does. It has no issues,
// pull requests or queue of its own.
func (f *Forge) ForkRepo(ctx context.Context, src forge.RepoID, name string) (forge.RepoID, error) {
	release, err := f.acquire(ctx)
	if err != nil {
		return "", err
	}
	defer release()
	s, err := f.repo(src)
	if err != nil {
		return "", err
	}
	id := forge.RepoID(fmt.Sprintf("r%d", f.next()))
	r := f.newRepoRec(id, name, s.issueTypes)
	r.defaultRef = s.defaultRef
	maps.Copy(r.commits, s.commits)
	maps.Copy(r.refs, s.refs)
	f.repos[id] = r
	return id, nil
}

// SetRef points a full ref name at an existing commit, creating it if needed. It ignores protection: it is a
// setup helper, not a push. Pull requests whose head is that branch follow it.
func (f *Forge) SetRef(ctx context.Context, repo forge.RepoID, ref, sha string) error {
	release, err := f.acquire(ctx)
	if err != nil {
		return err
	}
	defer release()
	r, err := f.repo(repo)
	if err != nil {
		return err
	}
	if !strings.HasPrefix(ref, "refs/") {
		return fmt.Errorf("ref %q is not a full ref name: %w", ref, forge.ErrInvalid)
	}
	if _, ok := r.commits[sha]; !ok {
		return fmt.Errorf("commit %s: %w", sha, forge.ErrNotFound)
	}
	f.moveRef(r, ref, sha)
	return nil
}

// ProtectBranch marks an existing branch (a short name or a full ref) protected. The default branch always is.
func (f *Forge) ProtectBranch(ctx context.Context, repo forge.RepoID, ref string) error {
	release, err := f.acquire(ctx)
	if err != nil {
		return err
	}
	defer release()
	r, err := f.repo(repo)
	if err != nil {
		return err
	}
	full := "refs/heads/" + shortBranch(ref)
	if _, ok := r.refs[full]; !ok {
		return fmt.Errorf("branch %q: %w", ref, forge.ErrNotFound)
	}
	r.protected[full] = true
	return nil
}

// SetBranchRules sets the rules BranchRules returns for a branch (a short name or a full ref), exactly as given,
// including Complete: false.
func (f *Forge) SetBranchRules(ctx context.Context, repo forge.RepoID, branch string, rules forge.BranchRules) error {
	release, err := f.acquire(ctx)
	if err != nil {
		return err
	}
	defer release()
	r, err := f.repo(repo)
	if err != nil {
		return err
	}
	r.rules[shortBranch(branch)] = rules
	return nil
}

// BranchRules implements [forge.RulesReader]. An unknown branch is ErrNotFound. An existing branch with no rules
// set reports an empty, complete rule set, which is what GitHub reports: consumers must fail on an empty set.
func (f *Forge) BranchRules(ctx context.Context, repo forge.RepoID, branch string) (forge.BranchRules, error) {
	release, err := f.acquire(ctx)
	if err != nil {
		return forge.BranchRules{}, err
	}
	defer release()
	r, err := f.repo(repo)
	if err != nil {
		return forge.BranchRules{}, err
	}
	b := shortBranch(branch)
	if _, ok := r.refs["refs/heads/"+b]; !ok {
		return forge.BranchRules{}, fmt.Errorf("branch %q: %w", branch, forge.ErrNotFound)
	}
	rules, ok := r.rules[b]
	if !ok {
		return forge.BranchRules{Complete: true}, nil
	}
	rules.RequiredChecks = append([]forge.RequiredCheck(nil), rules.RequiredChecks...)
	rules.BypassActors = append([]forge.Actor(nil), rules.BypassActors...)
	return rules, nil
}

// ResolveRef implements [forge.TreeReader]. It accepts a full ref name or a branch name.
func (f *Forge) ResolveRef(ctx context.Context, repo forge.RepoID, ref string) (string, error) {
	release, err := f.acquire(ctx)
	if err != nil {
		return "", err
	}
	defer release()
	r, err := f.repo(repo)
	if err != nil {
		return "", err
	}
	return r.resolve(ref)
}

func (r *repoRec) resolve(ref string) (string, error) {
	if sha, ok := r.refs[ref]; ok {
		return sha, nil
	}
	if sha, ok := r.refs["refs/heads/"+ref]; ok {
		return sha, nil
	}
	return "", fmt.Errorf("ref %q: %w", ref, forge.ErrNotFound)
}

// Tree implements [forge.TreeReader]. sha must be a full commit SHA: a short SHA or a ref is an error.
func (f *Forge) Tree(ctx context.Context, repo forge.RepoID, sha string) (fs.FS, error) {
	release, err := f.acquire(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	err = f.incomplete("Tree")
	if err != nil {
		return nil, err
	}
	t, err := f.tree(repo, sha)
	if err != nil {
		return nil, err
	}
	return t, nil
}

func (f *Forge) tree(repo forge.RepoID, sha string) (*gittree.FS, error) {
	if !fullSHA.MatchString(sha) {
		return nil, fmt.Errorf("tree %q: not a full commit SHA: %w", sha, forge.ErrNotFound)
	}
	r, err := f.repo(repo)
	if err != nil {
		return nil, err
	}
	c, ok := r.commits[sha]
	if !ok {
		return nil, fmt.Errorf("commit %s: %w", sha, forge.ErrNotFound)
	}
	key := string(repo) + "/" + sha
	if t, ok := f.trees[key]; ok {
		return t, nil
	}
	t, err := gittree.New(c.entries, f.limits)
	if err != nil {
		return nil, fmt.Errorf("tree %s: %w", sha, err)
	}
	f.trees[key] = t
	return t, nil
}

// ReadFile implements [forge.TreeReader]. It refuses a symlink in any component.
func (f *Forge) ReadFile(ctx context.Context, repo forge.RepoID, sha, path string) ([]byte, error) {
	release, err := f.acquire(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	t, err := f.tree(repo, sha)
	if err != nil {
		return nil, err
	}
	b, err := t.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s at %s: %w", path, sha, err)
	}
	return b, nil
}
