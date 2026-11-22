// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

package fake

import (
	"context"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/elliott-davis/lightsout/internal/forge"
	"github.com/elliott-davis/lightsout/internal/forge/gittree"
	"github.com/elliott-davis/lightsout/internal/pathglob"
)

const (
	factoryRefPrefix = "refs/heads/factory/"
	maxChangeIDLen   = 100
)

var changeID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

// assignment is a change issued to one coder, on top of one trusted base.
type assignment struct {
	owner forge.Actor
	base  string
}

// AssignChange models the control plane issuing a change to one coder identity (SEC-3): only owner may push to
// refs/heads/factory/<changeID> of repo. baseSHA is the trusted base the control plane chose, the head of the base
// branch, and must be an existing commit of repo (ErrInvalid otherwise). Every push must descend from it, and the
// push policy is evaluated over everything that differs from it. Assigning an already assigned change moves it to
// the new owner and base. The factory identity itself cannot be assigned a change: the merger is never a coder
// (SEC-2).
func (f *Forge) AssignChange(ctx context.Context, repo forge.RepoID, changeID string, owner forge.Actor, baseSHA string) error {
	release, err := f.acquire(ctx)
	if err != nil {
		return err
	}
	defer release()
	r, err := f.repo(repo)
	if err != nil {
		return err
	}
	if owner.Forge == f.factory.Forge && owner.ID == f.factory.ID {
		return fmt.Errorf("the factory identity merges and cannot be a coder: %w", forge.ErrForbidden)
	}
	if !validChangeID(changeID) {
		return fmt.Errorf("change ID %q: %w", changeID, forge.ErrInvalid)
	}
	if _, ok := r.commits[baseSHA]; !ok {
		return fmt.Errorf("trusted base %q is not a commit of %s: %w", baseSHA, repo, forge.ErrInvalid)
	}
	r.assigned[changeID] = assignment{owner: owner, base: baseSHA}
	return nil
}

func validChangeID(id string) bool {
	return len(id) <= maxChangeIDLen && changeID.MatchString(id) && !strings.Contains(id, "..") &&
		!strings.HasSuffix(id, ".lock") && !strings.HasSuffix(id, ".")
}

// Pusher is bound at construction to one principal, one repo and one ref (SEC-2, SEC-3). It cannot merge or
// enqueue, because it has no such methods.
type Pusher struct {
	f         *Forge
	principal forge.Actor
	repo      forge.RepoID
	changeID  string
	policy    forge.PushPolicy
}

// canPush checks the principal against the live actor record and the change's assignment, matching on both the
// forge and the ID. Callers hold the lock.
func (f *Forge) canPush(r *repoRec, principal forge.Actor, change string) error {
	as, ok := r.assigned[change]
	if owner := as.owner; !ok || owner.Forge != principal.Forge || owner.ID != principal.ID {
		return fmt.Errorf("change %q is not assigned to %s/%s: %w", change, principal.Forge, principal.ID, forge.ErrForbidden)
	}
	a, ok := f.actors[principal.ID]
	if !ok || a.Forge != principal.Forge || a.revoked || a.reviewer {
		return fmt.Errorf("principal %s/%s may not push: %w", principal.Forge, principal.ID, forge.ErrForbidden)
	}
	return nil
}

// Pusher binds a pusher. The ref must be refs/heads/factory/<change-id>, that change must be assigned (see
// [Forge.AssignChange]) to this principal, and the principal must be a live, non-reviewer account of this forge.
// Each is ErrForbidden, and each is checked again at every Push. The policy bounds what the branch may differ in
// from the trusted base: a path under .github/workflows/ needs policy.Workflows, and a path policy.Deny reports is
// never changed. policy.Deny is required, and a nil one is ErrInvalid.
func (f *Forge) Pusher(ctx context.Context, principal forge.Actor, repo forge.RepoID, ref string, policy forge.PushPolicy) (*Pusher, error) {
	release, err := f.acquire(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	if policy.Deny == nil {
		return nil, fmt.Errorf("a push policy needs a Deny function: %w", forge.ErrInvalid)
	}
	id, ok := strings.CutPrefix(ref, factoryRefPrefix)
	if !ok || !validChangeID(id) {
		return nil, fmt.Errorf("ref %q is not %s<change-id>: %w", ref, factoryRefPrefix, forge.ErrForbidden)
	}
	r, err := f.repo(repo)
	if err != nil {
		return nil, err
	}
	if err := f.canPush(r, principal, id); err != nil {
		return nil, err
	}
	return &Pusher{f: f, principal: principal, repo: repo, changeID: id, policy: policy}, nil
}

// pushPlan is what Push works out under the lock.
type pushPlan struct {
	parent  *commit
	entries []gittree.Entry
	paths   []string // every path that differs between the trusted base and the new tree
}

// plan validates a push and applies it to a new tree without writing anything. Callers hold the lock.
func (p *Pusher) plan(r *repoRec, expectedParentSHA string, change forge.Change) (*pushPlan, error) {
	if err := p.f.canPush(r, p.principal, p.changeID); err != nil {
		return nil, err
	}
	ref := factoryRefPrefix + p.changeID
	if ref == r.defaultRef || r.protected[ref] {
		return nil, fmt.Errorf("ref %q is protected: %w", ref, forge.ErrForbidden)
	}
	if head, exists := r.refs[ref]; exists && head != expectedParentSHA {
		return nil, fmt.Errorf("ref %q is at %s, not %s: %w", ref, head, expectedParentSHA, forge.ErrConflict)
	}
	parent, ok := r.commits[expectedParentSHA]
	if !ok {
		return nil, fmt.Errorf("parent %s: %w", expectedParentSHA, forge.ErrNotFound)
	}
	base := r.assigned[p.changeID].base
	if !r.ancestors(expectedParentSHA)[base] {
		return nil, fmt.Errorf("parent %s does not descend from the trusted base %s: %w", expectedParentSHA, base, forge.ErrForbidden)
	}
	entries, err := applyChange(parent.entries, change)
	if err != nil {
		return nil, err
	}
	return &pushPlan{parent: parent, entries: entries, paths: diffPaths(r.commits[base].entries, entries)}, nil
}

// diffPaths lists every file path that differs between two trees: added, removed, changed or mode-changed.
func diffPaths(base, next []gittree.Entry) []string {
	old, cur := files(&commit{entries: base}), files(&commit{entries: next})
	var out []string
	for path, n := range cur {
		if o, ok := old[path]; !ok || o.Mode != n.Mode || !sameContent(o, n) {
			out = append(out, path)
		}
	}
	for path := range old {
		if _, ok := cur[path]; !ok {
			out = append(out, path)
		}
	}
	slices.Sort(out)
	return out
}

// Push implements [forge.BranchPusher]. It is a compare-and-swap on the parent: when the ref exists its head
// must be expectedParentSHA, and when it does not the parent must be an existing commit. Either way the parent
// must descend from the change's trusted base, and the policy is evaluated over every path that differs between
// that base and the new tree, so a parent that already carries a forbidden change is refused whatever the push
// lists. The change is applied to the parent's tree as a new commit authored by the principal, and pull requests on
// the branch follow it. Deny runs outside the lock, so the parent is checked again before the write.
func (p *Pusher) Push(ctx context.Context, expectedParentSHA string, change forge.Change) (string, error) {
	release, err := p.f.acquire(ctx)
	if err != nil {
		return "", err
	}
	r, err := p.f.repo(p.repo)
	if err != nil {
		release()
		return "", err
	}
	plan, err := p.plan(r, expectedParentSHA, change)
	release()
	if err != nil {
		return "", err
	}
	for _, path := range plan.paths {
		if perr := checkPolicy(path, p.policy); perr != nil {
			return "", perr
		}
	}
	release, err = p.f.acquire(ctx)
	if err != nil {
		return "", err
	}
	defer release()
	r, err = p.f.repo(p.repo)
	if err != nil {
		return "", err
	}
	// Everything may have changed while the policy ran: plan again, and require the same outcome.
	again, err := p.plan(r, expectedParentSHA, change)
	if err != nil {
		return "", err
	}
	if !slices.Equal(again.paths, plan.paths) {
		return "", fmt.Errorf("the trusted base changed during the push: %w", forge.ErrConflict)
	}
	sha := p.f.addCommit(r, []string{again.parent.sha}, change.Message, p.f.sig(p.f.actors[p.principal.ID].Actor), again.entries)
	p.f.moveRef(r, factoryRefPrefix+p.changeID, sha)
	return sha, nil
}

func invalidf(format string, args ...any) error {
	return fmt.Errorf("push: "+format+": %w", append(args, forge.ErrInvalid)...)
}

// checkPolicy refuses a workflow path without the workflows permission, and any path the control plane denies.
// It must not be called with the forge's lock held, because Deny may read the forge.
func checkPolicy(p string, policy forge.PushPolicy) error {
	if isWorkflowPath(p) && !policy.Workflows {
		return fmt.Errorf("push: path %q is under .github/workflows, which needs the workflows permission: %w", p, forge.ErrForbidden)
	}
	if policy.Deny != nil && policy.Deny(p) {
		return fmt.Errorf("push: path %q is factory-protected: %w", p, forge.ErrForbidden)
	}
	return nil
}

func applyChange(base []gittree.Entry, change forge.Change) ([]gittree.Entry, error) {
	if len(change.Writes) == 0 && len(change.Deletes) == 0 {
		return nil, invalidf("empty change")
	}
	byPath := make(map[string]gittree.Entry, len(base))
	for _, e := range base {
		byPath[e.Path] = e
	}
	touched := map[string]bool{}
	for _, d := range change.Deletes {
		if touched[d] {
			return nil, invalidf("path %q appears twice", d)
		}
		touched[d] = true
		if e, ok := byPath[d]; !ok || e.Mode == gittree.ModeTree {
			return nil, invalidf("delete %q: no such file", d)
		}
		delete(byPath, d)
	}
	for _, w := range change.Writes {
		if touched[w.Path] {
			return nil, invalidf("path %q appears twice", w.Path)
		}
		touched[w.Path] = true
		if err := pathglob.ValidatePath(w.Path); err != nil {
			return nil, fmt.Errorf("push: %w: %w", forge.ErrInvalid, err)
		}
		if hasDotGit(w.Path) {
			return nil, fmt.Errorf("push: path %q has a .git segment: %w", w.Path, forge.ErrForbidden)
		}
		if err := checkParents(byPath, w.Path); err != nil {
			return nil, err
		}
		mode := gittree.ModeBlob
		if w.Executable {
			mode = gittree.ModeExecutable
		}
		byPath[w.Path] = gittree.Entry{Path: w.Path, Mode: mode, Data: slices.Clone(w.Data)}
	}
	out := make([]gittree.Entry, 0, len(byPath))
	for _, e := range byPath {
		out = append(out, e)
	}
	slices.SortFunc(out, func(a, b gittree.Entry) int { return strings.Compare(a.Path, b.Path) })
	if err := checkEntries(out); err != nil {
		return nil, fmt.Errorf("push: %w", err)
	}
	return out, nil
}

// checkParents refuses a write below a symlink (ErrSymlink) or any other non-directory (ErrInvalid).
func checkParents(byPath map[string]gittree.Entry, p string) error {
	for i := range len(p) {
		if p[i] != '/' {
			continue
		}
		switch e, ok := byPath[p[:i]]; {
		case !ok || e.Mode == gittree.ModeTree:
		case e.Mode == gittree.ModeSymlink:
			return fmt.Errorf("push: write %q below symlink %q: %w", p, e.Path, forge.ErrSymlink)
		default:
			return invalidf("write %q below a %s at %q", p, e.Mode, e.Path)
		}
	}
	if e, ok := byPath[p]; ok && e.Mode == gittree.ModeTree {
		return invalidf("write %q over a directory", p)
	}
	return nil
}
