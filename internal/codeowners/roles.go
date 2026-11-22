// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

package codeowners

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/elliott-davis/lightsout/internal/authz"
	"github.com/elliott-davis/lightsout/internal/forge"
	"github.com/elliott-davis/lightsout/internal/pathglob"
)

// IdentityReader is the part of the forge that maps a stable ID to a current login, team membership and access.
// Org and team names are passed lowercase.
type IdentityReader interface {
	GetActor(ctx context.Context, id string) (forge.Actor, error)
	IsTeamMember(ctx context.Context, org, team, actorID string) (bool, error)
	GetRepo(ctx context.Context, repo forge.RepoID) (forge.Repo, error)
	GetTeam(ctx context.Context, org, team string) (forge.Team, error)
	RepoPermission(ctx context.Context, repo forge.RepoID, actorID string) (forge.Permission, error)
	TeamRepoPermission(ctx context.Context, repo forge.RepoID, org, team string) (forge.Permission, error)
}

// MaxTeamLookups bounds the distinct team owners one HasRole call checks. Reaching it is an error, never a grant.
const MaxTeamLookups = 100

const (
	// MaxPaths bounds the distinct paths of one HasRole call. More is an error wrapping [forge.ErrTooLarge].
	MaxPaths = 10_000
	// maxWork bounds one HasRole call's total pattern work, summed as (pattern runes+1) * (path runes+1) over every
	// pattern tried. Going over is an error wrapping [forge.ErrTooLarge].
	maxWork = 2_000_000_000
)

// RoleSource implements [authz.RoleSource] for the owner roles (SEC-10, NFR-5, CON-2). It holds no cache: every
// call re-reads the actor, team membership and repository access.
type RoleSource struct {
	file *File
	ids  IdentityReader
}

var _ authz.RoleSource = (*RoleSource)(nil)

// NewRoleSource returns a role source for the CODEOWNERS of the trusted revision. It is bound to the repository
// the file was loaded from ([File.Repo]).
//
// Build a RoleSource per execution, from a CODEOWNERS that [Load] read at the trusted base of that execution
// (WI-11 does this). It must never be long-lived, since the file is a snapshot, and it must never be built from the
// file of a proposal under review (CON-2). A nil file, which is what an invalid CODEOWNERS leaves, denies
// everything.
func NewRoleSource(f *File, ids IdentityReader) *RoleSource {
	return &RoleSource{file: f, ids: ids}
}

// HasRole answers the three owner roles. Any other role returns (false, nil), so a misrouted role check is denied
// rather than failing.
//
// The three roles share one mechanism and differ only in which paths the caller puts in t.Paths:
//   - [authz.RolePathOwner]: the read-only paths a change touches (CON-7)
//   - [authz.RoleCodeOwner]: every changed path (CON-8)
//   - [authz.RoleContractOwner]: the contract file paths being activated (CON-2), such as svc/.factory.yaml,
//     which are the files GitHub's own code-owner review covers
//
// The principal holds the role only when it owns every path. The target must be in the repo scope of the file's
// repository, or the answer is false. Empty t.Paths is false, an invalid path is an error and an unowned path is
// false. The actor is looked up live by ID: a revoked or deleted account ([forge.ErrNotFound]), another forge, a
// non-user, or a login that is not a valid ASCII GitHub login denies, and any other lookup error is returned.
//
// As on GitHub, an owner counts only with write access to the repository. A @user owner matches the actor's
// current login and needs [forge.PermWrite] on the repo, so a renamed login stops matching and a recycled login
// belongs to its new holder only if that holder has write access. A @org/team owner needs org to be the repo's
// owner (ASCII case-insensitive), a visible team (GitHub ignores secret ones), write access for the team on the
// repo, and live membership. Any lookup error is returned and is never ownership, and so is checking more than
// [MaxTeamLookups] distinct teams. Email owners never match.
func (r *RoleSource) HasRole(ctx context.Context, p authz.Principal, role authz.Role, t authz.Target) (bool, error) {
	if !slices.Contains([]authz.Role{authz.RolePathOwner, authz.RoleCodeOwner, authz.RoleContractOwner}, role) {
		return false, nil
	}
	if r.file == nil || r.file.repo == "" || t.Scope.Kind != authz.ScopeRepo || t.Scope.ID != string(r.file.repo) ||
		len(t.Paths) == 0 {
		return false, nil
	}
	paths := make([]string, 0, min(len(t.Paths), MaxPaths))
	seen := make(map[string]bool, cap(paths))
	for _, path := range t.Paths {
		if err := pathglob.ValidatePath(path); err != nil {
			return false, fmt.Errorf("check %s: %w", role, escapedError{err})
		}
		if seen[path] {
			continue
		}
		if len(paths) >= MaxPaths {
			return false, fmt.Errorf("check %s: more than %d distinct paths: %w", role, MaxPaths, forge.ErrTooLarge)
		}
		seen[path] = true
		paths = append(paths, path)
	}
	if p.ID == "" {
		return false, nil
	}
	actor, err := r.ids.GetActor(ctx, p.ID)
	switch {
	case errors.Is(err, forge.ErrNotFound):
		return false, nil
	case err != nil:
		return false, fmt.Errorf("check %s: get actor: %w", role, err)
	case actor.ID != p.ID || actor.Forge != p.Forge || actor.Kind != forge.ActorUser || !validLogin(actor.Login):
		return false, nil
	}
	c := &checker{ids: r.ids, repo: r.file.repo, id: p.ID, login: asciiLower(actor.Login), members: map[string]bool{}}
	budget := maxWork
	charge := func(steps int) error {
		if budget -= steps; budget < 0 {
			return fmt.Errorf("more than %d units of pattern work: %w", maxWork, forge.ErrTooLarge)
		}
		return nil
	}
	for _, path := range paths {
		if err := ctx.Err(); err != nil {
			return false, fmt.Errorf("check %s: %w", role, err)
		}
		rule, err := r.file.lookup(ctx, path, charge)
		if err != nil {
			return false, fmt.Errorf("check %s: %w", role, err)
		}
		owned, err := c.owns(ctx, rule.Owners)
		if err != nil {
			return false, fmt.Errorf("check %s: %w", role, err)
		}
		if !owned {
			return false, nil
		}
	}
	return true, nil
}

// checker holds the facts read during one HasRole call, so each is read at most once there and never across calls.
type checker struct {
	ids     IdentityReader
	repo    forge.RepoID
	id      string
	login   string // ASCII lowercase
	members map[string]bool

	permRead  bool
	perm      forge.Permission
	ownerRead bool
	owner     string
}

func (c *checker) userPermission(ctx context.Context) (forge.Permission, error) {
	if !c.permRead {
		p, err := c.ids.RepoPermission(ctx, c.repo, c.id)
		if err != nil {
			return forge.PermUnknown, fmt.Errorf("repo permission: %w", err)
		}
		c.perm, c.permRead = p, true
	}
	return c.perm, nil
}

func (c *checker) repoOwner(ctx context.Context) (string, error) {
	if !c.ownerRead {
		repo, err := c.ids.GetRepo(ctx, c.repo)
		if err != nil {
			return "", fmt.Errorf("get repo: %w", err)
		}
		c.owner, c.ownerRead = repo.Owner, true
	}
	return c.owner, nil
}

// owns reports whether any owner matches the actor.
func (c *checker) owns(ctx context.Context, owners []Owner) (bool, error) {
	for _, o := range owners {
		var ok bool
		var err error
		switch {
		case o.Kind == OwnerUser && o.Login == c.login:
			ok, err = c.userOwns(ctx)
		case o.Kind == OwnerTeam:
			ok, err = c.teamOwns(ctx, o)
		}
		if err != nil || ok {
			return ok, err
		}
	}
	return false, nil // an email owner never matches
}

func (c *checker) userOwns(ctx context.Context) (bool, error) {
	p, err := c.userPermission(ctx)
	return p.AtLeast(forge.PermWrite), err
}

func (c *checker) teamOwns(ctx context.Context, o Owner) (bool, error) {
	owner, err := c.repoOwner(ctx)
	if err != nil || !equalFoldASCII(owner, o.Org) {
		return false, err
	}
	key := o.Org + "/" + o.Team
	if m, seen := c.members[key]; seen {
		return m, nil
	}
	if len(c.members) >= MaxTeamLookups {
		return false, fmt.Errorf("more than %d distinct team owners to check: %w", MaxTeamLookups, forge.ErrTooLarge)
	}
	team, err := c.ids.GetTeam(ctx, o.Org, o.Team)
	switch {
	case errors.Is(err, forge.ErrNotFound):
		c.members[key] = false
		return false, nil
	case err != nil:
		return false, fmt.Errorf("team %s: %w", key, err)
	case team.Privacy != forge.PrivacyVisible:
		c.members[key] = false // GitHub ignores a secret team, and an unknown privacy fails closed
		return false, nil
	}
	perm, err := c.ids.TeamRepoPermission(ctx, c.repo, o.Org, o.Team)
	if err != nil {
		return false, fmt.Errorf("team %s permission: %w", key, err)
	}
	m := false
	if perm.AtLeast(forge.PermWrite) {
		if m, err = c.ids.IsTeamMember(ctx, o.Org, o.Team, c.id); err != nil {
			return false, fmt.Errorf("team %s: %w", key, err)
		}
	}
	c.members[key] = m
	return m, nil
}

func asciiLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 'a' - 'A'
		}
	}
	return string(b)
}

// equalFoldASCII folds ASCII letters only, so a Unicode lookalike never equals a login.
func equalFoldASCII(a, b string) bool { return asciiLower(a) == asciiLower(b) }
