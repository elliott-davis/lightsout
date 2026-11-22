// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

package codeowners_test

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"strings"
	"sync"
	"testing"
	"testing/fstest"
	"time"

	"github.com/elliott-davis/lightsout/internal/audit"
	"github.com/elliott-davis/lightsout/internal/authz"
	"github.com/elliott-davis/lightsout/internal/codeowners"
	"github.com/elliott-davis/lightsout/internal/forge"
	"github.com/elliott-davis/lightsout/internal/forge/fake"
	"github.com/elliott-davis/lightsout/internal/forge/gittree"
	"github.com/elliott-davis/lightsout/internal/pathglob"
)

var t0 = time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)

const revA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

type world struct {
	fk    *fake.Forge
	repo  forge.RepoID
	alice forge.Actor
	bob   forge.Actor
}

func newWorld(ctx context.Context, t *testing.T) *world {
	t.Helper()
	fk := fake.New(func() time.Time { return t0 })
	repo, err := fk.AddRepo(ctx, "app", true)
	if err != nil {
		t.Fatal(err)
	}
	alice, err := fk.AddActor(ctx, "alice", forge.ActorUser)
	if err != nil {
		t.Fatal(err)
	}
	bob, err := fk.AddActor(ctx, "bob", forge.ActorUser)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range []forge.Actor{alice, bob} {
		if err := fk.SetRepoPermission(ctx, repo, a.ID, forge.PermWrite); err != nil {
			t.Fatal(err)
		}
	}
	return &world{fk: fk, repo: repo, alice: alice, bob: bob}
}

func blob(path, data string) gittree.Entry {
	return gittree.Entry{Path: path, Mode: gittree.ModeBlob, Data: []byte(data)}
}

// commit stores a tree and returns its SHA.
func (w *world) commit(ctx context.Context, t *testing.T, entries ...gittree.Entry) string {
	t.Helper()
	sha, err := w.fk.CommitTree(ctx, w.repo, nil, "c", entries)
	if err != nil {
		t.Fatal(err)
	}
	return sha
}

// load loads text as .github/CODEOWNERS.
func (w *world) load(ctx context.Context, t *testing.T, text string) *codeowners.File {
	t.Helper()
	f, err := codeowners.Load(ctx, w.fk, w.repo, w.commit(ctx, t, blob(".github/CODEOWNERS", text)))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return f
}

// source loads text as .github/CODEOWNERS and returns a role source over it.
func (w *world) source(t *testing.T, text string) *codeowners.RoleSource {
	t.Helper()
	ctx := t.Context()
	f, err := codeowners.Load(ctx, w.fk, w.repo, w.commit(ctx, t, blob(".github/CODEOWNERS", text)))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return codeowners.NewRoleSource(f, w.fk)
}

func principal(a forge.Actor) authz.Principal {
	return authz.Principal{Forge: a.Forge, ID: a.ID, Kind: authz.PrincipalUser}
}

// target is a repo-scoped target in w's repo.
func (w *world) target(paths ...string) authz.Target {
	return authz.Target{Scope: authz.Scope{Kind: authz.ScopeRepo, ID: string(w.repo)}, Paths: paths}
}

var ownerRoles = []authz.Role{authz.RolePathOwner, authz.RoleCodeOwner, authz.RoleContractOwner}

func TestHasRole_OwnerRolesShareOneMechanism(t *testing.T) { // CON-2, SEC-10
	t.Parallel()
	w := newWorld(t.Context(), t)
	rs := w.source(t, "/infra/ @alice\n")
	for _, role := range ownerRoles {
		t.Run(string(role), func(t *testing.T) {
			t.Parallel()
			ok, err := rs.HasRole(t.Context(), principal(w.alice), role, w.target("infra/main.tf"))
			if err != nil || !ok {
				t.Errorf("owner: HasRole = (%v, %v), want true", ok, err)
			}
			ok, err = rs.HasRole(t.Context(), principal(w.bob), role, w.target("infra/main.tf"))
			if err != nil || ok {
				t.Errorf("non-owner: HasRole = (%v, %v), want false", ok, err)
			}
		})
	}
}

func TestHasRole_OtherRolesDenied(t *testing.T) { // SEC-10, SEC-11
	t.Parallel()
	w := newWorld(t.Context(), t)
	rs := w.source(t, "* @alice\n")
	for _, role := range []authz.Role{authz.RoleIdeator, authz.RoleAdmin, "", "bogus"} {
		ok, err := rs.HasRole(t.Context(), principal(w.alice), role, w.target("a"))
		if ok || err != nil {
			t.Errorf("HasRole(%q) = (%v, %v), want (false, nil)", role, ok, err)
		}
	}
}

func TestHasRole_Denials(t *testing.T) { // SEC-10, SEC-11, NFR-5
	t.Parallel()
	w := newWorld(t.Context(), t)
	ctx := t.Context()
	rs := w.source(t, "/a/ @alice\n/b/ @bob\n/c/\n/d/ nobody@example.com\n")
	tests := []struct {
		name  string
		who   authz.Principal
		paths []string
		want  bool
	}{
		{"owns one of two", principal(w.alice), []string{"a/x", "b/x"}, false},
		{"owns both", principal(w.alice), []string{"a/x", "a/y"}, true},
		{"unowned path", principal(w.alice), []string{"zzz/x"}, false},
		{"owner-less override", principal(w.alice), []string{"c/x"}, false},
		{"email owner grants nothing", principal(w.alice), []string{"d/x"}, false},
		{"no paths", principal(w.alice), nil, false},
		{"empty id", authz.Principal{Forge: fake.ForgeName, Kind: authz.PrincipalUser}, []string{"a/x"}, false},
		{"unknown id", authz.Principal{Forge: fake.ForgeName, ID: "nope", Kind: authz.PrincipalUser}, []string{"a/x"}, false},
		{"another forge", authz.Principal{Forge: "github", ID: w.alice.ID, Kind: authz.PrincipalUser}, []string{"a/x"}, false},
		{"login in principal is ignored", authz.Principal{Forge: w.bob.Forge, ID: w.bob.ID, Login: "alice"}, []string{"a/x"}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ok, err := rs.HasRole(ctx, tc.who, authz.RoleCodeOwner, w.target(tc.paths...))
			if err != nil || ok != tc.want {
				t.Errorf("HasRole = (%v, %v), want (%v, nil)", ok, err, tc.want)
			}
		})
	}
}

func TestHasRole_InvalidPathIsAnError(t *testing.T) { // SEC-10, SEC-11
	t.Parallel()
	w := newWorld(t.Context(), t)
	rs := w.source(t, "* @alice\n")
	for _, p := range []string{"", "/a", "a/", "../a", "a//b"} {
		ok, err := rs.HasRole(t.Context(), principal(w.alice), authz.RoleCodeOwner, w.target("ok", p))
		if ok || err == nil {
			t.Errorf("path %q: HasRole = (%v, %v), want (false, error)", p, ok, err)
		}
	}
}

func TestHasRole_RenamedLogin(t *testing.T) { // SEC-11, NFR-5
	t.Parallel()
	w := newWorld(t.Context(), t)
	rs := w.source(t, "/a/ @alice\n")
	if ok, err := rs.HasRole(t.Context(), principal(w.alice), authz.RoleCodeOwner, w.target("a/x")); err != nil || !ok {
		t.Fatalf("before the rename: (%v, %v), want true", ok, err)
	}
	if err := w.fk.RenameActor(t.Context(), w.alice.ID, "alicia"); err != nil {
		t.Fatal(err)
	}
	if ok, err := rs.HasRole(t.Context(), principal(w.alice), authz.RoleCodeOwner, w.target("a/x")); err != nil || ok {
		t.Errorf("after the rename: (%v, %v), want false", ok, err)
	}
}

func TestHasRole_RecycledLogin(t *testing.T) { // SEC-11, NFR-5
	t.Parallel()
	w := newWorld(t.Context(), t)
	rs := w.source(t, "/a/ @alice\n")
	if err := w.fk.RevokeActor(t.Context(), w.alice.ID); err != nil {
		t.Fatal(err)
	}
	newAlice, err := w.fk.AddActor(t.Context(), "alice", forge.ActorUser)
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := rs.HasRole(t.Context(), principal(w.alice), authz.RoleCodeOwner, w.target("a/x")); err != nil || ok {
		t.Errorf("deleted ID 1: (%v, %v), want false", ok, err)
	}
	// Without write access the new holder of the login is not an owner, as on GitHub.
	if ok, err := rs.HasRole(t.Context(), principal(newAlice), authz.RoleCodeOwner, w.target("a/x")); err != nil || ok {
		t.Errorf("new holder without write access: (%v, %v), want false", ok, err)
	}
	// GitHub resolves @alice to whoever holds the login now, once it has write access.
	if err := w.fk.SetRepoPermission(t.Context(), w.repo, newAlice.ID, forge.PermWrite); err != nil {
		t.Fatal(err)
	}
	if ok, err := rs.HasRole(t.Context(), principal(newAlice), authz.RoleCodeOwner, w.target("a/x")); err != nil || !ok {
		t.Errorf("new holder with write access: (%v, %v), want true", ok, err)
	}
}

func TestHasRole_CaseInsensitiveLogin(t *testing.T) { // SEC-10
	t.Parallel()
	w := newWorld(t.Context(), t)
	rs := w.source(t, "/a/ @Alice\n")
	if ok, err := rs.HasRole(t.Context(), principal(w.alice), authz.RoleCodeOwner, w.target("a/x")); err != nil || !ok {
		t.Errorf("@Alice against login alice: (%v, %v), want true", ok, err)
	}
}

func TestHasRole_PathsAreCaseSensitive(t *testing.T) { // SEC-10: GitHub's server is case-sensitive
	t.Parallel()
	w := newWorld(t.Context(), t)
	rs := w.source(t, "/Docs/ @alice\n")
	if ok, err := rs.HasRole(t.Context(), principal(w.alice), authz.RoleCodeOwner, w.target("docs/x")); err != nil || ok {
		t.Errorf("docs/x under /Docs/: (%v, %v), want false", ok, err)
	}
	if ok, err := rs.HasRole(t.Context(), principal(w.alice), authz.RoleCodeOwner, w.target("Docs/x")); err != nil || !ok {
		t.Errorf("Docs/x under /Docs/: (%v, %v), want true", ok, err)
	}
}

func TestHasRole_Team(t *testing.T) { // SEC-11, NFR-5
	t.Parallel()
	w := newWorld(t.Context(), t)
	ctx := t.Context()
	rs := w.source(t, "/a/ @Acme/Core\n")
	if err := w.fk.AddTeamMember(ctx, "acme", "core", w.alice.ID); err != nil {
		t.Fatal(err)
	}
	if err := w.fk.SetTeamRepoPermission(ctx, w.repo, "acme", "core", forge.PermWrite); err != nil {
		t.Fatal(err)
	}
	if ok, err := rs.HasRole(ctx, principal(w.alice), authz.RoleCodeOwner, w.target("a/x")); err != nil || !ok {
		t.Fatalf("member: (%v, %v), want true", ok, err)
	}
	if ok, err := rs.HasRole(ctx, principal(w.bob), authz.RoleCodeOwner, w.target("a/x")); err != nil || ok {
		t.Errorf("non-member: (%v, %v), want false", ok, err)
	}
	// The team loses its repo access between the decision and its execution.
	if err := w.fk.SetTeamRepoPermission(ctx, w.repo, "acme", "core", forge.PermRead); err != nil {
		t.Fatal(err)
	}
	if ok, err := rs.HasRole(ctx, principal(w.alice), authz.RoleCodeOwner, w.target("a/x")); err != nil || ok {
		t.Errorf("team without write access: (%v, %v), want false", ok, err)
	}
	if err := w.fk.SetTeamRepoPermission(ctx, w.repo, "acme", "core", forge.PermWrite); err != nil {
		t.Fatal(err)
	}
	// Removed between the decision and its execution.
	if err := w.fk.RemoveTeamMember(ctx, "acme", "core", w.alice.ID); err != nil {
		t.Fatal(err)
	}
	if ok, err := rs.HasRole(ctx, principal(w.alice), authz.RoleCodeOwner, w.target("a/x")); err != nil || ok {
		t.Errorf("after removal: (%v, %v), want false", ok, err)
	}
}

func TestHasRole_TeamWithNoRepoAccess(t *testing.T) { // SEC-11
	t.Parallel()
	w := newWorld(t.Context(), t)
	rs := w.source(t, "/a/ @acme/core\n")
	if err := w.fk.AddTeamMember(t.Context(), "acme", "core", w.alice.ID); err != nil {
		t.Fatal(err)
	}
	if ok, err := rs.HasRole(t.Context(), principal(w.alice), authz.RoleCodeOwner, w.target("a/x")); err != nil || ok {
		t.Errorf("member of a team with no repo access: (%v, %v), want false", ok, err)
	}
}

func TestHasRole_TeamFromForeignOrg(t *testing.T) { // SEC-11
	t.Parallel()
	w := newWorld(t.Context(), t)
	ctx := t.Context()
	rs := w.source(t, "/a/ @other/core\n")
	if err := w.fk.AddTeamMember(ctx, "other", "core", w.alice.ID); err != nil {
		t.Fatal(err)
	}
	if err := w.fk.SetTeamRepoPermission(ctx, w.repo, "other", "core", forge.PermAdmin); err != nil {
		t.Fatal(err)
	}
	if ok, err := rs.HasRole(ctx, principal(w.alice), authz.RoleCodeOwner, w.target("a/x")); err != nil || ok {
		t.Errorf("team of another org: (%v, %v), want false", ok, err)
	}
}

func TestHasRole_UserWithoutWriteAccess(t *testing.T) { // SEC-11
	t.Parallel()
	w := newWorld(t.Context(), t)
	rs := w.source(t, "/a/ @alice\n")
	for _, p := range []forge.Permission{forge.PermNone, forge.PermRead, forge.PermTriage} {
		if err := w.fk.SetRepoPermission(t.Context(), w.repo, w.alice.ID, p); err != nil {
			t.Fatal(err)
		}
		if ok, err := rs.HasRole(t.Context(), principal(w.alice), authz.RoleCodeOwner, w.target("a/x")); err != nil || ok {
			t.Errorf("permission %s: (%v, %v), want false", p, ok, err)
		}
	}
	for _, p := range []forge.Permission{forge.PermWrite, forge.PermMaintain, forge.PermAdmin} {
		if err := w.fk.SetRepoPermission(t.Context(), w.repo, w.alice.ID, p); err != nil {
			t.Fatal(err)
		}
		if ok, err := rs.HasRole(t.Context(), principal(w.alice), authz.RoleCodeOwner, w.target("a/x")); err != nil || !ok {
			t.Errorf("permission %s: (%v, %v), want true", p, ok, err)
		}
	}
}

func TestHasRole_BoundToItsRepo(t *testing.T) { // SEC-10
	t.Parallel()
	w := newWorld(t.Context(), t)
	rs := w.source(t, "* @alice\n")
	other, err := w.fk.AddRepo(t.Context(), "other", true)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		tg   authz.Target
		want bool
	}{
		{"same repo", w.target("a"), true},
		{"another repo", authz.Target{Scope: authz.Scope{Kind: authz.ScopeRepo, ID: string(other)}, Paths: []string{"a"}}, false},
		{"install scope", authz.Target{Scope: authz.Scope{Kind: authz.ScopeInstall, ID: string(w.repo)}, Paths: []string{"a"}}, false},
		{"no scope", authz.Target{Paths: []string{"a"}}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ok, herr := rs.HasRole(t.Context(), principal(w.alice), authz.RoleCodeOwner, tc.tg)
			if herr != nil || ok != tc.want {
				t.Errorf("HasRole = (%v, %v), want (%v, nil)", ok, herr, tc.want)
			}
		})
	}
	// A file that was parsed, not loaded, has no repo and so no binding.
	f, err := codeowners.Parse("CODEOWNERS", []byte("* @alice\n"))
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := codeowners.NewRoleSource(f, w.fk).HasRole(t.Context(), principal(w.alice), authz.RoleCodeOwner, authz.Target{Paths: []string{"a"}}); ok || err != nil {
		t.Errorf("unbound file: (%v, %v), want (false, nil)", ok, err)
	}
}

func TestHasRole_ActorHardening(t *testing.T) { // SEC-10, SEC-11
	t.Parallel()
	w := newWorld(t.Context(), t)
	ctx := t.Context()
	grant := func(a forge.Actor) {
		t.Helper()
		if err := w.fk.SetRepoPermission(ctx, w.repo, a.ID, forge.PermWrite); err != nil {
			t.Fatal(err)
		}
	}
	mixed, err := w.fk.AddActor(ctx, "Carol", forge.ActorUser)
	if err != nil {
		t.Fatal(err)
	}
	kelvin, err := w.fk.AddActor(ctx, "\u212Aate", forge.ActorUser)
	if err != nil {
		t.Fatal(err)
	}
	bot, err := w.fk.AddActor(ctx, "ci", forge.ActorBot)
	if err != nil {
		t.Fatal(err)
	}
	app, err := w.fk.AddActor(ctx, "builder", forge.ActorApp)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range []forge.Actor{mixed, kelvin, bot, app} {
		grant(a)
	}
	rs := w.source(t, "/c/ @carol\n/k/ @kate\n/b/ @ci\n/p/ @builder\n")
	tests := []struct {
		name string
		who  forge.Actor
		path string
		want bool
	}{
		{"live Carol matches @carol", mixed, "c/x", true},
		{"kelvin sign login", kelvin, "k/x", false},
		{"bot listed as owner", bot, "b/x", false},
		{"app listed as owner", app, "p/x", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ok, err := rs.HasRole(ctx, principal(tc.who), authz.RoleCodeOwner, w.target(tc.path))
			if err != nil || ok != tc.want {
				t.Errorf("HasRole = (%v, %v), want (%v, nil)", ok, err, tc.want)
			}
		})
	}
	t.Run("a reader that returns another ID", func(t *testing.T) {
		t.Parallel()
		f := w.load(ctx, t, "* @carol\n")
		ids := &failingIDs{IdentityReader: w.fk, swapID: w.bob.ID}
		ok, err := codeowners.NewRoleSource(f, ids).HasRole(ctx, principal(mixed), authz.RoleCodeOwner, w.target("c/x"))
		if err != nil || ok {
			t.Errorf("HasRole = (%v, %v), want (false, nil)", ok, err)
		}
	})
	t.Run("empty principal ID does not call the reader", func(t *testing.T) {
		t.Parallel()
		f := w.load(ctx, t, "* @carol\n")
		ids := &failingIDs{IdentityReader: w.fk}
		p := authz.Principal{Forge: fake.ForgeName, Kind: authz.PrincipalUser}
		ok, err := codeowners.NewRoleSource(f, ids).HasRole(ctx, p, authz.RoleCodeOwner, w.target("c/x"))
		if err != nil || ok || ids.actorCalls != 0 {
			t.Errorf("HasRole = (%v, %v) after %d reads, want (false, nil) after none", ok, err, ids.actorCalls)
		}
	})
	t.Run("cancelled context", func(t *testing.T) {
		t.Parallel()
		c, cancel := context.WithCancel(ctx)
		cancel()
		ok, err := rs.HasRole(c, principal(mixed), authz.RoleCodeOwner, w.target("c/x"))
		if ok || !errors.Is(err, context.Canceled) {
			t.Errorf("HasRole = (%v, %v), want (false, Canceled)", ok, err)
		}
	})
}

// failingIDs wraps the fake and injects errors.
type failingIDs struct {
	codeowners.IdentityReader
	actorErr, teamErr, permErr, teamPermErr error
	repoErr, getTeamErr                     error
	unknownPerm                             bool   // permission reads answer (PermUnknown, nil)
	swapID                                  string // when set, GetActor answers with this ID
	mu                                      sync.Mutex
	teamCalls, actorCalls                   int
}

func (f *failingIDs) GetActor(ctx context.Context, id string) (forge.Actor, error) {
	f.mu.Lock()
	f.actorCalls++
	f.mu.Unlock()
	if f.actorErr != nil {
		return forge.Actor{}, f.actorErr
	}
	if f.swapID != "" {
		return f.IdentityReader.GetActor(ctx, f.swapID)
	}
	return f.IdentityReader.GetActor(ctx, id)
}

func (f *failingIDs) GetRepo(ctx context.Context, repo forge.RepoID) (forge.Repo, error) {
	if f.repoErr != nil {
		return forge.Repo{}, f.repoErr
	}
	return f.IdentityReader.GetRepo(ctx, repo)
}

func (f *failingIDs) GetTeam(ctx context.Context, org, team string) (forge.Team, error) {
	if f.getTeamErr != nil {
		return forge.Team{}, f.getTeamErr
	}
	return f.IdentityReader.GetTeam(ctx, org, team)
}

func (f *failingIDs) RepoPermission(ctx context.Context, repo forge.RepoID, id string) (forge.Permission, error) {
	if f.unknownPerm {
		return forge.PermUnknown, nil
	}
	if f.permErr != nil {
		return forge.PermAdmin, f.permErr // a buggy reader that also says admin must still not grant
	}
	return f.IdentityReader.RepoPermission(ctx, repo, id)
}

func (f *failingIDs) TeamRepoPermission(ctx context.Context, repo forge.RepoID, org, team string) (forge.Permission, error) {
	if f.unknownPerm {
		return forge.PermUnknown, nil
	}
	if f.teamPermErr != nil {
		return forge.PermAdmin, f.teamPermErr
	}
	return f.IdentityReader.TeamRepoPermission(ctx, repo, org, team)
}

func (f *failingIDs) IsTeamMember(ctx context.Context, org, team, id string) (bool, error) {
	f.mu.Lock()
	f.teamCalls++
	f.mu.Unlock()
	if f.teamErr != nil {
		return true, f.teamErr // a buggy reader that also says true must still not grant
	}
	return f.IdentityReader.IsTeamMember(ctx, org, team, id)
}

func TestHasRole_LookupErrors(t *testing.T) { // SEC-10, NFR-5: an error is never membership
	t.Parallel()
	w := newWorld(t.Context(), t)
	boom := errors.New("boom")
	ctx := t.Context()
	file := w.load(ctx, t, "/a/ @acme/core @alice\n/b/ @acme/core\n")
	if err := w.fk.SetTeamRepoPermission(ctx, w.repo, "acme", "core", forge.PermWrite); err != nil {
		t.Fatal(err)
	}
	t.Run("permission error", func(t *testing.T) {
		t.Parallel()
		rs := codeowners.NewRoleSource(file, &failingIDs{IdentityReader: w.fk, permErr: boom})
		ok, err := rs.HasRole(t.Context(), principal(w.alice), authz.RoleCodeOwner, w.target("a/x"))
		if ok || !errors.Is(err, boom) {
			t.Errorf("HasRole = (%v, %v), want (false, boom)", ok, err)
		}
	})
	t.Run("team permission error", func(t *testing.T) {
		t.Parallel()
		rs := codeowners.NewRoleSource(file, &failingIDs{IdentityReader: w.fk, teamPermErr: boom})
		ok, err := rs.HasRole(t.Context(), principal(w.bob), authz.RoleCodeOwner, w.target("b/x"))
		if ok || !errors.Is(err, boom) {
			t.Errorf("HasRole = (%v, %v), want (false, boom)", ok, err)
		}
	})
	t.Run("team error", func(t *testing.T) {
		t.Parallel()
		rs := codeowners.NewRoleSource(file, &failingIDs{IdentityReader: w.fk, teamErr: boom})
		ok, err := rs.HasRole(t.Context(), principal(w.bob), authz.RoleCodeOwner, w.target("b/x"))
		if ok || !errors.Is(err, boom) {
			t.Errorf("HasRole = (%v, %v), want (false, boom)", ok, err)
		}
	})
	t.Run("actor error", func(t *testing.T) {
		t.Parallel()
		rs := codeowners.NewRoleSource(file, &failingIDs{IdentityReader: w.fk, actorErr: boom})
		ok, err := rs.HasRole(t.Context(), principal(w.alice), authz.RoleCodeOwner, w.target("a/x"))
		if ok || !errors.Is(err, boom) {
			t.Errorf("HasRole = (%v, %v), want (false, boom)", ok, err)
		}
	})
	t.Run("incomplete actor lookup", func(t *testing.T) {
		t.Parallel()
		rs := codeowners.NewRoleSource(file, &failingIDs{IdentityReader: w.fk, actorErr: forge.ErrIncomplete})
		ok, err := rs.HasRole(t.Context(), principal(w.alice), authz.RoleCodeOwner, w.target("a/x"))
		if ok || !errors.Is(err, forge.ErrIncomplete) {
			t.Errorf("HasRole = (%v, %v), want (false, ErrIncomplete)", ok, err)
		}
	})
	t.Run("user match skips nothing before a team error", func(t *testing.T) {
		t.Parallel()
		// The team owner is listed first on /a/, so its error surfaces even though @alice would match.
		rs := codeowners.NewRoleSource(file, &failingIDs{IdentityReader: w.fk, teamErr: boom})
		ok, err := rs.HasRole(t.Context(), principal(w.alice), authz.RoleCodeOwner, w.target("a/x"))
		if ok || !errors.Is(err, boom) {
			t.Errorf("HasRole = (%v, %v), want (false, boom)", ok, err)
		}
	})
}

func TestHasRole_NoCache(t *testing.T) { // NFR-5
	t.Parallel()
	w := newWorld(t.Context(), t)
	f := w.load(t.Context(), t, "/a/ @acme/core\n")
	if err := w.fk.SetTeamRepoPermission(t.Context(), w.repo, "acme", "core", forge.PermWrite); err != nil {
		t.Fatal(err)
	}
	ids := &failingIDs{IdentityReader: w.fk}
	rs := codeowners.NewRoleSource(f, ids)
	if err := w.fk.AddTeamMember(t.Context(), "acme", "core", w.alice.ID); err != nil {
		t.Fatal(err)
	}
	for range 3 {
		if ok, err := rs.HasRole(t.Context(), principal(w.alice), authz.RoleCodeOwner, w.target("a/x", "a/y")); err != nil || !ok {
			t.Fatalf("HasRole = (%v, %v), want true", ok, err)
		}
	}
	if ids.teamCalls != 3 {
		t.Errorf("IsTeamMember calls = %d, want one per HasRole (3)", ids.teamCalls)
	}
}

func TestHasRole_NilFileDeniesEverything(t *testing.T) { // CON-2, SEC-11
	t.Parallel()
	w := newWorld(t.Context(), t)
	// What a caller holds after Parse rejected the file.
	f, err := codeowners.Parse("CODEOWNERS", []byte("* @alice\n!bad @alice\n"))
	if err == nil {
		t.Fatal("Parse accepted an invalid file")
	}
	rs := codeowners.NewRoleSource(f, w.fk)
	for _, role := range ownerRoles {
		if ok, err := rs.HasRole(t.Context(), principal(w.alice), role, w.target("a")); ok || err != nil {
			t.Errorf("%s: (%v, %v), want (false, nil)", role, ok, err)
		}
	}
}

func TestHasRole_NoFileOwnsNothing(t *testing.T) { // CON-2
	t.Parallel()
	w := newWorld(t.Context(), t)
	ctx := t.Context()
	f, err := codeowners.Load(ctx, w.fk, w.repo, w.commit(ctx, t, blob("README.md", "x")))
	if err != nil {
		t.Fatal(err)
	}
	rs := codeowners.NewRoleSource(f, w.fk)
	if ok, err := rs.HasRole(t.Context(), principal(w.alice), authz.RoleCodeOwner, w.target("README.md")); ok || err != nil {
		t.Errorf("HasRole = (%v, %v), want (false, nil)", ok, err)
	}
}

func TestLoad(t *testing.T) { // CON-2
	t.Parallel()
	w := newWorld(t.Context(), t)
	ctx := t.Context()
	pick := func(t *testing.T, entries ...gittree.Entry) *codeowners.File {
		t.Helper()
		f, err := codeowners.Load(ctx, w.fk, w.repo, w.commit(ctx, t, entries...))
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		return f
	}
	t.Run("order", func(t *testing.T) {
		t.Parallel()
		f := pick(t, blob("docs/CODEOWNERS", "* @c"), blob("CODEOWNERS", "* @b"), blob(".github/CODEOWNERS", "* @a"))
		if f.Path() != ".github/CODEOWNERS" || f.Rules()[0].Owners[0].Login != "a" {
			t.Errorf("used %s %+v, want .github/CODEOWNERS", f.Path(), f.Rules())
		}
		f = pick(t, blob("docs/CODEOWNERS", "* @c"), blob("CODEOWNERS", "* @b"))
		if f.Path() != "CODEOWNERS" {
			t.Errorf("used %s, want CODEOWNERS", f.Path())
		}
		f = pick(t, blob("docs/CODEOWNERS", "* @c"))
		if f.Path() != "docs/CODEOWNERS" {
			t.Errorf("used %s, want docs/CODEOWNERS", f.Path())
		}
	})
	t.Run("first file shadows an invalid later one", func(t *testing.T) {
		t.Parallel()
		f := pick(t, blob(".github/CODEOWNERS", "* @a"), blob("CODEOWNERS", "!bad @b"))
		if f.Path() != ".github/CODEOWNERS" {
			t.Errorf("used %s", f.Path())
		}
	})
	t.Run("none", func(t *testing.T) {
		t.Parallel()
		f := pick(t, blob("README.md", "x"))
		if f.Path() != "" || len(f.Rules()) != 0 {
			t.Errorf("file = %q with %d rules, want none", f.Path(), len(f.Rules()))
		}
	})
	t.Run("revision pinned", func(t *testing.T) {
		t.Parallel()
		sha := w.commit(ctx, t, blob("CODEOWNERS", "* @a"))
		f, err := codeowners.Load(ctx, w.fk, w.repo, sha)
		if err != nil || f.Revision() != sha {
			t.Errorf("Load = (%v, %v), want revision %s", f, err, sha)
		}
	})
	t.Run("syntax error", func(t *testing.T) {
		t.Parallel()
		_, err := codeowners.Load(ctx, w.fk, w.repo, w.commit(ctx, t, blob("CODEOWNERS", "!x @a")))
		var pe *codeowners.ParseError
		if !errors.As(err, &pe) {
			t.Errorf("err = %v, want *ParseError", err)
		}
	})
	t.Run("warnings", func(t *testing.T) {
		t.Parallel()
		f := pick(t, blob("CODEOWNERS", "* a@b.io"))
		if len(f.Warnings()) != 1 {
			t.Errorf("warnings = %+v, want one", f.Warnings())
		}
	})
}

func TestLoad_Refusals(t *testing.T) { // CON-2, SEC-11
	t.Parallel()
	w := newWorld(t.Context(), t)
	ctx := t.Context()
	link := func(path string) gittree.Entry {
		return gittree.Entry{Path: path, Mode: gittree.ModeSymlink, Data: []byte("elsewhere")}
	}
	tests := []struct {
		name    string
		entries []gittree.Entry
		want    error
	}{
		{"symlinked file", []gittree.Entry{link(".github/CODEOWNERS"), blob("CODEOWNERS", "* @a")}, forge.ErrSymlink},
		{"symlinked root file", []gittree.Entry{link("CODEOWNERS")}, forge.ErrSymlink},
		{"symlinked directory", []gittree.Entry{link(".github"), blob("CODEOWNERS", "* @a")}, forge.ErrSymlink},
		{"directory", []gittree.Entry{blob("CODEOWNERS/x", "* @a")}, forge.ErrInvalid},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f, err := codeowners.Load(ctx, w.fk, w.repo, w.commit(ctx, t, tc.entries...))
			if f != nil || !errors.Is(err, tc.want) {
				t.Errorf("Load = (%v, %v), want %v", f, err, tc.want)
			}
		})
	}
	t.Run("too large", func(t *testing.T) {
		t.Parallel()
		big := newWorld(ctx, t)
		if err := big.fk.SetTreeLimits(ctx, gittree.Limits{MaxFileBytes: 8 << 20, MaxTotalBytes: 16 << 20}); err != nil {
			t.Fatal(err)
		}
		entry := blob("CODEOWNERS", strings.Repeat("#", codeowners.MaxFileBytes))
		f, err := codeowners.Load(ctx, big.fk, big.repo, big.commit(ctx, t, entry))
		if f != nil || !errors.Is(err, forge.ErrTooLarge) {
			t.Errorf("Load = (%v, %v), want ErrTooLarge", f, err)
		}
	})
	t.Run("short SHA", func(t *testing.T) {
		t.Parallel()
		if _, err := codeowners.Load(ctx, w.fk, w.repo, "abc123"); err == nil {
			t.Error("Load accepted a short SHA")
		}
	})
	t.Run("unknown commit", func(t *testing.T) {
		t.Parallel()
		if _, err := codeowners.Load(ctx, w.fk, w.repo, strings.Repeat("0", 40)); !errors.Is(err, forge.ErrNotFound) {
			t.Errorf("err = %v, want ErrNotFound", err)
		}
	})
	t.Run("cancelled", func(t *testing.T) {
		t.Parallel()
		c, cancel := context.WithCancel(ctx)
		cancel()
		if _, err := codeowners.Load(c, w.fk, w.repo, w.commit(ctx, t, blob("CODEOWNERS", "* @a"))); !errors.Is(err, context.Canceled) {
			t.Errorf("err = %v, want context.Canceled", err)
		}
	})
}

// memTx is the smallest authz.Tx: it consumes IDs and appends to an audit log.
type memTx struct {
	consumed map[string]bool
	log      *audit.Log
}

func (x *memTx) Consume(_ context.Context, id string) error {
	if x.consumed[id] {
		return authz.ErrReplayed
	}
	x.consumed[id] = true
	return nil
}

func (x *memTx) Append(ctx context.Context, r audit.Record) (audit.Entry, error) {
	return x.log.Append(ctx, r)
}

func TestAuthorize_EndToEnd(t *testing.T) { // CON-2, CON-7, SEC-10, NFR-5, SEC-11
	t.Parallel()
	w := newWorld(t.Context(), t)
	ctx := t.Context()
	newLog := func() *audit.Log {
		l, err := audit.New(audit.NewMemory(), func() time.Time { return t0 })
		if err != nil {
			t.Fatal(err)
		}
		return l
	}
	denials := newLog()
	rs := w.source(t, "/infra/ @alice\n/docs/ @bob\n")
	az, err := authz.New(authz.Config{Forge: fake.ForgeName, InstallID: "inst-1"}, rs, denials, func() time.Time { return t0 })
	if err != nil {
		t.Fatal(err)
	}
	repoID := string(w.repo)
	scope := authz.Scope{Kind: authz.ScopeRepo, ID: repoID}
	subject := audit.Subject{Kind: audit.SubjectChange, Repo: repoID, ID: "7"}
	tx := &memTx{consumed: map[string]bool{}, log: newLog()}
	decide := func(a forge.Actor, id string) authz.Decision {
		return authz.Decision{
			ID: "fake:issue-comment:" + id, Channel: authz.ChannelIssueComment,
			Principal: principal(a), Authenticated: true, Location: authz.Location{Scope: scope, Subject: subject},
			Operation: authz.OpApprovePathException, Revision: revA, Integrity: authz.IntegrityOriginal,
			Created: t0.Add(-time.Minute),
		}
	}
	tg := authz.Target{
		Operation: authz.OpApprovePathException, Scope: scope, Subject: subject, Revision: revA,
		Paths: []string{"infra/main.tf", "infra/net/vpc.tf"},
	}

	if _, err := az.Authorize(ctx, tx, decide(w.bob, "1"), tg); !errors.Is(err, authz.ErrDenied) {
		t.Errorf("non-owner: err = %v, want a denial", err)
	}
	if tx.consumed["fake:issue-comment:1"] {
		t.Error("a denied decision was consumed")
	}
	if _, err := az.Authorize(ctx, tx, decide(w.alice, "2"), tg); err != nil {
		t.Errorf("owner: %v", err)
	}
	mixed := tg
	mixed.Paths = []string{"infra/main.tf", "docs/a.md"}
	if _, err := az.Authorize(ctx, tx, decide(w.alice, "3"), mixed); !errors.Is(err, authz.ErrDenied) {
		t.Errorf("owner of one of two areas: err = %v, want a denial", err)
	}
	// A rename after the file named @alice denies the same approver at execution time.
	if err := w.fk.RenameActor(ctx, w.alice.ID, "alicia"); err != nil {
		t.Fatal(err)
	}
	if _, err := az.Authorize(ctx, tx, decide(w.alice, "4"), tg); !errors.Is(err, authz.ErrDenied) {
		t.Errorf("renamed owner: err = %v, want a denial", err)
	}
}

// stubTrees records Tree calls and serves one FS.
type stubTrees struct {
	calls int
	tree  fs.FS
}

func (s *stubTrees) Tree(context.Context, forge.RepoID, string) (fs.FS, error) {
	s.calls++
	return s.tree, nil
}

// plainFS exposes only Open, so it has no Lstat.
type plainFS struct{ fs.FS }

func TestLoad_ChecksTheSHABeforeTheForge(t *testing.T) { // CON-2, SEC-11
	t.Parallel()
	good40 := strings.Repeat("a", 40)
	for _, sha := range []string{"main", "abc123", "", strings.Repeat("A", 40), strings.Repeat("a", 39), strings.Repeat("g", 40), good40 + "\x1b[31m", "refs/heads/main"} {
		s := &stubTrees{tree: fstest.MapFS{}}
		f, err := codeowners.Load(t.Context(), s, "r1", sha)
		if f != nil || !errors.Is(err, forge.ErrInvalid) || s.calls != 0 {
			t.Errorf("Load(%q) = (%v, %v) after %d Tree calls, want ErrInvalid and none", sha, f, err, s.calls)
		}
		if err != nil && strings.ContainsRune(err.Error(), 0x1b) {
			t.Errorf("error for %q echoes a raw control character", sha)
		}
	}
	for _, sha := range []string{good40, strings.Repeat("0", 64)} {
		s := &stubTrees{tree: fstest.MapFS{}}
		if _, err := codeowners.Load(t.Context(), s, "r1", sha); err != nil || s.calls != 1 {
			t.Errorf("Load(%q) = %v after %d Tree calls, want success after one", sha, err, s.calls)
		}
	}
}

func TestLoad_RequiresLstat(t *testing.T) { // CON-2, SEC-11
	t.Parallel()
	s := &stubTrees{tree: plainFS{fstest.MapFS{"CODEOWNERS": {Data: []byte("* @a\n")}}}}
	f, err := codeowners.Load(t.Context(), s, "r1", strings.Repeat("a", 40))
	if f != nil || !errors.Is(err, forge.ErrUnsupported) {
		t.Errorf("Load = (%v, %v), want ErrUnsupported", f, err)
	}
}

func TestHasRole_MoreDenials(t *testing.T) { // SEC-10, SEC-11, NFR-5
	t.Parallel()
	w := newWorld(t.Context(), t)
	ctx := t.Context()
	boom := errors.New("boom")
	file := w.load(ctx, t, "/u/ @alice\n/t/ @acme/core\n")
	if err := w.fk.AddTeamMember(ctx, "acme", "core", w.alice.ID); err != nil {
		t.Fatal(err)
	}
	if err := w.fk.SetTeamRepoPermission(ctx, w.repo, "acme", "core", forge.PermWrite); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name    string
		ids     codeowners.IdentityReader
		path    string
		want    bool
		wantErr error
	}{
		{"baseline user", w.fk, "u/x", true, nil},
		{"baseline team", w.fk, "t/x", true, nil},
		{"unknown permission denies a user", &failingIDs{IdentityReader: w.fk, unknownPerm: true}, "u/x", false, nil},
		{"unknown permission denies a team", &failingIDs{IdentityReader: w.fk, unknownPerm: true}, "t/x", false, nil},
		{"GetRepo error denies a team", &failingIDs{IdentityReader: w.fk, repoErr: boom}, "t/x", false, boom},
		{"GetTeam error", &failingIDs{IdentityReader: w.fk, getTeamErr: boom}, "t/x", false, boom},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ok, err := codeowners.NewRoleSource(file, tc.ids).HasRole(ctx, principal(w.alice), authz.RoleCodeOwner, w.target(tc.path))
			if ok != tc.want || !errors.Is(err, tc.wantErr) || (tc.wantErr == nil && err != nil) {
				t.Errorf("HasRole = (%v, %v), want (%v, %v)", ok, err, tc.want, tc.wantErr)
			}
		})
	}
}

func TestHasRole_SecretTeam(t *testing.T) { // SEC-11: GitHub ignores secret teams
	t.Parallel()
	w := newWorld(t.Context(), t)
	ctx := t.Context()
	rs := w.source(t, "/t/ @acme/core\n")
	if err := w.fk.AddTeamMember(ctx, "acme", "core", w.alice.ID); err != nil {
		t.Fatal(err)
	}
	if err := w.fk.SetTeamRepoPermission(ctx, w.repo, "acme", "core", forge.PermAdmin); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		privacy forge.TeamPrivacy
		want    bool
	}{{forge.PrivacyVisible, true}, {forge.PrivacySecret, false}} {
		if err := w.fk.SetTeam(ctx, "acme", "core", tc.privacy); err != nil {
			t.Fatal(err)
		}
		if ok, err := rs.HasRole(ctx, principal(w.alice), authz.RoleCodeOwner, w.target("t/x")); err != nil || ok != tc.want {
			t.Errorf("%s team: (%v, %v), want (%v, nil)", tc.privacy, ok, err, tc.want)
		}
	}
}

// unknownPrivacyIDs answers a team with unknown privacy.
type unknownPrivacyIDs struct{ codeowners.IdentityReader }

func (u unknownPrivacyIDs) GetTeam(_ context.Context, org, team string) (forge.Team, error) {
	return forge.Team{Org: org, Slug: team}, nil
}

func TestHasRole_UnknownTeamPrivacy(t *testing.T) { // SEC-11
	t.Parallel()
	w := newWorld(t.Context(), t)
	ctx := t.Context()
	f := w.load(ctx, t, "/t/ @acme/core\n")
	if err := w.fk.AddTeamMember(ctx, "acme", "core", w.alice.ID); err != nil {
		t.Fatal(err)
	}
	if err := w.fk.SetTeamRepoPermission(ctx, w.repo, "acme", "core", forge.PermAdmin); err != nil {
		t.Fatal(err)
	}
	rs := codeowners.NewRoleSource(f, unknownPrivacyIDs{w.fk})
	if ok, err := rs.HasRole(ctx, principal(w.alice), authz.RoleCodeOwner, w.target("t/x")); err != nil || ok {
		t.Errorf("unknown privacy: (%v, %v), want (false, nil)", ok, err)
	}
}

func TestHasRole_UnknownTeamIsNotOwner(t *testing.T) { // SEC-11
	t.Parallel()
	w := newWorld(t.Context(), t)
	rs := w.source(t, "/t/ @acme/ghosts\n")
	if ok, err := rs.HasRole(t.Context(), principal(w.alice), authz.RoleCodeOwner, w.target("t/x")); err != nil || ok {
		t.Errorf("team that does not exist: (%v, %v), want (false, nil)", ok, err)
	}
}

func TestHasRole_RepoOwnerCaseAndChange(t *testing.T) { // SEC-10, NFR-5
	t.Parallel()
	w := newWorld(t.Context(), t)
	ctx := t.Context()
	rs := w.source(t, "/t/ @acme/core\n")
	if err := w.fk.AddTeamMember(ctx, "acme", "core", w.alice.ID); err != nil {
		t.Fatal(err)
	}
	if err := w.fk.SetTeamRepoPermission(ctx, w.repo, "acme", "core", forge.PermWrite); err != nil {
		t.Fatal(err)
	}
	if err := w.fk.SetRepoOwner(ctx, w.repo, "Acme"); err != nil {
		t.Fatal(err)
	}
	if ok, err := rs.HasRole(ctx, principal(w.alice), authz.RoleCodeOwner, w.target("t/x")); err != nil || !ok {
		t.Fatalf("owner Acme against @acme/core: (%v, %v), want true", ok, err)
	}
	if err := w.fk.SetRepoOwner(ctx, w.repo, "elsewhere"); err != nil {
		t.Fatal(err)
	}
	if ok, err := rs.HasRole(ctx, principal(w.alice), authz.RoleCodeOwner, w.target("t/x")); err != nil || ok {
		t.Errorf("after the repo moved to another owner: (%v, %v), want false", ok, err)
	}
}

func TestHasRole_UnboundFileWithEmptyScope(t *testing.T) { // SEC-10
	t.Parallel()
	w := newWorld(t.Context(), t)
	f, err := codeowners.Parse("CODEOWNERS", []byte("* @alice\n"))
	if err != nil {
		t.Fatal(err)
	}
	tg := authz.Target{Scope: authz.Scope{Kind: authz.ScopeRepo, ID: ""}, Paths: []string{"a"}}
	if ok, err := codeowners.NewRoleSource(f, w.fk).HasRole(t.Context(), principal(w.alice), authz.RoleCodeOwner, tg); ok || err != nil {
		t.Errorf("HasRole = (%v, %v), want (false, nil)", ok, err)
	}
}

func TestHasRole_TeamLookupCap(t *testing.T) { // SEC-10: bounded work, and the cap is never a grant
	t.Parallel()
	w := newWorld(t.Context(), t)
	ctx := t.Context()
	var sb strings.Builder
	for i := range codeowners.MaxTeamLookups + 1 {
		fmt.Fprintf(&sb, "/p%d/ @acme/t%d\n", i, i)
	}
	f := w.load(ctx, t, sb.String())
	paths := make([]string, 0, codeowners.MaxTeamLookups+1)
	for i := range codeowners.MaxTeamLookups + 1 {
		paths = append(paths, fmt.Sprintf("p%d/x", i))
		if err := w.fk.AddTeamMember(ctx, "acme", fmt.Sprintf("t%d", i), w.alice.ID); err != nil {
			t.Fatal(err)
		}
		if err := w.fk.SetTeamRepoPermission(ctx, w.repo, "acme", fmt.Sprintf("t%d", i), forge.PermWrite); err != nil {
			t.Fatal(err)
		}
	}
	rs := codeowners.NewRoleSource(f, w.fk)
	if ok, err := rs.HasRole(ctx, principal(w.alice), authz.RoleCodeOwner, w.target(paths[:codeowners.MaxTeamLookups]...)); err != nil || !ok {
		t.Errorf("exactly the cap: (%v, %v), want true", ok, err)
	}
	if ok, err := rs.HasRole(ctx, principal(w.alice), authz.RoleCodeOwner, w.target(paths...)); ok || !errors.Is(err, forge.ErrTooLarge) {
		t.Errorf("over the cap: (%v, %v), want (false, ErrTooLarge)", ok, err)
	}
}

func TestHasRole_HiddenTeamNotCachedAcrossPaths(t *testing.T) { // SEC-11
	t.Parallel()
	ctx := t.Context()
	for _, tc := range []struct {
		name  string
		setup func(*testing.T, *world)
	}{
		{"secret", func(t *testing.T, w *world) {
			t.Helper()
			if err := w.fk.SetTeam(ctx, "acme", "hidden", forge.PrivacySecret); err != nil {
				t.Fatal(err)
			}
		}},
		{"nonexistent", func(*testing.T, *world) {}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			w := newWorld(ctx, t)
			rs := codeowners.NewRoleSource(w.load(ctx, t, "/a/ @acme/hidden @alice\n/b/ @acme/hidden\n"), w.fk)
			if err := w.fk.AddTeamMember(ctx, "acme", "hidden", w.alice.ID); err != nil {
				t.Fatal(err)
			}
			if err := w.fk.SetTeamRepoPermission(ctx, w.repo, "acme", "hidden", forge.PermAdmin); err != nil {
				t.Fatal(err)
			}
			tc.setup(t, w)
			if tc.name == "nonexistent" {
				// AddTeamMember creates the team in the fake, so ask a reader that has no such team.
				rs = codeowners.NewRoleSource(w.load(ctx, t, "/a/ @acme/hidden @alice\n/b/ @acme/hidden\n"), noTeams{w.fk})
			}
			if ok, err := rs.HasRole(ctx, principal(w.alice), authz.RoleCodeOwner, w.target("a/x", "b/x")); err != nil || ok {
				t.Errorf("HasRole = (%v, %v), want (false, nil)", ok, err)
			}
		})
	}
	t.Run("unknown privacy", func(t *testing.T) {
		t.Parallel()
		w := newWorld(ctx, t)
		f := w.load(ctx, t, "/a/ @acme/hidden @alice\n/b/ @acme/hidden\n")
		if err := w.fk.AddTeamMember(ctx, "acme", "hidden", w.alice.ID); err != nil {
			t.Fatal(err)
		}
		if err := w.fk.SetTeamRepoPermission(ctx, w.repo, "acme", "hidden", forge.PermAdmin); err != nil {
			t.Fatal(err)
		}
		rs := codeowners.NewRoleSource(f, unknownPrivacyIDs{w.fk})
		if ok, err := rs.HasRole(ctx, principal(w.alice), authz.RoleCodeOwner, w.target("a/x", "b/x")); err != nil || ok {
			t.Errorf("HasRole = (%v, %v), want (false, nil)", ok, err)
		}
	})
}

// noTeams answers every GetTeam with ErrNotFound.
type noTeams struct{ codeowners.IdentityReader }

func (noTeams) GetTeam(context.Context, string, string) (forge.Team, error) {
	return forge.Team{}, forge.ErrNotFound
}

func TestHasRole_TeamPermissionThresholds(t *testing.T) { // SEC-11
	t.Parallel()
	w := newWorld(t.Context(), t)
	ctx := t.Context()
	rs := w.source(t, "/t/ @acme/core\n")
	if err := w.fk.AddTeamMember(ctx, "acme", "core", w.alice.ID); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		p    forge.Permission
		want bool
	}{
		{forge.PermNone, false},
		{forge.PermRead, false},
		{forge.PermTriage, false},
		{forge.PermWrite, true},
		{forge.PermMaintain, true},
		{forge.PermAdmin, true},
	} {
		if err := w.fk.SetTeamRepoPermission(ctx, w.repo, "acme", "core", tc.p); err != nil {
			t.Fatal(err)
		}
		if ok, err := rs.HasRole(ctx, principal(w.alice), authz.RoleCodeOwner, w.target("t/x")); err != nil || ok != tc.want {
			t.Errorf("team permission %s: (%v, %v), want (%v, nil)", tc.p, ok, err, tc.want)
		}
	}
}

func TestHasRole_PathBudgets(t *testing.T) { // SEC-10: bounded work, and a budget is never a grant
	t.Parallel()
	w := newWorld(t.Context(), t)
	ctx := t.Context()
	rs := w.source(t, "* @alice\n")
	paths := make([]string, 0, codeowners.MaxPaths+1)
	for i := range codeowners.MaxPaths + 1 {
		paths = append(paths, fmt.Sprintf("p/%d", i))
	}
	if ok, err := rs.HasRole(ctx, principal(w.alice), authz.RoleCodeOwner, w.target(paths[:codeowners.MaxPaths]...)); err != nil || !ok {
		t.Errorf("exactly %d distinct paths: (%v, %v), want true", codeowners.MaxPaths, ok, err)
	}
	if ok, err := rs.HasRole(ctx, principal(w.alice), authz.RoleCodeOwner, w.target(paths...)); ok || !errors.Is(err, forge.ErrTooLarge) {
		t.Errorf("over the path cap: (%v, %v), want (false, ErrTooLarge)", ok, err)
	}
	dup := make([]string, 0, 3*codeowners.MaxPaths)
	for range 3 * codeowners.MaxPaths {
		dup = append(dup, "p/same")
	}
	if ok, err := rs.HasRole(ctx, principal(w.alice), authz.RoleCodeOwner, w.target(dup...)); err != nil || !ok {
		t.Errorf("duplicates count once: (%v, %v), want true", ok, err)
	}

	// Pattern work: the owning rule comes first, so every later rule is tried and fails before it is reached.
	var sb strings.Builder
	sb.WriteString("* @alice\n")
	for i := range 495 {
		fmt.Fprintf(&sb, "/%s%d @alice\n", strings.Repeat("q", 195), i%10)
	}
	f := w.load(ctx, t, sb.String())
	heavy := codeowners.NewRoleSource(f, w.fk)
	long := func(c string) string { return strings.TrimSuffix(strings.Repeat(strings.Repeat(c, 250)+"/", 16), "/") }
	if ok, err := heavy.HasRole(ctx, principal(w.alice), authz.RoleCodeOwner, w.target(long("b"))); err != nil || !ok {
		t.Errorf("one long path: (%v, %v), want true", ok, err)
	}
	many := []string{long("b"), long("c"), long("d"), long("e"), long("f"), long("g"), long("h")}
	if ok, err := heavy.HasRole(ctx, principal(w.alice), authz.RoleCodeOwner, w.target(many...)); ok || !errors.Is(err, forge.ErrTooLarge) {
		t.Errorf("over the work budget: (%v, %v), want (false, ErrTooLarge)", ok, err)
	}
}

func TestErrors_EscapeUntrustedPaths(t *testing.T) { // SEC-1
	t.Parallel()
	w := newWorld(t.Context(), t)
	ctx := t.Context()
	bad := "@acme/everyone/" + strings.Repeat("b", 300)
	rs := w.source(t, "* @alice\n")
	_, err := rs.HasRole(ctx, principal(w.alice), authz.RoleCodeOwner, w.target(bad))
	if err == nil || strings.ContainsAny(err.Error(), "@#") || !errors.Is(err, pathglob.ErrInvalidPath) {
		t.Errorf("HasRole error = %v, want an escaped error that wraps ErrInvalidPath", err)
	}
	f := w.load(ctx, t, "* @alice\n")
	_, _, err = f.Owners(ctx, bad)
	if err == nil || strings.ContainsAny(err.Error(), "@#") || !errors.Is(err, pathglob.ErrInvalidPath) {
		t.Errorf("Owners error = %v, want an escaped error that wraps ErrInvalidPath", err)
	}
}
