// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

package install

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"maps"
	"slices"
	"time"

	"github.com/elliott-davis/lightsout/internal/authz"
	"github.com/elliott-davis/lightsout/internal/contract"
)

// Config is a validated install config. It is immutable and safe for concurrent use: every method returns copies.
type Config struct {
	installation Installation
	manifest     string
	revision     string

	quorum    int
	approvers []Person
	admins    []Person

	timers           Timers
	quotas           Quotas
	contractDefaults contract.Defaults

	baseline struct {
		verify, union []installGate
		reviewers     [2]string // pr, security
		known         []string
		protected     []string
	}
	registry map[contract.GateRef]bool

	expiry        map[authz.Operation]time.Duration
	denialTimeout time.Duration

	keys  map[string]ed25519.PublicKey
	roles map[string]RoleProfile
}

// WithRevision returns a copy of c that carries revision, the commit the install config was read from (40 or 64
// lowercase hex digits). The revision is part of the policy identity: Baseline carries it, so every Effective
// contract and the trust digest bind to it (RUN-1).
func (c *Config) WithRevision(revision string) (*Config, error) {
	if !revisionPattern.MatchString(revision) {
		return nil, fmt.Errorf("install revision %s must be 40 or 64 lowercase hex digits", q(revision))
	}
	out := *c
	out.revision = revision
	return &out, nil
}

// Revision returns the install revision, or "" if none was set.
func (c *Config) Revision() string { return c.revision }

// Installation returns the installation's ID and forge.
func (c *Config) Installation() Installation {
	i := c.installation
	i.ForgeHosts = slices.Clone(i.ForgeHosts)
	return i
}

// DeploymentManifest returns the digest of the deployment manifest (WI-29 resolves and verifies it).
func (c *Config) DeploymentManifest() string { return c.manifest }

// ErrNoRevision is returned by [Config.Baseline] for a config that has no install revision. Every decision and piece of
// evidence binds to the install revision (RUN-1), so a baseline without one must never reach production.
var ErrNoRevision = errors.New("install: config has no install revision")

// Baseline returns the factory baseline for contract.Compile, with the install revision (CON-5, AGD-3, SEC-4). It
// returns [ErrNoRevision] unless the config was loaded with [Load] or given a revision with [Config.WithRevision].
func (c *Config) Baseline() (contract.Baseline, error) {
	if c.revision == "" {
		return contract.Baseline{}, ErrNoRevision
	}
	return c.baselineWith(c.revision), nil
}

// baselineWith builds the baseline carrying revision, which may be empty for validation inside Parse.
func (c *Config) baselineWith(revision string) contract.Baseline {
	gates := func(in []installGate) []contract.Gate {
		if in == nil {
			return nil
		}
		out := make([]contract.Gate, len(in))
		for i, g := range in {
			out[i] = contract.Gate{Name: g.Name, GateRef: g.GateRef, Mandatory: g.Mandatory}
		}
		return out
	}
	return contract.Baseline{
		Verify:           gates(c.baseline.verify),
		Union:            gates(c.baseline.union),
		Reviewers:        []string{c.baseline.reviewers[0], c.baseline.reviewers[1]},
		PRReviewer:       c.baseline.reviewers[0],
		SecurityReviewer: c.baseline.reviewers[1],
		Protected:        slices.Clone(c.baseline.protected),
		KnownAgents:      slices.Clone(c.baseline.known),
		InstallRevision:  revision,
	}
}

// Defaults returns the install-wide contract defaults (CON-9).
func (c *Config) Defaults() contract.Defaults { return c.contractDefaults }

// GateRegistry returns the registry of gate identities at pinned revisions (CON-4). It is a snapshot.
func (c *Config) GateRegistry() contract.GateRegistry {
	return registry(maps.Clone(c.registry))
}

type registry map[contract.GateRef]bool

func (r registry) Registered(ctx context.Context, ref contract.GateRef) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	return r[ref], nil
}

// AuthzConfig returns the authz.Config of the installation: forge, install ID, per-operation expiry (none by
// default) and the denial audit timeout.
func (c *Config) AuthzConfig() authz.Config {
	return authz.Config{
		Forge:              c.installation.Forge,
		InstallID:          c.installation.ID,
		Expiry:             maps.Clone(c.expiry),
		DenialAuditTimeout: c.denialTimeout,
	}
}

// Admins returns the emergency admins (SEC-6).
func (c *Config) Admins() []Person { return slices.Clone(c.admins) }

// Approvers are the install policy approvers and the quorum an activation needs.
type Approvers struct {
	Members []Person
	Quorum  int
}

// PolicyApprovers returns the policy approvers (Enterprise IT) and the quorum. Authz proves one approver per
// decision. The activation path counts quorum distinct granted decisions from members of the active revision.
func (c *Config) PolicyApprovers() Approvers {
	return Approvers{Members: slices.Clone(c.approvers), Quorum: c.quorum}
}

// RoleSource returns an authz.RoleSource that grants authz.RoleAdmin to the admins and authz.RolePolicyApprover to
// the policy approvers, matched by (forge, ID) and never by login. It grants nothing else, and only for this
// installation's scope. Build it from the active revision at execution time: membership of a candidate revision
// never counts.
func (c *Config) RoleSource() authz.RoleSource {
	s := &roleSource{install: c.installation, admins: map[Person]bool{}, approvers: map[Person]bool{}}
	for _, p := range c.admins {
		s.admins[p] = true
	}
	for _, p := range c.approvers {
		s.approvers[p] = true
	}
	return s
}

type roleSource struct {
	install   Installation
	admins    map[Person]bool
	approvers map[Person]bool
}

// HasRole implements authz.RoleSource.
func (s *roleSource) HasRole(ctx context.Context, p authz.Principal, r authz.Role, t authz.Target) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if p.Kind != authz.PrincipalUser || t.Scope.Kind != authz.ScopeInstall || t.Scope.ID != s.install.ID {
		return false, nil
	}
	who := Person{Forge: p.Forge, ID: p.ID}
	if r == authz.RoleAdmin {
		return s.admins[who], nil
	}
	if r == authz.RolePolicyApprover {
		return s.approvers[who], nil
	}
	return false, nil
}

// Timers returns the caps and breakers, defaults applied.
func (c *Config) Timers() Timers { return c.timers }

// Quotas returns the concurrency quotas and the CI rate limit.
func (c *Config) Quotas() Quotas {
	q := c.quotas
	q.Teams = slices.Clone(q.Teams)
	return q
}

// Role returns the enabled role called name. A role that is not listed is not enabled.
func (c *Config) Role(name string) (RoleProfile, bool) {
	r, ok := c.roles[name]
	if !ok {
		return RoleProfile{}, false
	}
	r = r.clone()
	r.Manifest = c.manifest
	return r, true
}

// Roles returns the names of the enabled roles, sorted.
func (c *Config) Roles() []string {
	return slices.Sorted(maps.Keys(c.roles))
}
