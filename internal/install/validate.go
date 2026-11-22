// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

package install

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"maps"
	"net/netip"
	pathpkg "path"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/elliott-davis/lightsout/internal/authz"
	"github.com/elliott-davis/lightsout/internal/codeowners"
	"github.com/elliott-davis/lightsout/internal/contract"
	"github.com/elliott-davis/lightsout/internal/pathglob"
)

// emptyRevision is the revision of the empty contract set the baseline is checked against. It names no commit.
const emptyRevision = "0000000000000000000000000000000000000000"

// keyBase64 and sigBase64 are the only accepted spellings of a public key and a signature: canonical padded base64
// with no whitespace, which the decoder alone would skip over (CR and LF).
var (
	keyBase64 = regexp.MustCompile(`^[A-Za-z0-9+/]{43}=$`)
	sigBase64 = regexp.MustCompile(`^[A-Za-z0-9+/]{86}==$`)
)

// githubID is the form of a GitHub account ID.
var githubID = regexp.MustCompile(`^[1-9]\d{0,19}$`)

var revisionPattern = regexp.MustCompile(`^([0-9a-f]{40}|[0-9a-f]{64})$`)

// DefaultProtected returns the protected patterns used when the install config gives none: workflows, actions and
// every CODEOWNERS location. A product PR must not be able to add or change any of them, because an earlier location
// takes precedence over a later one.
func DefaultProtected() []string {
	return append([]string{".github/workflows/**", ".github/actions/**"}, codeowners.Locations()...)
}

// build applies the defaults and the semantic rules to a decoded document. It reports every problem it finds.
func build(doc *document) (*Config, []Problem) {
	c := &collector{}
	cfg := &Config{
		installation: doc.Installation,
		manifest:     doc.DeploymentManifest,
		roles:        make(map[string]RoleProfile, len(doc.Roles)),
	}

	cfg.checkPeople(c, doc)
	cfg.checkTimersAndQuotas(c, doc)
	cfg.checkRoles(c, doc)
	cfg.checkQualifierKeys(c, doc)
	cfg.checkDecisions(c, doc)
	cfg.checkRegistry(c, doc)
	cfg.checkBaseline(c, doc)

	cfg.contractDefaults = contract.Defaults{
		SwitchStaleDays:     doc.ContractDefaults.SwitchStaleDays,
		SwitchAbandonedDays: doc.ContractDefaults.SwitchAbandonedDays,
		ReviewBudgetLines:   doc.ContractDefaults.ReviewBudgetLines,
	}
	if len(c.problems) == 0 {
		cfg.checkWithContract(c)
	}
	if len(c.problems) > 0 {
		return nil, c.problems
	}
	return cfg, nil
}

func orDefault(v *int, def int) int {
	if v == nil {
		return def
	}
	return *v
}

// checkPeople validates the policy approvers and the admins (SEC-6).
func (cfg *Config) checkPeople(c *collector, doc *document) {
	forge := doc.Installation.Forge
	people := func(list []Person, parts ...string) []Person {
		seen := map[Person]bool{}
		for i, p := range list {
			idx := append(slices.Clone(parts), strconv.Itoa(i))
			if p.Forge != forge {
				c.addf(CodeInvalid, append(idx, "forge"), "forge %s is not the installation's forge %s", q(p.Forge), q(forge))
			}
			if p.Forge == "github" && !githubID.MatchString(p.ID) {
				c.addf(CodeInvalid, append(idx, "id"), "a GitHub person is the numeric account ID, never a login: %s", q(p.ID))
			}
			if seen[p] {
				c.addf(CodeDuplicate, idx, "person %s on forge %s is listed twice", q(p.ID), q(p.Forge))
			}
			seen[p] = true
		}
		return slices.Clone(list)
	}
	cfg.approvers = people(doc.PolicyApprovers.Members, "policyApprovers", "members")
	cfg.admins = people(doc.Admins, "admins")
	cfg.quorum = orDefault(doc.PolicyApprovers.Quorum, DefaultQuorum)
	if cfg.quorum < 1 || cfg.quorum > len(cfg.approvers) {
		c.addf(CodeInvalid, at("policyApprovers", "quorum"),
			"quorum %d must be at least 1 and at most the %d listed members", cfg.quorum, len(cfg.approvers))
	}
	if len(cfg.approvers) == 0 {
		c.addf(CodeMissing, at("policyApprovers", "members"), "at least one policy approver is required")
	}
	if len(cfg.admins) == 0 {
		c.addf(CodeMissing, at("admins"), "at least one admin is required")
	}
}

// checkTimersAndQuotas applies the PRD defaults and checks the quota team IDs.
func (cfg *Config) checkTimersAndQuotas(c *collector, doc *document) {
	t := doc.Timers
	cfg.timers = Timers{
		ReviewRounds:            orDefault(t.ReviewRounds, DefaultReviewRounds),
		Replans:                 orDefault(t.Replans, DefaultReplans),
		AcceptanceRepairs:       orDefault(t.AcceptanceRepairs, DefaultAcceptanceRepairs),
		InverseRetries:          orDefault(t.InverseRetries, DefaultInverseRetries),
		SameGateFailures:        t.SameGateFailures,
		NoProgressIterations:    orDefault(t.NoProgressIterations, DefaultNoProgressIterations),
		SpendOverEstimateFactor: orDefault(t.SpendOverEstimateFactor, DefaultSpendOverEstimateFactor),
	}
	// The schema already holds every value to at least 1. Check again where it is cheap: a rule that lives in
	// one place only is a rule that a schema edit can silently drop.
	for _, f := range []struct {
		name string
		v    int
	}{
		{"reviewRounds", cfg.timers.ReviewRounds},
		{"replans", cfg.timers.Replans},
		{"acceptanceRepairs", cfg.timers.AcceptanceRepairs},
		{"inverseRetries", cfg.timers.InverseRetries},
		{"sameGateFailures", cfg.timers.SameGateFailures},
		{"noProgressIterations", cfg.timers.NoProgressIterations},
		{"spendOverEstimateFactor", cfg.timers.SpendOverEstimateFactor},
	} {
		if f.v < 1 {
			c.addf(CodeInvalid, at("timers", f.name), "must be at least 1, got %d", f.v)
		}
	}
	q2 := doc.Quotas
	cfg.quotas = Quotas{Teams: slices.Clone(q2.Teams), DefaultTeam: q2.DefaultTeam, CIRunsPerPRPerHour: q2.CIRunsPerPRPerHour}
	seen := map[string]bool{}
	for i, tm := range q2.Teams {
		idx := strconv.Itoa(i)
		if seen[tm.TeamID] {
			c.addf(CodeDuplicate, at("quotas", "teams", idx, "teamId"), "team %s is listed twice", q(tm.TeamID))
		}
		seen[tm.TeamID] = true
		if !strings.HasPrefix(tm.TeamID, doc.Installation.Forge+":") {
			c.addf(CodeInvalid, at("quotas", "teams", idx, "teamId"), "team %s is not on the installation's forge %s", q(tm.TeamID), q(doc.Installation.Forge))
		}
		if tm.AgentSessions < 1 || tm.CIRuns < 1 {
			c.addf(CodeInvalid, at("quotas", "teams", idx), "quota values must be at least 1")
		}
	}
	if q2.DefaultTeam.AgentSessions < 1 || q2.DefaultTeam.CIRuns < 1 {
		c.addf(CodeInvalid, at("quotas", "defaultTeam"), "quota values must be at least 1")
	}
	if q2.CIRunsPerPRPerHour < 1 {
		c.addf(CodeInvalid, at("quotas", "ciRunsPerPRPerHour"), "must be at least 1, got %d", q2.CIRunsPerPRPerHour)
	}
	d := doc.ContractDefaults
	for _, f := range []struct {
		name string
		v    int
	}{{"switchStaleDays", d.SwitchStaleDays}, {"switchAbandonedDays", d.SwitchAbandonedDays}, {"reviewBudgetLines", d.ReviewBudgetLines}} {
		if f.v < 1 {
			c.addf(CodeInvalid, at("contractDefaults", f.name), "must be at least 1, got %d", f.v)
		}
	}
}

// checkDecisions checks the authz settings.
func (cfg *Config) checkDecisions(c *collector, doc *document) {
	known := map[string]bool{}
	for _, op := range authz.Operations() {
		known[string(op)] = true
	}
	cfg.expiry = map[authz.Operation]time.Duration{}
	for _, name := range slices.Sorted(maps.Keys(doc.Decisions.Expiry)) {
		secs := doc.Decisions.Expiry[name]
		if !known[name] {
			c.addf(CodeInvalid, at("decisions", "expiry", name), "unknown operation %s", q(name))
			continue
		}
		if secs < 1 {
			c.addf(CodeInvalid, at("decisions", "expiry", name), "must be at least 1 second, got %d", secs)
			continue
		}
		cfg.expiry[authz.Operation(name)] = time.Duration(secs) * time.Second
	}
	timeout := orDefault(doc.Decisions.DenialAuditTimeoutSeconds, DefaultDenialAuditTimeoutSeconds)
	if timeout < 1 {
		c.addf(CodeInvalid, at("decisions", "denialAuditTimeoutSeconds"), "must be at least 1, got %d", timeout)
	}
	cfg.denialTimeout = time.Duration(timeout) * time.Second
}

// checkQualifierKeys decodes the qualification runners' public keys.
func (cfg *Config) checkQualifierKeys(c *collector, doc *document) {
	cfg.keys = map[string]ed25519.PublicKey{}
	for i, k := range doc.QualifierKeys {
		idx := strconv.Itoa(i)
		if _, dup := cfg.keys[k.ID]; dup {
			c.addf(CodeDuplicate, at("qualifierKeys", idx, "id"), "key ID %s is listed twice", q(k.ID))
			continue
		}
		raw, err := base64.StdEncoding.Strict().DecodeString(k.Key)
		if !keyBase64.MatchString(k.Key) || err != nil || len(raw) != ed25519.PublicKeySize {
			c.addf(CodeInvalid, at("qualifierKeys", idx, "key"), "must be the canonical base64 of a %d-byte ed25519 public key", ed25519.PublicKeySize)
			continue
		}
		if smallOrder(raw) {
			c.addf(CodeInvalid, at("qualifierKeys", idx, "key"), "is a small-order point, which verifies forged signatures: use a real public key")
			continue
		}
		cfg.keys[k.ID] = ed25519.PublicKey(raw)
	}
	if len(doc.QualifierKeys) == 0 {
		c.addf(CodeMissing, at("qualifierKeys"), "at least one qualifier key is required")
	}
}

// checkRegistry checks the gate registry (CON-4): each gate identity at a pinned revision once.
func (cfg *Config) checkRegistry(c *collector, doc *document) {
	cfg.registry = make(map[contract.GateRef]bool, len(doc.GateRegistry))
	for i, ref := range doc.GateRegistry {
		idx := strconv.Itoa(i)
		if !revisionPattern.MatchString(ref.WorkflowRevision) {
			c.addf(CodeInvalid, at("gateRegistry", idx, "workflowRevision"), "must be a full 40 or 64 digit lowercase hex commit ID")
		}
		if ref.ProducerID == "" || ref.WorkflowID == "" || ref.CheckID == "" {
			c.addf(CodeMissing, at("gateRegistry", idx), "producerId, workflowId and checkId must not be empty")
		}
		if cfg.registry[ref] {
			c.addf(CodeDuplicate, at("gateRegistry", idx), "gate %s at revision %s is registered twice", q(ref.CheckID), q(ref.WorkflowRevision))
		}
		cfg.registry[ref] = true
	}
}

// checkBaseline checks the factory baseline (SEC-4, CON-5, AGD-3). It runs after the roles and the registry are known.
func (cfg *Config) checkBaseline(c *collector, doc *document) {
	b := doc.Baseline
	cfg.baseline.reviewers = [2]string{b.Reviewers.PR, b.Reviewers.Security}
	cfg.baseline.known = slices.Clone(b.KnownAgents)
	cfg.baseline.protected = DefaultProtected()
	if b.Protected != nil {
		cfg.baseline.protected = slices.Clone(*b.Protected)
	}
	cfg.checkBaselineGates(c, doc)
	cfg.checkReviewers(c, doc)
	if b.Protected != nil {
		for _, want := range DefaultProtected() {
			if !covers(*b.Protected, want) {
				c.addf(CodeInvalid, at("baseline", "protected"),
					"no pattern covers %s: a custom list must protect everything the default does, including every CODEOWNERS location (a product PR could add .github/CODEOWNERS, which takes precedence)", q(want))
			}
		}
	}
	for i, name := range b.KnownAgents {
		if _, ok := doc.Roles[name]; !ok {
			c.addf(CodeUnknownRole, at("baseline", "knownAgents", strconv.Itoa(i)),
				"known agent %s is not an enabled role, so it could never run", q(name))
		}
	}
}

// checkBaselineGates checks every baseline gate is mandatory and registered, and that both SEC-4 purposes are met.
func (cfg *Config) checkBaselineGates(c *collector, doc *document) {
	purposes := map[string]int{}
	check := func(stage string, in []installGate) []installGate {
		for i, g := range in {
			idx := strconv.Itoa(i)
			if !g.Mandatory {
				c.addf(CodeInvalid, at("baseline", stage, idx, "mandatory"), "a baseline gate must be mandatory, it cannot be advisory (CON-5)")
			}
			if !cfg.registry[g.GateRef] {
				c.addf(CodeUnregisteredGate, at("baseline", stage, idx),
					"baseline gate %s (producer %s, workflow %s, revision %s) is not in the gate registry",
					q(g.CheckID), q(g.ProducerID), q(string(g.WorkflowID)), q(g.WorkflowRevision))
			}
			if g.Purpose == "" {
				continue
			}
			if stage != "verify" {
				c.addf(CodeInvalid, at("baseline", stage, idx, "purpose"), "a purpose is only allowed on verify gates")
			}
			purposes[g.Purpose]++
			if purposes[g.Purpose] > 1 {
				c.addf(CodeDuplicate, at("baseline", stage, idx, "purpose"), "purpose %s is already satisfied by another gate", q(g.Purpose))
			}
		}
		return slices.Clone(in)
	}
	cfg.baseline.verify = check("verify", doc.Baseline.Verify)
	cfg.baseline.union = check("union", doc.Baseline.Union)
	for _, p := range []string{PurposeSecretScan, PurposeDependencyScan} {
		if purposes[p] == 0 {
			c.addf(CodeMissing, at("baseline", "verify"), "no mandatory verify gate has purpose %s (SEC-4)", q(p))
		}
	}
}

// checkReviewers checks the core reviewers are distinct and both enabled roles (AGD-3).
func (cfg *Config) checkReviewers(c *collector, doc *document) {
	rv := doc.Baseline.Reviewers
	if rv.PR == rv.Security {
		c.addf(CodeInvalid, at("baseline", "reviewers"), "the PR reviewer and the security reviewer must be different roles, both are %s (AGD-3)", q(rv.PR))
	}
	for _, r := range []struct{ field, name string }{{"pr", rv.PR}, {"security", rv.Security}} {
		if _, ok := doc.Roles[r.name]; !ok {
			c.addf(CodeUnknownRole, at("baseline", "reviewers", r.field), "reviewer role %s is not an enabled role (AGD-3)", q(r.name))
		}
	}
}

// covers reports whether some pattern protects everything want matches: want is a pattern, or an exact path, and
// a pattern covers it when it matches it, or a protected directory above it, by pathglob's containment proof (which
// fails closed).
func covers(patterns []string, want string) bool {
	inner, err := pathglob.Compile(want)
	if err != nil {
		return false
	}
	for _, p := range patterns {
		g, err := pathglob.Compile(p)
		if err != nil {
			continue // checkWithContract reports the bad pattern
		}
		if pathglob.Contains(g.WithDescendants(), inner) {
			return true
		}
	}
	return false
}

// checkWithContract runs contract's own baseline validation by compiling an empty contract set, so its rules are not
// copied here. It only runs once the baseline and defaults pass the checks above, which report the same faults more precisely.
func (cfg *Config) checkWithContract(c *collector) {
	set, err := contract.NewSet(emptyRevision)
	if err != nil {
		c.addf(CodeBaseline, nil, "build the empty contract set: %v", err)
		return
	}
	if _, err = contract.Compile(set, cfg.baselineWith(""), cfg.contractDefaults); err != nil {
		c.addf(CodeBaseline, at("baseline"), "%s", err.Error())
	}
}

// hostPortRE splits a validated host:port.
var hostPortRE = regexp.MustCompile(`^[^:]+:(\d{1,5})$`)

// checkRoles checks every enabled role (SEC-1, RUN-4, RUN-6, AGT-7).
func (cfg *Config) checkRoles(c *collector, doc *document) {
	for _, name := range slices.Sorted(maps.Keys(doc.Roles)) {
		r := doc.Roles[name]
		r.Name = name
		cfg.roles[name] = r.clone()
		// A role that reviews is read-only: the two core reviewers and every known agent (the specialist reviews of AGD-3).
		reviewer := name == doc.Baseline.Reviewers.PR || name == doc.Baseline.Reviewers.Security || slices.Contains(doc.Baseline.KnownAgents, name)
		cfg.checkRole(c, name, r, reviewer)
	}
	if len(doc.Roles) == 0 {
		c.addf(CodeMissing, at("roles"), "at least one role is required")
	}
}

func (cfg *Config) checkRole(c *collector, name string, r RoleProfile, reviewer bool) {
	if len(r.SandboxSecrets) > 0 {
		c.addf(CodeUnsafeRole, at("roles", name, "sandboxSecrets"),
			"must be empty: v1 roles hold no secrets in the sandbox, credentials are injected by the gateway (RUN-4, SEC-1)")
	}
	cfg.checkRoleNetwork(c, name, r)
	cfg.checkRoleProfile(c, name, r, reviewer)
	if r.Qualification == "" {
		c.addf(CodeMissing, at("roles", name, "qualification"), "every enabled role needs a qualification digest (NFR-2)")
	}
}

// checkRoleNetwork checks a role's egress hosts and gateway credentials (SEC-1, RUN-4).
func (cfg *Config) checkRoleNetwork(c *collector, name string, r RoleProfile) {
	egress := map[string]bool{}
	for i, h := range r.Egress.Hosts {
		egress[h] = true
		m := hostPortRE.FindStringSubmatch(h)
		if m == nil {
			c.addf(CodeUnsafeRole, at("roles", name, "egress", "hosts", strconv.Itoa(i)), "must be a literal host:port")
			continue
		}
		if port, _ := strconv.Atoi(m[1]); port < 1 || port > 65535 {
			c.addf(CodeUnsafeRole, at("roles", name, "egress", "hosts", strconv.Itoa(i)), "port must be 1 to 65535")
		}
		if why := unsafeHost(h); why != "" {
			c.addf(CodeUnsafeRole, at("roles", name, "egress", "hosts", strconv.Itoa(i)), "%s", why)
		}
		if cfg.isForgeHost(h) {
			c.addf(CodeUnsafeRole, at("roles", name, "egress", "hosts", strconv.Itoa(i)), "%s", forgeReason)
		}
	}
	credNames := map[string]bool{}
	for i, gc := range r.GatewayCredentials {
		idx := strconv.Itoa(i)
		if !egress[gc.Host] {
			c.addf(CodeUnsafeRole, at("roles", name, "gatewayCredentials", idx, "host"),
				"host %s is not in the role's egress list: a credential is bound to an exact host the role may reach (RUN-4)", q(gc.Host))
		}
		if cfg.isForgeHost(gc.Host) {
			c.addf(CodeUnsafeRole, at("roles", name, "gatewayCredentials", idx, "host"), "%s", forgeReason)
		}
		for j, op := range gc.Operations {
			if why := unsafeOperation(op); why != "" {
				c.addf(CodeUnsafeRole, at("roles", name, "gatewayCredentials", idx, "operations", strconv.Itoa(j)), "%s", why)
			}
		}
		if credNames[gc.Name] {
			c.addf(CodeDuplicate, at("roles", name, "gatewayCredentials", idx, "name"), "credential %s is listed twice", q(gc.Name))
		}
		credNames[gc.Name] = true
	}
}

// checkRoleProfile checks a role's pins: tools, permissions and floating versions (RUN-6, SEC-3).
func (cfg *Config) checkRoleProfile(c *collector, name string, r RoleProfile, reviewer bool) {
	tools := map[string]bool{}
	for i, t := range r.Profile.Tools {
		if tools[t.Name] {
			c.addf(CodeDuplicate, at("roles", name, "profile", "tools", strconv.Itoa(i), "name"), "tool %s is listed twice", q(t.Name))
		}
		tools[t.Name] = true
		if floating(t.Version, true) {
			c.addf(CodeInvalid, at("roles", name, "profile", "tools", strconv.Itoa(i), "version"), "%s is a floating version, pin an exact one (RUN-6)", q(t.Version))
		}
		for j, perm := range t.Permissions {
			if reviewer && perm == "branch:push-own" {
				c.addf(CodeUnsafeRole, at("roles", name, "profile", "tools", strconv.Itoa(i), "permissions", strconv.Itoa(j)),
					"a reviewer (a core reviewer or a known agent) is read-only and may not hold %s (SEC-3)", q(perm))
			}
		}
	}
	cfg.checkSeparation(c, name, r)
	if floating(r.Profile.Model.Name, false) {
		c.addf(CodeInvalid, at("roles", name, "profile", "model", "name"), "%s names a moving model, pin an exact one (RUN-6)", q(r.Profile.Model.Name))
	}
	if floating(r.Profile.Model.Revision, false) {
		c.addf(CodeInvalid, at("roles", name, "profile", "model", "revision"), "%s is a floating revision, pin an exact one (RUN-6)", q(r.Profile.Model.Revision))
	}
	if floating(r.Profile.Harness.Version, true) {
		c.addf(CodeInvalid, at("roles", name, "profile", "harness", "version"), "%s is a floating version, pin an exact one (RUN-6)", q(r.Profile.Harness.Version))
	}
}

// smallOrderPoints are the encodings of the ed25519 curve points of small order (the 8-torsion subgroup) with the sign
// bit clear, which libsodium calls its blacklist (ge25519_has_small_order, and the RFC 8032 and "Taming the many
// EdDSAs" analyses). A public key of small order makes signatures that verify for many messages. The list has the
// all-zero encoding, the identity (y=1), the two points of order 8, y=p-1 (order 2) and the two non-canonical
// encodings y=p and y=p+1 (p = 2^255-19). smallOrder masks the sign bit, so the sign variants are caught too.
// There is no standard library API for this and no dependency may be added.
func smallOrderPoints() [7][32]byte {
	hexs := [7]string{
		"0000000000000000000000000000000000000000000000000000000000000000",
		"0100000000000000000000000000000000000000000000000000000000000000",
		"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
		"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
		"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		"eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
	}
	var pts [7][32]byte
	for i, h := range hexs {
		b, err := hex.DecodeString(h)
		if err != nil || len(b) != 32 {
			panic("install: bad small-order table") // programmer error
		}
		copy(pts[i][:], b)
	}
	return pts
}

// smallOrder reports whether key is one of the small-order points, with either value of the sign bit.
func smallOrder(key []byte) bool {
	var k [32]byte
	copy(k[:], key)
	k[31] &= 0x7f
	pts := smallOrderPoints()
	return slices.Contains(pts[:], k)
}

// alwaysFloating are tokens that name a moving target wherever they appear in a version, revision or model name.
func alwaysFloating() []string {
	return []string{
		"latest", "stable", "default", "current", "main", "master", "head", "edge", "nightly", "x", "lts", "rolling", "tip",
		"release", "trunk", "develop", "unstable", "experimental",
	}
}

// prerelease are tokens that mark a moving build only when nothing numeric or dated follows them: canary alone floats,
// 15.0.0-canary.12 and o1-preview-2024-09-12 are pins.
func prerelease() []string {
	return []string{"beta", "canary", "next", "dev", "preview", "snapshot", "alpha", "rc"}
}

// bareMajor matches a version that is only a major number: 2, v1.
var bareMajor = regexp.MustCompile(`^v?\d+$`)

// floating reports whether v pins nothing. v is split on - _ . : / + @ and compared in any case. It floats if it starts
// with refs/ or origin/ (a git ref), has a heads token, has a * range, has a token from alwaysFloating, or has a
// prerelease token with no numeric token after it (so claude-3-5-sonnet-latest, llama3:latest, refs/heads/develop and
// 2.47-latest float, and 2.0.0-beta.1 and gemini-2.5-pro-preview-06-05 are pins). With majorIsFloating a bare major
// version (2, v1) floats too: that rule is for versions, not for model revisions, which are often plain numbers (0613).
func floating(v string, majorIsFloating bool) bool {
	lower := strings.ToLower(v)
	if strings.HasPrefix(lower, "refs/") || strings.HasPrefix(lower, "origin/") || strings.Contains(lower, "*") {
		return true
	}
	if majorIsFloating && bareMajor.MatchString(lower) {
		return true
	}
	toks := strings.FieldsFunc(lower, func(r rune) bool { return strings.ContainsRune("-_.:/+@", r) })
	for i, tok := range toks {
		switch {
		case tok == "heads" || slices.Contains(alwaysFloating(), tok):
			return true
		case slices.Contains(prerelease(), tok) && !slices.ContainsFunc(toks[i+1:], numericToken):
			return true
		}
	}
	return false
}

// numericToken reports whether a token is all digits.
func numericToken(t string) bool { return t != "" && strings.Trim(t, "0123456789") == "" }

// metadataNames are host names that reach a cloud, container or cluster metadata or loopback service.
func metadataNames() []string {
	return []string{
		"metadata", "metadata.google.internal", "metadata.goog", "instance-data", "instance-data.ec2.internal",
		"kubernetes", "kubernetes.default", "kubernetes.default.svc",
	}
}

// loopbackNames are host names that reach the machine itself.
func loopbackNames() []string {
	return []string{
		"localhost", "localhost.localdomain", "localhost4", "localhost6", "ip6-localhost", "ip6-loopback",
		"host.docker.internal", "gateway.docker.internal",
	}
}

// unsafeHost explains why a validated host:port must not be an egress target, or returns "". It reads the literal
// text only. WI-30 still owns denying a hostname that resolves to a loopback, link-local, multicast or metadata address:
// install validation can't see DNS.
func unsafeHost(hostPort string) string {
	host, port, _ := strings.Cut(hostPort, ":")
	switch {
	case len(port) > 1 && port[0] == '0':
		return "a port must be written without leading zeros"
	case slices.Contains(loopbackNames(), host) || strings.HasSuffix(host, ".localhost"):
		return "localhost is not a valid egress target"
	case slices.Contains(metadataNames(), host) || strings.HasSuffix(host, ".svc.cluster.local"):
		return "cloud, cluster and metadata endpoints are not valid egress targets"
	}
	last := host[strings.LastIndexByte(host, '.')+1:]
	if !numericLabel(last) {
		return ""
	}
	addr, err := netip.ParseAddr(host)
	if err != nil || !addr.Is4() || addr.String() != host {
		return "an IPv4 address must be canonical dotted decimal (no hex, octal, shortened or single-integer spelling)"
	}
	switch {
	case addr.IsLoopback():
		return "a loopback address is not a valid egress target"
	case addr.IsLinkLocalUnicast():
		return "a link-local address (including the metadata address 169.254.169.254) is not a valid egress target"
	case addr.IsUnspecified() || addr.As4()[0] == 0:
		return "the 0.0.0.0/8 range is not a valid egress target"
	case addr.IsMulticast():
		return "a multicast address is not a valid egress target"
	case addr == netip.AddrFrom4([4]byte{255, 255, 255, 255}):
		return "the broadcast address is not a valid egress target"
	case addr == netip.AddrFrom4([4]byte{100, 100, 100, 200}), addr == netip.AddrFrom4([4]byte{168, 63, 129, 16}):
		return "a cloud provider metadata address is not a valid egress target"
	}
	return ""
}

// numericLabel reports whether a host's last label reads as a number, so the host is an address and not a name.
func numericLabel(l string) bool {
	if rest, ok := strings.CutPrefix(l, "0x"); ok {
		return rest != "" && strings.Trim(rest, "0123456789abcdef") == ""
	}
	return l != "" && strings.Trim(l, "0123456789") == ""
}

// segmentRE is one path segment of a gateway operation: unreserved characters only.
var segmentRE = regexp.MustCompile(`^[A-Za-z0-9._~-]+$`)

// unsafeOperation explains why a gateway operation ("METHOD /path") is not one exact operation, or returns "". The
// path must be its own path.Clean form with no . or .. segment, and every segment is plain unreserved characters, so
// there is no percent-encoding, matrix parameter, backslash or NUL to decode differently at the gateway and the origin.
func unsafeOperation(op string) string {
	_, p, _ := strings.Cut(op, " ")
	if strings.ContainsAny(p, "%;\\\x00") {
		return "a path may not contain %, ;, a backslash or NUL"
	}
	if p != pathpkg.Clean(p) {
		return "a path must be in canonical form, with no empty segment, trailing slash, . or .."
	}
	if p == "/" {
		return ""
	}
	for seg := range strings.SplitSeq(p[1:], "/") {
		if seg == "." || seg == ".." || !segmentRE.MatchString(seg) {
			return "every path segment must be plain unreserved characters and not . or .."
		}
	}
	return ""
}

// checkSeparation refuses a role that can both push a branch and review pull requests: the coder that wrote a change
// must not be able to approve it (SEC-2).
func (cfg *Config) checkSeparation(c *collector, name string, r RoleProfile) {
	push := false
	var reviewAt []string
	for i, t := range r.Profile.Tools {
		for j, perm := range t.Permissions {
			switch perm {
			case "branch:push-own":
				push = true
			case "pulls:review":
				if reviewAt == nil {
					reviewAt = at("roles", name, "profile", "tools", strconv.Itoa(i), "permissions", strconv.Itoa(j))
				}
			}
		}
	}
	if push && reviewAt != nil {
		c.addf(CodeUnsafeRole, reviewAt, "a role that holds branch:push-own may not also hold pulls:review: it could approve its own change (SEC-2)")
	}
}

// forgeReason is why a role may not reach the forge itself.
const forgeReason = "a role reaches the forge only through its scoped tool permissions: the control plane mints the forge token (WI-30), so a forge host may not appear in egress or a gateway credential (SEC-2, SEC-3)"

// githubHosts are the public GitHub hosts: the API, git transport, raw content and release downloads.
func githubHosts() []string {
	return []string{"github.com", "api.github.com", "uploads.github.com", "codeload.github.com", "raw.githubusercontent.com", "objects.githubusercontent.com"}
}

// isForgeHost reports whether hostPort is the forge: a public GitHub host (any port) when the forge is github, or a
// host listed in installation.forgeHosts (any port).
func (cfg *Config) isForgeHost(hostPort string) bool {
	host, _, _ := strings.Cut(hostPort, ":")
	if cfg.installation.Forge == "github" && slices.Contains(githubHosts(), host) {
		return true
	}
	for _, f := range cfg.installation.ForgeHosts {
		if fh, _, _ := strings.Cut(f, ":"); fh == host {
			return true
		}
	}
	return false
}
