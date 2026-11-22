// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

package authz

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/elliott-davis/lightsout/internal/audit"
)

const (
	// maxFuture is how far ahead of the clock a decision's creation time may be.
	maxFuture = time.Minute
	// denialClipBytes bounds every client-supplied string in a denial record. Grants are never clipped: an
	// oversized value makes the grant's append fail, which is an error and never a grant.
	denialClipBytes = 1024
	// maxIDBytes bounds decision and principal IDs.
	maxIDBytes = 256
	// defaultDenialAuditTimeout bounds the denial append, which runs detached from the caller's context.
	defaultDenialAuditTimeout = 5 * time.Second
)

// Config is the install configuration of an [Authorizer].
type Config struct {
	// Forge is the forge this installation serves, matching [a-z][a-z0-9-]* (for example "github"). Version 1 has
	// one forge per install. Required. Multi-forge support later widens this to a set.
	Forge string
	// InstallID identifies the installation. A denial whose target subject can't be recorded is recorded against
	// the installation instead, so every denial is audited. Required.
	InstallID string
	// Expiry is the maximum age of a decision per operation. A zero or absent entry means no expiry.
	Expiry map[Operation]time.Duration
	// DenialAuditTimeout bounds the append of a denial record, which survives cancellation of the caller's
	// context. Zero means 5 seconds. Negative is rejected.
	DenialAuditTimeout time.Duration
}

// Authorizer authorizes human decisions. It holds no per-decision state and is safe for concurrent use.
type Authorizer struct {
	policy        map[Operation]opPolicy
	expiry        map[Operation]time.Duration
	forge         string
	installID     string
	denialTimeout time.Duration
	roles         RoleSource
	denials       Auditor
	clock         func() time.Time
}

// New returns an Authorizer. denials records denials outside the caller's transaction.
func New(cfg Config, roles RoleSource, denials Auditor, clock func() time.Time) (*Authorizer, error) {
	if roles == nil {
		return nil, errors.New("authz: nil role source")
	}
	if denials == nil {
		return nil, errors.New("authz: nil denial auditor")
	}
	if clock == nil {
		return nil, errors.New("authz: nil clock")
	}
	if !validForge(cfg.Forge) {
		return nil, fmt.Errorf("authz: forge %q must match [a-z][a-z0-9-]*", cfg.Forge)
	}
	if !validPlainID(cfg.InstallID) {
		return nil, errors.New("authz: install ID must be 1 to 256 bytes of printable ASCII")
	}
	if cfg.DenialAuditTimeout < 0 {
		return nil, errors.New("authz: negative denial audit timeout")
	}
	timeout := cfg.DenialAuditTimeout
	if timeout == 0 {
		timeout = defaultDenialAuditTimeout
	}
	policy := operations()
	expiry := make(map[Operation]time.Duration, len(cfg.Expiry))
	for op, d := range cfg.Expiry {
		if _, ok := policy[op]; !ok {
			return nil, fmt.Errorf("authz: expiry for unknown operation %q", op)
		}
		if d < 0 {
			return nil, fmt.Errorf("authz: negative expiry for operation %q", op)
		}
		expiry[op] = d
	}
	return &Authorizer{
		policy: policy, expiry: expiry, forge: cfg.Forge, installID: cfg.InstallID, denialTimeout: timeout,
		roles: roles, denials: denials, clock: clock,
	}, nil
}

// Authorize checks d against t, in the order the design lists, and on success consumes the decision ID and appends
// the grant entry through tx.
//
// On any non-nil error, including [ErrDenied], the caller must not commit its state change and must roll back tx.
// A denial is a *[DeniedError] wrapping [ErrDenied], audited through the denial auditor even if ctx is already
// cancelled. If that append fails too, the error also wraps the audit error, and it is still a denial. Any other
// error (a Consume or grant append failure) is returned wrapped and is not a denial.
//
// Callers must not echo a denial's reason to an unauthorized principal: "stale" versus "no-role" would reveal
// whether a guessed revision was right.
func (a *Authorizer) Authorize(ctx context.Context, tx Tx, d Decision, t Target) (Grant, error) {
	if tx == nil {
		return Grant{}, errors.New("authz: nil transaction")
	}
	pol, known := a.policy[d.Operation]
	if r := a.check(d, t, pol, known); r != "" {
		return Grant{}, a.deny(ctx, d, t, r, false)
	}
	// Logins can be renamed or recycled, so the role source resolves by forge and ID only.
	p := d.Principal
	p.Login = ""
	ok, err := a.roles.HasRole(ctx, p, pol.Role, cloneTarget(t))
	switch {
	case err != nil:
		// Fail closed. The cause is joined so the caller can see it, but it is never put in the audit record.
		return Grant{}, errors.Join(a.deny(ctx, d, t, ReasonRoleError, true), fmt.Errorf("check role: %w", err))
	case !ok:
		return Grant{}, a.deny(ctx, d, t, ReasonNoRole, true)
	}
	// Consume runs only after every binding passed, so a wrong-target attempt cannot burn a valid approval.
	if err = tx.Consume(ctx, d.ID); err != nil {
		if errors.Is(err, ErrReplayed) {
			return Grant{}, a.deny(ctx, d, t, ReasonReplayed, true)
		}
		return Grant{}, fmt.Errorf("consume decision: %w", err)
	}
	e, err := tx.Append(ctx, a.grantRecord(d, t))
	if err != nil {
		return Grant{}, fmt.Errorf("append grant entry: %w", err)
	}
	return Grant{DecisionID: d.ID, Target: cloneTarget(t), Seq: e.Seq}, nil
}

// check runs the pre-role checks and returns the first failing reason, or "".
func (a *Authorizer) check(d Decision, t Target, pol opPolicy, known bool) Reason {
	switch {
	case !d.Authenticated || d.Principal.ID == "" || d.Principal.Forge == "":
		return ReasonUnauthenticated
	case d.Principal.Kind != PrincipalUser:
		return ReasonNotAPerson
	case !known || d.Operation != t.Operation || t.Scope.Kind != pol.ScopeKind:
		return ReasonWrongOperation
	case d.Location.Scope != t.Scope || d.Location.Subject != t.Subject || d.Principal.Forge != a.forge ||
		!a.placeConsistent(t, pol):
		return ReasonWrongPlace
	case !validDecisionID(d.ID) || !validPrincipalID(d.Principal.ID) || !validRevision(d.Revision) ||
		!validRevision(t.Revision) || !validChannel(d.Channel) || d.Integrity < IntegrityOriginal ||
		d.Integrity > IntegrityQuoted || !validChoice(d.Choice) || !validChoice(t.Choice) || d.Created.IsZero():
		return ReasonMalformed
	case d.Revision != t.Revision:
		return ReasonStale
	case choiceMismatch(d, t, pol):
		return ReasonWrongChoice
	case d.Integrity == IntegrityEdited:
		return ReasonEdited
	case d.Integrity == IntegrityQuoted:
		return ReasonQuoted
	}
	now := a.clock()
	if d.Created.After(now.Add(maxFuture)) {
		return ReasonMalformed
	}
	if exp := a.expiry[d.Operation]; exp > 0 && now.Sub(d.Created) > exp {
		return ReasonExpired
	}
	return ""
}

// placeConsistent checks that the target's scope and subject agree with each other, with the operation and with
// this installation.
func (a *Authorizer) placeConsistent(t Target, pol opPolicy) bool {
	// Scope and subject strings come from the target but end up verbatim in grant records, so they must be plain.
	if !validPlainID(t.Scope.ID) || !validPlainID(t.Subject.ID) || (t.Subject.Repo != "" && !validPlainID(t.Subject.Repo)) ||
		!slices.Contains(pol.Subjects, t.Subject.Kind) {
		return false
	}
	if !validPaths(t.Paths, pol.Area) {
		return false
	}
	switch t.Scope.Kind {
	case ScopeRepo:
		return t.Subject.Repo == t.Scope.ID
	case ScopeInstall:
		return t.Scope.ID == a.installID && t.Subject.Kind == audit.SubjectInstall &&
			t.Subject.ID == t.Scope.ID && t.Subject.Repo == ""
	}
	return false
}

// validPaths requires an area for owner operations, with no empty or duplicate elements, and none otherwise.
func validPaths(paths []string, area bool) bool {
	if !area {
		return len(paths) == 0
	}
	if len(paths) == 0 {
		return false
	}
	seen := make(map[string]bool, len(paths))
	for _, p := range paths {
		if p == "" || seen[p] || !printablePath(p) {
			return false
		}
		seen[p] = true
	}
	return true
}

// printablePath reports whether a path element is valid UTF-8 without control or format characters (NUL, C0, C1,
// Cf), so it can't hide or forge anything when displayed.
func printablePath(p string) bool {
	if !utf8.ValidString(p) {
		return false
	}
	for _, r := range p {
		if unsafeRune(r) {
			return false
		}
	}
	return true
}

// validPlainID accepts 1 to 256 bytes of printable ASCII, for scope and subject strings.
func validPlainID(s string) bool { return s != "" && len(s) <= maxIDBytes && printableASCII(s) }

// validForge accepts [a-z][a-z0-9-]*, so "<forge>:<id>" is unambiguous.
func validForge(s string) bool {
	if s == "" || s[0] < 'a' || s[0] > 'z' {
		return false
	}
	for i := range len(s) {
		c := s[i]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
			return false
		}
	}
	return true
}

func printableASCII(s string) bool {
	for i := range len(s) {
		if s[i] < 0x21 || s[i] > 0x7E {
			return false
		}
	}
	return true
}

// validDecisionID accepts 1 to 256 bytes of printable ASCII.
func validDecisionID(s string) bool { return s != "" && len(s) <= maxIDBytes && printableASCII(s) }

// validPrincipalID accepts 1 to 256 bytes of printable ASCII without ':', so "<forge>:<id>" is unambiguous.
func validPrincipalID(s string) bool {
	return validDecisionID(s) && !strings.Contains(s, ":")
}

// validChoice accepts no choice or a SHA-256 digest in lowercase hex.
func validChoice(s string) bool { return s == "" || isHex(s, 64) }

func choiceMismatch(d Decision, t Target, pol opPolicy) bool {
	if pol.Choice {
		return d.Choice == "" || t.Choice == "" || d.Choice != t.Choice
	}
	return d.Choice != "" || t.Choice != ""
}

// validRevision accepts a git SHA-1 or SHA-256 digest in lowercase hex.
func validRevision(s string) bool {
	return isHex(s, 40) || isHex(s, 64)
}

func isHex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for i := range len(s) {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func validChannel(c Channel) bool {
	switch c {
	case ChannelIssueComment, ChannelReview, ChannelAPI, ChannelAdminCLI:
		return true
	}
	return false
}

// deny audits a denial outside the transaction and returns the DeniedError, joined with the audit error if the
// append failed. An audit failure never turns a denial into anything else. The append is detached from the
// caller's cancellation, so a client that disconnects cannot erase its probing, and bounded by a timeout.
func (a *Authorizer) deny(ctx context.Context, d Decision, t Target, r Reason, roleChecked bool) error {
	denied := &DeniedError{Reason: r}
	actx, cancel := context.WithTimeout(context.WithoutCancel(ctx), a.denialTimeout)
	defer cancel()
	if _, err := a.denials.Append(actx, a.denialRecord(d, t, r, roleChecked)); err != nil {
		return errors.Join(denied, fmt.Errorf("audit denial: %w", err))
	}
	return denied
}

// auditOperation is the operation to record: never client text.
func (a *Authorizer) auditOperation(d Decision, t Target) string {
	if _, ok := a.policy[t.Operation]; ok {
		return string(t.Operation)
	}
	if _, ok := a.policy[d.Operation]; ok {
		return string(d.Operation)
	}
	return "unknown"
}

func (a *Authorizer) grantRecord(d Decision, t Target) audit.Record {
	op := a.auditOperation(d, t)
	// Everything but the login was validated by check, so it is stored verbatim.
	attrs := map[string]string{
		"decision_id": d.ID,
		"channel":     string(d.Channel),
	}
	if d.Choice != "" {
		attrs["choice"] = d.Choice
	}
	if len(t.Paths) > 0 {
		attrs["paths_digest"] = pathsDigest(t.Paths)
		attrs["paths_count"] = strconv.Itoa(len(t.Paths))
	}
	actor, _ := a.actorOf(d, sanitize)
	return audit.Record{
		Actor:   actor,
		Subject: audit.Subject{Kind: t.Subject.Kind, Repo: t.Subject.Repo, ID: t.Subject.ID},
		Action:  audit.ActionDecision,
		Target:  op,
		Outcome: string(audit.VerdictGranted),
		Decision: &audit.Decision{
			Operation: op,
			Role:      string(a.policy[t.Operation].Role),
			Revision:  d.Revision,
			Verdict:   audit.VerdictGranted,
		},
		Attrs: attrs,
	}
}

// denialRecord builds the record of a denial. Client-supplied strings are clipped, sanitized and clipped again.
// The role is recorded only once the role check has run, and the revision only if it is a valid digest.
func (a *Authorizer) denialRecord(d Decision, t Target, r Reason, roleChecked bool) audit.Record {
	cs := func(s string) string { return clip(sanitize(clip(s))) }
	op := a.auditOperation(d, t)
	actor, claimed := a.actorOf(d, cs)
	attrs := map[string]string{
		"decision_id":   cs(d.ID),
		"channel":       cs(string(d.Channel)),
		"denial_reason": string(r),
	}
	if claimed != "" {
		attrs["claimed_principal"] = claimed
	}
	if d.Operation != "" {
		attrs["requested_operation"] = cs(string(d.Operation))
	}
	revision := ""
	if validRevision(d.Revision) {
		revision = d.Revision
	} else if d.Revision != "" {
		attrs["requested_revision"] = cs(d.Revision)
	}
	role := ""
	if roleChecked {
		role = string(a.policy[t.Operation].Role)
	}
	if r == ReasonWrongPlace {
		attrs["location_scope_kind"] = cs(string(d.Location.Scope.Kind))
		attrs["location_scope_id"] = cs(d.Location.Scope.ID)
		attrs["location_subject_kind"] = cs(string(d.Location.Subject.Kind))
		attrs["location_subject_repo"] = cs(d.Location.Subject.Repo)
		attrs["location_subject_id"] = cs(d.Location.Subject.ID)
	}
	if r == ReasonStale {
		attrs["target_revision"] = cs(t.Revision)
	}
	if r == ReasonWrongChoice {
		attrs["requested_choice"] = cs(d.Choice)
		attrs["target_choice"] = cs(t.Choice)
	}
	sub := audit.Subject{Kind: audit.SubjectKind(cs(string(t.Subject.Kind))), Repo: cs(t.Subject.Repo), ID: cs(t.Subject.ID)}
	if !recordableSubject(sub) {
		attrs["target_subject_kind"] = cs(string(t.Subject.Kind))
		attrs["target_subject_repo"] = cs(t.Subject.Repo)
		attrs["target_subject_id"] = cs(t.Subject.ID)
		sub = audit.Subject{Kind: audit.SubjectInstall, ID: cs(a.installID)}
	}
	return audit.Record{
		Actor:   actor,
		Subject: sub,
		Action:  audit.ActionDecision,
		Target:  op,
		Outcome: string(audit.VerdictDenied),
		Decision: &audit.Decision{
			Operation: op,
			Role:      role,
			Revision:  revision,
			Verdict:   audit.VerdictDenied,
			Reason:    string(r),
		},
		Attrs: attrs,
	}
}

// recordableSubject mirrors the audit log's subject rules.
func recordableSubject(s audit.Subject) bool {
	switch s.Kind {
	case audit.SubjectChange, audit.SubjectIssue:
		return s.Repo != "" && s.ID != ""
	case audit.SubjectInstall:
		return s.Repo == "" && s.ID != ""
	}
	return false
}

// actorOf maps the principal to an audit actor. Only an authenticated identity is attributed. An unauthenticated
// claim is never recorded as the actor: it comes back as the claimed string for an attribute instead. An
// authenticated bot or app keeps its verified forge and ID as an external actor.
func (a *Authorizer) actorOf(d Decision, cs func(string) string) (actor audit.Actor, claimed string) {
	p := d.Principal
	if !d.Authenticated || !validForge(p.Forge) || !validPrincipalID(p.ID) {
		claimed = fmt.Sprintf("forge=%s id=%s login=%s", cs(p.Forge), cs(p.ID), cs(p.Login))
		return audit.Actor{Kind: audit.ActorExternal, ID: "unauthenticated"}, claimed
	}
	kind := audit.ActorExternal
	if p.Kind == PrincipalUser {
		kind = audit.ActorHuman
	}
	return audit.Actor{Kind: kind, ID: cs(p.Forge) + ":" + p.ID, Display: cs(p.Login)}, ""
}

// pathsDigest is the hex SHA-256 over the sorted paths, each prefixed by its length as a big-endian uint64, so
// two different lists can never share a digest.
func pathsDigest(paths []string) string {
	h := sha256.New()
	for _, p := range slices.Sorted(slices.Values(paths)) {
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], uint64(len(p)))
		h.Write(n[:])
		h.Write([]byte(p))
	}
	return hex.EncodeToString(h.Sum(nil))
}

// unsafeRune reports whether r can hide or forge display output: C0 and C1 controls, every Unicode format
// character (zero-width, bidi, soft hyphen, tags, BOM), line and paragraph separators, and the Hangul and
// halfwidth fillers that render as blanks.
func unsafeRune(r rune) bool {
	return unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == 0x2028 || r == 0x2029 ||
		r == 0x115F || r == 0x1160 || r == 0x3164 || r == 0xFFA0
}

// sanitize makes a client-supplied string safe to audit: valid UTF-8 with every unsafe rune replaced by U+FFFD.
func sanitize(s string) string {
	s = strings.ToValidUTF8(s, "\uFFFD")
	return strings.Map(func(r rune) rune {
		if unsafeRune(r) {
			return '\uFFFD'
		}
		return r
	}, s)
}

// clip cuts s to denialClipBytes on a rune boundary.
func clip(s string) string {
	if len(s) <= denialClipBytes {
		return s
	}
	cut := denialClipBytes
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}

func cloneTarget(t Target) Target {
	t.Paths = slices.Clone(t.Paths)
	return t
}
