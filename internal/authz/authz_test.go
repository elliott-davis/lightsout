// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

package authz

import (
	"context"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/google/go-cmp/cmp"

	"github.com/elliott-davis/lightsout/internal/audit"
)

var t0 = time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)

const (
	repoA     = "github:repo-a"
	repoB     = "github:repo-b"
	installID = "inst-1"
	forgeName = "github"
	choiceA   = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc" // 64 hex
	choiceB   = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
	revA      = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" // 64 hex
	revB      = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	sha1A     = "1111111111111111111111111111111111111111" // 40 hex
	sha1B     = "2222222222222222222222222222222222222222"
)

// fakeRoles answers HasRole from a mutable set, so a test can revoke a role between decision and execution. It
// records what it was asked.
type fakeRoles struct {
	mu      sync.Mutex
	granted map[string]bool // "<principal id>/<role>"
	err     error
	hook    func(Target)    // runs inside HasRole with the target it received, before the answer
	block   bool            // HasRole blocks until its context is done
	owned   map[string]bool // when non-nil, an owner check needs every target path in this set
	gotP    Principal
	gotRole Role
	gotT    Target
	calls   int
}

// set grants or revokes a role for principal 42.
func (f *fakeRoles) set(r Role, ok bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.granted[forgeName+"/42/"+string(r)] = ok
}

func (f *fakeRoles) setErr(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.err = err
}

func (f *fakeRoles) HasRole(ctx context.Context, p Principal, r Role, t Target) (bool, error) {
	f.mu.Lock()
	f.calls++
	f.gotP, f.gotRole, f.gotT = p, r, t
	f.gotT.Paths = slices.Clone(t.Paths) // what it was given, before any mutation below
	hook, block, owned, err := f.hook, f.block, f.owned, f.err
	held := f.granted[p.Forge+"/"+p.ID+"/"+string(r)] // keyed on forge and ID together
	f.mu.Unlock()
	if hook != nil {
		hook(t)
	}
	if block {
		<-ctx.Done()
		return false, ctx.Err()
	}
	if err != nil {
		return false, err
	}
	if owned != nil {
		for _, path := range t.Paths {
			if !owned[path] {
				return false, nil
			}
		}
	}
	return held, nil
}

// store is the shared state behind every fakeTx: the consumed set and the committed grant log. Consume reserves
// immediately, like a unique index, and a rollback releases the reservation.
type store struct {
	mu        sync.Mutex
	consumed  map[string]bool
	grants    *audit.Log // committed grant entries
	probe     *audit.Log // validates records at Append time, like the real store would
	committed uint64
	failAppd  bool
}

func (s *store) Begin() *fakeTx { return &fakeTx{s: s} }

func (s *store) setFail(v bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failAppd = v
}

func (s *store) isConsumed(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.consumed[id]
}

// fakeTx buffers its appends until Commit and drops them on Rollback.
type fakeTx struct {
	s    *store
	mine []string
	buf  []audit.Record
	done bool
	// consumeCalls counts calls to Consume, so a test can assert a denial never reached it.
	consumeCalls int
}

func (x *fakeTx) Consume(_ context.Context, id string) error {
	x.s.mu.Lock()
	defer x.s.mu.Unlock()
	x.consumeCalls++
	if x.s.consumed[id] {
		return ErrReplayed
	}
	x.s.consumed[id] = true
	x.mine = append(x.mine, id)
	return nil
}

func (x *fakeTx) Append(ctx context.Context, r audit.Record) (audit.Entry, error) {
	x.s.mu.Lock()
	defer x.s.mu.Unlock()
	if x.s.failAppd {
		return audit.Entry{}, errors.New("disk full")
	}
	if _, err := x.s.probe.Append(ctx, r); err != nil {
		return audit.Entry{}, err
	}
	x.buf = append(x.buf, r)
	return audit.Entry{Seq: x.s.committed + uint64(len(x.buf))}, nil
}

// Commit is safe to call from a goroutine: it reports failure instead of failing the test.
func (x *fakeTx) Commit(ctx context.Context) error {
	x.s.mu.Lock()
	defer x.s.mu.Unlock()
	for i := range x.buf {
		if _, err := x.s.grants.Append(ctx, x.buf[i]); err != nil {
			return err
		}
		x.s.committed++
	}
	x.buf, x.done = nil, true
	return nil
}

func (x *fakeTx) Rollback() {
	x.s.mu.Lock()
	defer x.s.mu.Unlock()
	if x.done {
		return
	}
	for _, id := range x.mine {
		delete(x.s.consumed, id)
	}
	x.buf, x.mine = nil, nil
}

type env struct {
	az      *Authorizer
	roles   *fakeRoles
	store   *store
	denials *audit.Log
}

func newLog(t *testing.T) *audit.Log {
	t.Helper()
	l, err := audit.New(audit.NewMemory(), func() time.Time { return t0 })
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func newEnv(t *testing.T, cfg Config) *env {
	t.Helper()
	cfg.InstallID = installID
	cfg.Forge = forgeName
	denials := newLog(t)
	roles := &fakeRoles{granted: map[string]bool{}}
	az, err := New(cfg, roles, denials, func() time.Time { return t0 })
	if err != nil {
		t.Fatal(err)
	}
	return &env{
		az: az, roles: roles, denials: denials,
		store: &store{consumed: map[string]bool{}, grants: newLog(t), probe: newLog(t)},
	}
}

func readAll(t *testing.T, l *audit.Log) []audit.Entry {
	t.Helper()
	es, err := l.Read(t.Context(), 1, audit.MaxReadLimit)
	if err != nil {
		t.Fatal(err)
	}
	return es
}

func (e *env) denied(t *testing.T) []audit.Entry  { t.Helper(); return readAll(t, e.denials) }
func (e *env) granted(t *testing.T) []audit.Entry { t.Helper(); return readAll(t, e.store.grants) }

// authorize runs Authorize in a fresh transaction, committing on success and rolling back otherwise.
func (e *env) authorize(t *testing.T, d Decision, tg Target) (Grant, error) {
	t.Helper()
	tx := e.store.Begin()
	g, err := e.az.Authorize(t.Context(), tx, d, tg)
	if err != nil {
		tx.Rollback()
		return g, err
	}
	if err := tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	return g, nil
}

// allRoles gives principal 42 every role.
func (e *env) allRoles() {
	for _, r := range []Role{RoleIdeator, RolePathOwner, RoleCodeOwner, RoleContractOwner, RoleAdmin} {
		e.roles.set(r, true)
	}
}

func wantDenied(t *testing.T, err error, r Reason) {
	t.Helper()
	var de *DeniedError
	if !errors.As(err, &de) || !errors.Is(err, ErrDenied) {
		t.Fatalf("err = %v, want a denial with reason %q", err, r)
	}
	if de.Reason != r {
		t.Fatalf("reason = %q, want %q", de.Reason, r)
	}
}

// caseFor returns a valid decision by principal 42 and its matching target for op.
func caseFor(op Operation) (Decision, Target) {
	pol := operations()[op]
	sc := Scope{Kind: ScopeRepo, ID: repoA}
	sub := audit.Subject{Kind: pol.Subjects[0], Repo: repoA, ID: "7"}
	if pol.ScopeKind == ScopeInstall {
		sc = Scope{Kind: ScopeInstall, ID: installID}
		sub = audit.Subject{Kind: audit.SubjectInstall, ID: installID}
	}
	tg := Target{Operation: op, Scope: sc, Subject: sub, Revision: revA}
	if pol.Choice {
		tg.Choice = choiceA
	}
	if pol.Area {
		tg.Paths = []string{"infra/", "docs/"}
	}
	d := Decision{
		ID: "github:issue-comment:1001", Channel: ChannelIssueComment,
		Principal:     Principal{Forge: forgeName, ID: "42", Login: "alice", Kind: PrincipalUser},
		Authenticated: true, Location: Location{Scope: sc, Subject: sub},
		Operation: op, Revision: revA, Choice: tg.Choice, Integrity: IntegrityOriginal, Created: t0.Add(-time.Minute),
	}
	return d, tg
}

func scenariosCase() (Decision, Target) { return caseFor(OpApproveScenarios) }

func TestOperations_Table(t *testing.T) { // SEC-10, SEC-6, INT-3, INT-4, INT-11, CON-2, CON-7, CON-8
	t.Parallel()
	issue := []audit.SubjectKind{audit.SubjectIssue}
	change := []audit.SubjectKind{audit.SubjectChange}
	install := []audit.SubjectKind{audit.SubjectInstall}
	want := map[Operation]opPolicy{
		"confirm-classification": {Role: "ideator", ScopeKind: "repo", Subjects: issue},
		"decide-split":           {Role: "ideator", ScopeKind: "repo", Subjects: issue, Choice: true},
		"approve-scenarios":      {Role: "ideator", ScopeKind: "repo", Subjects: issue},
		"reject-scenarios":       {Role: "ideator", ScopeKind: "repo", Subjects: issue},
		"approve-path-exception": {Role: "path-owner", ScopeKind: "repo", Subjects: change, Area: true},
		"approve-lights-on":      {Role: "code-owner", ScopeKind: "repo", Subjects: change, Area: true},
		"activate-contract":      {Role: "contract-owner", ScopeKind: "repo", Subjects: change, Area: true},
		"halt":                   {Role: "admin", ScopeKind: "install", Subjects: install},
		"resume":                 {Role: "admin", ScopeKind: "install", Subjects: install},
	}
	ops := operations()
	if diff := cmp.Diff(want, ops); diff != "" {
		t.Errorf("operations (-want +got):\n%s", diff)
	}
	// Mutating a returned table must not affect the next call.
	delete(ops, OpHalt)
	if _, ok := operations()[OpHalt]; !ok {
		t.Error("operations() shares state between calls")
	}
}

func TestNew_Validates(t *testing.T) { // SEC-10
	t.Parallel()
	log, err := audit.New(audit.NewMemory(), func() time.Time { return t0 })
	if err != nil {
		t.Fatal(err)
	}
	roles := &fakeRoles{}
	clock := func() time.Time { return t0 }
	ok := Config{InstallID: installID, Forge: forgeName}
	tests := map[string]struct {
		cfg   Config
		roles RoleSource
		aud   Auditor
		clock func() time.Time
	}{
		"nil roles":              {ok, nil, log, clock},
		"nil auditor":            {ok, roles, nil, clock},
		"nil clock":              {ok, roles, log, nil},
		"empty install ID":       {Config{Forge: forgeName}, roles, log, clock},
		"empty forge":            {Config{InstallID: installID}, roles, log, clock},
		"uppercase forge":        {Config{InstallID: installID, Forge: "GitHub"}, roles, log, clock},
		"forge with colon":       {Config{InstallID: installID, Forge: "git:hub"}, roles, log, clock},
		"forge with digit first": {Config{InstallID: installID, Forge: "1git"}, roles, log, clock},
		"negative timeout":       {Config{InstallID: installID, Forge: forgeName, DenialAuditTimeout: -1}, roles, log, clock},
		"unknown operation":      {Config{InstallID: installID, Forge: forgeName, Expiry: map[Operation]time.Duration{"nope": time.Hour}}, roles, log, clock},
		"negative expiry":        {Config{InstallID: installID, Forge: forgeName, Expiry: map[Operation]time.Duration{OpResume: -time.Hour}}, roles, log, clock},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := New(tc.cfg, tc.roles, tc.aud, tc.clock); err == nil {
				t.Error("want an error")
			}
		})
	}
	if _, err := New(ok, roles, log, clock); err != nil {
		t.Errorf("valid config: %v", err)
	}
}

func TestAuthorize_Granted(t *testing.T) { // SEC-10
	t.Parallel()
	e := newEnv(t, Config{})
	e.allRoles()
	d, tg := scenariosCase()
	g, err := e.authorize(t, d, tg)
	if err != nil {
		t.Fatal(err)
	}
	es := e.granted(t)
	if len(es) != 1 || len(e.denied(t)) != 0 {
		t.Fatalf("%d grant entries, %d denials, want exactly one grant", len(es), len(e.denied(t)))
	}
	if g.Seq != es[0].Seq || g.DecisionID != d.ID {
		t.Errorf("grant = %+v", g)
	}
	want := audit.Record{
		Actor:    audit.Actor{Kind: audit.ActorHuman, ID: "github:42", Display: "alice"},
		Subject:  tg.Subject,
		Action:   audit.ActionDecision,
		Target:   "approve-scenarios",
		Outcome:  "granted",
		Decision: &audit.Decision{Operation: "approve-scenarios", Role: "ideator", Revision: revA, Verdict: audit.VerdictGranted},
		Attrs:    map[string]string{"decision_id": d.ID, "channel": "issue-comment"},
	}
	if diff := cmp.Diff(want, es[0].Record); diff != "" {
		t.Errorf("record (-want +got):\n%s", diff)
	}
	if !e.store.isConsumed(d.ID) {
		t.Error("decision not consumed")
	}
}

func TestAuthorize_GrantRecords(t *testing.T) { // SEC-6, SEC-10, CON-2, CON-7
	t.Parallel()
	tests := map[string]struct {
		op        Operation
		role      string
		rev       string
		wantPaths bool
		choice    string
	}{
		"halt":                   {OpHalt, "admin", revA, false, ""},
		"resume":                 {OpResume, "admin", revB, false, ""},
		"approve-path-exception": {OpApprovePathException, "path-owner", sha1A, true, ""},
		"activate-contract":      {OpActivateContract, "contract-owner", revA, true, ""},
		"decide-split":           {OpDecideSplit, "ideator", revA, false, choiceA},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			e := newEnv(t, Config{})
			e.allRoles()
			d, tg := caseFor(tc.op)
			d.Revision, tg.Revision = tc.rev, tc.rev
			if _, err := e.authorize(t, d, tg); err != nil {
				t.Fatal(err)
			}
			r := e.granted(t)[0].Record
			if r.Decision.Operation != string(tc.op) || r.Decision.Role != tc.role || r.Decision.Revision != tc.rev ||
				r.Target != string(tc.op) || r.Subject != tg.Subject || r.Decision.Verdict != audit.VerdictGranted {
				t.Errorf("record = %+v / %+v", r, r.Decision)
			}
			if tc.wantPaths {
				if r.Attrs["paths_digest"] != pathsDigest([]string{"docs/", "infra/"}) || r.Attrs["paths_count"] != "2" {
					t.Errorf("attrs = %v", r.Attrs)
				}
			} else if _, ok := r.Attrs["paths_digest"]; ok {
				t.Errorf("unexpected paths digest: %v", r.Attrs)
			}
			if r.Attrs["choice"] != tc.choice {
				t.Errorf("choice attr = %q, want %q", r.Attrs["choice"], tc.choice)
			}
		})
	}
}

func TestPathsDigest(t *testing.T) { // SEC-10
	t.Parallel()
	if pathsDigest([]string{"a", "b"}) != pathsDigest([]string{"b", "a"}) {
		t.Error("digest depends on order")
	}
	lists := [][]string{
		{"a", "b"},
		{"ab"},
		{"a\x00b"},
		{"a\x00", "b"},
		{"a", "\x00b"},
		{"ab", "c"},
		{"a", "bc"},
		{"abc"},
		{""},
		{"", ""},
		{},
		{"a"},
		{"a", "a"},
	}
	seen := map[string][]string{}
	for _, l := range lists {
		d := pathsDigest(l)
		if prev, ok := seen[d]; ok {
			t.Errorf("%q and %q share digest %s", prev, l, d)
		}
		seen[d] = l
	}
}

func TestSanitize(t *testing.T) { // SEC-10
	t.Parallel()
	tests := map[string]rune{
		"ZWSP U+200B": 0x200B, "ZWJ U+200D": 0x200D, "LRM U+200E": 0x200E, "RLM U+200F": 0x200F,
		"LRE U+202A": 0x202A, "RLO U+202E": 0x202E, "LS U+2028": 0x2028, "PS U+2029": 0x2029,
		"WJ U+2060": 0x2060, "LRI U+2066": 0x2066, "PDI U+2069": 0x2069, "ALM U+061C": 0x061C,
		"BOM U+FEFF": 0xFEFF, "soft hyphen U+00AD": 0x00AD, "tag U+E0001": 0xE0001, "filler U+3164": 0x3164,
		"filler U+115F": 0x115F, "filler U+1160": 0x1160, "filler U+FFA0": 0xFFA0,
		"NUL": 0, "ESC": 0x1b, "DEL": 0x7f, "C1 U+0085": 0x85, "CR": '\r', "LF": '\n',
	}
	for name, r := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if got := sanitize("a" + string(r) + "b"); got != "a\uFFFDb" {
				t.Errorf("sanitize = %q", got)
			}
		})
	}
	if got := sanitize("plain é 漢 ok"); got != "plain é 漢 ok" {
		t.Errorf("sanitize changed a harmless string: %q", got)
	}
	if got := sanitize("a\xffb"); got != "a\uFFFDb" {
		t.Errorf("invalid UTF-8: %q", got)
	}
}

func TestAuthorize_Denials(t *testing.T) { // SEC-10, SEC-11
	t.Parallel()
	otherIssue := audit.Subject{Kind: audit.SubjectIssue, Repo: repoA, ID: "8"}
	type mut func(*Decision, *Target)
	tests := map[string]struct {
		op     Operation // defaults to approve-scenarios
		mutate mut
		want   Reason
	}{
		"forged: unauthenticated": {mutate: func(d *Decision, _ *Target) { d.Authenticated = false }, want: ReasonUnauthenticated},
		"forged: empty forge":     {mutate: func(d *Decision, _ *Target) { d.Principal.Forge = "" }, want: ReasonUnauthenticated},
		"forged: empty author ID": {mutate: func(d *Decision, _ *Target) { d.Principal.ID = "" }, want: ReasonUnauthenticated},
		"bot":                     {mutate: func(d *Decision, _ *Target) { d.Principal.Kind = PrincipalBot }, want: ReasonNotAPerson},
		"app":                     {mutate: func(d *Decision, _ *Target) { d.Principal.Kind = PrincipalApp }, want: ReasonNotAPerson},
		"unknown kind":            {mutate: func(d *Decision, _ *Target) { d.Principal.Kind = "" }, want: ReasonNotAPerson},
		"unknown operation": {mutate: func(d *Decision, tg *Target) {
			d.Operation, tg.Operation = "delete-everything", "delete-everything"
		}, want: ReasonWrongOperation},
		"different operation, same subject and revision": {mutate: func(d *Decision, _ *Target) { d.Operation = OpRejectScenarios }, want: ReasonWrongOperation},
		"scope kind does not fit":                        {mutate: func(_ *Decision, tg *Target) { tg.Scope.Kind = ScopeInstall }, want: ReasonWrongOperation},
		"cross-repo replay": {mutate: func(d *Decision, _ *Target) {
			d.Location.Scope.ID = repoB
			d.Location.Subject.Repo = repoB
		}, want: ReasonWrongPlace},
		"location scope differs, subject same": {mutate: func(d *Decision, _ *Target) { d.Location.Scope.ID = repoB }, want: ReasonWrongPlace},
		"copied to a second issue":             {mutate: func(d *Decision, _ *Target) { d.Location.Subject = otherIssue }, want: ReasonWrongPlace},
		"empty scope ID on both sides": {mutate: func(d *Decision, tg *Target) {
			d.Location.Scope.ID, tg.Scope.ID = "", ""
			d.Location.Subject.Repo, tg.Subject.Repo = "", ""
		}, want: ReasonWrongPlace},
		"scope repo vs subject repo": {mutate: func(d *Decision, tg *Target) {
			tg.Subject.Repo, d.Location.Subject.Repo = repoB, repoB
		}, want: ReasonWrongPlace},
		"target subject kind not allowed": {mutate: func(d *Decision, tg *Target) {
			s := audit.Subject{Kind: audit.SubjectChange, Repo: repoA, ID: "7"}
			d.Location.Subject, tg.Subject = s, s
		}, want: ReasonWrongPlace},
		"owner op without an area": {op: OpApproveLightsOn, mutate: func(_ *Decision, tg *Target) { tg.Paths = nil }, want: ReasonWrongPlace},
		"install scope vs subject ID": {op: OpHalt, mutate: func(d *Decision, tg *Target) {
			tg.Subject.ID, d.Location.Subject.ID = "other-install", "other-install"
		}, want: ReasonWrongPlace},
		"install subject with a repo": {op: OpHalt, mutate: func(d *Decision, tg *Target) {
			tg.Subject.Repo, d.Location.Subject.Repo = repoA, repoA
		}, want: ReasonWrongPlace},
		"revision: branch name":                {mutate: func(d *Decision, tg *Target) { d.Revision, tg.Revision = "main", "main" }, want: ReasonMalformed},
		"revision: ref":                        {mutate: func(d *Decision, tg *Target) { d.Revision, tg.Revision = "refs/heads/x", "refs/heads/x" }, want: ReasonMalformed},
		"revision: uppercase hex":              {mutate: func(d *Decision, tg *Target) { r := strings.ToUpper(revA); d.Revision, tg.Revision = r, r }, want: ReasonMalformed},
		"revision: 39 hex":                     {mutate: func(d *Decision, tg *Target) { r := revA[:39]; d.Revision, tg.Revision = r, r }, want: ReasonMalformed},
		"revision: 600 bytes":                  {mutate: func(d *Decision, tg *Target) { r := strings.Repeat("a", 600); d.Revision, tg.Revision = r, r }, want: ReasonMalformed},
		"revision: empty on both":              {mutate: func(d *Decision, tg *Target) { d.Revision, tg.Revision = "", "" }, want: ReasonMalformed},
		"revision: target malformed":           {mutate: func(_ *Decision, tg *Target) { tg.Revision = "main" }, want: ReasonMalformed},
		"channel: empty":                       {mutate: func(d *Decision, _ *Target) { d.Channel = "" }, want: ReasonMalformed},
		"channel: unknown":                     {mutate: func(d *Decision, _ *Target) { d.Channel = "check-run" }, want: ReasonMalformed},
		"integrity: unknown (zero)":            {mutate: func(d *Decision, _ *Target) { d.Integrity = IntegrityUnknown }, want: ReasonMalformed},
		"integrity: out of range":              {mutate: func(d *Decision, _ *Target) { d.Integrity = 99 }, want: ReasonMalformed},
		"created in future":                    {mutate: func(d *Decision, _ *Target) { d.Created = t0.Add(2 * time.Minute) }, want: ReasonMalformed},
		"older revision":                       {mutate: func(d *Decision, _ *Target) { d.Revision = revB }, want: ReasonStale},
		"proposal edited":                      {mutate: func(_ *Decision, tg *Target) { tg.Revision = revB }, want: ReasonStale},
		"sha-1 vs sha-256 of same":             {mutate: func(d *Decision, _ *Target) { d.Revision = revA[:40] }, want: ReasonStale},
		"edited comment":                       {mutate: func(d *Decision, _ *Target) { d.Integrity = IntegrityEdited }, want: ReasonEdited},
		"quoted command":                       {mutate: func(d *Decision, _ *Target) { d.Integrity = IntegrityQuoted }, want: ReasonQuoted},
		"no role":                              {mutate: func(d *Decision, _ *Target) { d.Principal.ID = "99" }, want: ReasonNoRole},
		"choice given to op without":           {mutate: func(d *Decision, _ *Target) { d.Choice = choiceA }, want: ReasonWrongChoice},
		"target choice for op without":         {mutate: func(_ *Decision, tg *Target) { tg.Choice = choiceA }, want: ReasonWrongChoice},
		"split: wrong choice":                  {op: OpDecideSplit, mutate: func(_ *Decision, tg *Target) { tg.Choice = choiceB }, want: ReasonWrongChoice},
		"split: both choices empty":            {op: OpDecideSplit, mutate: func(d *Decision, tg *Target) { d.Choice, tg.Choice = "", "" }, want: ReasonWrongChoice},
		"split: choice not named":              {op: OpDecideSplit, mutate: func(d *Decision, _ *Target) { d.Choice = "" }, want: ReasonWrongChoice},
		"foreign install, halt":                {op: OpHalt, mutate: func(d *Decision, tg *Target) { foreignInstall(d, tg) }, want: ReasonWrongPlace},
		"foreign install, resume":              {op: OpResume, mutate: func(d *Decision, tg *Target) { foreignInstall(d, tg) }, want: ReasonWrongPlace},
		"foreign forge":                        {mutate: func(d *Decision, _ *Target) { d.Principal.Forge = "gitlab" }, want: ReasonWrongPlace},
		"same ID on another forge":             {mutate: func(d *Decision, _ *Target) { d.Principal.Forge = "gitlab"; d.Principal.ID = "42" }, want: ReasonWrongPlace},
		"principal ID with colon":              {mutate: func(d *Decision, _ *Target) { d.Principal.ID = "4:2" }, want: ReasonMalformed},
		"principal ID not ASCII":               {mutate: func(d *Decision, _ *Target) { d.Principal.ID = "4\u00e9" }, want: ReasonMalformed},
		"zero Created":                         {mutate: func(d *Decision, _ *Target) { d.Created = time.Time{} }, want: ReasonMalformed},
		"decision ID empty":                    {mutate: func(d *Decision, _ *Target) { d.ID = "" }, want: ReasonMalformed},
		"decision ID control":                  {mutate: func(d *Decision, _ *Target) { d.ID = "github:\x01" }, want: ReasonMalformed},
		"decision ID with space":               {mutate: func(d *Decision, _ *Target) { d.ID = "a b" }, want: ReasonMalformed},
		"decision ID 1 MiB":                    {mutate: func(d *Decision, _ *Target) { d.ID = strings.Repeat("a", 1<<20) }, want: ReasonMalformed},
		"revision: 40 non-hex":                 {mutate: func(d *Decision, tg *Target) { r := strings.Repeat("g", 40); d.Revision, tg.Revision = r, r }, want: ReasonMalformed},
		"choice not a digest":                  {op: OpDecideSplit, mutate: func(d *Decision, tg *Target) { d.Choice, tg.Choice = "keep-a", "keep-a" }, want: ReasonMalformed},
		"paths: empty element":                 {op: OpApproveLightsOn, mutate: func(_ *Decision, tg *Target) { tg.Paths = []string{"a/", ""} }, want: ReasonWrongPlace},
		"paths: NUL inside an element":         {op: OpApproveLightsOn, mutate: func(_ *Decision, tg *Target) { tg.Paths = []string{"a\x00b", "c"} }, want: ReasonWrongPlace},
		"paths: control and format characters": {op: OpApproveLightsOn, mutate: func(_ *Decision, tg *Target) { tg.Paths = []string{"a\x1b[2K", "b\u202e"} }, want: ReasonWrongPlace},
		"paths: invalid UTF-8":                 {op: OpApproveLightsOn, mutate: func(_ *Decision, tg *Target) { tg.Paths = []string{"a\xffb"} }, want: ReasonWrongPlace},
		"repo with OSC and RLO": {mutate: func(d *Decision, tg *Target) {
			r := "gh\x1b]0;pwned\x07\u202e"
			tg.Scope.ID, tg.Subject.Repo = r, r
			d.Location = Location{Scope: tg.Scope, Subject: tg.Subject}
		}, want: ReasonWrongPlace},
		"subject ID with control": {mutate: func(d *Decision, tg *Target) { tg.Subject.ID = "7\n8"; d.Location.Subject = tg.Subject }, want: ReasonWrongPlace},
		"subject ID 257 bytes": {mutate: func(d *Decision, tg *Target) {
			tg.Subject.ID = strings.Repeat("7", 257)
			d.Location.Subject = tg.Subject
		}, want: ReasonWrongPlace},
		"principal ID 257 bytes":     {mutate: func(d *Decision, _ *Target) { d.Principal.ID = strings.Repeat("7", 257) }, want: ReasonMalformed},
		"decision ID with DEL":       {mutate: func(d *Decision, _ *Target) { d.ID = "abc\x7f" }, want: ReasonMalformed},
		"only d.Revision malformed":  {mutate: func(d *Decision, _ *Target) { d.Revision = "main" }, want: ReasonMalformed},
		"only t.Choice malformed":    {op: OpDecideSplit, mutate: func(_ *Decision, tg *Target) { tg.Choice = "keep-a" }, want: ReasonMalformed},
		"paths: duplicate":           {op: OpApproveLightsOn, mutate: func(_ *Decision, tg *Target) { tg.Paths = []string{"a/", "a/"} }, want: ReasonWrongPlace},
		"paths on a non-area op":     {mutate: func(_ *Decision, tg *Target) { tg.Paths = []string{"a/"} }, want: ReasonWrongPlace},
		"owns only one of two paths": {op: OpApproveLightsOn, mutate: func(_ *Decision, tg *Target) { tg.Paths = []string{"a/", "b/"} }, want: ReasonNoRole},
		// Check order: each row breaks two adjacent checks and expects the earlier one.
		"order 1-2 unauthenticated + bot":         {mutate: func(d *Decision, _ *Target) { d.Authenticated = false; d.Principal.Kind = PrincipalBot }, want: ReasonUnauthenticated},
		"order 2-3 bot + wrong operation":         {mutate: func(d *Decision, _ *Target) { d.Principal.Kind = PrincipalBot; d.Operation = OpRejectScenarios }, want: ReasonNotAPerson},
		"order 3-4 wrong operation + wrong place": {mutate: func(d *Decision, _ *Target) { d.Operation = OpRejectScenarios; d.Location.Scope.ID = repoB }, want: ReasonWrongOperation},
		"order 4-5 wrong place + malformed":       {mutate: func(d *Decision, _ *Target) { d.Location.Scope.ID = repoB; d.Channel = "" }, want: ReasonWrongPlace},
		"order 5-6 malformed + stale":             {mutate: func(d *Decision, _ *Target) { d.Channel = ""; d.Revision = revB }, want: ReasonMalformed},
		"order 6-7 stale + wrong choice":          {mutate: func(d *Decision, _ *Target) { d.Revision = revB; d.Choice = choiceA }, want: ReasonStale},
		"order 7-8 wrong choice + edited":         {mutate: func(d *Decision, _ *Target) { d.Choice = choiceA; d.Integrity = IntegrityEdited }, want: ReasonWrongChoice},
		"order 8-9 edited + expired":              {mutate: func(d *Decision, _ *Target) { d.Integrity = IntegrityEdited; d.Created = t0.Add(-2 * time.Hour) }, want: ReasonEdited},
		"order 9-10 expired + no role":            {mutate: func(d *Decision, _ *Target) { d.Created = t0.Add(-2 * time.Hour); d.Principal.ID = "99" }, want: ReasonExpired},
		"order unauthenticated + expired":         {mutate: func(d *Decision, _ *Target) { d.Authenticated = false; d.Created = t0.Add(-2 * time.Hour) }, want: ReasonUnauthenticated},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			e := newEnv(t, Config{Expiry: map[Operation]time.Duration{OpApproveScenarios: time.Hour}})
			e.allRoles()
			e.roles.owned = map[string]bool{"a/": true, "infra/": true, "docs/": true}
			op := tc.op
			if op == "" {
				op = OpApproveScenarios
			}
			d, tg := caseFor(op)
			tc.mutate(&d, &tg)
			tx := e.store.Begin()
			_, err := e.az.Authorize(t.Context(), tx, d, tg)
			wantDenied(t, err, tc.want)
			if tx.consumeCalls != 0 || len(tx.buf) != 0 {
				t.Errorf("a denial reached Consume (%d calls) or the transaction (%d records)", tx.consumeCalls, len(tx.buf))
			}
			tx.Rollback()
			es := e.denied(t)
			if len(es) != 1 || len(e.granted(t)) != 0 {
				t.Fatalf("%d denial entries, %d grant entries; want 1 and 0", len(es), len(e.granted(t)))
			}
			r := es[0].Record
			if r.Decision.Verdict != audit.VerdictDenied || r.Decision.Reason != string(tc.want) ||
				r.Outcome != "denied" || r.Attrs["denial_reason"] != string(tc.want) {
				t.Errorf("record = %+v", r)
			}
			// The role is recorded only once the role check has run.
			wantRole := ""
			if tc.want == ReasonNoRole {
				wantRole = string(operations()[op].Role)
			}
			if r.Decision.Role != wantRole {
				t.Errorf("role = %q, want %q", r.Decision.Role, wantRole)
			}
			checkEvidence(t, tc.want, r, d, tg)
			if e.store.isConsumed(d.ID) && d.ID != "" {
				t.Error("a denied decision was consumed")
			}
		})
	}
}

func foreignInstall(d *Decision, tg *Target) {
	tg.Scope.ID, tg.Subject.ID = "inst-other", "inst-other"
	d.Location = Location{Scope: tg.Scope, Subject: tg.Subject}
}

// checkEvidence asserts the truthful evidence a denial records for each reason.
func checkEvidence(t *testing.T, reason Reason, r audit.Record, d Decision, tg Target) {
	t.Helper()
	wantAttrs := map[string]string{}
	if reason == ReasonWrongPlace {
		wantAttrs["location_scope_kind"] = string(d.Location.Scope.Kind)
		wantAttrs["location_scope_id"] = d.Location.Scope.ID
		wantAttrs["location_subject_kind"] = string(d.Location.Subject.Kind)
		wantAttrs["location_subject_repo"] = d.Location.Subject.Repo
		wantAttrs["location_subject_id"] = d.Location.Subject.ID
	}
	if reason == ReasonStale {
		wantAttrs["target_revision"] = tg.Revision
	}
	if reason == ReasonWrongChoice {
		wantAttrs["requested_choice"] = d.Choice
		wantAttrs["target_choice"] = tg.Choice
	}
	for k, v := range wantAttrs {
		if got, ok := r.Attrs[k]; !ok || got != sanitize(v) {
			t.Errorf("attr %s = %q (present %v), want %q", k, got, ok, v)
		}
	}
	if validRevision(d.Revision) {
		if r.Decision.Revision != d.Revision {
			t.Errorf("revision = %q, want %q", r.Decision.Revision, d.Revision)
		}
		if _, ok := r.Attrs["requested_revision"]; ok {
			t.Error("requested_revision recorded for a valid revision")
		}
	} else {
		if r.Decision.Revision != "" {
			t.Errorf("an invalid revision was recorded as evidence: %q", r.Decision.Revision)
		}
		if d.Revision != "" && r.Attrs["requested_revision"] != d.Revision {
			t.Errorf("requested_revision = %q", r.Attrs["requested_revision"])
		}
	}
}

func TestAuthorize_DenialDoesNotBurnApproval(t *testing.T) { // SEC-10: wrong-target attempt must not consume
	t.Parallel()
	e := newEnv(t, Config{})
	e.allRoles()
	d, tg := scenariosCase()
	bad := tg
	bad.Revision = revB
	_, err := e.authorize(t, d, bad)
	wantDenied(t, err, ReasonStale)
	if _, err := e.authorize(t, d, tg); err != nil {
		t.Fatalf("valid approval after a wrong-target attempt: %v", err)
	}
}

func TestAuthorize_NoRoleStaysUnconsumed(t *testing.T) { // SEC-10
	t.Parallel()
	e := newEnv(t, Config{})
	d, tg := scenariosCase()
	_, err := e.authorize(t, d, tg)
	wantDenied(t, err, ReasonNoRole)
	e.roles.set(RoleIdeator, true)
	if _, err := e.authorize(t, d, tg); err != nil {
		t.Fatalf("after the role was granted: %v", err)
	}
}

func TestAuthorize_EachOpRequiresItsRole(t *testing.T) { // SEC-10, SEC-6
	t.Parallel()
	allRoles := []Role{RoleIdeator, RolePathOwner, RoleCodeOwner, RoleContractOwner, RoleAdmin}
	for op, pol := range operations() {
		t.Run(string(op), func(t *testing.T) {
			t.Parallel()
			e := newEnv(t, Config{})
			for _, r := range allRoles {
				e.roles.set(r, r != pol.Role)
			}
			d, tg := caseFor(op)
			_, err := e.authorize(t, d, tg)
			wantDenied(t, err, ReasonNoRole)
			for _, r := range allRoles {
				e.roles.set(r, r == pol.Role)
			}
			if _, err := e.authorize(t, d, tg); err != nil {
				t.Fatalf("holding only %s: %v", pol.Role, err)
			}
		})
	}
}

func TestAuthorize_RoleSourceInput(t *testing.T) { // SEC-10
	t.Parallel()
	e := newEnv(t, Config{})
	e.allRoles()
	d, tg := caseFor(OpApprovePathException)
	if _, err := e.authorize(t, d, tg); err != nil {
		t.Fatal(err)
	}
	wantP := Principal{Forge: "github", ID: "42", Kind: PrincipalUser} // no Login
	if diff := cmp.Diff(wantP, e.roles.gotP); diff != "" {
		t.Errorf("principal (-want +got):\n%s", diff)
	}
	if e.roles.gotRole != RolePathOwner {
		t.Errorf("role = %q", e.roles.gotRole)
	}
	if diff := cmp.Diff(tg, e.roles.gotT); diff != "" {
		t.Errorf("target (-want +got):\n%s", diff)
	}
	if d.Principal.Login != "alice" {
		t.Error("caller's decision was mutated")
	}
}

func TestAuthorize_RoleSourceCannotChangeTheGrant(t *testing.T) { // SEC-10: HasRole gets a copy of Paths
	t.Parallel()
	e := newEnv(t, Config{})
	e.allRoles()
	e.roles.hook = func(t Target) { t.Paths[0] = "evil/" }
	d, tg := caseFor(OpApprovePathException)
	g, err := e.authorize(t, d, tg)
	if err != nil {
		t.Fatal(err)
	}
	if want := pathsDigest([]string{"infra/", "docs/"}); e.granted(t)[0].Attrs["paths_digest"] != want {
		t.Error("paths_digest reflects the role source's mutation")
	}
	if diff := cmp.Diff([]string{"infra/", "docs/"}, g.Target.Paths); diff != "" {
		t.Errorf("Grant.Target.Paths (-want +got):\n%s", diff)
	}
	if tg.Paths[0] != "infra/" {
		t.Error("caller's Paths mutated")
	}
}

func TestAuthorize_RoleSourceNotCalledOnEarlierDenial(t *testing.T) { // SEC-10
	t.Parallel()
	e := newEnv(t, Config{})
	e.allRoles()
	d, tg := scenariosCase()
	d.Integrity = IntegrityQuoted
	if _, err := e.authorize(t, d, tg); err == nil {
		t.Fatal("want denial")
	}
	if e.roles.calls != 0 {
		t.Error("role source consulted for a decision that was already denied")
	}
}

func TestAuthorize_AuditActor(t *testing.T) { // SEC-1, SEC-10
	t.Parallel()
	unauth := audit.Actor{Kind: audit.ActorExternal, ID: "unauthenticated"}
	tests := map[string]struct {
		mutate  func(*Decision)
		want    audit.Actor
		claimed string // wanted attrs["claimed_principal"]; empty means absent
	}{
		"unauthenticated claim is never attributed": {
			func(d *Decision) { d.Authenticated = false },
			unauth, "forge=github id=42 login=alice",
		},
		"empty id": {
			func(d *Decision) { d.Principal.ID = "" },
			unauth, "forge=github id= login=alice",
		},
		"empty forge": {
			func(d *Decision) { d.Principal.Forge = "" },
			unauth, "forge= id=42 login=alice",
		},
		"authenticated bot keeps its verified identity": {
			func(d *Decision) { d.Principal.Kind = PrincipalBot },
			audit.Actor{Kind: audit.ActorExternal, ID: "github:42", Display: "alice"},
			"",
		},
		"authenticated app keeps its verified identity": {
			func(d *Decision) { d.Principal.Kind = PrincipalApp },
			audit.Actor{Kind: audit.ActorExternal, ID: "github:42", Display: "alice"},
			"",
		},
		"ambiguous principal ID is not attributed": {
			func(d *Decision) { d.Principal.ID = "4:2" },
			unauth, "forge=github id=4:2 login=alice",
		},
		"control characters in an unauthenticated claim": {
			func(d *Decision) {
				d.Authenticated = false
				d.Principal.Login = "a\x1b[2K\r\nb\u202ec\u0085\u2028\u200b\ufeff"
			},
			unauth, "forge=github id=42 login=a\uFFFD[2K\uFFFD\uFFFDb\uFFFDc\uFFFD\uFFFD\uFFFD\uFFFD",
		},
		"control characters in a verified login": {
			func(d *Decision) { d.Principal.Kind = PrincipalBot; d.Principal.Login = "x\x1b[2K\u061cy" },
			audit.Actor{Kind: audit.ActorExternal, ID: "github:42", Display: "x\uFFFD[2K\uFFFDy"},
			"",
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			e := newEnv(t, Config{})
			e.allRoles()
			d, tg := scenariosCase()
			tc.mutate(&d)
			if _, err := e.authorize(t, d, tg); !errors.Is(err, ErrDenied) {
				t.Fatalf("err = %v", err)
			}
			r := e.denied(t)[0]
			if r.Actor != tc.want {
				t.Errorf("actor = %+v, want %+v", r.Actor, tc.want)
			}
			if got := r.Attrs["claimed_principal"]; got != tc.claimed {
				t.Errorf("claimed_principal = %q, want %q", got, tc.claimed)
			}
		})
	}
}

func TestAuthorize_GrantSanitizesLogin(t *testing.T) { // SEC-10
	t.Parallel()
	e := newEnv(t, Config{})
	e.allRoles()
	d, tg := scenariosCase()
	d.Principal.Login = "bob\x1b[2K\r\n"
	if _, err := e.authorize(t, d, tg); err != nil {
		t.Fatal(err)
	}
	if got := e.granted(t)[0].Actor.Display; got != "bob�[2K��" {
		t.Errorf("display = %q", got)
	}
}

func TestAuthorize_CopiedCommandOnSecondIssue(t *testing.T) { // SEC-10: identical content, different issue
	t.Parallel()
	e := newEnv(t, Config{})
	e.allRoles()
	d, tg := scenariosCase()
	if _, err := e.authorize(t, d, tg); err != nil {
		t.Fatal(err)
	}
	// Issue 8 has the same proposal text, but revisions are unique per subject, and the location differs.
	other := audit.Subject{Kind: audit.SubjectIssue, Repo: repoA, ID: "8"}
	tg2 := tg
	tg2.Subject, tg2.Revision = other, revB
	d2 := d
	d2.ID = "github:issue-comment:1002"
	_, err := e.authorize(t, d2, tg2) // the copied command still names issue 7's location and revision
	wantDenied(t, err, ReasonWrongPlace)
	d3 := d2
	d3.Location.Subject = other // even with the location rewritten, the copied revision is stale
	_, err = e.authorize(t, d3, tg2)
	wantDenied(t, err, ReasonStale)
}

func TestAuthorize_Revocation(t *testing.T) { // SEC-6, SEC-10, NFR-5
	t.Parallel()
	for _, op := range []Operation{OpHalt, OpResume, OpApprovePathException} {
		t.Run(string(op), func(t *testing.T) {
			t.Parallel()
			e := newEnv(t, Config{})
			pol := operations()[op]
			e.roles.owned = map[string]bool{"infra/": true, "docs/": true}
			e.roles.set(pol.Role, true)
			dA, tg := caseFor(op)
			dA.ID = "github:event:A"
			if _, err := e.authorize(t, dA, tg); err != nil {
				t.Fatalf("decision A while the role is held: %v", err)
			}
			// Revocation lands. A second decision by the same principal is denied at execution.
			e.roles.set(pol.Role, false)
			dB := dA
			dB.ID = "github:event:B"
			_, err := e.authorize(t, dB, tg)
			wantDenied(t, err, ReasonNoRole)
			if e.store.isConsumed(dB.ID) {
				t.Error("revoked approval consumed")
			}
			es := e.denied(t)
			if len(es) != 1 {
				t.Fatalf("%d denial entries", len(es))
			}
			if dec := es[0].Decision; dec.Verdict != audit.VerdictDenied || dec.Reason != "no-role" || dec.Role != string(pol.Role) {
				t.Errorf("decision = %+v", dec)
			}
			if len(e.granted(t)) != 1 {
				t.Errorf("%d grant entries, want only A's", len(e.granted(t)))
			}
			// Granting the role again must not resurrect anything cached: a fresh check passes.
			e.roles.set(pol.Role, true)
			if _, err := e.authorize(t, dB, tg); err != nil {
				t.Fatalf("with role restored: %v", err)
			}
		})
	}
}

func TestAuthorize_HaltResumeByNonAdmin(t *testing.T) { // SEC-6, SEC-11
	t.Parallel()
	for _, op := range []Operation{OpHalt, OpResume} {
		t.Run(string(op), func(t *testing.T) {
			t.Parallel()
			e := newEnv(t, Config{})
			e.roles.set(RoleIdeator, true) // holds a role, but not admin
			d, tg := caseFor(op)
			_, err := e.authorize(t, d, tg)
			wantDenied(t, err, ReasonNoRole)
			es := e.denied(t)
			if len(es) != 1 || es[0].Decision.Operation != string(op) || es[0].Decision.Role != "admin" ||
				es[0].Decision.Verdict != audit.VerdictDenied || es[0].Subject.Kind != audit.SubjectInstall {
				t.Errorf("entries = %+v", es)
			}
			if len(e.granted(t)) != 0 {
				t.Error("grant entry written")
			}
		})
	}
}

func TestAuthorize_StaleOwnerApproval(t *testing.T) { // CON-2, SEC-10, SEC-11
	t.Parallel()
	e := newEnv(t, Config{})
	e.allRoles()
	d, tg := caseFor(OpActivateContract)
	d.Revision, tg.Revision = sha1A, sha1B // approved at sha-1, executed at sha-2
	_, err := e.authorize(t, d, tg)
	wantDenied(t, err, ReasonStale)
	if es := e.denied(t); len(es) != 1 || es[0].Decision.Reason != "stale" {
		t.Errorf("entries = %+v", es)
	}
	if e.store.isConsumed(d.ID) {
		t.Error("consumed")
	}
}

func TestAuthorize_RoleSourceError(t *testing.T) { // SEC-10: fail closed
	t.Parallel()
	e := newEnv(t, Config{})
	e.allRoles()
	cause := errors.New("directory unavailable")
	e.roles.setErr(cause)
	d, tg := scenariosCase()
	_, err := e.authorize(t, d, tg)
	wantDenied(t, err, ReasonRoleError)
	if !errors.Is(err, cause) {
		t.Error("cause not visible to the caller")
	}
	es := e.denied(t)
	if len(es) != 1 || es[0].Decision.Reason != "role-error" || es[0].Decision.Role != "ideator" {
		t.Errorf("entries = %+v", es)
	}
	if e.store.isConsumed(d.ID) {
		t.Error("consumed on role error")
	}
}

func TestAuthorize_UnknownOperationAudited(t *testing.T) { // SEC-10, SEC-1
	t.Parallel()
	tests := map[string]struct {
		dOp, tOp Operation
		wantOp   string
		wantReq  string
	}{
		"both unknown":        {"do-something", "do-other", "unknown", "do-something"},
		"decision known":      {OpApproveScenarios, "nope", "approve-scenarios", "approve-scenarios"},
		"target known":        {"do-something", OpResume, "resume", "do-something"},
		"empty both":          {"", "", "unknown", ""},
		"control characters":  {"x\x1b[2Ky", "", "unknown", "x�[2Ky"},
		"decision op is text": {"approve-scenarios; DROP", OpApproveScenarios, "approve-scenarios", "approve-scenarios; DROP"},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			e := newEnv(t, Config{})
			e.allRoles()
			d, tg := scenariosCase()
			d.Operation, tg.Operation = tc.dOp, tc.tOp
			_, err := e.authorize(t, d, tg)
			wantDenied(t, err, ReasonWrongOperation)
			r := e.denied(t)[0].Record
			want := &audit.Decision{Operation: tc.wantOp, Revision: revA, Verdict: audit.VerdictDenied, Reason: "wrong-operation"}
			if diff := cmp.Diff(want, r.Decision); diff != "" {
				t.Errorf("decision (-want +got):\n%s", diff)
			}
			if r.Target != tc.wantOp || r.Attrs["requested_operation"] != tc.wantReq {
				t.Errorf("target = %q, attrs = %v", r.Target, r.Attrs)
			}
		})
	}
}

func TestAuthorize_UnrecordableSubjectFallsBackToInstall(t *testing.T) { // SEC-10: every denial is audited
	t.Parallel()
	tests := map[string]audit.Subject{
		"empty ID":     {Kind: audit.SubjectIssue, Repo: repoA},
		"empty repo":   {Kind: audit.SubjectIssue, ID: "7"},
		"garbage kind": {Kind: "x\x1b", Repo: repoA, ID: "7"},
		"zero":         {},
	}
	for name, sub := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			e := newEnv(t, Config{})
			e.allRoles()
			d, tg := scenariosCase()
			d.Location.Subject, tg.Subject = sub, sub
			_, err := e.authorize(t, d, tg)
			wantDenied(t, err, ReasonWrongPlace)
			es := e.denied(t)
			if len(es) != 1 {
				t.Fatalf("%d entries", len(es))
			}
			if want := (audit.Subject{Kind: audit.SubjectInstall, ID: installID}); es[0].Subject != want {
				t.Errorf("subject = %+v", es[0].Subject)
			}
			if _, ok := es[0].Attrs["target_subject_id"]; !ok {
				t.Errorf("raw subject not recorded: %v", es[0].Attrs)
			}
		})
	}
}

func TestAuthorize_DenialClipsClientStrings(t *testing.T) { // SEC-10
	t.Parallel()
	e := newEnv(t, Config{})
	e.allRoles()
	d, tg := scenariosCase()
	huge := strings.Repeat("x", 100_000)
	d.Operation = Operation(huge)
	d.ID = huge
	d.Principal.Login = huge + "\xff"
	d.Principal.Forge = huge
	d.Channel = Channel(huge)
	d.Revision = huge
	_, err := e.authorize(t, d, tg)
	wantDenied(t, err, ReasonWrongOperation)
	es := e.denied(t)
	if len(es) != 1 {
		t.Fatal("oversized client strings were not clipped, so audit rejected the denial")
	}
	if n := len(es[0].Attrs["decision_id"]); n != denialClipBytes {
		t.Errorf("decision_id length = %d", n)
	}
}

func TestAuthorize_GrantNeverClipped(t *testing.T) { // SEC-10: an oversized value is an error, never a grant
	t.Parallel()
	e := newEnv(t, Config{})
	e.allRoles()
	d, tg := scenariosCase()
	d.Principal.Login = strings.Repeat("x", 5000)
	_, err := e.authorize(t, d, tg)
	if err == nil || errors.Is(err, ErrDenied) {
		t.Fatalf("err = %v, want a non-denial error", err)
	}
	if len(e.granted(t)) != 0 || e.store.isConsumed(d.ID) {
		t.Error("grant committed or consumed")
	}
}

type failingAuditor struct{}

func (failingAuditor) Append(context.Context, audit.Record) (audit.Entry, error) {
	return audit.Entry{}, errors.New("audit down")
}

func TestAuthorize_DenialAuditFailureStaysDenial(t *testing.T) { // SEC-10, NFR-4
	t.Parallel()
	e := newEnv(t, Config{})
	az, err := New(Config{InstallID: installID, Forge: forgeName}, e.roles, failingAuditor{}, func() time.Time { return t0 })
	if err != nil {
		t.Fatal(err)
	}
	d, tg := scenariosCase()
	d.Authenticated = false
	_, err = az.Authorize(t.Context(), e.store.Begin(), d, tg)
	wantDenied(t, err, ReasonUnauthenticated)
	if err.Error() == (&DeniedError{Reason: ReasonUnauthenticated}).Error() {
		t.Error("audit failure not visible to the caller")
	}
}

func TestAuthorize_DenialSurvivesCancelledContext(t *testing.T) { // SEC-10: probing can't be erased by disconnecting
	t.Parallel()
	t.Run("cancelled before Authorize", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t, Config{})
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		d, tg := scenariosCase()
		d.Authenticated = false
		_, err := e.az.Authorize(ctx, e.store.Begin(), d, tg)
		wantDenied(t, err, ReasonUnauthenticated)
		if errors.Is(err, context.Canceled) {
			t.Errorf("denial audit failed: %v", err)
		}
		if es := e.denied(t); len(es) != 1 || es[0].Decision.Reason != "unauthenticated" {
			t.Errorf("entries = %+v", es)
		}
	})
	t.Run("deadline expires inside HasRole", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t, Config{})
		e.allRoles()
		e.roles.block = true // the role source really waits for the caller's context
		ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
		defer cancel()
		d, tg := scenariosCase()
		_, err := e.az.Authorize(ctx, e.store.Begin(), d, tg)
		wantDenied(t, err, ReasonRoleError)
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("err = %v, want the role source's deadline error joined", err)
		}
		es := e.denied(t)
		if len(es) != 1 || es[0].Decision.Reason != "role-error" {
			t.Errorf("entries = %+v", es)
		}
	})
}

// blockingAuditor blocks until its context is done.
type blockingAuditor struct{}

func (blockingAuditor) Append(ctx context.Context, _ audit.Record) (audit.Entry, error) {
	<-ctx.Done()
	return audit.Entry{}, ctx.Err()
}

func TestAuthorize_DenialAuditTimeout(t *testing.T) { // SEC-10: a stuck audit store can't hang the caller
	t.Parallel()
	e := newEnv(t, Config{})
	az, err := New(Config{InstallID: installID, Forge: forgeName, DenialAuditTimeout: 50 * time.Millisecond},
		e.roles, blockingAuditor{}, func() time.Time { return t0 })
	if err != nil {
		t.Fatal(err)
	}
	d, tg := scenariosCase()
	d.Authenticated = false
	start := time.Now()
	_, err = az.Authorize(t.Context(), e.store.Begin(), d, tg)
	wantDenied(t, err, ReasonUnauthenticated)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("err = %v, want the audit timeout joined", err)
	}
	if time.Since(start) > 10*time.Second {
		t.Error("Authorize hung")
	}
}

func TestAuthorize_Replay(t *testing.T) { // SEC-6, SEC-10
	t.Parallel()
	e := newEnv(t, Config{})
	e.allRoles()
	d1, tg1 := caseFor(OpResume)
	d1.ID = "github:admin:h1"
	d1.Revision, tg1.Revision = revA, revA // halt H1
	if _, err := e.authorize(t, d1, tg1); err != nil {
		t.Fatal(err)
	}
	// The same resume against the same halt, again: replayed. The denial lands in the denial log, not the tx.
	tx := e.store.Begin()
	_, err := e.az.Authorize(t.Context(), tx, d1, tg1)
	wantDenied(t, err, ReasonReplayed)
	if len(tx.buf) != 0 {
		t.Errorf("replay wrote %d records into the transaction", len(tx.buf))
	}
	tx.Rollback()
	es := e.denied(t)
	if len(es) != 1 || es[0].Decision.Reason != "replayed" || es[0].Decision.Verdict != audit.VerdictDenied || es[0].Decision.Role != "admin" {
		t.Errorf("denials = %+v", es)
	}
	if len(e.granted(t)) != 1 {
		t.Errorf("%d grant entries, want the first only", len(e.granted(t)))
	}
	if !e.store.isConsumed(d1.ID) {
		t.Error("rolling back the replay released the original consumption")
	}

	// A resume for halt H1 delivered after H2 began is stale, and does not burn its ID.
	d2, tg2 := d1, tg1
	d2.ID = "github:admin:h1-late"
	tg2.Revision = revB // halt H2
	_, err = e.authorize(t, d2, tg2)
	wantDenied(t, err, ReasonStale)
	if e.store.isConsumed(d2.ID) {
		t.Error("stale resume consumed")
	}
}

func TestAuthorize_GrantAuditFailureRollsBack(t *testing.T) { // SEC-10, NFR-4
	t.Parallel()
	e := newEnv(t, Config{})
	e.allRoles()
	d, tg := scenariosCase()
	e.store.setFail(true)
	_, err := e.authorize(t, d, tg)
	if err == nil || errors.Is(err, ErrDenied) {
		t.Fatalf("err = %v, want a non-denial error", err)
	}
	if e.store.isConsumed(d.ID) {
		t.Error("decision stayed consumed after rollback")
	}
	if len(e.granted(t)) != 0 || len(e.denied(t)) != 0 {
		t.Error("entries after failed grant")
	}
	e.store.setFail(false)
	if _, err := e.authorize(t, d, tg); err != nil {
		t.Fatalf("retry: %v", err)
	}
	if n := len(e.granted(t)); n != 1 {
		t.Errorf("%d grant entries after retry, want 1", n)
	}
}

func TestAuthorize_RolledBackGrantLeavesNothing(t *testing.T) { // SEC-10, NFR-4
	t.Parallel()
	e := newEnv(t, Config{})
	e.allRoles()
	d, tg := scenariosCase()
	tx := e.store.Begin()
	if _, err := e.az.Authorize(t.Context(), tx, d, tg); err != nil {
		t.Fatal(err)
	}
	tx.Rollback() // the caller's own state change failed
	if len(e.granted(t)) != 0 || len(e.denied(t)) != 0 || e.store.isConsumed(d.ID) {
		t.Error("a rolled-back grant left evidence or a consumption behind")
	}
}

type consumeFails struct{ fakeTx }

func (*consumeFails) Consume(context.Context, string) error { return errors.New("db down") }

func TestAuthorize_ConsumeErrorIsNotDenial(t *testing.T) { // SEC-10
	t.Parallel()
	e := newEnv(t, Config{})
	e.allRoles()
	d, tg := scenariosCase()
	_, err := e.az.Authorize(t.Context(), &consumeFails{fakeTx{s: e.store}}, d, tg)
	if err == nil || errors.Is(err, ErrDenied) {
		t.Fatalf("err = %v, want a plain error so the caller rolls back", err)
	}
	if len(e.granted(t)) != 0 || len(e.denied(t)) != 0 {
		t.Error("an audit entry was written")
	}
}

func TestAuthorize_Race(t *testing.T) { // SEC-10, NFR-5
	t.Parallel()
	e := newEnv(t, Config{})
	e.allRoles()
	d, tg := scenariosCase()
	bad := tg
	bad.Revision = revB
	var wg sync.WaitGroup
	results := make([]error, 3)
	commitErrs := make([]error, 3)
	for i, target := range []Target{tg, bad, tg} {
		wg.Go(func() {
			tx := e.store.Begin()
			_, err := e.az.Authorize(t.Context(), tx, d, target)
			if err != nil {
				tx.Rollback()
			} else {
				commitErrs[i] = tx.Commit(t.Context())
			}
			results[i] = err
		})
	}
	wg.Wait()
	if err := errors.Join(commitErrs...); err != nil {
		t.Fatal(err)
	}
	granted := 0
	for i, err := range results {
		switch {
		case err == nil:
			granted++
		case i == 1:
			wantDenied(t, err, ReasonStale)
		default:
			wantDenied(t, err, ReasonReplayed)
		}
	}
	if granted != 1 || len(e.granted(t)) != 1 {
		t.Fatalf("%d grants, %d grant entries, want exactly one", granted, len(e.granted(t)))
	}
}

func TestAuthorize_Expiry(t *testing.T) { // SEC-10
	t.Parallel()
	t.Run("no expiry: seven days old succeeds", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t, Config{})
		e.allRoles()
		d, tg := scenariosCase()
		d.Created = t0.Add(-7 * 24 * time.Hour)
		if _, err := e.authorize(t, d, tg); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("zero expiry means none", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t, Config{Expiry: map[Operation]time.Duration{OpApproveScenarios: 0}})
		e.allRoles()
		d, tg := scenariosCase()
		d.Created = t0.Add(-7 * 24 * time.Hour)
		if _, err := e.authorize(t, d, tg); err != nil {
			t.Fatal(err)
		}
	})
	tests := map[string]struct {
		age  time.Duration
		want Reason // empty means granted
	}{
		"59m59s":              {59*time.Minute + 59*time.Second, ""},
		"exactly 1h":          {time.Hour, ""},
		"1h0m1s":              {time.Hour + time.Second, ReasonExpired},
		"just under a minute": {-59 * time.Second, ""},
		"2 minutes ahead":     {-2 * time.Minute, ReasonMalformed},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			e := newEnv(t, Config{Expiry: map[Operation]time.Duration{OpApproveScenarios: time.Hour}})
			e.allRoles()
			d, tg := scenariosCase()
			d.Created = t0.Add(-tc.age)
			_, err := e.authorize(t, d, tg)
			if tc.want == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			wantDenied(t, err, tc.want)
		})
	}
	t.Run("expiry is per operation", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t, Config{Expiry: map[Operation]time.Duration{OpResume: time.Minute}})
		e.allRoles()
		d, tg := scenariosCase()
		d.Created = t0.Add(-time.Hour)
		if _, err := e.authorize(t, d, tg); err != nil {
			t.Fatal(err)
		}
	})
}

func TestAuthorize_DoesNotMutateInputs(t *testing.T) { // NFR-5
	t.Parallel()
	e := newEnv(t, Config{})
	e.allRoles()
	d, tg := caseFor(OpApprovePathException)
	d0, tg0 := d, tg
	tg0.Paths = slices.Clone(tg.Paths)
	g, err := e.authorize(t, d, tg)
	if err != nil {
		t.Fatal(err)
	}
	if diff := cmp.Diff(d0, d); diff != "" {
		t.Errorf("decision mutated:\n%s", diff)
	}
	if diff := cmp.Diff(tg0, tg); diff != "" {
		t.Errorf("target mutated:\n%s", diff)
	}
	tg.Paths[0] = "mutated"
	if g.Target.Paths[0] == "mutated" {
		t.Error("grant aliases the caller's Paths")
	}
}

func TestAuthorize_NilTx(t *testing.T) { // SEC-10
	t.Parallel()
	e := newEnv(t, Config{})
	d, tg := scenariosCase()
	if _, err := e.az.Authorize(t.Context(), nil, d, tg); err == nil || errors.Is(err, ErrDenied) {
		t.Errorf("err = %v", err)
	}
}

func TestAuthorize_DenialClipBoundaries(t *testing.T) { // SEC-10: every denial is audited, whatever the size
	t.Parallel()
	t.Run("multibyte character straddling the clip boundary", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t, Config{})
		e.allRoles()
		d, tg := scenariosCase()
		d.ID = strings.Repeat("a", denialClipBytes-1) + "\u00e9" + "tail" // the 2-byte rune spans bytes 1023-1024
		_, err := e.authorize(t, d, tg)
		wantDenied(t, err, ReasonMalformed)
		es := e.denied(t)
		if len(es) != 1 {
			t.Fatalf("%d denial entries", len(es))
		}
		if got := es[0].Attrs["decision_id"]; !utf8.ValidString(got) || len(got) > denialClipBytes {
			t.Errorf("decision_id = %d bytes, valid UTF-8 %v", len(got), utf8.ValidString(got))
		}
	})
	for name, mutate := range map[string]func(*Target){
		"oversized subject ID":   func(tg *Target) { tg.Subject.ID = strings.Repeat("x", 5000) },
		"oversized subject repo": func(tg *Target) { tg.Subject.Repo = strings.Repeat("x", 5000) },
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			e := newEnv(t, Config{})
			e.allRoles()
			d, tg := scenariosCase()
			mutate(&tg)
			d.Location.Subject = tg.Subject
			_, err := e.authorize(t, d, tg)
			wantDenied(t, err, ReasonWrongPlace)
			es := e.denied(t)
			if len(es) != 1 {
				t.Fatalf("%d denial entries", len(es))
			}
			if n := max(len(es[0].Subject.ID), len(es[0].Subject.Repo)); n > denialClipBytes {
				t.Errorf("subject not clipped: %d bytes", n)
			}
		})
	}
}
