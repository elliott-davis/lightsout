// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

// Package audit is the append-only, hash-chained audit log (NFR-4, RUN-5, AGT-6).
//
// The log is a domain concept, not slog output. Every entry names the actor's workload identity and the agent
// template version (RUN-5), and every agent tool call, model call and repo write carries the change or issue it
// belongs to (AGT-6). Authorization decisions, granted and denied, carry the evidence SEC-10 asks for.
//
// There is deliberately no update, delete, truncate, rewrite or reorder operation anywhere in the package API
// (NFR-4).
//
// The hash chain is unkeyed. It detects corruption and inconsistent edits: a changed entry, a reorder or a
// mid-chain deletion that leaves the rest of the chain unchanged fails [Log.Verify]. It does not detect a
// deliberate rewrite, because anyone who can write the storage can recompute every hash from the edit point
// onward, and it cannot detect removal of the last entries, because a shorter chain is still a valid chain.
// Both need a checkpoint: save a [Head] from [Log.Head] somewhere outside the log's storage and check it with
// [Log.VerifyAgainst]. Durable anchoring of checkpoints is a later work item.
//
// Entries are claims made by whoever holds the [Log], kept as evidence for later review. They must never be read
// back as authorization input: "a granted decision exists, so proceed" is wrong. SEC-10 and NFR-5 require
// identity, role, scope and revision to be rechecked at execution time against current sources.
//
// Holding a [Backend] (including [Memory] and [File]) is a write capability: a backend can append entries with
// any seal. Only the owner of a [Log] should hold its backend.
package audit

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// FormatVersion is the entry format version. It is part of the hashed bytes, so a later format can verify old
// entries.
const FormatVersion = 1

// Size bounds enforced on every appended [Record].
const (
	// MaxStringBytes is the largest allowed length of any single string field, attribute key or value.
	MaxStringBytes = 4096
	// MaxAttrs is the largest allowed number of attributes.
	MaxAttrs = 64
	// MaxAttrKeyBytes is the largest allowed attribute key length. Keys are 1..MaxAttrKeyBytes bytes of [a-z0-9_.-].
	MaxAttrKeyBytes = 128
	// MaxRecordBytes is the largest allowed total length of all strings (including attribute keys and values).
	MaxRecordBytes = 64 << 10
)

// ActorKind says what sort of principal acted.
type ActorKind string

// Actor kinds.
const (
	ActorAgent   ActorKind = "agent"
	ActorHuman   ActorKind = "human"
	ActorFactory ActorKind = "factory" // the control plane itself
	// ActorExternal is a bot, app or unverified principal. It can only appear on [ActionDecision] entries, so a
	// denial of such a principal can be recorded truthfully.
	ActorExternal ActorKind = "external"
)

// Actor is who performed an action. On an [ActionDecision] entry it is the principal whose action is being
// authorized, not the component that made the decision.
type Actor struct {
	Kind ActorKind
	// ID is the stable identity. Agent and factory: the workload identity (RUN-5). Human: a forge-scoped stable
	// ID such as "github:12345".
	ID string
	// Display is optional, for example a forge login. It is never used for identity.
	Display string
}

// SubjectKind says what the action was about.
type SubjectKind string

// Subject kinds.
const (
	SubjectChange  SubjectKind = "change"  // one PR
	SubjectIssue   SubjectKind = "issue"   // intake work before any PR exists
	SubjectInstall SubjectKind = "install" // the whole installation
)

// Subject is what an action was about.
type Subject struct {
	Kind SubjectKind
	// Repo is the forge-scoped repository ID. Required for change and issue, empty for install.
	Repo string
	// ID is the change ID, issue number or installation ID.
	ID string
}

// Action is the closed set of audited action types.
type Action string

// Actions.
const (
	ActionToolCall        Action = "tool-call"
	ActionModelCall       Action = "model-call"
	ActionRepoWrite       Action = "repo-write"
	ActionDecision        Action = "authz-decision"
	ActionStateTransition Action = "state-transition"
	ActionAdmin           Action = "admin"
	// ActionLink records that a change came from an issue's intake work. The Subject is the change and Record.Link
	// is the issue.
	ActionLink Action = "link"
)

// Verdict is the outcome of an authorization decision.
type Verdict string

// Verdicts.
const (
	VerdictGranted Verdict = "granted"
	VerdictDenied  Verdict = "denied"
)

// Decision is the evidence for one authorization decision (SEC-10). It is required when the action is
// [ActionDecision] and forbidden otherwise.
type Decision struct {
	Operation string // the intended action, for example "approve-scenarios" or "resume"
	// Role is the role that was checked. Required for a granted verdict. A denial may lack evidence the request
	// never supplied, so it may be empty when the verdict is denied.
	Role string
	// Revision is the exact proposal revision the decision binds to. The authz package requires a 40- or 64-digit
	// lowercase hex digest (a git SHA or a SHA-256), never a branch or tag. The audit log enforces that for a granted verdict and may
	// be empty on a denial, for the same reason as Role.
	Revision string
	Verdict  Verdict
	Reason   string // why, especially for denials; optional for granted
}

// Record is what callers supply to [Log.Append].
//
// Attrs carries extra detail. The log stores it verbatim and forever, so callers must redact secrets and private
// holdout content before appending.
type Record struct {
	Actor           Actor
	TemplateVersion string // agent template version (RUN-5), or the factory build version; required for agent and factory actors
	Subject         Subject
	Action          Action
	Target          string // for example a tool name, model ID, file path or state name
	Outcome         string // short, for example "ok", "error" or "denied"; for a decision, empty or the verdict
	Decision        *Decision
	Link            *Subject // the issue a change came from; required for ActionLink, forbidden otherwise
	Attrs           map[string]string
}

// Hash is a SHA-256 digest.
type Hash [32]byte

// Entry is one sealed log entry.
type Entry struct {
	Format int
	Seq    uint64    // starts at 1 and is contiguous; entries are ordered by Seq, not by Time
	Time   time.Time // UTC, as the log's clock reported it, truncated to microseconds, in years 1970..9999
	Record
	PrevHash Hash // zero for Seq 1
	Hash     Hash
}

// Head identifies the end of the chain. Seq 0 with a zero Hash means the log is empty.
type Head struct {
	Seq  uint64
	Hash Hash
}

// Errors.
var (
	// ErrInvalidRecord is wrapped by every record validation failure.
	ErrInvalidRecord = errors.New("audit: invalid record")
	// ErrBrokenChain is wrapped by every chain verification failure.
	ErrBrokenChain = errors.New("audit: broken chain")
	// ErrStoreFailed means a backend failed a write and refuses further appends because its tail is unknown.
	ErrStoreFailed = errors.New("audit: store failed")
	// ErrClosed means the backend was closed.
	ErrClosed = errors.New("audit: closed")
	// ErrLocked means another File already holds the audit file.
	ErrLocked = errors.New("audit: file is locked by another writer")
	// ErrInsecureFile means the audit file is not a regular file owned by the current user with no group or
	// other permissions.
	ErrInsecureFile = errors.New("audit: insecure audit file")
)

// RecordError describes why a record was rejected. It wraps [ErrInvalidRecord].
type RecordError struct {
	Field  string
	Reason string
}

func (e *RecordError) Error() string {
	return fmt.Sprintf("audit: invalid record: %s: %s", e.Field, e.Reason)
}

// Unwrap returns [ErrInvalidRecord].
func (e *RecordError) Unwrap() error { return ErrInvalidRecord }

// StoreError reports a failed backend write. The entry with this Seq and Hash may or may not be persisted: after
// reopening, reconcile against the tail of the log before retrying. It wraps [ErrStoreFailed] and the cause.
type StoreError struct {
	Seq  uint64
	Hash Hash
	Err  error
}

func (e *StoreError) Error() string {
	return fmt.Sprintf("audit: store failed at seq %d (entry may or may not be persisted): %v", e.Seq, e.Err)
}

// Unwrap returns [ErrStoreFailed] and the cause.
func (e *StoreError) Unwrap() []error { return []error{ErrStoreFailed, e.Err} }

// ChainError names the first entry position at which verification failed. It wraps [ErrBrokenChain].
type ChainError struct {
	Seq    uint64 // the position (sequence number) that failed to verify
	Reason string
}

func (e *ChainError) Error() string {
	return fmt.Sprintf("audit: broken chain at seq %d: %s", e.Seq, e.Reason)
}

// Unwrap returns [ErrBrokenChain].
func (e *ChainError) Unwrap() error { return ErrBrokenChain }

// String returns the hash as lowercase hex.
func (h Hash) String() string { return hex.EncodeToString(h[:]) }

// MarshalText encodes the hash as lowercase hex.
func (h Hash) MarshalText() ([]byte, error) { return []byte(h.String()), nil }

// UnmarshalText decodes a 64-character hex hash.
func (h *Hash) UnmarshalText(text []byte) error {
	if len(text) != 2*len(h) {
		return fmt.Errorf("audit: hash must be %d hex characters, got %d", 2*len(h), len(text))
	}
	var out Hash
	for i := range out {
		hi, ok1 := unhex(text[2*i])
		lo, ok2 := unhex(text[2*i+1])
		if !ok1 || !ok2 {
			return errors.New("audit: hash is not lowercase hex")
		}
		out[i] = hi<<4 | lo
	}
	*h = out
	return nil
}

func unhex(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	}
	return 0, false
}

// String renders the entry on one line with every value quoted, so control characters in the data cannot forge
// or hide display output. Attributes are printed as attr.<key>, so an attribute cannot impersonate a real field.
func (e Entry) String() string {
	var b strings.Builder
	q := strconv.Quote
	fmt.Fprintf(&b, "seq=%d time=%s actor_kind=%s actor_id=%s template=%s subject_kind=%s subject_repo=%s subject_id=%s action=%s target=%s outcome=%s",
		e.Seq, q(e.Time.UTC().Format(time.RFC3339Nano)), q(string(e.Actor.Kind)), q(e.Actor.ID), q(e.TemplateVersion),
		q(string(e.Subject.Kind)), q(e.Subject.Repo), q(e.Subject.ID), q(string(e.Action)), q(e.Target), q(e.Outcome))
	if e.Actor.Display != "" {
		fmt.Fprintf(&b, " display=%s", q(e.Actor.Display))
	}
	if d := e.Decision; d != nil {
		fmt.Fprintf(&b, " decision_operation=%s decision_role=%s decision_revision=%s decision_verdict=%s decision_reason=%s",
			q(d.Operation), q(d.Role), q(d.Revision), q(string(d.Verdict)), q(d.Reason))
	}
	if l := e.Link; l != nil {
		fmt.Fprintf(&b, " link_kind=%s link_repo=%s link_id=%s", q(string(l.Kind)), q(l.Repo), q(l.ID))
	}
	for _, k := range sortedKeys(e.Attrs) {
		name := k
		if !validAttrKey(k) {
			name = q(k)
		}
		fmt.Fprintf(&b, " attr.%s=%s", name, q(e.Attrs[k]))
	}
	fmt.Fprintf(&b, " hash=%s", e.Hash)
	return b.String()
}

func headOf(e Entry) Head { return Head{Seq: e.Seq, Hash: e.Hash} }

func cloneRecord(r Record) Record {
	if r.Decision != nil {
		d := *r.Decision
		r.Decision = &d
	}
	if r.Link != nil {
		l := *r.Link
		r.Link = &l
	}
	if len(r.Attrs) == 0 {
		r.Attrs = nil
	} else {
		m := make(map[string]string, len(r.Attrs))
		for k, v := range r.Attrs {
			m[k] = v
		}
		r.Attrs = m
	}
	return r
}

func cloneEntry(e Entry) Entry {
	e.Record = cloneRecord(e.Record)
	return e
}

func cloneEntries(es []Entry) []Entry {
	out := make([]Entry, len(es))
	for i := range es {
		out[i] = cloneEntry(es[i])
	}
	return out
}
