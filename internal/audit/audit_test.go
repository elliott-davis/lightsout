// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
)

var t0 = time.Date(2026, 3, 4, 5, 6, 7, 123456789, time.UTC)

// stepClock returns a clock that advances one second per call.
func stepClock() func() time.Time {
	var mu sync.Mutex
	t := t0
	return func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		t = t.Add(time.Second)
		return t
	}
}

func agentRec() Record {
	return Record{
		Actor:           Actor{Kind: ActorAgent, ID: "spiffe://lightsout/agent/impl-1", Display: "impl"},
		TemplateVersion: "implementor@v3",
		Subject:         Subject{Kind: SubjectChange, Repo: "github:99", ID: "42"},
		Action:          ActionToolCall,
		Target:          "bash",
		Outcome:         "ok",
		Attrs:           map[string]string{"exit": "0"},
	}
}

// testRev is a valid revision digest for granted decisions.
const testRev = "0123456789abcdef0123456789abcdef01234567"

func decisionRec(v Verdict) Record {
	return Record{
		Actor:   Actor{Kind: ActorHuman, ID: "github:12345", Display: "octocat"},
		Subject: Subject{Kind: SubjectChange, Repo: "github:99", ID: "42"},
		Action:  ActionDecision,
		Target:  "scenarios",
		Outcome: string(v),
		Decision: &Decision{
			Operation: "approve-scenarios", Role: "code-owner", Revision: testRev, Verdict: v, Reason: "because",
		},
	}
}

// secureDir returns a fresh temporary directory with mode 0700. The file backend refuses a group-writable parent,
// and t.TempDir() is 0775 under the common umask 002.
func secureDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return dir
}

func newMemLog(t *testing.T) *Log {
	t.Helper()
	l, err := New(NewMemory(), stepClock())
	if err != nil {
		t.Fatal(err)
	}
	return l
}

// newFileLog creates a new audit file at path and returns a log over it.
func newFileLog(t *testing.T, path string) (*Log, *File) {
	t.Helper()
	f, err := CreateFile(t.Context(), path)
	if errors.Is(err, errors.ErrUnsupported) {
		t.Skip("file backend unsupported on this platform")
	}
	if err != nil {
		t.Fatal(err)
	}
	return logOver(t, f), f
}

// reopenFileLog opens the existing audit file at path and returns a log over it.
func reopenFileLog(t *testing.T, path string) (*Log, *File) {
	t.Helper()
	f, err := OpenFile(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	return logOver(t, f), f
}

func logOver(t *testing.T, f *File) *Log {
	t.Helper()
	t.Cleanup(func() { _ = f.Close() })
	l, err := New(f, stepClock())
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func TestNew_NilArgs(t *testing.T) { // NFR-4
	t.Parallel()
	if _, err := New(nil, time.Now); err == nil {
		t.Error("nil backend accepted")
	}
	if _, err := New(NewMemory(), nil); err == nil {
		t.Error("nil clock accepted")
	}
}

func TestAppend_RecordsActorAndTemplate(t *testing.T) { // RUN-5
	t.Parallel()
	l := newMemLog(t)
	e, err := l.Append(t.Context(), agentRec())
	if err != nil {
		t.Fatal(err)
	}
	if e.Actor.ID != "spiffe://lightsout/agent/impl-1" || e.TemplateVersion != "implementor@v3" || e.Actor.Kind != ActorAgent {
		t.Errorf("entry lost identity: %+v", e)
	}
	got, err := l.Read(t.Context(), 1, 10)
	if err != nil || len(got) != 1 {
		t.Fatalf("Read = %v, %v", got, err)
	}
	if diff := cmp.Diff(e, got[0]); diff != "" {
		t.Errorf("read differs from appended (-append +read):\n%s", diff)
	}

	t.Run("agent without template version is rejected", func(t *testing.T) {
		t.Parallel()
		r := agentRec()
		r.TemplateVersion = ""
		assertInvalid(t, r, "template_version")
	})
	for _, kind := range []ActorKind{ActorAgent, ActorHuman, ActorFactory} {
		t.Run("missing actor id "+string(kind), func(t *testing.T) {
			t.Parallel()
			r := agentRec()
			r.Actor.Kind = kind
			r.Actor.ID = ""
			r.Action = ActionStateTransition
			assertInvalid(t, r, "actor.id")
		})
	}
	t.Run("unknown actor kind", func(t *testing.T) {
		t.Parallel()
		r := agentRec()
		r.Actor.Kind = "robot"
		assertInvalid(t, r, "actor.kind")
	})
	t.Run("human may omit template version", func(t *testing.T) {
		t.Parallel()
		r := agentRec()
		r.Actor.Kind = ActorHuman
		r.TemplateVersion = ""
		r.Action = ActionStateTransition
		if _, err := l.Append(t.Context(), r); err != nil {
			t.Errorf("human entry without template version rejected: %v", err)
		}
	})
}

// assertInvalid checks that r is rejected on field and leaves a fresh log untouched.
func assertInvalid(t *testing.T, r Record, field string) {
	t.Helper()
	l := newMemLog(t)
	if _, err := l.Append(t.Context(), agentRec()); err != nil {
		t.Fatal(err)
	}
	before, _ := l.Head(t.Context())
	_, err := l.Append(t.Context(), r)
	if !errors.Is(err, ErrInvalidRecord) {
		t.Fatalf("Append err = %v, want ErrInvalidRecord", err)
	}
	var re *RecordError
	if !errors.As(err, &re) || re.Field != field {
		t.Errorf("Append err = %v, want RecordError on %q", err, field)
	}
	after, _ := l.Head(t.Context())
	if before != after {
		t.Error("rejected record changed the log")
	}
}

func TestAppend_AgentActionsNeedChange(t *testing.T) { // AGT-6
	t.Parallel()
	l := newMemLog(t)
	for _, action := range []Action{ActionToolCall, ActionModelCall, ActionRepoWrite} {
		t.Run(string(action), func(t *testing.T) {
			t.Parallel()
			r := agentRec()
			r.Action = action
			if _, err := l.Append(t.Context(), r); err != nil {
				t.Fatalf("valid change-scoped %s rejected: %v", action, err)
			}
			r.Subject = Subject{Kind: SubjectIssue, Repo: "github:99", ID: "7"}
			if _, err := l.Append(t.Context(), r); err != nil {
				t.Errorf("issue-scoped %s rejected: %v", action, err)
			}

			r = agentRec()
			r.Action = action
			r.Subject = Subject{Kind: SubjectInstall, ID: "inst-1"}
			assertInvalid(t, r, "subject.kind")

			r = agentRec()
			r.Action = action
			r.Subject.ID = ""
			assertInvalid(t, r, "subject.id")

			r = agentRec()
			r.Action = action
			r.Subject.Repo = ""
			assertInvalid(t, r, "subject.repo")

			r = agentRec()
			r.Action = action
			r.Actor.Kind = ActorHuman
			assertInvalid(t, r, "actor.kind")

			r = agentRec()
			r.Action = action
			r.Actor.Kind = ActorFactory
			if action == ActionRepoWrite {
				// The control plane merges and reverts, so the factory may write to repos.
				if _, err := l.Append(t.Context(), r); err != nil {
					t.Errorf("factory repo-write rejected: %v", err)
				}
				return
			}
			assertInvalid(t, r, "actor.kind")
		})
	}
	t.Run("install subject shape", func(t *testing.T) {
		t.Parallel()
		r := Record{
			Actor:   Actor{Kind: ActorHuman, ID: "github:1"},
			Subject: Subject{Kind: SubjectInstall, ID: "inst-1"},
			Action:  ActionAdmin, Target: "halt", Outcome: "ok",
		}
		if _, err := l.Append(t.Context(), r); err != nil {
			t.Fatalf("install admin rejected: %v", err)
		}
		r.Subject.Repo = "github:99"
		assertInvalid(t, r, "subject.repo")
		r.Subject = Subject{Kind: "galaxy", ID: "1"}
		assertInvalid(t, r, "subject.kind")
	})
	t.Run("unknown action", func(t *testing.T) {
		t.Parallel()
		r := agentRec()
		r.Action = "rm-rf"
		assertInvalid(t, r, "action")
	})
}

func TestAppend_DecisionEvidence(t *testing.T) { // SEC-10 data
	t.Parallel()
	l := newMemLog(t)
	for _, v := range []Verdict{VerdictGranted, VerdictDenied} {
		t.Run("roundtrip "+string(v), func(t *testing.T) {
			t.Parallel()
			e, err := l.Append(t.Context(), decisionRec(v))
			if err != nil {
				t.Fatal(err)
			}
			got, err := l.Read(t.Context(), e.Seq, 1)
			if err != nil {
				t.Fatal(err)
			}
			if got[0].Decision == nil || *got[0].Decision != *decisionRec(v).Decision {
				t.Errorf("decision = %+v", got[0].Decision)
			}
		})
	}
	tests := map[string]struct {
		mutate func(*Record)
		field  string
	}{
		"no decision":             {func(r *Record) { r.Decision = nil }, "decision"},
		"no operation":            {func(r *Record) { r.Decision.Operation = "" }, "decision.operation"},
		"granted no role":         {func(r *Record) { r.Decision.Verdict = VerdictGranted; r.Outcome = ""; r.Decision.Role = "" }, "decision.role"},
		"granted no rev":          {func(r *Record) { r.Decision.Verdict = VerdictGranted; r.Outcome = ""; r.Decision.Revision = "" }, "decision.revision"},
		"granted rev is a branch": {func(r *Record) { r.Decision.Verdict = VerdictGranted; r.Outcome = ""; r.Decision.Revision = "main" }, "decision.revision"},
		"no verdict":              {func(r *Record) { r.Decision.Verdict = "" }, "decision.verdict"},
		"unknown verdict":         {func(r *Record) { r.Decision.Verdict = "maybe" }, "decision.verdict"},
		"decision on other":       {func(r *Record) { r.Action = ActionAdmin }, "decision"},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			r := decisionRec(VerdictDenied)
			tc.mutate(&r)
			assertInvalid(t, r, tc.field)
		})
	}
}

func TestLog_DeniedDecisionMayLackRoleAndRevision(t *testing.T) { // SEC-10
	t.Parallel()
	l := newMemLog(t)
	r := decisionRec(VerdictDenied)
	r.Decision.Role, r.Decision.Revision = "", ""
	if _, err := l.Append(t.Context(), r); err != nil {
		t.Fatalf("denied without role and revision: %v", err)
	}
	g := decisionRec(VerdictGranted)
	g.Decision.Role, g.Decision.Revision = "", ""
	assertInvalid(t, g, "decision.role")
}

func TestLog_GrantedDecisionRequiresHuman(t *testing.T) { // SEC-10
	t.Parallel()
	r := decisionRec(VerdictGranted)
	r.Actor = Actor{Kind: ActorExternal, ID: "github:1"}
	assertInvalid(t, r, "actor.kind")
	r.Decision.Verdict, r.Outcome = VerdictDenied, "denied"
	if _, err := newMemLog(t).Append(t.Context(), r); err != nil {
		t.Fatalf("external denial: %v", err)
	}
}

func TestLog_NoMutationThroughAPI(t *testing.T) { // NFR-4
	t.Parallel()
	run := func(t *testing.T, l *Log) {
		t.Helper()
		r := decisionRec(VerdictGranted)
		r.Attrs = map[string]string{"k": "v"}
		e, err := l.Append(t.Context(), r)
		if err != nil {
			t.Fatal(err)
		}
		want := cloneEntry(e)

		// Mutate the caller's input.
		r.Attrs["k"] = "changed"
		r.Attrs["new"] = "x"
		r.Decision.Verdict = VerdictDenied
		// Mutate the returned entry.
		e.Attrs["k"] = "changed"
		e.Decision.Role = "root"
		e.Target = "evil"

		got, err := l.Read(t.Context(), 1, 10)
		if err != nil {
			t.Fatal(err)
		}
		if diff := cmp.Diff([]Entry{want}, got); diff != "" {
			t.Fatalf("log changed through caller mutation:\n%s", diff)
		}
		// Mutate Read results.
		got[0].Attrs["k"] = "again"
		got[0].Decision.Reason = "again"
		got[0].Outcome = "again"
		got2, err := l.Read(t.Context(), 1, 10)
		if err != nil {
			t.Fatal(err)
		}
		if diff := cmp.Diff([]Entry{want}, got2); diff != "" {
			t.Fatalf("log changed through Read result mutation:\n%s", diff)
		}
		if _, err := l.Verify(t.Context()); err != nil {
			t.Errorf("Verify after mutation attempts: %v", err)
		}
	}
	t.Run("memory", func(t *testing.T) { run(t, newMemLog(t)) })
	t.Run("file", func(t *testing.T) {
		t.Parallel()
		l, _ := newFileLog(t, filepath.Join(secureDir(t), "audit.jsonl"))
		run(t, l)
	})

	// Allowlist of exported methods. Adding one must be a conscious change here (NFR-4).
	methods := func(rt reflect.Type) []string {
		var names []string
		for m := range rt.Methods() {
			names = append(names, m.Name)
		}
		slices.Sort(names)
		return names
	}
	wants := map[string]struct {
		got  []string
		want []string
	}{
		"*Log":    {methods(reflect.TypeFor[*Log]()), []string{"Append", "Head", "Read", "Verify", "VerifyAgainst"}},
		"*Memory": {methods(reflect.TypeFor[*Memory]()), []string{"AppendNext", "Head", "Read"}},
		"*File":   {methods(reflect.TypeFor[*File]()), []string{"AppendNext", "Close", "Head", "Read"}},
		"Backend": {methods(reflect.TypeFor[Backend]()), []string{"AppendNext", "Head", "Read"}},
	}
	for name, w := range wants {
		if diff := cmp.Diff(w.want, w.got); diff != "" {
			t.Errorf("%s method set changed (-want +got):\n%s", name, diff)
		}
	}
}

// buildFile writes n agent entries to a new audit file and returns its path and final head.
func buildFile(t *testing.T, n int) (string, Head) {
	t.Helper()
	path := filepath.Join(secureDir(t), "audit.jsonl")
	l, f := newFileLog(t, path)
	for i := range n {
		r := agentRec()
		r.Target = fmt.Sprintf("tool-%d", i)
		if _, err := l.Append(t.Context(), r); err != nil {
			t.Fatal(err)
		}
	}
	h, err := l.Head(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	return path, h
}

// readLines returns the file's lines, each with its trailing newline.
func readLines(t *testing.T, path string) []string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return strings.SplitAfter(strings.TrimSuffix(string(b), "\n"), "\n")
}

func writeLines(t *testing.T, path string, lines []string) {
	t.Helper()
	for i, l := range lines {
		if !strings.HasSuffix(l, "\n") {
			lines[i] = l + "\n"
		}
	}
	if err := os.WriteFile(path, []byte(strings.Join(lines, "")), 0o600); err != nil {
		t.Fatal(err)
	}
}

func assertBrokenAt(t *testing.T, path string, seq uint64) {
	t.Helper()
	_, err := OpenFile(t.Context(), path)
	var ce *ChainError
	if !errors.Is(err, ErrBrokenChain) || !errors.As(err, &ce) || ce.Seq != seq {
		t.Fatalf("OpenFile err = %v, want ChainError at seq %d", err, seq)
	}
}

func TestVerify_DetectsTampering(t *testing.T) { // NFR-4
	t.Parallel()
	mutateEntry := func(t *testing.T, lines []string, i int, mut func(*Entry)) {
		t.Helper()
		e, err := decodeLine([]byte(strings.TrimSpace(lines[i])))
		if err != nil {
			t.Fatal(err)
		}
		mut(&e)
		lines[i], _ = marshalLine(e)
	}
	tests := map[string]struct {
		n      int
		edit   func(t *testing.T, lines []string) []string
		wantAt uint64
	}{
		"edit middle entry": {5, func(_ *testing.T, l []string) []string {
			l[2] = strings.Replace(l[2], `"tool-2"`, `"tool-X"`, 1)
			return l
		}, 3},
		"edit with recomputed hash breaks next link": {5, func(t *testing.T, l []string) []string {
			t.Helper()
			mutateEntry(t, l, 2, func(e *Entry) { e.Target = "rewritten"; e.Hash = computeHash(*e) })
			return l
		}, 4},
		"reorder": {5, func(_ *testing.T, l []string) []string {
			l[1], l[2] = l[2], l[1]
			return l
		}, 2},
		"delete middle line": {5, func(_ *testing.T, l []string) []string { return slices.Delete(l, 2, 3) }, 3},
		"forged line with valid hash and wrong prev": {3, func(t *testing.T, l []string) []string {
			t.Helper()
			last, err := decodeLine([]byte(strings.TrimSpace(l[2])))
			if err != nil {
				t.Fatal(err)
			}
			forged := Entry{Format: FormatVersion, Seq: 4, Time: last.Time, Record: agentRec(), PrevHash: Hash{1}}
			forged.Hash = computeHash(forged)
			line, _ := marshalLine(forged)
			return append(l, line)
		}, 4},
		"garbage line":  {3, func(_ *testing.T, l []string) []string { return append(l, "not json") }, 4},
		"blank line":    {3, func(_ *testing.T, l []string) []string { return append(l, "") }, 4},
		"oversize line": {2, func(_ *testing.T, l []string) []string { return append(l, strings.Repeat("a", MaxLineBytes+10)) }, 3},
		"unknown field": {2, func(_ *testing.T, l []string) []string {
			l[1] = strings.Replace(l[1], `{"format"`, `{"extra":1,"format"`, 1)
			return l
		}, 2},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			path, _ := buildFile(t, tc.n)
			writeLines(t, path, tc.edit(t, readLines(t, path)))
			assertBrokenAt(t, path, tc.wantAt)
		})
	}

	t.Run("memory backend detects a corrupt entry", func(t *testing.T) {
		t.Parallel()
		m := NewMemory()
		l, _ := New(m, stepClock())
		for range 3 {
			if _, err := l.Append(t.Context(), agentRec()); err != nil {
				t.Fatal(err)
			}
		}
		m.entries[1].Target = "edited" // in-package corruption
		_, err := l.Verify(t.Context())
		var ce *ChainError
		if !errors.As(err, &ce) || ce.Seq != 2 {
			t.Errorf("Verify err = %v, want ChainError at 2", err)
		}
	})
}

func TestVerify_Checkpoint(t *testing.T) { // NFR-4
	t.Parallel()
	t.Run("removed tail passes Verify but fails VerifyAgainst", func(t *testing.T) {
		t.Parallel()
		path, saved := buildFile(t, 5)
		writeLines(t, path, readLines(t, path)[:4])
		l, _ := reopenFileLog(t, path)
		if _, err := l.Verify(t.Context()); err != nil {
			t.Fatalf("Verify on truncated chain: %v", err)
		}
		err := l.VerifyAgainst(t.Context(), saved)
		var ce *ChainError
		if !errors.Is(err, ErrBrokenChain) || !errors.As(err, &ce) || ce.Seq != 5 {
			t.Errorf("VerifyAgainst err = %v, want ChainError at 5", err)
		}
	})
	t.Run("rewritten history fails VerifyAgainst", func(t *testing.T) {
		t.Parallel()
		build := func(target string) *Log {
			l := newMemLog(t)
			r := agentRec()
			r.Target = target
			for range 3 {
				if _, err := l.Append(t.Context(), r); err != nil {
					t.Fatal(err)
				}
			}
			return l
		}
		cp, _ := build("original").Head(t.Context())
		if err := build("different").VerifyAgainst(t.Context(), cp); !errors.Is(err, ErrBrokenChain) {
			t.Errorf("VerifyAgainst err = %v, want ErrBrokenChain", err)
		}
	})
	t.Run("intact chain verifies", func(t *testing.T) {
		t.Parallel()
		path, saved := buildFile(t, 5)
		l, _ := reopenFileLog(t, path)
		h, err := l.Verify(t.Context())
		if err != nil || h.Seq != 5 || h.Hash != saved.Hash {
			t.Fatalf("Verify = %+v, %v", h, err)
		}
		if err := l.VerifyAgainst(t.Context(), saved); err != nil {
			t.Error(err)
		}
		if err := l.VerifyAgainst(t.Context(), Head{}); err != nil {
			t.Errorf("empty checkpoint: %v", err)
		}
		if err := l.VerifyAgainst(t.Context(), Head{Hash: Hash{1}}); !errors.Is(err, ErrBrokenChain) {
			t.Errorf("bogus checkpoint err = %v", err)
		}
	})
}

func jsonLine(e Entry) ([]byte, error) { return json.Marshal(toFileEntry(e)) }

func marshalLine(e Entry) (string, error) {
	var buf bytes.Buffer
	b, err := json.Marshal(toFileEntry(e))
	if err != nil {
		return "", err
	}
	buf.Write(b)
	buf.WriteByte('\n')
	return buf.String(), nil
}

func TestFile_PartialLastLineFailsClosed(t *testing.T) { // NFR-4
	t.Parallel()
	path := filepath.Join(secureDir(t), "audit.jsonl")
	l, f := newFileLog(t, path)
	for range 3 {
		if _, err := l.Append(t.Context(), agentRec()); err != nil {
			t.Fatal(err)
		}
	}
	_ = f.Close()
	b, _ := os.ReadFile(path)
	// Simulate a crash mid-write of the 3rd line.
	if err := os.WriteFile(path, b[:len(b)-20], 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := OpenFile(t.Context(), path)
	var ce *ChainError
	if !errors.Is(err, ErrBrokenChain) || !errors.As(err, &ce) || ce.Seq != 3 {
		t.Fatalf("OpenFile err = %v, want ChainError at 3", err)
	}
	// A complete line missing only its newline is also not trusted.
	if err := os.WriteFile(path, b[:len(b)-1], 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenFile(t.Context(), path); !errors.Is(err, ErrBrokenChain) {
		t.Errorf("missing final newline err = %v", err)
	}
}

func TestFile_ReopenContinuesChain(t *testing.T) { // NFR-4
	t.Parallel()
	path := filepath.Join(secureDir(t), "audit.jsonl")
	l, f := newFileLog(t, path)
	for range 3 {
		if _, err := l.Append(t.Context(), agentRec()); err != nil {
			t.Fatal(err)
		}
	}
	first, _ := l.Read(t.Context(), 1, 10)
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := l.Append(t.Context(), agentRec()); !errors.Is(err, ErrClosed) {
		t.Errorf("append after close err = %v, want ErrClosed", err)
	}

	l2, _ := reopenFileLog(t, path)
	e, err := l2.Append(t.Context(), decisionRec(VerdictDenied))
	if err != nil {
		t.Fatal(err)
	}
	if e.Seq != 4 || e.PrevHash != first[2].Hash {
		t.Errorf("continued entry = seq %d prev %s", e.Seq, e.PrevHash)
	}
	all, err := l2.Read(t.Context(), 1, 10)
	if err != nil || len(all) != 4 {
		t.Fatalf("Read = %d entries, %v", len(all), err)
	}
	if diff := cmp.Diff(first, all[:3]); diff != "" {
		t.Errorf("entries changed across reopen:\n%s", diff)
	}
	if _, err := l2.Verify(t.Context()); err != nil {
		t.Error(err)
	}
}

func TestFile_Permissions(t *testing.T) { // NFR-4
	t.Parallel()
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permissions")
	}
	path := filepath.Join(secureDir(t), "audit.jsonl")
	_, _ = newFileLog(t, path)
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := fi.Mode().Perm(); got != 0o600 {
		t.Errorf("mode = %o, want 600", got)
	}
}

func TestFile_StickyErrorAfterFailedWrite(t *testing.T) { // NFR-4
	t.Parallel()
	path := filepath.Join(secureDir(t), "audit.jsonl")
	l, f := newFileLog(t, path)
	if _, err := l.Append(t.Context(), agentRec()); err != nil {
		t.Fatal(err)
	}
	headBefore, _ := l.Head(t.Context())
	bytesBefore, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// Close the underlying handle so the next write fails.
	_ = f.f.Close()
	if _, err := l.Append(t.Context(), agentRec()); !errors.Is(err, ErrStoreFailed) {
		t.Fatalf("append err = %v, want ErrStoreFailed", err)
	}
	if _, err := l.Append(t.Context(), agentRec()); !errors.Is(err, ErrStoreFailed) {
		t.Errorf("second append err = %v, want sticky ErrStoreFailed", err)
	}
	if h, _ := l.Head(t.Context()); h != headBefore {
		t.Errorf("head changed after failed write: %+v -> %+v", headBefore, h)
	}
	if got, _ := os.ReadFile(path); !bytes.Equal(got, bytesBefore) {
		t.Error("file bytes changed after failed write")
	}
}

func TestHash_Golden(t *testing.T) { // NFR-4, SEC-10 (decision evidence is hashed)
	t.Parallel()
	base := Entry{
		Format: FormatVersion,
		Seq:    7,
		Time:   time.UnixMicro(1772600767123456).UTC(),
		Record: Record{
			Actor:           Actor{Kind: ActorAgent, ID: "wl-1", Display: "disp"},
			TemplateVersion: "tpl@1",
			Subject:         Subject{Kind: SubjectChange, Repo: "r1", ID: "c1"},
			Action:          ActionToolCall,
			Target:          "bash",
			Outcome:         "ok",
			Attrs:           map[string]string{"b": "2", "a": "1"},
		},
		PrevHash: Hash{0xaa, 0xbb},
	}
	const want = "1af6bb76a778159120d4abfc78c587d92df3c9fa4baf19fc735cd2193e93ba84"
	if got := computeHash(base).String(); got != want {
		t.Errorf("golden hash = %s, want %s (format drift?)", got, want)
	}
	withDecision := base
	withDecision.Action = ActionDecision
	withDecision.Decision = &Decision{Operation: "op", Role: "r", Revision: "rev", Verdict: VerdictGranted, Reason: "why"}
	const wantDecision = "f4239c7ecf587dcb1cff513fc733e3f0489c4c63c96be2a5939b8684c2bc0fb1"
	if got := computeHash(withDecision).String(); got != wantDecision {
		t.Errorf("golden decision hash = %s, want %s", got, wantDecision)
	}

	withLink := base
	withLink.Action = ActionLink
	withLink.Subject = Subject{Kind: SubjectChange, Repo: "r1", ID: "c1"}
	withLink.Link = &Subject{Kind: SubjectIssue, Repo: "r1", ID: "i9"}
	const wantLink = "b7a28042a95a417d469530b60bc3b9cfc469bfc05655a419179cc8ddbcacbef5"
	if got := computeHash(withLink).String(); got != wantLink {
		t.Errorf("golden link hash = %s, want %s", got, wantLink)
	}
	for _, mut := range map[string]func(*Subject){
		"kind": func(l *Subject) { l.Kind = SubjectChange },
		"repo": func(l *Subject) { l.Repo += "x" },
		"id":   func(l *Subject) { l.ID += "x" },
	} {
		e := cloneEntry(withLink)
		mut(e.Link)
		if computeHash(e) == computeHash(withLink) {
			t.Error("changing a link field did not change the hash")
		}
	}

	baseHash := computeHash(base)
	dec := func(e *Entry) {
		e.Decision = &Decision{Operation: "op", Role: "r", Revision: "rev", Verdict: VerdictGranted}
	}
	mutations := map[string]func(*Entry){
		"format":           func(e *Entry) { e.Format++ },
		"seq":              func(e *Entry) { e.Seq++ },
		"time":             func(e *Entry) { e.Time = e.Time.Add(time.Microsecond) },
		"actor kind":       func(e *Entry) { e.Actor.Kind = ActorHuman },
		"actor id":         func(e *Entry) { e.Actor.ID += "x" },
		"actor display":    func(e *Entry) { e.Actor.Display += "x" },
		"template":         func(e *Entry) { e.TemplateVersion += "x" },
		"subject kind":     func(e *Entry) { e.Subject.Kind = SubjectIssue },
		"subject repo":     func(e *Entry) { e.Subject.Repo += "x" },
		"subject id":       func(e *Entry) { e.Subject.ID += "x" },
		"action":           func(e *Entry) { e.Action = ActionModelCall },
		"target":           func(e *Entry) { e.Target += "x" },
		"outcome":          func(e *Entry) { e.Outcome += "x" },
		"decision present": dec,
		"link present":     func(e *Entry) { e.Link = &Subject{Kind: SubjectIssue, Repo: "r", ID: "1"} },
		"attr value":       func(e *Entry) { e.Attrs = map[string]string{"b": "2", "a": "9"} },
		"attr key":         func(e *Entry) { e.Attrs = map[string]string{"b": "2", "c": "1"} },
		"attr added":       func(e *Entry) { e.Attrs = map[string]string{"b": "2", "a": "1", "c": "3"} },
		"attrs removed":    func(e *Entry) { e.Attrs = nil },
		"prev hash":        func(e *Entry) { e.PrevHash[31] ^= 1 },
	}
	seen := map[Hash]string{}
	for name, mut := range mutations {
		e := cloneEntry(base)
		mut(&e)
		h := computeHash(e)
		if h == baseHash {
			t.Errorf("changing %s did not change the hash", name)
		}
		if other, dup := seen[h]; dup {
			t.Errorf("%s and %s collide", name, other)
		}
		seen[h] = name
	}
	for _, f := range []string{"verdict", "operation", "role", "revision", "reason"} {
		e := cloneEntry(withDecision)
		switch f {
		case "verdict":
			e.Decision.Verdict = VerdictDenied
		case "operation":
			e.Decision.Operation += "x"
		case "role":
			e.Decision.Role += "x"
		case "revision":
			e.Decision.Revision += "x"
		case "reason":
			e.Decision.Reason += "x"
		}
		if computeHash(e) == computeHash(withDecision) {
			t.Errorf("changing decision %s did not change the hash", f)
		}
	}

	t.Run("string boundaries", func(t *testing.T) {
		t.Parallel()
		a, b := cloneEntry(base), cloneEntry(base)
		a.Target, a.Outcome = "ab", "c"
		b.Target, b.Outcome = "a", "bc"
		if computeHash(a) == computeHash(b) {
			t.Error("Target/Outcome boundary shift collides")
		}
		a.Attrs = map[string]string{"k": "vk2"}
		b.Attrs = map[string]string{"kv": "k2"}
		a.Target, b.Target = "x", "x"
		a.Outcome, b.Outcome = "y", "y"
		if computeHash(a) == computeHash(b) {
			t.Error("attr key/value boundary shift collides")
		}
	})
	t.Run("attr order is irrelevant", func(t *testing.T) {
		t.Parallel()
		a, b := cloneEntry(base), cloneEntry(base)
		a.Attrs = map[string]string{"a": "1", "b": "2", "c": "3"}
		b.Attrs = map[string]string{"c": "3", "b": "2", "a": "1"}
		if computeHash(a) != computeHash(b) {
			t.Error("map order changed the hash")
		}
	})
}

func TestAppend_Bounds(t *testing.T) { // NFR-4
	t.Parallel()
	l := newMemLog(t)
	long := strings.Repeat("a", MaxStringBytes+1)
	ok := strings.Repeat("a", MaxStringBytes)
	tests := map[string]func(*Record){
		"long target":        func(r *Record) { r.Target = long },
		"long actor id":      func(r *Record) { r.Actor.ID = long },
		"long attr value":    func(r *Record) { r.Attrs = map[string]string{"k": long} },
		"invalid utf8":       func(r *Record) { r.Target = "a\xffb" },
		"invalid utf8 attr":  func(r *Record) { r.Attrs = map[string]string{"k": "\xc3\x28"} },
		"empty attr key":     func(r *Record) { r.Attrs = map[string]string{"": "v"} },
		"uppercase attr key": func(r *Record) { r.Attrs = map[string]string{"Key": "v"} },
		"space attr key":     func(r *Record) { r.Attrs = map[string]string{"a b": "v"} },
		"long attr key":      func(r *Record) { r.Attrs = map[string]string{strings.Repeat("k", MaxAttrKeyBytes+1): "v"} },
		"too many attrs": func(r *Record) {
			r.Attrs = map[string]string{}
			for i := range MaxAttrs + 1 {
				r.Attrs[fmt.Sprintf("k%d", i)] = "v"
			}
		},
		"record too large": func(r *Record) {
			r.Attrs = map[string]string{}
			for i := range 17 {
				r.Attrs[fmt.Sprintf("k%d", i)] = ok
			}
		},
	}
	for name, mut := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			r := agentRec()
			mut(&r)
			if _, err := l.Append(t.Context(), r); !errors.Is(err, ErrInvalidRecord) {
				t.Errorf("err = %v, want ErrInvalidRecord", err)
			}
		})
	}
	t.Run("limits themselves are accepted", func(t *testing.T) {
		t.Parallel()
		r := agentRec()
		r.Target = ok
		r.Attrs = map[string]string{strings.Repeat("k", MaxAttrKeyBytes): ok}
		if _, err := l.Append(t.Context(), r); err != nil {
			t.Errorf("at-limit record rejected: %v", err)
		}
		r.Attrs = map[string]string{}
		for i := range MaxAttrs {
			r.Attrs[fmt.Sprintf("k%d", i)] = "v"
		}
		if _, err := l.Append(t.Context(), r); err != nil {
			t.Errorf("max attrs rejected: %v", err)
		}
	})
	t.Run("control characters are data and escaped for display", func(t *testing.T) {
		t.Parallel()
		r := agentRec()
		r.Target = "a\nb\x1b[31m\x00"
		e, err := l.Append(t.Context(), r)
		if err != nil {
			t.Fatal(err)
		}
		if e.Target != r.Target {
			t.Error("control characters were altered")
		}
		s := e.String()
		if strings.ContainsAny(s, "\n\x1b\x00") {
			t.Errorf("String() leaks control characters: %q", s)
		}
	})
	t.Run("read limit bounds", func(t *testing.T) {
		t.Parallel()
		for _, n := range []int{0, -1, MaxReadLimit + 1} {
			if _, err := l.Read(t.Context(), 1, n); err == nil {
				t.Errorf("limit %d accepted", n)
			}
		}
	})
}

func TestLog_ConcurrentAppend(t *testing.T) { // NFR-4
	t.Parallel()
	run := func(t *testing.T, l *Log) {
		t.Helper()
		const n = 50
		var wg sync.WaitGroup
		errs := make(chan error, n)
		for i := range n {
			wg.Go(func() {
				r := agentRec()
				r.Target = fmt.Sprintf("t%d", i)
				_, err := l.Append(t.Context(), r)
				errs <- err
			})
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			if err != nil {
				t.Fatal(err)
			}
		}
		all, err := l.Read(t.Context(), 1, MaxReadLimit)
		if err != nil || len(all) != n {
			t.Fatalf("Read = %d entries, %v", len(all), err)
		}
		for i, e := range all {
			if e.Seq != uint64(i+1) {
				t.Fatalf("entry %d has seq %d", i, e.Seq)
			}
		}
		h, err := l.Verify(t.Context())
		if err != nil || h.Seq != n {
			t.Fatalf("Verify = %+v, %v", h, err)
		}
	}
	t.Run("memory", func(t *testing.T) { run(t, newMemLog(t)) })
	t.Run("file", func(t *testing.T) {
		t.Parallel()
		l, _ := newFileLog(t, filepath.Join(secureDir(t), "audit.jsonl"))
		run(t, l)
	})
}

func TestLog_ClockNotMonotonic(t *testing.T) { // NFR-4: the log records the clock truthfully and orders by Seq
	t.Parallel()
	mk := map[string]func(t *testing.T) Backend{
		"memory": func(*testing.T) Backend { return NewMemory() },
		"file": func(t *testing.T) Backend {
			t.Helper()
			_, f := newFileLog(t, filepath.Join(secureDir(t), "audit.jsonl"))
			return f
		},
	}
	for name, newBackend := range mk {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			times := []time.Time{
				t0.Add(10 * time.Second), t0.Add(5 * time.Second), t0.Add(5 * time.Second), t0.Add(20 * time.Second), t0,
			}
			i := 0
			l, err := New(newBackend(t), func() time.Time { i++; return times[i-1] })
			if err != nil {
				t.Fatal(err)
			}
			for range times {
				if _, err := l.Append(t.Context(), agentRec()); err != nil {
					t.Fatal(err)
				}
			}
			all, _ := l.Read(t.Context(), 1, 10)
			for i, e := range all {
				want := times[i].UTC().Truncate(time.Microsecond)
				if !e.Time.Equal(want) || e.Time.Location() != time.UTC {
					t.Errorf("entry %d time = %v, want the clock's %v", e.Seq, e.Time, want)
				}
			}
			if _, err := l.Verify(t.Context()); err != nil {
				t.Errorf("Verify with backwards clock: %v", err)
			}
		})
	}
}

func TestLog_RejectsTimesOutOfRange(t *testing.T) { // NFR-4: Memory and File agree
	t.Parallel()
	bad := map[string]time.Time{
		"year 10000": time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC),
		"year 1969":  time.Date(1969, 12, 31, 23, 59, 59, 0, time.UTC),
		"zero time":  {},
	}
	for bname, bt := range bad {
		for _, name := range []string{"memory", "file"} {
			t.Run(bname+" "+name, func(t *testing.T) {
				t.Parallel()
				var b Backend = NewMemory()
				if name == "file" {
					_, f := newFileLog(t, filepath.Join(secureDir(t), "audit.jsonl"))
					b = f
				}
				l, _ := New(b, func() time.Time { return bt })
				if _, err := l.Append(t.Context(), agentRec()); !errors.Is(err, ErrInvalidRecord) {
					t.Errorf("err = %v, want ErrInvalidRecord", err)
				}
				if h, _ := l.Head(t.Context()); h != (Head{}) {
					t.Errorf("rejected time changed the log: %+v", h)
				}
			})
		}
	}
	t.Run("boundaries are accepted", func(t *testing.T) {
		t.Parallel()
		for _, ok := range []time.Time{time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(9999, 12, 31, 23, 59, 59, 999999000, time.UTC)} {
			l, _ := New(NewMemory(), func() time.Time { return ok })
			if _, err := l.Append(t.Context(), agentRec()); err != nil {
				t.Errorf("%v rejected: %v", ok, err)
			}
		}
	})
}

// backendContract runs the shared behavior every Backend must have.
func backendContract(t *testing.T, mk func(t *testing.T) Backend) {
	t.Helper()
	t.Run("empty", func(t *testing.T) { contract0(t, mk) })
	t.Run("append and page", func(t *testing.T) { contract1(t, mk) })
	t.Run("seal called once with current head", func(t *testing.T) { contract2(t, mk) })
	t.Run("rejects entries that do not extend the head", func(t *testing.T) { contract3(t, mk) })
	t.Run("cancelled context", func(t *testing.T) { contract4(t, mk) })
}

func contract0(t *testing.T, mk func(t *testing.T) Backend) {
	t.Helper()
	b := mk(t)
	h, err := b.Head(t.Context())
	if err != nil || h != (Head{}) {
		t.Errorf("Head = %+v, %v", h, err)
	}
	es, err := b.Read(t.Context(), 1, 10)
	if err != nil || len(es) != 0 {
		t.Errorf("Read = %v, %v", es, err)
	}
}

func contract1(t *testing.T, mk func(t *testing.T) Backend) {
	t.Helper()
	b := mk(t)
	l, _ := New(b, stepClock())
	var want []Entry
	for range 7 {
		e, err := l.Append(t.Context(), agentRec())
		if err != nil {
			t.Fatal(err)
		}
		want = append(want, e)
	}
	var got []Entry
	for from := uint64(1); ; from += 3 {
		page, err := b.Read(t.Context(), from, 3)
		if err != nil {
			t.Fatal(err)
		}
		if len(page) == 0 {
			break
		}
		if len(page) > 3 {
			t.Fatalf("page of %d exceeds limit", len(page))
		}
		got = append(got, page...)
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("paged read differs (-want +got):\n%s", diff)
	}
	h, _ := b.Head(t.Context())
	if h != headOf(want[6]) {
		t.Errorf("Head = %+v, want %+v", h, headOf(want[6]))
	}
	if es, _ := b.Read(t.Context(), 8, 3); len(es) != 0 {
		t.Errorf("Read past end = %v", es)
	}
}

func contract2(t *testing.T, mk func(t *testing.T) Backend) {
	t.Helper()
	b := mk(t)
	l, _ := New(b, stepClock())
	e1, _ := l.Append(t.Context(), agentRec())
	calls := 0
	var seen Head
	_, err := b.AppendNext(t.Context(), func(prev Head) (Entry, error) {
		calls++
		seen = prev
		return Entry{}, errors.New("boom")
	})
	if err == nil || calls != 1 || seen != headOf(e1) {
		t.Errorf("err=%v calls=%d prev=%+v", err, calls, seen)
	}
	if h, _ := b.Head(t.Context()); h != headOf(e1) {
		t.Error("failed seal changed the head")
	}
}

func contract3(t *testing.T, mk func(t *testing.T) Backend) {
	t.Helper()
	b := mk(t)
	l, _ := New(b, stepClock())
	e1, _ := l.Append(t.Context(), agentRec())
	forge := func(mut func(*Entry)) SealFunc {
		return func(prev Head) (Entry, error) {
			e := Entry{Format: FormatVersion, Seq: prev.Seq + 1, Time: t0.Truncate(time.Microsecond), Record: agentRec(), PrevHash: prev.Hash}
			mut(&e)
			e.Hash = computeHash(e)
			return e, nil
		}
	}
	muts := map[string]func(*Entry){
		"wrong seq":  func(e *Entry) { e.Seq = 5 },
		"wrong prev": func(e *Entry) { e.PrevHash = Hash{9} },
		"bad record": func(e *Entry) { e.Actor.ID = "" },
	}
	for name, mut := range muts {
		if _, err := b.AppendNext(t.Context(), forge(mut)); !errors.Is(err, ErrBrokenChain) {
			t.Errorf("%s: err = %v, want ErrBrokenChain", name, err)
		}
	}
	bad := func(prev Head) (Entry, error) {
		e, _ := forge(func(*Entry) {})(prev)
		e.Hash = Hash{1}
		return e, nil
	}
	if _, err := b.AppendNext(t.Context(), bad); !errors.Is(err, ErrBrokenChain) {
		t.Errorf("bad hash: err = %v", err)
	}
	if h, _ := b.Head(t.Context()); h != headOf(e1) {
		t.Error("rejected entry changed the head")
	}
}

func contract4(t *testing.T, mk func(t *testing.T) Backend) {
	t.Helper()
	b := mk(t)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := b.AppendNext(ctx, func(Head) (Entry, error) { t.Error("seal called"); return Entry{}, nil }); !errors.Is(err, context.Canceled) {
		t.Errorf("AppendNext err = %v", err)
	}
	if _, err := b.Read(ctx, 1, 1); !errors.Is(err, context.Canceled) {
		t.Errorf("Read err = %v", err)
	}
	if _, err := b.Head(ctx); !errors.Is(err, context.Canceled) {
		t.Errorf("Head err = %v", err)
	}
}

func TestBackendContract(t *testing.T) { // NFR-4
	t.Parallel()
	t.Run("memory", func(t *testing.T) {
		t.Parallel()
		backendContract(t, func(*testing.T) Backend { return NewMemory() })
	})
	t.Run("file", func(t *testing.T) {
		t.Parallel()
		backendContract(t, func(t *testing.T) Backend {
			t.Helper()
			_, f := newFileLog(t, filepath.Join(secureDir(t), "audit.jsonl"))
			return f
		})
	})
}

func TestHash_TextRoundTrip(t *testing.T) { // NFR-4
	t.Parallel()
	h := Hash{0xde, 0xad, 0xbe, 0xef}
	b, err := h.MarshalText()
	if err != nil || len(b) != 64 {
		t.Fatalf("MarshalText = %q, %v", b, err)
	}
	var got Hash
	if err := got.UnmarshalText(b); err != nil || got != h {
		t.Errorf("UnmarshalText = %v, %v", got, err)
	}
	for _, bad := range []string{"", "zz", strings.Repeat("g", 64), strings.Repeat("A", 64), strings.Repeat("a", 63)} {
		if err := got.UnmarshalText([]byte(bad)); err == nil {
			t.Errorf("UnmarshalText(%q) accepted", bad)
		}
	}
}
