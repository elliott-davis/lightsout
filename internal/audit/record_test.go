// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"errors"
	"strings"
	"testing"
)

func linkRec() Record {
	return Record{
		Actor:           Actor{Kind: ActorFactory, ID: "wl-factory"},
		TemplateVersion: "factory@1.2.3",
		Subject:         Subject{Kind: SubjectChange, Repo: "github:99", ID: "42"},
		Action:          ActionLink,
		Outcome:         "ok",
		Link:            &Subject{Kind: SubjectIssue, Repo: "github:99", ID: "7"},
	}
}

func TestAppend_LinkShapes(t *testing.T) { // AGT-6: a change is traceable to its issue
	t.Parallel()
	if _, err := newMemLog(t).Append(t.Context(), linkRec()); err != nil {
		t.Fatalf("valid link rejected: %v", err)
	}
	tests := map[string]struct {
		mutate func(*Record)
		field  string
	}{
		"missing link":        {func(r *Record) { r.Link = nil }, "link"},
		"subject is an issue": {func(r *Record) { r.Subject.Kind = SubjectIssue }, "subject.kind"},
		"subject is install":  {func(r *Record) { r.Subject = Subject{Kind: SubjectInstall, ID: "i"} }, "subject.kind"},
		"link is a change":    {func(r *Record) { r.Link.Kind = SubjectChange }, "link.kind"},
		"link is install":     {func(r *Record) { r.Link.Kind = SubjectInstall }, "link.kind"},
		"repo mismatch":       {func(r *Record) { r.Link.Repo = "github:100" }, "link.repo"},
		"link without id":     {func(r *Record) { r.Link.ID = "" }, "link.id"},
		"link on tool call": {func(r *Record) {
			*r = agentRec()
			r.Link = &Subject{Kind: SubjectIssue, Repo: "github:99", ID: "7"}
		}, "link"},
		"link on decision": {func(r *Record) {
			*r = decisionRec(VerdictGranted)
			r.Link = &Subject{Kind: SubjectIssue, Repo: "github:99", ID: "7"}
		}, "link"},
		"link with oversized id": {func(r *Record) { r.Link.ID = strings.Repeat("x", MaxStringBytes+1) }, "link.id"},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			r := linkRec()
			tc.mutate(&r)
			assertInvalid(t, r, tc.field)
		})
	}
}

func TestAppend_FactoryAndIssueRules(t *testing.T) { // RUN-5, AGT-6
	t.Parallel()
	t.Run("issue subject needs a repo", func(t *testing.T) {
		t.Parallel()
		r := agentRec()
		r.Subject = Subject{Kind: SubjectIssue, ID: "7"}
		assertInvalid(t, r, "subject.repo")
	})
	t.Run("factory repo-write is accepted", func(t *testing.T) {
		t.Parallel()
		r := agentRec()
		r.Actor = Actor{Kind: ActorFactory, ID: "wl-factory"}
		r.TemplateVersion = "factory@1.2.3"
		r.Action = ActionRepoWrite
		if _, err := newMemLog(t).Append(t.Context(), r); err != nil {
			t.Errorf("factory repo-write rejected: %v", err)
		}
	})
	t.Run("human repo-write is rejected", func(t *testing.T) {
		t.Parallel()
		r := agentRec()
		r.Actor = Actor{Kind: ActorHuman, ID: "github:1"}
		r.Action = ActionRepoWrite
		assertInvalid(t, r, "actor.kind")
	})
	t.Run("factory entry needs a build version", func(t *testing.T) {
		t.Parallel()
		r := agentRec()
		r.Actor = Actor{Kind: ActorFactory, ID: "wl-factory"}
		r.TemplateVersion = ""
		r.Action = ActionRepoWrite
		assertInvalid(t, r, "template_version")
	})
	t.Run("factory tool call stays rejected", func(t *testing.T) {
		t.Parallel()
		r := agentRec()
		r.Actor = Actor{Kind: ActorFactory, ID: "wl-factory"}
		assertInvalid(t, r, "actor.kind")
	})
}

func TestAppend_ErrorsAreBounded(t *testing.T) { // NFR-4: untrusted input is never echoed unbounded
	t.Parallel()
	big := strings.Repeat("é", 1000) // 2000 bytes, within the size bound
	mutations := map[string]func(*Record){
		"actor kind":   func(r *Record) { r.Actor.Kind = ActorKind(big) },
		"subject kind": func(r *Record) { r.Subject.Kind = SubjectKind(big) },
		"action":       func(r *Record) { r.Action = Action(big) },
		"verdict": func(r *Record) {
			*r = decisionRec(VerdictGranted)
			r.Decision.Verdict = Verdict(big)
		},
		"attr key": func(r *Record) { r.Attrs = map[string]string{big: "v"} },
	}
	for name, mut := range mutations {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			r := agentRec()
			mut(&r)
			_, err := newMemLog(t).Append(t.Context(), r)
			if !errors.Is(err, ErrInvalidRecord) {
				t.Fatalf("err = %v", err)
			}
			if len(err.Error()) > 300 || !strings.Contains(err.Error(), "…") {
				t.Errorf("error is not bounded (%d bytes): %.120s", len(err.Error()), err.Error())
			}
		})
	}
}

func TestAppend_SizeChecksComeFirst(t *testing.T) { // NFR-4
	t.Parallel()
	r := agentRec()
	r.Action = Action(strings.Repeat("x", MaxStringBytes+1))
	r.Actor.ID = ""
	assertInvalid(t, r, "action") // oversized first, even though actor.id is also bad
}

func TestEntry_StringCannotBeForged(t *testing.T) { // NFR-4: display cannot be spoofed through data
	t.Parallel()
	r := decisionRec(VerdictDenied)
	r.Outcome = "denied"
	r.Attrs = map[string]string{"outcome": "granted", "decision_verdict": "granted"}
	e, err := newMemLog(t).Append(t.Context(), r)
	if err != nil {
		t.Fatal(err)
	}
	s := e.String()
	if strings.Contains(s, " outcome=\"granted\"") || strings.Contains(s, " decision_verdict=\"granted\"") {
		t.Errorf("attribute impersonates a field: %s", s)
	}
	for _, want := range []string{`outcome="denied"`, `decision_verdict="denied"`, `attr.outcome="granted"`, `actor_kind="human"`, `action="authz-decision"`} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %s in %s", want, s)
		}
	}
	forged := e
	forged.Attrs = map[string]string{"x\n y=\"z": "v\nseq=999"}
	if out := forged.String(); strings.Contains(out, "\n") || strings.Count(out, " seq=") != 0 {
		t.Errorf("odd attr key forged output: %q", out)
	}
}

func TestAppend_DecisionOutcomeAndExternalActors(t *testing.T) { // SEC-10 data
	t.Parallel()
	t.Run("outcome must be empty or the verdict", func(t *testing.T) {
		t.Parallel()
		l := newMemLog(t)
		for _, outcome := range []string{"", "denied"} {
			r := decisionRec(VerdictDenied)
			r.Outcome = outcome
			if _, err := l.Append(t.Context(), r); err != nil {
				t.Errorf("outcome %q rejected: %v", outcome, err)
			}
		}
		r := decisionRec(VerdictDenied)
		r.Outcome = "granted"
		assertInvalid(t, r, "outcome")
		r.Outcome = "ok"
		assertInvalid(t, r, "outcome")
	})
	t.Run("external actor may be recorded on a decision", func(t *testing.T) {
		t.Parallel()
		r := decisionRec(VerdictDenied)
		r.Actor = Actor{Kind: ActorExternal, ID: "github:app/12"}
		if _, err := newMemLog(t).Append(t.Context(), r); err != nil {
			t.Errorf("external decision rejected: %v", err)
		}
		r.Actor.ID = ""
		assertInvalid(t, r, "actor.id")
	})
	for _, action := range []Action{ActionToolCall, ActionModelCall, ActionRepoWrite, ActionAdmin, ActionStateTransition, ActionLink} {
		t.Run("external actor rejected on "+string(action), func(t *testing.T) {
			t.Parallel()
			r := agentRec()
			if action == ActionLink {
				r = linkRec()
			}
			r.Action = action
			r.Actor = Actor{Kind: ActorExternal, ID: "github:app/12"}
			assertInvalid(t, r, "actor.kind")
		})
	}
	t.Run("admin is for humans and the factory", func(t *testing.T) {
		t.Parallel()
		l := newMemLog(t)
		for _, a := range []Actor{{Kind: ActorHuman, ID: "github:1"}, {Kind: ActorFactory, ID: "wl-f"}} {
			r := Record{Actor: a, TemplateVersion: "v1", Subject: Subject{Kind: SubjectInstall, ID: "i"}, Action: ActionAdmin, Outcome: "ok"}
			if _, err := l.Append(t.Context(), r); err != nil {
				t.Errorf("%s admin rejected: %v", a.Kind, err)
			}
		}
		r := Record{Actor: Actor{Kind: ActorAgent, ID: "wl-a"}, TemplateVersion: "v1", Subject: Subject{Kind: SubjectInstall, ID: "i"}, Action: ActionAdmin}
		assertInvalid(t, r, "actor.kind")
	})
}
