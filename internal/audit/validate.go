// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"fmt"
	"slices"
	"strconv"
	"unicode/utf8"
)

// validateRecord checks r against the closed sets, the agent rules (RUN-5, AGT-6), the decision evidence rules
// (SEC-10) and the size bounds. It returns a *RecordError.
func validateRecord(r Record) error {
	// Size checks come first so that nothing oversized is echoed back or examined further.
	if err := validateSizes(r); err != nil {
		return err
	}
	if err := validateActor(r); err != nil {
		return err
	}
	if err := validateSubject(r); err != nil {
		return err
	}
	return validateAction(r)
}

// clip quotes s, cutting it to 64 bytes (on a rune boundary) with a marker, so errors stay bounded.
func clip(s string) string {
	const limit = 64
	if len(s) <= limit {
		return strconv.Quote(s)
	}
	cut := limit
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return strconv.Quote(s[:cut]) + "…"
}

func invalid(field, format string, args ...any) error {
	return &RecordError{Field: field, Reason: fmt.Sprintf(format, args...)}
}

func validateActor(r Record) error {
	switch r.Actor.Kind {
	case ActorAgent, ActorHuman, ActorFactory, ActorExternal:
	default:
		return invalid("actor.kind", "unknown kind %s", clip(string(r.Actor.Kind)))
	}
	if r.Actor.ID == "" {
		return invalid("actor.id", "required")
	}
	if (r.Actor.Kind == ActorAgent || r.Actor.Kind == ActorFactory) && r.TemplateVersion == "" {
		return invalid("template_version", "required for agent (template version) and factory (build version) actors")
	}
	return nil
}

func validateSubject(r Record) error {
	switch r.Subject.Kind {
	case SubjectChange, SubjectIssue:
		if r.Subject.Repo == "" {
			return invalid("subject.repo", "required for %s subjects", r.Subject.Kind)
		}
	case SubjectInstall:
		if r.Subject.Repo != "" {
			return invalid("subject.repo", "must be empty for install subjects")
		}
	default:
		return invalid("subject.kind", "unknown kind %s", clip(string(r.Subject.Kind)))
	}
	if r.Subject.ID == "" {
		return invalid("subject.id", "required")
	}
	return nil
}

func validateAction(r Record) error {
	switch r.Action {
	case ActionToolCall, ActionModelCall:
		// AGT-6: only agents call tools and models, always inside a change or issue.
		if err := requireAgentScope(r); err != nil {
			return err
		}
	case ActionRepoWrite:
		// The control plane also writes to repos (merges, reverts), so the factory may too.
		if r.Actor.Kind == ActorHuman {
			return invalid("actor.kind", "%s must be performed by an agent or the factory", r.Action)
		}
		if r.Subject.Kind == SubjectInstall {
			return invalid("subject.kind", "%s must name a change or issue", r.Action)
		}
	case ActionAdmin:
		if r.Actor.Kind != ActorHuman && r.Actor.Kind != ActorFactory {
			return invalid("actor.kind", "%s must be performed by a human or the factory", r.Action)
		}
	case ActionStateTransition, ActionDecision, ActionLink:
	default:
		return invalid("action", "unknown action %s", clip(string(r.Action)))
	}
	if r.Actor.Kind == ActorExternal && r.Action != ActionDecision {
		return invalid("actor.kind", "external actors may only appear on %s entries", ActionDecision)
	}
	if err := validateLink(r); err != nil {
		return err
	}
	return validateDecision(r)
}

func requireAgentScope(r Record) error {
	if r.Actor.Kind != ActorAgent {
		return invalid("actor.kind", "%s must be performed by an agent", r.Action)
	}
	if r.Subject.Kind == SubjectInstall {
		return invalid("subject.kind", "%s must name a change or issue", r.Action)
	}
	return nil
}

func validateLink(r Record) error {
	l := r.Link
	if r.Action != ActionLink {
		if l != nil {
			return invalid("link", "only allowed for %s", ActionLink)
		}
		return nil
	}
	switch {
	case l == nil:
		return invalid("link", "required for %s", ActionLink)
	case r.Subject.Kind != SubjectChange:
		return invalid("subject.kind", "%s must name a change", ActionLink)
	case l.Kind != SubjectIssue:
		return invalid("link.kind", "must be issue")
	case l.Repo != r.Subject.Repo:
		return invalid("link.repo", "must equal the change's repo")
	case l.ID == "":
		return invalid("link.id", "required")
	}
	return nil
}

func validateDecision(r Record) error {
	d := r.Decision
	if r.Action != ActionDecision {
		if d != nil {
			return invalid("decision", "only allowed for %s", ActionDecision)
		}
		return nil
	}
	switch {
	case d == nil:
		return invalid("decision", "required for %s", ActionDecision)
	case d.Operation == "":
		return invalid("decision.operation", "required")
	case d.Role == "":
		return invalid("decision.role", "required")
	case d.Revision == "":
		return invalid("decision.revision", "required")
	case d.Verdict != VerdictGranted && d.Verdict != VerdictDenied:
		return invalid("decision.verdict", "unknown verdict %s", clip(string(d.Verdict)))
	case r.Outcome != "" && r.Outcome != string(d.Verdict):
		return invalid("outcome", "must be empty or equal the verdict for %s", ActionDecision)
	}
	return nil
}

type namedString struct{ name, v string }

func validateSizes(r Record) error {
	fields := []namedString{
		{"actor.kind", string(r.Actor.Kind)},
		{"actor.id", r.Actor.ID},
		{"actor.display", r.Actor.Display},
		{"template_version", r.TemplateVersion},
		{"subject.kind", string(r.Subject.Kind)},
		{"subject.repo", r.Subject.Repo},
		{"subject.id", r.Subject.ID},
		{"action", string(r.Action)},
		{"target", r.Target},
		{"outcome", r.Outcome},
	}
	if d := r.Decision; d != nil {
		fields = append(fields,
			namedString{"decision.operation", d.Operation},
			namedString{"decision.role", d.Role},
			namedString{"decision.revision", d.Revision},
			namedString{"decision.verdict", string(d.Verdict)},
			namedString{"decision.reason", d.Reason})
	}
	if l := r.Link; l != nil {
		fields = append(fields,
			namedString{"link.kind", string(l.Kind)},
			namedString{"link.repo", l.Repo},
			namedString{"link.id", l.ID})
	}
	if len(r.Attrs) > MaxAttrs {
		return invalid("attrs", "more than %d attributes", MaxAttrs)
	}
	for _, k := range sortedKeys(r.Attrs) {
		if !validAttrKey(k) {
			return invalid("attrs", "key %s must be 1..%d bytes of [a-z0-9_.-]", clip(k), MaxAttrKeyBytes)
		}
		fields = append(fields, namedString{"attrs." + k, r.Attrs[k]}, namedString{"attrs key " + k, k})
	}
	total := 0
	for _, f := range fields {
		if len(f.v) > MaxStringBytes {
			return invalid(f.name, "longer than %d bytes", MaxStringBytes)
		}
		if !utf8.ValidString(f.v) {
			return invalid(f.name, "not valid UTF-8")
		}
		total += len(f.v)
	}
	if total > MaxRecordBytes {
		return invalid("record", "strings total more than %d bytes", MaxRecordBytes)
	}
	return nil
}

func validAttrKey(k string) bool {
	if k == "" || len(k) > MaxAttrKeyBytes {
		return false
	}
	for _, c := range []byte(k) {
		ok := c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_' || c == '.' || c == '-'
		if !ok {
			return false
		}
	}
	return true
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}
