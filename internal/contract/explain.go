// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

package contract

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"unicode"
	"unicode/utf16"
)

// Explanation is the effective contract for one path with the source of every
// value (CON-13). Its strings are raw repository text. WriteExplanation and
// MarshalJSON escape them; any other consumer must too.
type Explanation struct {
	Revision string // the commit the contracts were read from
	// InstallRevision is the commit of the install config the baseline came from, empty if none.
	InstallRevision string
	Effective       PathPolicy
}

// Explain returns every effective value for path and the contract that set it.
// Errors from ForPath pass through: an invalid path wraps pathglob.ErrInvalidPath
// and an over-budget one wraps ErrTooComplex.
func (p *Policy) Explain(path string) (Explanation, error) {
	pp, err := p.ForPath(path)
	if err != nil {
		return Explanation{}, err
	}
	return Explanation{Revision: p.revision, InstallRevision: p.base.InstallRevision, Effective: pp}, nil
}

// quoted escapes untrusted text for one line of explain output: control,
// format (bidi) and invalid bytes, and backslashes, become escapes, a '"'
// becomes \", and it is bounded. The result is always one double-quoted token.
func quoted(s string) string { return quoteEscaped(display(s, maxFileLen)) }

func quotedList(ss []string) string {
	if len(ss) == 0 {
		return "none"
	}
	out := make([]string, len(ss))
	for i, s := range ss {
		out[i] = quoted(s)
	}
	return strings.Join(out, ", ")
}

// WriteExplanation prints one line per effective value with its source. Every
// string from the repository is escaped, so a newline, escape sequence or
// bidi control in a path, contract file or gate name cannot forge a line.
func WriteExplanation(w io.Writer, e Explanation) error {
	pp := e.Effective
	var b strings.Builder
	line := func(format string, args ...any) {
		fmt.Fprintf(&b, format, args...)
		b.WriteByte('\n')
	}
	line("revision: %s", quoted(e.Revision))
	line("installRevision: %s", quoted(e.InstallRevision))
	line("path: %s", quoted(pp.Path))
	line("covered: %t", pp.Covered)
	line("stack: %s", quotedList(pp.Stack))
	line("access: %s (source: %s)", pp.Access, quoted(pp.AccessSource))
	line("protected: %t", pp.Protected)
	line("sensitive: %t (sources: %s)", pp.Sensitive, quotedList(pp.SensitiveSources))
	line("generated: %t (source: %s)", pp.Generated.Value, quoted(pp.Generated.Source))
	line("lightsOn: %t (sources: %s)", pp.LightsOn, quotedList(pp.LightsOnSources))
	line("switchStaleDays: %d (source: %s)", pp.SwitchStaleDays.Value, quoted(pp.SwitchStaleDays.Source))
	line("switchAbandonedDays: %d (source: %s)", pp.SwitchAbandonedDays.Value, quoted(pp.SwitchAbandonedDays.Source))
	line("reviewBudgetLines: %d (source: %s)", pp.ReviewBudgetLines.Value, quoted(pp.ReviewBudgetLines.Source))
	for _, stage := range []struct {
		name string
		obs  []Obligation
	}{{stageVerify, pp.VerifyGates}, {stageUnion, pp.UnionGates}} {
		for i := range stage.obs {
			o := &stage.obs[i]
			line("%s gate: name=%s producer=%s workflow=%s check=%s revision=%s mandatory=%t owner=%s sources: %s",
				stage.name, quoted(o.Gate.Name), quoted(o.Gate.ProducerID), quoted(string(o.Gate.WorkflowID)),
				quoted(o.Gate.CheckID), quoted(o.Gate.WorkflowRevision), o.Gate.Mandatory, quoted(string(o.Owner)),
				quotedList(o.Sources))
		}
	}
	for i := range pp.Oracles {
		o := &pp.Oracles[i]
		obs := make([]string, len(o.Oracle.Observables))
		for j, ob := range o.Oracle.Observables {
			obs[j] = string(ob)
		}
		line("oracle: name=%s producer=%s workflow=%s check=%s revision=%s observables=%s sources: %s",
			quoted(o.Oracle.Name), quoted(o.Oracle.ProducerID), quoted(string(o.Oracle.WorkflowID)),
			quoted(o.Oracle.CheckID), quoted(o.Oracle.WorkflowRevision), quotedList(obs), quotedList(o.Sources))
	}
	for _, r := range pp.Reviewers {
		line("reviewer: %s sources: %s", quoted(r.Role), quotedList(r.Sources))
	}
	_, err := io.WriteString(w, b.String())
	if err != nil {
		return fmt.Errorf("write explanation: %w", err)
	}
	return nil
}

// The JSON shape of an Explanation. Field names are stable: add fields, never
// rename or repurpose one. Access is "forbidden", "none", "read-only" or
// "writable". Every "source" is a contract file, "install default" or
// "factory baseline". encoding/json escapes control characters in strings.
type (
	jsonValued[T any] struct {
		Value  T      `json:"value"`
		Source string `json:"source"`
	}
	jsonGate struct {
		Name             string   `json:"name"`
		ProducerID       string   `json:"producerId"`
		WorkflowID       string   `json:"workflowId"`
		WorkflowRevision string   `json:"workflowRevision"`
		CheckID          string   `json:"checkId"`
		Mandatory        bool     `json:"mandatory"`
		Owner            string   `json:"owner"`
		Sources          []string `json:"sources"`
	}
	jsonOracle struct {
		Name             string   `json:"name"`
		ProducerID       string   `json:"producerId"`
		WorkflowID       string   `json:"workflowId"`
		WorkflowRevision string   `json:"workflowRevision"`
		CheckID          string   `json:"checkId"`
		Observables      []string `json:"observables"`
		Sources          []string `json:"sources"`
	}
	jsonReviewer struct {
		Role    string   `json:"role"`
		Sources []string `json:"sources"`
	}
	jsonExplanation struct {
		Revision            string             `json:"revision"`
		InstallRevision     string             `json:"installRevision"`
		Path                string             `json:"path"`
		Covered             bool               `json:"covered"`
		Stack               []string           `json:"stack"`
		Access              jsonValued[string] `json:"access"`
		Protected           bool               `json:"protected"`
		Sensitive           jsonSources[bool]  `json:"sensitive"`
		Generated           jsonValued[bool]   `json:"generated"`
		LightsOn            jsonSources[bool]  `json:"lightsOn"`
		SwitchStaleDays     jsonValued[int]    `json:"switchStaleDays"`
		SwitchAbandonedDays jsonValued[int]    `json:"switchAbandonedDays"`
		ReviewBudgetLines   jsonValued[int]    `json:"reviewBudgetLines"`
		VerifyGates         []jsonGate         `json:"verifyGates"`
		UnionGates          []jsonGate         `json:"unionGates"`
		Oracles             []jsonOracle       `json:"oracles"`
		Reviewers           []jsonReviewer     `json:"reviewers"`
	}
	jsonSources[T any] struct {
		Value   T        `json:"value"`
		Sources []string `json:"sources"`
	}
)

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func jsonGateOf(o *Obligation) jsonGate {
	g := o.Gate
	return jsonGate{
		Name: g.Name, ProducerID: g.ProducerID, WorkflowID: string(g.WorkflowID), WorkflowRevision: g.WorkflowRevision,
		CheckID: g.CheckID, Mandatory: g.Mandatory, Owner: string(o.Owner), Sources: nonNil(o.Sources),
	}
}

// MarshalJSON encodes the explanation in a stable shape (see jsonExplanation),
// with empty lists as [] and not null.
func (e Explanation) MarshalJSON() ([]byte, error) {
	pp := e.Effective
	out := jsonExplanation{
		Revision: e.Revision, InstallRevision: e.InstallRevision, Path: pp.Path, Covered: pp.Covered, Stack: nonNil(pp.Stack),
		Access:              jsonValued[string]{Value: pp.Access.String(), Source: pp.AccessSource},
		Protected:           pp.Protected,
		Sensitive:           jsonSources[bool]{Value: pp.Sensitive, Sources: nonNil(pp.SensitiveSources)},
		Generated:           jsonValued[bool](pp.Generated),
		LightsOn:            jsonSources[bool]{Value: pp.LightsOn, Sources: nonNil(pp.LightsOnSources)},
		SwitchStaleDays:     jsonValued[int](pp.SwitchStaleDays),
		SwitchAbandonedDays: jsonValued[int](pp.SwitchAbandonedDays),
		ReviewBudgetLines:   jsonValued[int](pp.ReviewBudgetLines),
		VerifyGates:         []jsonGate{}, UnionGates: []jsonGate{}, Oracles: []jsonOracle{}, Reviewers: []jsonReviewer{},
	}
	for i := range pp.VerifyGates {
		out.VerifyGates = append(out.VerifyGates, jsonGateOf(&pp.VerifyGates[i]))
	}
	for i := range pp.UnionGates {
		out.UnionGates = append(out.UnionGates, jsonGateOf(&pp.UnionGates[i]))
	}
	for i := range pp.Oracles {
		o := &pp.Oracles[i]
		obs := make([]string, len(o.Oracle.Observables))
		for j, ob := range o.Oracle.Observables {
			obs[j] = string(ob)
		}
		out.Oracles = append(out.Oracles, jsonOracle{
			Name: o.Oracle.Name, ProducerID: o.Oracle.ProducerID, WorkflowID: string(o.Oracle.WorkflowID),
			WorkflowRevision: o.Oracle.WorkflowRevision, CheckID: o.Oracle.CheckID,
			Observables: obs, Sources: nonNil(o.Sources),
		})
	}
	for _, r := range pp.Reviewers {
		out.Reviewers = append(out.Reviewers, jsonReviewer{Role: r.Role, Sources: nonNil(r.Sources)})
	}
	data, err := json.Marshal(out)
	if err != nil {
		return nil, fmt.Errorf("encode explanation: %w", err)
	}
	return escapeFormat(data), nil
}

// escapeFormat rewrites every rune that display would escape ('#', C1 controls,
// format characters such as bidi overrides and zero-width joiners, other
// non-printable runes) as \uXXXX. encoding/json escapes only the C0 controls,
// and a consumer that prints the JSON could be misled by the rest. A rewrite
// is always valid JSON because such runes occur only inside strings.
func escapeFormat(data []byte) []byte {
	var b bytes.Buffer
	for _, r := range string(data) {
		switch {
		case r > 0xffff && (!unicode.IsPrint(r) || unicode.Is(unicode.Cf, r)):
			hi, lo := utf16.EncodeRune(r)
			fmt.Fprintf(&b, `\u%04x\u%04x`, hi, lo)
		case r == '#' || !unicode.IsPrint(r) || unicode.Is(unicode.Cf, r):
			fmt.Fprintf(&b, `\u%04x`, r)
		default:
			b.WriteRune(r)
		}
	}
	return b.Bytes()
}
