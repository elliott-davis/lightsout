// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

package oracle

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

// report is a parsed lightsout.oracle/v1 report. Every string is untrusted.
type parsedReport struct {
	Repo                                      string
	RunID, RunAttempt, JobID                  string
	BaselineSHA, CandidateSHA, OracleRevision string
	Comparison, CaseManifest                  string
	SwitchOverrides                           map[string]string
	RequestedBaseline, RequestedCandidate     string
	LoadedBaseline, LoadedCandidate           string
	Observations                              []observation
}

type side struct {
	Status, Fixture, Digest string
}

type observation struct {
	Case, Boundary      string
	Baseline, Candidate side
	DiffsComplete       bool
	Diffs               []difference
}

type difference struct {
	Record, Operation, Field string
	Before, After            any
}

var plainNumber = regexp.MustCompile(`^-?(0|[1-9]\d*)(\.\d+)?$`)

// parseReport decodes a report strictly: valid UTF-8, one JSON value, no duplicate keys (case-sensitively), no
// unknown or missing fields, depth bounded. Errors are static or escaped.
func parseReport(data []byte) (*parsedReport, error) {
	tree, err := parseJSON(data, maxReportDepth)
	if err != nil {
		return nil, err
	}
	root, err := exactObject(tree, "schema", "repo", "job", "baselineSHA", "candidateSHA", "oracleRevision",
		"comparison", "caseManifest", "switchOverrides", "configs", "observations")
	if err != nil {
		return nil, err
	}
	r := &parsedReport{}
	if sch, _ := root["schema"].(string); sch != ReportSchema {
		return nil, errors.New("unsupported report schema")
	}
	strs := []struct {
		key string
		dst *string
	}{
		{"repo", &r.Repo},
		{"baselineSHA", &r.BaselineSHA},
		{"candidateSHA", &r.CandidateSHA},
		{"oracleRevision", &r.OracleRevision},
		{"comparison", &r.Comparison},
		{"caseManifest", &r.CaseManifest},
	}
	for _, f := range strs {
		if *f.dst, err = str(root, f.key); err != nil {
			return nil, err
		}
	}
	job, err := exactObject(root["job"], "runId", "runAttempt", "jobId")
	if err != nil {
		return nil, fmt.Errorf("job: %w", err)
	}
	for _, f := range []struct {
		key string
		dst *string
	}{{"runId", &r.RunID}, {"runAttempt", &r.RunAttempt}, {"jobId", &r.JobID}} {
		if *f.dst, err = str(job, f.key); err != nil {
			return nil, fmt.Errorf("job: %w", err)
		}
	}
	ov, ok := root["switchOverrides"].(map[string]any)
	if !ok {
		return nil, errors.New("switchOverrides: not an object")
	}
	r.SwitchOverrides = make(map[string]string, len(ov))
	for k, v := range ov {
		val, isStr := v.(string)
		if !isStr || len(val) > MaxScalar || len(k) > MaxScalar || strings.ContainsRune(k+val, 0) {
			return nil, errors.New("switchOverrides: not a map of bounded strings")
		}
		r.SwitchOverrides[k] = val
	}
	cfg, err := exactObject(root["configs"], "requested", "loaded")
	if err != nil {
		return nil, fmt.Errorf("configs: %w", err)
	}
	for _, c := range []struct {
		name string
		dsts [2]*string
	}{
		{"requested", [2]*string{&r.RequestedBaseline, &r.RequestedCandidate}},
		{"loaded", [2]*string{&r.LoadedBaseline, &r.LoadedCandidate}},
	} {
		o, err := exactObject(cfg[c.name], "baseline", "candidate")
		if err != nil {
			return nil, fmt.Errorf("configs.%s: %w", c.name, err)
		}
		if *c.dsts[0], err = str(o, "baseline"); err != nil {
			return nil, err
		}
		if *c.dsts[1], err = str(o, "candidate"); err != nil {
			return nil, err
		}
	}
	list, ok := root["observations"].([]any)
	if !ok {
		return nil, errors.New("observations: not a list")
	}
	total := 0
	for i, v := range list {
		o, err := parseObservation(v)
		if err != nil {
			return nil, fmt.Errorf("observations[%d]: %w", i, err)
		}
		if total += len(o.Diffs); total > maxTotalDifferences {
			return nil, fmt.Errorf("more than %d differences", maxTotalDifferences)
		}
		r.Observations = append(r.Observations, o)
	}
	return r, nil
}

func parseObservation(v any) (observation, error) {
	var o observation
	m, err := exactObject(v, "case", "boundary", "baseline", "candidate", "differencesComplete", "differences")
	if err != nil {
		return o, err
	}
	if o.Case, err = str(m, "case"); err != nil {
		return o, err
	}
	if o.Boundary, err = str(m, "boundary"); err != nil {
		return o, err
	}
	for _, sd := range []struct {
		name string
		dst  *side
	}{{"baseline", &o.Baseline}, {"candidate", &o.Candidate}} {
		s, err := exactObject(m[sd.name], "status", "fixture", "digest")
		if err != nil {
			return o, fmt.Errorf("%s: %w", sd.name, err)
		}
		for _, f := range []struct {
			key string
			dst *string
		}{{"status", &sd.dst.Status}, {"fixture", &sd.dst.Fixture}, {"digest", &sd.dst.Digest}} {
			if *f.dst, err = str(s, f.key); err != nil {
				return o, fmt.Errorf("%s: %w", sd.name, err)
			}
		}
	}
	complete, ok := m["differencesComplete"].(bool)
	if !ok {
		return o, errors.New("differencesComplete: not a boolean")
	}
	o.DiffsComplete = complete
	diffs, ok := m["differences"].([]any)
	if !ok || len(diffs) > maxDifferences {
		return o, fmt.Errorf("differences: not a list of at most %d", maxDifferences)
	}
	for i, dv := range diffs {
		d, err := exactObject(dv, "record", "operation", "field", "before", "after")
		if err != nil {
			return o, fmt.Errorf("differences[%d]: %w", i, err)
		}
		var df difference
		for _, f := range []struct {
			key string
			dst *string
		}{{"record", &df.Record}, {"operation", &df.Operation}, {"field", &df.Field}} {
			if *f.dst, err = str(d, f.key); err != nil {
				return o, fmt.Errorf("differences[%d]: %w", i, err)
			}
		}
		var okb, oka bool
		if df.Before, okb = scalar(d["before"]); !okb {
			return o, fmt.Errorf("differences[%d]: before is not a bounded scalar", i)
		}
		if df.After, oka = scalar(d["after"]); !oka {
			return o, fmt.Errorf("differences[%d]: after is not a bounded scalar", i)
		}
		o.Diffs = append(o.Diffs, df)
	}
	return o, nil
}

// str returns the string at key, which must be present, and bounded to 1 KiB.
func str(m map[string]any, key string) (string, error) {
	s, ok := m[key].(string)
	if !ok {
		return "", fmt.Errorf("%s: not a string", key)
	}
	if len(s) > MaxScalar {
		return "", fmt.Errorf("%s: longer than %d bytes", key, MaxScalar)
	}
	if strings.ContainsRune(s, 0) {
		return "", fmt.Errorf("%s: contains a NUL character", key)
	}
	return s, nil
}

// scalar returns v when it is null, a boolean, a string of at most 1 KiB or a plain decimal number of at most 1 KiB.
func scalar(v any) (any, bool) {
	switch x := v.(type) {
	case nil, bool:
		return x, true
	case string:
		return x, len(x) <= MaxScalar && !strings.ContainsRune(x, 0)
	case json.Number:
		return x, len(x) <= MaxScalar && plainNumber.MatchString(string(x))
	default:
		return nil, false
	}
}

// canon returns a canonical text of a JSON scalar, so that equal values compare equal and 404 equals 404.0. It
// returns false for anything that is not a bounded scalar.
func canon(v any) (string, bool) {
	v, ok := scalar(v)
	if !ok {
		return "", false
	}
	switch x := v.(type) {
	case nil:
		return "null", true
	case bool:
		return "b:" + strconv.FormatBool(x), true
	case string:
		return "s:" + x, true
	case json.Number:
		s := string(x)
		if strings.Contains(s, ".") {
			s = strings.TrimRight(s, "0")
			s = strings.TrimSuffix(s, ".")
		}
		if s == "-0" {
			s = "0"
		}
		return "n:" + s, true
	}
	return "", false
}

// parseJSON decodes one JSON value into map[string]any, []any, string, bool, nil or json.Number. It rejects invalid
// UTF-8, a byte-order mark, duplicate object keys (exact match) at any level, nesting deeper than maxDepth and
// anything after the top-level value. It reads tokens, so no value is built before its depth is checked.
func parseJSON(data []byte, maxDepth int) (any, error) {
	if !utf8.Valid(data) {
		return nil, errors.New("report is not valid UTF-8")
	}
	if bytes.HasPrefix(data, []byte{0xEF, 0xBB, 0xBF}) {
		return nil, errors.New("report starts with a byte-order mark")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	p := &jsonParser{dec: dec, maxDepth: maxDepth}
	tok, err := dec.Token()
	if err != nil {
		return nil, errors.New("invalid JSON")
	}
	v, err := p.value(tok, 1)
	if err != nil {
		return nil, err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("data after the top-level JSON value")
	}
	return v, nil
}

type jsonParser struct {
	dec      *json.Decoder
	maxDepth int
	values   int
}

var errSyntax = errors.New("invalid JSON")

func (p *jsonParser) value(tok json.Token, depth int) (any, error) {
	p.values++
	if p.values > maxValues {
		return nil, fmt.Errorf("more than %d JSON values", maxValues)
	}
	d, ok := tok.(json.Delim)
	if !ok {
		return tok, nil // string, json.Number, bool or nil
	}
	if depth > p.maxDepth {
		return nil, fmt.Errorf("nesting is deeper than %d", p.maxDepth)
	}
	if d == '{' {
		return p.object(depth)
	}
	return p.array(depth)
}

func (p *jsonParser) object(depth int) (any, error) {
	out := map[string]any{}
	for p.dec.More() {
		if len(out) >= maxOverrides {
			return nil, fmt.Errorf("an object has more than %d keys", maxOverrides)
		}
		kt, err := p.dec.Token()
		if err != nil {
			return nil, errSyntax
		}
		key, _ := kt.(string) // the decoder only yields strings here
		if _, dup := out[key]; dup {
			return nil, errors.New("duplicate object key")
		}
		vt, err := p.dec.Token()
		if err != nil {
			return nil, errSyntax
		}
		v, err := p.value(vt, depth+1)
		if err != nil {
			return nil, err
		}
		out[key] = v
	}
	if _, err := p.dec.Token(); err != nil { // the closing brace
		return nil, errSyntax
	}
	return out, nil
}

func (p *jsonParser) array(depth int) (any, error) {
	out := []any{}
	for p.dec.More() {
		if len(out) >= MaxMatrix {
			return nil, fmt.Errorf("an array has more than %d items", MaxMatrix)
		}
		vt, err := p.dec.Token()
		if err != nil {
			return nil, errSyntax
		}
		v, err := p.value(vt, depth+1)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	if _, err := p.dec.Token(); err != nil { // the closing bracket
		return nil, errSyntax
	}
	return out, nil
}
