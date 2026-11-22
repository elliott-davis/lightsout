// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

package switches

import (
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"

	"go.yaml.in/yaml/v3"
)

// This file ports the part of flagd core v0.19.3 that turns a file into flags, so that detection judges what flagd
// would serve and not what a file looks like. The ported code is from github.com/open-feature/flagd, Copyright The
// OpenFeature Authors, licensed under the Apache License 2.0 (https://www.apache.org/licenses/LICENSE-2.0). Each
// function cites its source in core/pkg. Only the behaviour is ported, with Go types of this package, and the
// differential corpus in testdata/flagd-differential pins it to the real loader without importing flagd.

// effFlag is one flag as flagd's store holds it after loading.
type effFlag struct {
	Key            string
	State          string
	DefaultVariant string
	Variants       map[string]any
	HasTargeting   bool
}

// flagModel is core/pkg/model.Flag (flag.go) for decoding. Its tags match case-insensitively, as flagd's do.
type flagModel struct {
	Key            string          `json:"key"`
	State          string          `json:"state"`
	DefaultVariant string          `json:"defaultVariant"`
	Variants       map[string]any  `json:"variants"`
	Targeting      json.RawMessage `json:"targeting,omitempty"`
	Source         string          `json:"source"`
	Metadata       map[string]any  `json:"metadata,omitempty"`
}

// extJSON is the detected type of a JSON file.
const extJSON = "json"

// Load stages of [emulateFile].
const (
	stageConvert = "convert" // utils.ConvertToJSON refused the file
	stageLoad    = "load"    // the evaluator refused the converted text
	stageOK      = "ok"
)

// emulateFile ports the path from a file's bytes and extension to flagd's store: core/pkg/utils.ConvertToJSON and
// core/pkg/evaluator.JSON.SetState. It returns the stage reached and, for [stageOK], the flags sorted by key.
func emulateFile(data []byte, ext string) (string, []effFlag) {
	js, ok := convertToJSON(data, ext)
	if !ok {
		return stageConvert, nil
	}
	flags, err := loadFlags(js)
	if err != nil {
		return stageLoad, nil
	}
	return stageOK, flags
}

// convertToJSON ports core/pkg/utils/convert_to_json.go ConvertToJSON for a file extension: the extension is
// stripped of everything that is not an ASCII letter or digit (the ASCII-only class [^a-zA-Z0-9]+, so "é" and "ſ"
// are removed, not kept), lower-cased, and must be json, yaml or yml. ok is false for any other extension, and for
// a file with no extension (flagd then needs a media type, which a file does not have).
func convertToJSON(data []byte, ext string) (string, bool) {
	switch asciiExtension(ext) {
	case "yaml", "yml":
		return yamlToJSON(data)
	case extJSON:
		return string(data), true
	}
	return "", false
}

// asciiExtension is the detected type of ConvertToJSON: the extension without any byte that is not an ASCII letter
// or digit, in lower case.
func asciiExtension(ext string) string {
	var b strings.Builder
	for i := range len(ext) {
		c := ext[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9':
			b.WriteByte(c)
		case c >= 'A' && c <= 'Z':
			b.WriteByte(c + 'a' - 'A')
		}
	}
	return b.String()
}

// yamlToJSON ports core/pkg/utils/yaml.go YAMLToJSON: the first document is unmarshalled into a map, nested keys
// are made strings, and the map is marshalled. An empty file is the empty string, which the evaluator then refuses.
func yamlToJSON(raw []byte) (string, bool) {
	if len(raw) == 0 {
		return "", true
	}
	var ms map[string]any
	if yaml.Unmarshal(raw, &ms) != nil {
		return "", false
	}
	out, err := json.Marshal(convertMapKeys(ms))
	if err != nil {
		return "", false
	}
	return string(out), true
}

// convertMapKeys ports core/pkg/utils/yaml.go convertMapKeys: a map[any]any becomes a map[string]any with
// fmt.Sprintf("%v") keys. When two keys give the same string flagd keeps whichever the map iteration reaches last,
// so the result is random. [stringKeys] reports that as a problem instead.
func convertMapKeys(in any) any {
	switch v := in.(type) {
	case map[string]any:
		for key, val := range v {
			v[key] = convertMapKeys(val)
		}
		return v
	case map[any]any:
		out := make(map[string]any, len(v))
		for key, val := range v {
			out[fmt.Sprintf("%v", key)] = convertMapKeys(val)
		}
		return out
	case []any:
		for i, val := range v {
			v[i] = convertMapKeys(val)
		}
		return v
	}
	return in
}

// loadFlags ports core/pkg/evaluator/json.go configToFlagDefinition, without the schema check, which only logs a
// warning: evaluators are transposed, the text is decoded, "flags" is read as an array or as an object, and every
// default variant must name a variant. It returns the flags sorted by key (and by order for an array).
func loadFlags(config string) ([]effFlag, error) {
	transposed, err := transposeEvaluators(config)
	if err != nil {
		return nil, fmt.Errorf("transposing evaluators: %w", err)
	}
	var rawDef struct {
		Flags    json.RawMessage `json:"flags"`
		Metadata map[string]any  `json:"metadata"`
	}
	if err := json.Unmarshal([]byte(transposed), &rawDef); err != nil {
		return nil, fmt.Errorf("unmarshalling provided configurations: %w", err)
	}
	var models []flagModel
	if strings.HasPrefix(strings.TrimSpace(string(rawDef.Flags)), "[") {
		if err := json.Unmarshal(rawDef.Flags, &models); err != nil {
			return nil, fmt.Errorf("unmarshalling flags array: %w", err)
		}
	} else {
		var byKey map[string]flagModel
		if err := json.Unmarshal(rawDef.Flags, &byKey); err != nil {
			return nil, fmt.Errorf("unmarshalling flags map: %w", err)
		}
		for _, k := range slices.Sorted(maps.Keys(byKey)) {
			m := byKey[k]
			m.Key = k
			models = append(models, m)
		}
	}
	out := make([]effFlag, 0, len(models))
	for _, m := range models {
		// validateDefaultVariants in json.go: an empty default variant is "not provided".
		if _, ok := m.Variants[m.DefaultVariant]; m.DefaultVariant != "" && !ok {
			return nil, fmt.Errorf("default variant %q is not a variant of flag %q", m.DefaultVariant, m.Key)
		}
		out = append(out, effFlag{Key: m.Key, State: m.State, DefaultVariant: m.DefaultVariant, Variants: m.Variants, HasTargeting: len(m.Targeting) > 0})
	}
	slices.SortStableFunc(out, func(a, b effFlag) int { return strings.Compare(a.Key, b.Key) })
	return out, nil
}

// transposeEvaluators ports core/pkg/evaluator/json.go transposeEvaluators, including its flaw: the text is
// normalized by a decode and re-marshal, and then every {"$ref":"name"} is replaced by raw string replacement with
// the evaluator's text as it appeared in the original file, so an evaluator name or value that carries quotes and
// braces rewrites the surrounding JSON. flagd walks a Go map, so its order is random. This walks the names in sorted
// order. The canonical form refuses every name that could matter, so the order is irrelevant to a canonical file.
func transposeEvaluators(state string) (string, error) {
	var evaluators struct {
		Evaluators map[string]json.RawMessage `json:"$evaluators"`
	}
	if err := json.Unmarshal([]byte(state), &evaluators); err != nil {
		return "", fmt.Errorf("unmarshal: %w", err)
	}
	var raw any
	if err := json.Unmarshal([]byte(state), &raw); err != nil {
		return "", fmt.Errorf("normalize: %w", err)
	}
	normalized, err := json.Marshal(raw)
	if err != nil {
		return "", fmt.Errorf("normalize marshal: %w", err)
	}
	result := string(normalized)
	for _, name := range slices.Sorted(maps.Keys(evaluators.Evaluators)) {
		value := string(evaluators.Evaluators[name])
		if len(value) < 3 {
			return "", errors.New("evaluator object is empty")
		}
		result = strings.ReplaceAll(result, `{"$ref":"`+name+`"}`, value)
	}
	return result, nil
}

// sourceKeys reports which of "flags" and "$evaluators" the top level of a JSON object has, matched as
// encoding/json matches field names (and so as flagd's decode does): case-insensitively, whatever the value.
func sourceKeys(js string) (flags, evaluators bool) {
	var s struct {
		Flags      json.RawMessage `json:"flags"`
		Evaluators json.RawMessage `json:"$evaluators"`
	}
	if json.Unmarshal([]byte(js), &s) != nil {
		return false, false
	}
	return len(s.Flags) > 0, len(s.Evaluators) > 0
}

// manifestShaped reports whether a JSON document is an OpenFeature manifest: "flags" is an object with an entry
// that has "flagType" and neither "state" nor "variants". No SDK reads a manifest, so it never makes a flag, and
// it is not a flagd source, but its definitions are recorded as the manifest's.
func manifestShaped(js string) bool {
	var s struct {
		Flags map[string]json.RawMessage `json:"flags"`
	}
	if json.Unmarshal([]byte(js), &s) != nil {
		return false
	}
	for _, e := range s.Flags {
		var entry map[string]json.RawMessage
		if json.Unmarshal(e, &entry) != nil {
			continue
		}
		_, hasType := entry["flagType"]
		_, hasState := entry["state"]
		_, hasVariants := entry["variants"]
		if hasType && !hasState && !hasVariants {
			return true
		}
	}
	return false
}

// isFlagSource is the source test. A document is a source if flagd would serve a flag with variants from it, if
// its top level has any key that folds to "$evaluators" (so a splice that lifts "flags" out of a nested object,
// or hides it behind another, cannot slip through), or if it has the shape of an OpenFeature manifest. A flag
// without variants gives no value in flagd, so the SDK uses the code default, exactly as for a missing flag.
func isFlagSource(js string) bool {
	flags, evaluators := sourceKeys(js)
	if evaluators {
		return true
	}
	if !flags {
		return false
	}
	if manifestShaped(js) {
		return true
	}
	eff, err := loadFlags(js)
	if err != nil {
		return false
	}
	return slices.ContainsFunc(eff, func(f effFlag) bool { return len(f.Variants) > 0 })
}

// canonicalMatchesEffective reports whether the canonical flags of a strictly parsed flagd source are exactly the
// flags flagd would serve from it: the same keys, and for each the same state, default variant, variants and
// whether it has targeting. A canonical file cannot differ, so a difference means a splice or a quirk this package
// does not model, which fails closed.
func canonicalMatchesEffective(doc map[string]any, js string) bool {
	eff, err := loadFlags(js)
	if err != nil {
		return false
	}
	flags, _ := doc[keyFlags].(map[string]any)
	if len(flags) != len(eff) {
		return false
	}
	for _, e := range eff {
		entry, ok := flags[e.Key].(map[string]any)
		if !ok {
			return false
		}
		state, _ := entry["state"].(string)
		def, _ := entry["defaultVariant"].(string)
		_, targeting := entry["targeting"]
		if state != e.State || def != e.DefaultVariant || targeting != e.HasTargeting ||
			canon(normalizeNumbers(entry["variants"])) != canon(e.Variants) {
			return false
		}
	}
	return true
}

// normalizeNumbers turns the json.Number of a strict parse into the float64 flagd decodes.
func normalizeNumbers(v any) any {
	switch t := v.(type) {
	case json.Number:
		f, err := t.Float64()
		if err != nil {
			return string(t)
		}
		return f
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, e := range t {
			out[k] = normalizeNumbers(e)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, e := range t {
			out[i] = normalizeNumbers(e)
		}
		return out
	}
	return v
}
