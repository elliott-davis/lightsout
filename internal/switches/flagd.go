// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

package switches

import (
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"
)

const (
	keySchema     = "$schema"
	keyFlags      = "flags"
	keyEvaluators = "$evaluators"
	keyMetadata   = "metadata"
	jsonNull      = "null"
)

func flagdTopKey(k string) bool {
	switch k {
	case keySchema, keyFlags, keyEvaluators, keyMetadata:
		return true
	}
	return false
}

func flagdFlagKey(k string) bool {
	switch k {
	case "state", "variants", "defaultVariant", "targeting", keyMetadata, "description":
		return true
	}
	return false
}

func manifestTopKey(k string) bool { return k == keySchema || k == keyFlags }

func manifestFlagKey(k string) bool {
	switch k {
	case "flagType", "defaultValue", "description":
		return true
	}
	return false
}

// valueType names the JSON type of a decoded value.
func valueType(v any) string {
	switch v := v.(type) {
	case bool:
		return "boolean"
	case string:
		return "string"
	case json.Number:
		return "number"
	case map[string]any:
		return "object"
	case []any:
		return "array"
	case nil:
		return jsonNull
	default:
		return fmt.Sprintf("%T", v)
	}
}

// evaluatorName reports whether n is a valid $evaluators name. flagd splices the evaluator into the flag text by
// string replacement, so a name that could carry quotes or braces could rewrite other flags. The set is
// deliberately small.
func evaluatorName(n string) bool {
	if n == "" || len(n) > 64 {
		return false
	}
	for _, r := range n {
		if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '_' && r != '-' {
			return false
		}
	}
	return true
}

// scalarObject reports whether v is an object of string, number and boolean values.
func scalarObject(v any) bool {
	obj, ok := v.(map[string]any)
	if !ok {
		return false
	}
	for _, e := range obj {
		switch e.(type) {
		case string, bool, json.Number:
		default:
			return false
		}
	}
	return true
}

// flagsObject returns the "flags" object of a source, or reports why it is not canonical.
func (sc *scan) flagsObject(p string, doc map[string]any) (map[string]any, bool) {
	switch v := doc[keyFlags].(type) {
	case map[string]any:
		return v, true
	case []any:
		sc.addf(p, []string{keyFlags}, CodeNonCanonicalArray, "flags is an array, which flagd accepts but this check does not: use an object keyed by switch name")
	default:
		sc.addf(p, []string{keyFlags}, CodeSchema, "flags must be an object keyed by switch name")
	}
	return nil, false
}

// flagd records the flags of one flagd source in canonical form (see [Detect]).
func (sc *scan) flagd(p string, doc map[string]any) error {
	sc.unknownKeys(p, nil, doc, flagdTopKey)
	if s, has := doc[keySchema]; has {
		if _, ok := s.(string); !ok {
			sc.addf(p, []string{keySchema}, CodeSchema, "$schema must be a string")
		}
	}
	evaluators := map[string]bool{}
	if raw, has := doc[keyEvaluators]; has {
		obj, ok := raw.(map[string]any)
		if !ok {
			sc.addf(p, []string{keyEvaluators}, CodeSchema, "$evaluators must be an object")
		}
		for _, name := range slices.Sorted(maps.Keys(obj)) {
			switch body, isObj := obj[name].(map[string]any); {
			case !evaluatorName(name):
				sc.addf(p, []string{keyEvaluators, name}, CodeSchema, "evaluator name must match [A-Za-z0-9_-]{1,64}")
			case !isObj || len(body) == 0:
				sc.addf(p, []string{keyEvaluators, name}, CodeSchema, "evaluator must be a non-empty object")
			default:
				evaluators[name] = true
			}
		}
	}
	if raw, has := doc[keyMetadata]; has && !scalarObject(raw) {
		sc.addf(p, []string{keyMetadata}, CodeSchema, "metadata must be an object of string, number or boolean values")
	}
	fs := fileState{sig: canon([]any{doc[keyEvaluators], doc[keyMetadata]}), evaluators: evaluators}
	for _, k := range slices.Sorted(maps.Keys(doc)) {
		if k != keyFlags {
			sc.refs(p, []string{k}, doc[k], false, evaluators)
		}
	}
	flags, ok := sc.flagsObject(p, doc)
	if !ok {
		return nil
	}
	if len(flags) > sc.lim.MaxFlagsPerFile {
		return &scanError{op: opScan, path: p, err: fmt.Errorf("more than %d flags: %w", sc.lim.MaxFlagsPerFile, ErrTooLarge)}
	}
	for _, key := range slices.Sorted(maps.Keys(flags)) {
		if err := sc.flagdFlag(p, key, flags[key], fs); err != nil {
			return err
		}
	}
	return nil
}

// fileState is what a flagd file says outside its flags, which changes what its flags mean at runtime.
type fileState struct {
	sig        string // canonical $evaluators and top-level metadata
	evaluators map[string]bool
}

// refs checks every "$ref" under v. flagd splices an evaluator in for {"$ref": name}, so a $ref is allowed only
// inside a flag's targeting, as an object with that one key naming an evaluator of the file.
func (sc *scan) refs(p string, ptr []string, v any, inTargeting bool, evaluators map[string]bool) {
	switch t := v.(type) {
	case map[string]any:
		if ref, has := t["$ref"]; has {
			name, isStr := ref.(string)
			switch {
			case !inTargeting:
				sc.addf(p, append(slices.Clone(ptr), "$ref"), CodeSchema, "$ref is allowed only inside targeting")
			case len(t) != 1 || !isStr || !evaluators[name]:
				sc.addf(p, append(slices.Clone(ptr), "$ref"), CodeSchema, "$ref must be the only key and name an evaluator of this file")
			}
		}
		for _, k := range slices.Sorted(maps.Keys(t)) {
			sc.refs(p, append(slices.Clone(ptr), k), t[k], inTargeting, evaluators)
		}
	case []any:
		for i, e := range t {
			sc.refs(p, append(slices.Clone(ptr), strconv.Itoa(i)), e, inTargeting, evaluators)
		}
	}
}

func (sc *scan) unknownKeys(p string, ptr []string, obj map[string]any, allowed func(string) bool) {
	for _, k := range slices.Sorted(maps.Keys(obj)) {
		if !allowed(k) {
			sc.addf(p, append(slices.Clone(ptr), k), CodeUnknownKey, "unknown key")
		}
	}
}

func (sc *scan) flagdFlag(p, key string, raw any, fs fileState) (err error) {
	ptr := []string{keyFlags, key}
	def := Definition{Path: p, Kind: KindFlagd, fileSig: fs.sig}
	bad := func(sub, format string, args ...any) {
		def.Invalid = true
		sc.addf(p, append(slices.Clone(ptr), sub), CodeSchema, format, args...)
	}
	defer func() { err = sc.addDef(key, &def) }()
	if key == "" {
		def.Invalid = true
		sc.addf(p, ptr, CodeSchema, "switch name is empty")
	}
	obj, ok := raw.(map[string]any)
	if !ok {
		def.Invalid = true
		sc.addf(p, ptr, CodeSchema, "flag must be an object, not %s", valueType(raw))
		sc.refs(p, ptr, raw, false, fs.evaluators)
		return err
	}
	for _, k := range slices.Sorted(maps.Keys(obj)) {
		sc.refs(p, append(slices.Clone(ptr), k), obj[k], k == "targeting", fs.evaluators)
	}
	for _, k := range slices.Sorted(maps.Keys(obj)) {
		if !flagdFlagKey(k) {
			def.Invalid = true
			sc.addf(p, append(slices.Clone(ptr), k), CodeUnknownKey, "unknown key")
		}
	}
	switch s, _ := obj["state"].(string); State(s) {
	case StateEnabled, StateDisabled:
		def.State = State(s)
	default:
		bad("state", "state must be ENABLED or DISABLED")
	}
	if v, has := obj["description"]; has {
		if s, isStr := v.(string); isStr {
			def.Description = s
		} else {
			bad("description", "description must be a string")
		}
	}
	if v, has := obj[keyMetadata]; has {
		if !scalarObject(v) {
			bad(keyMetadata, "metadata must be an object of string, number or boolean values")
		}
		def.metaSig = canon(v)
	}
	if v, has := obj["targeting"]; has {
		def.HasTargeting = true
		def.targetingSig = canon(v)
	}
	variants, ok := obj["variants"].(map[string]any)
	switch {
	case !ok:
		bad("variants", "variants must be an object")
	case len(variants) == 0:
		bad("variants", "variants must not be empty")
	default:
		def.Variants = variants
		def.Type = variantType(variants, bad)
	}
	switch dv := obj["defaultVariant"].(type) {
	case nil: // absent or null: the code default applies
	case string:
		if dv == "" { // flagd treats the empty string as no default, so the code default applies
			break
		}
		def.DefaultVariant, def.HasDefaultVariant = dv, true
		if val, found := variants[dv]; found {
			def.Default, def.HasDefault = val, true
		} else {
			bad("defaultVariant", "defaultVariant %s names no variant", dv)
		}
	default:
		bad("defaultVariant", "defaultVariant must be a string or null")
	}
	return nil
}

// variantType checks that every variant value is one non-array type and returns it, or "" after reporting why not.
func variantType(variants map[string]any, bad func(sub, format string, args ...any)) Type {
	var first string
	for _, name := range slices.Sorted(maps.Keys(variants)) {
		t := valueType(variants[name])
		switch {
		case t == "array" || t == "null":
			bad("variants", "variant %s must not be %s", name, t)
			return ""
		case first == "":
			first = t
		case t != first:
			bad("variants", "variant values must all be one type, found %s and %s", first, t)
			return ""
		}
	}
	return Type(first)
}

// manifestFlags records the flags of the OpenFeature CLI manifest.
func (sc *scan) manifestFlags(p string, doc map[string]any) error {
	sc.unknownKeys(p, nil, doc, manifestTopKey)
	for _, k := range slices.Sorted(maps.Keys(doc)) {
		sc.refs(p, []string{k}, doc[k], false, nil)
	}
	flags, ok := sc.flagsObject(p, doc)
	if !ok {
		return nil
	}
	if len(flags) > sc.lim.MaxFlagsPerFile {
		return &scanError{op: opScan, path: p, err: fmt.Errorf("more than %d flags: %w", sc.lim.MaxFlagsPerFile, ErrTooLarge)}
	}
	for _, key := range slices.Sorted(maps.Keys(flags)) {
		if err := sc.manifestFlag(p, key, flags[key]); err != nil {
			return err
		}
	}
	return nil
}

func (sc *scan) manifestFlag(p, key string, raw any) (err error) {
	ptr := []string{keyFlags, key}
	def := Definition{Path: p, Kind: KindManifest}
	bad := func(sub, format string, args ...any) {
		def.Invalid = true
		sc.addf(p, append(slices.Clone(ptr), sub), CodeSchema, format, args...)
	}
	defer func() { err = sc.addDef(key, &def) }()
	if key == "" {
		def.Invalid = true
		sc.addf(p, ptr, CodeSchema, "switch name is empty")
	}
	obj, ok := raw.(map[string]any)
	if !ok {
		def.Invalid = true
		sc.addf(p, ptr, CodeSchema, "flag must be an object, not %s", valueType(raw))
		return err
	}
	for _, k := range slices.Sorted(maps.Keys(obj)) {
		if !manifestFlagKey(k) {
			def.Invalid = true
			sc.addf(p, append(slices.Clone(ptr), k), CodeUnknownKey, "unknown key")
		}
	}
	if v, has := obj["description"]; has {
		if s, isStr := v.(string); isStr {
			def.Description = s
		} else {
			bad("description", "description must be a string")
		}
	}
	ft, _ := obj["flagType"].(string)
	if !manifestType(Type(ft)) {
		bad("flagType", "flagType must be boolean, string, integer, float or object")
		return err
	}
	def.Type = Type(ft)
	dv, has := obj["defaultValue"]
	if !has {
		bad("defaultValue", "defaultValue is required")
		return err
	}
	if !matchesType(def.Type, dv) {
		bad("defaultValue", "defaultValue is %s, which does not match flagType %s", valueType(dv), string(def.Type))
		return err
	}
	def.Default, def.HasDefault = dv, true
	return nil
}

// manifestType reports whether t is a flagType of the OpenFeature manifest.
func manifestType(t Type) bool {
	return t == TypeBoolean || t == TypeString || t == TypeInteger || t == TypeFloat || t == TypeObject
}

// matchesType reports whether v is a valid manifest defaultValue for t. An integer is a JSON number with no
// fraction or exponent.
func matchesType(t Type, v any) bool {
	switch { //nolint:staticcheck // a tagged switch would need the case TypeNumber, which no manifest has
	case t == TypeBoolean:
		_, ok := v.(bool)
		return ok
	case t == TypeString:
		_, ok := v.(string)
		return ok
	case t == TypeObject:
		_, ok := v.(map[string]any)
		return ok
	case t == TypeFloat:
		_, ok := v.(json.Number)
		return ok
	case t == TypeInteger:
		n, ok := v.(json.Number)
		return ok && !strings.ContainsAny(string(n), ".eE")
	}
	return false
}
