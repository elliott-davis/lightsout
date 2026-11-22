// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

package install

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"slices"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/santhosh-tekuri/jsonschema/v6/kind"
	"golang.org/x/text/language"
	"golang.org/x/text/message"

	"github.com/elliott-davis/lightsout/internal/yamlsafe"
)

const schemaURL = "urn:lightsout:install:v1alpha1"

// Limits of the YAML pipeline for an install file. The size cap is checked before decoding.
const (
	// MaxFileSize is the largest accepted install file, in bytes.
	MaxFileSize = 2 << 20
	maxDepth    = 16
	maxNodes    = 100_000
)

func yamlLimits() yamlsafe.Limits {
	return yamlsafe.Limits{MaxBytes: MaxFileSize, MaxDepth: maxDepth, MaxNodes: maxNodes, Name: "install config"}
}

//go:embed schema/v1alpha1.json
var schemaJSON []byte

// SchemaJSON returns a copy of the embedded v1alpha1 JSON Schema.
func SchemaJSON() []byte { return slices.Clone(schemaJSON) }

// noLoader refuses every external reference, so validation never reads files or the network.
type noLoader struct{}

func (noLoader) Load(url string) (any, error) {
	return nil, fmt.Errorf("external schema reference %q is not allowed", url)
}

func compileSchema() (*jsonschema.Schema, error) {
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(schemaJSON))
	if err != nil {
		return nil, fmt.Errorf("decode embedded install schema: %w", err)
	}
	c := jsonschema.NewCompiler()
	c.UseLoader(noLoader{})
	if err = c.AddResource(schemaURL, doc); err != nil {
		return nil, fmt.Errorf("add install schema: %w", err)
	}
	sch, err := c.Compile(schemaURL)
	if err != nil {
		return nil, fmt.Errorf("compile install schema: %w", err)
	}
	return sch, nil
}

// Parse parses and validates an install file. Untrusted bytes go through yamlsafe, then the schema, then a strict
// decode, then the semantic rules. Any problem returns a [*ValidationError] and no Config. The returned Config has no
// install revision: see [Config.WithRevision].
func Parse(data []byte) (*Config, error) {
	sch, err := compileSchema()
	if err != nil {
		return nil, fmt.Errorf("parse install config: %w", err)
	}
	value, yerr := yamlsafe.Decode(data, yamlLimits())
	if yerr != nil {
		return nil, newValidationError([]Problem{{Field: yerr.Path, Code: Code(yerr.Code), Message: yerr.Message}})
	}
	if verr := sch.Validate(value); verr != nil {
		var ve *jsonschema.ValidationError
		if !errors.As(verr, &ve) {
			return nil, newValidationError([]Problem{{Code: CodeSchema, Message: yamlsafe.Sanitize(verr.Error())}})
		}
		return nil, newValidationError(schemaProblems(ve))
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, newValidationError([]Problem{{Code: CodeSchema, Message: yamlsafe.Sanitize("re-encode install config: " + err.Error())}})
	}
	dec := json.NewDecoder(bytes.NewReader(encoded))
	dec.DisallowUnknownFields()
	var doc document
	if derr := dec.Decode(&doc); derr != nil {
		return nil, newValidationError([]Problem{{Code: CodeSchema, Message: yamlsafe.Sanitize("decode install config: " + derr.Error())}})
	}
	cfg, problems := build(&doc)
	if len(problems) > 0 {
		return nil, newValidationError(problems)
	}
	return cfg, nil
}

// schemaProblems flattens the leaves of a schema error into Problems.
func schemaProblems(verr *jsonschema.ValidationError) []Problem {
	printer := message.NewPrinter(language.English)
	var out []Problem
	var walk func(e *jsonschema.ValidationError)
	walk = func(e *jsonschema.ValidationError) {
		if len(e.Causes) > 0 {
			for _, c := range e.Causes {
				walk(c)
			}
			return
		}
		if ap, ok := e.ErrorKind.(*kind.AdditionalProperties); ok {
			for _, prop := range ap.Properties {
				out = append(out, Problem{
					Field:   yamlsafe.Pointer(append(slices.Clone(e.InstanceLocation), prop)),
					Code:    CodeUnknownField,
					Message: "unknown field " + yamlsafe.Quote(prop),
				})
			}
			return
		}
		out = append(out, Problem{
			Field:   yamlsafe.Pointer(e.InstanceLocation),
			Code:    CodeSchema,
			Message: yamlsafe.Sanitize(e.ErrorKind.LocalizedString(printer)),
		})
	}
	walk(verr)
	return out
}
