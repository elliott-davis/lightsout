// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

package contract

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/santhosh-tekuri/jsonschema/v6/kind"
	"golang.org/x/text/language"
	"golang.org/x/text/message"

	"github.com/elliott-davis/lightsout/internal/pathglob"
	"github.com/elliott-davis/lightsout/internal/yamlsafe"
)

const (
	schemaURL = "urn:lightsout:contract:v1alpha1"

	maxDepth = 16
	maxNodes = 10000
)

// yamlLimits bound the YAML pipeline for a contract file.
func yamlLimits() yamlsafe.Limits {
	return yamlsafe.Limits{MaxBytes: MaxFileSize, MaxDepth: maxDepth, MaxNodes: maxNodes, Name: "contract"}
}

// Parser parses and validates contract files. It is safe for concurrent use.
type Parser struct {
	schema  *jsonschema.Schema
	printer *message.Printer
}

// noLoader refuses every external reference, so validation never reads files
// or the network.
type noLoader struct{}

func (noLoader) Load(url string) (any, error) {
	return nil, fmt.Errorf("external schema reference %q is not allowed", url)
}

// NewParser compiles the embedded schema.
func NewParser() (*Parser, error) {
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(schemaJSON))
	if err != nil {
		return nil, fmt.Errorf("decode embedded contract schema: %w", err)
	}
	c := jsonschema.NewCompiler()
	c.UseLoader(noLoader{})
	if err = c.AddResource(schemaURL, doc); err != nil {
		return nil, fmt.Errorf("add contract schema: %w", err)
	}
	sch, err := c.Compile(schemaURL)
	if err != nil {
		return nil, fmt.Errorf("compile contract schema: %w", err)
	}
	return &Parser{schema: sch, printer: message.NewPrinter(language.English)}, nil
}

// filePath returns the repo-relative path of the contract file in dir.
func filePath(dir string) string {
	if dir == "" {
		return FileName
	}
	return dir + "/" + FileName
}

// Parse parses one contract file found in dir, a repo-relative slash path
// ("" for the repo root). dir is caller input, not contract content: an
// invalid dir returns a plain error wrapping pathglob.ErrInvalidPath. Any
// problem with the contract itself returns a *ValidationError.
func (p *Parser) Parse(dir string, data []byte) (*Contract, error) {
	if dir != "" {
		if err := pathglob.ValidatePath(dir); err != nil {
			return nil, fmt.Errorf("parse contract: invalid directory: %w", err)
		}
	}
	c, problems := p.parse(dir, data)
	if len(problems) > 0 {
		return nil, newValidationError(problems)
	}
	return c, nil
}

// parse is Parse for a dir that is already valid. It returns the problems
// uncapped and unescaped, so that Load can cap them once across all files.
func (p *Parser) parse(dir string, data []byte) (*Contract, []Problem) {
	file := filePath(dir)
	fail := func(code Code, format string, args ...any) (*Contract, []Problem) {
		return nil, []Problem{{File: file, Code: code, Message: fmt.Sprintf(format, args...)}}
	}

	value, yerr := yamlsafe.Decode(data, yamlLimits())
	if yerr != nil {
		return nil, []Problem{{File: file, Field: yerr.Path, Code: Code(yerr.Code), Message: yerr.Message}}
	}

	if verr := p.schema.Validate(value); verr != nil {
		var ve *jsonschema.ValidationError
		if !errors.As(verr, &ve) {
			return fail(CodeSchema, "%s", sanitize(verr.Error()))
		}
		return nil, p.problems(file, ve)
	}

	encoded, err := json.Marshal(value)
	if err != nil {
		return fail(CodeSchema, "re-encode contract: %s", sanitize(err.Error()))
	}
	dec := json.NewDecoder(bytes.NewReader(encoded))
	dec.DisallowUnknownFields()
	dec.UseNumber()
	var c Contract
	if derr := dec.Decode(&c); derr != nil {
		return fail(CodeSchema, "decode contract: %s", sanitize(derr.Error()))
	}
	if ps := checkPatterns(file, dir, &c); len(ps) > 0 {
		return nil, ps
	}
	c.Dir = dir
	if data, err := canonicalJSON(&c); err == nil {
		c.digest, c.digested = sha256.Sum256(data), true
	}
	return &c, nil
}

// checkPatterns compiles every path pattern and anchors it at dir, so a
// contract the glob compiler would reject never loads (CON-1, CON-11).
func checkPatterns(file, dir string, c *Contract) []Problem {
	deref := func(l *[]string) []string {
		if l == nil {
			return nil
		}
		return *l
	}
	lists := []struct {
		name string
		pats []string
	}{
		{"writable", deref(c.Paths.Writable)},
		{"readOnly", c.Paths.ReadOnly},
		{"forbidden", c.Paths.Forbidden},
		{"sensitive", c.Paths.Sensitive},
		{"generated", deref(c.Paths.Generated)},
	}
	var out []Problem
	for _, l := range lists {
		for i, pat := range l.pats {
			g, err := pathglob.Compile(pat)
			if err == nil {
				_, err = g.Rebase(dir)
			}
			if err != nil {
				out = append(out, Problem{
					File:    file,
					Field:   pointer([]string{"paths", l.name, strconv.Itoa(i)}),
					Code:    CodeInvalidPattern,
					Message: sanitize(err.Error()),
				})
			}
		}
	}
	return out
}

// problems flattens the leaves of a schema error into Problems.
func (p *Parser) problems(file string, verr *jsonschema.ValidationError) []Problem {
	var out []Problem
	seen := map[Problem]bool{}
	add := func(pr Problem) {
		if !seen[pr] {
			seen[pr] = true
			out = append(out, pr)
		}
	}
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
				add(Problem{
					File:    file,
					Field:   pointer(append(append([]string(nil), e.InstanceLocation...), prop)),
					Code:    CodeUnknownField,
					Message: "unknown field " + quote(prop),
				})
			}
			return
		}
		add(Problem{
			File:    file,
			Field:   pointer(e.InstanceLocation),
			Code:    CodeSchema,
			Message: sanitize(e.ErrorKind.LocalizedString(p.printer)),
		})
	}
	walk(verr)
	return out
}

// pointer renders an RFC 6901 JSON pointer. Tokens come from untrusted keys,
// so each is made printable and bounded.
func pointer(parts []string) string { return yamlsafe.Pointer(parts) }

// sanitize makes untrusted message text single-line and bounded.
func sanitize(s string) string { return yamlsafe.Sanitize(s) }
