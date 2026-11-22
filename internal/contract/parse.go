// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

package contract

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/santhosh-tekuri/jsonschema/v6/kind"
	"go.yaml.in/yaml/v3"
	"golang.org/x/text/language"
	"golang.org/x/text/message"

	"github.com/elliott-davis/lightsout/internal/pathglob"
)

const (
	tagStr = "!!str"

	schemaURL = "urn:lightsout:contract:v1alpha1"

	maxDepth    = 16
	maxNodes    = 10000
	maxIntDigit = 30
)

// plainInt is the only accepted spelling of an integer: plain decimal with no
// sign other than "-", underscores, radix prefixes or leading zeros.
var plainInt = regexp.MustCompile(`^-?(0|[1-9]\d*)$`)

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

	if len(data) > MaxFileSize {
		return fail(CodeTooLarge, "contract is %d bytes, limit is %d", len(data), MaxFileSize)
	}
	if !validEncoding(data) {
		return fail(CodeUnsafeYAML, "contracts must be UTF-8 without a byte-order mark")
	}

	root, perr := decodeNode(data)
	if perr != nil {
		perr.File = file
		return nil, []Problem{*perr}
	}

	w := &walker{}
	value, cerr := w.convert(root, 1)
	if cerr != nil {
		cerr.File = file
		return nil, []Problem{*cerr}
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

// validEncoding reports whether data is UTF-8 text with no byte-order mark
// and no NUL byte, which also rules out UTF-16 and UTF-32 input.
func validEncoding(data []byte) bool {
	for _, bom := range [][]byte{
		{0xEF, 0xBB, 0xBF},       // UTF-8
		{0xFE, 0xFF},             // UTF-16BE
		{0xFF, 0xFE},             // UTF-16LE and UTF-32LE
		{0x00, 0x00, 0xFE, 0xFF}, // UTF-32BE
	} {
		if bytes.HasPrefix(data, bom) {
			return false
		}
	}
	return !bytes.ContainsRune(data, 0) && utf8.Valid(data)
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

// decodeNode decodes exactly one YAML document into a node tree.
func decodeNode(data []byte) (*yaml.Node, *Problem) {
	syntax := func(msg string) *Problem { return &Problem{Code: CodeSyntax, Message: msg} }
	dec := yaml.NewDecoder(bytes.NewReader(data))
	var doc yaml.Node
	if err := dec.Decode(&doc); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, syntax("contract is empty")
		}
		return nil, syntax(sanitize(err.Error()))
	}
	var extra yaml.Node
	switch err := dec.Decode(&extra); {
	case err == nil:
		return nil, unsafe(&extra, "multiple YAML documents are not allowed")
	case !errors.Is(err, io.EOF):
		return nil, syntax(sanitize(err.Error()))
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) != 1 {
		return nil, syntax("unexpected YAML document structure")
	}
	return doc.Content[0], nil
}

// walker checks a node tree and converts it to plain JSON values.
type walker struct {
	nodes int
	path  []string // JSON pointer tokens of the node being converted
}

func unsafe(n *yaml.Node, format string, args ...any) *Problem {
	return &Problem{Code: CodeUnsafeYAML, Message: fmt.Sprintf("%d:%d: %s", n.Line, n.Column, fmt.Sprintf(format, args...))}
}

func (w *walker) unsafe(n *yaml.Node, format string, args ...any) *Problem {
	p := unsafe(n, format, args...)
	p.Field = pointer(w.path)
	return p
}

func (w *walker) bad(n *yaml.Node, format string, args ...any) *Problem {
	return &Problem{
		Field:   pointer(w.path),
		Code:    CodeSchema,
		Message: fmt.Sprintf("%d:%d: %s", n.Line, n.Column, fmt.Sprintf(format, args...)),
	}
}

// convert returns map[string]any, []any, string, bool, nil or json.Number.
func (w *walker) convert(n *yaml.Node, depth int) (any, *Problem) {
	w.nodes++
	if w.nodes > maxNodes {
		return nil, w.unsafe(n, "document has more than %d nodes", maxNodes)
	}
	if depth > maxDepth {
		return nil, w.unsafe(n, "document is nested deeper than %d levels", maxDepth)
	}
	if n.Anchor != "" {
		return nil, w.unsafe(n, "anchors are not allowed")
	}
	if depth == 1 && n.Kind != yaml.MappingNode {
		return nil, w.bad(n, "the top level must be a mapping")
	}

	switch n.Kind {
	case yaml.AliasNode:
		return nil, w.unsafe(n, "aliases are not allowed")
	case yaml.MappingNode:
		return w.convertMap(n, depth)
	case yaml.SequenceNode:
		if tag := n.ShortTag(); tag != "!!seq" {
			return nil, w.unsafe(n, "tag %s is not allowed", quote(tag))
		}
		out := make([]any, 0, len(n.Content))
		for i, c := range n.Content {
			w.path = append(w.path, strconv.Itoa(i))
			v, p := w.convert(c, depth+1)
			w.path = w.path[:len(w.path)-1]
			if p != nil {
				return nil, p
			}
			out = append(out, v)
		}
		return out, nil
	case yaml.ScalarNode:
		return w.convertScalar(n)
	case yaml.DocumentNode:
		return nil, w.unsafe(n, "unexpected nested document")
	default:
		return nil, w.unsafe(n, "unsupported YAML node")
	}
}

func (w *walker) convertMap(n *yaml.Node, depth int) (any, *Problem) {
	if tag := n.ShortTag(); tag != "!!map" {
		return nil, w.unsafe(n, "tag %s is not allowed", quote(tag))
	}
	out := make(map[string]any, len(n.Content)/2)
	for i := 0; i+1 < len(n.Content); i += 2 {
		k, v := n.Content[i], n.Content[i+1]
		w.nodes++
		if k.Anchor != "" {
			return nil, w.unsafe(k, "anchors are not allowed")
		}
		if k.Kind == yaml.AliasNode {
			return nil, w.unsafe(k, "aliases are not allowed")
		}
		if k.Kind != yaml.ScalarNode {
			return nil, w.unsafe(k, "mapping keys must be plain strings")
		}
		tag := k.ShortTag()
		if tag == "!!merge" || (tag == tagStr && k.Value == "<<" && k.Style == 0) {
			return nil, w.unsafe(k, "merge keys are not allowed")
		}
		if tag != tagStr {
			return nil, w.unsafe(k, "mapping key %s must be a string, quote it", quote(k.Value))
		}
		if _, dup := out[k.Value]; dup {
			return nil, w.unsafe(k, "duplicate key %s", quote(k.Value))
		}
		w.path = append(w.path, k.Value)
		val, p := w.convert(v, depth+1)
		w.path = w.path[:len(w.path)-1]
		if p != nil {
			return nil, p
		}
		out[k.Value] = val
	}
	return out, nil
}

func (w *walker) convertScalar(n *yaml.Node) (any, *Problem) {
	switch tag := n.ShortTag(); tag {
	case tagStr:
		return n.Value, nil
	case "!!null":
		return nil, nil
	case "!!bool":
		switch n.Value {
		case "true":
			return true, nil
		case "false":
			return false, nil
		}
		return nil, w.bad(n, "invalid boolean %s", quote(n.Value))
	case "!!int":
		return w.convertInt(n)
	case "!!float":
		return nil, w.bad(n, "use an integer")
	case "!!timestamp":
		return nil, w.unsafe(n, "timestamp %s is not allowed, quote the value", quote(n.Value))
	default:
		return nil, w.unsafe(n, "tag %s is not allowed, quote the value", quote(tag))
	}
}

func (w *walker) convertInt(n *yaml.Node) (any, *Problem) {
	if !plainInt.MatchString(n.Value) {
		return nil, w.bad(n, "write integers in plain decimal")
	}
	if len(strings.TrimPrefix(n.Value, "-")) > maxIntDigit {
		return nil, w.bad(n, "integer has more than %d digits", maxIntDigit)
	}
	return json.Number(n.Value), nil
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
func pointer(parts []string) string {
	var b strings.Builder
	for _, s := range parts {
		b.WriteByte('/')
		b.WriteString(display(strings.NewReplacer("~", "~0", "/", "~1").Replace(s), maxFieldLen))
	}
	return b.String()
}

// sanitize makes untrusted message text single-line and bounded.
func sanitize(s string) string {
	return display(s, maxMessageLen)
}
