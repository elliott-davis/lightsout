// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

// Package yamlsafe converts untrusted YAML to plain JSON values under hard
// limits. It is the first stage of every strict config parser in the factory
// (contracts, install config): the caller validates the result against its own
// schema and decodes it into its own types.
//
// Decode caps the byte size before decoding. It then rejects anything that is
// not UTF-8 without a byte-order mark, more than one document, anchors,
// aliases, merge keys, custom tags, non-string and duplicate keys, timestamps,
// floats and integers not written in plain decimal, and documents nested
// deeper or larger than the limits. Text taken from the input in an [Error]
// is escaped, bounded and safe to print on one line (SEC-1).
package yamlsafe

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

	"go.yaml.in/yaml/v3"
)

const (
	tagStr = "!!str"

	maxIntDigit = 30
)

// Code classifies an [Error].
type Code string

// Error codes. Their values equal the contract package's problem codes of the
// same meaning.
const (
	CodeSyntax     Code = "syntax"
	CodeUnsafeYAML Code = "unsafe-yaml"
	CodeTooLarge   Code = "too-large"
	// CodeSchema marks a value the conversion cannot represent as JSON: a
	// top level that is not a mapping, a float, a bad boolean, or an integer
	// not written in plain decimal.
	CodeSchema Code = "schema"
)

// Limits bound one decode.
type Limits struct {
	// MaxBytes is the largest input in bytes. It is checked before anything is decoded.
	MaxBytes int
	// MaxDepth is the deepest nesting, counting the top-level mapping as 1.
	MaxDepth int
	// MaxNodes is the most YAML nodes, mapping keys included.
	MaxNodes int
	// Name is what the input is called in messages, in the singular: "contract".
	Name string
}

// Error is why Decode rejected its input.
type Error struct {
	Code    Code
	Message string // escaped and bounded
	Path    string // JSON pointer of the offending value, escaped; empty when the whole input is at fault
}

// Error renders the code and message.
func (e *Error) Error() string { return fmt.Sprintf("[%s] %s", e.Code, e.Message) }

// plainInt is the only accepted spelling of an integer: plain decimal with no
// sign other than "-", underscores, radix prefixes or leading zeros.
var plainInt = regexp.MustCompile(`^-?(0|[1-9]\d*)$`)

// Decode converts one YAML document to map[string]any, []any, string, bool,
// nil or json.Number. The top level must be a mapping.
func Decode(data []byte, lim Limits) (any, *Error) {
	if len(data) > lim.MaxBytes {
		return nil, &Error{Code: CodeTooLarge, Message: fmt.Sprintf("%s is %d bytes, limit is %d", lim.Name, len(data), lim.MaxBytes)}
	}
	if !validEncoding(data) {
		return nil, &Error{Code: CodeUnsafeYAML, Message: lim.Name + "s must be UTF-8 without a byte-order mark"}
	}
	root, err := decodeNode(data, lim.Name)
	if err != nil {
		return nil, err
	}
	w := &walker{lim: lim}
	return w.convert(root, 1)
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

// decodeNode decodes exactly one YAML document into a node tree.
func decodeNode(data []byte, name string) (*yaml.Node, *Error) {
	syntax := func(msg string) *Error { return &Error{Code: CodeSyntax, Message: msg} }
	dec := yaml.NewDecoder(bytes.NewReader(data))
	var doc yaml.Node
	if err := dec.Decode(&doc); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, syntax(name + " is empty")
		}
		return nil, syntax(Sanitize(err.Error()))
	}
	var extra yaml.Node
	switch err := dec.Decode(&extra); {
	case err == nil:
		return nil, unsafe(&extra, "multiple YAML documents are not allowed")
	case !errors.Is(err, io.EOF):
		return nil, syntax(Sanitize(err.Error()))
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) != 1 {
		return nil, syntax("unexpected YAML document structure")
	}
	return doc.Content[0], nil
}

// walker checks a node tree and converts it to plain JSON values.
type walker struct {
	lim   Limits
	nodes int
	path  []string // JSON pointer tokens of the node being converted
}

func unsafe(n *yaml.Node, format string, args ...any) *Error {
	return &Error{Code: CodeUnsafeYAML, Message: fmt.Sprintf("%d:%d: %s", n.Line, n.Column, fmt.Sprintf(format, args...))}
}

func (w *walker) unsafe(n *yaml.Node, format string, args ...any) *Error {
	p := unsafe(n, format, args...)
	p.Path = Pointer(w.path)
	return p
}

func (w *walker) bad(n *yaml.Node, format string, args ...any) *Error {
	return &Error{
		Path:    Pointer(w.path),
		Code:    CodeSchema,
		Message: fmt.Sprintf("%d:%d: %s", n.Line, n.Column, fmt.Sprintf(format, args...)),
	}
}

// convert returns map[string]any, []any, string, bool, nil or json.Number.
func (w *walker) convert(n *yaml.Node, depth int) (any, *Error) {
	w.nodes++
	if w.nodes > w.lim.MaxNodes {
		return nil, w.unsafe(n, "document has more than %d nodes", w.lim.MaxNodes)
	}
	if depth > w.lim.MaxDepth {
		return nil, w.unsafe(n, "document is nested deeper than %d levels", w.lim.MaxDepth)
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
			return nil, w.unsafe(n, "tag %s is not allowed", Quote(tag))
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

func (w *walker) convertMap(n *yaml.Node, depth int) (any, *Error) {
	if tag := n.ShortTag(); tag != "!!map" {
		return nil, w.unsafe(n, "tag %s is not allowed", Quote(tag))
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
			return nil, w.unsafe(k, "mapping key %s must be a string, quote it", Quote(k.Value))
		}
		if _, dup := out[k.Value]; dup {
			return nil, w.unsafe(k, "duplicate key %s", Quote(k.Value))
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

func (w *walker) convertScalar(n *yaml.Node) (any, *Error) {
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
		return nil, w.bad(n, "invalid boolean %s", Quote(n.Value))
	case "!!int":
		return w.convertInt(n)
	case "!!float":
		return nil, w.bad(n, "use an integer")
	case "!!timestamp":
		return nil, w.unsafe(n, "timestamp %s is not allowed, quote the value", Quote(n.Value))
	default:
		return nil, w.unsafe(n, "tag %s is not allowed, quote the value", Quote(tag))
	}
}

func (w *walker) convertInt(n *yaml.Node) (any, *Error) {
	if !plainInt.MatchString(n.Value) {
		return nil, w.bad(n, "write integers in plain decimal")
	}
	if len(strings.TrimPrefix(n.Value, "-")) > maxIntDigit {
		return nil, w.bad(n, "integer has more than %d digits", maxIntDigit)
	}
	return json.Number(n.Value), nil
}
