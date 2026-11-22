// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

package switches

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/elliott-davis/lightsout/internal/yamlsafe"
)

// parseError is a strict-JSON failure at a place in the document.
type parseError struct {
	code Code
	path []string // JSON pointer tokens, unescaped
	msg  string   // static text
}

func (e *parseError) Error() string { return e.msg }

// parseJSON decodes one JSON value into map[string]any, []any, string, bool, nil or json.Number. Unlike
// encoding/json it rejects duplicate object keys at any level, invalid UTF-8, nesting deeper than maxDepth and
// anything after the top-level value. It reads tokens, so no value is built before its depth is checked.
func parseJSON(data []byte, maxDepth int) (any, *parseError) {
	if !utf8.Valid(data) {
		return nil, &parseError{code: CodeEncoding, msg: "file is not valid UTF-8"}
	}
	if bytes.HasPrefix(data, []byte{0xEF, 0xBB, 0xBF}) {
		return nil, &parseError{code: CodeEncoding, msg: "file starts with a byte-order mark"}
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	p := &jsonParser{dec: dec, maxDepth: maxDepth}
	tok, err := dec.Token()
	if err != nil {
		return nil, syntax(nil, err)
	}
	v, perr := p.value(tok, 1)
	if perr != nil {
		return nil, perr
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, &parseError{code: CodeSyntax, msg: "data after the top-level value"}
	}
	return v, nil
}

type jsonParser struct {
	dec      *json.Decoder
	maxDepth int
	path     []string
}

func syntax(path []string, err error) *parseError {
	msg := "invalid JSON"
	var se *json.SyntaxError
	if errors.As(err, &se) {
		msg = fmt.Sprintf("invalid JSON at byte %d", se.Offset)
	}
	return &parseError{code: CodeSyntax, path: append([]string(nil), path...), msg: msg}
}

func (p *jsonParser) fail(code Code, msg string) *parseError {
	return &parseError{code: code, path: append([]string(nil), p.path...), msg: msg}
}

func (p *jsonParser) value(tok json.Token, depth int) (any, *parseError) {
	d, ok := tok.(json.Delim)
	if !ok {
		return tok, nil // string, json.Number, bool or nil
	}
	if depth > p.maxDepth {
		return nil, p.fail(CodeTooDeep, fmt.Sprintf("nesting is deeper than %d", p.maxDepth))
	}
	if d == '{' {
		return p.object(depth)
	}
	return p.array(depth)
}

func (p *jsonParser) object(depth int) (any, *parseError) {
	out := map[string]any{}
	for p.dec.More() {
		kt, err := p.dec.Token()
		if err != nil {
			return nil, syntax(p.path, err)
		}
		key, _ := kt.(string) // the decoder only yields strings here
		if _, dup := out[key]; dup {
			return nil, &parseError{code: CodeDuplicateKey, path: append(append([]string(nil), p.path...), key), msg: "duplicate object key"}
		}
		vt, err := p.dec.Token()
		if err != nil {
			return nil, syntax(p.path, err)
		}
		p.path = append(p.path, key)
		v, perr := p.value(vt, depth+1)
		if perr != nil {
			return nil, perr
		}
		p.path = p.path[:len(p.path)-1]
		out[key] = v
	}
	if _, err := p.dec.Token(); err != nil { // the closing brace
		return nil, syntax(p.path, err)
	}
	return out, nil
}

func (p *jsonParser) array(depth int) (any, *parseError) {
	out := []any{}
	for i := 0; p.dec.More(); i++ {
		vt, err := p.dec.Token()
		if err != nil {
			return nil, syntax(p.path, err)
		}
		p.path = append(p.path, strconv.Itoa(i))
		v, perr := p.value(vt, depth+1)
		if perr != nil {
			return nil, perr
		}
		p.path = p.path[:len(p.path)-1]
		out = append(out, v)
	}
	if _, err := p.dec.Token(); err != nil { // the closing bracket
		return nil, syntax(p.path, err)
	}
	return out, nil
}

// escapeLimit bounds one escaped repository-supplied string.
const escapeLimit = 200

// escape makes untrusted text safe for one line of a Markdown table, a GitHub check and a CI log. It escapes
// everything yamlsafe.Escape does (control and format characters, invalid UTF-8, backslash, '#'), then
// [markdownSafe]. Backslashes are already doubled, so an escaped form cannot be forged by input that contains it.
func escape(s string) string { return markdownSafe(yamlsafe.Escape(s, escapeLimit)) }

// markdownSafe escapes what GitHub renders specially in text that is already printable: mentions, HTML, links,
// code spans, tables, the "::" of a workflow command, and the autolinks "://" and "www.".
func markdownSafe(s string) string {
	s = strings.NewReplacer(
		"@", `\x40`, "<", `\x3c`, ">", `\x3e`, "&", `\x26`, "`", `\x60`, "[", `\x5b`, "]", `\x5d`,
		"(", `\x28`, ")", `\x29`, "|", `\x7c`, "*", `\x2a`, "~", `\x7e`, "!", `\x21`, "::", `\x3a\x3a`,
		"://", `:\/\/`,
	).Replace(s)
	return breakWWW(s)
}

// breakWWW turns every "www." (ASCII, any case) into `www\.`, so GitHub does not autolink it. It compares bytes of s
// itself: lower-casing first would change the byte offsets of text such as "İ" or "Ⱥ", and so the slices taken.
func breakWWW(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); {
		if i+4 <= len(s) && asciiFoldEqual(s[i:i+4], "www.") {
			b.WriteString(s[i : i+3])
			b.WriteString(`\.`)
			i += 4
			continue
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}

// asciiFoldEqual compares two strings of ASCII letters and punctuation, ignoring ASCII case. want is lower case.
func asciiFoldEqual(s, want string) bool {
	for i := range len(want) {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		if c != want[i] {
			return false
		}
	}
	return true
}

// pointer renders JSON pointer tokens, escaped for display. A "~" in a token is escaped as text, so "~1" can only
// be the escape of "/".
func pointer(parts []string) string {
	if len(parts) == 0 {
		return ""
	}
	var b strings.Builder
	for _, s := range parts {
		b.WriteByte('/')
		b.WriteString(strings.ReplaceAll(escape(s), "/", "~1"))
	}
	return b.String()
}
