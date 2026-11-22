// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

package yamlsafe

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	maxFieldLen   = 200 // bytes of one pointer token
	maxMessageLen = 300 // bytes of message text built from untrusted input
	maxQuoteLen   = 100
)

// Escape makes untrusted text safe to print on one line. It escapes every
// rune that is not printable or is a format character (so newlines, escape
// sequences and bidi overrides cannot forge output) and a literal backslash
// (so the text \u000a in input cannot pass for an escaped newline) and '#'
// (so no "##[command" can reach a CI log). It returns
// at most limit bytes including the ellipsis that marks a cut, which falls on a
// rune boundary.
func Escape(s string, limit int) string {
	const marker = "…"
	var b strings.Builder
	cut := 0 // longest prefix of b at a piece boundary that leaves room for the marker
	for s != "" {
		r, size := utf8.DecodeRuneInString(s)
		var piece string
		switch {
		case r == utf8.RuneError && size == 1:
			piece = fmt.Sprintf(`\x%02x`, s[0])
		case r == '\\':
			piece = `\\`
		case r == '#':
			// GitHub's legacy runner parser finds "##[" anywhere in a line.
			piece = `\x23`
		case !unicode.IsPrint(r) || unicode.Is(unicode.Cf, r):
			if r <= 0xffff {
				piece = fmt.Sprintf(`\u%04x`, r)
			} else {
				piece = fmt.Sprintf(`\U%08x`, r)
			}
		default:
			piece = s[:size]
		}
		b.WriteString(piece)
		s = s[size:]
		if b.Len()+len(marker) <= limit {
			cut = b.Len()
		}
		if b.Len() > limit {
			return b.String()[:cut] + marker
		}
	}
	return b.String()
}

// Quote renders untrusted text safely and bounded.
func Quote(s string) string {
	if len(s) > maxQuoteLen {
		s = strings.ToValidUTF8(s[:maxQuoteLen], "") + "..."
	}
	return strings.ReplaceAll(fmt.Sprintf("%q", s), "#", `\x23`)
}

// Pointer renders an RFC 6901 JSON pointer. Tokens come from untrusted keys,
// so each is made printable and bounded.
func Pointer(parts []string) string {
	var b strings.Builder
	for _, s := range parts {
		b.WriteByte('/')
		b.WriteString(Escape(strings.NewReplacer("~", "~0", "/", "~1").Replace(s), maxFieldLen))
	}
	return b.String()
}

// Sanitize makes untrusted message text single-line and bounded.
func Sanitize(s string) string {
	return Escape(s, maxMessageLen)
}
