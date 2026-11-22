// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

// Package pathglob implements the anchored path globs used by contracts
// (CON-7, CON-12).
//
// A pattern is a sequence of segments separated by "/". A segment is a literal,
// a glob using "*" (any run of characters within one segment) and "?" (exactly
// one rune), or "**" (zero or more whole segments). Patterns are anchored and
// case-sensitive. Rebasing a pattern to repository coordinates prefixes it with
// literal directory segments, even if the directory name contains wildcard
// characters.
//
// [Contains] is a conservative containment proof: it returns true only when it
// can prove that one pattern is contained in another, and false otherwise.
package pathglob
