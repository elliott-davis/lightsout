// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

// Package codeowners parses CODEOWNERS at a trusted revision, resolves who owns each path, and implements the
// owner roles of [authz.RoleSource] (CON-2, SEC-10, NFR-5).
//
// The semantics are GitHub's, made fail closed. GitHub skips a line it cannot parse, but skipping one can silently
// change who owns what, so any syntax error here makes the whole file invalid: [Parse] returns a [*ParseError]
// and a [RoleSource] without a file denies everything. The last matching line wins, and a line with no owners makes
// its paths explicitly unowned.
//
// Ownership needs write access, as on GitHub: an owner without it is ignored. [RoleSource.HasRole] therefore
// reads the actor's repository permission, and for a team also that the team is visible (GitHub ignores secret
// teams), the team's repository permission and that the team's org owns the repository.
//
// Some forms GitHub accepts are refused here, because their meaning is undocumented or differs between
// implementations, and each makes the whole file invalid: "foo**" (a "**" that is not a whole segment), "{}"
// (braces), any backslash escape (a leading "\#", "\ ", "\!", "\*" and so on), "!" negation and "[ ]" ranges.
// A file must be under [MaxFileBytes] bytes and stay within the rule, pattern and owner limits ([MaxRules] and the
// constants beside it), so resolving a path has a documented work bound.
//
// Matching is case-sensitive on paths, as on GitHub's case-sensitive server, and case-insensitive on logins and
// team names, as on GitHub. Patterns are printable ASCII (the pathglob rule). A trailing "/" means a directory and
// everything below it, a trailing "/**" means strict descendants only, and a last segment of exactly "*" matches
// that level only. An email owner can't be tied to a verified account here, so it is recorded and reported as a
// warning but never grants ownership.
//
// The file is read only through a forge tree at a full commit SHA ([Load]), so a symlinked CODEOWNERS is an error
// and the revision is pinned. Callers pass the trusted revision, never the proposal's own file (CON-2).
package codeowners
