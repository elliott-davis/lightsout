// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

package fake

import "strings"

// ignorable reports the code points HFS+ ignores when it compares names, as git's is_hfs_dotgit does.
func ignorable(r rune) bool {
	return (r >= 0x200c && r <= 0x200f) || (r >= 0x202a && r <= 0x202e) || (r >= 0x206a && r <= 0x206f) || r == 0xfeff
}

// canonSeg folds a path segment the way case-insensitive, NTFS and HFS+ file systems do: it drops HFS-ignorable
// code points, cuts an NTFS stream suffix, trims trailing dots and spaces, and lowercases.
func canonSeg(seg string) string {
	s := strings.Map(func(r rune) rune {
		if ignorable(r) {
			return -1
		}
		return r
	}, seg)
	if i := strings.IndexByte(s, ':'); i >= 0 {
		s = s[:i]
	}
	return strings.ToLower(strings.TrimRight(s, ". "))
}

// segIs reports whether seg is name on any of those file systems, or its 8.3 short form.
func segIs(seg, name, short string) bool {
	c := canonSeg(seg)
	return c == name || c == short
}

// hasDotGit reports whether any segment of p names a .git directory on some file system, mirroring git's
// is_ntfs_dotgit and is_hfs_dotgit checks.
func hasDotGit(p string) bool {
	for seg := range strings.SplitSeq(p, "/") {
		if segIs(seg, ".git", "git~1") {
			return true
		}
	}
	return false
}

// isWorkflowPath reports whether p is .github/workflows or below it, under the same equivalences.
func isWorkflowPath(p string) bool {
	segs := strings.Split(p, "/")
	return len(segs) >= 2 && segIs(segs[0], ".github", "github~1") && segIs(segs[1], "workflows", "workfl~1")
}
