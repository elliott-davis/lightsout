// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

package holdout

import (
	"strings"
	"unicode"

	"golang.org/x/text/cases"
	"golang.org/x/text/unicode/norm"

	"github.com/elliott-davis/lightsout/internal/pathglob"
)

// validFilePath validates a private file path like a repository path ([pathglob.ValidatePath]) and additionally
// rejects wildcard characters, backslashes, control and invisible characters, non-NFC text, colons, trailing dots or
// spaces, 8.3 short names and any ".git" component (so a bundle cannot plant repository metadata when materialized), since a file is a literal path.
func validFilePath(p string) error {
	if err := pathglob.ValidatePath(p); err != nil {
		return err
	}
	if strings.ContainsAny(p, `*?[]{}\`) {
		return invalidf("path has a wildcard or backslash")
	}
	if !norm.NFC.IsNormalString(p) {
		return invalidf("path is not NFC-normalized")
	}
	for _, seg := range strings.Split(p, "/") {
		if err := validSegment(seg); err != nil {
			return err
		}
	}
	for _, r := range p {
		if r < 0x20 || r == 0x7f {
			return invalidf("path has a control character")
		}
		if invisible(r) {
			return invalidf("path has an invisible code point")
		}
	}
	return nil
}

// validSegment rejects names that a filesystem may treat as another name: ".git" in any case, a trailing dot or
// space (Windows drops them), an 8.3 short name such as "GIT~1", and an NTFS stream separator.
func validSegment(seg string) error {
	switch {
	case strings.EqualFold(seg, ".git"):
		return invalidf("path has a .git component")
	case strings.HasSuffix(seg, ".") || strings.HasSuffix(seg, " "):
		return invalidf("path component ends with a dot or space")
	case strings.Contains(seg, ":"):
		return invalidf("path component has a colon")
	}
	for i := range len(seg) - 1 {
		if seg[i] == '~' && seg[i+1] >= '0' && seg[i+1] <= '9' {
			return invalidf("path component looks like a short name")
		}
	}
	return nil
}

// invisible reports Default_Ignorable_Code_Point characters: format characters (zero-width joiners and the like),
// variation selectors and the other default-ignorable code points, which render as nothing and so can disguise a
// name such as ".git".
func invisible(r rune) bool {
	return unicode.Is(unicode.Cf, r) || unicode.Is(unicode.Variation_Selector, r) ||
		unicode.Is(unicode.Other_Default_Ignorable_Code_Point, r)
}

// foldPath is the form under which two paths collide on a case-insensitive or normalizing filesystem.
func foldPath(p string) string { return cases.Fold().String(norm.NFC.String(p)) }

// checkPathCollisions refuses duplicate paths, paths that differ only by case or Unicode normalization, and a path
// that is both a file and a directory prefix of another.
func checkPathCollisions(paths []string) error {
	files := make(map[string]bool, len(paths))
	dirs := map[string]bool{}
	for _, p := range paths {
		f := foldPath(p)
		if files[f] {
			return invalidf("duplicate or colliding path")
		}
		files[f] = true
		for i := range len(f) {
			if f[i] == '/' {
				dirs[f[:i]] = true
			}
		}
	}
	for d := range dirs {
		if files[d] {
			return invalidf("path is both a file and a directory")
		}
	}
	return nil
}
