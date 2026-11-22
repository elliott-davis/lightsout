// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

package contract

import (
	"fmt"
	"strings"
	"testing"
)

// The hostile shapes found in review. Each builds contracts by hand, so it also
// works as a regression test: the outcome must be success or a bounded failure.

func handSet(tb testing.TB, cs ...*Contract) *Set {
	tb.Helper()
	for _, c := range cs {
		c.APIVersion, c.Kind = APIVersion, Kind
	}
	set, err := NewSet(rev40, cs...)
	if err != nil {
		tb.Fatal(err)
	}
	return set
}

func nPatterns(n int, f func(i int) string) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = f(i)
	}
	return out
}

func writableList(p ...string) *[]string { return &p }

// shapeDeepForbidden is a 32-deep chain d/d/..., each level with 117 forbidden
// patterns "**/*" + a x500 + bNNN. It returns the set and two deep paths: one
// with a long final segment and one split into segments of at most 255 bytes.
func shapeDeepForbidden(tb testing.TB) (set *Set, long, split string) {
	tb.Helper()
	var cs []*Contract
	var dirs []string
	for i := range MaxStackDepth {
		c := &Contract{Dir: strings.Join(dirs, "/"), Paths: Paths{
			Forbidden: nPatterns(117, func(j int) string { return fmt.Sprintf("**/*%sb%03d", strings.Repeat("a", 500), j) }),
		}}
		if i == 0 {
			c.Paths.Writable = writableList("**")
		}
		cs = append(cs, c)
		dirs = append(dirs, "d")
	}
	prefix := strings.Repeat("d/", MaxStackDepth-1)
	var parts []string
	for range 15 {
		parts = append(parts, "A"+strings.Repeat("a", 250))
	}
	return handSet(tb, cs...), prefix + "A" + strings.Repeat("a", 3900), prefix + strings.Join(parts, "/")
}

// shapeLongForbiddenRoot is a root with 119 forbidden "*" + a x506 + NNNx.
func shapeLongForbiddenRoot(tb testing.TB) *Set {
	tb.Helper()
	return handSet(tb, &Contract{Paths: Paths{
		Writable:  writableList("**"),
		Forbidden: nPatterns(119, func(j int) string { return fmt.Sprintf("*%s%03dx", strings.Repeat("a", 506), j) }),
	}})
}

// longSegmentPaths returns n distinct paths with one 250-byte segment.
func longSegmentPaths(n int) []string {
	return nPatterns(n, func(i int) string { return fmt.Sprintf("%s%05d", strings.Repeat("a", 245), i) })
}

// shapeWritableReadOnly is a root with 246 writable "**/*" + a x245 + NNNb and
// 31 nested children with 125 literal readOnly patterns of a x500 + NNN.
func shapeWritableReadOnly(tb testing.TB) *Set {
	tb.Helper()
	cs := []*Contract{{Paths: Paths{Writable: writableList(nPatterns(246, func(j int) string {
		return fmt.Sprintf("**/*%s%03db", strings.Repeat("a", 245), j)
	})...)}}}
	dir := ""
	for range 31 {
		dir = strings.TrimPrefix(dir+"/d", "/")
		cs = append(cs, &Contract{Dir: dir, Paths: Paths{
			ReadOnly: nPatterns(125, func(j int) string { return fmt.Sprintf("%s%03d", strings.Repeat("a", 500), j) }),
		}})
	}
	return handSet(tb, cs...)
}

// shapeSiblings is a root and 100 sibling contracts with 115 forbidden "**/*a..." each.
func shapeSiblings(tb testing.TB) *Set {
	tb.Helper()
	cs := []*Contract{{Paths: Paths{Writable: writableList("**")}}}
	for i := range 100 {
		cs = append(cs, &Contract{Dir: fmt.Sprintf("s%03d", i), Paths: Paths{
			Forbidden: nPatterns(115, func(j int) string { return fmt.Sprintf("**/*%s%03d", strings.Repeat("a", 490), j) }),
		}})
	}
	return handSet(tb, cs...)
}

// shapeWitness: the root's writable list is 115 "c/*" + a x250 + bNNN then
// "c/?*"; the child at c has 115 writable "?*" + a x500 + NNN.
func shapeWitness(tb testing.TB) *Set {
	tb.Helper()
	root := nPatterns(115, func(j int) string { return fmt.Sprintf("c/*%sb%03d", strings.Repeat("a", 250), j) })
	root = append(root, "c/?*")
	return handSet(tb,
		&Contract{Paths: Paths{Writable: writableList(root...)}},
		&Contract{Dir: "c", Paths: Paths{Writable: writableList(nPatterns(115, func(j int) string {
			return fmt.Sprintf("?*%s%03d", strings.Repeat("a", 500), j)
		})...)}},
	)
}

// shapeWitnessReadOnly: root writable "**/*x"; the child has 99 readOnly
// "**/*a..." patterns, each a loosening that needs a witness.
func shapeWitnessReadOnly(tb testing.TB) *Set {
	tb.Helper()
	return handSet(tb,
		&Contract{Paths: Paths{Writable: writableList("**/*x")}},
		&Contract{Dir: "c", Paths: Paths{ReadOnly: nPatterns(99, func(j int) string {
			return fmt.Sprintf("**/*%s%03d", strings.Repeat("a", 200), j)
		})}},
	)
}
