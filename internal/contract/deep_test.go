// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

package contract

import (
	"fmt"
	"strings"
	"testing"
)

// deepSet builds a chain of contracts depth levels deep, each with n distinct
// patterns of the form **/xN/** in forbidden, readOnly and sensitive. It
// returns the set and a path under the deepest contract.
func deepSet(tb testing.TB, depth, n int) (*Set, string) {
	tb.Helper()
	list := func(prefix string) []string {
		pats := make([]string, n)
		for i := range pats {
			pats[i] = fmt.Sprintf("**/%s%d/**", prefix, i)
		}
		return pats
	}
	forbidden, readOnly, sensitive := list("f"), list("r"), list("s")
	var cs []*Contract
	var segs []string
	for i := range depth {
		w := []string{"**"}
		c := &Contract{
			Dir: strings.Join(segs, "/"), APIVersion: APIVersion, Kind: Kind,
			Paths: Paths{ReadOnly: readOnly, Forbidden: forbidden, Sensitive: sensitive},
		}
		if i == 0 {
			c.Paths.Writable = &w
		}
		cs = append(cs, c)
		segs = append(segs, fmt.Sprintf("d%d", i))
	}
	set, err := NewSet(rev40, cs...)
	if err != nil {
		tb.Fatal(err)
	}
	return set, strings.Join(segs, "/") + "/x.go"
}
