// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

package gittree_test

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/elliott-davis/lightsout/internal/contract"
	"github.com/elliott-davis/lightsout/internal/forge/gittree"
)

const rev = "0123456789abcdef0123456789abcdef01234567"

const minimalContract = "apiVersion: factory/v1alpha1\nkind: Contract\npaths:\n  writable: []\nlightsOn: true\n"

func load(t *testing.T, entries ...gittree.Entry) (*contract.Set, error) {
	t.Helper()
	tree, err := gittree.New(entries, gittree.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	p, err := contract.NewParser()
	if err != nil {
		t.Fatal(err)
	}
	return contract.Load(t.Context(), tree, p, rev)
}

func problemCodes(t *testing.T, err error) []contract.Code {
	t.Helper()
	var verr *contract.ValidationError
	if !errors.As(err, &verr) {
		t.Fatalf("error = %v, want *contract.ValidationError", err)
	}
	var codes []contract.Code
	for _, p := range verr.Problems {
		codes = append(codes, p.Code)
	}
	return codes
}

func TestContractLoad_OverGittree(t *testing.T) { // CON-1
	t.Parallel()
	c := func(p string) gittree.Entry {
		return gittree.Entry{Path: p, Mode: gittree.ModeBlob, Data: []byte(minimalContract)}
	}

	t.Run("finds nested contracts", func(t *testing.T) {
		t.Parallel()
		set, err := load(t, c(".factory.yaml"), c("svc/api/.factory.yaml"))
		if err != nil {
			t.Fatal(err)
		}
		if got := set.Dirs(); !slices.Equal(got, []string{"", "svc/api"}) {
			t.Fatalf("Dirs() = %q", got)
		}
	})

	t.Run("rejects a symlinked contract", func(t *testing.T) {
		t.Parallel()
		_, err := load(t, c("real.yaml"), gittree.Entry{Path: ".factory.yaml", Mode: gittree.ModeSymlink, Data: []byte("real.yaml")})
		if got := problemCodes(t, err); !slices.Contains(got, contract.CodeSymlink) {
			t.Fatalf("codes = %v, want CodeSymlink", got)
		}
	})

	t.Run("does not descend into a gitlink named vendor", func(t *testing.T) {
		t.Parallel()
		set, err := load(t, c(".factory.yaml"), gittree.Entry{Path: "vendor", Mode: gittree.ModeGitlink, SHA: strings.Repeat("c", 40)})
		if err != nil {
			t.Fatal(err)
		}
		if got := set.Dirs(); !slices.Equal(got, []string{""}) {
			t.Fatalf("Dirs() = %q, want only the root contract", got)
		}
	})

	t.Run("nested vendor/.git is a foreign tree", func(t *testing.T) {
		t.Parallel()
		_, err := load(t, c(".factory.yaml"), gittree.Entry{Path: "vendor/.git/HEAD", Mode: gittree.ModeBlob, Data: []byte("ref")}, c("vendor/.factory.yaml"))
		if got := problemCodes(t, err); !slices.Contains(got, contract.CodeForeignTree) {
			t.Fatalf("codes = %v, want CodeForeignTree", got)
		}
	})
}
