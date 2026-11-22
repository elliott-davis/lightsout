// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

// TestExportedAPI_Allowlist // NFR-4: the exported top-level identifiers are an explicit allowlist, so adding an
// update, delete or rewrite entry point forces a conscious change here. Methods are covered by
// TestLog_NoMutationThroughAPI.
func TestExportedAPI_Allowlist(t *testing.T) {
	t.Parallel()
	want := []string{
		// types
		"Action", "Actor", "ActorKind", "Backend", "ChainError", "Decision", "Entry", "File", "Hash", "Head", "Log",
		"Memory", "Record", "RecordError", "SealFunc", "StoreError", "Subject", "SubjectKind", "Verdict",
		// funcs
		"CheckSuccessor", "CreateFile", "New", "NewMemory", "OpenFile",
		// consts
		"ActionAdmin", "ActionDecision", "ActionLink", "ActionModelCall", "ActionRepoWrite", "ActionStateTransition",
		"ActionToolCall", "ActorAgent", "ActorExternal", "ActorFactory", "ActorHuman", "FormatVersion", "MaxAttrKeyBytes", "MaxAttrs",
		"MaxLineBytes", "MaxReadLimit", "MaxRecordBytes", "MaxStringBytes", "SubjectChange", "SubjectInstall",
		"SubjectIssue", "VerdictDenied", "VerdictGranted",
		// vars
		"ErrBrokenChain", "ErrClosed", "ErrInsecureFile", "ErrInvalidRecord", "ErrLocked", "ErrStoreFailed",
	}
	slices.Sort(want)

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	parsed := 0
	fset := token.NewFileSet()
	for _, de := range entries {
		name := de.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		parsed++
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		got = append(got, exportedNames(f)...)
	}
	if parsed == 0 {
		t.Fatal("no package source files found; run the test from the package directory")
	}
	slices.Sort(got)
	got = slices.Compact(got)
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("exported API changed (-want +got); review it against NFR-4:\n%s", diff)
	}
}

// exportedNames returns the exported top-level funcs (not methods), types, consts and vars declared in f.
func exportedNames(f *ast.File) []string {
	var out []string
	add := func(id *ast.Ident) {
		if id.IsExported() {
			out = append(out, id.Name)
		}
	}
	for _, d := range f.Decls {
		switch d := d.(type) {
		case *ast.FuncDecl:
			if d.Recv == nil {
				add(d.Name)
			}
		case *ast.GenDecl:
			for _, spec := range d.Specs {
				switch s := spec.(type) {
				case *ast.TypeSpec:
					add(s.Name)
				case *ast.ValueSpec:
					for _, n := range s.Names {
						add(n)
					}
				}
			}
		}
	}
	return out
}
