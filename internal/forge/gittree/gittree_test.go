// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

package gittree_test

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/google/go-cmp/cmp"

	"github.com/elliott-davis/lightsout/internal/forge"
	"github.com/elliott-davis/lightsout/internal/forge/gittree"
)

func blob(p, data string) gittree.Entry {
	return gittree.Entry{Path: p, Mode: gittree.ModeBlob, Data: []byte(data)}
}

func TestNew_Rejects(t *testing.T) { // INTG-1
	t.Parallel()
	tests := []struct {
		name    string
		entries []gittree.Entry
		lim     gittree.Limits
		want    error
	}{
		{"empty path", []gittree.Entry{blob("", "x")}, gittree.Limits{}, gittree.ErrInvalidEntry},
		{"dot", []gittree.Entry{blob(".", "x")}, gittree.Limits{}, gittree.ErrInvalidEntry},
		{"leading slash", []gittree.Entry{blob("/a", "x")}, gittree.Limits{}, gittree.ErrInvalidEntry},
		{"dotdot", []gittree.Entry{blob("a/../b", "x")}, gittree.Limits{}, gittree.ErrInvalidEntry},
		{"trailing slash", []gittree.Entry{blob("a/", "x")}, gittree.Limits{}, gittree.ErrInvalidEntry},
		{"empty segment", []gittree.Entry{blob("a//b", "x")}, gittree.Limits{}, gittree.ErrInvalidEntry},
		{"NUL byte", []gittree.Entry{blob("a\x00b", "x")}, gittree.Limits{}, gittree.ErrInvalidEntry},
		{"invalid UTF-8", []gittree.Entry{blob("a\xffb", "x")}, gittree.Limits{}, gittree.ErrInvalidEntry},
		{"segment too long", []gittree.Entry{blob(strings.Repeat("a", 300), "x")}, gittree.Limits{}, gittree.ErrInvalidEntry},
		{"invalid mode", []gittree.Entry{{Path: "a", Mode: gittree.ModeInvalid}}, gittree.Limits{}, gittree.ErrInvalidEntry},
		{"duplicate", []gittree.Entry{blob("a", "1"), blob("a", "2")}, gittree.Limits{}, gittree.ErrInvalidEntry},
		{"under blob", []gittree.Entry{blob("a", "1"), blob("a/b", "2")}, gittree.Limits{}, gittree.ErrInvalidEntry},
		{"under blob reversed", []gittree.Entry{blob("a/b", "2"), blob("a", "1")}, gittree.Limits{}, gittree.ErrInvalidEntry},
		{"under symlink", []gittree.Entry{{Path: "l", Mode: gittree.ModeSymlink, Data: []byte("x")}, blob("l/b", "2")}, gittree.Limits{}, gittree.ErrInvalidEntry},
		{"under gitlink", []gittree.Entry{{Path: "vendor", Mode: gittree.ModeGitlink}, blob("vendor/b", "2")}, gittree.Limits{}, gittree.ErrInvalidEntry},
		{"too many entries", []gittree.Entry{blob("a", ""), blob("b", ""), blob("c", "")}, gittree.Limits{MaxEntries: 2}, forge.ErrTooLarge},
		{"synthesized directories count", []gittree.Entry{blob("a/b/c/d/e", "")}, gittree.Limits{MaxEntries: 1}, forge.ErrTooLarge},
		{"total path bytes", []gittree.Entry{blob("aaaa/bbbb/cccc", "")}, gittree.Limits{MaxPathBytes: 10}, forge.ErrTooLarge},
		{"newline in name", []gittree.Entry{blob("a\nb", "x")}, gittree.Limits{}, gittree.ErrInvalidEntry},
		{"escape in name", []gittree.Entry{blob("a\x1bb", "x")}, gittree.Limits{}, gittree.ErrInvalidEntry},
		{"DEL in name", []gittree.Entry{blob("a\x7fb", "x")}, gittree.Limits{}, gittree.ErrInvalidEntry},
		{"C1 in name", []gittree.Entry{blob("a\u0085b", "x")}, gittree.Limits{}, gittree.ErrInvalidEntry},
		{"backslash in name", []gittree.Entry{blob("a\\b", "x")}, gittree.Limits{}, gittree.ErrInvalidEntry},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if _, err := gittree.New(tt.entries, tt.lim); !errors.Is(err, tt.want) {
				t.Fatalf("New() error = %v, want %v", err, tt.want)
			}
		})
	}
}

func basicsTree(t *testing.T) *gittree.FS {
	t.Helper()
	tree, err := gittree.New([]gittree.Entry{
		blob("z.txt", "z"),
		blob("a/b/c.txt", "c"),
		{Path: "bin/run", Mode: gittree.ModeExecutable, Data: []byte("#!/bin/sh")},
		{Path: "link", Mode: gittree.ModeSymlink, Data: []byte("a/b/c.txt")},
		{Path: "vendor", Mode: gittree.ModeGitlink, SHA: strings.Repeat("a", 40)},
		blob("README", "1"),
		blob("readme", "2"),
		{Path: "empty", Mode: gittree.ModeTree},
	}, gittree.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	return tree
}

func TestFS_ReadDirSortedWithModes(t *testing.T) { // INTG-1
	t.Parallel()
	ents, err := basicsTree(t).ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, e := range ents {
		got = append(got, e.Name()+":"+e.Type().String())
	}
	want := []string{"README:----------", "a:d---------", "bin:d---------", "empty:d---------", "link:L---------", "readme:----------", "vendor:?---------", "z.txt:----------"}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Fatalf("ReadDir mismatch (-want +got):\n%s", diff)
	}
}

func TestFS_StatModes(t *testing.T) { // INTG-1
	t.Parallel()
	tree := basicsTree(t)
	for p, want := range map[string]fs.FileMode{
		"z.txt": 0o644, "bin/run": 0o755, "link": fs.ModeSymlink, "vendor": fs.ModeIrregular, "a": fs.ModeDir | 0o755,
	} {
		fi, err := fs.Stat(tree, p)
		if err != nil {
			t.Fatalf("Stat(%q): %v", p, err)
		}
		if fi.Mode() != want {
			t.Errorf("Stat(%q) mode = %v, want %v", p, fi.Mode(), want)
		}
	}
}

func TestFS_CaseCollidingNamesBothPresent(t *testing.T) { // INTG-1
	t.Parallel()
	tree := basicsTree(t)
	for p, want := range map[string]string{"README": "1", "readme": "2"} {
		got, err := tree.ReadFile(p)
		if err != nil || string(got) != want {
			t.Errorf("ReadFile(%q) = %q, %v; want %q", p, got, err, want)
		}
	}
}

func TestFS_ReadLink(t *testing.T) { // INTG-1
	t.Parallel()
	tree := basicsTree(t)
	got, err := tree.ReadLink("link")
	if err != nil || got != "a/b/c.txt" {
		t.Fatalf("ReadLink = %q, %v", got, err)
	}
	if _, err := tree.ReadLink("z.txt"); err == nil {
		t.Fatal("ReadLink on a blob succeeded")
	}
}

func TestFS_Missing(t *testing.T) { // INTG-1
	t.Parallel()
	tree := basicsTree(t)
	if _, err := tree.Open("nope"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("Open(nope) error = %v", err)
	}
	if _, err := tree.Open("z.txt/x"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("Open(z.txt/x) error = %v", err)
	}
	if _, err := tree.Open("../x"); !errors.Is(err, fs.ErrInvalid) {
		t.Fatalf("Open(../x) error = %v", err)
	}
}

func TestFS_Symlinks(t *testing.T) { // INTG-1, SEC-1
	t.Parallel()
	tree, err := gittree.New([]gittree.Entry{
		{Path: "dirlink", Mode: gittree.ModeSymlink, Data: []byte("real")},
		blob("real/CODEOWNERS", "x"),
		{Path: "real/CODEOWNERS.link", Mode: gittree.ModeSymlink, Data: []byte("CODEOWNERS")},
		{Path: "vendor", Mode: gittree.ModeGitlink, SHA: strings.Repeat("b", 40)},
	}, gittree.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"dirlink", "dirlink/CODEOWNERS", "real/CODEOWNERS.link"} {
		if _, err := tree.Open(p); !errors.Is(err, forge.ErrSymlink) {
			t.Errorf("Open(%q) error = %v, want ErrSymlink", p, err)
		}
		if _, err := tree.ReadFile(p); !errors.Is(err, forge.ErrSymlink) {
			t.Errorf("ReadFile(%q) error = %v, want ErrSymlink", p, err)
		}
	}
	if _, err := tree.Stat("dirlink/CODEOWNERS"); !errors.Is(err, forge.ErrSymlink) {
		t.Errorf("Stat through symlink error = %v", err)
	}
	if _, err := tree.ReadDir("dirlink"); !errors.Is(err, forge.ErrSymlink) {
		t.Errorf("ReadDir(symlink) error = %v", err)
	}
	for _, p := range []string{"vendor", "vendor/x"} {
		if _, err := tree.Open(p); err == nil {
			t.Errorf("Open(%q) succeeded on a gitlink", p)
		}
	}
	if _, err := tree.Open("vendor"); !errors.Is(err, forge.ErrUnsupported) {
		t.Errorf("Open(gitlink) error = %v, want ErrUnsupported", err)
	}
}

func TestNew_ContentLimits(t *testing.T) { // INTG-1
	t.Parallel()
	if _, err := gittree.New([]gittree.Entry{blob("big", "123456"), blob("ok", "12")}, gittree.Limits{MaxFileBytes: 4}); !errors.Is(err, forge.ErrTooLarge) {
		t.Fatalf("New(oversized blob) error = %v, want ErrTooLarge", err)
	}
	link := gittree.Entry{Path: "l", Mode: gittree.ModeSymlink, Data: []byte("0123456789")}
	if _, err := gittree.New([]gittree.Entry{link}, gittree.Limits{MaxFileBytes: 4}); !errors.Is(err, forge.ErrTooLarge) {
		t.Fatalf("New(oversized symlink target) error = %v, want ErrTooLarge", err)
	}
	if _, err := gittree.New([]gittree.Entry{blob("a", "123"), blob("b", "123")}, gittree.Limits{MaxFileBytes: 4, MaxTotalBytes: 5}); !errors.Is(err, forge.ErrTooLarge) {
		t.Fatalf("New(total over limit) error = %v, want ErrTooLarge", err)
	}
	tree, err := gittree.New([]gittree.Entry{blob("ok", "12")}, gittree.Limits{MaxFileBytes: 4})
	if err != nil {
		t.Fatal(err)
	}
	if got, err := tree.ReadFile("ok"); err != nil || !bytes.Equal(got, []byte("12")) {
		t.Fatalf("ReadFile(ok) = %q, %v", got, err)
	}
}

func TestFS_ReadDirPagingIsLinear(t *testing.T) { // INTG-1
	// Not parallel: testing.AllocsPerRun forbids it.
	const n = 50_000
	entries := make([]gittree.Entry, n)
	for i := range entries {
		entries[i] = blob(fmt.Sprintf("f%06d", i), "")
	}
	tree, err := gittree.New(entries, gittree.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	f, err := tree.Open(".")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	dir, ok := f.(fs.ReadDirFile)
	if !ok {
		t.Fatal("directory does not implement fs.ReadDirFile")
	}
	// Paging builds only the entry it returns, so the allocations per call stay constant however large the
	// directory is. A rebuild of the whole listing would allocate once per entry.
	allocs := testing.AllocsPerRun(200, func() {
		if _, err := dir.ReadDir(1); err != nil {
			t.Fatal(err)
		}
	})
	if allocs > 6 {
		t.Fatalf("ReadDir(1) made %v allocations on a %d-entry directory, want a small constant", allocs, n)
	}
	count := 201 // AllocsPerRun ran the function once more than asked
	for {
		ents, err := dir.ReadDir(1)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		count += len(ents)
	}
	if count != n {
		t.Fatalf("paged %d entries, want %d", count, n)
	}
}

func TestFS_ReadFileReturnsCopy(t *testing.T) {
	t.Parallel()
	tree, err := gittree.New([]gittree.Entry{blob("a", "abc")}, gittree.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := tree.ReadFile("a")
	b[0] = 'X'
	if again, _ := tree.ReadFile("a"); string(again) != "abc" {
		t.Fatalf("ReadFile result aliases tree data: %q", again)
	}
}

func TestFS_FSTest(t *testing.T) { // INTG-1
	t.Parallel()
	tree, err := gittree.New([]gittree.Entry{
		blob("a.txt", "alpha"),
		blob("dir/b.txt", "bravo"),
		blob("dir/sub/c.txt", "charlie"),
		{Path: "dir/run.sh", Mode: gittree.ModeExecutable, Data: []byte("echo")},
		blob("Dir/case.txt", "case"),
		{Path: "emptydir", Mode: gittree.ModeTree},
	}, gittree.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if err := fstest.TestFS(tree, "a.txt", "dir/b.txt", "dir/sub/c.txt", "dir/run.sh", "Dir/case.txt"); err != nil {
		t.Fatal(err)
	}
}

func TestFS_ReadLinkFS(t *testing.T) { // INTG-1
	t.Parallel()
	tree, err := gittree.New([]gittree.Entry{
		blob("real", "x"),
		{Path: "link", Mode: gittree.ModeSymlink, Data: []byte("real")},
	}, gittree.Limits{MaxFileBytes: 12})
	if err != nil {
		t.Fatal(err)
	}
	if target, lerr := fs.ReadLink(tree, "link"); lerr != nil || target != "real" {
		t.Fatalf("fs.ReadLink = %q, %v", target, lerr)
	}
	fi, err := fs.Lstat(tree, "link")
	if err != nil || fi.Mode()&fs.ModeSymlink == 0 {
		t.Fatalf("fs.Lstat = %v, %v", fi, err)
	}
}

// BenchmarkNew builds a 20k-entry tree with every file 50 directories deep.
func BenchmarkNew(b *testing.B) {
	dir := strings.Repeat("d/", 49) + "d"
	entries := make([]gittree.Entry, 20_000)
	for i := range entries {
		entries[i] = blob(fmt.Sprintf("%s/f%05d", dir, i), "x")
	}
	b.ReportAllocs()
	for b.Loop() {
		if _, err := gittree.New(entries, gittree.Limits{}); err != nil {
			b.Fatal(err)
		}
	}
}
