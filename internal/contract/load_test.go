// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

package contract

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"testing/fstest"
	"unicode"
	"unicode/utf8"

	"github.com/google/go-cmp/cmp"
)

func file(s string) *fstest.MapFile { return &fstest.MapFile{Data: []byte(s)} }

func validTree() fstest.MapFS {
	return fstest.MapFS{
		".factory.yaml":                      file(head + "paths:\n  writable: ['**']\n"),
		"src/checkout/.factory.yaml":         file(head + "lightsOn: true\n"),
		"src/checkout/payment/.factory.yaml": file(head + "paths:\n  sensitive: ['**']\n"),
		"src/other/main.go":                  file("package other"),
		".git/.factory.yaml":                 file("not: [valid"),
		"vendor/lib.go":                      file("package vendor"),
	}
}

func loadProblems(t *testing.T, fsys fs.FS) []Problem {
	t.Helper()
	set, err := Load(t.Context(), fsys, newParser(t), rev40)
	if err == nil {
		t.Fatalf("Load succeeded with dirs %v, want failure", set.Dirs())
	}
	if set != nil {
		t.Error("Load returned a partial set with an error")
	}
	var ve *ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("error %v is not a *ValidationError", err)
	}
	return ve.Problems
}

func TestLoad_Discovery(t *testing.T) { // CON-1
	t.Parallel()
	set, err := Load(t.Context(), validTree(), newParser(t), rev40)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	want := []string{"", "src/checkout", "src/checkout/payment"}
	if diff := cmp.Diff(want, set.Dirs()); diff != "" {
		t.Errorf("Dirs (-want +got):\n%s", diff)
	}
	if set.Revision() != rev40 {
		t.Errorf("Revision = %q", set.Revision())
	}
	c, ok := set.Get("src/checkout")
	if !ok || c.Dir != "src/checkout" || c.LightsOn == nil || !*c.LightsOn {
		t.Errorf("Get(src/checkout) = %+v, %v", c, ok)
	}
	if _, ok := set.Get("src/other"); ok {
		t.Error("Get(src/other) found a contract")
	}
}

func TestLoad_Misnamed(t *testing.T) {
	t.Parallel()
	fsys := validTree()
	names := []string{".factory.yml", ".Factory.yaml", ".factory.YAML", ".FACTORY.YML", ".Factory.Yml"}
	for _, n := range names {
		fsys["svc/"+n] = file(head)
	}
	ps := loadProblems(t, fsys)
	var want []Problem
	for _, n := range slices.Sorted(slices.Values(names)) {
		want = append(want, Problem{File: "svc/" + n, Code: CodeMisnamed, Message: "rename to .factory.yaml"})
	}
	if diff := cmp.Diff(want, ps); diff != "" {
		t.Errorf("problems (-want +got):\n%s", diff)
	}
}

func TestLoad_Symlink(t *testing.T) {
	t.Parallel()
	fsys := validTree()
	fsys["svc/.factory.yaml"] = &fstest.MapFile{Data: []byte(head), Mode: fs.ModeSymlink}
	ps := loadProblems(t, fsys)
	if len(ps) != 1 || ps[0].Code != CodeSymlink || ps[0].File != "svc/.factory.yaml" {
		t.Errorf("problems = %v", ps)
	}
}

func TestLoad_NotRegular(t *testing.T) {
	t.Parallel()
	fsys := validTree()
	fsys["svc/.factory.yaml"] = &fstest.MapFile{Mode: fs.ModeNamedPipe}
	ps := loadProblems(t, fsys)
	if len(ps) != 1 || ps[0].Code != CodeNotRegular {
		t.Errorf("problems = %v", ps)
	}
}

func TestLoad_DirectoryNamedLikeContract(t *testing.T) {
	t.Parallel()
	fsys := validTree()
	fsys["svc/.factory.yaml/x"] = file("")
	set, err := Load(t.Context(), fsys, newParser(t), rev40)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if _, ok := set.Get("svc"); ok {
		t.Error("directory treated as contract")
	}
}

func TestLoad_TooLarge(t *testing.T) {
	t.Parallel()
	fsys := validTree()
	fsys["big/.factory.yaml"] = file(head + "# " + strings.Repeat("x", MaxFileSize))
	ps := loadProblems(t, fsys)
	if len(ps) != 1 || ps[0].Code != CodeTooLarge {
		t.Errorf("problems = %v", ps)
	}
}

func TestLoad_FailsClosedWithAllProblems(t *testing.T) {
	t.Parallel()
	fsys := validTree()
	fsys["a/.factory.yaml"] = file(head + "command: make\n")
	fsys["b/c/.factory.yaml"] = file(head + "lightsOn: yes\n")
	fsys["d/.factory.yml"] = file(head)
	ps := loadProblems(t, fsys)
	var got []string
	for _, p := range ps {
		got = append(got, p.File+"|"+p.Field+"|"+string(p.Code))
	}
	want := []string{
		"a/.factory.yaml|/command|unknown-field",
		"b/c/.factory.yaml|/lightsOn|schema",
		"d/.factory.yml||misnamed",
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("problems (-want +got):\n%s", diff)
	}
}

func TestLoad_CanceledContext(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	set, err := Load(ctx, validTree(), newParser(t), rev40)
	if !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want context.Canceled", err)
	}
	if set != nil {
		t.Error("got a set from a canceled load")
	}
}

func TestNewSet_RejectsDuplicateDir(t *testing.T) {
	t.Parallel()
	if _, err := NewSet(rev40, &Contract{Dir: "a"}, &Contract{Dir: "a"}); err == nil {
		t.Error("duplicate dir accepted")
	}
	if _, err := NewSet(rev40, nil); err == nil {
		t.Error("nil contract accepted")
	}
	if s, err := NewSet(rev40); err != nil || len(s.Dirs()) != 0 {
		t.Errorf("empty set: %v", err)
	}
}

func TestLoad_ForeignTreeFailsClosed(t *testing.T) { // CON-1
	t.Parallel()
	tests := []struct {
		name string
		git  map[string]*fstest.MapFile
		want string
	}{
		{"git file", map[string]*fstest.MapFile{"svc/.git": file("gitdir: ../.git/modules/svc\n")}, "svc/.git"},
		{"git directory", map[string]*fstest.MapFile{"svc/.git/HEAD": file("ref: refs/heads/main\n")}, "svc/.git"},
		{"deep git file", map[string]*fstest.MapFile{"svc/sub/.git": file("x")}, "svc/sub/.git"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			fsys := fstest.MapFS{
				".factory.yaml":         file(head + "paths:\n  writable: ['**']\n"),
				"svc/.factory.yaml":     file(head + "paths:\n  forbidden: ['**']\n"),
				"svc/sub/.factory.yaml": file(head),
			}
			maps.Copy(fsys, tt.git)
			set, err := Load(t.Context(), fsys, newParser(t), rev40)
			var ve *ValidationError
			if !errors.As(err, &ve) || set != nil {
				t.Fatalf("set = %v, err = %v, want *ValidationError and no set", set, err)
			}
			if !hasFile(ve.Problems, CodeForeignTree, tt.want) {
				t.Errorf("problems = %v, want %s on %s", ve.Problems, CodeForeignTree, tt.want)
			}
		})
	}
}

func hasFile(ps []Problem, code Code, file string) bool {
	return slices.ContainsFunc(ps, func(p Problem) bool { return p.Code == code && p.File == file })
}

func TestLoad_KeepsFullFilePath(t *testing.T) { // SEC-1
	t.Parallel()
	dir := strings.Repeat("d", 100) + "/" + strings.Repeat("e", 100) + "/" + strings.Repeat("f", 98)
	fsys := fstest.MapFS{dir + "/.factory.yaml": file(head + "command: x\n")}
	ps := loadProblems(t, fsys)
	if len(ps) != 1 || ps[0].File != dir+"/.factory.yaml" || len(ps[0].File) < 300 {
		t.Errorf("File = %q", ps[0].File)
	}
}

func TestLoad_InvalidContractDirIsProblem(t *testing.T) { // CON-1
	t.Parallel()
	deep := strings.Repeat("a/", 257) + FileName // 257 directories
	fsys := fstest.MapFS{
		deep:               file(head),
		"z/.factory.yaml":  file(head + "command: x\n"),
		"y/.Factory.yaml":  file(head),
		"ok/.factory.yaml": file(head),
	}
	ps := loadProblems(t, fsys)
	if !hasFile(ps, CodeInvalidPath, deep) || !hasProblem(ps, CodeUnknownField, "/command") || !hasProblem(ps, CodeMisnamed, "") {
		t.Errorf("problems = %v", ps)
	}
	_, err := Load(t.Context(), fsys, newParser(t), rev40)
	var ve *ValidationError
	if !errors.As(err, &ve) {
		t.Errorf("error %v is not a *ValidationError", err)
	}
}

func TestLoad_RootGitEntryDoesNotSkipRoot(t *testing.T) { // CON-1
	t.Parallel()
	set, err := Load(t.Context(), validTree(), newParser(t), rev40)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := set.Get(""); !ok {
		t.Error("root contract missing")
	}
}

func TestLoad_SymlinkOnDisk(t *testing.T) { // CON-1
	t.Parallel()
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "svc"), 0o750); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "real.yaml")
	if err := os.WriteFile(target, []byte(head), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(dir, "svc", FileName)); err != nil {
		t.Skipf("symlinks unsupported: %v", err)
	}
	ps := loadProblems(t, os.DirFS(dir))
	if len(ps) != 1 || ps[0].Code != CodeSymlink || ps[0].File != "svc/.factory.yaml" {
		t.Errorf("problems = %v", ps)
	}
}

func TestLoad_RejectsInvalidRevision(t *testing.T) { // CON-1
	t.Parallel()
	p := newParser(t)
	for _, rev := range []string{"", "rev", "abc123", strings.ToUpper(rev40), rev40 + "0", rev40[:39], "HEAD", strings.Repeat("g", 40)} {
		_, err := Load(t.Context(), validTree(), p, rev)
		var ve *ValidationError
		if err == nil || errors.As(err, &ve) {
			t.Errorf("Load revision %q: err = %v, want plain error", rev, err)
		}
		if _, err := NewSet(rev); err == nil {
			t.Errorf("NewSet revision %q accepted", rev)
		}
	}
	if _, err := NewSet(strings.Repeat("a", 64)); err != nil {
		t.Errorf("64-hex revision rejected: %v", err)
	}
}

func TestNewSet_RejectsInvalidDir(t *testing.T) { // CON-1
	t.Parallel()
	for _, dir := range []string{".", "/a", "a/", "a/../b", "a//b", "a\x00b"} {
		if _, err := NewSet(rev40, &Contract{Dir: dir}); err == nil {
			t.Errorf("dir %q accepted", dir)
		}
	}
}

func TestLoad_TooManyContractFiles(t *testing.T) { // CON-1
	t.Parallel()
	fsys := fstest.MapFS{}
	for i := range maxContracts + 5 {
		fsys[fmt.Sprintf("d%04d/.factory.yaml", i)] = file(head)
	}
	ps := loadProblems(t, fsys)
	if len(ps) != 1 || ps[0].Code != CodeTooMany {
		t.Errorf("problems = %v", ps)
	}
	delete(fsys, "d0000/.factory.yaml")
	delete(fsys, "d0001/.factory.yaml")
	delete(fsys, "d0002/.factory.yaml")
	delete(fsys, "d0003/.factory.yaml")
	delete(fsys, "d0004/.factory.yaml")
	if _, err := Load(t.Context(), fsys, newParser(t), rev40); err != nil {
		t.Errorf("exactly %d files rejected: %v", maxContracts, err)
	}
}

func TestLoad_CapsProblemsOnce(t *testing.T) { // CON-1
	t.Parallel()
	var b strings.Builder
	b.WriteString(head + "paths:\n  forbidden:\n")
	for i := range 150 {
		fmt.Fprintf(&b, "    - ../x%d\n", i)
	}
	fsys := fstest.MapFS{
		"z/.factory.yaml": file(b.String()),
		"a/.factory.yml":  file(head),
	}
	ps := loadProblems(t, fsys)
	if len(ps) != maxProblems {
		t.Fatalf("got %d problems, want %d", len(ps), maxProblems)
	}
	last := ps[len(ps)-1]
	if last.Code != CodeTooMany || last.File != "" || last.Message != "52 more problems omitted" {
		t.Errorf("last problem = %v", last)
	}
	for _, p := range ps[:len(ps)-1] {
		if p.Code == CodeTooMany {
			t.Errorf("unexpected note %v", p)
		}
	}
	if ps[0].Code != CodeMisnamed {
		t.Errorf("first problem = %v, want the misnamed file", ps[0])
	}
}

func TestLoad_CapsReportedProblems(t *testing.T) { // CON-1
	t.Parallel()
	fsys := fstest.MapFS{}
	for i := range 150 {
		fsys[fmt.Sprintf("d%03d/.factory.yaml", i)] = file(head + "command: x\n")
	}
	ps := loadProblems(t, fsys)
	if len(ps) != maxProblems {
		t.Fatalf("got %d problems, want %d", len(ps), maxProblems)
	}
	last := ps[len(ps)-1]
	if last.Code != CodeTooMany || !strings.Contains(last.Message, "51 more") {
		t.Errorf("last problem = %v", last)
	}
}

func TestParse_CapsProblems(t *testing.T) { // CON-11
	t.Parallel()
	var b strings.Builder
	b.WriteString(head + "paths:\n  forbidden:\n")
	for i := range 200 {
		fmt.Fprintf(&b, "    - ../x%d\n", i)
	}
	ps := problemsOf(t, newParser(t), b.String())
	if len(ps) != maxProblems || ps[len(ps)-1].Code != CodeTooMany {
		t.Errorf("got %d problems, last %v", len(ps), ps[len(ps)-1])
	}
}

func TestLoad_RejectsInvalidPatternFile(t *testing.T) { // CON-1, CON-11
	t.Parallel()
	fsys := validTree()
	fsys["svc/.factory.yaml"] = file(head + "paths:\n  sensitive: ['a/../b']\n")
	ps := loadProblems(t, fsys)
	if len(ps) != 1 || ps[0].Code != CodeInvalidPattern || ps[0].Field != "/paths/sensitive/0" || ps[0].File != "svc/.factory.yaml" {
		t.Errorf("problems = %v", ps)
	}
}

func TestLoad_SanitizesFileNames(t *testing.T) { // SEC-1
	t.Parallel()
	fsys := validTree()
	fsys["evil\n::error::fake/.factory.yaml"] = file(head + "command: x\n")
	fsys["evil\n::error::fake/.Factory.yml"] = file(head)
	for _, p := range loadProblems(t, fsys) {
		assertSafeProblem(t, p)
	}
}

// failReadDirFS fails ReadDir for one directory.
type failReadDirFS struct {
	fs.FS
	dir string
	err error
}

func (f failReadDirFS) ReadDir(name string) ([]fs.DirEntry, error) {
	if name == f.dir {
		return nil, f.err
	}
	return fs.ReadDir(f.FS, name)
}

func TestLoad_IOErrorIsWrappedNotAProblem(t *testing.T) { // CON-1
	t.Parallel()
	boom := errors.New("disk on fire")
	fsys := failReadDirFS{FS: validTree(), dir: "src/checkout", err: boom}
	set, err := Load(t.Context(), fsys, newParser(t), rev40)
	var ve *ValidationError
	if !errors.Is(err, boom) || errors.As(err, &ve) || set != nil {
		t.Errorf("set = %v, err = %v, want wrapped I/O error and no set", set, err)
	}
}

// hostilePath holds invalid UTF-8, a newline, a workflow command, an escape
// sequence and a legacy command.
const hostilePath = "evil\xff\n::error x::y\n\x1b[2K##[error]z"

// failingFS is a MapFS whose chosen operations fail with a *fs.PathError that
// carries hostilePath, as os.DirFS does with a real path.
type failingFS struct {
	fstest.MapFS
	failReadDir string
	failOpen    string
}

func (f failingFS) ReadDir(name string) ([]fs.DirEntry, error) {
	if name == f.failReadDir {
		return nil, &fs.PathError{Op: "readdirent", Path: hostilePath, Err: errors.New("permission denied")}
	}
	return f.MapFS.ReadDir(name)
}

func (f failingFS) Open(name string) (fs.File, error) {
	if name == f.failOpen {
		return nil, &fs.PathError{Op: "open", Path: hostilePath, Err: errors.New("permission denied")}
	}
	return f.MapFS.Open(name)
}

func requirePlain(t *testing.T, what, s string) {
	t.Helper()
	for _, r := range s {
		if !unicode.IsPrint(r) || unicode.Is(unicode.Cf, r) || r == '#' || r == utf8.RuneError {
			t.Errorf("%s holds the raw rune %U: %q", what, r, s)
			return
		}
	}
}

func TestLoad_HostilePathErrorsCannotReachOutput(t *testing.T) { // SEC-1
	t.Parallel()
	bad := "d" + hostilePath
	base := fstest.MapFS{
		".factory.yaml":     file(head + writableAll),
		bad + "/other.txt":  file("x"),
		"svc/.factory.yaml": file(head),
	}
	t.Run("an unreadable directory is a problem", func(t *testing.T) {
		t.Parallel()
		_, err := Load(t.Context(), failingFS{MapFS: base, failReadDir: bad}, newParser(t), rev40)
		ps := problemsFrom(t, err)
		if len(ps) != 1 || ps[0].Code != CodeInvalidPath {
			t.Fatalf("problems = %v, want one invalid-path", ps)
		}
		requirePlain(t, "Error", err.Error())
		requirePlain(t, "String", ps[0].String())
	})
	t.Run("an I/O error wraps only the cause", func(t *testing.T) {
		t.Parallel()
		_, err := Load(t.Context(), failingFS{MapFS: base, failOpen: "svc/.factory.yaml"}, newParser(t), rev40)
		var ve *ValidationError
		if err == nil || errors.As(err, &ve) {
			t.Fatalf("err = %v, want an I/O error", err)
		}
		var pe *fs.PathError
		if errors.As(err, &pe) {
			t.Errorf("the error still wraps a *fs.PathError: %v", pe)
		}
		requirePlain(t, "Error", err.Error())
		if !strings.Contains(err.Error(), "permission denied") {
			t.Errorf("err = %v, want the cause kept", err)
		}
	})
	t.Run("a hostile directory with a contract problem", func(t *testing.T) {
		t.Parallel()
		m := fstest.MapFS{".factory.yaml": file(head + writableAll), bad + "/.factory.yml": file(head)}
		_, err := Load(t.Context(), m, newParser(t), rev40)
		ps := problemsFrom(t, err)
		if len(ps) != 1 {
			t.Fatalf("problems = %v", ps)
		}
		requirePlain(t, "String", ps[0].String())
	})
}
