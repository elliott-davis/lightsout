// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

// requirePOSIXFiles skips the test where the file backend is unsupported.
func requirePOSIXFiles(t *testing.T) {
	t.Helper()
	f, err := CreateFile(t.Context(), filepath.Join(secureDir(t), "probe.jsonl"))
	if errors.Is(err, errors.ErrUnsupported) {
		t.Skip("file backend unsupported on this platform")
	}
	if err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
}

func assertChainErrAt(t *testing.T, err error, seq uint64) {
	t.Helper()
	var ce *ChainError
	if !errors.Is(err, ErrBrokenChain) || !errors.As(err, &ce) || ce.Seq != seq {
		t.Fatalf("err = %v, want ChainError at seq %d", err, seq)
	}
}

func TestFile_RejectsNoncanonicalLines(t *testing.T) { // NFR-4
	t.Parallel()
	requirePOSIXFiles(t)
	// noncanonical lists forms that encoding/json accepts but that are not what this package writes. Each is applied
	// to the line of seq 2. A reader such as jq could read any of them differently from this package.
	noncanonical := map[string]func(line string) string{
		"case-variant key": func(l string) string {
			return strings.Replace(l, `"target":"tool-1"`, `"target":"tool-1","TARGET":"evil"`, 1)
		},
		"duplicate key": func(l string) string {
			return strings.Replace(l, `"target":"tool-1"`, `"target":"tool-1","target":"evil"`, 1)
		},
		"unicode escape": func(l string) string { return strings.Replace(l, `"tool-1"`, `"tool`+"\\"+`u002d1"`, 1) },
		"extra whitespace": func(l string) string {
			return strings.Replace(l, `"seq":2`, `"seq": 2`, 1)
		},
		"time offset": func(l string) string { return strings.Replace(l, `Z","actor"`, `+00:00","actor"`, 1) },
		"null prev hash": func(l string) string {
			return regexp.MustCompile(`"prev_hash":"[0-9a-f]+"`).ReplaceAllString(l, `"prev_hash":null`)
		},
		"CRLF ending":        func(l string) string { return l + "\r" },
		"empty attrs object": func(l string) string { return strings.Replace(l, `"prev_hash"`, `"attrs":{},"prev_hash"`, 1) },
	}
	for name, mutate := range noncanonical {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			path, _ := buildFile(t, 3)
			lines := readLines(t, path)
			orig := strings.TrimSuffix(lines[1], "\n")
			lines[1] = mutate(orig)
			if lines[1] == orig {
				t.Fatal("mutation did not change the line")
			}
			writeLines(t, path, lines)
			assertBrokenAt(t, path, 2)
		})
		t.Run(name+" after open", func(t *testing.T) {
			t.Parallel()
			path, _ := buildFile(t, 3)
			l, _ := reopenFileLog(t, path)
			lines := readLines(t, path)
			lines[1] = mutate(strings.TrimSuffix(lines[1], "\n"))
			writeLines(t, path, lines)
			_, err := l.Read(t.Context(), 1, 10)
			assertChainErrAt(t, err, 2)
			_, err = l.Verify(t.Context())
			assertChainErrAt(t, err, 2)
		})
	}
}

func TestFile_ReadDetectsInPlaceEdit(t *testing.T) { // NFR-4
	t.Parallel()
	requirePOSIXFiles(t)
	path, _ := buildFile(t, 3)
	l, _ := reopenFileLog(t, path)
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	edited := strings.Replace(string(b), `"tool-1"`, `"tool-9"`, 1) // same length
	if len(edited) != len(b) || edited == string(b) {
		t.Fatal("bad edit")
	}
	if err = os.WriteFile(path, []byte(edited), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, rerr := l.Read(t.Context(), 1, 1); rerr != nil || len(got) != 1 {
		t.Fatalf("untouched entry unreadable: %v", rerr)
	}
	_, err = l.Read(t.Context(), 2, 1)
	assertChainErrAt(t, err, 2)
	_, err = l.Verify(t.Context())
	assertChainErrAt(t, err, 2)
}

func TestFile_RoundTripsAllRecordShapes(t *testing.T) { // NFR-4
	t.Parallel()
	requirePOSIXFiles(t)
	path := filepath.Join(secureDir(t), "audit.jsonl")
	l, f := newFileLog(t, path)
	link := Record{
		Actor:   Actor{Kind: ActorFactory, ID: "wl-factory"},
		Subject: Subject{Kind: SubjectChange, Repo: "github:99", ID: "42"},
		Action:  ActionLink, TemplateVersion: "factory@1.2.3", Outcome: "ok",
		Link: &Subject{Kind: SubjectIssue, Repo: "github:99", ID: "7"},
	}
	odd := agentRec()
	odd.Target = "<a&b>   \x00\x1b\n\r\t é 😀 \\ \""
	odd.Attrs = map[string]string{"a.b-c_d": "x<y>&z", "z": ""}
	for _, r := range []Record{agentRec(), decisionRec(VerdictDenied), link, odd} {
		if _, err := l.Append(t.Context(), r); err != nil {
			t.Fatal(err)
		}
	}
	want, _ := l.Read(t.Context(), 1, 10)
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	l2, _ := reopenFileLog(t, path)
	got, err := l2.Read(t.Context(), 1, 10)
	if err != nil {
		t.Fatal(err)
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("round trip differs:\n%s", diff)
	}
	if _, err := l2.Verify(t.Context()); err != nil {
		t.Error(err)
	}
}

func TestFile_CreateAndOpenAreStrict(t *testing.T) { // NFR-4: a deleted or swapped log never silently becomes a new one
	t.Parallel()
	requirePOSIXFiles(t)
	t.Run("missing file", func(t *testing.T) {
		t.Parallel()
		_, err := OpenFile(t.Context(), filepath.Join(secureDir(t), "audit.jsonl"))
		if !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("err = %v, want fs.ErrNotExist", err)
		}
	})
	t.Run("create refuses existing file", func(t *testing.T) {
		t.Parallel()
		path, _ := buildFile(t, 1)
		if _, err := CreateFile(t.Context(), path); !errors.Is(err, fs.ErrExist) {
			t.Errorf("err = %v, want fs.ErrExist", err)
		}
	})
	t.Run("dangling symlink", func(t *testing.T) {
		t.Parallel()
		dir := secureDir(t)
		path := filepath.Join(dir, "audit.jsonl")
		if err := os.Symlink(filepath.Join(dir, "nowhere"), path); err != nil {
			t.Fatal(err)
		}
		if _, err := OpenFile(t.Context(), path); err == nil {
			t.Error("OpenFile followed a dangling symlink")
		}
		if _, err := CreateFile(t.Context(), path); err == nil {
			t.Error("CreateFile followed a dangling symlink")
		}
		if _, err := os.Stat(filepath.Join(dir, "nowhere")); err == nil {
			t.Error("symlink target was created")
		}
	})
	t.Run("symlink to a real log", func(t *testing.T) {
		t.Parallel()
		target, _ := buildFile(t, 2)
		link := filepath.Join(secureDir(t), "link.jsonl")
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
		if _, err := OpenFile(t.Context(), link); err == nil {
			t.Error("OpenFile followed a symlink")
		}
	})
	t.Run("group or other permissions", func(t *testing.T) {
		t.Parallel()
		path, _ := buildFile(t, 1)
		if err := os.Chmod(path, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := OpenFile(t.Context(), path); !errors.Is(err, ErrInsecureFile) {
			t.Errorf("err = %v, want ErrInsecureFile", err)
		}
		if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o644 {
			t.Errorf("OpenFile changed the mode to %o", fi.Mode().Perm())
		}
	})
	t.Run("second open while locked", func(t *testing.T) {
		t.Parallel()
		path := filepath.Join(secureDir(t), "audit.jsonl")
		_, first := newFileLog(t, path)
		if _, err := OpenFile(t.Context(), path); !errors.Is(err, ErrLocked) {
			t.Errorf("err = %v, want ErrLocked", err)
		}
		if err := first.Close(); err != nil {
			t.Fatal(err)
		}
		again, err := OpenFile(t.Context(), path)
		if err != nil {
			t.Fatalf("open after close: %v", err)
		}
		_ = again.Close()
	})
}

func TestVerify_FullRewritePassesVerifyButNotCheckpoint(t *testing.T) { // NFR-4: the chain is unkeyed
	t.Parallel()
	requirePOSIXFiles(t)
	path, saved := buildFile(t, 5)
	l, f := reopenFileLog(t, path)
	all, err := l.Read(t.Context(), 1, 10)
	if err != nil {
		t.Fatal(err)
	}
	_ = f.Close()

	// An attacker who can write the file rewrites seq 2 and recomputes every hash after it.
	lines := []string{}
	prev := all[0]
	first, _ := marshalLine(prev)
	lines = append(lines, first)
	for _, e := range all[1:] {
		e.PrevHash = prev.Hash
		if e.Seq == 2 {
			e.Target = "rewritten"
		}
		e.Hash = computeHash(e)
		line, _ := marshalLine(e)
		lines = append(lines, line)
		prev = e
	}
	writeLines(t, path, lines)

	l2, _ := reopenFileLog(t, path)
	if _, err := l2.Verify(t.Context()); err != nil {
		t.Fatalf("a fully recomputed rewrite should pass local Verify, got %v", err)
	}
	assertChainErrAt(t, l2.VerifyAgainst(t.Context(), saved), 5)
}
