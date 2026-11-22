// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

//go:build darwin || dragonfly || freebsd || linux || netbsd || openbsd

package audit

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// TestCreateFile_RestrictiveUmask // NFR-4. It does not call t.Parallel: the umask is process-wide, and a
// non-parallel test runs while the parallel tests are paused, so no other test creates files meanwhile.
func TestCreateFile_RestrictiveUmask(t *testing.T) {
	for _, umask := range []int{0o277, 0o777} { // would give 0400 and 0000
		path := filepath.Join(secureDir(t), "audit.jsonl") // made before the umask changes
		old := syscall.Umask(umask)
		f, err := CreateFile(t.Context(), path)
		syscall.Umask(old)
		if err != nil {
			t.Fatalf("umask %o: %v", umask, err)
		}
		fi, _ := os.Stat(path)
		if fi.Mode().Perm() != 0o600 {
			t.Errorf("umask %o: mode = %o, want 600", umask, fi.Mode().Perm())
		}
		l := logOver(t, f)
		if _, err := l.Append(t.Context(), agentRec()); err != nil {
			t.Errorf("umask %o: append: %v", umask, err)
		}
	}
}

func TestCreateFile_FailureRemovesTheFile(t *testing.T) { // NFR-4: a retry must not hit "already exists"
	t.Parallel()
	path := filepath.Join(secureDir(t), "audit.jsonl")
	boom := errors.New("check failed")
	// A failure after the lock is taken removes the file we created.
	_, err := openChecked(path, true, openHooks{afterLock: func(*os.File) error { return boom }})
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want the injected error", err)
	}
	if _, serr := os.Lstat(path); !errors.Is(serr, os.ErrNotExist) {
		t.Errorf("failed create left the file behind: %v", serr)
	}
	f, err := CreateFile(t.Context(), path)
	if err != nil {
		t.Fatalf("retry: %v", err)
	}
	_ = f.Close()
}

// flipCtx reports no error on its first Err call and Canceled afterwards, so it cancels between openAudit's
// entry check and load.
type flipCtx struct{ calls atomic.Int32 }

func (c *flipCtx) Deadline() (time.Time, bool) { return time.Time{}, false }
func (c *flipCtx) Done() <-chan struct{}       { return nil }
func (c *flipCtx) Value(any) any               { return nil }

func (c *flipCtx) Err() error {
	if c.calls.Add(1) == 1 {
		return nil
	}
	return context.Canceled
}

func TestCreateFile_LoadFailureRemovesTheFile(t *testing.T) { // NFR-4
	t.Parallel()
	path := filepath.Join(secureDir(t), "audit.jsonl")
	if _, err := CreateFile(&flipCtx{}, path); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want Canceled", err)
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("failed create left the file behind: %v", err)
	}
	f, err := CreateFile(t.Context(), path)
	if err != nil {
		t.Fatalf("retry: %v", err)
	}
	_ = f.Close()
}

// TestCreateFile_LosingTheLockRaceKeepsTheFile // NFR-4: a racing opener takes the lock between our create and
// our lock. We must fail with ErrLocked and must not unlink the file the winner is appending to.
func TestCreateFile_LosingTheLockRaceKeepsTheFile(t *testing.T) {
	t.Parallel()
	path := filepath.Join(secureDir(t), "audit.jsonl")
	var winner *File
	var winnerErr error
	hooks := openHooks{afterOpen: func() { winner, winnerErr = OpenFile(t.Context(), path) }}
	_, err := openChecked(path, true, hooks)
	if winnerErr != nil {
		t.Fatalf("racing opener: %v", winnerErr)
	}
	if !errors.Is(err, ErrLocked) {
		t.Fatalf("CreateFile err = %v, want ErrLocked", err)
	}
	l := logOver(t, winner)
	for range 3 {
		if _, err := l.Append(t.Context(), agentRec()); err != nil {
			t.Fatal(err)
		}
	}
	_ = winner.Close()
	l2, _ := reopenFileLog(t, path) // the path still names the winner's file
	if h, err := l2.Verify(t.Context()); err != nil || h.Seq != 3 {
		t.Errorf("Verify after reopen = %+v, %v; want the winner's 3 entries", h, err)
	}
}

// openRacing opens path (creating it, or opening an existing log) while a hook unlinks it, or unlinks it and puts a
// different file there, between the open and the lock.
func openRacing(t *testing.T, create, replace bool) (string, error) {
	t.Helper()
	path := filepath.Join(secureDir(t), "audit.jsonl")
	if !create {
		f, err := CreateFile(t.Context(), path)
		if err != nil {
			t.Fatal(err)
		}
		_ = f.Close()
	}
	hooks := openHooks{afterOpen: func() {
		if err := os.Remove(path); err != nil {
			t.Error(err)
		}
		if replace {
			if err := os.WriteFile(path, nil, 0o600); err != nil {
				t.Error(err)
			}
		}
	}}
	_, err := openChecked(path, create, hooks)
	return path, err
}

func TestOpenFile_RefusesAFileUnlinkedOrReplacedBeforeLocking(t *testing.T) { // NFR-4
	t.Parallel()
	for _, create := range []bool{false, true} {
		for _, replace := range []bool{false, true} {
			t.Run(fmt.Sprintf("create=%v replace=%v", create, replace), func(t *testing.T) {
				t.Parallel()
				path, err := openRacing(t, create, replace)
				if !errors.Is(err, ErrInsecureFile) {
					t.Errorf("err = %v, want ErrInsecureFile", err)
				}
				if _, serr := os.Lstat(path); replace && serr != nil {
					t.Errorf("the replacement file was removed: %v", serr)
				}
			})
		}
	}
}

func TestOwnership_ForeignOwnerIsRefused(t *testing.T) { // NFR-4
	t.Parallel()
	dir := secureDir(t)
	path := filepath.Join(dir, "audit.jsonl")
	f, err := CreateFile(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	me := os.Geteuid()

	fi, _ := os.Stat(path)
	st, _ := fi.Sys().(*syscall.Stat_t)
	if !ownedBy(st, me) || ownedBy(st, me+1) || ownedBy(nil, me) {
		t.Error("ownedBy gives the wrong answer")
	}

	raw, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	if err := checkFile(raw, me); err != nil {
		t.Errorf("own file refused: %v", err)
	}
	if err := checkFile(raw, me+1); !errors.Is(err, ErrInsecureFile) {
		t.Errorf("file owned by someone else: err = %v, want ErrInsecureFile", err)
	}
	if err := checkParent(dir, me+1); !errors.Is(err, ErrInsecureFile) {
		t.Errorf("directory owned by someone else: err = %v, want ErrInsecureFile", err)
	}
}

func TestOwnership_ChownedByRoot(t *testing.T) { // NFR-4
	t.Parallel()
	if os.Geteuid() != 0 {
		t.Skip("needs root to chown")
	}
	path, _ := buildFile(t, 1)
	if err := os.Chown(path, 65534, -1); err != nil {
		t.Skip(err)
	}
	if _, err := OpenFile(t.Context(), path); !errors.Is(err, ErrInsecureFile) {
		t.Errorf("file owned by 65534: err = %v, want ErrInsecureFile", err)
	}
	dir := filepath.Dir(path)
	if err := os.Chown(path, 0, -1); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(dir, 65534, -1); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenFile(t.Context(), path); !errors.Is(err, ErrInsecureFile) {
		t.Errorf("directory owned by 65534: err = %v, want ErrInsecureFile", err)
	}
}

func TestFile_RefusesUnsafePaths(t *testing.T) { // NFR-4
	t.Parallel()
	t.Run("hard link", func(t *testing.T) {
		t.Parallel()
		path, _ := buildFile(t, 1)
		if err := os.Link(path, path+".copy"); err != nil {
			t.Skipf("hard links unavailable: %v", err)
		}
		if _, err := OpenFile(t.Context(), path); !errors.Is(err, ErrInsecureFile) {
			t.Errorf("err = %v, want ErrInsecureFile", err)
		}
	})
	t.Run("group-writable parent directory", func(t *testing.T) {
		t.Parallel()
		dir := secureDir(t)
		path := filepath.Join(dir, "audit.jsonl")
		created, err := CreateFile(t.Context(), path)
		if err != nil {
			t.Fatal(err)
		}
		_ = created.Close()
		if err := os.Chmod(dir, 0o770); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
		if _, err := OpenFile(t.Context(), path); !errors.Is(err, ErrInsecureFile) {
			t.Errorf("OpenFile err = %v, want ErrInsecureFile", err)
		}
		if _, err := CreateFile(t.Context(), filepath.Join(dir, "other.jsonl")); !errors.Is(err, ErrInsecureFile) {
			t.Errorf("CreateFile err = %v, want ErrInsecureFile", err)
		}
	})
	t.Run("symlinked parent directory", func(t *testing.T) {
		t.Parallel()
		realDir := secureDir(t)
		path := filepath.Join(realDir, "audit.jsonl")
		f, err := CreateFile(t.Context(), path)
		if err != nil {
			t.Fatal(err)
		}
		_ = f.Close()
		linkDir := filepath.Join(secureDir(t), "dirlink")
		if err := os.Symlink(realDir, linkDir); err != nil {
			t.Fatal(err)
		}
		// Only the final directory component is protected; earlier components are followed (documented).
		if _, err := OpenFile(t.Context(), filepath.Join(linkDir, "audit.jsonl")); err == nil {
			t.Error("OpenFile followed a symlinked parent directory")
		}
	})
	t.Run("fifo", func(t *testing.T) {
		t.Parallel()
		path := filepath.Join(secureDir(t), "audit.jsonl")
		if err := syscall.Mkfifo(path, 0o600); err != nil {
			t.Skipf("mkfifo unavailable: %v", err)
		}
		if _, err := OpenFile(t.Context(), path); !errors.Is(err, ErrInsecureFile) {
			t.Errorf("err = %v, want ErrInsecureFile", err)
		}
	})
	t.Run("unreadable by owner", func(t *testing.T) {
		t.Parallel()
		path, _ := buildFile(t, 1)
		if err := os.Chmod(path, 0o400); err != nil {
			t.Fatal(err)
		}
		// Non-root users cannot even open it; root reaches the mode check.
		if _, err := OpenFile(t.Context(), path); err == nil {
			t.Error("a file without owner read and write was opened")
		}
	})
}

func TestFile_LoadHonorsContext(t *testing.T) { // NFR-4
	t.Parallel()
	path, _ := buildFile(t, 3)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := OpenFile(ctx, path); !errors.Is(err, context.Canceled) {
		t.Errorf("OpenFile err = %v, want Canceled", err)
	}
	f, err := openLocked(path, false)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	af := &File{f: f, syncFile: f.Sync}
	if err := af.load(ctx); !errors.Is(err, context.Canceled) {
		t.Errorf("load err = %v, want Canceled", err)
	}
	if len(af.lines) != 0 {
		t.Error("load indexed lines after cancellation")
	}
}
