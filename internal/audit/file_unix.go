// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

//go:build darwin || dragonfly || freebsd || linux || netbsd || openbsd

package audit

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
)

// openLocked opens the audit file and takes an exclusive non-blocking flock that Close releases. See [File] for
// what is checked.
func openLocked(path string, create bool) (*os.File, error) {
	return openChecked(path, create, openHooks{})
}

// openHooks lets tests act inside the windows between steps. A nil hook does nothing (lock defaults to flock).
type openHooks struct {
	afterOpen func()               // after the file is opened or created, before it is locked
	lock      func(*os.File) error // replaces the flock
	afterLock func(*os.File) error // after locking, before the checks; an error fails the open
}

// openChecked opens the file, locks it at once, and runs every check while holding the lock. When create is set
// the file must not exist. If a step after the lock fails, the new file is removed (while still locked, and only
// if the path still names the file we created) so a retry does not hit "already exists". If the lock itself fails,
// the file is left alone: another writer may legitimately hold it.
func openChecked(path string, create bool, h openHooks) (*os.File, error) {
	euid := os.Geteuid()
	if err := checkParent(filepath.Dir(path), euid); err != nil {
		return nil, err
	}
	flags := os.O_RDWR | os.O_APPEND | syscall.O_NOFOLLOW
	if create {
		flags |= os.O_CREATE | os.O_EXCL
	} else if fi, err := os.Lstat(path); err != nil {
		return nil, fmt.Errorf("open audit file: %w", err)
	} else if !fi.Mode().IsRegular() && fi.Mode()&fs.ModeSymlink == 0 {
		// Do not open FIFOs, devices and the like at all. Symlinks are refused by O_NOFOLLOW below.
		return nil, fmt.Errorf("%w: not a regular file", ErrInsecureFile)
	}
	f, err := os.OpenFile(path, flags, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open audit file: %w", err)
	}
	if h.afterOpen != nil {
		h.afterOpen()
	}
	lock := lockFile
	if h.lock != nil {
		lock = h.lock
	}
	if err := lock(f); err != nil {
		_ = f.Close() // never remove: the holder of the lock may be using this file
		return nil, err
	}
	fail := func(err error) (*os.File, error) {
		if create {
			removeCreated(path, f)
		}
		_ = f.Close()
		return nil, err
	}
	if h.afterLock != nil {
		if err := h.afterLock(f); err != nil {
			return fail(err)
		}
	}
	if create {
		// The umask may have removed owner permissions.
		if err := f.Chmod(0o600); err != nil {
			return fail(fmt.Errorf("chmod new audit file: %w", err))
		}
	}
	if err := checkFile(f, euid); err != nil {
		return fail(err)
	}
	if err := sameInode(path, f); err != nil {
		return fail(err)
	}
	if create {
		if err := syncDir(filepath.Dir(path)); err != nil {
			return fail(err)
		}
	}
	return f, nil
}

// sameInode requires that path still names the file f was opened on, so a file unlinked or replaced before it was
// locked is refused.
func sameInode(path string, f *os.File) error {
	pi, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("%w: path no longer names the opened file: %w", ErrInsecureFile, err)
	}
	fi, err := f.Stat()
	if err != nil {
		return fmt.Errorf("stat audit file: %w", err)
	}
	if !os.SameFile(pi, fi) {
		return fmt.Errorf("%w: path was replaced while opening", ErrInsecureFile)
	}
	return nil
}

// removeCreated unlinks path if it still names f. The caller holds the lock on f.
func removeCreated(path string, f *os.File) {
	if sameInode(path, f) == nil {
		_ = os.Remove(path)
	}
}

// checkParent requires the directory to be a real directory (not a symlink as its final component), owned by
// euid, not writable by group or others, and without a POSIX ACL.
func checkParent(dir string, euid int) error {
	d, err := os.OpenFile(dir, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return fmt.Errorf("open audit directory: %w", err)
	}
	defer d.Close()
	fi, err := d.Stat()
	if err != nil {
		return fmt.Errorf("stat audit directory: %w", err)
	}
	if !fi.IsDir() {
		return fmt.Errorf("%w: parent is not a directory", ErrInsecureFile)
	}
	if fi.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%w: directory mode %04o is writable by group or others", ErrInsecureFile, fi.Mode().Perm())
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); !ok || !ownedBy(st, euid) {
		return fmt.Errorf("%w: directory is not owned by the current user", ErrInsecureFile)
	}
	if has, err := hasACL(d, true); err != nil {
		return fmt.Errorf("check audit directory ACL: %w", err)
	} else if has {
		return fmt.Errorf("%w: directory has a POSIX ACL", ErrInsecureFile)
	}
	return nil
}

// ownedBy reports whether the file with this stat is owned by uid.
func ownedBy(st *syscall.Stat_t, uid int) bool {
	return st != nil && int64(st.Uid) == int64(uid)
}

func checkFile(f *os.File, euid int) error {
	fi, err := f.Stat()
	if err != nil {
		return fmt.Errorf("stat audit file: %w", err)
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("%w: not a regular file", ErrInsecureFile)
	}
	if fi.Mode().Perm()&0o600 != 0o600 {
		return fmt.Errorf("%w: mode %04o lacks owner read and write", ErrInsecureFile, fi.Mode().Perm())
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%w: mode %04o grants group or other access", ErrInsecureFile, fi.Mode().Perm())
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || !ownedBy(st, euid) {
		return fmt.Errorf("%w: not owned by the current user", ErrInsecureFile)
	}
	if st.Nlink != 1 {
		return fmt.Errorf("%w: file has %d hard links", ErrInsecureFile, st.Nlink)
	}
	if has, err := hasACL(f, false); err != nil {
		return fmt.Errorf("check audit file ACL: %w", err)
	} else if has {
		return fmt.Errorf("%w: file has a POSIX ACL", ErrInsecureFile)
	}
	return nil
}

func lockFile(f *os.File) error {
	rc, err := f.SyscallConn()
	if err != nil {
		return fmt.Errorf("lock audit file: %w", err)
	}
	var lockErr error
	if err := rc.Control(func(fd uintptr) {
		lockErr = syscall.Flock(int(fd), syscall.LOCK_EX|syscall.LOCK_NB)
	}); err != nil {
		return fmt.Errorf("lock audit file: %w", err)
	}
	switch {
	case lockErr == nil:
		return nil
	case errors.Is(lockErr, syscall.EWOULDBLOCK):
		return ErrLocked
	}
	return fmt.Errorf("lock audit file: %w", lockErr)
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("open audit directory: %w", err)
	}
	if err := d.Sync(); err != nil {
		_ = d.Close()
		return fmt.Errorf("fsync audit directory: %w", err)
	}
	return d.Close()
}
