// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package audit

import (
	"errors"
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

// hasACL reports whether f carries a POSIX ACL xattr: the access ACL, and for directories the default ACL too.
// It uses fgetxattr on the descriptor, so it needs no /proc and cannot be redirected by a path swap. ENODATA means
// no ACL, and so does a filesystem without xattr support; any other error fails closed.
func hasACL(f *os.File, dir bool) (bool, error) {
	names := []string{"system.posix_acl_access"}
	if dir {
		names = append(names, "system.posix_acl_default")
	}
	rc, err := f.SyscallConn()
	if err != nil {
		return false, fmt.Errorf("get descriptor: %w", err)
	}
	for _, name := range names {
		p, err := syscall.BytePtrFromString(name)
		if err != nil {
			return false, err
		}
		var errno syscall.Errno
		if err := rc.Control(func(fd uintptr) {
			// A zero-size buffer asks for the attribute's size without reading it. p is a live NUL-terminated string.
			_, _, errno = syscall.Syscall6(syscall.SYS_FGETXATTR, fd, uintptr(unsafe.Pointer(p)), 0, 0, 0, 0)
		}); err != nil {
			return false, fmt.Errorf("get descriptor: %w", err)
		}
		switch {
		case errno == 0:
			return true, nil
		case errors.Is(errno, syscall.ENODATA), errors.Is(errno, syscall.ENOTSUP):
		default:
			return false, errno
		}
	}
	return false, nil
}
