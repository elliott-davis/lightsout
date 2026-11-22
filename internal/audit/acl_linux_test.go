// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package audit

import (
	"encoding/binary"
	"errors"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// posixACL returns a valid ACL granting one extra user read access with a zero mask. The zero mask keeps the
// file's mode at 0600 (a non-zero mask would show up in the group bits and trip the mode check first), so a
// refusal can only come from the ACL check.
func posixACL() []byte {
	b := binary.LittleEndian.AppendUint32(nil, 2) // POSIX_ACL_XATTR_VERSION
	ent := func(tag, perm uint16, id uint32) {
		b = binary.LittleEndian.AppendUint16(b, tag)
		b = binary.LittleEndian.AppendUint16(b, perm)
		b = binary.LittleEndian.AppendUint32(b, id)
	}
	const none = 0xffffffff
	ent(0x01, 7, none)  // USER_OBJ rwx
	ent(0x02, 4, 12345) // USER r
	ent(0x04, 0, none)  // GROUP_OBJ
	ent(0x10, 0, none)  // MASK, zero
	ent(0x20, 0, none)  // OTHER
	return b
}

// plantACL sets the xattr, skipping the test where the filesystem cannot hold POSIX ACLs.
func plantACL(t *testing.T, path, name string) {
	t.Helper()
	if err := syscall.Setxattr(path, name, posixACL(), 0); err != nil {
		t.Skipf("filesystem does not support POSIX ACLs here: %v", err)
	}
}

func assertACLRefusal(t *testing.T, err error) {
	t.Helper()
	if !errors.Is(err, ErrInsecureFile) || !strings.Contains(err.Error(), "POSIX ACL") {
		t.Errorf("err = %v, want ErrInsecureFile from the ACL check", err)
	}
}

func TestFile_RefusesPOSIXACLs(t *testing.T) { // NFR-4
	t.Parallel()
	t.Run("file access ACL", func(t *testing.T) {
		t.Parallel()
		path, _ := buildFile(t, 1)
		plantACL(t, path, "system.posix_acl_access")
		_, err := OpenFile(t.Context(), path)
		assertACLRefusal(t, err)
	})
	t.Run("directory access ACL", func(t *testing.T) {
		t.Parallel()
		path, _ := buildFile(t, 1)
		plantACL(t, filepath.Dir(path), "system.posix_acl_access")
		_, err := OpenFile(t.Context(), path)
		assertACLRefusal(t, err)
		_, err = CreateFile(t.Context(), filepath.Join(filepath.Dir(path), "other.jsonl"))
		assertACLRefusal(t, err)
	})
	t.Run("directory default ACL", func(t *testing.T) {
		t.Parallel()
		path, _ := buildFile(t, 1)
		plantACL(t, filepath.Dir(path), "system.posix_acl_default")
		_, err := OpenFile(t.Context(), path)
		assertACLRefusal(t, err)
		_, err = CreateFile(t.Context(), filepath.Join(filepath.Dir(path), "other.jsonl"))
		assertACLRefusal(t, err)
	})
}
