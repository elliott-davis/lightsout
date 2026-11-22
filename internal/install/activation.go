// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

package install

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"regexp"
)

const activationDomain = "lightsout/install-activation/v1\n"

// installIDPattern is the schema's installation ID.
var installIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$`)

// ActivationRevision returns the value an approver's decision binds to when it approves activating candidate as the
// successor of the active generation of installID. It is the authz.Target.Revision of [authz.OpActivateInstall] (and
// the Decision.Revision the approver names): the lowercase hex SHA-256 of
//
//	"lightsout/install-activation/v1\n"
//	u64(len(installID)) installID
//	u64(8) u64(generation)
//	u64(len(candidate)) candidate
//
// where u64 is 8 big-endian bytes. Binding the generation means a decision made for one generation can never activate
// from another, and binding the commit means it can never activate another candidate. Authz can't check either on its
// own: the activation path (WI-10) computes the value from the store's current generation, so a decision bound to an
// earlier one fails authz's revision check, and must be denied.
//
// It returns an error for an empty installID or one outside the schema's install ID form, and for a candidate that is
// not 40 or 64 lowercase hex digits.
func ActivationRevision(installID string, generation uint64, candidate string) (string, error) {
	if !installIDPattern.MatchString(installID) {
		return "", fmt.Errorf("activation revision: install ID %s is not a valid install ID", q(installID))
	}
	if !revisionPattern.MatchString(candidate) {
		return "", fmt.Errorf("activation revision: candidate %s must be 40 or 64 lowercase hex digits", q(candidate))
	}
	h := sha256.New()
	h.Write([]byte(activationDomain))
	field := func(b []byte) {
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], uint64(len(b)))
		h.Write(n[:])
		h.Write(b)
	}
	var gen [8]byte
	binary.BigEndian.PutUint64(gen[:], generation)
	field([]byte(installID))
	field(gen[:])
	field([]byte(candidate))
	return hex.EncodeToString(h.Sum(nil)), nil
}
