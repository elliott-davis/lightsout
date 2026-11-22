// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

package oracle

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
)

// configDomain separates the config digest from every other SHA-256 the factory computes.
const configDomain = "lightsout.oracle-config/v1"

// DeriveConfig is the config digest of the release defaults with switch overrides applied: what a first-introduction
// run (PIP-13) requests for the candidate. The harness must reproduce it exactly.
//
// With no overrides it returns releaseDefaults unchanged. Otherwise it returns "sha256:" followed by the lowercase
// hex SHA-256 of this byte sequence, where str(s) is the 8-byte big-endian length of s followed by its bytes:
//
//	str("lightsout.oracle-config/v1") str(releaseDefaults) count
//	str(key1) str(value1) str(key2) str(value2) ...
//
// count is the number of overrides as 8-byte big-endian. Pairs are sorted by key in byte order. Lengths make the
// encoding unambiguous for any keys and values.
func DeriveConfig(releaseDefaults string, overrides map[string]string) string {
	if len(overrides) == 0 {
		return releaseDefaults
	}
	h := sha256.New()
	str := func(s string) {
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], uint64(len(s)))
		h.Write(n[:])
		h.Write([]byte(s))
	}
	str(configDomain)
	str(releaseDefaults)
	var n [8]byte
	binary.BigEndian.PutUint64(n[:], uint64(len(overrides)))
	h.Write(n[:])
	keys := make([]string, 0, len(overrides))
	for k := range overrides {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	for _, k := range keys {
		str(k)
		str(overrides[k])
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}

// smallOrder lists the encodings of the Ed25519 points of small order, with the sign bit cleared: the identity, the
// other points of order 2, 4 and 8, and the non-canonical encodings of the identity and of y = 0 and y = -1 (y of
// p, p+1 and p-1, which encode the same points). A signature (R, 0) with R such a point verifies for every message
// under such a key, so a key like that signs for anyone.
var smallOrder = [][32]byte{
	smallOrderKey("0000000000000000000000000000000000000000000000000000000000000000"),
	smallOrderKey("0100000000000000000000000000000000000000000000000000000000000000"),
	smallOrderKey("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05"),
	smallOrderKey("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a"),
	smallOrderKey("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
	smallOrderKey("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
	smallOrderKey("eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
}

func smallOrderKey(h string) [32]byte {
	var out [32]byte
	b, err := hex.DecodeString(h)
	if err != nil || len(b) != len(out) {
		panic("oracle: bad small-order constant") // programmer error
	}
	copy(out[:], b)
	return out
}

// ValidHarnessKey reports why pub cannot be a harness key: a wrong size, or a small-order point (including the
// identity), which would accept a forged signature for any message. WI-12 calls it at registration; Evaluate
// rejects such keys as invalid input too.
func ValidHarnessKey(pub ed25519.PublicKey) error {
	if len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("harness key is %d bytes, want %d", len(pub), ed25519.PublicKeySize)
	}
	var k [32]byte
	copy(k[:], pub)
	k[31] &^= 0x80 // the sign bit does not change the order of the point
	if slices.Contains(smallOrder, k) {
		return errors.New("harness key is a small-order point")
	}
	return nil
}
