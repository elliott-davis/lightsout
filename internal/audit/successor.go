// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

package audit

// CheckSuccessor reports whether e is the valid next entry after prev: the format, the sequence number, the
// previous-hash link, the time, the record's validity and the recomputed hash. It is what [Log.Verify] applies to
// each entry, exported so a [Backend] can refuse a sealed entry that does not extend its head. A failure is a
// *[ChainError] wrapping [ErrBrokenChain] and names position prev.Seq+1.
func CheckSuccessor(prev Head, e Entry) error { return checkLink(prev, e) }
