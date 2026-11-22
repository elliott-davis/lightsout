// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"crypto/sha256"
	"encoding/binary"
	"hash"
)

const hashDomain = "lightsout-audit"

// computeHash is the single definition of the entry hash: SHA-256 over an unambiguous, length-prefixed binary
// encoding of the domain tag, Format, Seq, Time (UnixMicro), every Record field in a fixed order, the attributes
// sorted by key, and PrevHash. Every variable-length field is prefixed with its uint64 length, so no two distinct
// entries share an encoding. The result field e.Hash is not part of the input. There is no JSON in here: do not
// change this function without bumping FormatVersion.
//
// Encoding notes: Decision and Link each start with a presence byte (0 or 1). A Decision is followed by its
// operation, role, revision, verdict and reason, and a Link by its kind, repo and ID, all length-prefixed. The Link
// block sits between the Decision block and the attribute count. It was added before any log was released, so
// FormatVersion stays 1.
func computeHash(e Entry) Hash {
	w := encoder{h: sha256.New()}
	w.str(hashDomain)
	w.u64(uint64(e.Format)) //nolint:gosec // Format is a small non-negative constant
	w.u64(e.Seq)
	w.u64(uint64(e.Time.UnixMicro()))

	w.str(string(e.Actor.Kind))
	w.str(e.Actor.ID)
	w.str(e.Actor.Display)
	w.str(e.TemplateVersion)
	w.str(string(e.Subject.Kind))
	w.str(e.Subject.Repo)
	w.str(e.Subject.ID)
	w.str(string(e.Action))
	w.str(e.Target)
	w.str(e.Outcome)
	if d := e.Decision; d != nil {
		w.h.Write([]byte{1})
		w.str(d.Operation)
		w.str(d.Role)
		w.str(d.Revision)
		w.str(string(d.Verdict))
		w.str(d.Reason)
	} else {
		w.h.Write([]byte{0})
	}
	if l := e.Link; l != nil {
		w.h.Write([]byte{1})
		w.str(string(l.Kind))
		w.str(l.Repo)
		w.str(l.ID)
	} else {
		w.h.Write([]byte{0})
	}
	w.u64(uint64(len(e.Attrs)))
	for _, k := range sortedKeys(e.Attrs) {
		w.str(k)
		w.str(e.Attrs[k])
	}
	w.h.Write(e.PrevHash[:])

	var out Hash
	w.h.Sum(out[:0])
	return out
}

type encoder struct{ h hash.Hash }

func (w encoder) u64(v uint64) {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], v)
	w.h.Write(b[:])
}

func (w encoder) str(s string) {
	w.u64(uint64(len(s)))
	w.h.Write([]byte(s))
}
