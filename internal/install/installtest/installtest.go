// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

// Package installtest helps tests of install config and admission sign qualification records and serve them from
// memory. It uses deterministic keys, so a fixture's digests are stable.
package installtest

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"sync"

	"github.com/elliott-davis/lightsout/internal/install"
)

// SuiteRevision is the qualification suite revision test records carry.
const SuiteRevision = "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a"

// QualifiedAt is the time test records carry.
const QualifiedAt = "2026-11-21T00:00:00Z"

// Signer signs qualification records with a key derived from a seed text.
type Signer struct {
	KeyID string
	priv  ed25519.PrivateKey
}

// NewSigner returns a signer for keyID whose key derives from seed. The same seed gives the same key and
// signatures: two signers with the same keyID and different seeds model a forger of a known key ID.
func NewSigner(keyID, seed string) *Signer {
	sum := sha256.Sum256([]byte("installtest/" + seed))
	return &Signer{KeyID: keyID, priv: ed25519.NewKeyFromSeed(sum[:])}
}

// PublicKey returns the base64 public key, as an install config lists it under qualifierKeys.
func (s *Signer) PublicKey() string {
	return base64.StdEncoding.EncodeToString(s.priv[ed25519.SeedSize:]) // the last 32 bytes of the private key are the public key
}

// Record returns a signed record of result ("pass" or "fail") for tupleDigest.
func (s *Signer) Record(tupleDigest, result string) install.QualificationRecord {
	rec := install.QualificationRecord{
		TupleDigest:   tupleDigest,
		SuiteRevision: SuiteRevision,
		Result:        result,
		Evidence:      []string{"sha256:" + strings.Repeat("e", 64)},
		QualifiedAt:   QualifiedAt,
		KeyID:         s.KeyID,
	}
	return s.Sign(rec)
}

// Sign signs rec, replacing its KeyID and Signature.
func (s *Signer) Sign(rec install.QualificationRecord) install.QualificationRecord {
	rec.KeyID = s.KeyID
	rec.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(s.priv, rec.SigningBytes()))
	return rec
}

// Store is an in-memory content-addressed QualificationStore.
type Store struct {
	mu      sync.Mutex
	records map[string][]byte
}

// NewStore returns an empty store.
func NewStore() *Store { return &Store{records: map[string][]byte{}} }

// Put stores record bytes under their digest and returns it.
func (s *Store) Put(record []byte) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	d := install.RecordDigest(record)
	s.records[d] = record
	return d
}

// PutAs stores bytes under digest whatever they hash to, to model a store that returns the wrong bytes.
func (s *Store) PutAs(digest string, record []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.records[digest] = record
}

// Get implements install.QualificationStore.
func (s *Store) Get(_ context.Context, digest string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.records[digest]
	if !ok {
		return nil, install.ErrRecordNotFound
	}
	return append([]byte(nil), b...), nil
}

// Encode returns the stored form of rec and its digest.
func Encode(rec install.QualificationRecord) ([]byte, string) {
	data, err := rec.Marshal()
	if err != nil {
		panic("installtest: " + err.Error())
	}
	return data, install.RecordDigest(data)
}
