// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

// Package oracle decides whether a change's dark-merge oracle shows it to be observably neutral against the queue
// baseline, or to differ only by an authorized Fix delta (PIP-13, PIP-4, INT-10).
//
// Evaluate is pure: it takes the effective contract and the inputs the caller (WI-18) fetched, and does no I/O. The
// oracle job is a gate of record, so its execution is judged by [gate.Evaluate]; its report is untrusted (the job
// runs candidate code) and is parsed strictly. ValidateManifest checks a case manifest, and DeriveConfig computes
// the config digest the harness must reproduce for a first-introduction run. See docs/design/oracle.md.
//
// A pass establishes only the comparison. A dark Feature still needs Acceptance (PIP-3).
package oracle
