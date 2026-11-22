// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

// Package holdout is the private holdout store (INT-6, INT-7, INT-9, AGT-2 store side).
//
// QE binds each ideator-approved public scenario to private executable material: test code, extra private cases,
// fixtures and assertions. If a coder, PR reviewer or customer CI could read that material, Acceptance would stop
// being an independent check (P4). A [Store] is the only way to reach it, and every call is authorized and
// audited.
//
// # Access
//
// A caller presents an opaque [Credential]. The store asks the [Verifier] for the [Workload] (role, repo, principal,
// session, assignment) and never takes identity from method arguments. Only four roles reach the store at all
// ([RoleQE], [RoleScenarioReviewer], [RoleAcceptanceScheduler], [RoleAcceptanceRunner]); every other role, an
// unverified credential and a workload of another repo is denied. Authorization happens before any backend lookup, so
// a denied caller gets the same [ErrDenied] and causes no backend read, whether or not the suite or revision exists.
// A runner is also denied with [ErrDenied] for every grant problem (unknown, other run, other assignment, expired,
// reused, fenced), so a runner learns nothing about grants it does not hold.
//
// # Revisions
//
// A suite revision is immutable and content-addressed: [Bundle.Revision] is "sha256:" plus the hex SHA-256 of a
// canonical encoding that length-prefixes every field (see [Bundle.Canonical]). The author is metadata, not part of
// the address. A revision moves through proposed, then active (after an independent scenario review) or rejected. It
// becomes stale when the approved intent moves on, frozen after a recorded Acceptance failure (PIP-15), and
// superseded when a reviewed successor or correction goes active.
//
// # Freshness
//
// At review, grant issue and open, the store checks inside one backend transaction that the current intent from the
// [IntentSource] is approved, has no pending unapproved edit, and equals the bundle's intent revision.
//
// # Audit
//
// Every call appends to the audit log, denials included. Success is appended before any private byte is returned or
// any state is committed, so a failed append releases and changes nothing. No entry contains private bytes.
//
// # Storage
//
// [Backend] is the storage port. The in-memory implementation in package memholdout is for tests and development
// only. A durable backend is a prerequisite for the first real Acceptance run, with no memory fallback in a
// production configuration.
package holdout
