// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

// Package forge defines the domain types, capability interfaces and errors of the forge boundary (INTG-1).
//
// The forge is the source of record and everything it returns is untrusted input (SEC-1). Actors are identified
// by a stable ID, never a login. Gate evidence is a [JobExecution] with full provenance, never a check name
// (CON-4, PIP-2). Content is read at full commit SHAs. A truncated or partial result is an error
// ([ErrIncomplete]), never a short answer.
//
// The capability interfaces are exported so the in-memory fake and the adapters can be checked against one list.
// Consumers declare the small subset they use. The package imports nothing from the rest of the module, and only
// internal/forge/github may import go-github.
package forge
