// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

// Package contract defines the .factory.yaml contract schema (v1alpha1), parses
// untrusted contract files with a fail-closed pipeline, and discovers contracts
// in a repository tree (CON-1, CON-4, CON-11).
//
// A contract file is repo content and untrusted. Parsing rejects YAML features
// that hide content (aliases, anchors, merge keys, custom tags, duplicate keys),
// validates against an embedded JSON Schema that rejects unknown fields, and
// then strictly decodes into Go types.
//
// [Compile] turns a [Set] into a [Policy] after relational validation: a child
// contract can only tighten its ancestors' safety fields and the factory
// baseline (CON-3, CON-5, CON-12). [Policy.Resolve] returns the effective
// contract for a change, with the source of every value.
//
// Path patterns are anchored at the directory of the contract that declares
// them. In certs/.factory.yaml, "*.pem" matches certs/x.pem but not
// certs/a/x.pem, and a contract's patterns never match outside its directory.
// Write "**/*.pem" to match at any depth. The forbidden, readOnly and sensitive
// lists also deny everything below a matched path and match folded variants of
// it (CON-7). A forbidden or sensitive match in any form counts. A readOnly
// match that exists only in a folded form caps a level's verdict at read-only
// and never raises it.
//
// A path with a form that is not a valid path, or one that costs too much to
// evaluate, is an error from [Policy.ForPath] and [Policy.Resolve], never an
// "allowed" result. Raw repository path text in results must be escaped by any
// consumer that writes it to a PR comment, check run or log.
package contract
