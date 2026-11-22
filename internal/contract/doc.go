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
package contract
