// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

// Package install parses and validates the install config: the one source of the factory's defaults.
//
// The install config holds defaults for timers and caps, the factory baseline (mandatory gates, core reviewers,
// protected paths), the gate registry, the policy approvers and emergency admins, one pinned runtime, harness and
// model profile per enabled role, and the keys that verify qualification records. It lives in git and the factory
// loads only an activated revision (RUN-1).
//
// [Parse] reads untrusted YAML with the same bounded pipeline as contracts (see [yamlsafe]), checks it against the
// embedded schema, decodes it strictly and then applies the semantic rules in docs/design/install.md. It fails
// closed: any problem returns a [*ValidationError] and no [Config]. A [Config] is immutable. Its methods return
// copies, so a caller cannot change what another caller sees.
//
// Nothing else in the factory hard-codes a default this package produces. The outputs are [Config.Baseline],
// [Config.Defaults], [Config.GateRegistry], [Config.AuthzConfig], [Config.RoleSource], [Config.Role],
// [Config.Timers] and [Config.Quotas]. [Config.Admit] runs the qualification check before a role is scheduled (NFR-2).
package install
