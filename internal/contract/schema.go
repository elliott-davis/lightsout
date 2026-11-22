// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

package contract

import (
	_ "embed"
	"slices"
)

//go:embed schema/v1alpha1.json
var schemaJSON []byte

// SchemaJSON returns a copy of the embedded v1alpha1 JSON Schema.
func SchemaJSON() []byte {
	return slices.Clone(schemaJSON)
}
