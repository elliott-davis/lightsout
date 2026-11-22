// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

package install

import (
	"encoding/json"
	"testing"
)

// TestInstallIDPatternMatchesSchema keeps the pattern ActivationRevision checks equal to the schema's installation ID,
// so an ID the schema accepts is never refused when a decision binds to it, and the reverse.
func TestInstallIDPatternMatchesSchema(t *testing.T) { // RUN-1
	t.Parallel()
	var s struct {
		Properties struct {
			Installation struct {
				Properties struct {
					ID struct {
						Pattern string `json:"pattern"`
					} `json:"id"`
				} `json:"properties"`
			} `json:"installation"`
		} `json:"properties"`
	}
	if err := json.Unmarshal(schemaJSON, &s); err != nil {
		t.Fatal(err)
	}
	if got, want := installIDPattern.String(), s.Properties.Installation.Properties.ID.Pattern; got != want || want == "" {
		t.Errorf("installIDPattern = %q, schema installation.id pattern = %q", got, want)
	}
}
