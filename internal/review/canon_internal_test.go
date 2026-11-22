// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

package review

import "testing"

func TestDomains_SeparateIdenticalBodies(t *testing.T) { // AGT-3
	t.Parallel()
	domains := map[string]string{
		"attestation": attestationDomain, "resolution": resolutionDomain, "manifest": manifestDomain,
		"approval": approvalDomain, "area": areaDomain, "assignment": assignmentDomain, "claim": claimDomain,
	}
	body := struct {
		X string `json:"x"`
	}{"same body"}
	seen := map[string]string{}
	for name, d := range domains {
		sum := hexSum(canonical(d, body))
		if other, ok := seen[sum]; ok {
			t.Errorf("domains of %s and %s give the same digest over an identical body", name, other)
		}
		seen[sum] = name
		if d == "" || d[len(d)-1] != '\n' {
			t.Errorf("%s domain %q isn't newline-terminated", name, d)
		}
	}
	if len(seen) != len(domains) {
		t.Error("two domains collide")
	}
}
