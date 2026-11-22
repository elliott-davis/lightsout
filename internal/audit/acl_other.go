// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package audit

import "os"

// hasACL is not implemented off Linux: neither the file nor the directory is checked for ACLs, so the operator
// must make sure the audit directory carries none (documented on [File]).
func hasACL(*os.File, bool) (bool, error) { return false, nil }
