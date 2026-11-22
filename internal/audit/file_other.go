// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !(darwin || dragonfly || freebsd || linux || netbsd || openbsd)

package audit

import (
	"errors"
	"fmt"
	"os"
)

func openLocked(string, bool) (*os.File, error) {
	return nil, fmt.Errorf("audit file backend is not supported on this platform: %w", errors.ErrUnsupported)
}

// removeCreated is never reached where the file backend is unsupported.
func removeCreated(string, *os.File) {}
