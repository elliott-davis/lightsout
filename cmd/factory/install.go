// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/elliott-davis/lightsout/internal/install"
)

const installUsage = `usage: factory install <command>

commands:
  validate <file>                validate an install config; prints the problems or "ok"
`

// runInstall runs "factory install ...".
func runInstall(_ context.Context, args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return usageError(stderr, installUsage, "no install command given")
	}
	switch args[0] {
	case "validate":
		if len(args) != 2 {
			return usageError(stderr, installUsage, "validate takes exactly one file")
		}
		if _, err := loadInstall(stdout, args[1]); err != nil {
			return err
		}
		_, err := fmt.Fprintln(stdout, "ok")
		return err
	case "-h", "-help", "--help", "help":
		fmt.Fprint(stdout, installUsage)
		return nil
	default:
		return usageError(stderr, installUsage, "unknown install command %q", args[0])
	}
}

// loadInstall reads and validates an install config. Problems are printed to
// stdout one per line (their text is already escaped) and returned as an error
// that says how many.
func loadInstall(stdout io.Writer, name string) (*install.Config, error) {
	f, err := os.Open(name) //nolint:gosec // the operator names the file on the command line; this CLI reads whichever file it is told to
	if err != nil {
		return nil, fmt.Errorf("open install config: %w", err)
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, install.MaxFileSize+1))
	if err != nil {
		return nil, fmt.Errorf("read install config: %w", err)
	}
	cfg, err := install.Parse(data)
	if err != nil {
		var ve *install.ValidationError
		if !errors.As(err, &ve) {
			return nil, err
		}
		for _, p := range ve.Problems {
			fmt.Fprintln(stdout, p.String())
		}
		return nil, fmt.Errorf("install config validation failed: %d problem(s)", len(ve.Problems))
	}
	return cfg, nil
}
