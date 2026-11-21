// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

// Command factory is the Lightsout control plane.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/elliott-davis/lightsout/internal/version"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	err := run(ctx, os.Args[1:], os.Stdout, os.Stderr)
	stop()
	if err != nil {
		fmt.Fprintln(os.Stderr, "factory:", err)
		os.Exit(1)
	}
}

var errUsage = errors.New("no command given")

func run(_ context.Context, args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("factory", flag.ContinueOnError)
	fs.SetOutput(stderr)
	showVersion := fs.Bool("version", false, "print version and exit")
	if err := fs.Parse(args); err != nil {
		return fmt.Errorf("parse flags: %w", err)
	}
	if *showVersion {
		_, err := fmt.Fprintln(stdout, version.String())
		return err
	}
	fmt.Fprintln(stderr, "usage: factory [--version]")
	fs.PrintDefaults()
	return errUsage
}
