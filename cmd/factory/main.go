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

	"github.com/elliott-davis/lightsout/internal/contract"
	"github.com/elliott-davis/lightsout/internal/version"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	err := run(ctx, os.Args[1:], os.Stdout, os.Stderr)
	stop()
	if err != nil {
		printError(os.Stderr, err)
		os.Exit(1)
	}
}

var errUsage = errors.New("usage")

// printError writes err to w for a person or a CI log. Error text can carry
// repository paths and command-line arguments, which are untrusted, so it is
// escaped like any other repository text: control and format characters,
// invalid UTF-8, backslashes and '#' cannot forge a line or a workflow command.
func printError(w io.Writer, err error) {
	fmt.Fprintln(w, "factory:", contract.EscapeText(err.Error()))
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	if len(args) > 0 {
		switch args[0] {
		case "contract":
			return runContract(ctx, args[1:], stdout, stderr)
		case "install":
			return runInstall(ctx, args[1:], stdout, stderr)
		}
	}
	fs := flag.NewFlagSet("factory", flag.ContinueOnError)
	showVersion := fs.Bool("version", false, "print version and exit")
	if err := parseFlags(fs, args, stderr, "usage: factory [--version] | contract <command> | install <command>\n"); err != nil {
		return fmt.Errorf("parse flags: %w", err)
	}
	if *showVersion {
		_, err := fmt.Fprintln(stdout, version.String())
		return err
	}
	fmt.Fprintln(stderr, "usage: factory [--version] | contract <command> | install <command>")
	fs.PrintDefaults()
	return errUsage
}
