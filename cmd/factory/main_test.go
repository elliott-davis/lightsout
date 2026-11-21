// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/elliott-davis/lightsout/internal/version"
)

func TestRun(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		args       []string
		wantErr    bool
		wantStdout string
		wantStderr string
	}{
		{name: "version", args: []string{"--version"}, wantStdout: version.String()},
		{name: "no args", wantErr: true, wantStderr: "usage: factory"},
		{name: "bad flag", args: []string{"--nope"}, wantErr: true, wantStderr: "flag provided but not defined"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var stdout, stderr bytes.Buffer
			err := run(context.Background(), tt.args, &stdout, &stderr)
			if (err != nil) != tt.wantErr {
				t.Fatalf("run() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !strings.Contains(stdout.String(), tt.wantStdout) {
				t.Errorf("stdout = %q, want it to contain %q", stdout.String(), tt.wantStdout)
			}
			if !strings.Contains(stderr.String(), tt.wantStderr) {
				t.Errorf("stderr = %q, want it to contain %q", stderr.String(), tt.wantStderr)
			}
		})
	}
}
