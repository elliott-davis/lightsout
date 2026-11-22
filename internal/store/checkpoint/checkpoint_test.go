// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

package checkpoint_test

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/elliott-davis/lightsout/internal/audit"
	"github.com/elliott-davis/lightsout/internal/store/checkpoint"
)

func TestFileRoundTrip(t *testing.T) { // NFR-4
	t.Parallel()
	dir := t.TempDir()
	f, err := checkpoint.NewFile(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok, lerr := f.Load(t.Context(), "decision"); lerr != nil || ok {
		t.Fatalf("empty sink: ok=%v err=%v", ok, lerr)
	}
	want := checkpoint.Checkpoint{Chain: "decision", Seq: 3, Hash: audit.Hash{1, 2, 3}}
	if err = f.Save(t.Context(), want); err != nil {
		t.Fatal(err)
	}
	got, ok, err := f.Load(t.Context(), "decision")
	if err != nil || !ok || got != want {
		t.Fatalf("got %+v ok=%v err=%v, want %+v", got, ok, err, want)
	}
	left, _ := filepath.Glob(filepath.Join(dir, ".*tmp*"))
	if len(left) != 0 {
		t.Fatalf("temp files left behind: %v", left)
	}
}

func TestFileRefusesRegression(t *testing.T) { // NFR-4 negative
	t.Parallel()
	f, _ := checkpoint.NewFile(t.TempDir())
	if err := f.Save(t.Context(), checkpoint.Checkpoint{Chain: "denial", Seq: 5, Hash: audit.Hash{5}}); err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]checkpoint.Checkpoint{
		"lower seq":      {Chain: "denial", Seq: 4, Hash: audit.Hash{4}},
		"same seq, hash": {Chain: "denial", Seq: 5, Hash: audit.Hash{9}},
	} {
		if err := f.Save(t.Context(), c); !errors.Is(err, checkpoint.ErrRegression) {
			t.Errorf("%s: err = %v, want ErrRegression", name, err)
		}
	}
	// Saving the same checkpoint again is fine.
	if err := f.Save(t.Context(), checkpoint.Checkpoint{Chain: "denial", Seq: 5, Hash: audit.Hash{5}}); err != nil {
		t.Errorf("idempotent save: %v", err)
	}
}

func TestFileRejectsBadInput(t *testing.T) { // NFR-4 negative
	t.Parallel()
	dir := t.TempDir()
	f, _ := checkpoint.NewFile(dir)
	for _, chain := range []string{"", "../x", "a/b", "A", "x.y"} {
		if err := f.Save(t.Context(), checkpoint.Checkpoint{Chain: chain, Seq: 1, Hash: audit.Hash{1}}); !errors.Is(err, checkpoint.ErrInvalid) {
			t.Errorf("save chain %q: err = %v, want ErrInvalid", chain, err)
		}
		if _, _, err := f.Load(t.Context(), chain); !errors.Is(err, checkpoint.ErrInvalid) {
			t.Errorf("load chain %q: err = %v, want ErrInvalid", chain, err)
		}
	}
	// A corrupt file, a file for another chain and unknown fields are errors, never "no checkpoint".
	for name, body := range map[string]string{
		"corrupt":    "{",
		"other":      `{"chain":"denial","seq":0,"hash":"` + audit.Hash{}.String() + `"}`,
		"unknownfld": `{"chain":"decision","seq":0,"hash":"` + audit.Hash{}.String() + `","x":1}`,
		"hashnoseq":  `{"chain":"decision","seq":0,"hash":"` + audit.Hash{1}.String() + `"}`,
	} {
		if err := os.WriteFile(filepath.Join(dir, "decision.checkpoint.json"), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, ok, err := f.Load(t.Context(), "decision"); err == nil || ok {
			t.Errorf("%s: ok=%v err=%v, want an error", name, ok, err)
		}
	}
	if _, err := checkpoint.NewFile(filepath.Join(dir, "missing")); err == nil {
		t.Error("NewFile on a missing directory succeeded")
	}
}
