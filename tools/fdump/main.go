// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

// Command fdump records what flagd core would serve from a file. It runs flagd's own load pipeline
// (utils.ConvertToJSON, then evaluator.JSON.SetState) and prints the store's flags as JSON. Its output is the
// expected side of internal/switches/testdata/flagd-differential.
//
// It lives in its own module so flagd and its dependencies never enter the factory's module graph or its
// offline bill of materials (NFR-8).
//
// Usage: fdump <file>
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/open-feature/flagd/core/pkg/evaluator"
	"github.com/open-feature/flagd/core/pkg/logger"
	"github.com/open-feature/flagd/core/pkg/store"
	"github.com/open-feature/flagd/core/pkg/sync"
	"github.com/open-feature/flagd/core/pkg/utils"
	"go.uber.org/zap"
)

type flagOut struct {
	Key            string         `json:"key"`
	State          string         `json:"state"`
	DefaultVariant string         `json:"defaultVariant"`
	Variants       map[string]any `json:"variants"`
	HasTargeting   bool           `json:"hasTargeting"`
}

type result struct {
	Stage string    `json:"stage"` // "convert", "load" or "ok"
	Flags []flagOut `json:"flags"`
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: fdump <file>")
		os.Exit(2)
	}
	if err := run(context.Background(), os.Args[1]); err != nil {
		fmt.Fprintln(os.Stderr, "fdump:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	res, err := load(ctx, data, filepath.Ext(path))
	if err != nil {
		return err
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(res)
}

// load reports the stage at which flagd rejects the file, or the flags it would serve.
func load(ctx context.Context, data []byte, ext string) (result, error) {
	js, err := utils.ConvertToJSON(data, ext, "")
	if err != nil {
		return result{Stage: "convert", Flags: []flagOut{}}, nil
	}
	lg := logger.NewLogger(zap.NewNop(), false)
	st, err := store.NewStore(lg, []string{"src"})
	if err != nil {
		return result{}, fmt.Errorf("new store: %w", err)
	}
	if err := evaluator.NewJSON(lg, st).SetState(sync.DataSync{FlagData: js, Source: "src"}); err != nil {
		return result{Stage: "load", Flags: []flagOut{}}, nil
	}
	all, _, err := st.GetAll(ctx, &store.Selector{})
	if err != nil {
		return result{}, fmt.Errorf("list flags: %w", err)
	}
	res := result{Stage: "ok", Flags: make([]flagOut, 0, len(all))}
	for _, f := range all {
		res.Flags = append(res.Flags, flagOut{
			Key: f.Key, State: f.State, DefaultVariant: f.DefaultVariant, Variants: f.Variants,
			HasTargeting: len(f.Targeting) > 0,
		})
	}
	sort.Slice(res.Flags, func(i, j int) bool { return res.Flags[i].Key < res.Flags[j].Key })
	return res, nil
}
