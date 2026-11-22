// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

package contract

import (
	"fmt"
	"strings"
	"testing"

	"github.com/elliott-davis/lightsout/internal/pathglob"
)

// These benchmarks measure what one unit of matchWork costs, to calibrate the
// budgets. Run: go test -run X -bench UnitCost ./internal/contract

func reportUnits(b *testing.B, unitsPerOp int64) {
	b.Helper()
	b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N)/float64(unitsPerOp), "ns/unit")
}

func BenchmarkUnitCost_Match(b *testing.B) {
	for name, tc := range map[string]struct{ pattern, path string }{
		"long glob, long segments": {"**/*" + strings.Repeat("a", 500) + "b001", strings.Repeat("d/", 10) + strings.Join(repeatStr("A"+strings.Repeat("a", 250), 14), "/")},
		"long glob, one segment":   {"*" + strings.Repeat("a", 506) + "001x", strings.Repeat("a", 250) + "00001"},
		"short, deep":              {"**/p1/**", strings.Repeat("d/", 100) + "x.go"},
		"many segments":            {"**/" + strings.Repeat("a/**/", 100) + "zaaq", strings.Repeat("a/", 254) + "a"},
		"many segments, single":    {"**/" + strings.Repeat("a/*/", 100) + "zaaq", strings.Repeat("a/", 254) + "a"},
	} {
		b.Run(name, func(b *testing.B) {
			p, err := pathglob.Compile(tc.pattern)
			if err != nil {
				b.Fatal(err)
			}
			p = p.WithDescendants()
			runes := len([]rune(tc.path))
			units := matchWork(p.Runes(), runes)
			b.ResetTimer()
			for range b.N {
				p.Match(tc.path)
			}
			reportUnits(b, units)
		})
	}
}

func BenchmarkUnitCost_Contains(b *testing.B) {
	for name, tc := range map[string]struct{ outer, inner string }{
		"long literals":    {"**/*" + strings.Repeat("a", 245) + "001b", strings.Repeat("a", 500) + "001"},
		"many segments":    {"**/" + strings.Repeat("a/**/", 100) + "zaaq", strings.Repeat("a/", 150) + "zaaq"},
		"many wildcards":   {strings.Repeat("*/", 250) + "x", strings.Repeat("*/", 250) + "x"},
		"alternating star": {strings.Repeat("**/a/", 90) + "**", strings.Repeat("a/", 250) + "a"},
	} {
		b.Run(name, func(b *testing.B) {
			outer, err := pathglob.Compile(tc.outer)
			if err != nil {
				b.Fatal(err)
			}
			inner, err := pathglob.Compile(tc.inner)
			if err != nil {
				b.Fatal(err)
			}
			units := int64(proofCost(outer, inner))
			b.ResetTimer()
			for range b.N {
				pathglob.Contains(outer, inner)
			}
			reportUnits(b, units)
		})
	}
}

func repeatStr(s string, n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("%s%d", s, i%10)[:min(len(s), 255)]
	}
	return out
}
