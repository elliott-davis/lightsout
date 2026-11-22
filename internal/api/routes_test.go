// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

package api_test

import (
	"net/http"
	"os"
	"slices"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/go-cmp/cmp"
	"go.yaml.in/yaml/v3"
)

// TestRoutesMatchOpenAPI checks that the served routes are exactly the operations in api/openapi.yaml.
// AGENTS.md "API first"; NFR-5.
func TestRoutesMatchOpenAPI(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile("../../api/openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var spec struct {
		Paths map[string]map[string]any `yaml:"paths"`
	}
	if err = yaml.Unmarshal(raw, &spec); err != nil {
		t.Fatal(err)
	}
	var want []string
	for path, ops := range spec.Paths {
		for method := range ops {
			switch method {
			case "get", "put", "post", "delete", "options", "head", "patch", "trace":
				want = append(want, method+" "+path)
			}
		}
	}
	slices.Sort(want)

	h := newHarness(t)
	mux, ok := h.handler.(chi.Routes)
	if !ok {
		t.Fatalf("handler %T is not a chi router", h.handler)
	}
	var got []string
	err = chi.Walk(mux, func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		got = append(got, lower(method)+" "+route)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	slices.Sort(got)
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("served routes differ from api/openapi.yaml (-spec +served):\n%s", diff)
	}
}

func lower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 'a' - 'A'
		}
	}
	return string(b)
}
