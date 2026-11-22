// Copyright 2026 The Lightsout Authors
// SPDX-License-Identifier: Apache-2.0

// Package gen holds the code generated from api/openapi.yaml. Never edit api.gen.go: change the spec and run
// "go generate ./internal/api/gen".
package gen

//go:generate go tool -modfile=../../../tools/go.mod oapi-codegen -config cfg.yaml -o api.gen.go ../../../api/openapi.yaml
