# GNU make 3.81 compatible.
SHELL := /bin/bash
.DEFAULT_GOAL := help

GOLANGCI    := go tool -modfile=tools/go.mod golangci-lint
GOVULNCHECK := go tool -modfile=tools/go.mod govulncheck
ACTIONLINT  := go tool -modfile=tools/go.mod actionlint

PKG     := github.com/elliott-davis/lightsout
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo devel)
LDFLAGS := -s -w -X $(PKG)/internal/version.Version=$(VERSION)
BASE    ?= origin/main

.PHONY: help tools build fmt fmt-files fmt-check lint lint-fix test test-postgres cover vuln tidy-check gen gen-check actionlint dco check ci clean

help: ## Show this help
	@awk 'BEGIN {FS = ":.*## "} /^[a-zA-Z_-]+:.*## / {printf "  %-12s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

tools: ## Download and build the pinned tool binaries
	go build -modfile=tools/go.mod -o /dev/null github.com/golangci/golangci-lint/v2/cmd/golangci-lint
	go build -modfile=tools/go.mod -o /dev/null golang.org/x/vuln/cmd/govulncheck
	go build -modfile=tools/go.mod -o /dev/null github.com/rhysd/actionlint/cmd/actionlint

build: ## Build bin/factory
	go build -trimpath -ldflags '$(LDFLAGS)' -o bin/factory ./cmd/factory

fmt: ## Format all Go files
	$(GOLANGCI) fmt

fmt-files: ## Format only FILES="a.go b.go" (no spaces in paths)
	@test -n "$$FILES" || { echo "usage: make fmt-files FILES=\"a.go b.go\"" >&2; exit 2; }
	@set -f; set -- $$FILES; $(GOLANGCI) fmt -- "$$@"

fmt-check: ## Fail with a diff if any file is unformatted
	@rc=0; out=$$($(GOLANGCI) fmt --diff) || rc=$$?; \
	if [ -n "$$out" ]; then echo "$$out"; echo "files are not formatted; run 'make fmt'" >&2; exit 1; fi; \
	if [ "$$rc" -ne 0 ]; then echo "formatter failed (exit $$rc)" >&2; exit 1; fi

lint: ## Run golangci-lint
	$(GOLANGCI) run

lint-fix: ## Run golangci-lint with auto-fix
	$(GOLANGCI) run --fix

test: ## Run tests with race detector
	go test -race -shuffle=on -count=1 ./...

test-postgres: ## Run the store tests against LIGHTSOUT_TEST_POSTGRES_URL; any skipped test fails
	@test -n "$$LIGHTSOUT_TEST_POSTGRES_URL" || { echo "LIGHTSOUT_TEST_POSTGRES_URL is not set" >&2; exit 2; }
	@out=$$(mktemp); trap 'rm -f "$$out"' EXIT; rc=0; \
	go test -race -shuffle=on -count=1 -v ./internal/store/... > "$$out" 2>&1 || rc=$$?; \
	if [ "$$rc" -ne 0 ]; then cat "$$out"; exit "$$rc"; fi; \
	grep -E '^(ok|FAIL|-test.shuffle)' "$$out"; \
	if grep -q -- '--- SKIP' "$$out"; then grep -- '--- SKIP' "$$out"; echo "PostgreSQL store tests were skipped" >&2; exit 1; fi

cover: ## Write coverage.out and print a summary
	go test -race -count=1 -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out | tail -n 1

vuln: ## Run govulncheck (needs network)
	$(GOVULNCHECK) ./...

tidy-check: ## Fail if go.mod/go.sum need tidying (main and tools)
	go mod tidy -diff
	cd tools && go mod tidy -diff

gen: ## Regenerate internal/api/gen from api/openapi.yaml
	go generate ./internal/api/gen

gen-check: ## Fail if internal/api/gen differs from what its go:generate line produces
	@cd internal/api/gen && line=$$(sed -n 's#^//go:generate ##p' generate.go) && test -n "$$line" \
		&& diff -u api.gen.go <(eval "$${line/ -o api.gen.go/}") \
		|| { echo "internal/api/gen is stale (or has no go:generate line); run 'make gen'" >&2; exit 1; }

actionlint: ## Lint GitHub Actions workflows
	$(ACTIONLINT)

dco: ## Check Signed-off-by on commits in $(BASE)..HEAD
	scripts/check-dco.sh $(BASE)..HEAD

check: fmt-check tidy-check gen-check lint test actionlint ## Everything that works offline

ci: check vuln ## check + vuln

clean: ## Remove build artifacts
	$(RM) bin/factory coverage.out
