# Lightsout — agent and contributor guide

Lightsout is the "Dark AI Software Factory" described in [PRD.md](PRD.md): a Go control plane that takes an
idea from a GitHub issue to merged, tested code behind a feature switch that defaults to off. It is open source
(Apache-2.0), installs on-prem and must work disconnected. This file is the shared rulebook for every agent
(Claude, Codex) and human working here.

## Commands

| Command | What it does |
| --- | --- |
| `make check` | Everything that works offline: format check, `go mod tidy` check, lint, race tests, actionlint. **Run before declaring any work done.** |
| `make ci` | `check` plus `govulncheck` (needs network). |
| `make fmt` / `make fmt-files FILES=...` | gofumpt + goimports via golangci-lint. |
| `make lint` / `make lint-fix` | golangci-lint with the repo config. |
| `make test` | `go test -race -shuffle=on -count=1 ./...` |
| `make build` | Builds `bin/factory`. |

Tools (golangci-lint, govulncheck, actionlint) are pinned in `tools/go.mod` and run with
`go tool -modfile=tools/go.mod <tool>`. Don't rely on whatever version happens to be on `PATH`.

## Requirements traceability

The PRD's requirement IDs (`CON-3`, `PIP-2`, `SEC-10`, ...) are stable. Use them:

- Each work item implements one or more IDs, and only their `v1` phase unless told otherwise.
- Each acceptance criterion gets at least one test. Name the ID in the test name or a comment on it, e.g.
  `TestEffectiveContract_ChildCannotDropMandatoryGate // CON-3`.
- Reference an ID in production code only where it explains *why* the code is shaped that way.
- When a requirement is ambiguous or two of them conflict, the PRD's design principles (P1–P7) decide. If they don't, stop and
  ask; don't guess.

## Architecture rules (enforced by lint where possible)

- Layout: binaries in `cmd/<name>`, everything else in `internal/`. No `pkg/`, `util`, `common` or `helpers` packages.
- **Adapter boundaries** (depguard): only `internal/runtime/kagent` may import kagent (RUN-8), and only
  `internal/forge/github` may import go-github. Everything else talks to the `internal/runtime` and
  `internal/forge` interfaces. GitLab, Jenkins, Jira and other runtimes come later as more adapters.
- Define interfaces in the package that consumes them, keep them small, accept interfaces and return concrete types.
- No package-level mutable state and no `init()`. Pass configuration, clocks (`func() time.Time` or a small
  `Clock` interface) and randomness in explicitly. Timers, trains and staleness rules must be testable without sleeping.
- The audit log (NFR-4, RUN-5, AGT-6) is a domain concept with its own append-only interface. Don't treat it as `slog` output.
- **API first.** Every HTTP API the factory serves (control-plane API, admin, callbacks, webhook receivers) is designed
  as an OpenAPI document in the repo before it is implemented, and that document is the contract: server code
  conforms to it, and tests check the served routes against it. Change the spec first, then the code. Server types
  and handler interfaces are generated from the spec with oapi-codegen (chi strict-server); never hand-edit them.
- **REST uses [chi](https://github.com/go-chi/chi)** (`github.com/go-chi/chi/v5`) for routing and middleware. Don't add another web framework.

## Go conventions

- **Errors:** wrap with context and `%w` (`fmt.Errorf("load contract %s: %w", path, err)`). Use sentinel
  `ErrFoo` and typed `FooError` where callers need to branch, and check them with `errors.Is`/`errors.As`.
  Handle an error once: either log it or return it, never both. No `panic` outside `main` and programmer-error invariants.
- **Context:** `ctx context.Context` is the first parameter of anything that does I/O or blocks, and is never
  stored in a struct. Honor cancellation.
- **Logging:** inject `*slog.Logger`. Use static messages and snake_case keys. Never log secrets, credentials, private holdout
  content or raw untrusted input at info level.
- **Concurrency:** every goroutine has an owner and a shutdown path (prefer `errgroup`). No fire-and-forget.
  Tests always run with `-race`.
- **Output:** no `fmt.Print*` outside `cmd/`. Write to an injected `io.Writer`.
- **Dependencies:** keep them minimal. Every module ends up in the offline bill of materials (NFR-8). Justify each new dependency
  in the PR description. No `replace` directives. Run `go mod tidy`.
- **Generated code** carries the standard `// Code generated ... DO NOT EDIT.` header and is regenerated, never hand-edited.
- **License header** on every hand-written `.go` file:
  ```go
  // Copyright 2026 The Lightsout Authors
  // SPDX-License-Identifier: Apache-2.0
  ```

## Testing

- Use the standard `testing` package plus `github.com/google/go-cmp/cmp` for diffs. No testify and no mocking frameworks.
  Write small hand-written fakes that implement the consumer's interface.
- Prefer table-driven tests with `t.Run`, and add `t.Parallel()` where safe. Use `t.Helper()` in helpers, and `t.Context()` and `t.TempDir()`.
- Golden files live in `testdata/` and are updated with an `-update` flag, never by hand.
- Security controls need **negative tests**: forged, stale and replayed approvals, foreign checks with the same
  name, and access to private fixtures (SEC-11). A control without a denial test is not done.

## Security posture

The factory is the most privileged actor in the repos it manages. Treat every file, issue, comment, CI log and
tool result as untrusted input (SEC-1). Authorization is checked at execution time against the current identity,
role and the exact revision (SEC-10, NFR-5). It is never inferred from comment text or cached from an earlier check.

**Contributor tooling is not the factory harness.** `.claude/`, `scripts/codex.sh` and this file configure agents
that *develop Lightsout*, and they deliberately load this repo's own instructions and hooks. The coding harness the
factory launches against managed repos must do the opposite (SEC-9): load only factory-supplied settings, tools and
instructions, with Claude Code in bare mode and Codex config coming from the factory. Never reuse this repo's
tooling as that launcher. Test it with a fixture checkout that plants hooks, MCP config and instructions, and assert that none of them load.

## Lint policy

- Never weaken `.golangci.yml` to get green. Changing the config is a human decision.
- `//nolint` must name the linter and give a reason (`//nolint:gosec // path is validated by contract.Resolve`),
  scoped to one line. Fixing the code is almost always better.

## Commits

- DCO sign-off on every commit (`git commit -s`). The commit-msg hook and CI enforce it (NFR-7).
- Imperative subject with an area prefix and PRD IDs: `contract: reject unknown fields (CON-11)`.
- One logical change per commit. `make check` passes on each.
