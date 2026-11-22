# Lightsout

Lightsout is an open-source "dark AI software factory". It takes an idea from a GitHub issue to merged, tested code, and
every change lands behind a feature switch that defaults to off. Humans approve the intent, own the exceptions and decide
when a feature is released. Agents do the rest, inside the repo's own CI and review rules. It is written in Go, installs
on-prem and is designed to work disconnected.

Status: early development. The control-plane building blocks are in place, but there is no end-to-end pipeline yet. See
[docs/backlog.md](docs/backlog.md) for what's done and what's next, and the
[issues](https://github.com/elliott-davis/lightsout/issues) for open follow-ups.

## How it fits together

- **Contracts** (`.factory.yaml`, `internal/contract`): each repo area declares what agents may change, which gates must
  pass and who reviews. A product change can never supply the policy that authorizes it.
- **Install config** (`internal/install`): the factory-wide baseline, with mandatory gates, pinned model, harness and
  runtime profiles per agent role, and qualification records.
- **Authorization and audit** (`internal/authz`, `internal/audit`, `internal/codeowners`): every human decision is bound
  to an exact revision and checked at execution time. All decisions go to an append-only, hash-chained audit log.
- **Verify** (`internal/gate`, `internal/review`, `internal/switches`): pure evaluators for gate-of-record evidence at the
  merge-group candidate, review completeness from signed reviewer verdicts, and switch detection (flagd and OpenFeature).
- **State** (`internal/store`): PostgreSQL-backed state and audit storage, with an in-memory implementation for tests.
- **Forge** (`internal/forge`): the GitHub boundary, with a fake and a conformance suite. The GitHub adapter is still to
  come.

Read more:
- [PRD.md](PRD.md): the requirements. IDs such as `CON-3` are referenced throughout the code and tests.
- [docs/design/](docs/design/): one design doc per area.
- [AGENTS.md](AGENTS.md): the rules for contributors and coding agents.

## Getting started

Prerequisites:
- Go 1.27
- `make`
- [pre-commit](https://pre-commit.com)
- Docker, optional, for the PostgreSQL tests

```sh
git clone git@github.com:elliott-davis/lightsout.git && cd lightsout
pre-commit install          # format, tidy and DCO sign-off hooks
make tools                  # builds the pinned golangci-lint, govulncheck and actionlint
make check                  # format, tidy, lint, race tests, actionlint: run before every commit
make build                  # builds bin/factory
```

The PostgreSQL store tests are skipped unless a database is available. To run them:

```sh
docker run -d --rm --name lo-pg -e POSTGRES_PASSWORD=pg -p 127.0.0.1:55432:5432 postgres:16-alpine
LIGHTSOUT_TEST_POSTGRES_URL='postgres://postgres:pg@127.0.0.1:55432/postgres?sslmode=disable' make test-postgres
```

Try the CLI:

```sh
bin/factory contract schema                       # the contract JSON Schema
bin/factory contract validate --revision "$(git rev-parse HEAD)" \
  --interim-defaults --no-gate-registry            # validate the .factory.yaml files in a checkout
bin/factory install validate internal/install/testdata/valid.yaml
```

## Contributing

- Every commit needs a DCO sign-off (`git commit -s`).
- Subjects take an area prefix and PRD IDs, for example `contract: reject unknown fields (CON-11)`.
- Security controls need denial tests.
- HTTP APIs are designed in OpenAPI first and served with chi.

See [AGENTS.md](AGENTS.md) for the full conventions.

## License

Apache-2.0. See [LICENSE](LICENSE).
