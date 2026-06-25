# Contributing

## Setup

After cloning or creating a new worktree, install the pre-push hook:

```bash
make install
```

The hook runs lint, unit tests with 100% coverage enforcement, integration tests, and E2E tests before every push.

## Make targets

| Target | Description |
|---|---|
| `make build` | Build the binary |
| `make lint` | Run golangci-lint |
| `make test` | Run unit tests and generate coverage profile |
| `make check-coverage` | Enforce 100% coverage on the generated profile |
| `make test-integration` | Run eBPF integration tests (requires root) |
| `make test-e2e` | Run end-to-end tests |
| `make install` | Install the pre-push hook |
