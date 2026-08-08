# CLAUDE.md

## Language

This is an OSS project. All communication, code comments, commit messages, PR descriptions, and issue text must be in **English**.

## Project

`tinytap` is a tiny eBPF-based HTTP traffic capture tool. See `README.md` for project overview and vision.

## Architecture

```
tinytap/
├── bpf/
│   └── tinytap.bpf.c        # eBPF C program
├── cmd/
│   └── tinytap/
│       └── main.go           # CLI entry, loads eBPF, reads ringbuf
├── internal/
│   ├── loader/               # eBPF program lifecycle (load, attach, detach)
│   ├── events/               # Event struct, ringbuf reader
│   ├── proc/                 # PID → process name lookup via /proc
│   └── parser/               # HTTP parser
├── docs/                     # reference material (see Reference docs below)
├── scripts/
│   ├── demo.sh               # `make run` orchestrated HTTP smoke test
│   └── demo/                 # 0A demo recording (app + tmux split + vhs tape) — see scripts/demo/README.md
├── go.mod
├── go.sum
├── Makefile
└── README.md
```

(The `internal/` subdirectories are the planned layout; the v0.0.1 code currently lives directly in `cmd/tinytap/main.go` and will be split during the v0.1.0 work tracked in #15.)

### Boundaries

- `bpf/` — kernel-side, written in C, compiled by clang
- `internal/loader/` — knows about cilium/ebpf, loads `.o` files, attaches probes
- `internal/events/` — knows about ringbuf semantics, decodes raw event bytes into Go structs
- `internal/proc/` — pure Go, reads /proc, no eBPF
- `internal/parser/` — pure Go, HTTP state machine, no eBPF, no syscalls
- `cmd/tinytap/` — wires everything together

### Why this separation

Because it makes it easy to test the HTTP parser without eBPF, and the proc lookup without HTTP. The eBPF and ringbuf parts are the irreducibly system-dependent parts; everything else can be unit-tested with plain Go.

### Reference docs

Lower-level reference material lives under `docs/`:

- [`docs/event-schema.md`](docs/event-schema.md) — the kernel↔userspace event struct (C / Go layouts, field semantics, byte offsets)
- [`docs/terminology.md`](docs/terminology.md) — outgoing/incoming vocabulary and the HTTP protocol mapping
- [`docs/ebpf-basics.md`](docs/ebpf-basics.md) — eBPF primer
- [`docs/waveterm-claude-code.md`](docs/waveterm-claude-code.md) — making Wave Terminal's Claude Code badges work inside the Lima VM

## Development Environment

- **Edit code**: Mac (`/Users/helpfeel2/Documents/tinytap`) or VS Code Remote SSH to `lima-tinytap`
- **Build and run**: Lima VM only (`limactl shell tinytap`, working dir `~/tinytap`)
- **VM home**: `/home/helpfeel2.guest/tinytap`

## Build

Inside the Lima VM:

```bash
# Regenerate Go bindings from C — required before every build/test, not
# just after editing bpf/*.c (#260): the generated files aren't committed
cd ~/tinytap && make generate

# Build
go build ./...

# Run (requires root)
sudo ./tinytap
```

## Key Facts

- eBPF only runs on Linux — the Lima VM is mandatory, no native macOS build
- `go generate` invokes `bpf2go` which calls `clang` — must run inside the VM
- Generated files under `internal/loader/bpf/` and `internal/loader/bpf/fixture/` (every `*_bpfel.go`, `*_bpfeb.go`, `*.o` — the tinytap/kprobe/uprobe bindings and the test fixture, not just `tinytap_bpfel.go`/`tinytap_bpfeb.go`) are **not** committed (#260) — run `make generate` (needs clang-17 + libbpf 1.6.2, already installed on the primary dev VM) before any build or test; CI regenerates them itself via `.github/actions/setup-bpf-toolchain`
- Remote URL inside the VM: `git@github.com:shinagawa-web/tinytap.git`

## Workflow

1. Write code → commit → `git push` from VM
2. Open PR against `main`
3. One PR per issue

Run `make install` once per worktree after cloning or creating a new worktree — it installs the pre-push hook that runs lint, tests, and coverage checks before every push.

### PR title convention

PR titles must follow [Conventional Commits](https://www.conventionalcommits.org/): `type(scope): summary`, e.g. `feat(cli): add --version flag`, `chore(license): add MIT LICENSE`. `.github/workflows/auto-label.yml` labels PRs from the title and fails a required check if none of the recognized types match, so getting the prefix right is not optional.

Recognized types and their label:

| Type       | Label           |
|------------|-----------------|
| `feat`     | `enhancement`   |
| `fix`      | `bug`           |
| `docs`     | `documentation` |
| `test`     | `test`          |
| `chore`    | `chore`         |
| `refactor` | `refactor`      |
| `ci`       | `ci`            |
| `build`    | `build`         |
| `deps`, or `fix(deps)`/`chore(deps)` | `dependencies` |

Append `!` before the colon (e.g. `feat(cli)!: ...`) for a breaking change — it adds the `breaking-change` label on top of the type label.

The scope is the component, not the type — `cli:`, `license:`, `config:` read as scopes, so write `feat(cli): ...` / `chore(license): ...` instead. Existing merged history predates this convention and doesn't need retrofitting.

## Terminology

For socket I/O, prefer **process-relative** vocabulary in code comments, commit messages, PR descriptions, and issues:

- **outgoing** — data leaving the process: `write`, `sendto`, `sendmsg`, `writev`
- **incoming** — data entering the process: `read`, `recvfrom`, `recvmsg`, `readv`

Avoid bare **send-side** / **receive-side** as the first mention — they sound protocol-relative (request vs response) but are actually process-relative, so they invite confusion. Once a paragraph has established the direction, the short forms are fine.

When HTTP direction matters, write it out: "the HTTP response (server's outgoing payload)" rather than "the send-side payload" — the same outgoing syscall is the *response* on a server and the *request* on a client.

See [docs/terminology.md](docs/terminology.md) for the full glossary and the protocol mapping table.
