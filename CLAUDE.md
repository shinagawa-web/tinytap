# CLAUDE.md

## Language

This is an OSS project. All communication, code comments, commit messages, PR descriptions, and issue text must be in **English**.

## Project

`tinytap` is a learning project — a tiny eBPF-based HTTP traffic capture tool. See `README.md` for full design doc.

## Development Environment

- **Edit code**: Mac (`/Users/helpfeel2/Documents/tinytap`) or VS Code Remote SSH to `lima-tinytap`
- **Build and run**: Lima VM only (`limactl shell tinytap`, working dir `~/tinytap`)
- **VM home**: `/home/helpfeel2.guest/tinytap`

## Build

Inside the Lima VM:

```bash
# Regenerate Go bindings from C (run after editing bpf/*.c)
cd ~/tinytap/cmd/tinytap && go generate

# Build
cd ~/tinytap && go build ./...

# Run (requires root)
sudo ./tinytap
```

## Key Facts

- eBPF only runs on Linux — the Lima VM is mandatory, no native macOS build
- `go generate` invokes `bpf2go` which calls `clang` — must run inside the VM
- Generated files (`tinytap_bpfel.go`, `tinytap_bpfeb.go`, `*.o`) are committed to the repo
- Remote URL inside the VM: `git@github.com:shinagawa-web/tinytap.git`

## Workflow

1. Write code → commit → `git push` from VM
2. Open PR against `main`
3. One PR per issue

## Terminology

For socket I/O, prefer **process-relative** vocabulary in code comments, commit messages, PR descriptions, and issues:

- **outgoing** — data leaving the process: `write`, `sendto`, `sendmsg`, `writev`
- **incoming** — data entering the process: `read`, `recvfrom`, `recvmsg`, `readv`

Avoid bare **send-side** / **receive-side** as the first mention — they sound protocol-relative (request vs response) but are actually process-relative, so they invite confusion. Once a paragraph has established the direction, the short forms are fine.

When HTTP direction matters, write it out: "the HTTP response (server's outgoing payload)" rather than "the send-side payload" — the same outgoing syscall is the *response* on a server and the *request* on a client.

See README §1.5 for the full glossary and the protocol mapping table.
