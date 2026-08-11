# tinytap

[![Test](https://github.com/shinagawa-web/tinytap/actions/workflows/test.yml/badge.svg)](https://github.com/shinagawa-web/tinytap/actions/workflows/test.yml)
[![codecov](https://codecov.io/gh/shinagawa-web/tinytap/graph/badge.svg)](https://codecov.io/gh/shinagawa-web/tinytap)
[![Go Report Card](https://goreportcard.com/badge/github.com/shinagawa-web/tinytap)](https://goreportcard.com/report/github.com/shinagawa-web/tinytap)
[![Go Reference](https://pkg.go.dev/badge/github.com/shinagawa-web/tinytap.svg)](https://pkg.go.dev/github.com/shinagawa-web/tinytap)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://github.com/shinagawa-web/tinytap/blob/main/LICENSE)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/shinagawa-web/tinytap/badge)](https://securityscorecards.dev/viewer/?uri=github.com/shinagawa-web/tinytap)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/13990/badge)](https://www.bestpractices.dev/projects/13990)

> A tiny eBPF-based HTTP traffic capture tool for local development.

![Left: an ordinary app makes one HTTPS API call. Right: tinytap shows the exact request it sent (headers, Authorization: Bearer, and the JSON body) in plaintext, with no proxy and no CA certificate installed](docs/tui-demo.gif)

An ordinary app calls an API over HTTPS; tinytap's TUI
(`output = "tui"` in the config file, see [Configuration](#configuration))
shows the exact bytes that app sent: the request line, every header
including `Authorization: Bearer`, and the decoded JSON body, in plaintext,
with no proxy and no CA certificate installed. In the request table `j`/`k`
scroll and `Enter` opens the detail panel (`b` toggles the hex body view). See
[`scripts/demo/`](scripts/demo/) for how the gif is recorded.

## Quick start

Install it with:

```bash
curl -fsSL https://raw.githubusercontent.com/shinagawa-web/tinytap/main/scripts/install.sh | sh
```

Grant it the capabilities it needs, then run it, no full root required:

```bash
sudo setcap cap_dac_read_search,cap_perfmon,cap_bpf,cap_sys_admin,cap_syslog=eip $(command -v tinytap)
tinytap
```

That's the full set: plaintext HTTP and HTTPS (via the libssl uprobes,
`cap_sys_admin`) both work out of the box. See
[Running Without Full Root](https://shinagawa-web.github.io/tinytap/docs/running-without-root/)
on the docs site if you want the smaller plaintext-only set instead.

With no config file, that opens the TUI shown at the top of this README:
`j`/`k` to scroll, `Enter` for the detail panel, `q` or `Ctrl-C` to quit,
as long as your terminal is at least 120x24. In a smaller or non-interactive
terminal it prints guidance and exits instead of silently streaming; see
[Configuration](#configuration) to switch to the line-oriented `stdout` mode.

Didn't work? Run `tinytap doctor` first for a read-only preflight report
(kernel version, capabilities, libssl execute bit, etc.); see
[Troubleshooting](https://shinagawa-web.github.io/tinytap/docs/troubleshooting/).

Linux amd64/arm64 only. On macOS/Windows, see
[Where tinytap Runs](#where-tinytap-runs). Want a specific version, or to
verify a release download? See the
[docs site](https://shinagawa-web.github.io/tinytap/) below.

## Where tinytap Runs

**tinytap requires a Linux kernel.** It cannot run natively on macOS or Windows, because eBPF is a Linux kernel technology. But that's less restrictive than it sounds, because Linux kernels are everywhere:

| Where the user works | How tinytap runs there |
|---|---|
| Linux (desktop, laptop, workstation, or server) | Native. Just run the binary. |
| Mac (Intel or Apple Silicon) | Inside a Linux VM: Docker Desktop's VM, OrbStack, Lima, UTM, Multipass, etc. |
| Windows | Inside WSL2 (which is a real Linux kernel). |

Containers need no special handling either, since eBPF sees every process on the
host kernel, containerized or not, so tinytap doesn't need to run inside a
container or as a sidecar. See
[Where tinytap Runs](https://shinagawa-web.github.io/tinytap/docs/where-it-runs/)
on the docs site for the full container story and kernel requirements.

## What it does today

`tinytap` attaches eBPF probes to a process's socket syscalls
(`accept4`/`read`/`write`/`close`/`recvfrom`/`sendto`/`recvmsg`/`sendmsg`),
parses the payload bytes as HTTP/1.1, pairs each request with its response,
and renders the exchange live, either in the terminal TUI above or as a line-oriented stream:

```text
12:47:57.005  python3[27122]  GET   /                        200    1304B     0.3ms
12:47:57.005  curl[1234]       GET   /api                     ABANDONED     12.3ms  (peer closed)
```

`output = "auto"` (the default) picks the TUI when stdout/stdin are an
interactive terminal of at least 120x24; otherwise it prints guidance and
exits rather than silently streaming; the line stream is opt-in via
`output = "stdout"`. `output = "tui"` forces the TUI (and exits the same way
if the terminal can't host it); `verbose = true` hangs the full
request/response headers under each stdout line. `--version` prints the
build's version, commit, and date, and exits without needing root.

## Configuration

Session settings (`output`, `verbose`) live in a TOML config file, not CLI
flags. `tinytap config init` writes one, fully populated with defaults, so
`tinytap config init && tinytap` just works:

```bash
tinytap config init          # writes ./tinytap.toml
tinytap config init path/to/config.toml   # or a specific path
tinytap config init --force  # overwrite an existing file
```

Search order when `--config <path>` isn't given:
`./tinytap.toml`, then `$XDG_CONFIG_HOME/tinytap/config.toml` (falling back
to `~/.config/tinytap/config.toml`); finding neither is not an error, the
defaults below apply.

```toml
output = "auto"   # auto | stdout | tui
verbose = false
```

The only CLI surface is one-shot actions, not session settings: `--config
<path>` (point at an alternate config file), `--version` (build metadata,
exits before any eBPF load), `config init` (above), and `doctor` (see
[Troubleshooting](https://shinagawa-web.github.io/tinytap/docs/troubleshooting/)).

## Current limitations

HTTP/1.1 only (no HTTP/2/gRPC yet), single-host only, and TLS capture needs
the process to expose OpenSSL symbols, either a dynamically linked
`libssl.so` or an unstripped static build. Stacks that don't use OpenSSL
at all, like Go's `crypto/tls`, remain invisible either way. Full list,
including per-server body-visibility details, on the
[docs site](https://shinagawa-web.github.io/tinytap/docs/limitations/).

## Status & Roadmap

Released so far: `v0.1.0` (HTTP request/response visible) through `v0.6.0`
(production readiness). `v0.7.0` (real-hardware bring-up) is in progress,
see [#198](https://github.com/shinagawa-web/tinytap/issues/198). Full
roadmap in [#19](https://github.com/shinagawa-web/tinytap/issues/19).

## Documentation

Full documentation is available at
[shinagawa-web.github.io/tinytap](https://shinagawa-web.github.io/tinytap/):

- [Quick Start](https://shinagawa-web.github.io/tinytap/docs/quick-start/)
- [Use Cases](https://shinagawa-web.github.io/tinytap/docs/use-cases/)
- [Usage](https://shinagawa-web.github.io/tinytap/docs/usage/)
- [Where tinytap Runs](https://shinagawa-web.github.io/tinytap/docs/where-it-runs/)

- [Running Without Full Root](https://shinagawa-web.github.io/tinytap/docs/running-without-root/)
- [How It Works](https://shinagawa-web.github.io/tinytap/docs/how-it-works/)
- [Configuration](https://shinagawa-web.github.io/tinytap/docs/configuration/)
- [Server Compatibility](https://shinagawa-web.github.io/tinytap/docs/server-compatibility/)

- [TLS Compatibility](https://shinagawa-web.github.io/tinytap/docs/tls-compatibility/)
- [Installing & Verifying Releases](https://shinagawa-web.github.io/tinytap/docs/installing-and-verifying/)
- [Troubleshooting](https://shinagawa-web.github.io/tinytap/docs/troubleshooting/)
- [Event Schema](https://shinagawa-web.github.io/tinytap/docs/event-schema/)

- [Terminology](https://shinagawa-web.github.io/tinytap/docs/terminology/)
- [Current Limitations](https://shinagawa-web.github.io/tinytap/docs/limitations/)

## Toolchain

| Component | Choice | Why |
|---|---|---|
| eBPF lib | `github.com/cilium/ebpf` | Pure Go, modern, standard for new projects |
| Build | `bpf2go` (part of cilium/ebpf) | Generates Go bindings from C code |
| Compiler | `clang` 17+ | Standard for eBPF, supports BTF. `clang-14` compiles cleanly but the emitted `bpf_probe_read_user` call fails the kernel verifier (`R2 unbounded memory access`), so CI pins 17 (#207); 15/16 untested |
| Go | 1.24+ | |
| Kernel | Linux 5.8+ | Required for `BPF_MAP_TYPE_RINGBUF`, tinytap's event transport |
| Architecture | amd64 + arm64 | Need arm64 for Apple Silicon Lima VM |
| Release builds | [GoReleaser](https://goreleaser.com/) v2 | Cross-compiles linux/amd64 + linux/arm64 on tag push (`.goreleaser.yml`). The release workflow regenerates the bpf2go artifacts from source first (#260), then it's a plain `go build`; GoReleaser itself needs no clang/libbpf step |

### Dev environment

Mac (Apple Silicon) + Lima with Ubuntu 24.04. Build and run inside the Lima VM. Edit code on Mac via VS Code's remote SSH or the auto-mounted filesystem. This is private to the maintainer's workflow; it does not constrain users. See [Where tinytap Runs](#where-tinytap-runs) for how tinytap runs on a user's machine.

Setup commands are:

```bash
# Mac side
brew install lima
limactl start --name=tinytap template://ubuntu
limactl shell tinytap

# Inside the VM
sudo apt update
sudo apt install -y llvm linux-headers-$(uname -r) build-essential git pkg-config

# clang 17 from the official LLVM repo — Ubuntu's own `clang` package isn't
# guaranteed to be 17, and clang-14 is known to fail the eBPF verifier (#207)
wget -O /tmp/llvm.sh https://apt.llvm.org/llvm.sh
echo "9474ecd78b52aba6e923976b1e9773f5613027cc7e237b9956986cb536e02a36  /tmp/llvm.sh" | sha256sum -c -
chmod +x /tmp/llvm.sh
sudo /tmp/llvm.sh 17

# libbpf 1.6.2 headers — Ubuntu's libbpf-dev predates the BPF_UPROBE macro
# bpf/tinytap_uprobe.bpf.c uses
git clone --depth 1 --branch v1.6.2 https://github.com/libbpf/libbpf.git /tmp/libbpf
sudo make -C /tmp/libbpf/src install_headers PREFIX=/usr

# Go (apt version is old)
GO_VERSION=1.24.0
ARCH=$(dpkg --print-architecture)  # arm64 on Apple Silicon
wget https://go.dev/dl/go${GO_VERSION}.linux-${ARCH}.tar.gz
sudo tar -C /usr/local -xzf go${GO_VERSION}.linux-${ARCH}.tar.gz
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
source ~/.bashrc
```

## Building from source

Build and run inside the Lima VM (see [Toolchain](#toolchain) above for setup):

```bash
# Regenerate Go bindings from C — required before every build/test, not just
# after editing bpf/*.c: the generated files aren't committed (needs clang-17
# + libbpf 1.6.2, see Toolchain above)
cd ~/tinytap && make generate

# Build (go build ./... alone won't write a ./tinytap binary — it builds
# every package in the module to check they compile, without picking one
# to write out; -o plus a single package path produces the binary)
go build -o tinytap ./cmd/tinytap

# Run (requires root — eBPF needs CAP_BPF/CAP_PERFMON or root)
sudo ./tinytap
```

Root isn't actually required. See
[Running Without Full Root](https://shinagawa-web.github.io/tinytap/docs/running-without-root/)
for the minimal `setcap` invocation.

Or via `make`:

```bash
make run       # orchestrated smoke test: starts a demo HTTP server, fires a request, shows the capture
make run-raw   # build + run with output = "stdout" against whatever's already running
```

Run `make install` once per checkout (or worktree) to install the pre-push
hook that runs lint, tests, and coverage checks before every push.

## License

MIT, see [`LICENSE`](LICENSE). Exception: [`bpf/vmlinux.h`](bpf/vmlinux.h) is
generated from the Linux kernel's BTF info and is distributed under the
kernel's GPL-2.0 license instead.

## References

- [cilium/ebpf examples](https://github.com/cilium/ebpf/tree/main/examples): primary reference for the Go side
- [hengyoush/kyanos](https://github.com/hengyoush/kyanos): reference for HTTP capture implementation patterns
- [mozillazg/ptcpdump](https://github.com/mozillazg/ptcpdump): reference for process-awareness patterns
- [Pixie blog: Debugging with eBPF Part 2](https://blog.px.dev/ebpf-http-tracing/): the canonical "tracing HTTP via syscalls" walkthrough

- [eunomia eBPF tutorials](https://eunomia.dev/): readable, hands-on
- Brendan Gregg's blog: for the kernel-side mental model
