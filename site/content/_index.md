---
title: "tinytap"
---

# tinytap

[![Test](https://github.com/shinagawa-web/tinytap/actions/workflows/test.yml/badge.svg)](https://github.com/shinagawa-web/tinytap/actions/workflows/test.yml)
[![codecov](https://codecov.io/gh/shinagawa-web/tinytap/graph/badge.svg)](https://codecov.io/gh/shinagawa-web/tinytap)
[![Go Reference](https://pkg.go.dev/badge/github.com/shinagawa-web/tinytap.svg)](https://pkg.go.dev/github.com/shinagawa-web/tinytap)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://github.com/shinagawa-web/tinytap/blob/main/LICENSE)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/shinagawa-web/tinytap/badge)](https://securityscorecards.dev/viewer/?uri=github.com/shinagawa-web/tinytap)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/13990/badge)](https://www.bestpractices.dev/projects/13990)

<img src="tui-demo.gif" width="800" alt="Left: an ordinary app makes one HTTPS API call. Right: tinytap shows the exact request it sent (headers, Authorization: Bearer, and the JSON body) in plaintext, with no proxy and no CA certificate installed">

> A tiny eBPF-based HTTP traffic capture tool for local development.
> See the exact request/response bytes an app sends (every header, the decoded body) in plaintext, with no proxy and no CA certificate installed.

```sh
curl -fsSL https://raw.githubusercontent.com/shinagawa-web/tinytap/main/scripts/install.sh | sh
```

[Quick Start →]({{< relref "/docs/quick-start" >}})

- See the exact bytes an app sends and receives (request line, every header, decoded body) live in a terminal UI
- Works on plaintext HTTP and TLS (via libssl uprobes), with no proxy, no CA certificate, and no code changes
- Runs without full root: grant three Linux capabilities instead of `sudo`

## Why

Debugging HTTP traffic usually means a MITM proxy: install a CA certificate, point the app at the proxy, hope nothing breaks in the process. tinytap skips all of that. It attaches eBPF probes directly to the kernel syscalls a process already makes, so it sees the same bytes the process does, with nothing sitting in between and nothing to configure on the app's side.

> Goal: see what your app actually sent, not what a proxy reconstructed.

## Features

- Live TUI or line-oriented `stdout` output, request paired with response automatically
- TLS capture via libssl uprobes: no proxy, no CA certificate
- Runs without full root: three Linux capabilities instead of `sudo`
- Single static binary, no runtime dependencies

- Sees traffic from containerized processes too: no sidecar, no install-inside-the-container

What's planned next:

- Container-aware attribution (mapping a PID to the container it belongs to)
- HTTP/2 and gRPC support
