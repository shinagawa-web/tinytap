---
title: Quick Start
weight: 1
---

Install:

```bash
curl -fsSL https://raw.githubusercontent.com/shinagawa-web/tinytap/main/scripts/install.sh | sh
```

Grant it the capabilities it needs, then run it — no full root required:

```bash
sudo setcap cap_dac_read_search,cap_perfmon,cap_bpf=eip $(command -v tinytap)
tinytap
```

With no config file, that opens the TUI — `j`/`k` to scroll, `Enter` for the
detail panel, `q` or `Ctrl-C` to quit — as long as your terminal is at least
120x24. In a smaller or non-interactive terminal it prints guidance and exits
instead of silently streaming; see [Configuration]({{< relref "configuration" >}})
to switch to the line-oriented `stdout` mode.

Linux amd64/arm64 only — on macOS/Windows, see
[Where tinytap Runs]({{< relref "where-it-runs" >}}). Want HTTPS capture too, a
specific version, or to build from source instead? See
[Running Without Full Root]({{< relref "running-without-root" >}}),
[Installing & Verifying Releases]({{< relref "installing-and-verifying" >}}),
or the repo's [CONTRIBUTING.md](https://github.com/shinagawa-web/tinytap/blob/main/CONTRIBUTING.md)
for building from source.

Didn't work? See [Troubleshooting]({{< relref "troubleshooting" >}}).
