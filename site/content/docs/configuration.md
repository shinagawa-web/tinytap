---
title: Configuration
weight: 5
---

# Configuration

Session settings (`output`, `verbose`, and process filters) live in a TOML
config file, not CLI flags.

## Generating a config file

`tinytap config init` writes one, fully populated with defaults, so
`tinytap config init && tinytap` just works:

```bash
tinytap config init          # writes ./tinytap.toml
tinytap config init path/to/config.toml   # or a specific path
tinytap config init --force  # overwrite an existing file
```

## Search order and defaults

Search order when `--config <path>` isn't given:
`./tinytap.toml`, then `$XDG_CONFIG_HOME/tinytap/config.toml` (falling back
to `~/.config/tinytap/config.toml`) — finding neither is not an error, the
defaults below apply.

```toml
output = "auto"   # auto | stdout | tui
verbose = false

[filter]
pid  = []         # []uint32 — schema only, not yet enforced by the BPF program
comm = []         # []string — schema only, not yet enforced by the BPF program
```

## CLI surface

The only CLI surface is one-shot actions, not session settings:

| Flag / command | What it does |
|---|---|
| `--config <path>` | Point at an alternate config file |
| `--version` | Print build metadata, exiting before any eBPF load |
| `config init` | Write a fully-populated default config file (see above) |
| `doctor` | Read-only preflight checks (see [Troubleshooting]({{< relref "troubleshooting" >}})) |
