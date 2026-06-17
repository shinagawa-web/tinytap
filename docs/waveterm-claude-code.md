# Wave Terminal + Claude Code Badges (Lima VM)

[Wave Terminal](https://waveterm.dev/) can display tab badges that react to a
Claude Code session — a bell when Claude asks for permission, a checkmark when a
response finishes, and so on. Wave drives these badges through Claude Code
[lifecycle hooks](https://docs.waveterm.dev/claude-code) that run the `wsh badge`
command.

This works out of the box when Claude Code runs in a local Wave session. It does
**not** work for tinytap by default, because tinytap is edited on the Mac host
but built and run inside the Lima VM (see [the development setup in
`CLAUDE.md`](../CLAUDE.md)). The hooks fire inside the VM, while Wave runs on the
Mac — and `wsh` is missing in the VM, so the badges never appear.

This document explains how to bridge that gap.

## Why It Does Not Work By Default

The badge mechanism has two requirements that both fail in the default Lima
setup:

1. **`wsh` must be present in the session.** Wave only injects `wsh` into hosts
   you connect to *through Wave's own SSH connection*. If you reach the VM with
   `limactl shell` or the VS Code integrated terminal, `wsh` is absent and the
   hook commands are no-ops.
2. **`wsh` must be able to reach the Wave instance.** Even if `wsh` existed, a
   session that Wave did not establish has no socket back to the Wave app on the
   Mac, so `wsh badge` has nothing to talk to.

You can confirm the gap from inside the VM:

```bash
command -v wsh        # not found in a non-Wave session
echo "$WAVETERM"      # empty in a non-Wave session
```

The fix is therefore to **run Claude Code inside a session that Wave itself
opened over SSH**, which injects `wsh` and wires up the socket automatically.

## Step 1: Connect to the VM Through Wave

Lima generates an SSH config for the VM. Make it visible to Wave by including it
from `~/.ssh/config` on the **Mac** (Wave reads `~/.ssh/config`):

```ssh-config
Include ~/.lima/<vm-name>/ssh.config
```

Lima regenerates that file on every VM start and may assign a new forwarded
port, so `Include` always reflects the current port automatically — no
hard-coding needed. The catch (next section): the Lima-generated `Host` block
uses directives that Wave's own SSH client cannot handle, so `Include` alone is
not enough.

The Lima-generated `Host` block, however, contains directives that Wave's
embedded Go SSH client does not handle well:

- `Ciphers "^aes128-gcm@openssh.com,..."` — the `^` (prepend) syntax
- `ControlMaster auto` / `ControlPath ...` — connection multiplexing
- `UserKnownHostsFile /dev/null` — Wave cannot persist an accepted host key to
  `/dev/null`, so the handshake fails with `knownhosts: key is unknown`

So instead of connecting to the Lima-generated alias directly, add a **clean,
Wave-friendly alias** to `~/.ssh/config` (above the `Include` line). Fill in the
host, port, user, and identity file from `limactl show-ssh --format=config
<vm-name>`:

```ssh-config
Host lima-wave
  HostName 127.0.0.1
  Port 50049                       # see the tradeoff note below
  User <vm-user>
  IdentityFile ~/.lima/_config/user
  IdentitiesOnly yes
  StrictHostKeyChecking accept-new
  UserKnownHostsFile ~/.ssh/known_hosts_lima
```

**Tradeoff — why this alias hard-codes the port (unlike `Include`).** The
`Include` above auto-tracks Lima's dynamic port, but its `Host` block is
unusable by Wave; this hand-written alias is usable by Wave but is *not*
auto-updated. So the port is pinned here and you must refresh it whenever Lima
reassigns it (e.g. after the VM is recreated, or sometimes after a plain
restart). Check the current value with `limactl show-ssh --format=config
<vm-name>` and update `Port` if a `wsh ssh lima-wave` connection starts failing.

Key differences from the Lima default:

- No `Ciphers` / `ControlMaster` / `BatchMode` — Wave's SSH client tolerates the
  rest.
- `StrictHostKeyChecking accept-new` plus a **real** known_hosts file
  (`~/.ssh/known_hosts_lima`, kept separate so Lima's volatile keys do not
  pollute your main file) — Wave silently records the key on first connect and
  the handshake succeeds.

Verify with the plain `ssh` client first, then connect from Wave:

```bash
ssh lima-wave whoami     # should print the VM user
wsh ssh lima-wave        # Wave connects and injects wsh on first connect
```

If the VM is later **recreated** (not just restarted), its host key changes and
`accept-new` will refuse it. Drop the stale entry and reconnect:

```bash
ssh-keygen -R '[127.0.0.1]:50049' -f ~/.ssh/known_hosts_lima
```

Inside the Wave session, confirm the bridge is up:

```bash
command -v wsh          # e.g. ~/.waveterm/bin/wsh
echo "$WAVETERM"        # 1
```

## Step 2: Add the Badge Hooks

Add the `wsh badge` hooks to `~/.claude/settings.json` **inside the VM** (merge
with any existing `hooks` key):

```json
{
  "hooks": {
    "Notification": [
      {
        "matcher": "permission_prompt",
        "hooks": [
          { "type": "command", "command": "wsh badge bell-exclamation --color '#e0b956' --priority 20 --beep" }
        ]
      },
      {
        "matcher": "elicitation_dialog",
        "hooks": [
          { "type": "command", "command": "wsh badge message-question --color '#e0b956' --priority 20 --beep" }
        ]
      }
    ],
    "Stop": [
      {
        "hooks": [
          { "type": "command", "command": "wsh badge check --color '#58c142' --priority 10" }
        ]
      }
    ],
    "PreToolUse": [
      {
        "matcher": "AskUserQuestion",
        "hooks": [
          { "type": "command", "command": "wsh badge message-question --color '#e0b956' --priority 20 --beep" }
        ]
      }
    ],
    "UserPromptSubmit": [
      {
        "hooks": [
          { "type": "command", "command": "wsh badge --clear" }
        ]
      }
    ]
  }
}
```

| Event | Badge | Color | Meaning |
| --- | --- | --- | --- |
| `Notification` / `permission_prompt` | `bell-exclamation` + beep | `#e0b956` (amber) | Claude is waiting for a permission decision |
| `Notification` / `elicitation_dialog`, `PreToolUse` / `AskUserQuestion` | `message-question` + beep | `#e0b956` (amber) | Claude is asking you a question |
| `Stop` | `check` | `#58c142` (green) | The response finished |
| `UserPromptSubmit` | cleared | — | You sent a new prompt |

The `UserPromptSubmit` / `--clear` entry is not part of the upstream Wave
example; it clears the leftover green checkmark when you submit the next prompt.
Drop it if you prefer the badge to persist until the next event overwrites it.

Restart any running Claude Code session so the new hooks are loaded.

## Troubleshooting

- **No badge appears.** Run `wsh badge check --color '#58c142'` directly in the
  VM session. If the badge shows, the problem is the hook config or PATH; if it
  does not, `wsh` is not reaching Wave — re-check that you connected via
  `wsh ssh lima-wave` and that `$WAVETERM` is set.
- **`wsh: command not found` in hooks.** Hooks rely on `wsh` being on `PATH`.
  Wave's session shell adds `~/.waveterm/bin` to `PATH`; if your hook runs in a
  stripped environment, use the absolute path `~/.waveterm/bin/wsh` in the hook
  commands.
- **`knownhosts: key is unknown` on connect.** The alias is still pointing at a
  `/dev/null` known_hosts file. Use a real file with `StrictHostKeyChecking
  accept-new` as shown above.
- **Notification badge is slow.** Upstream notes a known Claude Code issue where
  `Notification` hooks can be delayed by a few seconds before firing.

## See Also

- Wave's official guide: <https://docs.waveterm.dev/claude-code>
- [`CLAUDE.md`](../CLAUDE.md) — the Mac-host / Lima-VM development split that
  makes this bridge necessary
