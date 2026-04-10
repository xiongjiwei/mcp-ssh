# mcp-ssh

An MCP server that lets AI agents (Claude Code, Cursor, etc.) execute shell commands on remote servers over SSH. It manages persistent, stateful SSH sessions — so `cd`, `export`, and other shell state carry over between commands. Zero install required on the remote side: it uses the system `ssh` binary and honors `~/.ssh/config`.

## How it works

```
AI Agent (Claude Code / Cursor)
        │  MCP JSON-RPC
        ▼
    mcp-ssh
        │  SSH (via system ssh + ~/.ssh/config)
        ▼
  Remote Server
```

The agent calls `open` to establish a session, `exec` to run commands, and `close` when done. All operations are audited to a local rotating log and optionally shipped to VictoriaLogs.

## Installation

```bash
go install github.com/xiongjiwei/mcp-ssh@latest
```

## Usage

**stdio mode** — for direct integration with agent frameworks:

```bash
mcp-ssh
# or explicitly:
mcp-ssh stdio
```

**HTTP serve mode** — for network-accessible MCP endpoint:

```bash
mcp-ssh serve
mcp-ssh serve --addr 127.0.0.1:7408
```

In serve mode the server listens at `:7408` by default and registers the MCP handler at `/mcp`.

## MCP Tools

| Tool | Description |
|------|-------------|
| `open` | Open a persistent SSH session to a host. Params: `host`, `user`. |
| `exec` | Run a command on an open session. Params: `host`, `command`, `timeout` (optional). Returns stdout + exit code. Shell state (cd, export) persists between calls. |
| `close` | Close the SSH session for a host and release resources. |
| `status` | List all active sessions with idle time and state. |

`exec` does not auto-open a session — call `open` first.

## Configuration

Config file location: `~/.mcp-ssh/config.toml` (created automatically with defaults on first run).

See [`config.example.toml`](config.example.toml) for all options. Key sections:

```toml
[server]
addr = "127.0.0.1:7408"

[session]
idle_timeout_minutes      = 30
connect_timeout_seconds   = 15
command_timeout_seconds   = 30
max_output_bytes          = 262144

[approval]
provider  = "auto_deny"
whitelist = ["ls", "pwd", "cat", "echo", "grep", "find",
             "wc", "head", "tail", "ps", "df", "du",
             "uname", "whoami", "env", "cd"]

[audit]
max_size_mb       = 128
max_age_days      = 3
compress          = false
victoria_logs_url = ""    # e.g. "http://victoria:9428"
```

## Approval

Every `exec` call goes through an approval gate before execution:

- **Whitelisted commands** run immediately.
- **Everything else** is passed to the configured approval provider.

| Provider | Behavior |
|----------|----------|
| `auto_deny` (default) | Deny all non-whitelisted commands immediately. Safe for unattended use. |
| `auto_allow` | Allow all non-whitelisted commands immediately. Use only in trusted environments. |

### Custom Approval Provider

Implement the `approval.Approver` interface and register it in `NewApprover`:

```go
// approval/my_approver.go
package approval

import "context"

type MyApprover struct{}

func (a *MyApprover) RequestApproval(ctx context.Context, user, host, command string) (bool, error) {
    // your logic here — return (true, nil) to allow, (false, nil) to deny
    return false, nil
}
```

Then register it in `approval/approver.go`:

```go
func NewApprover(cfg Config) Approver {
    switch cfg.Provider {
    case "auto_allow":
        return &AutoAllowApprover{}
    case "my_approver":
        return &MyApprover{}
    default:
        return &AutoDenyApprover{}
    }
}
```

Set `provider = "my_approver"` in `~/.mcp-ssh/config.toml` and rebuild.

## Audit Logging

All events (session open/close, exec, approval requested/approved/denied) are written to:

1. **`~/.mcp-ssh/audit.log`** — human-readable, rotated by size and age. Each entry includes a `digest` (first 4 bytes of SHA-256 over session+command+timestamp) to correlate approval and execution events.

2. **VictoriaLogs** — when `victoria_logs_url` is set, structured JSON events are shipped asynchronously. Each event includes `_msg`, `user`, `host`, `remote_ip`, `session`, `command`, `digest`, `exit_code`, `duration_ms`.

## Claude Code Integration

**stdio mode** — add to `~/.claude.json`:

```json
{
  "mcpServers": {
    "mcp-ssh": {
      "command": "mcp-ssh",
      "args": ["stdio"]
    }
  }
}
```

**HTTP mode** — start the server, then add:

```json
{
  "mcpServers": {
    "mcp-ssh": {
      "type": "http",
      "url": "http://127.0.0.1:7408/mcp"
    }
  }
}
```

## License

MIT
