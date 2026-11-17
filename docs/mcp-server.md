# YL Agent Runtime — MCP Server Documentation

## Overview

YL Agent Runtime exposes an MCP (Model Context Protocol) server that gives AI agents controlled access to your local filesystem and process execution. The server supports two transports:

- **Stdio** (`yl mcp --root <dir>`) — for local MCP clients (Opencode, Claude Desktop, Cursor)
- **Streamable HTTP** (`yl serve --root <dir>`) — for remote/networked MCP clients

## Quick Start

### Start the MCP server over HTTP

```powershell
# Basic (localhost only)
cargo run -p runtime-cli -- serve --root .

# Or run the compiled binary directly
./target/debug/yl.exe serve --root .

# Bind to all interfaces (LAN accessible)
./target/debug/yl.exe serve --allow-remote --root .

# Custom port
./target/debug/yl.exe serve --host 0.0.0.0 --port 8080 --root .

# With custom config file
./target/debug/yl.exe serve --root . --config ./config/runtime.toml
```

### Connecting from another device (phone / Android MCP client)

1. Start the server bound to all interfaces:

   ```powershell
   ./target/debug/yl.exe serve --allow-remote --root .
   ```

2. Find the machine's LAN address:

   ```powershell
   Get-NetIPAddress -AddressFamily IPv4 |
     Where-Object { $_.InterfaceAlias -notmatch 'Loopback' -and $_.IPAddress -notmatch '^169\.' } |
     Select-Object IPAddress
   ```

3. Point the client at `http://<lan-ip>:8077/mcp` (for example
   `http://192.168.1.130:8077/mcp`). Allow port `8077` through Windows
   Firewall on **Private** networks:

   ```powershell
   New-NetFirewallRule -DisplayName "YL Agent Runtime MCP" -Direction Inbound `
     -Protocol TCP -LocalPort 8077 -Profile Private -Action Allow
   ```

**Why `--allow-remote` matters for `403 Forbidden`.** rmcp protects against DNS
rebinding by checking the request's `Host` header against an allowlist that
defaults to `localhost`, `127.0.0.1` and `::1`. A phone sends
`Host: 192.168.1.130:8077`, which is not on that list, so the server answers
`403 Forbidden` before the request ever reaches a tool. `--allow-remote` (or any
non-loopback `--host`) therefore disables the host allowlist and the server
accepts any `Host` value. Loopback-only mode keeps the strict default.

> Security note: with `--allow-remote` anyone on the same network can call the
> tools. Run it only on trusted networks, keep `--root` pointed at a project
> directory, and remember the workspace layer still refuses paths outside the
> configured roots and blocks sensitive files such as `.env`.

### Connect an MCP client

#### Opencode (`opencode.json`)

```json
{
  "mcp": {
    "servers": {
      "yl-runtime": {
        "type": "local",
        "command": ["target/debug/yl.exe", "serve", "--root", "."]
      }
    }
  }
}
```

For remote HTTP access:

```json
{
  "mcp": {
    "servers": {
      "yl-runtime": {
        "type": "remote",
        "url": "http://127.0.0.1:8077/mcp"
      }
    }
  }
}
```

### Available MCP Tools

| Tool | Description |
|------|-------------|
| `workspace.read` | Read file content with byte/line modes |
| `workspace.write` | Create or overwrite files |
| `workspace.edit` | Apply find/replace edits (all-or-nothing) |
| `workspace.patch` | Apply unified git diffs |
| `workspace.replace_text` | Replace occurrences of text |
| `workspace.search` | Search file contents (regex supported) |
| `workspace.find_files` | Find files by glob pattern |
| `workspace.list` | List directory entries |
| `workspace.tree` | Recursive directory tree |
| `workspace.stat` | File metadata |
| `workspace.mkdir` | Create directory |
| `workspace.move` | Move/rename file |
| `workspace.delete` | Delete file or directory |
| `workspace.allowed_roots` | List configured workspace roots |
| `process.exec` | Execute command and wait for completion |
| `process.start` | Start long-running process |
| `process.read` | Read process output (cursor-paged) |
| `process.stop` | Terminate process |
| `process.list` | List running processes |
| `process.discover_tools` | Discover installed toolchains |
| `runtime.status` | Runtime status summary |
| `runtime.capabilities` | Backend capabilities |

## Configuration

### Command-line flags

| Flag | Default | Description |
|------|---------|-------------|
| `--root` | (required) | Workspace root directory (repeatable for multiple roots) |
| `--read-only-root` | — | Read-only workspace root |
| `--config` | `./config/runtime.toml` | Path to config file |
| `--host` | `127.0.0.1` | Bind address (HTTP server only) |
| `--port` | `8077` | Bind port |
| `--allow-remote` | false | Bind to `0.0.0.0` and accept any `Host` header (needed for LAN/phone clients) |

### Config file (`config/runtime.toml`)

```toml
[workspace]
roots = ["/path/to/workspace1", "/path/to/workspace2"]
read_only_roots = ["/path/to/readonly"]
max_file_size = 10485760

[audit]
enabled = true
retention_days = 90
max_log_size_mb = 100
redact_secrets = true

[policy]
default_profile = "Development"
fail_closed = true
require_approval_for = ["ProcessExec", "TerminalOpen", "GitCommit", "SystemElevate"]

[transport]
enable_stdio = true
enable_streamable_http = true
http_bind_address = "127.0.0.1"
http_port = 8077
enable_iroh = false
```

## Security

### Path Containment

All file operations are validated against configured workspace roots:

- Paths must resolve inside an allowed root
- Symlinks/junctions are resolved and re-checked against roots
- NTFS alternate data streams (`.txt:stream`) are rejected
- Reserved device names (`CON`, `PRN`, `NUL`, `COM1-9`, `LPT1-9`) are rejected
- Trailing dots/spaces in path components are rejected
- Null bytes are rejected
- Path traversal (`..`) is rejected

### Secret-File Blocking

The following file patterns are blocked from read/write/edit:

- `.env`, `.env.*`, `.envrc`
- `*.pem`, `*.key`, `*.p12`, `*.pfx`, `*.ppk`, `*.jks`, `*.keystore`
- `*id_rsa*`, `*id_dsa*`, `*id_ecdsa*`, `*id_ed25519*`
- `.ssh/**`, `.gnupg/**`, `.aws/**`, `.kube/**`
- `.npmrc`, `.pypirc`, `.netrc`, `.git-credentials`, `.pgpass`
- `.vault-token`, `.terraform.d/credentials*`, `.cargo/credentials*`
- `.docker/config.json`, `.s3cfg`, `*.tfstate*`, `*.tfvars*`
- `.dev.vars{,.*}`, `.my.cnf`

### Approval Gates (Phase 3 — planned)

Currently all tools execute without approval. Phase 3 will add:

- Tool tiers: `read` (auto-approve), `write` (prompt), `exec` (prompt)
- Project-level `.yl/policy.toml` with operator trust-mark
- Global `config/runtime.toml` `[tools.approval]` section
- `--yolo` mode with one-time risk acknowledgement
- `approval.request` MCP tool with auto-deny after 30 minutes

## Error Handling

All tools return JSON-RPC responses. Errors use `McpError::invalid_params` for agent-fixable problems (with actionable fix hints) and `McpError::internal_error` for unexpected failures.

Example error:
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "error": {
    "code": -32602,
    "message": "Sensitive file blocked: E:\\workspace\\.env (matched .env)"
  }
}
```

## Testing

```powershell
# Test read
cargo run -p runtime-cli -- mcp --root . 
# Then in another terminal:
curl -s http://127.0.0.1:8077/mcp -X POST -H "Content-Type: application/json" -H "Accept: application/json, text/event-stream" -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"workspace.read","arguments":{"path":"README.md","head":5}}}'

# Test process execution
curl -s http://127.0.0.1:8077/mcp -X POST -H "Content-Type: application/json" -H "Accept: application/json, text/event-stream" -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"process.exec","arguments":{"command":"cargo","args":["--version"],"timeout_seconds":30}}}'
```

## Architecture

```
Client (Opencode/Claude/Cursor)
    │ MCP over HTTP/Stdio
    ▼
┌─────────────────────────────┐
│   YL Agent Runtime Server   │
│  ├── workspace.* tools      │
│  ├── process.* tools        │
│  └── runtime.* tools        │
└─────────────────────────────┘
         │
    ┌────┴────┐
    ▼         ▼
Filesystem   Process
(contained)  (Job Object)
```

## Troubleshooting

| Problem | Solution |
|---------|----------|
| "No workspace roots configured" | Pass `--root <dir>` or set `[workspace] roots` in config |
| "Sensitive file blocked" | The file matches a secret pattern (`.env`, `*.pem`, etc.) |
| "Absolute path not within allowed roots" | Use a relative path or add the directory as a root |
| Connection refused | Server not running; start with `yl serve --root .` |
| 403 Forbidden on a LAN/phone client | The `Host` allowlist blocks non-loopback names. Start with `--allow-remote` (or `--host 0.0.0.0`) |
| 415 Unsupported Media Type | Send `Content-Type: application/json` and `Accept: application/json, text/event-stream` |
| "Unknown argument 'X'" | The tool rejected the field; the error lists the valid argument names |
| `tool not found` | Tool names are dotted (`workspace.read`), not underscored (`workspace_read`) |

## Files

- `crates/runtime-cli/src/commands.rs` — `run_http_server()` implementation
- `crates/runtime-cli/src/main.rs` — `Serve` subcommand definition
- `crates/runtime-mcp/src/server.rs` — MCP server with all 24 tools
- `crates/runtime-workspace/src/path_safety.rs` — Path containment logic
- `crates/runtime-workspace/src/sensitive.rs` — Secret-file blocking
- `crates/runtime-process/src/process.rs` — Process execution engine
- `crates/runtime-process/src/cursor.rs` — Cursor-paged process logs
- `config/runtime.toml` — Runtime configuration file
