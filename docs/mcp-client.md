# YL Agent Runtime — MCP Client Documentation

## Overview

YL Agent Runtime exposes an MCP (Model Context Protocol) server that AI agents can connect to for real filesystem and process execution on your host. This guide covers connecting various MCP clients to the YL Agent Runtime server.

## Server Endpoints

| Transport | Endpoint | Use Case |
|-----------|----------|----------|
| Stdio | `yl mcp --root <dir>` | Local agents (Claude Desktop, Opencode, Cursor) |
| Streamable HTTP | `http://127.0.0.1:8077/mcp` | Remote/network agents |

## Client Configuration

### Opencode (`opencode.json`)

Place this in your project root or `~/.config/opencode/opencode.json`:

**Local (stdio):**
```json
{
  "mcp": {
    "servers": {
      "yl-runtime": {
        "type": "local",
        "command": ["target/debug/yl.exe", "serve", "--root", "."],
        "cwd": ".",
        "disabled": false
      }
    }
  }
}
```

**Remote (HTTP):**
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

### Claude Desktop (`claude_desktop_config.json`)

```json
{
  "mcpServers": {
    "yl-runtime": {
      "command": "C:\\path\\to\\yl.exe",
      "args": ["mcp", "--root", "C:\\path\\to\\workspace"]
    }
  }
}
```

### Cursor (`.cursor/mcp.json`)

```json
{
  "mcpServers": {
    "yl-runtime": {
      "command": "yl",
      "args": ["mcp", "--root", "."],
      "env": {}
    }
  }
}
```

## Available Tools

Once connected, your agent can call these MCP tools:

### Filesystem Tools

| Tool | Description | Example Use |
|------|-------------|-------------|
| `workspace.read` | Read file contents | Read source code, configs, logs |
| `workspace.write` | Create/overwrite files | Write code, configs, documentation |
| `workspace.edit` | Find/replace text edits | Modify specific lines in source files |
| `workspace.patch` | Apply unified git diffs | Apply code changes from patches |
| `workspace.replace_text` | Replace text occurrences | Rename variables, update strings |
| `workspace.search` | Search content (regex) | Find all occurrences of a pattern |
| `workspace.find_files` | Find files by glob | Discover project structure |
| `workspace.list` | List directory entries | Browse project files |
| `workspace.tree` | Recursive tree view | Visualize project structure |
| `workspace.stat` | File metadata | Check file size, timestamps |
| `workspace.mkdir` | Create directories | Scaffold project folders |
| `workspace.move` | Move/rename files | Reorganize project structure |
| `workspace.delete` | Delete files/dirs | Remove temporary files |

### Process Tools

| Tool | Description | Example Use |
|------|-------------|-------------|
| `process.exec` | Run command, wait for completion | Run `cargo build`, `npm test`, `git status` |
| `process.start` | Start long-running process | Start dev server, database |
| `process.read` | Read process output (cursor-paged) | Stream logs from long-running process |
| `process.stop` | Terminate process | Stop a dev server |
| `process.list` | List running processes | Check what's running |
| `process.discover_tools` | Discover toolchains | Check if cargo, node, python are installed |

### Example Agent Workflows

#### Read and edit a source file

1. `workspace.list` — Explore project structure
2. `workspace.read` — Read source file
3. `workspace.edit` — Make targeted changes
4. `workspace.read` — Verify changes

#### Run a build command

1. `process.discover_tools` — Check if cargo is installed
2. `process.exec` — Run `cargo build`
3. `process.read` — Check build output if long-running

#### Search and modify across files

1. `workspace.search` — Find all occurrences of a pattern
2. `workspace.edit` — Replace text in each file
3. `workspace.read` — Verify changes

## Safety & Security

### Path Containment

All file operations are contained within configured workspace roots:

```powershell
# Only files inside these roots are accessible
yl mcp --root C:\projects\myapp --root C:\projects\shared
```

Attempts to access files outside roots are rejected:
```json
{
  "error": "Absolute path not within allowed roots: C:\\Windows\\System32\\drivers\\etc\\hosts"
}
```

### Secret-File Blocking

These files cannot be read or written:
- `.env`, `.env.*`, `.envrc`
- `*.pem`, `*.key`, `*.p12`, `*.pfx`, `*.ppk`, `*.jks`, `*.keystore`
- `*id_rsa*`, `*id_dsa*`, `*id_ecdsa*`, `*id_ed25519*`
- `.ssh/**`, `.gnupg/**`, `.aws/**`, `.kube/**`
- `.npmrc`, `.pypirc`, `.netrc`, `.git-credentials`, `.pgpass`
- `*.tfstate*`, `*.tfvars*`, `.dev.vars{,.*}`
- `.docker/config.json`, `.s3cfg`

### Process Safety

- Executable allowlist: only `cargo`, `rustc`, `rustup`, `git`, `node`, `bun`, `python`, `python3`, `py`, `go`, `dotnet`, `cmake`, `ninja`, `java`, `javac` can be executed
- Direct argv execution only — no shell interpretation (prevents shell injection)
- Environment variable filtering: tokens, secrets, passwords, keys are blocked
- Timeout protection: processes are killed after the configured timeout
- Windows Job Object: children are terminated when the server exits

## Example Workflows

### Building a Rust Project

```powershell
# 1. Check if cargo is available
curl -s http://127.0.0.1:8077/mcp -X POST \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"process.discover_tools","arguments":{}}}'

# 2. Run cargo build
curl -s http://127.0.0.1:8077/mcp -X POST \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"process.exec","arguments":{"command":"cargo","args":["build"],"timeout_seconds":300}}}'
```

### Editing Source Code

```powershell
# 1. Read the file
curl -s http://127.0.0.1:8077/mcp -X POST \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"workspace.read","arguments":{"path":"src/main.rs","head":50}}}'

# 2. Edit the file
curl -s http://127.0.0.1:8077/mcp -X POST \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"workspace.edit","arguments":{"path":"src/main.rs","edits":[{"old_text":"fn main()","new_text":"fn main() {\n    println!(\"Hello from YL Agent Runtime\");\n}","expected_occurrences":1}]}}}'

# 3. Verify the edit
curl -s http://127.0.0.1:8077/mcp -X POST \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"workspace.read","arguments":{"path":"src/main.rs","head":10}}}'
```

## Troubleshooting

| Problem | Solution |
|---------|----------|
| "No workspace roots configured" | Pass `--root <dir>` to the server or set `[workspace] roots` in config |
| "Sensitive file blocked" | The file matches a blocked pattern (`.env`, `*.pem`, etc.) |
| "Absolute path not within allowed roots" | Use paths relative to the configured root |
| Connection refused | Server not running; start with `yl serve --root .` or `yl mcp --root .` |
| Tool not found | Ensure you're using the correct tool name from the tool list |
| Timeout | Increase `timeout_seconds` parameter (max 3600) |

## Architecture Diagram

```
┌─────────────────┐
│   AI Agent      │
│  (Opencode,     │
│   Cursor, etc.) │
└────────┬────────┘
         │ MCP over HTTP/Stdio
         ▼
┌─────────────────────────────┐
│   YL Agent Runtime Server   │
│  ├── workspace.* tools      │  ← Filesystem operations
│  ├── process.* tools        │  ← Process execution
│  └── runtime.* tools        │  ← Runtime status/capabilities
└─────────────────────────────┘
         │
    ┌────┴────┐
    ▼         ▼
Filesystem   Process
(contained)   (Job Object)
```

## Files

- `docs/mcp-server.md` — Server-side documentation
- `crates/runtime-cli/src/main.rs` — CLI entry point (`Mcp` and `Serve` subcommands)
- `crates/runtime-cli/src/commands.rs` — `run_mcp_server()` and `run_http_server()` implementations
- `crates/runtime-mcp/src/server.rs` — MCP server with all 24 tools
- `crates/runtime-workspace/src/path_safety.rs` — Path containment logic
- `crates/runtime-workspace/src/sensitive.rs` — Secret-file blocking
- `crates/runtime-process/src/process.rs` — Process execution engine
- `crates/runtime-process/src/cursor.rs` — Cursor-paged process logs
- `config/runtime.toml` — Runtime configuration file
- `opencode.json` — Example Opencode client configuration
