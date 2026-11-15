# YL Agent Runtime

**Unified Portable Agent Execution Runtime**

A lightweight, portable execution service that gives AI agents controlled access to real development environments. It is the execution and policy layer between an agent and the operating system — not an AI model, IDE, container manager, or remote desktop product.

## Specification

See [PRD v0.2.0](https://github.com/yl-stack/yl-agent-runtime) for the full product requirements and technical specification.

## Architecture

```
yl-agent-runtime/
  crates/
    runtime-core/       # Core types, traits, errors
    runtime-daemon/     # Daemon lifecycle and service coordination
    runtime-cli/        # CLI (yl) for diagnostics and administration
    runtime-protocol/   # MCP tool and message definitions
    runtime-policy/     # Policy engine and capability model
    runtime-identity/   # Agent/device identity, pairing, revocation
    runtime-approval/   # User approval broker
    runtime-workspace/  # Safe file operations with path containment
    runtime-process/    # Process execution, trees, limits
    runtime-terminal/   # PTY/ConPTY interactive sessions
    runtime-toolchain/  # Toolchain discovery (no bundling)
    runtime-audit/      # Append-only audit records
    runtime-mcp/        # MCP server adapter (rmcp)
    runtime-transport/  # Local IPC + optional Iroh remote
    runtime-backend-api/# Stable backend trait boundary
    backend-native/     # Native host execution backend
    backend-windows/    # Windows: AppContainer, Job Objects
    backend-linux/      # Linux: Landlock, seccomp, cgroups
    backend-macos/      # macOS: Seatbelt
    backend-arapuca/    # Arapuca sandbox backend (Phase 0 eval)
    backend-virtx/      # Virtx VM backend (Phase 5, optional)
    runtime-config/     # Configuration and migrations
    runtime-testkit/    # Test utilities and fixtures
  apps/
    desktop-tauri/      # Optional Tauri 2 desktop UI
  docs/
    architecture/       # Architecture decision records
    threat-model/       # Threat modeling
    decisions/          # ADRs
    integrations/       # Integration guides
  tests/
    conformance/        # Conformance tests
    security/           # Security tests
    cross-platform/     # Cross-platform tests
```

## Key Design Principles

- **Native first, isolated when needed** — Trusted work uses native host toolchains under controlled permissions; untrusted work uses stronger sandbox profiles.
- **No silent downgrade** — If required isolation cannot be applied, execution is rejected or the user is asked to choose a weaker profile. Never label unsandboxed as sandboxed.
- **Capability-oriented API** — Agents request named capabilities (`workspace.read`, `process.exec`, `terminal.interactive`, etc.).
- **MCP first** — Uses the official Rust MCP SDK (`rmcp`) for agent protocol.
- **Headless by design** — The daemon works without Tauri, Node, Python, Docker, WSL, or SSH.

## Platform Support

| Platform | Status | Isolation Backend |
|----------|--------|-------------------|
| Windows 10/11 x64 | P0 | Restricted token + Job Objects; AppContainer where supported |
| Linux x64/ARM64 | P1 | Landlock, seccomp, namespaces, cgroups v2 |
| macOS Apple Silicon/Intel | P1 | Seatbelt sandbox profiles |

## Development Status

**Phase 0** — Feasibility and reuse audit (in progress)
- [x] Repository structure and Cargo workspace
- [x] Architecture Decision Records (ADRs 001-009)
- [x] Dependency research (arapuca 0.2.9, rmcp 3.10, iroh 1.4.1, portable-pty 0.9)
- [x] Core types and traits
- [x] Workspace path safety validation
- [x] Policy engine with profiles
- [x] Native host backend
- [x] Windows/Linux/macOS backend stubs
- [ ] Windows 10 process supervision PoC
- [ ] ConPTY PoC
- [ ] Arapuca evaluation

**Phase 1** — Native Windows MVP (planned)
- Rust daemon and CLI
- Project registry
- Workspace read/write/search
- Toolchain discovery
- Native process execution
- Job Object process-tree supervision
- Output streaming and cancellation
- Audit log
- Local MCP stdio server
- Minimal policy and approval system

## License

MIT OR Apache-2.0

## Related Projects (References Only)

- [Arapuca](https://github.com/sergio-correia/arapuca) — Cross-platform process sandbox (Apache-2.0)
- [rmcp](https://github.com/modelcontextprotocol/rust-sdk) — Official Rust MCP SDK (Apache-2.0)
- [iroh](https://github.com/n0-computer/iroh) — Encrypted peer transport (MIT OR Apache-2.0)
- [portable-pty](https://github.com/bytedance/portable-pty) — Cross-platform PTY/ConPTY
- [Tauri 2](https://github.com/tauri-apps/tauri) — Optional desktop UI
- [LocalForge MCP](https://github.com/takattowo/localforge-mcp) — Python reference implementation (design inspiration only)
