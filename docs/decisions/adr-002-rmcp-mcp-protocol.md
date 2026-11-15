# ADR-002: rmcp as MCP Protocol Implementation

**Status:** Decided  
**Date:** 2026-11-16  
**Decision Makers:** YL Stack engineering team  

## Context

Per PRD section 13.1, the runtime must use the official Rust SDK (`rmcp`) for MCP protocol handling. MCP is the primary agent protocol (MCP first).

## Options Considered

| Option | Version | License | MSRV | Notes |
|--------|---------|---------|------|-------|
| rmcp (modelcontextprotocol/rust-sdk) | 3.10.0 | Apache-2.0 | 1.88 | Official SDK, actively maintained |
| Custom MCP implementation | N/A | MIT/Apache-2.0 | Internal | High maintenance, protocol drift risk |
| Other community MCP crates | Various | Various | Various | Not official, less maintained |

## Decision

**Use rmcp 3.10.x** as the MCP server/client implementation.

## Rationale

- Official SDK from the Model Context Protocol authors
- Implements stable MCP 2026-07-28 spec
- Actively maintained (49M+ downloads, recent releases)
- Apache-2.0 license compatible with our dual licensing
- Supports stdio and Streamable HTTP transports (PRD section 13.3)

## Consequences

### Positive
- Protocol compliance by construction
- Active security updates
- Macro-based tool definition (`#[tool]`)

### Risks / Mitigations
- **MSRV 1.88**: Requires relatively recent Rust. Mitigation: document MSRV in CI.
- **Breaking changes in 3.x**: Pin exact version, use cargo audit/deny.

## Open Questions

- [ ] Pin exact rmcp version with checksum
- [ ] Review `#[tool]` macro Send limitations on async bodies
