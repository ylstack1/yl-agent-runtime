# ADR-001: Arapuca as OS Sandbox Backend

**Status:** Proposed (pending Phase 0 evaluation)  
**Date:** 2026-11-16  
**Decision Makers:** YL Stack engineering team  

## Context

The YL Agent Runtime requires an OS-native sandbox backend for executing untrusted code with kernel-enforced restrictions across Windows, Linux, and macOS. Per PRD section 9.3, Arapuca is the first candidate to validate.

## Options Considered

| Option | Platform Support | License | Maintenance | Notes |
|--------|-----------------|---------|-------------|-------|
| Arapuca | Windows (AppContainer/Job Objects), Linux (Landlock/seccomp/cgroups v2/network namespaces), macOS (Seatbelt) | Apache-2.0 | Active (v0.2.9, recent Fedora packaging) | Primary candidate per PRD |
| skarn-sandbox | Unknown | Unknown | Unknown | Alternative per PRD |
| Anthropic Sandbox Runtime | TypeScript, platform-specific | Unknown | Unknown | Reference only, not embeddable in Rust core |
| Custom implementation | All | MIT/Apache-2.0 | Internal | High maintenance burden |

## Decision

**Use Arapuca as the OS sandbox backend**, subject to Phase 0 verification:
1. License: Apache-2.0 — compatible with our MIT OR Apache-2.0 dual licensing
2. Version: pin to 0.2.x series
3. Repository: https://github.com/sergio-correia/arapuca (canonical; LeGambiArt is a fork/redirect)
4. Must verify Windows 10 compatibility explicitly (PRD requirement)

## Consequences

### Positive
- Cross-platform kernel-enforced isolation in a single Rust crate
- Active maintenance with Fedora packaging
- C-compatible static library option for embedding

### Risks / Mitigations
- **Windows 10 compatibility**: Must verify AppContainer and Job Objects work on Windows 10 minimum build. Mitigation: Prototype on Windows 10 first (PRD Phase 0).
- **API stability**: v0.2.x may have breaking changes. Mitigation: Pin exact version, vendor if needed.
- **MicroVM is Linux-specific/experimental**: We will not use Arapuca's microVM feature; Virtx remains separate for VM backend.

## Open Questions

- [ ] Verify Arapuca Windows 10 support (AppContainer availability on Windows 10)
- [ ] Review Arapuca unsafe Rust and FFI usage
- [ ] Confirm no incompatible transitive dependencies
- [ ] Decide: link as dependency vs invoke as subprocess vs design inspiration only
