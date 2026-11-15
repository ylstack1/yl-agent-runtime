# ADR-004: Tauri 2 as Optional Desktop Control Center

**Status:** Decided (optional)  
**Date:** 2026-11-16  
**Decision Makers:** YL Stack engineering team  

## Context

Per PRD section 17, Tauri 2 is an optional desktop control center. The runtime must remain usable without it (headless).

## Options Considered

| Option | Version | License | Notes |
|--------|---------|---------|-------|
| Tauri 2 | 2.0 | MIT/Apache-2.0 | Small binary, Rust backend, system WebView |
| Electron | Various | Various | Large bundle, bundles Chromium |
| Custom native UI | N/A | Internal | Per-platform UI, high maintenance |
| No UI (CLI only) | N/A | MIT/Apache-2.0 | Headless only |

## Decision

**Use Tauri 2** as optional desktop application, in a separate crate (`apps/desktop-tauri`).

## Rationale

- Keeps UI outside the daemon's trusted computing base
- Small binary size (uses system WebView)
- Rust-first, aligns with our core implementation
- Tray-first support matches PRD requirements
- Optional — headless core works without it

## Consequences

### Positive
- UI cannot bypass authorization (daemon is policy authority)
- Optional dependency — core crate doesn't depend on Tauri
- Cross-platform (Windows, Linux, macOS)

### Risks / Mitigations
- **Tauri is optional**: desktop-tauri crate only builds when Tauri feature enabled
- **WebView availability**: System WebView must be present on target OS

## Open Questions

- [ ] Decide IPC mechanism between desktop and daemon (named pipe / Unix domain socket)
- [ ] Design tray icon and notification behavior
