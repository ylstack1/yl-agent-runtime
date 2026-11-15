# ADR-005: portable-pty as Cross-Platform PTY/ConPTY Library

**Status:** Decided  
**Date:** 2026-11-16  
**Decision Makers:** YL Stack engineering team  

## Context

Per PRD section 12, the runtime needs ConPTY on Windows and PTY on Linux/macOS for interactive terminal sessions. PRD section 12 says to evaluate maintained ConPTY and cross-platform PTY crates before writing custom FFI.

## Options Considered

| Option | Platforms | License | Notes |
|--------|-----------|---------|-------|
| portable-pty | Windows (ConPTY), Linux/macOS (pty-system) | MIT/Apache-2.0 | Cross-platform, actively used by editors |
| conpty (zhiburt/conpty) | Windows only | Unknown | Windows ConPTY only |
| nix (PTY) | Linux/macOS | MIT/Apache-2.0 | Unix-only, needs Windows separate |
| Custom FFI | All | Internal | High maintenance, error-prone |

## Decision

**Use portable-pty 0.9.x** with `conpty` and `pty-system` features as the cross-platform terminal implementation.

## Rationale

- Single crate handles Windows ConPTY and Unix PTY
- Used by mature projects (edda/xi-editor ecosystem)
- Avoids custom terminal emulation (PRD requirement)
- Feature-gated platform support

## Consequences

### Positive
- Cross-platform PTY/ConPTY in one crate
- No custom FFI for terminal creation
- Well-tested in production editors

### Risks / Mitigations
- **Windows ConPTY requires Windows 10 1809+**: Must verify minimum Windows build. Mitigation: probe at runtime, report capability.
- **Scrollback limits**: portable-pty may not limit scrollback. Mitigation: implement our own bounded scrollback buffer.

## Open Questions

- [ ] Verify portable-pty Windows 10 1809+ compatibility
- [ ] Design bounded scrollback and output byte limits
