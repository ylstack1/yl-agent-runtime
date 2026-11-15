# ADR-007: rappct as Windows AppContainer/LPAC Toolkit

**Status:** Proposed (optional, Phase 0 evaluation)  
**Date:** 2026-11-16  
**Decision Makers:** YL Stack engineering team  

## Context

Per PRD section 8.4, Windows preferred evaluation order starts with AppContainer. rappct is a Rust AppContainer/LPAC toolkit discovered during research.

## Options Considered

| Option | Version | License | MSRP | Notes |
|--------|---------|---------|------|-------|
| rappct (cpjet64/rappct) | 0.13.3 | MIT | 1.90 | AppContainer profiles, capabilities, process launch, diagnostics |
| Raw Windows API via windows crate | 0.59 | MIT/Apache-2.0 | N/A | More control, more FFI/unsafe code |
| Custom AppContainer implementation | N/A | Internal | N/A | High maintenance burden |

## Decision

**Use rappct 0.13.x** as optional Windows AppContainer support, behind a feature flag.

## Rationale

- MIT license compatible
- Provides AppContainer profiles, capabilities, process launch, diagnostics
- Actively maintained (recent downloads ~35K)
- MSRP 1.90 aligns with our toolchain

## Consequences

### Positive
- Reduces unsafe FFI code for AppContainer
- Diagnostics capability helps with enforcement reporting
- Feature-gatable — not required for minimal build

### Risks / Mitigations
- **Windows 10 compatibility**: Must verify AppContainer works on Windows 10. Mitigation: probe at runtime, fall back to restricted token + Job Objects.
- **Small crate (45K downloads)**: Less battle-tested than windows crate alone. Mitigation: thorough testing on Windows 10/11.

## Open Questions

- [ ] Verify rappct Windows 10 support
- [ ] Decide feature flag name (e.g., `appcontainer`)
