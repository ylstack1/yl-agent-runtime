# ADR-008: Virtx as Optional VM Backend

**Status:** Proposed (optional, Phase 5)  
**Date:** 2026-11-16  
**Decision Makers:** YL Stack engineering team  

## Context

Per PRD section 9.4, Virtx is an optional candidate for VM isolation. VM execution is optional, isolated from the core, and never silently substituted for native execution.

## Options Considered

| Option | Platforms | License | Notes |
|--------|-----------|---------|-------|
| Virtx (brekkylab/virtx) | Linux VM backend, Windows 11+/macOS optional | Unknown | Disposable Linux execution environments |
| Custom QEMU/libvirt integration | All | Various | High integration burden |
| No VM backend | N/A | N/A | Phase 1-4 don't need VM |

## Decision

**Defer Virtx integration to Phase 5.** Create the crate structure but keep it as a stub pending host requirements verification.

## Rationale

- VM backend is not needed for Phase 1 MVP (native Windows execution)
- Must verify host requirements and mount dependencies before adoption
- PRD explicitly says "Do not combine two VM providers into the first release"
- Never mandatory for ordinary Windows 10 native development

## Consequences

### Positive
- Keeps initial release focused and small
- VM crate exists as placeholder for future integration

### Risks / Mitigations
- **Virtx Linux-specific**: May not work on Windows 10. Mitigation: evaluate separately per PRD.
- **VM images not bundled**: Must design image download/caching strategy.

## Open Questions

- [ ] Verify Virtx host requirements (Windows 11+, Linux, macOS)
- [ ] Review Virtx license and maintenance
- [ ] Design VM image format and caching strategy
