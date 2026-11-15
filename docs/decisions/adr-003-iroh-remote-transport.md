# ADR-003: Iroh as Optional Remote Transport

**Status:** Proposed (optional, Phase 4)  
**Date:** 2026-11-16  
**Decision Makers:** YL Stack engineering team  

## Context

Per PRD section 14.1, Iroh is an optional encrypted peer transport, not the authorization layer. The runtime still owns identity, access policy, and audit.

## Options Considered

| Option | Version | License | MSRP | Notes |
|--------|---------|---------|------|-------|
| iroh (n0-computer/iroh) | 1.4.1 | MIT OR Apache-2.0 | 1.91 | P2P QUIC, hole-punching, relay fallback |
| Custom TLS over TCP | N/A | MIT/Apache-2.0 | Internal | No NAT traversal, no relay |
| libp2p | Various | Various | Various | Heavier, more complex |

## Decision

**Use iroh 1.4.x** as optional remote transport, behind a Cargo feature flag (`iroh`).

## Rationale

- QUIC + NAT traversal with relay fallback — ideal for peer-to-peer connectivity
- Dial by public key — aligns with our identity model
- MIT OR Apache-2.0 dual license compatible
- Very actively maintained (last commit within hours)
- Not used as authorization layer — we layer our own identity/policy on top

## Consequences

### Positive
- Encrypted P2P connectivity out of the box
- Relay fallback for NAT-unfriendly networks
- Feature-flaggable — minimal local build excludes it

### Risks / Mitigations
- **Not an auth system**: We must implement our own pairing, identity binding, replay protection, revocation. Mitigation: clearly separate identity service from transport.
- **Large dependency**: iroh pulls in rustls, quinn, etc. Mitigation: feature-gated, optional.

## Open Questions

- [ ] Verify iroh works on Windows 10 (QUIC/UDP support)
- [ ] Design pairing flow (QR code or one-time code)
- [ ] Decide session token format and expiration
