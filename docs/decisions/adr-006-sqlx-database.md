# ADR-006: sqlx with SQLite for Durable Metadata and Audit

**Status:** Decided  
**Date:** 2026-11-16  
**Decision Makers:** YL Stack engineering team  

## Context

Per PRD section 16, use SQLite for durable metadata and audit indexing. TOML/JSON for human-editable policy files.

## Options Considered

| Option | License | Notes |
|--------|---------|-------|
| sqlx + SQLite | MIT/Apache-2.0 | Async, compile-time checked queries, Rust-native |
| rusqlite | MIT/Apache-2.0 | Synchronous, simpler but blocking |
| sled | MIT/Apache-2.0 | Embedded KV store, not SQL |
| PostgreSQL/MySQL | Various | Overkill for local runtime, requires server |

## Decision

**Use sqlx 0.8.x with SQLite** as the durable metadata and audit store.

## Rationale

- Async-native, integrates with Tokio
- Compile-time query checking reduces runtime SQL errors
- SQLite is serverless, single-file, zero-config
- MIT/Apache-2.0 dual license compatible

## Consequences

### Positive
- Zero-operational-overhead database
- ACID transactions for audit integrity
- Async, non-blocking

### Risks / Mitigations
- **SQLite write contention**: Single writer limitation. Mitigation: async serialization through audit service, WAL mode.
- **Schema migrations**: Must support schema versions. Mitigation: use sqlx migrate with embedded migration files.

## Open Questions

- [ ] Design migration strategy for policy schema versions
- [ ] Decide WAL vs journal mode for SQLite
- [ ] Audit log rotation and retention policy
