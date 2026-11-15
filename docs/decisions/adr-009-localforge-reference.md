# ADR-009: LocalForge MCP as Reference Implementation (Design Inspiration Only)

**Status:** Decided (reference only, no code reuse)  
**Date:** 2026-11-16  
**Decision Makers:** YL Stack engineering team  

## Context

Per PRD section 5.1, LocalForge MCP is listed as a reference implementation for workspace APIs, process lifecycle, command handling, path validation, and security documentation.

## Findings

| Attribute | Value |
|-----------|-------|
| Repository | https://github.com/takattowo/localforge-mcp |
| Language | Python |
| License | MIT (reported — verify) |
| Transport | MCP STDIO (JSON-RPC) |
| Platform | Windows-focused |
| Stars | ~1 (low community adoption) |
| Maintenance | Unknown |

## Tools Provided (Reference)

- `project_context`, `list_directory`, `read_file`, `search_code` — Workspace
- `apply_patch` — File editing
- `git_status`, `git_diff`, `git_log`, `git_show` — Git inspection
- `shell`, `run_python` — Command execution
- `process_status`, `process_stop` — Process lifecycle
- `work_status`, `work_update` — Work state tracking
- `validate` — Path validation

## Decision

**Use LocalForge MCP as design inspiration only — do not copy code.**

### Rationale

1. **Python implementation**: Cannot be linked as a Rust dependency. Would require subprocess invocation or reimplementation.
2. **Low adoption**: ~1 GitHub star, unknown maintenance state — risky to depend on.
3. **Windows-focused**: PRD requires cross-platform (Windows, Linux, macOS).
4. **No OS sandbox**: Runs under current user context — not a security boundary. Useful for native host backend patterns, not sandbox backend.

### Patterns to Borrow (Design Only)

- Workspace root containment: resolve + check path doesn't escape root
- Job Objects for process-tree lifecycle on Windows
- Dev mode vs Safe mode execution profiles (maps to our ExecutionProfile)
- Structured tool schemas with permission requirements
- Audit logging for all operations
- Path validation rejecting traversal, symlinks outside root

## Open Questions

- [ ] Verify LocalForge license before using any patterns as inspiration
- [ ] Document which LocalForge patterns influenced our API design
