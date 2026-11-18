# Phase 3 Comparison Improvements Plan

**Branch:** `phase3-comparison-improvements` (from master `72f4808`)
**Source:** DesktopCommanderMCP analysis at `E:\ylstack-space\Developments\opensource\AI\mcp-skills\DesktopCommanderMCP`

## Weaknesses to Address (borrowed from DesktopCommanderMCP)

| # | Weakness | Borrowed Pattern | Priority |
|---|----------|-----------------|----------|
| 1 | No session-based process I/O (no `interact_with_process`, no paginated `read_process_output`) | `start_process` → `interact_with_process` → `read_process_output(offset, length)` | High |
| 2 | No session-based search pagination | `start_search` → `get_more_search_results` → `stop_search` | High |
| 3 | No fuzzy edit matching (exact `old_text` only) | Fuzzy search fallback at 0.7 similarity | Medium |
| 4 | No `blockedCommands` list (only allowlist) | `config.json` blockedCommands alongside allowlist | Medium |
| 5 | No dynamic runtime config (no `get_config`/`set_config_value`) | Runtime config get/set without restart | Medium |
| 6 | No `read_multiple_files` tool | `read_multiple_files({paths: [...]})` | Medium |
| 7 | No tool-call history query | `get_recent_tool_calls` with bounded previews | Low |
| 8 | No usage stats / feedback tools | `get_usage_stats`, `give_feedback` | Low |
| 9 | No negative offset file reading | Negative `offset` = read from end | Low |
| 10 | Error messages terse (no causes + fixes) | `buildPermissionError` with 5 causes + fixes | Medium |
| 11 | No `origin` telemetry field on schemas | `origin: 'ui' \| 'llm'` per tool | Low |
| 12 | No binary file support (Excel/PDF/DOCX) | Built-in Excel, PDF, DOCX read/edit | Low |

## Already Strong (Don't Touch)

- Approval gate (Allow/Deny/Ask with `approval_id`, 30-min TTL) — DesktopCommanderMCP has none
- Executable allowlist (deny-by-default) vs their blocklist (allow-by-default)
- `runtime.status` / `runtime.capabilities` with real data
- Argument alias normalization (`oldText`→`old_text`, flat `{path, old_text, new_text}`)
- Windows Job Object process containment (`KILL_ON_JOB_CLOSE`)
- Policy violations mapped to `-32602` not `-32603`
- Git tools with approval (`git.commit` blocks `git add -A`)
- Undo/Redo persistent journal
- Path containment + sensitive file blocking

## Plan of Execution

1. **Session-based process I/O** — Add `process.interact` (send stdin to running PID) and paginated `process.read(offset, limit_bytes)` returning `total_chars`, `line_count`, `stream_chars`
2. **Session-based search** — Add `search.start` (session-based), `search.more` (paginated), `search.stop`
3. **Fuzzy edit fallback** — In `workspace.edit`, if exact `old_text` fails, run fuzzy match at 0.7 similarity and offer closest region
4. **Blocked commands** — Add `blocked_commands` to `config/runtime.toml` `[tools.approval]` and check in `allowlist_error()`
5. **Dynamic config** — Add `config.get` / `config.set` MCP tools that read/write `config/runtime.toml` at runtime
6. **read_multiple_files** — Single tool accepting array of paths
7. **Educational error messages** — Wrap path/policy errors with causes + fixes list
8. **`get_recent_tool_calls`** — Query `data/audit.jsonl` with limit + preview truncation

## Verification

- `cargo check --workspace` gate clean (standard excludes)
- `cargo test` all passing
- Real MCP testing against live server on port 8077
