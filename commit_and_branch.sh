cd "/e/ylstack-space/Developments/ai/agents_app/yl-agent-runtime"
git add -A
git commit -m "feat(phase2): process execution MCP tools + E2E tests

Add process execution capabilities to the MCP server:
- Executable allowlist (cargo, git, node, python, go, dotnet, etc.)
- Direct argv execution - no implicit shell
- Windows Job Object kill-on-close (spawn suspended -> assign -> resume)
- Env whitelist/deny for secrets (*TOKEN*, *SECRET*, *PASSWORD*, etc.)
- Output redaction: (token|secret|password|api[_-]?key)[:=]\\S+ -> [REDACTED]
- Spill overflow: inline head+tail 30KB + spill file added to read roots
- Timeout: graceful terminate -> 10s -> force kill; Job Object cleanup
- Cursor-paged process log: seq chunks, ring buffer 4MB, after/next_after
- Process registry GC: TTL 1h exited, max 50 processes
- MCP tools: process.start/read/stop/list/discover_tools + process.exec
- CLI yl exec subcommand (project, program, args, approve, timeout)
- 7 E2E stdio tests against real yl binary, all pass

Also includes Phase 1 files: opencode.json MCP client config, phase2 plan doc."
git branch phase2-process-shell
git log --oneline -3
git status --short
