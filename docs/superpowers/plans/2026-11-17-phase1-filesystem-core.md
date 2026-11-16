# Phase 1 — Filesystem Core (MCP Toolset) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A real agent-facing filesystem toolset over MCP stdio — `yl mcp --root <dir>` serves workspace.read/write/edit/patch/replace_text/search/find_files/list/tree/stat/mkdir/move/delete with hard path containment, secret-file blocking, EOL-preserving edits, and dry-run diffs — verified end-to-end by an rmcp client talking to the actual binary.

**Architecture:** New engines live in `runtime-workspace` (`path_safety` upgraded in place; new `sensitive.rs`, `files/{read,write,edit,patch}.rs`, `search.rs`) as inherent methods on the existing `WorkspaceServiceImpl`; `runtime-mcp` replaces its 4-tool demo server with the full tool registry driven by a JSON-argument normalization layer (aliases + did-you-mean); `runtime-cli`'s `mcp` subcommand becomes the single-process stdio server. Zero roots = fail closed.

**Tech Stack:** Rust 2021, rmcp 3.10 (`server`, `macros`, plus `client`+`transport-child-process` in test deps), `diffy 0.5`, `ignore 0.4`, `globset 0.4`, `regex 1.11`, `sha2 0.10`, `base64 0.22`, `tempfile 3`, tokio.

**Spec:** `docs/superpowers/specs/2026-11-17-mcp-toolset-design.md` (Phase 1 section + Resolved design decisions). PRD: `docs/spec/YL-Agent-Runtime-Specification-v0.2.md` (§13.1 names, §8.2 path safety).

## Global Constraints

- Windows 10/11 is the acceptance platform; every test must pass there. POSIX: compile-green only (`cargo check` on Windows covers the common code; `#[cfg(windows)]` guards Windows-specific tests).
- schemars 0.8 lives in workspace crates; rmcp 3.10 uses schemars 1.x internally. **Never** derive a `JsonSchema` for rmcp from core types — every new tool passes an explicit `input_schema = Arc::new(...)` built from `serde_json::json!` (pattern already used by `process_exec` in `crates/runtime-mcp/src/server.rs:116`).
- Tool names are dotted lowercase (`workspace.read`); JSON parameter names are snake_case; camelCase spellings are accepted as aliases, never required.
- Errors to agents: `McpError::invalid_params(msg, None)` for argument/containment/sensitive-path problems (agent-fixable), `internal_error` only for unexpected failures. Messages must state the fix ("pass overwrite: true", "Set recursive: true").
- No crate restructuring; no new workspace members; existing trait signatures in `runtime-core` unchanged.
- Every mutating tool call records one `AuditEvent` via `Arc<dyn AuditService>`; audit failures log a warning and never fail the tool call.
- PowerShell note: `cargo` commands in this repo are run from `E:\ylstack-space\Developments\ai\agents_app\yl-agent-runtime`; use `;` separators, not `&&`.

## Review Focus

1. **CRLF churn:** editing a CRLF file must not rewrite the whole file's line endings. Expect: untouched lines keep their exact bytes. → `edit_preserves_crlf_byte_exact` (Task 6).
2. **Symlink/junction escape after registration:** a junction created *inside* the root pointing outside must be caught at call time. Expect: `PathEscape` error, no read. → `validate_rejects_junction_escape_at_call_time` (Task 2).
3. **Secret-file write bypass:** `.env` must be refused by write/edit/patch/replace/move/copy/delete, not just read. Expect: `invalid_params` naming the matched pattern. → `all_write_paths_refuse_sensitive_files` (Task 9).
4. **Silent first-match edit:** a multi-occurrence `old_text` must never silently replace one instance. Expect: error listing up to 5 line numbers. → `multi_match_without_expected_occurrences_errors` (Task 6).
5. **Zero-roots server:** `yl mcp` with no `--root` must exit nonzero with instructions, never trust cwd. → `mcp_without_roots_fails_closed` (Task 12).

---

### Task 1: Workspace dependencies

**Files:**
- Modify: `Cargo.toml` (root, `[workspace.dependencies]`)
- Modify: `crates/runtime-workspace/Cargo.toml`
- Modify: `crates/runtime-mcp/Cargo.toml`

**Interfaces:**
- Produces: available deps `diffy`, `ignore`, `globset`, `regex`, `sha2`, `base64` in `runtime-workspace`; `runtime-config` + `base64` in `runtime-mcp`.

- [ ] **Step 1: Add to root `Cargo.toml` under `[workspace.dependencies]`** (after the `which` line):

```toml
# Phase 1 toolset: diffs, gitignore-aware walking, globs, hashing
diffy = "0.5"
ignore = "0.4"
globset = "0.4"
regex = "1.11"
sha2 = "0.10"
base64 = "0.22"
```

- [ ] **Step 2: `crates/runtime-workspace/Cargo.toml` — add to `[dependencies]`:**

```toml
diffy = { workspace = true }
ignore = { workspace = true }
globset = { workspace = true }
regex = { workspace = true }
sha2 = { workspace = true }
base64 = { workspace = true }
tempfile = { workspace = true }
```

- [ ] **Step 3: `crates/runtime-mcp/Cargo.toml` — add to `[dependencies]`:**

```toml
runtime-config = { path = "../runtime-config" }
base64 = { workspace = true }
```

- [ ] **Step 4: Verify workspace still compiles**

Run: `cargo check -p runtime-workspace -p runtime-mcp`
Expected: `Finished` with 0 errors (warnings about unused deps are acceptable).

- [ ] **Step 5: Commit**

```bash
git add Cargo.toml crates/runtime-workspace/Cargo.toml crates/runtime-mcp/Cargo.toml
git commit -m "build: add diffy/ignore/globset/regex/sha2/base64 for Phase 1 filesystem toolset"
```

---

### Task 2: Path safety upgrade (typed access modes, Windows hardening, realpath re-containment)

**Files:**
- Modify: `crates/runtime-workspace/src/path_safety.rs` (validator struct + `validate`)
- Test: same file `#[cfg(test)] mod tests`

**Interfaces:**
- Consumes: existing `PathValidator`, `ContainedPath`, `Error::{PathEscape, PathNotAllowed, Validation}`.
- Produces (used by Tasks 5–9):

```rust
pub enum AccessMode { Read, Write, Move }

impl PathValidator {
    /// Full pipeline: expanduser → normalize → deny/ADS/device/trailing checks
    /// → root containment → canonicalize (realpath) → re-containment.
    /// Write/Move refuse paths inside any read-only root.
    pub fn validate_access(&self, project_id: ProjectId, user_path: &Path, mode: AccessMode) -> Result<ContainedPath>;
    pub fn with_read_only_root(mut self, root: PathBuf) -> Self;
}

/// "/c/tmp/x" -> "C:\tmp\x"; "C:" -> "C:\"; lowercases→capitalizes drive letter;
/// forward slashes → backslashes; preserves a leading UNC "\\\\server\\share".
#[cfg(windows)]
pub fn normalize_windows_path(input: &str) -> String;
```

`validate()` keeps its signature and delegates to `validate_access(..., AccessMode::Read)` so all existing callers/tests are unchanged.

Upgrades to implement, in order inside `validate_access`:
1. Null byte check (existing).
2. `..`-collapse normalization (existing `normalize_path`) — but keep the drive prefix when the input is absolute Windows (current code drops `Prefix`; fix that: retain `Component::Prefix`).
3. **ADS colon check** (replaces the `contains(":$")` check): reject when the path string contains `':'` anywhere except as the drive prefix (`^[A-Za-z]:` or `\\?\C:`). Reject `file.txt:stream`, `file.txt::$DATA`, `C:data\evil`.
4. **Reserved device names per component** (replaces file_name-only check): every component matched case-insensitively against `WINDOWS_DEVICE_NAMES` including the `CON.txt` extension form (`^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(\..+)?$`).
5. **Trailing dot/space components**: any component ending in `.` or `' '` → reject (`Win32 strips them`).
6. **Drive normalization** (`#[cfg(windows)]`): run `normalize_windows_path` on the user path before containment.
7. Root containment (existing `resolve_against_roots`, separator-boundary safe: compare with `root + sep` prefix unless exact/root-drive match).
8. **Realpath re-containment**: `canonicalize()` the contained path; if it differs from the pre-canonical path, re-check `is_within_roots(canonical)` — a junction/symlink that leaves the roots fails with `Error::PathEscape`. ENOENT during canonicalize is fine (new file): skip re-containment only when `canonicalize` errors with NotFound, using the pre-canonical path.
9. Deny paths + read-only roots: deny (existing) applies to all modes; read-only roots refuse `Write`/`Move` with `Error::PathNotAllowed("Path is in a read-only root: {root}")`.

- [ ] **Step 1: Write the failing tests** (append to `mod tests` in `path_safety.rs`; Windows-only ones under `#[cfg(windows)]`):

```rust
#[test]
fn validate_rejects_ads_colon_stream() {
    let v = PathValidator::new().with_root(PathBuf::from("C:\\ws"));
    let err = v.validate(ProjectId::new(), Path::new("notes.txt:secret")).unwrap_err();
    assert!(matches!(err, Error::PathNotAllowed(_)));
}

#[test]
fn validate_rejects_reserved_name_with_extension() {
    let v = PathValidator::new().with_root(PathBuf::from("C:\\ws"));
    assert!(v.validate(ProjectId::new(), Path::new("src/NUL.txt")).is_err());
    assert!(v.validate(ProjectId::new(), Path::new("src/CON.txt")).is_err());
}

#[test]
fn validate_rejects_trailing_dot_and_space_components() {
    let v = PathValidator::new().with_root(PathBuf::from("C:\\ws"));
    assert!(v.validate(ProjectId::new(), Path::new("src/file.")).is_err());
    assert!(v.validate(ProjectId::new(), Path::new("src/file ")).is_err());
}

#[test]
fn validate_rejects_colon_after_drive_component() {
    let v = PathValidator::new().with_root(PathBuf::from("C:\\ws"));
    assert!(v.validate(ProjectId::new(), Path::new("C:\\ws\\C:\\evil")).is_err());
}

#[test]
fn read_mode_allows_readonly_root_write_mode_refuses() {
    let v = PathValidator::new()
        .with_root(PathBuf::from("C:\\ws"))
        .with_read_only_root(PathBuf::from("C:\\ws\\vendor"));
    let ok = v.validate_access(ProjectId::new(), Path::new("vendor/lib.rs"), AccessMode::Read);
    assert!(ok.is_ok());
    let err = v.validate_access(ProjectId::new(), Path::new("vendor/lib.rs"), AccessMode::Write).unwrap_err();
    assert!(err.to_string().contains("read-only"));
}

#[cfg(windows)]
#[test]
fn validate_converts_slash_drive_paths() {
    let tmp = std::env::temp_dir();
    let v = PathValidator::new().with_root(tmp.clone());
    // "/c/Users/..." spelling must resolve to the same drive root
    let slash_form = format!("/{}/foo.txt", &tmp.to_string_lossy().chars().next().unwrap().to_ascii_lowercase());
    let r = v.validate_access(ProjectId::new(), Path::new(&slash_form), AccessMode::Read);
    assert!(r.is_ok(), "slash-drive form should validate: {slash_form}");
}

#[cfg(windows)]
#[test]
fn validate_rejects_junction_escape_at_call_time() {
    let tmp = tempfile::TempDir::new().unwrap();
    let outside = tempfile::TempDir::new().unwrap();
    let root = tmp.path().join("ws");
    std::fs::create_dir_all(root.join("link")).unwrap();
    std::os::windows::fs::junction(outside.path(), root.join("link")).unwrap();
    let v = PathValidator::new().with_root(root.clone());
    let err = v.validate(ProjectId::new(), Path::new("link/secret.txt")).unwrap_err();
    assert!(matches!(err, Error::PathEscape(_)));
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p runtime-workspace path_safety`
Expected: FAIL — `validate_access`, `with_read_only_root`, `normalize_windows_path` do not exist; junction test fails on current code (returns Ok or wrong error).

- [ ] **Step 3: Implement** per the numbered pipeline above. Use a small hand-rolled drive-prefix matcher (no regex dep needed here); reuse `WINDOWS_DEVICE_NAMES`. `normalize_windows_path` is ~30 lines of string surgery: detect `\\?\` prefix, drive letter (`/c/`→`C:\`), replace `/`→`\`, collapse `\\` runs (outside UNC head), capitalize drive, append `\` for bare `C:`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p runtime-workspace path_safety`
Expected: all PASS (existing tests unchanged and passing).

- [ ] **Step 5: Commit**

```bash
git add crates/runtime-workspace/src/path_safety.rs
git commit -m "feat(workspace): typed access modes, ADS/reserved/trailing-dot rejection, slash-drive normalization, realpath re-containment"
```

---

### Task 3: Sensitive-file matcher

**Files:**
- Create: `crates/runtime-workspace/src/sensitive.rs`
- Modify: `crates/runtime-workspace/src/lib.rs` (add `pub mod sensitive;` + `pub use sensitive::*;`)

**Interfaces:**
- Produces (used by Tasks 8–9, 11):

```rust
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SensitiveVerdict { Allowed, Blocked { pattern: String } }

pub struct SensitiveMatcher { /* builtin/deny/allow GlobSets, private */ }

impl SensitiveMatcher {
    pub fn new() -> Self;
    pub fn with_operator_deny(self, patterns: &[String]) -> Self;
    pub fn with_operator_allow(self, patterns: &[String]) -> Self;
    /// Case-insensitive; matched against the file name AND the path.
    /// Strips an ADS suffix first ("notes.txt:ads" -> "notes.txt").
    pub fn verdict(&self, path: &Path) -> SensitiveVerdict;
}

pub const BUILTIN_SENSITIVE_PATTERNS: &[&str] = &[
    ".env", ".env.*", ".envrc", ".htpasswd", ".npmrc", ".pypirc", ".netrc", "_netrc",
    ".git-credentials", ".pgpass", ".ssh/**", ".gnupg/**", ".aws/**", ".kube/**",
    ".vault-token", ".terraform.d/credentials*", ".cargo/credentials*",
    ".docker/config.json", ".dockercfg", ".s3cfg",
    "*.tfstate", "*.tfstate.*", "*.tfvars", "*.tfvars.json", ".dev.vars",
    "*.pem", "*.key", "*.p12", "*.pfx", "*.ppk", "*.jks", "*.keystore",
    "*id_rsa*", "*id_dsa*", "*id_ecdsa*", "*id_ed25519*",
];
```

Pattern→glob rule: a pattern containing `/` is compiled as-is **and** with a `**/` prefix (matches at any depth); a bare pattern compiles as `**/<pat>` (basename match at any depth). Case-insensitive via `GlobBuilder::case_insensitive(true)`. Resolution order: operator deny match → `Blocked`; operator allow match → `Allowed` (relieves builtins only); builtin match → `Blocked`; else `Allowed`.

- [ ] **Step 1: Write the failing tests** (in `sensitive.rs`):

```rust
fn m() -> SensitiveMatcher { SensitiveMatcher::new() }

#[test]
fn builtin_env_blocked() {
    assert_eq!(m().verdict(Path::new("C:/ws/.env")), SensitiveVerdict::Blocked { pattern: ".env".into() });
    assert_eq!(m().verdict(Path::new("C:/ws/app/.env.local")), Blocked-ish); // use pattern ".env.*"
}
#[test]
fn builtin_key_case_insensitive() {
    assert!(matches!(m().verdict(Path::new("C:/ws/KEY.PEM")), SensitiveVerdict::Blocked { .. }));
}
#[test]
fn builtin_ssh_dir_blocked_and_nested() {
    assert!(matches!(m().verdict(Path::new("C:/ws/.ssh/id_rsa")), SensitiveVerdict::Blocked { .. }));
}
#[test]
fn plain_file_allowed() { assert_eq!(m().verdict(Path::new("C:/ws/notes.txt")), SensitiveVerdict::Allowed); }
#[test]
fn operator_allow_relieves_builtin_but_not_deny() {
    let a = m().with_operator_allow(&[".env".to_string()]);
    assert_eq!(a.verdict(Path::new("C:/ws/.env")), SensitiveVerdict::Allowed);
    let d = m().with_operator_deny(&["secrets/**".to_string()]).with_operator_allow(&["secrets/tokens.txt".to_string()]);
    assert!(matches!(d.verdict(Path::new("C:/ws/secrets/tokens.txt")), SensitiveVerdict::Blocked { .. }));
}
#[test]
fn ads_suffix_stripped_before_match() {
    assert_eq!(m().verdict(Path::new("C:/ws/notes.txt:hidden")), SensitiveVerdict::Allowed);
    assert!(matches!(m().verdict(Path::new("C:/ws/.env:hidden")), SensitiveVerdict::Blocked { .. }));
}
```

(Fix the `Blocked-ish` placeholder when writing: assert `pattern == ".env.*"`.)

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p runtime-workspace sensitive`
Expected: FAIL — module doesn't exist.

- [ ] **Step 3: Implement `SensitiveMatcher`** per the pattern rule. ADS strip: split the last path component on `':'` when a `':'` is present beyond a drive prefix and drop the tail before matching.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p runtime-workspace sensitive`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/runtime-workspace/src/sensitive.rs crates/runtime-workspace/src/lib.rs
git commit -m "feat(workspace): sensitive-file matcher with builtin patterns, operator deny/allow tiers, ADS stripping"
```

---

### Task 4: Read engine

**Files:**
- Create: `crates/runtime-workspace/src/files/mod.rs`, `crates/runtime-workspace/src/files/read.rs`
- Modify: `crates/runtime-workspace/src/lib.rs` (`pub mod files;`)

**Interfaces:**
- Produces (used by Task 9 service methods and Task 11 MCP tools):

```rust
#[derive(Debug, Clone, Default, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ReadOptions {
    pub offset: Option<u64>,        // byte offset
    pub max_bytes: Option<u64>,     // default 65_536; hard cap 1_048_576
    pub line_start: Option<u64>,    // 1-based, inclusive
    pub line_end: Option<u64>,      // 1-based, inclusive
    pub head: Option<u64>,          // first N lines
    pub tail: Option<u64>,          // last N lines
    pub line_numbers: bool,
    pub media: bool,
    pub want_sha256: bool,
}
pub struct TextRead { pub content: String, pub truncated: bool, pub next_line: Option<u64>, pub total_lines: Option<u64>, pub size: u64, pub returned_bytes: u64, pub sha256: Option<String> }
pub struct MediaRead { pub mime: String, pub base64: String, pub size: u64 }
pub enum ReadOutcome { Text(TextRead), Media(MediaRead), Binary { size: u64 } }

pub fn read_text(path: &Path, opts: &ReadOptions) -> Result<ReadOutcome>;      // runtime_core::error::Result
pub fn detect_binary_probe(path: &Path) -> std::io::Result<bool>;              // NUL byte in first 8192 bytes
pub fn mime_for_extension(ext: &str) -> &'static str;                          // png/jpeg/gif/webp/bmp/svg/mp3/wav/ogg/flac; else "application/octet-stream"
pub const READ_MAX_BYTES: u64 = 1_048_576;
pub const READ_DEFAULT_BYTES: u64 = 65_536;
pub const READ_MAX_LINES: usize = 2000;
pub const LINE_CUT_AT: usize = 4000;                                           // long line cut + " ...[line cut]"
```

Semantics (pin exactly):
- `head` + `tail` both set → `Error::Validation("Cannot specify both head and tail")`. `head`/`tail` compared against `Option` — `0` means zero lines.
- Binary probe true and `media == false` → `Error::Validation("Binary file; pass media: true for image/audio content")` returning `Binary` variant is NOT used for that error — `Binary` variant is returned only when `media == true` but the extension is not in the media table.
- Byte mode (no line params): read `min(max_bytes, READ_MAX_BYTES) + 1` bytes → `truncated` = more available; `next_line`/`total_lines` = `None`; lossy UTF-8 decode with `String::from_utf8_lossy` (byte mode may split a codepoint).
- Line mode (`line_start`/`line_end` or `head`/`tail` set): decode as UTF-8 (invalid → `Error::Validation("File is not valid UTF-8")`); windows of `READ_MAX_LINES`; lines numbered `"{n}\t{line}"` joined `\n` when `line_numbers` (default true for line mode); `line_start` past EOF → `Error::Validation("line_start {n} is past the end of the file ({m} lines)")`; when EOF reached `total_lines = Some(n)`, else `next_line = Some(last+1)`, `truncated = true`.
- `want_sha256` → hex sha256 of the *returned* bytes (the slice actually given to the agent, post-decode for text: hash the decoded string's bytes).

- [ ] **Step 1: Write the failing tests** (in `files/read.rs`):

```rust
// seeded file "l1\nl2\nl3\nl4\nl5\n"
#[test] fn byte_mode_defaults_and_truncation_flag();      // max_bytes=5 -> content "l1\nl2", truncated=true
#[test] fn line_mode_numbered_with_next_line();           // line_start 2 line_end 3 -> "2\tl2\n3\tl3", next_line=Some(4)
#[test] fn line_mode_past_eof_errors_with_message();      // line_start 9 -> message contains "(5 lines)"
#[test] fn head_and_tail_conflict_errors();               // both -> Validation
#[test] fn head_zero_returns_empty_not_error();           // head=0 -> content ""
#[test] fn tail_returns_last_n_lines();                   // tail=2 -> "4\tl4\n5\tl5", total_lines=Some(5)
#[test] fn binary_probe_detects_nul_and_media_serves_base64(); // png bytes with NUL: probe true; media:true -> MediaRead mime "image/png"
#[test] fn long_line_cut_marks_truncation();              // 5000-char line -> content contains " ...[line cut]"
#[test] fn sha256_hash_of_returned_slice();               // want_sha256 with known input -> sha2 hex of b"l1\n"
```

- [ ] **Step 2: Run to verify failure** — `cargo test -p runtime-workspace files::read`
Expected: FAIL (module missing).

- [ ] **Step 3: Implement `read_text`/`detect_binary_probe`/`mime_for_extension`** (~150 lines).

- [ ] **Step 4: Run to verify pass** — `cargo test -p runtime-workspace files::read`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/runtime-workspace/src/files crates/runtime-workspace/src/lib.rs
git commit -m "feat(workspace): read engine with byte/line modes, binary probe, media, sha256"
```

---

### Task 5: Write engine (atomic, overwrite guard, EOL preservation)

**Files:**
- Create: `crates/runtime-workspace/src/files/write.rs`

**Interfaces:**
- Consumes: `read_text` not required; uses `tempfile`, `diffy`.
- Produces (Task 9):

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Eol { Lf, Crlf }

#[derive(Debug, Clone, Default, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct WriteOptions { pub overwrite: bool, pub append: bool, pub want_diff: bool }

pub struct WriteOutcome { pub bytes: u64, pub eol: Eol, pub diff: Option<String> }

/// CRLF count > bare-LF count -> Crlf; empty or LF-only -> Lf
pub fn detect_dominant_eol(bytes: &[u8]) -> Eol;
pub fn write_text(path: &Path, content: &str, opts: &WriteOptions) -> Result<WriteOutcome>;
```

Semantics:
- `!overwrite && path exists && !append` → `Error::Validation("File exists; pass overwrite: true to replace it")`.
- Atomic: `tempfile::NamedTempFile::with_prefix(".yl-")` in the target's parent (parent dirs created first with `create_dir_all`), write bytes, `persist(path)` (Windows-correct replace).
- EOL: if the file exists and `detect_dominant_eol(existing) == Crlf` and `content` contains `'\n'` but not `"\r\n"` → replace `\n` with `\r\n` before writing; otherwise write verbatim. `append` writes bytes verbatim to the end (no EOL conversion, no atomicity guarantee documented).
- `want_diff` and file existed → `diffy::create_patch(old_lf_view, new_lf_view)` rendered via `Display`, headers replaced with the file path string, capped at 8192 chars with a trailing `"... diff truncated"`. New file → `diff = None`.

- [ ] **Step 1: Failing tests** (in `files/write.rs`):

```rust
#[test] fn overwrite_guard_message_exact();   // error text contains "pass overwrite: true"
#[test] fn new_file_written_verbatim();       // eol field is Lf, bytes == content.len()
#[test] fn crlf_target_preserved_when_content_has_bare_lf(); // write CRLF file, then write "a\nb" -> file bytes contain b"a\r\nb\r\n"? pin: bytes end with \r\n and contain no bare \n
#[test] fn append_extends_without_conversion();
#[test] fn diff_returned_for_overwrite_when_requested(); // diff contains "@@" and the path
#[test] fn persist_replaces_existing_on_overwrite();      // overwrite:true round-trip
```

- [ ] **Step 2: Verify fail** — `cargo test -p runtime-workspace files::write` → FAIL.
- [ ] **Step 3: Implement** (~120 lines).
- [ ] **Step 4: Verify pass** — `cargo test -p runtime-workspace files::write` → PASS.
- [ ] **Step 5: Commit** — `git commit -m "feat(workspace): atomic write engine with overwrite guard and EOL preservation"`

---

### Task 6: Edit engine (two-stage matcher, occurrence counting, closest-match errors, dry-run diff)

**Files:**
- Create: `crates/runtime-workspace/src/files/edit.rs`

**Interfaces:**
- Consumes: `write_text` + `detect_dominant_eol` (Task 5), `detect_binary_probe` (Task 4), `diffy`.
- Produces (Task 9):

```rust
#[derive(Debug, Clone, serde::Deserialize)]
pub struct EditSpec {
    pub old_text: String,
    pub new_text: String,
    #[serde(default)] pub expected_occurrences: Option<usize>, // default 1
}
#[derive(Debug, Clone, Default, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct EditOptions { pub dry_run: bool }
pub struct EditOutcome { pub applied_edits: usize, pub diff: Option<String>, pub dry_run: bool }
pub fn edit_text(path: &Path, edits: &[EditSpec], opts: &EditOptions) -> Result<EditOutcome>;
```

Algorithm (the one non-obvious body — implement exactly):
1. Probe binary → `Error::Validation("Binary file cannot be edited")`. Strict UTF-8 decode → `Error::Validation("File is not valid UTF-8")`.
2. `dominant = detect_dominant_eol(raw)`; work on the LF view: `original_lf = raw.replace("\r\n", "\n")`, `old/new` needles LF-normalized the same way.
3. `content = original_lf`; for each edit `i` (1-based), against the **evolving** `content`:
   - `expected = spec.expected_occurrences.unwrap_or(1)`; `count = count_occurrences(content, old)`.
   - `count == expected` (≥1) → `content = content.replacen(old, new, usize::MAX)`... pin: when `expected > 1` replace **all** occurrences (replacen MAX); when `expected == 1` replace the **first** only (`replacen(old, new, 1)`).
   - `count == 0` → **stage 2 fallback**: split `old` into lines (trailing empty line dropped from comparison but requires a newline after the match in the file); scan content lines top-down for a window where every file line's `trim()` equals the old line's `trim()` (inner whitespace must match). Exactly one window → replace it; each replacement line is re-indented: `indent_of(file_line) + indent_of(new_line) - indent_of(old_line)` clamped at 0 spaces (tabs treated as 4-space units for the delta). More than one window → `Error::Validation("Edit {i}: old_text matches {k} places (lines {a}, {b}, ...). Add surrounding lines or pass expected_occurrences.")` listing up to 5 line numbers (1-based, of window starts).
   - still no match → **closest-match error**: for every start line, similarity = sum of per-line bigram-Dice similarity with **all whitespace removed** (blank vs blank = 1.0); earliest best start wins; error text:
     `"Could not find exact match for edit {i} of {m}. old_text must match the file's text exactly; only line endings and leading/trailing whitespace may differ.\nold_text:\n{quoted old lines numbered}\nclosest region (lines {s}..{e}):\n{numbered file lines, ±2 around best start, max 30 lines, each clipped at 500 chars with '[…cut]'}\nRetry with old_text copied exactly from the file."`
   - `count != expected && count != 0` → `Error::Validation("Edit {i}: expected {expected} occurrence(s), found {count}. Pass expected_occurrences to replace all {count} of them.")`
   - `old == new` (after normalization) → `Error::Validation("Edit {i}: old_text equals new_text; nothing would change")`.
4. If `content == original_lf` → `Error::Validation("No edits changed the file")`.
5. EOL-preserving write: **first** try byte-exact — apply the same edits to `raw` with needles converted to `dominant` EOL (`old.replace('\n', "\r\n")` when CRLF); if the LF-view of that result equals `content` → final bytes = that result. Else final bytes = `content` with `\n` → `\r\n` when `dominant == Crlf`. Write with `WriteOptions { overwrite: true, .. }` (edit implies overwrite) but **skip** the diff generation in `write_text` — compute the diff here:
6. `diff = Some(diffy::create_patch(original_lf, content))` rendered, headers = the path, capped 20 480 chars + `"\n... diff truncated"`. `dry_run` → return `EditOutcome { dry_run: true, .. }` **without writing**.

Helpers: `fn count_occurrences(h: &str, n: &str) -> usize` (naive sliding match), `fn bigram_dice(a: &str, b: &str) -> f64`, `fn indent_of(line: &str) -> &str`.

- [ ] **Step 1: Failing tests** (seed files per test; exact assertions):

```rust
#[test] fn exact_single_replace();                       // "alpha\nbeta\n" edit alpha->ALPHA => "ALPHA\nbeta\n", applied_edits=1
#[test] fn multi_match_without_expected_errors_with_lines(); // "x\nx\nx\n" edit "x"->"y" => err msg contains "matches 3 places (lines 1, 2, 3)"
#[test] fn expected_two_replaces_all();                  // expected_occurrences Some(2) on "x\nx\nz\n" => "y\ny\nz\n"
#[test] fn count_mismatch_errors_with_fix_hint();        // 3 found, expected 2 => msg contains "expected 2 occurrence(s), found 3"
#[test] fn edit_preserves_crlf_byte_exact();             // CRLF file "a\r\nb\r\n": edit "a"->"A" => bytes b"A\r\nb\r\n" (no stray \n)
#[test] fn trim_fallback_matches_and_reindents();        // old "  if x {\n    go()\n  }" vs file indented 4 -> matches once, replacement uses file indent
#[test] fn closest_match_error_shows_region();           // wrong old_text => err contains "closest region (lines" and "Retry with old_text"
#[test] fn dry_run_writes_nothing_and_returns_diff();    // dry_run: file bytes unchanged, diff contains "@@"
#[test] fn old_equals_new_errors();
#[test] fn all_or_nothing_second_edit_failure_writes_nothing(); // edit1 ok + edit2 no-match => file bytes unchanged
```

- [ ] **Step 2: Verify fail** — `cargo test -p runtime-workspace files::edit` → FAIL.
- [ ] **Step 3: Implement** per the algorithm (~280 lines including tests).
- [ ] **Step 4: Verify pass** — `cargo test -p runtime-workspace files::edit` → PASS.
- [ ] **Step 5: Commit** — `git commit -m "feat(workspace): edit engine with occurrence counting, two-stage matcher, closest-match errors, dry-run diff"`

---

### Task 7: Patch engine (diffy PatchSet, two-phase apply)

**Files:**
- Create: `crates/runtime-workspace/src/files/patch.rs`

**Interfaces:**
- Consumes: `diffy::patch_set::{PatchSet, ParseOptions, FileOperation}`, `diffy::apply`.
- Produces (Task 9):

```rust
pub struct PatchFileResult { pub path: PathBuf, pub created: bool, pub bytes: u64 }
pub fn apply_patch_set(root: &Path, diff_text: &str, dry_run: bool) -> Result<Vec<PatchFileResult>>;
pub const PATCH_MAX_BYTES: usize = 262_144;   // diff text cap
pub const PATCH_MAX_FILES: usize = 10;
```

Semantics:
- `diff_text.len() > PATCH_MAX_BYTES` → `Error::Validation("Patch too large (max 262144 bytes)")`. Parse via `ParseOptions::gitdiff()`; parse error → `Error::Validation("Invalid patch: {e}")`. More than `PATCH_MAX_FILES` file ops → error.
- Path safety per file op (after `strip_prefix(1)`): must be relative; reject absolute, drive letters, leading `/`, any `..` component, NUL → `Error::Validation("Patch path escapes base: {p}")`. **Additionally** validate the joined path with the caller-provided root containment by construction (we join `root` + rel path; rel path cannot escape).
- `FileOperation::Delete` → `Error::Validation("Patch deletes are not supported; use workspace.delete")`.
- Two-phase: for every file, compute the new content in memory (`Modify`: read file, `diffy::apply(base, patch)` → `ApplyError(hunk_index)` → `Error::Validation("Patch hunk failed in {rel} (hunk {n})")`; `Create`: base `""`, target must not exist or error `"Patch creates {rel} but it already exists"`). Build all `NamedTempFile`s in each target's parent. Only after **all** temps are built: persist each (rename). If a persist fails mid-way, restore already-renamed targets from their saved original bytes (rollback) then error.
- `dry_run` → return the planned results with `bytes: 0`, write nothing.

- [ ] **Step 1: Failing tests:**

```rust
// git-style diff text modifying "a.txt": "-alpha\n+ALPHA\n" with @@ header
#[test] fn modify_applies_and_reports_bytes();
#[test] fn create_new_file_via_dev_null();               // "--- /dev/null\n+++ b/new.txt"
#[test] fn failing_hunk_leaves_file_unchanged();          // context mismatch => err; file bytes == original
#[test] fn dry_run_writes_nothing();
#[test] fn escaping_path_rejected();                      // b/../../evil.txt => "Patch path escapes base"
#[test] fn delete_operation_rejected();
#[test] fn two_files_second_failing_first_not_written();  // 2-file diff, 2nd hunk bad => a.txt unchanged
```

- [ ] **Step 2: Verify fail** — `cargo test -p runtime-workspace files::patch` → FAIL.
- [ ] **Step 3: Implement** (~180 lines).
- [ ] **Step 4: Verify pass** — `cargo test -p runtime-workspace files::patch` → PASS.
- [ ] **Step 5: Commit** — `git commit -m "feat(workspace): patch engine - diffy PatchSet with two-phase all-or-nothing apply"`

---

### Task 8: Search engine (gitignore-aware content search + find_files)

**Files:**
- Create: `crates/runtime-workspace/src/search.rs`
- Modify: `crates/runtime-workspace/src/lib.rs` (`pub mod search; pub use search::*;`)

**Interfaces:**
- Consumes: `SensitiveMatcher` (Task 3).
- Produces (Task 9):

```rust
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct SearchOptions {
    pub query: String,
    #[serde(default)] pub is_regex: bool,
    #[serde(default)] pub case_sensitive: bool,
    #[serde(default)] pub include: Vec<String>,     // file globs, e.g. "**/*.rs"
    #[serde(default)] pub exclude: Vec<String>,     // extra exclude globs
    #[serde(default)] pub context: u32,             // 0..=5
    #[serde(default = "default_max_results")] pub max_results: usize, // 200; hard cap 5000
    #[serde(default)] pub files_only: bool,
    #[serde(default)] pub include_hidden: bool,
    #[serde(default)] pub include_ignored: bool,
    #[serde(default = "default_max_file_size")] pub max_file_size: u64, // 1_000_000
    #[serde(skip)] pub sensitive: Option<crate::sensitive::SensitiveMatcher>,
}
pub struct SearchMatch { pub file: PathBuf, pub line: u64, pub column: u64, pub text: String, pub before: Vec<String>, pub after: Vec<String> }
pub struct SearchReport { pub matches: Vec<SearchMatch>, pub files_matched: u64, pub files_scanned: u64, pub skipped_binary: u64, pub skipped_too_large: u64, pub skipped_inaccessible: u64, pub truncated: bool }
pub fn search_tree(root: &Path, opts: &SearchOptions) -> Result<SearchReport>;

pub struct FindOptions { pub pattern: String, pub max_results: usize /*100*/, pub want_dirs: bool, pub include_hidden: bool, pub include_ignored: bool }
pub struct FindReport { pub paths: Vec<PathBuf>, pub total_matches: u64, pub files_scanned: u64, pub truncated: bool }
pub fn find_files(root: &Path, opts: &FindOptions) -> Result<FindReport>;
pub const DEFAULT_EXCLUDES: &[&str] = &[".git", "node_modules", "target", "dist", "build", "__pycache__", ".venv", "coverage", ".next", "vendor"];
```

Implementation rules:
- `ignore::WalkBuilder`: `hidden(!include_hidden)`, `git_ignore(include_ignored)`, `git_global(include_ignored)`, `require_git(false)`; default excludes applied as `overrides` unless `include_ignored` (use `ignore::overrides::OverrideBuilder::add("!{name}")` per `DEFAULT_EXCLUDES` + caller `exclude`).
- Regex: `is_regex == false` → `regex::escape(&query)`; `RegexBuilder` with `case_insensitive(!case_sensitive)`, `size_limit(10 * 1024 * 1024)`. Compile error → `Error::Validation("Invalid pattern: {e}")`.
- Per file: skip if `opts.sensitive.as_ref().map(|s| s.verdict(path)).is_blocked()`; skip binary (`detect_binary_probe`) counting `skipped_binary`; skip `len() > max_file_size` counting `skipped_too_large`; per-line match (read lines, `regex.captures(line)`); collect with `before`/`after` = context lines; stop collecting at `max_results` (`truncated = true`).
- `files_only` → one `SearchMatch` per matching file (`file`, `line: 0`, `column: 0`, empty text).
- `find_files`: pattern with no `*` → exact basename match at any depth (with `bare word hint` in the report? no — keep report data-only); else `GlobBuilder::new(pattern).literal_separator(true)` matched against the path **relative to root**.

- [ ] **Step 1: Failing tests** (seed a temp tree: `src/a.rs` with "fn main() {}", `src/deep/b.txt`, `.gitignore` with `deep/`, `node_modules/x.js`, a binary `blob.bin`):

```rust
#[test] fn literal_query_with_regex_chars_is_escaped();   // query "fn main() {}" finds a.rs
#[test] fn gitignore_and_default_excludes_skipped_unless_included(); // no match under deep/ or node_modules; counts via files_scanned delta when include_ignored
#[test] fn binary_and_too_large_counted_in_skip_triad();
#[test] fn context_lines_windowed();                      // context=1 returns before/after neighbors
#[test] fn max_results_truncates_flag();                  // max_results=1 -> truncated true
#[test] fn sensitive_files_excluded_from_results();       // matcher blocks .env -> no match, no error
#[test] fn find_files_bare_word_matches_any_depth();      // pattern "b.txt" -> src/deep/b.txt
#[test] fn find_files_glob_relative_path();               // pattern "**/*.rs" -> src/a.rs
```

- [ ] **Step 2: Verify fail** — `cargo test -p runtime-workspace search` → FAIL.
- [ ] **Step 3: Implement** (~220 lines).
- [ ] **Step 4: Verify pass** — `cargo test -p runtime-workspace search` → PASS.
- [ ] **Step 5: Commit** — `git commit -m "feat(workspace): gitignore-aware search + find_files with skip accounting and sensitive exclusion"`

---

### Task 9: Route WorkspaceServiceImpl through the engines + sensitive guard on all mutating paths

**Files:**
- Modify: `crates/runtime-workspace/src/service.rs`
- Modify: `crates/runtime-workspace/src/lib.rs` (re-exports if needed)

**Interfaces:**
- Consumes: Tasks 2–8 engines.
- Produces (Task 11 consumes these exact inherent methods on `WorkspaceServiceImpl`):

```rust
impl WorkspaceServiceImpl {
    pub fn sensitive(&self) -> SensitiveMatcher;                      // clone of the configured matcher
    pub fn set_sensitive(&self, matcher: SensitiveMatcher);           // CLI wiring (Task 10)
    pub async fn read_text(&self, project_id: ProjectId, path: &Path, opts: &ReadOptions) -> Result<ReadOutcome>;
    pub async fn write_text(&self, project_id: ProjectId, path: &Path, content: &str, opts: &WriteOptions) -> Result<WriteOutcome>;
    pub async fn edit_text(&self, project_id: ProjectId, path: &Path, edits: &[EditSpec], opts: &EditOptions) -> Result<EditOutcome>;
    pub async fn apply_patch(&self, project_id: ProjectId, diff_text: &str, dry_run: bool) -> Result<Vec<PatchFileResult>>;
    pub async fn search(&self, project_id: ProjectId, root_rel: Option<&Path>, opts: &SearchOptions) -> Result<SearchReport>;
    pub async fn find(&self, project_id: ProjectId, root_rel: Option<&Path>, opts: &FindOptions) -> Result<FindReport>;
    pub async fn delete_entries(&self, project_id: ProjectId, paths: &[PathBuf], recursive: bool) -> Result<Vec<PathBuf>>;
    pub async fn move_entry_checked(&self, project_id: ProjectId, source: &Path, dest: &Path) -> Result<PathBuf>;
}
```

Rules:
- Field `sensitive: SensitiveMatcher` added (default `SensitiveMatcher::new()`); validators per project now built with `.with_read_only_root(...)` when the profile is `Inspect` (read-only roots represented as Inspect-profile workspaces).
- Every method resolves via `validator.validate_access(project_id, path, mode)` — `Read` for read/search/stat, `Write` for write/edit/mkdir/delete-dest, `Move` for move source+dest.
- **Sensitive guard runs before every mutating op and before read** on the resolved path: `verdict != Allowed` → `Error::PathNotAllowed("Sensitive file blocked: {path} (matched {pattern})")`. Applies to: `read_text`, `write_text`, `edit_text`, `apply_patch` (each patched path), `delete_entries`, `move_entry_checked` (both ends).
- Trait methods `read_file`/`write_file`/`replace_text`/`search`/`find_files`/`delete`/`move_entry`/`copy_entry` are reimplemented as thin delegates into the engines (behavior supersedes old naive versions); `copy_entry` gains no new trait param but inherent `copy_entry_checked(..., overwrite: bool)` is added with the same guard; trait `move_entry` refuses when destination exists (`Error::Validation("Destination already exists: {p}")`).
- `delete_entries`: empty dir/file → ok; non-empty dir with `recursive == false` → `Error::Validation("Directory not empty. Set recursive: true.")`; missing path with `recursive == false` → error; returns the deleted paths.
- `apply_patch` root = the workspace root for `project_id`.

- [ ] **Step 1: Failing tests** (in `service.rs` tests module; temp roots):

```rust
#[tokio::test] async fn read_text_returns_engine_outcome();          // write then read via service, Text variant
#[tokio::test] async fn write_refuses_existing_without_overwrite();
#[tokio::test] async fn edit_via_service_preserves_crlf();
#[tokio::test] async fn all_write_paths_refuse_sensitive_files();    // .env: write_text, edit_text, move_entry_checked, delete_entries each -> PathNotAllowed containing "Sensitive file blocked"
#[tokio::test] async fn move_refuses_existing_destination();         // msg contains "Destination already exists"
#[tokio::test] async fn delete_nonempty_requires_recursive();        // msg contains "Set recursive: true"
#[tokio::test] async fn readonly_profile_refuses_write();            // register with ExecutionProfile::Inspect -> write_text errs "read-only"
#[tokio::test] async fn patch_via_service_two_phase();               // 2-file diff, 2nd bad -> first unchanged
```

- [ ] **Step 2: Verify fail** — `cargo test -p runtime-workspace service` → FAIL.
- [ ] **Step 3: Implement** (delegate plumbing; keep the naive helpers that remain referenced, delete ones now unused to avoid dead-code warnings).
- [ ] **Step 4: Verify pass** — `cargo test -p runtime-workspace` → ALL PASS.
- [ ] **Step 5: Commit** — `git commit -m "feat(workspace): route WorkspaceServiceImpl through read/write/edit/patch/search engines with sensitive guard on every mutating path"`

---

### Task 10: Config workspace section + real `yl mcp` + daemon backend registration

**Files:**
- Modify: `crates/runtime-config/src/config.rs`
- Modify: `crates/runtime-cli/src/main.rs`, `crates/runtime-cli/src/commands.rs`, `crates/runtime-cli/Cargo.toml`
- Modify: `crates/runtime-daemon/src/daemon.rs` (register NativeBackend in `new()`)

**Interfaces:**
- Consumes: `WorkspaceServiceImpl` (Task 9), `NativeBackend` (backend-native crate), rmcp `ServiceExt::serve(stdio())`.
- Produces:

```rust
// runtime-config
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkspaceConfig {
    #[serde(default)] pub roots: Vec<PathBuf>,
    #[serde(default)] pub read_only_roots: Vec<PathBuf>,
    #[serde(default = "default_ws_max_file_size")] pub max_file_size: u64, // 10_485_760
}
// Config gains: #[serde(default)] pub workspace: WorkspaceConfig  (+ Default impl)
```

```rust
// runtime-cli Commands::Mcp gains:
//   #[arg(long = "root")] roots: Vec<String>,
//   #[arg(long = "read-only-root")] read_only_roots: Vec<String>,
//   #[arg(long)] config: Option<String>,
// commands::run_mcp_server(opts: McpOptions) -> anyhow::Result<()>  where
// pub struct McpOptions { pub roots: Vec<String>, pub read_only_roots: Vec<String>, pub config: Option<String> }
```

Behavior of `run_mcp_server` (pin exactly):
1. Load config: `config` path if given (error if unreadable), else `./config/runtime.toml` when it exists, else `Config::default()`.
2. Merge roots: CLI `--root` args (expanded via `dunce::canonicalize`-style: `std::fs::canonicalize`, falling back to the literal path when NotFound since the root may not exist yet — no: roots must exist; error `"Workspace root does not exist: {p}"`) **replace** config roots when non-empty; else use config roots; read-only roots append and are also required to exist.
3. Fail closed: zero roots → `eprintln!("No workspace roots configured. Pass --root <dir> (repeatable) or set [workspace] roots in your config."); std::process::exit(1)`.
4. Build `WorkspaceServiceImpl::new()`; `set_sensitive(SensitiveMatcher::new())`; for each root: `service.register(root, ExecutionProfile::Development).await?`; for each read-only root: `register(root, ExecutionProfile::Inspect).await?`. Collect `(ProjectId, root)` pairs.
5. Build audit: `runtime_audit::AuditServiceImpl::new().with_log_path(config.data_dir.join("audit.jsonl"))` as `Arc<dyn runtime_audit::AuditService>`; create `config.data_dir` if missing.
6. Build `McpServer::new_for_fs(Arc<service>, roots_pairs, Arc<audit>)` — **constructor added in Task 11**; Task 10 compiles against it.
7. Serve: `use rmcp::ServiceExt; let server = mcp_server.serve(rmcp::transport::stdio()).await?; server.waiting().await?;` — return `Ok(())` on clean shutdown.

Daemon: in `RuntimeDaemon::new`, after building the struct: `let daemon = Self { ...backends: Arc::new(RwLock::new(Vec::new())) };` then in `new()` push `backend_native::NativeBackend::new()?` — pin: `new()` becomes:
`pub fn new(config) -> Result<Self>` → build `daemon`, then `daemon.backends.blocking_write()`... `new()` is sync and `backends` is tokio RwLock — simplest correct: construct the Vec before the struct: `let backends = vec![Box::new(backend_native::NativeBackend::new()?) as Box<dyn ExecutionBackend>];` and init the field from it. `runtime-daemon/Cargo.toml` gains `backend-native = { path = "../backend-native" }`.

`status`/`discover-tools` real: `show_status` prints version, platform/arch, config paths, and workspace roots from config; `discover_tools` instantiates `runtime_toolchain::ToolchainDiscovery` and prints each discovered toolchain (method names read from the crate; it's `discover()` per the crate's API — implementer confirms at implementation).

`runtime-cli/Cargo.toml` deps add: `runtime-workspace`, `runtime-mcp`, `runtime-audit`, `runtime-toolchain`, `backend-native`, `runtime-backend-api`, `rmcp = { workspace = true }`, `dirs` not needed (config paths come from Config). Dev-deps: `tempfile`, `serde_json`.

- [ ] **Step 1: Failing test** — `crates/runtime-cli/tests/fail_closed.rs`:

```rust
// Spawn the yl binary with NO --root and an empty stdin; it must exit nonzero.
#[test]
fn mcp_without_roots_fails_closed() {
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_yl"))
        .args(["mcp"]).stdin(std::process::Stdio::null())
        .output().unwrap();
    assert!(!out.status.success());
    let msg = String::from_utf8_lossy(&out.stderr);
    assert!(msg.contains("No workspace roots configured"), "stderr: {msg}");
}
```

Also a config test in `runtime-config/src/config.rs`: TOML with `[workspace] roots = ["C:/x"]` parses; TOML without a workspace section parses via defaults.

- [ ] **Step 2: Verify fail** — `cargo test -p runtime-cli -p runtime-config` → FAIL (subcommand lacks the flags / Config lacks the section; binary exits 0 today).
- [ ] **Step 3: Implement** config section, CLI flags, `run_mcp_server` per the pinned behavior, daemon backend registration, real status/discover-tools.
- [ ] **Step 4: Verify pass + manual smoke** — `cargo test -p runtime-cli -p runtime-config` PASS; then:

```powershell
$t = "$env:TEMP\yl-smoke"; New-Item -ItemType Directory -Force $t | Out-Null
Set-Content "$t\hello.txt" "hello world"
'{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"smoke","version":"0"}}}' | cargo run -p runtime-cli -- mcp --root $t
```

Expected: JSON response containing `"serverInfo"` and `"yl-agent-runtime"`.

- [ ] **Step 5: Commit** — `git commit -m "feat(cli): real yl mcp stdio server with --root/--read-only-root, fail-closed; config workspace section; daemon registers NativeBackend"`

---

### Task 11: runtime-mcp full tool registry + argument normalization

**Files:**
- Create: `crates/runtime-mcp/src/args.rs`, `crates/runtime-mcp/src/tools_fs.rs`
- Modify: `crates/runtime-mcp/src/server.rs`, `crates/runtime-mcp/src/lib.rs`

**Interfaces:**
- Consumes: Task 9 inherent methods; `runtime_audit::AuditService` + `runtime_core::audit::AuditEvent` (constructor read from `crates/runtime-core/src/audit.rs` at implementation).
- Produces:

```rust
// args.rs
pub fn normalize_args(tool: &str, args: &JsonObject) -> std::result::Result<JsonObject, McpError>;
//   - applies ALIASES (below); canonical key always wins when both present
//   - unknown keys: nearest known key within Levenshtein <= 2 -> error "Unknown argument '{k}'. Did you mean '{known}'?"
//     else -> "Unknown argument '{k}' for {tool}. Valid arguments: {list}"
//   - missing required keys (per REQUIRED table) -> "Missing required argument(s): {fields}"
pub fn levenshtein(a: &str, b: &str) -> usize;

pub const ALIASES: &[(&str, &[(&str, &str)])] = &[
    ("*path", &[("file","path"),("target","path"),("filepath","path"),("filePath","path")]),
    ("workspace.write", &[("text","content"),("data","content"),("force","overwrite")]),
    ("workspace.edit", &[("old","old_text"),("oldText","old_text"),("find","old_text"),
                         ("new","new_text"),("newText","new_text"),("replacement","new_text"),("replace","new_text"),
                         ("count","expected_occurrences"),("occurrences","expected_occurrences"),
                         ("dryRun","dry_run"),("dry","dry_run")]),
    ("workspace.search", &[("pattern","query"),("q","query"),("text","query"),
                           ("maxResults","max_results"),("limit","max_results"),
                           ("isRegex","is_regex"),("regex","is_regex"),("caseSensitive","case_sensitive"),
                           ("globs","include"),("include_globs","include"),
                           ("excludePatterns","exclude"),("exclude_globs","exclude")]),
    ("workspace.move", &[("src","source"),("from","source"),("dest","destination"),("dst","destination"),("to","destination")]),
    ("workspace.delete", &[("path","paths"),("files","paths")]),
    ("workspace.read", &[("start","line_start"),("end","line_end")]),
    ("workspace.stat", &[("file","path"),("target","path")]),
];
pub const REQUIRED: &[(&str, &[&str])] = &[
    ("workspace.read", &["path"]), ("workspace.write", &["path","content"]),
    ("workspace.edit", &["path","edits"]), ("workspace.patch", &["diff"]),
    ("workspace.replace_text", &["search","replacement"]), ("workspace.search", &["query"]),
    ("workspace.find_files", &["pattern"]), ("workspace.tree", &["path"]),
    ("workspace.mkdir", &["path"]), ("workspace.move", &["source","destination"]),
    ("workspace.delete", &["paths"]), ("workspace.stat", &["path"]),
];
```

- `tools_fs.rs` — one method per tool on `McpServer` inside a second `#[tool_router]`-merged impl (same struct; rmcp merges multiple `#[tool_router]` impls is NOT supported — so all tools live in the single existing `#[tool_router] impl McpServer` block in `server.rs`; `tools_fs.rs` holds the free helper fns + per-tool arg structs and the methods are written in `server.rs`):

Actually pin the structure precisely: all `#[tool]` methods go in the existing `#[tool_router] impl McpServer` in `server.rs`; `tools_fs.rs` provides:
```rust
pub fn resolve_project<'a>(roots: &'a [(ProjectId, PathBuf)], user_path: &Path) -> Option<(ProjectId, PathBuf)>;
//   absolute: first root that is a prefix (separator-boundary); relative: join roots[0]
pub fn output_json<T: serde::Serialize>(v: &T) -> Result<CallToolResult, McpError>;   // compact serde_json::to_string
pub fn invalid(msg: impl Into<String>) -> McpError;   // McpError::invalid_params(msg, None)
```

Tool methods (each takes `Parameters<JsonObject>`, calls `normalize_args`, `serde_json::from_value::<XxxArgs>`, then the service): `workspace.read`, `workspace.write`, `workspace.edit`, `workspace.patch`, `workspace.replace_text`, `workspace.search`, `workspace.find_files`, `workspace.list`, `workspace.tree`, `workspace.stat`, `workspace.mkdir`, `workspace.move`, `workspace.delete`, `workspace.allowed_roots`, plus **PRD-alias tools** `workspace.read_file` and `workspace.write_file` (thin delegates to read/write with the same arg handling; description "Deprecated alias of workspace.read"). `runtime.status`, `runtime.capabilities`, `process.exec` stay. Each tool's `input_schema` is an explicit `serde_json::json!` object mirroring the arg struct (snake_case, `required` from `REQUIRED`). No zero-arg `workspace.list` from the old server remains — the old one is replaced by `workspace.allowed_roots`.

`McpServer` struct changes:
```rust
pub struct McpServer {
    runtime: Arc<dyn RuntimeService + Send + Sync>,
    fs: Arc<WorkspaceServiceImpl>,
    roots: Vec<(ProjectId, PathBuf)>,       // ordered; roots[0] is primary for relative paths
    read_only_roots: Vec<PathBuf>,
    audit: Arc<dyn runtime_audit::AuditService>,
    principal_agent: String,   // "mcp-local" (design decision 4)
    session_id: SessionId,     // per-process synthetic session
}
impl McpServer {
    pub fn new_for_fs(fs: Arc<WorkspaceServiceImpl>, roots: Vec<(ProjectId, PathBuf)>, audit: Arc<dyn runtime_audit::AuditService>) -> Self;
}
```

Behavior pins:
- Zero roots → every workspace tool returns `invalid("No workspace roots configured. Restart with --root <dir>.")` (belt-and-braces; CLI already exits).
- Path tools resolve via `resolve_project`; unresolved → `invalid("Path is not within any allowed workspace root: {p}. Allowed roots: {list}")`.
- Mutating tools (`write`, `edit`, `patch`, `replace_text`, `mkdir`, `move`, `delete`) record one `AuditEvent` per call (type from `runtime_core::audit::AuditEventType` variants available; agent = `principal_agent`); failures → `tracing::warn!`, never fail the call.
- Error mapping: `Error::PathEscape | PathNotAllowed | Validation | WorkspaceNotFound` → `invalid(e.to_string())`; `Error::Io(e)` → `invalid(format!("IO error: {e}"))`; anything else → `McpError::internal_error`.
- `workspace.list` args: `path?`, `depth?` (default 1), `max_entries?` (default 1000, cap 20 000), `include_hidden?`, `sort_by?` ("name"|"size"); uses `ignore` walker at depth via Task 8's walker with a depth-bound wrapper **implemented here** (a small `walk_shallow` helper in `tools_fs.rs`, reusing `ignore::WalkBuilder` with `max_depth`). Output: entries `{name, type, size?, modified?}` + `total` + advice line `// hid {n} entries (hidden or ignored); pass include_hidden: true to see hidden entries.` when applicable.
- `workspace.tree` args: `path`, `depth?`, `exclude_patterns?`; output JSON array `{name, type, children?}`; entry budget 100 000 → `invalid("Tree stopped after 100000 entries under {root}. Narrow the path or add exclude_patterns.")`.
- `workspace.allowed_roots` → `{"roots": [...], "read_only_roots": [...]}`.
- `workspace.replace_text` args: `path?` (file only), `search`, `replacement`, `case_sensitive?` (default false), `max_matches?` (default 100), `dry_run?`; implemented on top of `edit_text` when `path` is a file (single edit, expected_occurrences = max_matches) — tree-wide replace is Phase 4; description says so.

- [ ] **Step 1: Failing tests** — `crates/runtime-mcp/tests/args_test.rs` (normalize_args, no server needed) and `crates/runtime-mcp/tests/handlers_test.rs` (build `McpServer::new_for_fs` with a temp root and call the tool methods directly — they're crate-private; tests in `crates/runtime-mcp/src/server.rs #[cfg(test)]` instead so access is guaranteed):

```rust
// args tests (tests/args_test.rs — normalize_args and levenshtein are pub)
#[test] fn alias_cmd_maps_to_command_for_execute();          // (reserved) {"cmd"} on a *path tool: {"file":"a.txt"} -> {"path":"a.txt"}
#[test] fn alias_old_find_map_to_old_text();                 // {"old","new"} -> old_text/new_text
#[test] fn canonical_wins_over_alias();                      // {"path":"p","file":"q"} -> path "p"
#[test] fn unknown_key_suggests_did_you_mean();              // {"patern":"x"} on search -> "Did you mean 'query'?"
#[test] fn unknown_key_lists_valid();                        // {"zzz":1} -> "Valid arguments:"
#[test] fn missing_required_lists_fields();                  // write without content -> "Missing required argument(s): content"

// handler tests (in src/server.rs mod tests, tokio::test)
#[tokio::test] async fn read_tool_returns_file_content_json();       // workspace.read {"path":"a.txt"} -> text contains "hello"
#[tokio::test] async fn edit_tool_reports_diff_and_writes();         // workspace.edit with one edit -> applied_edits 1; file changed
#[tokio::test] async fn escape_attempt_is_invalid_params();          // read {"path":"../../etc/passwd"} -> Err McpError, message contains "allowed"
#[tokio::test] async fn sensitive_write_is_refused_with_pattern();    // write {"path":".env","content":"X","overwrite":true} -> message contains "Sensitive file blocked"
#[tokio::test] async fn alias_file_key_accepted_on_read();           // {"file":"a.txt"} works
#[tokio::test] async fn prd_alias_tools_registered_and_callable();   // workspace.read_file works like workspace.read
#[tokio::test] async fn mutating_calls_write_audit_events();         // audit Arc is a shared in-memory impl (test passes its own); assert event_count() > 0 after write
```

- [ ] **Step 2: Verify fail** — `cargo test -p runtime-mcp` → FAIL.
- [ ] **Step 3: Implement** `args.rs` (aliases/levenshtein ~120 lines), `tools_fs.rs` helpers (~80 lines), tool methods in `server.rs` (~450 lines with schemas), keeping `#[tool_handler]` on the `ServerHandler` impl unchanged.
- [ ] **Step 4: Verify pass** — `cargo test -p runtime-mcp` → ALL PASS; `cargo check --workspace --exclude backend-linux --exclude backend-macos --exclude runtime-terminal --exclude backend-windows` → 0 errors.
- [ ] **Step 5: Commit** — `git commit -m "feat(mcp): full Phase 1 workspace tool registry with argument aliasing, did-you-mean errors, audit recording"`

---

### Task 12: Integration tests (stdio E2E + escape matrix + conformance)

**Files:**
- Create: `crates/runtime-cli/tests/mcp_stdio.rs`
- Modify: `crates/runtime-cli/Cargo.toml` (dev-deps: `rmcp = { workspace = true, features = ["client", "transport-child-process"] }`)

**Interfaces:**
- Consumes: the real `yl` binary (Task 10) — `env!("CARGO_BIN_EXE_yl")` works because the test lives in the same package as the `[[bin]] name = "yl"`.
- Produces: the Phase 1 acceptance gate.

Test plan (all `#[tokio::test]`):

```rust
use rmcp::{ServiceExt, model::CallToolRequestParam, service::Service, transport::{TokioChildProcess, ConfigureCommandExt}};
use tokio::process::Command;

async fn spawn_client(extra_args: &[&str]) -> /* running client service */ {
    let tmp = tempfile::TempDir::new().unwrap();
    std::fs::write(tmp.path().join("hello.txt"), "hello world\nsecond line\n").unwrap();
    let transport = TokioChildProcess::new(Command::new(env!("CARGO_BIN_EXE_yl"))
        .configure(|cmd| { cmd.arg("mcp").arg("--root").arg(tmp.path()); }))?;
    let client = ().serve(transport).await?;
    // client().list_tools() / call tools; tmp kept alive via TempDir guard returned alongside
}
```

(Adjust the client construction to the rmcp 3.10 client API present in the vendored version — `().serve(transport)` per the README; the implementer confirms the exact builder at implementation time and keeps this helper as the single place it appears.)

1. `conformance_phase1_tools_present` — `client.list_tools()`; assert these names are all present: `runtime.status`, `runtime.capabilities`, `workspace.read`, `workspace.write`, `workspace.edit`, `workspace.patch`, `workspace.replace_text`, `workspace.search`, `workspace.find_files`, `workspace.list`, `workspace.tree`, `workspace.stat`, `workspace.mkdir`, `workspace.move`, `workspace.delete`, `workspace.allowed_roots`, `workspace.read_file`, `workspace.write_file`, `process.exec`. (Deferred per design: `process.start/wait/terminate/discover_tools`, `terminal.*`, `git.*`, `approval.request` — Phase 2/3.)
2. `write_read_edit_roundtrip_over_stdio` — `workspace.write` {"path":"a.txt","content":"alpha\n"} → `workspace.edit` {"path":"a.txt","edits":[{"old_text":"alpha","new_text":"ALPHA"}]} → `workspace.read` returns "ALPHA\n".
3. `search_over_stdio_finds_content` — write two files; `workspace.search` {"query":"needle"} returns a match with the right file.
4. `escape_attempt_is_error` — `workspace.read` {"path":"../../outside.txt"} → error result mentioning "allowed".
5. `sensitive_file_hidden_and_refused` — `workspace.write` {"path":".env","content":"K=1","overwrite":true"} → error "Sensitive file blocked"; `workspace.read` {"path":".env"} → same.
6. `mcp_without_roots_fails_closed` (already in Task 10; keep it here if moved) — binary exits nonzero.
7. `server_instructions_advertise_workspace_tools` — the initialize response's `instructions` field (set in `#[tool_handler(instructions = ...) ]`) mentions `workspace.read` and `--root`.

- [ ] **Step 1: Write the tests** (they fail today: `mcp` without Task 10/11 would not list these tools).
- [ ] **Step 2: Verify they pass against Tasks 10+11** — `cargo test -p runtime-cli --test mcp_stdio` → ALL PASS. If any fails, fix the server (these tests are the spec).
- [ ] **Step 3: Full gate** — `cargo test --workspace --exclude backend-linux --exclude backend-macos --exclude runtime-terminal --exclude backend-windows` → ALL PASS; repeat the Task 10 manual smoke command and additionally run a real `tools/call` through the smoke pipe:

```powershell
'{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"workspace.read","arguments":{"path":"hello.txt"}}}' | cargo run -p runtime-cli -- mcp --root $t
```

Expected: response containing `"hello world"`.

- [ ] **Step 4: Commit** — `git commit -m "test(e2e): stdio MCP client conformance + escape matrix + sensitive refusal against the yl binary"`

---

## Self-Review Notes

- Spec coverage: design Phase 1 table → Tasks 4–9 engines, Task 11 registry; prereq wiring → Task 10; resolved decisions 1 (fail-closed roots), 4 (synthetic principal, trait routing), 6 (single-process) pinned in Tasks 10–11; conformance per design §"Conformance & tool naming" in Task 12 including PRD alias tools. Audit constraint from design ("every mutating call → AuditEvent") in Task 11.
- Terminal tools, YOLO/approval, git, batch, undo: explicitly Phase 2–4, out of this plan.
- Type consistency: `ReadOutcome`/`WriteOutcome`/`EditSpec` names identical across Tasks 4–9 and 11; `validate_access(project_id, path, mode)` signature consistent; `McpServer::new_for_fs` referenced in Task 10 step 6 and defined in Task 11 — Task 10 will not compile until Task 11 lands, so **Tasks 10 and 11 are one review unit**: implement Task 11's constructor skeleton first (stub `new_for_fs` + old tools) then Task 10, then finish Task 11. Executors should implement in order 1–9, then 11, then 10, then 12.
- Review Focus items map: CRLF→Task 6 test, junction→Task 2 test, sensitive write bypass→Task 9 test, multi-match→Task 6 test, zero-roots→Task 10 test + Task 12.
