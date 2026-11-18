//! Argument normalization for MCP tool calls.
//!
//! Applies the PRD alias table (canonical key always wins), unknown-key
//! did-you-mean suggestions (Levenshtein <= 2), and missing-required
//! validation before per-tool argument structs are deserialized.

use rmcp::ErrorData as McpError;
use rmcp::model::JsonObject;

/// Canonical aliases per tool: `(alias, canonical)`.
///
/// The `*path` entry is a wildcard: it applies to every tool that has a
/// canonical `path` argument (`file`, `target`, `filepath`, `filePath` all
/// normalize to `path`).
pub const ALIASES: &[(&str, &[(&str, &str)])] = &[
    ("*path", &[("file", "path"), ("target", "path"), ("filepath", "path"), ("filePath", "path")]),
    ("workspace.write", &[("text", "content"), ("data", "content"), ("force", "overwrite")]),
    (
        "workspace.edit",
        &[
            ("old", "old_text"),
            ("oldText", "old_text"),
            ("find", "old_text"),
            ("new", "new_text"),
            ("newText", "new_text"),
            ("replacement", "new_text"),
            ("replace", "new_text"),
            ("count", "expected_occurrences"),
            ("occurrences", "expected_occurrences"),
            ("dryRun", "dry_run"),
            ("dry", "dry_run"),
        ],
    ),
    (
        "workspace.search",
        &[
            ("pattern", "query"),
            ("q", "query"),
            ("text", "query"),
            ("maxResults", "max_results"),
            ("limit", "max_results"),
            ("isRegex", "is_regex"),
            ("regex", "is_regex"),
            ("caseSensitive", "case_sensitive"),
            ("globs", "include"),
            ("include_globs", "include"),
            ("excludePatterns", "exclude"),
            ("exclude_globs", "exclude"),
        ],
    ),
    ("workspace.move", &[("src", "source"), ("from", "source"), ("dest", "destination"), ("dst", "destination"), ("to", "destination")]),
    ("workspace.delete", &[("path", "paths"), ("files", "paths")]),
    ("workspace.read", &[("start", "line_start"), ("end", "line_end")]),
    (
        "workspace.read_many",
        &[
            ("files", "paths"),
            ("paths_to_read", "paths"),
            ("start", "line_start"),
            ("end", "line_end"),
        ],
    ),
    ("workspace.stat", &[("file", "path"), ("target", "path")]),
    ("workspace.register", &[("directory", "path"), ("dir", "path")]),
    (
        "process.start",
        &[
            ("cmd", "program"),
            ("exe", "program"),
            ("executable", "program"),
            ("arguments", "args"),
            ("argv", "args"),
            ("working_dir", "cwd"),
            ("directory", "cwd"),
            ("timeout", "timeout_seconds"),
        ],
    ),
    (
        "process.read",
        &[
            ("id", "process_id"),
            ("pid", "process_id"),
            ("cursor", "after"),
            ("after_cursor", "after"),
            ("limit", "limit_bytes"),
            ("max_bytes", "limit_bytes"),
            ("wait", "wait_ms"),
            ("timeout", "wait_ms"),
        ],
    ),
    ("process.stop", &[("id", "process_id"), ("pid", "process_id"), ("kill", "force")]),
    (
        "process.interact",
        &[
            ("id", "process_id"),
            ("pid", "process_id"),
            ("input", "data"),
            ("text", "data"),
            ("stdin", "data"),
            ("close", "close_stdin"),
            ("eof", "close_stdin"),
        ],
    ),
    ("process.list", &[]),
    ("process.discover_tools", &[]),
];

/// Required arguments per tool (PRD §13.1 names are canonical).
pub const REQUIRED: &[(&str, &[&str])] = &[
    ("workspace.read", &["path"]),
    ("workspace.read_many", &["paths"]),
    ("workspace.write", &["path", "content"]),
    ("workspace.edit", &["path"]),
    ("workspace.patch", &["diff"]),
    ("workspace.replace_text", &["search", "replacement"]),
    ("workspace.search", &["query"]),
    ("workspace.find_files", &["pattern"]),
    ("workspace.tree", &["path"]),
    ("workspace.mkdir", &["path"]),
    ("workspace.register", &["path"]),
    ("workspace.move", &["source", "destination"]),
    ("workspace.delete", &["paths"]),
    ("workspace.stat", &["path"]),
    ("process.exec", &["project_id", "command"]),
    ("process.start", &["project_id", "program"]),
    ("process.read", &["process_id"]),
    ("process.interact", &["process_id", "data"]),
    ("process.stop", &["process_id"]),
    ("process.list", &[]),
    ("process.discover_tools", &[]),
];

/// Base (struct-field) argument keys per tool, used for unknown-key detection
/// and the "Valid arguments:" listing. Kept in sync with each tool's
/// `input_schema`; alias canonical targets are added on top in
/// `base_keys_for`.
const KNOWN: &[(&str, &[&str])] = &[
    (
        "workspace.read",
        &[
            "path",
            "line_start",
            "line_end",
            "offset",
            "max_bytes",
            "media",
            "head",
            "tail",
            "want_sha256",
        ],
    ),
    (
        "workspace.read_file",
        &["path", "line_start", "line_end", "offset", "max_bytes", "media", "head", "tail", "want_sha256"],
    ),
    ("workspace.read_many", &["paths", "line_start", "line_end", "max_bytes"]),
    ("workspace.write", &["path", "content", "overwrite", "append"]),
    ("workspace.edit", &["path", "edits", "old_text", "new_text", "expected_occurrences", "dry_run"]),
    ("workspace.patch", &["diff", "dry_run"]),
    (
        "workspace.replace_text",
        &["path", "search", "replacement", "case_sensitive", "max_matches", "dry_run"],
    ),
    (
        "workspace.search",
        &[
            "query",
            "max_results",
            "offset",
            "is_regex",
            "case_sensitive",
            "include",
            "exclude",
            "context",
        ],
    ),
    ("workspace.find_files", &["path", "pattern", "max_results"]),
    ("workspace.list", &["path", "depth", "max_entries", "include_hidden", "sort_by"]),
    ("workspace.tree", &["path", "depth", "exclude_patterns"]),
    ("workspace.stat", &["path"]),
    ("workspace.mkdir", &["path"]),
    ("workspace.register", &["path"]),
    ("workspace.move", &["source", "destination"]),
    ("workspace.delete", &["paths", "recursive"]),
    ("workspace.allowed_roots", &[]),
    ("process.exec", &["project_id", "command", "args", "timeout_seconds"]),
    ("process.start", &["project_id", "program", "args", "cwd", "timeout_seconds"]),
    ("process.read", &["process_id", "after", "limit_bytes", "wait_ms"]),
    ("process.interact", &["process_id", "data", "close_stdin"]),
    ("process.stop", &["process_id", "force"]),
    ("process.list", &["project_id"]),
    ("process.discover_tools", &[]),
    ("git.root", &["project_id"]),
    ("git.status", &["project_id"]),
    ("git.diff", &["project_id", "path", "staged"]),
    ("git.log", &["project_id", "max_count", "path"]),
    ("git.branch", &["project_id"]),
    ("git.commit", &["project_id", "message", "files"]),
    ("approval.request", &["capability", "resource", "justification"]),
    ("approval.approve", &["approval_id"]),
    ("approval.reject", &["approval_id", "reason"]),
    ("approval.list", &[]),
];

/// Base keys plus every alias canonical target (post-normalization names such
/// as `old_text` are valid arguments even though they are not struct fields).
fn base_keys_for(tool: &str) -> Vec<&'static str> {
    let base: Vec<&'static str> = match tool {
        "workspace.read_file" => vec![
            "path",
            "line_start",
            "line_end",
            "offset",
            "max_bytes",
            "media",
            "head",
            "tail",
            "want_sha256",
        ],
        "workspace.write_file" => vec!["path", "content", "overwrite"],
        _ => KNOWN
            .iter()
            .find(|(target, _)| *target == tool)
            .map(|(_, keys)| keys.to_vec())
            .unwrap_or_default(),
    };
    let has_path = base.contains(&"path");
    let mut keys = base;
    for (target, pairs) in ALIASES.iter() {
        let applies = *target == tool
            || (tool == "workspace.read_file" && *target == "workspace.read")
            || (tool == "workspace.write_file" && *target == "workspace.write")
            || (*target == "*path" && has_path);
        if applies {
            for (_, canonical) in *pairs {
                if !keys.contains(&canonical) {
                    keys.push(canonical);
                }
            }
        }
    }
    keys
}

/// Levenshtein edit distance between two strings (insert/delete/substitute,
/// unit cost each).
pub fn levenshtein(a: &str, b: &str) -> usize {
    let n = b.len();
    let mut previous: Vec<usize> = (0..=n).collect();
    let mut current: Vec<usize> = vec![0; n + 1];
    for (i, ac) in a.chars().enumerate() {
        current[0] = i + 1;
        for (j, bc) in b.chars().enumerate() {
            let cost = if ac == bc { 0 } else { 1 };
            current[j + 1] = std::cmp::min(
                std::cmp::min(current[j] + 1, previous[j + 1] + 1),
                previous[j] + cost,
            );
        }
        std::mem::swap(&mut previous, &mut current);
    }
    previous[n]
}

fn alias_pairs_for(tool: &str) -> Vec<(&'static str, &'static str)> {
    let mut out: Vec<(&'static str, &'static str)> = Vec::new();
    for (target, pairs) in ALIASES.iter() {
        if *target == tool {
            out.extend_from_slice(pairs);
        }
    }
    // `workspace.read_file` / `workspace.write_file` mirror `workspace.read` /
    // `workspace.write` (PRD aliases).
    let base = match tool {
        "workspace.read_file" => "workspace.read",
        "workspace.write_file" => "workspace.write",
        _ => tool,
    };
    if base != tool {
        for (target, pairs) in ALIASES.iter() {
            if *target == base {
                out.extend_from_slice(pairs);
            }
        }
    }
    // `*path` wildcard applies to any tool with a canonical `path` key.
    if base_keys_for(tool).contains(&"path") {
        for (target, pairs) in ALIASES.iter() {
            if *target == "*path" {
                out.extend_from_slice(pairs);
            }
        }
    }
    out
}

fn required_for(tool: &str) -> Vec<&'static str> {
    for (target, fields) in REQUIRED.iter() {
        if *target == tool {
            return fields.to_vec();
        }
    }
    match tool {
        "workspace.read_file" => vec!["path"],
        "workspace.write_file" => vec!["path", "content"],
        _ => Vec::new(),
    }
}

/// Normalize the raw arguments of a tool call:
///
/// 1. Apply aliases (canonical key always wins when both are present).
/// 2. Reject unknown keys: nearest known key within Levenshtein <= 2 yields a
///    did-you-mean error (naming the canonical key); otherwise a "Valid
///    arguments:" listing error.
/// 3. Reject missing required arguments.
pub fn normalize_args(tool: &str, args: &JsonObject) -> Result<JsonObject, McpError> {
    let mut normalized = args.clone();
    let pairs = alias_pairs_for(tool);

    // Apply aliases; the canonical key always wins.
    for (alias, canonical) in &pairs {
        if normalized.contains_key(*alias) {
            if normalized.contains_key(*canonical) {
                normalized.remove(*alias);
            } else {
                let value = normalized.remove(*alias).expect("key is present");
                normalized.insert(canonical.to_string(), value);
            }
        }
    }

    // Valid keys: struct fields plus alias canonical targets.
    let mut known: Vec<&str> = base_keys_for(tool);
    for (_, canonical) in &pairs {
        if !known.contains(canonical) {
            known.push(canonical);
        }
    }
    let alias_names: Vec<&str> = pairs.iter().map(|(alias, _)| *alias).collect();
    let mut unknown: Vec<String> = normalized
        .keys()
        .filter(|key| {
            !known.iter().any(|&known_key| known_key == *key)
                && !alias_names.iter().any(|&alias| alias == *key)
        })
        .cloned()
        .collect();
    unknown.sort();

    for key in &unknown {
        let mut best: Option<(&str, usize)> = None;
        for candidate in known.iter().copied().chain(alias_names.iter().copied()) {
            let distance = levenshtein(key, candidate);
            let better = match best {
                None => true,
                Some((_, best_distance)) => distance < best_distance,
            };
            if better {
                best = Some((candidate, distance));
            }
        }
        if let Some((candidate, _)) = best.filter(|(_, distance)| *distance <= 2) {
            let suggestion = pairs
                .iter()
                .find(|(alias, _)| *alias == candidate)
                .map(|(_, canonical)| *canonical)
                .unwrap_or(candidate);
            return Err(invalid_params(
                format!("Unknown argument '{key}'. Did you mean '{suggestion}'?"),
                None,
            ));
        }
    }

    if let Some(key) = unknown.first() {
        let list = known.join(", ");
        return Err(invalid_params(
            format!("Unknown argument '{key}' for {tool}. Valid arguments: {list}"),
            None,
        ));
    }

    let required = required_for(tool);
    let missing: Vec<&str> = required
        .iter()
        .copied()
        .filter(|field| !normalized.contains_key(*field))
        .collect();
    if !missing.is_empty() {
        return Err(invalid_params(
            format!("Missing required argument(s): {}", missing.join(", ")),
            None,
        ));
    }

    Ok(normalized)
}

fn invalid_params(message: impl Into<String>, data: Option<serde_json::Value>) -> McpError {
    McpError::invalid_params(message.into(), data)
}
