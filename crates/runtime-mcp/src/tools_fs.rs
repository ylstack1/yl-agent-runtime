//! Filesystem MCP tool helpers.
//!
//! Provides path resolution (`resolve_project`), output rendering
//! (`output_json`, `invalid`), shallow directory walking (`walk_shallow`),
//! tree walking (`walk_tree`), and the per-tool argument structs consumed by
//! the tool methods in `server.rs`.

use ignore::overrides::{Override, OverrideBuilder};
use ignore::WalkBuilder;
use rmcp::ErrorData as McpError;
use rmcp::model::{CallToolResult, ContentBlock};
use runtime_core::types::ProjectId;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Resolve a user-supplied path against the configured roots:
///
/// - absolute: first root that is a prefix (separator-boundary safe via
///   `Path::starts_with`);
/// - relative: joined against `roots[0]` (the primary root).
///
/// Returns `None` when there are no roots, or when an absolute path is not
/// within any root.
pub fn resolve_project(roots: &[(ProjectId, PathBuf)], user_path: &Path) -> Option<(ProjectId, PathBuf)> {
    if roots.is_empty() {
        return None;
    }
    if user_path.is_absolute() {
        for (project_id, root) in roots {
            if user_path.starts_with(root) {
                return Some((*project_id, user_path.to_path_buf()));
            }
        }
        return None;
    }
    Some((roots[0].0, roots[0].1.join(user_path)))
}

/// Render a serializable value as a compact JSON text content block.
pub fn output_json<T: serde::Serialize>(v: &T) -> Result<CallToolResult, McpError> {
    let json =
        serde_json::to_string(v).map_err(|e| McpError::internal_error(format!("failed to serialize response: {e}"), None))?;
    Ok(CallToolResult::success(vec![ContentBlock::text(json)]))
}

/// Convenience: `McpError::invalid_params(msg, None)`.
pub fn invalid(msg: impl Into<String>) -> McpError {
    McpError::invalid_params(msg.into(), None)
}

// ---------------------------------------------------------------------------
// Per-tool argument structures (deserialized after `normalize_args`).
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct ReadArgs {
    pub path: String,
    #[allow(dead_code)]
    pub line_start: Option<u64>,
    #[allow(dead_code)]
    pub line_end: Option<u64>,
    #[allow(dead_code)]
    pub offset: Option<u64>,
    #[allow(dead_code)]
    pub max_bytes: Option<u64>,
    #[allow(dead_code)]
    pub media: Option<bool>,
    #[allow(dead_code)]
    pub head: Option<u64>,
    #[allow(dead_code)]
    pub tail: Option<u64>,
    #[allow(dead_code)]
    pub want_sha256: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub struct WriteArgs {
    pub path: String,
    pub content: String,
    #[allow(dead_code)]
    pub overwrite: Option<bool>,
    #[allow(dead_code)]
    pub append: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub struct EditSpecArgs {
    pub old_text: String,
    pub new_text: String,
    #[serde(default)]
    #[allow(dead_code)]
    pub expected_occurrences: Option<usize>,
}

#[derive(Debug, Deserialize)]
pub struct EditArgs {
    pub path: String,
    pub edits: Vec<EditSpecArgs>,
    #[allow(dead_code)]
    pub dry_run: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub struct PatchArgs {
    pub diff: String,
    #[allow(dead_code)]
    pub dry_run: Option<bool>,
}

fn default_max_matches() -> usize {
    100
}

#[derive(Debug, Deserialize)]
pub struct ReplaceTextArgs {
    #[allow(dead_code)]
    pub path: Option<String>,
    pub search: String,
    pub replacement: String,
    #[serde(default)]
    #[allow(dead_code)]
    pub case_sensitive: bool,
    #[serde(default = "default_max_matches")]
    #[allow(dead_code)]
    pub max_matches: usize,
    #[allow(dead_code)]
    pub dry_run: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub struct SearchArgs {
    pub query: String,
    #[serde(default = "default_search_max_results")]
    #[allow(dead_code)]
    pub max_results: usize,
    #[serde(default)]
    #[allow(dead_code)]
    pub is_regex: bool,
    #[serde(default)]
    #[allow(dead_code)]
    pub case_sensitive: bool,
    #[serde(default)]
    #[allow(dead_code)]
    pub include: Vec<String>,
    #[serde(default)]
    #[allow(dead_code)]
    pub exclude: Vec<String>,
    #[serde(default)]
    pub context: u32,
}

fn default_search_max_results() -> usize {
    200
}

#[derive(Debug, Deserialize)]
pub struct FindFilesArgs {
    #[allow(dead_code)]
    pub path: Option<String>,
    pub pattern: String,
    #[serde(default = "default_find_max_results")]
    #[allow(dead_code)]
    pub max_results: usize,
}

fn default_find_max_results() -> usize {
    100
}

#[derive(Debug, Deserialize)]
pub struct ListArgs {
    #[allow(dead_code)]
    pub path: Option<String>,
    #[serde(default = "default_depth")]
    #[allow(dead_code)]
    pub depth: usize,
    #[serde(default = "default_max_entries")]
    #[allow(dead_code)]
    pub max_entries: usize,
    #[serde(default)]
    #[allow(dead_code)]
    pub include_hidden: bool,
    #[allow(dead_code)]
    pub sort_by: Option<String>,
}

fn default_depth() -> usize {
    1
}

fn default_max_entries() -> usize {
    1000
}

#[derive(Debug, Deserialize)]
pub struct TreeArgs {
    pub path: String,
    #[allow(dead_code)]
    pub depth: Option<usize>,
    #[serde(default)]
    #[allow(dead_code)]
    pub exclude_patterns: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct StatArgs {
    pub path: String,
}

#[derive(Debug, Deserialize)]
pub struct MkdirArgs {
    pub path: String,
}

#[derive(Debug, Deserialize)]
pub struct MoveArgs {
    pub source: String,
    pub destination: String,
}

/// A path argument accepted either as a single string or an array of strings.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum Paths {
    Multi(Vec<String>),
    Single(String),
}

impl Paths {
    pub fn into_paths(self) -> Vec<String> {
        match self {
            Paths::Multi(values) => values,
            Paths::Single(value) => vec![value],
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct DeleteArgs {
    pub paths: Paths,
    #[allow(dead_code)]
    pub recursive: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub struct AllowedRootsArgs {}

#[derive(Debug, Deserialize)]
pub struct ProcessExecArgs {
    #[allow(dead_code)]
    pub project_id: String,
    pub command: String,
    #[allow(dead_code)]
    pub args: Option<Vec<String>>,
    #[allow(dead_code)]
    pub timeout_seconds: Option<u64>,
}

// ---------------------------------------------------------------------------
// Tree walking
// ---------------------------------------------------------------------------

/// Entry budget for `walk_tree`; beyond it the tree tool refuses with an
/// invalid-params error so a client can narrow the request.
pub const TREE_ENTRY_BUDGET: usize = 100_000;

/// Signal that `walk_tree` stopped because the entry budget was exceeded.
#[derive(Debug)]
pub struct TreeBudgetExceeded;

struct TreeNode {
    name: String,
    r#type: String,
    children: Vec<usize>,
}

/// Build gitignore-style override rules (`!` = exclude) for the caller-supplied
/// `exclude_patterns`, so the walker prunes excluded subtrees during descent
/// instead of filtering children after the fact (which let excluded directories
/// leak through via mis-parented absolute/relative path comparisons).
fn build_exclude_overrides(root: &Path, patterns: &[String]) -> Option<Override> {
    if patterns.is_empty() {
        return None;
    }
    let mut builder = OverrideBuilder::new(root);
    for pattern in patterns {
        // Fail-soft on invalid patterns, mirroring the previous glob fallback.
        if builder.add(&format!("!{pattern}")).is_err() {
            continue;
        }
    }
    builder.build().ok()
}

/// Walk `root` up to `max_depth` and emit a nested JSON array of
/// `{name, type, children?}` nodes. Directories at (or beyond) the depth
/// limit carry `children: []`; files carry `children: None`. Excluded
/// subtrees (via `exclude_patterns`) are pruned before descent, so their
/// contents never enter the output.
pub fn walk_tree(
    root: &Path,
    max_depth: Option<usize>,
    exclude_patterns: &[String],
) -> Result<Vec<serde_json::Value>, TreeBudgetExceeded> {
    let overrides = build_exclude_overrides(root, exclude_patterns);
    let mut walker = WalkBuilder::new(root);
    if let Some(depth) = max_depth {
        walker.max_depth(Some(depth));
    }
    walker.hidden(true).ignore(true).require_git(false);
    if let Some(overrides) = &overrides {
        walker.overrides(overrides.clone());
    }

    let mut nodes: Vec<TreeNode> = Vec::new();
    let mut by_path: std::collections::HashMap<PathBuf, usize> = std::collections::HashMap::new();
    let mut top_level: Vec<usize> = Vec::new();
    let mut count: usize = 0;

    for entry in walker.build() {
        let entry = match entry {
            Ok(entry) => entry,
            Err(_) => continue,
        };
        count += 1;
        if count > TREE_ENTRY_BUDGET {
            return Err(TreeBudgetExceeded);
        }

        let path = entry.path().to_path_buf();
        if path == root {
            continue;
        }

        let r#type = if entry.file_type().map_or(false, |ft| ft.is_dir()) {
            "directory"
        } else if entry.file_type().map_or(false, |ft| ft.is_symlink()) {
            "symlink"
        } else {
            "file"
        };
        let name = entry.file_name().to_string_lossy().to_string();

        let idx = nodes.len();
        nodes.push(TreeNode { name, r#type: r#type.to_string(), children: Vec::new() });
        if let Some(parent) = path.parent() {
            if parent == root {
                top_level.push(idx);
            } else if let Some(&parent_idx) = by_path.get(parent) {
                nodes[parent_idx].children.push(idx);
            } else {
                top_level.push(idx);
            }
        } else {
            top_level.push(idx);
        }
        by_path.insert(path, idx);
    }

    let mut json: Vec<Option<serde_json::Value>> = vec![None; nodes.len()];
    for i in (0..nodes.len()).rev() {
        let node = &nodes[i];
        let children = if node.r#type == "directory" {
            Some(
                node
                    .children
                    .iter()
                    .map(|&child_idx| {
                        json[child_idx]
                            .as_ref()
                            .expect("child serialized first")
                            .clone()
                    })
                    .collect::<Vec<serde_json::Value>>(),
            )
        } else {
            None
        };
        json[i] = Some(serde_json::json!({ "name": node.name, "type": node.r#type, "children": children }));
    }

    Ok(top_level
        .into_iter()
        .map(|i| json[i].take().expect("top-level node serialized"))
        .collect())
}

/// One shallow list entry.
#[derive(Debug, Clone, Serialize)]
pub struct ListEntry {
    pub name: String,
    pub r#type: String,
    pub size: Option<u64>,
    pub modified: Option<String>,
}

/// Walk `root` to `depth` levels and return flat entries plus a count of
/// hidden entries that were skipped (caller decides whether to surface the
/// advice line).
pub fn walk_shallow(
    root: &Path,
    depth: usize,
    include_hidden: bool,
    sort_by: &str,
) -> (Vec<ListEntry>, usize) {
    let mut walker = WalkBuilder::new(root);
    walker.max_depth(Some(depth));
    walker.hidden(false);
    walker.ignore(true);
    walker.require_git(false);

    let mut entries: Vec<ListEntry> = Vec::new();
    let mut hidden_count: usize = 0;

    for entry in walker.build() {
        let entry = match entry {
            Ok(entry) => entry,
            Err(_) => continue,
        };
        if entry.depth() == 0 {
            continue; // skip the root directory itself
        }
        let name = entry.file_name().to_string_lossy().to_string();
        if !include_hidden && name.starts_with('.') {
            hidden_count += 1;
            continue;
        }
        let file_type = entry.file_type();
        let metadata = entry.metadata().ok();
        let r#type = if file_type.map_or(false, |ft| ft.is_dir()) {
            "directory"
        } else if file_type.map_or(false, |ft| ft.is_symlink()) {
            "symlink"
        } else {
            "file"
        };
        entries.push(ListEntry {
            name,
            r#type: r#type.to_string(),
            size: metadata.as_ref().map(|m| m.len()),
            modified: metadata
                .and_then(|m| m.modified().ok())
                .map(|t| chrono::DateTime::<chrono::Utc>::from(t).to_rfc3339()),
        });
    }

    match sort_by {
        "size" => entries.sort_by(|a, b| a.size.cmp(&b.size).then_with(|| a.name.cmp(&b.name))),
        _ => entries.sort_by(|a, b| a.name.cmp(&b.name)),
    }

    (entries, hidden_count)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seed_tree(root: &Path) {
        std::fs::create_dir_all(root.join("src")).expect("create src");
        std::fs::write(root.join("src").join("a.txt"), "hello\n").expect("write src/a.txt");
        std::fs::create_dir_all(root.join("node_modules")).expect("create node_modules");
        std::fs::write(root.join("node_modules").join("x.js"), "module.exports = 1;\n").expect("write x.js");
        std::fs::create_dir_all(root.join("dist")).expect("create dist");
        std::fs::write(root.join("dist").join("b.js"), "bundle\n").expect("write b.js");
    }

    fn collect_names(nodes: &[serde_json::Value]) -> Vec<String> {
        let mut out = Vec::new();
        for node in nodes {
            out.push(node["name"].as_str().unwrap_or_default().to_string());
            if let Some(children) = node["children"].as_array() {
                out.extend(collect_names(children));
            }
        }
        out
    }

    #[test]
    fn tree_exclude_pattern_prunes_subtree() {
        let dir = tempfile::tempdir().expect("tempdir");
        seed_tree(dir.path());

        let nodes = walk_tree(dir.path(), None, &["node_modules".to_string()]).expect("tree walk");
        let names = collect_names(&nodes);
        assert!(
            !names.iter().any(|n| n == "node_modules"),
            "excluded subtree leaked into tree output: {names:?}"
        );
        assert!(
            names.iter().any(|n| n == "src") && names.iter().any(|n| n == "dist"),
            "non-excluded entries should remain: {names:?}"
        );
    }

    #[test]
    fn tree_without_excludes_lists_all_subtrees() {
        let dir = tempfile::tempdir().expect("tempdir");
        seed_tree(dir.path());

        let nodes = walk_tree(dir.path(), None, &[]).expect("tree walk");
        let names = collect_names(&nodes);
        assert!(
            names.iter().any(|n| n == "node_modules"),
            "unfiltered tree should include the subtree: {names:?}"
        );
    }
}
