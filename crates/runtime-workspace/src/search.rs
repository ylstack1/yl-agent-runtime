//! gitignore-aware content search (`search_tree`) and file discovery
//! (`find_files`).
//!
//! Both entry points walk a tree with [`ignore::WalkBuilder`], honouring
//! `.gitignore` plus the built-in and caller-supplied excludes unless ignored
//! files are explicitly included. `search_tree` additionally applies the
//! sensitive-file policy before any read attempt and skips binary and
//! oversized files with exact skip accounting.

use crate::files::read::detect_binary_probe;
use crate::sensitive::SensitiveVerdict;
use runtime_core::error::{Error, Result};

use globset::{GlobBuilder, GlobSet, GlobSetBuilder};
use ignore::overrides::OverrideBuilder;
use ignore::WalkBuilder;
use regex::RegexBuilder;
use serde::Deserialize;
use std::path::{Path, PathBuf};

const DEFAULT_MAX_RESULTS: usize = 200;
const MAX_RESULTS_CAP: usize = 5_000;
const DEFAULT_MAX_FILE_SIZE: u64 = 1_000_000;
const REGEX_SIZE_LIMIT: usize = 10 * 1024 * 1024;
const MAX_CONTEXT: u32 = 5;

fn default_max_results() -> usize {
    DEFAULT_MAX_RESULTS
}

fn default_max_file_size() -> u64 {
    DEFAULT_MAX_FILE_SIZE
}

/// Built-in directory/file names excluded by default (unless `include_ignored`
/// is set).
pub const DEFAULT_EXCLUDES: &[&str] = &[
    ".git",
    "node_modules",
    "target",
    "dist",
    "build",
    "__pycache__",
    ".venv",
    "coverage",
    ".next",
    "vendor",
];

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct SearchOptions {
    pub query: String,
    #[serde(default)]
    pub is_regex: bool,
    #[serde(default)]
    pub case_sensitive: bool,
    #[serde(default)]
    pub include: Vec<String>,
    #[serde(default)]
    pub exclude: Vec<String>,
    #[serde(default)]
    pub context: u32, // 0..=5, clamped
    #[serde(default = "default_max_results")]
    pub max_results: usize, // 200 default; hard-capped at 5000
    #[serde(default)]
    pub files_only: bool,
    #[serde(default)]
    pub include_hidden: bool,
    #[serde(default)]
    pub include_ignored: bool,
    #[serde(default = "default_max_file_size")]
    pub max_file_size: u64, // 1_000_000 default
    #[serde(skip)]
    pub sensitive: Option<crate::sensitive::SensitiveMatcher>,
}

impl std::fmt::Debug for SearchOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SearchOptions")
            .field("query", &self.query)
            .field("is_regex", &self.is_regex)
            .field("case_sensitive", &self.case_sensitive)
            .field("include", &self.include)
            .field("exclude", &self.exclude)
            .field("context", &self.context)
            .field("max_results", &self.max_results)
            .field("files_only", &self.files_only)
            .field("include_hidden", &self.include_hidden)
            .field("include_ignored", &self.include_ignored)
            .field("max_file_size", &self.max_file_size)
            .field("sensitive", &self.sensitive.is_some())
            .finish()
    }
}

#[derive(Debug, Clone)]
pub struct SearchMatch {
    pub file: PathBuf,
    pub line: u64,
    pub column: u64,
    pub text: String,
    pub before: Vec<String>,
    pub after: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct SearchReport {
    pub matches: Vec<SearchMatch>,
    pub files_matched: u64,
    pub files_scanned: u64,
    pub skipped_binary: u64,
    pub skipped_too_large: u64,
    pub skipped_inaccessible: u64,
    pub truncated: bool,
}

#[derive(Debug, Clone)]
pub struct FindOptions {
    pub pattern: String,
    pub max_results: usize,
    pub want_dirs: bool,
    pub include_hidden: bool,
    pub include_ignored: bool,
}

impl Default for FindOptions {
    fn default() -> Self {
        Self {
            pattern: String::new(),
            max_results: 100,
            want_dirs: false,
            include_hidden: false,
            include_ignored: false,
        }
    }
}

#[derive(Debug, Clone)]
pub struct FindReport {
    pub paths: Vec<PathBuf>,
    pub total_matches: u64,
    pub files_scanned: u64,
    pub truncated: bool,
}

/// Search `root` for `opts.query` and return a [`SearchReport`].
///
/// Literal queries are escaped with [`regex::escape`] before compilation. Regex
/// compilation failures surface as [`Error::Validation`]. The sensitive-file
/// matcher is consulted on the resolved path before any read attempt, so
/// excluded files never contribute I/O, matches, or skip counts.
pub fn search_tree(root: &Path, opts: &SearchOptions) -> Result<SearchReport> {
    let pattern_text = if opts.is_regex {
        opts.query.clone()
    } else {
        regex::escape(&opts.query)
    };
    let regex = RegexBuilder::new(&pattern_text)
        .case_insensitive(!opts.case_sensitive)
        .size_limit(REGEX_SIZE_LIMIT)
        .build()
        .map_err(|e| Error::Validation(format!("Invalid pattern: {e}")))?;

    let include_set = build_glob_set(&opts.include)?;
    let overrides = build_overrides(root, opts)?;
    let max_results = opts.max_results.min(MAX_RESULTS_CAP);
    let context = opts.context.min(MAX_CONTEXT) as usize;

    let mut walker = WalkBuilder::new(root);
    walker.hidden(!opts.include_hidden);
    walker.git_ignore(!opts.include_ignored);
    walker.git_global(!opts.include_ignored);
    walker.require_git(false);
    if let Some(overrides) = overrides {
        walker.overrides(overrides);
    }

    let mut matches: Vec<SearchMatch> = Vec::new();
    let mut found: u64 = 0; // total matches encountered (may exceed max_results)
    let mut files_matched: u64 = 0;
    let mut files_scanned: u64 = 0;
    let mut skipped_binary: u64 = 0;
    let mut skipped_too_large: u64 = 0;
    let mut skipped_inaccessible: u64 = 0;
    let mut truncated = false;

    'walk: for entry in walker.build() {
        let entry = match entry {
            Ok(entry) => entry,
            // Walker errors (e.g. unreadable directory) are not file-level
            // skips; skip them silently.
            Err(_) => continue,
        };
        let file_type = match entry.file_type() {
            Some(file_type) => file_type,
            None => continue,
        };
        if !file_type.is_file() {
            continue;
        }

        let path = entry.path();
        let relative = path
            .strip_prefix(root)
            .map(|relative| relative.to_path_buf())
            .unwrap_or_else(|_| path.to_path_buf());

        // Include globs: the file must match at least one pattern.
        if !include_set.is_empty() {
            let relative = normalize_separators(&relative);
            if !include_set.is_match(&relative) {
                continue;
            }
        }

        // Sensitive-file policy is consulted before any read attempt.
        if let Some(matcher) = opts.sensitive.as_ref() {
            if matches!(matcher.verdict(path), SensitiveVerdict::Blocked { .. }) {
                continue;
            }
        }

        // Binary probe opens the file; failures count as inaccessible.
        let binary = match detect_binary_probe(path) {
            Ok(binary) => binary,
            Err(_) => {
                skipped_inaccessible += 1;
                continue;
            }
        };
        if binary {
            skipped_binary += 1;
            continue;
        }

        let len = match path.metadata().and_then(|metadata| Ok(metadata.len())) {
            Ok(len) => len,
            Err(_) => {
                skipped_inaccessible += 1;
                continue;
            }
        };
        if len > opts.max_file_size {
            skipped_too_large += 1;
            continue;
        }

        let content = match std::fs::read_to_string(path) {
            Ok(content) => {
                files_scanned += 1;
                content
            }
            Err(_) => {
                skipped_inaccessible += 1;
                continue;
            }
        };
        let lines: Vec<&str> = content.lines().collect();

        let mut file_matches: Vec<SearchMatch> = Vec::new();
        for (index, line) in lines.iter().enumerate() {
            let Some(captures) = regex.captures(line) else { continue };
            let Some(m) = captures.get(0) else { continue };
            found += 1;
            if found <= max_results as u64 {
                file_matches.push(SearchMatch {
                    file: path.to_path_buf(),
                    line: (index + 1) as u64,
                    column: (m.start() + 1) as u64,
                    text: m.as_str().to_string(),
                    before: context_before(&lines, index, context),
                    after: context_after(&lines, index, context),
                });
            }
        }

        if file_matches.is_empty() {
            // No collectable matches in this file. If we already ran past the
            // cap, there are more matches elsewhere: stop early.
            if found > max_results as u64 {
                truncated = true;
                break 'walk;
            }
            continue;
        }

        files_matched += 1;
        let emitted = if opts.files_only {
            vec![SearchMatch {
                file: path.to_path_buf(),
                line: 0,
                column: 0,
                text: String::new(),
                before: Vec::new(),
                after: Vec::new(),
            }]
        } else {
            file_matches
        };
        matches.extend(emitted);

        // More matches exist than we can collect: stop early.
        if found > max_results as u64 {
            truncated = true;
            break 'walk;
        }
    }

    Ok(SearchReport {
        matches,
        files_matched,
        files_scanned,
        skipped_binary,
        skipped_too_large,
        skipped_inaccessible,
        truncated,
    })
}

/// Context lines immediately before `index`, clamped at file start.
fn context_before(lines: &[&str], index: usize, context: usize) -> Vec<String> {
    let start = index.saturating_sub(context);
    lines[start..index].iter().map(ToString::to_string).collect()
}

/// Context lines immediately after `index`, clamped at file end.
fn context_after(lines: &[&str], index: usize, context: usize) -> Vec<String> {
    let end = (index + 1 + context).min(lines.len());
    lines[index + 1..end].iter().map(ToString::to_string).collect()
}

/// Build a [`GlobSet`] from include globs, matched against paths relative to
/// the search root.
fn build_glob_set(patterns: &[String]) -> Result<GlobSet> {
    let mut builder = GlobSetBuilder::new();
    for pattern in patterns {
        let glob = GlobBuilder::new(pattern)
            .literal_separator(true)
            .build()
            .map_err(|e| Error::Validation(format!("Invalid include glob: {e}")))?;
        builder.add(glob);
    }
    builder
        .build()
        .map_err(|e| Error::Validation(format!("Invalid include glob set: {e}")))
}

/// Build the override rules applying `DEFAULT_EXCLUDES` plus caller excludes,
/// unless ignored files are explicitly included.
fn build_overrides(root: &Path, opts: &SearchOptions) -> Result<Option<ignore::overrides::Override>> {
    if opts.include_ignored {
        return Ok(None);
    }
    let mut builder = OverrideBuilder::new(root);
    for name in DEFAULT_EXCLUDES {
        builder
            .add(&format!("!{name}"))
            .map_err(|e| Error::Validation(format!("Invalid default exclude '{name}': {e}")))?;
    }
    for pattern in &opts.exclude {
        builder
            .add(&format!("!{pattern}"))
            .map_err(|e| Error::Validation(format!("Invalid exclude glob '{pattern}': {e}")))?;
    }
    Ok(Some(
        builder
            .build()
            .map_err(|e| Error::Validation(format!("Invalid overrides: {e}")))?,
    ))
}

/// Normalize path separators to `/` so glob matching behaves identically on
/// Windows and Unix.
fn normalize_separators(path: &Path) -> String {
    path.as_os_str().to_string_lossy().replace('\\', "/")
}

/// Find files (and optionally directories) under `root` matching `opts.pattern`.
///
/// A pattern without `*` matches by exact basename at any depth; otherwise the
/// pattern is compiled with [`GlobBuilder`] (`literal_separator(true)`) and
/// matched against the path relative to `root`.
pub fn find_files(root: &Path, opts: &FindOptions) -> Result<FindReport> {
    let bare = !opts.pattern.contains('*');
    let glob_set = if bare {
        None
    } else {
        let mut builder = GlobSetBuilder::new();
        let glob = GlobBuilder::new(&opts.pattern)
            .literal_separator(true)
            .build()
            .map_err(|e| Error::Validation(format!("Invalid glob pattern: {e}")))?;
        builder.add(glob);
        Some(builder.build().map_err(|e| Error::Validation(format!("Invalid glob pattern: {e}")))?)
    };

    let overrides = if opts.include_ignored {
        None
    } else {
        let mut builder = OverrideBuilder::new(root);
        for name in DEFAULT_EXCLUDES {
            builder
                .add(&format!("!{name}"))
                .map_err(|e| Error::Validation(format!("Invalid default exclude '{name}': {e}")))?;
        }
        Some(builder.build().map_err(|e| Error::Validation(format!("Invalid overrides: {e}")))?)
    };

    let mut walker = WalkBuilder::new(root);
    walker.hidden(!opts.include_hidden);
    walker.git_ignore(!opts.include_ignored);
    walker.git_global(!opts.include_ignored);
    walker.require_git(false);
    if let Some(overrides) = overrides {
        walker.overrides(overrides);
    }

    let max_results = opts.max_results;
    let mut paths: Vec<PathBuf> = Vec::new();
    let mut total_matches: u64 = 0;
    let mut files_scanned: u64 = 0;
    let mut truncated = false;

    for entry in walker.build() {
        let Ok(entry) = entry else { continue };
        let Some(file_type) = entry.file_type() else { continue };
        let is_dir = file_type.is_dir();
        if is_dir && !opts.want_dirs {
            continue;
        }
        if !is_dir {
            files_scanned += 1;
        }

        let path = entry.path();
        let matched = if bare {
            path.file_name()
                .map(|name| name == opts.pattern.as_str())
                .unwrap_or(false)
        } else {
            let relative = normalize_separators(
                &path
                    .strip_prefix(root)
                    .map(|relative| relative.to_path_buf())
                    .unwrap_or_else(|_| path.to_path_buf()),
            );
            glob_set.as_ref().unwrap().is_match(&relative)
        };

        if matched {
            total_matches += 1;
            if paths.len() < max_results {
                paths.push(path.to_path_buf());
            } else {
                truncated = true;
            }
        }
    }

    Ok(FindReport {
        paths,
        total_matches,
        files_scanned,
        truncated,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::{Path, PathBuf};
    use tempfile::TempDir;

    const QUERY: &str = "fn main() {}";

    fn write_file(root: &Path, rel: &str, bytes: &[u8]) -> PathBuf {
        let path = root.join(rel);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("create parent dirs");
        }
        std::fs::write(&path, bytes).expect("write file");
        path
    }

    fn base_opts(query: &str) -> SearchOptions {
        SearchOptions {
            query: query.to_string(),
            is_regex: false,
            case_sensitive: true,
            include: Vec::new(),
            exclude: Vec::new(),
            context: 0,
            max_results: DEFAULT_MAX_RESULTS,
            files_only: false,
            include_hidden: false,
            include_ignored: false,
            max_file_size: DEFAULT_MAX_FILE_SIZE,
            sensitive: None,
        }
    }

    /// Seed the brief's standard tree:
    /// `src/a.rs` ("fn main() {}"), `src/deep/b.txt`, `.gitignore` (`deep/`),
    /// `node_modules/x.js`, binary `blob.bin`.
    fn seed_tree() -> (TempDir, PathBuf) {
        let root = TempDir::new().expect("temp dir");
        let path = root.path().to_path_buf();
        write_file(&path, "src/a.rs", b"fn main() {}\n");
        write_file(&path, "src/deep/b.txt", b"nothing to see here\n");
        write_file(&path, ".gitignore", b"deep/\n");
        write_file(&path, "node_modules/x.js", b"console.log('hi');\n");
        write_file(&path, "blob.bin", b"\x00\x01binary payload\x02\n");
        (root, path)
    }

    #[test]
    fn literal_query_with_regex_chars_is_escaped() {
        let (_root, path) = seed_tree();
        let opts = base_opts(QUERY);
        let report = search_tree(&path, &opts).expect("search must not error");
        assert_eq!(
            report.matches.len(),
            1,
            "expected exactly one match for escaped literal query, got {report:?}"
        );
        let m = &report.matches[0];
        assert_eq!(m.file, path.join("src/a.rs"));
        assert_eq!(m.line, 1);
        assert_eq!(m.column, 1);
        assert_eq!(m.text, "fn main() {}");
        assert!(m.before.is_empty());
        assert!(m.after.is_empty());
        assert!(!report.truncated);
    }

    #[test]
    fn gitignore_and_default_excludes_skipped_unless_included() {
        let (_root, path) = seed_tree();

        let report = search_tree(&path, &base_opts(QUERY)).expect("search must not error");
        assert_eq!(report.matches.len(), 1);
        assert_eq!(report.matches[0].file, path.join("src/a.rs"));
        assert!(!report
            .matches
            .iter()
            .any(|m| m.file.starts_with(path.join("src/deep"))));
        assert!(!report
            .matches
            .iter()
            .any(|m| m.file.starts_with(path.join("node_modules"))));

        let mut included = base_opts(QUERY);
        included.include_ignored = true;
        let included_report = search_tree(&path, &included).expect("search must not error");
        assert!(
            included_report.files_scanned > report.files_scanned,
            "files_scanned must grow when ignored files are included: {report:?} vs {included_report:?}"
        );
    }

    #[test]
    fn binary_and_too_large_counted_in_skip_triad() {
        let root = TempDir::new().expect("temp dir");
        let path = root.path().to_path_buf();
        write_file(&path, "small.txt", b"target needle\n");
        write_file(&path, "blob.bin", b"\x00\x01target\x02\n");
        write_file(
            &path,
            "big.txt",
            &std::iter::repeat(b'a').take(2000).collect::<Vec<_>>(),
        );

        let mut opts = base_opts("target");
        opts.max_file_size = 100;
        let report = search_tree(&path, &opts).expect("search must not error");

        assert_eq!(report.skipped_binary, 1);
        assert_eq!(report.skipped_too_large, 1);
        assert_eq!(report.files_scanned, 1);
        assert_eq!(report.matches.len(), 1);
        assert_eq!(report.matches[0].file, path.join("small.txt"));
        assert_eq!(report.matches[0].text, "target");
        assert!(!report.truncated);
    }

    #[test]
    fn context_lines_windowed() {
        let root = TempDir::new().expect("temp dir");
        let path = root.path().to_path_buf();
        write_file(&path, "note.txt", b"alpha\nbeta query line\ngamma\n");

        let mut opts = base_opts("query");
        opts.context = 1;
        let report = search_tree(&path, &opts).expect("search must not error");

        assert_eq!(report.matches.len(), 1);
        let m = &report.matches[0];
        assert_eq!(m.file, path.join("note.txt"));
        assert_eq!(m.line, 2);
        assert_eq!(m.column, 6);
        assert_eq!(m.text, "query");
        assert_eq!(m.before, vec!["alpha"]);
        assert_eq!(m.after, vec!["gamma"]);
    }

    #[test]
    fn max_results_truncates_flag() {
        let root = TempDir::new().expect("temp dir");
        let path = root.path().to_path_buf();
        write_file(&path, "lines.txt", b"z\nz\nz\nz\n");

        let mut opts = base_opts("z");
        opts.max_results = 1;
        let report = search_tree(&path, &opts).expect("search must not error");
        assert_eq!(report.matches.len(), 1);
        assert!(report.truncated, "must be truncated at max_results");

        let mut full = base_opts("z");
        full.max_results = 4;
        let full_report = search_tree(&path, &full).expect("search must not error");
        assert_eq!(full_report.matches.len(), 4);
        assert!(!full_report.truncated);
    }

    #[test]
    fn sensitive_files_excluded_from_results() {
        let root = TempDir::new().expect("temp dir");
        let path = root.path().to_path_buf();
        write_file(&path, ".env", b"SECRET=target\n");
        write_file(&path, "notes.txt", b"target visible\n");

        let mut opts = base_opts("target");
        opts.include_hidden = true; // ensure .env is walked so the matcher is exercised
        opts.sensitive = Some(crate::sensitive::SensitiveMatcher::new());
        let report = search_tree(&path, &opts).expect("search must not error");

        assert_eq!(report.matches.len(), 1);
        assert_eq!(report.matches[0].file, path.join("notes.txt"));
        assert!(!report
            .matches
            .iter()
            .any(|m| m.file.as_os_str() == ".env"));
        assert!(!report.truncated);
    }

    #[test]
    fn find_files_bare_word_matches_any_depth() {
        let root = TempDir::new().expect("temp dir");
        let path = root.path().to_path_buf();
        write_file(&path, "deep/b.txt", b"b\n");
        write_file(&path, "a.txt", b"a\n");

        let opts = FindOptions {
            pattern: "b.txt".to_string(),
            max_results: 10,
            want_dirs: false,
            include_hidden: false,
            include_ignored: false,
        };
        let report = find_files(&path, &opts).expect("find must not error");

        assert_eq!(report.paths, vec![path.join("deep/b.txt")]);
        assert_eq!(report.total_matches, 1);
        assert_eq!(report.files_scanned, 2);
        assert!(!report.truncated);
    }

    #[test]
    fn find_files_glob_relative_path() {
        let root = TempDir::new().expect("temp dir");
        let path = root.path().to_path_buf();
        write_file(&path, "src/a.rs", b"x\n");
        write_file(&path, "src/deep/b.txt", b"x\n");

        let opts = FindOptions {
            pattern: "**/*.rs".to_string(),
            max_results: 10,
            want_dirs: false,
            include_hidden: false,
            include_ignored: false,
        };
        let report = find_files(&path, &opts).expect("find must not error");

        assert_eq!(report.paths, vec![path.join("src/a.rs")]);
        assert_eq!(report.total_matches, 1);
        assert!(!report.truncated);
    }

    #[test]
    fn find_files_truncates_at_max_results() {
        let root = TempDir::new().expect("temp dir");
        let path = root.path().to_path_buf();
        for name in ["a.rs", "b.rs", "c.rs", "d.rs", "e.rs"] {
            write_file(&path, name, b"x\n");
        }

        let opts = FindOptions {
            pattern: "*.rs".to_string(),
            max_results: 2,
            want_dirs: false,
            include_hidden: false,
            include_ignored: false,
        };
        let report = find_files(&path, &opts).expect("find must not error");

        assert_eq!(report.paths.len(), 2);
        assert_eq!(report.total_matches, 5);
        assert!(report.truncated);
    }

    #[test]
    fn find_files_want_dirs_includes_directories() {
        let root = TempDir::new().expect("temp dir");
        let path = root.path().to_path_buf();
        write_file(&path, "deep/nested/x.txt", b"x\n");

        let opts = FindOptions {
            pattern: "deep".to_string(),
            max_results: 10,
            want_dirs: true,
            include_hidden: false,
            include_ignored: false,
        };
        let report = find_files(&path, &opts).expect("find must not error");

        assert_eq!(report.paths, vec![path.join("deep")]);
        assert_eq!(report.total_matches, 1);
    }
}
