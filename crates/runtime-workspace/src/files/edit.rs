//! Edit engine: two-stage matcher with occurrence counting, closest-match
//! errors, EOL-preserving writes and dry-run diffs.
//!
//! Produces `EditOutcome` consumed by Task 9 service methods and Task 11
//! MCP tools. Semantics are pinned by the Task 6 brief.

use std::collections::HashSet;
use std::path::Path;

use crate::files::read::detect_binary_probe;
use crate::files::write::{detect_dominant_eol, Eol, WriteOptions, write_text};
use runtime_core::error::{Error, Result};

/// A single text replacement.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct EditSpec {
    pub old_text: String,
    pub new_text: String,
    #[serde(default)] pub expected_occurrences: Option<usize>, // default 1
}

/// Options for [`edit_text`].
#[derive(Debug, Clone, Default, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct EditOptions {
    pub dry_run: bool,
}

/// Outcome of [`edit_text`].
#[derive(Debug, Clone)]
pub struct EditOutcome {
    pub applied_edits: usize,
    pub diff: Option<String>,
    pub dry_run: bool,
}

/// Rendered edit diffs longer than this are truncated.
const EDIT_DIFF_CAP: usize = 20_480;
const EDIT_DIFF_TRUNCATED: &str = "\n... diff truncated";

/// Edit `path` applying every edit in `edits` in order against the evolving
/// in-memory content. The file is written exactly once, and only when every
/// edit applies cleanly; any failure returns an error and leaves the file
/// untouched (all-or-nothing via compute-then-write-once).
pub fn edit_text(path: &Path, edits: &[EditSpec], opts: &EditOptions) -> Result<EditOutcome> {
    if detect_binary_probe(path)? {
        return Err(Error::Validation("Binary file cannot be edited".to_string()));
    }

    let raw = std::fs::read(path)?;
    let raw = String::from_utf8(raw).map_err(|_| Error::Validation("File is not valid UTF-8".to_string()))?;

    let dominant = detect_dominant_eol(raw.as_bytes());
    let original_lf = raw.replace("\r\n", "\n");

    let normalize = |s: &str| s.replace("\r\n", "\n");
    let total = edits.len();

    let mut content = original_lf.clone();
    for (i, spec) in edits.iter().enumerate() {
        let edit_no = i + 1;
        let old = normalize(&spec.old_text);
        let new = normalize(&spec.new_text);

        if old == new {
            return Err(Error::Validation(format!(
                "Edit {edit_no}: old_text equals new_text; nothing would change"
            )));
        }

        let expected = spec.expected_occurrences.unwrap_or(1);
        let count = count_occurrences(&content, &old);

        if count == 0 {
            stage2_replace(&mut content, edit_no, total, &old, &new)?;
        } else if count == expected {
            content = if expected == 1 {
                // expected == 1: replace the first occurrence only.
                content.replacen(&old, &new, 1)
            } else {
                // expected > 1: replace all occurrences.
                content.replacen(&old, &new, usize::MAX)
            };
        } else if spec.expected_occurrences.is_none() {
            // defaulted expected_occurrences with multiple exact matches:
            // fall through to the helpful stage-2 window analysis.
            stage2_replace(&mut content, edit_no, total, &old, &new)?;
        } else {
            return Err(Error::Validation(format!(
                "Edit {edit_no}: expected {expected} occurrence(s), found {count}. Pass expected_occurrences to replace all {count} of them."
            )));
        }
    }

    if content == original_lf {
        return Err(Error::Validation("No edits changed the file".to_string()));
    }

    // EOL-preserving write: byte-exact first, then dominant-EOL normalized.
    let final_bytes = final_bytes(&raw, edits, dominant, &content);

    let diff = render_edit_diff(&original_lf, &content, path);

    if opts.dry_run {
        return Ok(EditOutcome {
            applied_edits: total,
            diff: Some(diff),
            dry_run: true,
        });
    }

    let final_str = String::from_utf8(final_bytes).expect("edit result is valid UTF-8");
    write_text(
        path,
        &final_str,
        &WriteOptions {
            overwrite: true, // edit implies overwrite
            ..Default::default()
        },
    )?;

    Ok(EditOutcome {
        applied_edits: total,
        diff: Some(diff),
        dry_run: false,
    })
}

/// Stage 2 fallback: match `old` line-by-line ignoring leading and trailing
/// whitespace (inner whitespace must match) and re-indent each replacement
/// line against the matched file line.
fn stage2_replace(
    content: &mut String,
    edit_no: usize,
    total: usize,
    old: &str,
    new: &str,
) -> Result<()> {
    let old_ends_nl = old.ends_with('\n');
    let mut old_lines: Vec<&str> = old.split('\n').collect();
    if old_ends_nl {
        // trailing empty line dropped from comparison
        old_lines.pop();
    }
    let new_lines: Vec<&str> = new.split('\n').collect();
    let content_lines: Vec<&str> = content.split('\n').collect();

    let len = old_lines.len();
    if len == 0 {
        return Err(closest_match_error(edit_no, total, &[], content_lines.as_slice()));
    }

    let mut windows: Vec<usize> = Vec::new();
    for s in 0..=content_lines.len().saturating_sub(len) {
        if old_ends_nl && s + len == content_lines.len() {
            continue; // `old` expected a newline after the match; the file has none there
        }
        if (0..len).all(|j| content_lines[s + j].trim() == old_lines[j].trim()) {
            windows.push(s);
        }
    }

    match windows.len() {
        0 => Err(closest_match_error(
            edit_no,
            total,
            old_lines.as_slice(),
            content_lines.as_slice(),
        )),
        1 => {
            *content = replace_window(
                &content,
                windows[0],
                len,
                content_lines,
                new_lines.as_slice(),
                old_lines.as_slice(),
            );
            Ok(())
        }
        k => Err(Error::Validation(format!(
            "Edit {edit_no}: old_text matches {k} places (lines {}). Add surrounding lines or pass expected_occurrences.",
            window_list(&windows)
        ))),
    }
}

/// Replace the window at line `s` (length `len`) with `new_lines`, re-indenting
/// each replacement line by `indent(file_line) + indent(new_line) -
/// indent(old_line)` clamped at 0 spaces (tabs count as 4-space units).
fn replace_window(
    content: &str,
    s: usize,
    len: usize,
    content_lines: Vec<&str>,
    new_lines: &[&str],
    old_lines: &[&str],
) -> String {
    let mut out: Vec<String> = content_lines[..s].iter().map(|l| (*l).to_string()).collect();
    for (j, nl) in new_lines.iter().enumerate() {
        let file_indent = content_lines.get(s + j).map(|l| indent_of(l)).unwrap_or("");
        let old_indent = old_lines.get(j).map(|l| indent_of(l)).unwrap_or("");
        let new_indent = indent_of(nl);
        let width = indent_width(file_indent) + indent_width(new_indent) - indent_width(old_indent);
        let width = width.max(0);
        out.push(format!("{}{}", " ".repeat(width), nl.trim_start()));
    }
    out.extend(content_lines[s + len..].iter().map(|l| (*l).to_string()));
    out.join("\n")
}

/// Closest-match error: for every start line, the similarity is the sum of
/// per-line bigram-Dice similarity with all whitespace removed; the earliest
/// best start wins.
fn closest_match_error(edit_no: usize, total: usize, old_lines: &[&str], file_lines: &[&str]) -> Error {
    let len = old_lines.len();
    let mut best_start = 0usize;
    let mut best_sim = f64::NEG_INFINITY;
    if len > 0 && len <= file_lines.len() {
        for s in 0..=file_lines.len() - len {
            let sim: f64 = (0..len)
                .map(|j| {
                    bigram_dice(
                        &strip_whitespace(old_lines[j]),
                        &strip_whitespace(file_lines[s + j]),
                    )
                })
                .sum();
            if sim > best_sim {
                best_sim = sim;
                best_start = s;
            }
        }
    }

    let s_1 = best_start + 1;
    let e_1 = best_start + len;
    let region_start = best_start.saturating_sub(2);
    let region_end = (best_start + len + 2).min(file_lines.len());
    let mut region = String::new();
    let mut shown = 0usize;
    for (idx, line) in file_lines[region_start..region_end].iter().enumerate() {
        if shown >= 30 {
            break;
        }
        let n = region_start + idx + 1;
        region.push_str(&format!("{}\t{}\n", n, clip(line, 500)));
        shown += 1;
    }

    let mut old = String::new();
    for (idx, line) in old_lines.iter().enumerate() {
        old.push_str(&format!("{}\t{}\n", idx + 1, line));
    }

    Error::Validation(format!(
        "Could not find exact match for edit {edit_no} of {total}.\n\
         old_text must match the file's text exactly; only line endings and leading/trailing whitespace may differ.\n\
         old_text:\n{old}closest region (lines {s_1}..{e_1}):\n{region}Retry with old_text copied exactly from the file."
    ))
}

/// List up to 5 window start lines (1-based) for the matches-k-places error.
fn window_list(windows: &[usize]) -> String {
    let listed: Vec<String> = windows.iter().take(5).map(|s| (s + 1).to_string()).collect();
    if windows.len() > 5 {
        format!("{}, ...", listed.join(", "))
    } else {
        listed.join(", ")
    }
}

/// Byte-exact write first: apply the edits to `raw` with needles converted to
/// `dominant` EOL. If the LF view of that result equals the computed
/// `content`, those bytes are returned verbatim. Otherwise `content` is
/// normalized to the dominant EOL (`\n` -> `\r\n` for CRLF).
fn final_bytes(raw: &str, edits: &[EditSpec], dominant: Eol, content: &str) -> Vec<u8> {
    if dominant == Eol::Crlf {
        let mut b = raw.to_string();
        for spec in edits {
            let expected = spec.expected_occurrences.unwrap_or(1);
            let old = spec.old_text.replace("\r\n", "\n").replace('\n', "\r\n");
            let new = spec.new_text.replace("\r\n", "\n").replace('\n', "\r\n");
            b = if expected == 1 {
                b.replacen(&old, &new, 1)
            } else {
                b.replacen(&old, &new, usize::MAX)
            };
        }
        if b.replace("\r\n", "\n") == *content {
            return b.into_bytes();
        }
    }
    let normalized = if dominant == Eol::Crlf {
        content.replace('\n', "\r\n")
    } else {
        content.to_string()
    };
    normalized.into_bytes()
}

/// Render a `diffy` patch with headers replaced by `path`, capped at
/// `EDIT_DIFF_CAP` chars.
fn render_edit_diff(old: &str, new: &str, path: &Path) -> String {
    let rendered = format!("{}", diffy::create_patch(old, new));
    let path_str = path.to_string_lossy();
    let mut out = String::new();
    out.push_str("--- ");
    out.push_str(&path_str);
    out.push('\n');
    out.push_str("+++ ");
    out.push_str(&path_str);
    out.push('\n');
    let mut in_hunks = false;
    for line in rendered.lines() {
        if line.starts_with("@@ ") {
            in_hunks = true;
        }
        if in_hunks {
            out.push_str(line);
            out.push('\n');
        }
    }
    let mut diff = out;
    if diff.len() > EDIT_DIFF_CAP {
        diff = diff.chars().take(EDIT_DIFF_CAP).collect();
        diff.push_str(EDIT_DIFF_TRUNCATED);
    }
    diff
}

/// Naive non-overlapping sliding match count.
fn count_occurrences(haystack: &str, needle: &str) -> usize {
    if needle.is_empty() {
        return 0;
    }
    let mut count = 0usize;
    let mut start = 0usize;
    while let Some(pos) = haystack[start..].find(needle) {
        count += 1;
        start += pos + needle.len();
    }
    count
}

fn strip_whitespace(s: &str) -> String {
    s.chars().filter(|c| !c.is_whitespace()).collect()
}

/// Bigram-Dice similarity with all whitespace removed; blank vs blank = 1.0.
fn bigram_dice(a: &str, b: &str) -> f64 {
    let a = strip_whitespace(a);
    let b = strip_whitespace(b);
    if a.is_empty() && b.is_empty() {
        return 1.0;
    }
    let bigrams = |s: &str| {
        let chars: Vec<char> = s.chars().collect();
        chars
            .windows(2)
            .map(|w| (w[0], w[1]))
            .collect::<HashSet<(char, char)>>()
    };
    let aa = bigrams(&a);
    let bb = bigrams(&b);
    if aa.is_empty() || bb.is_empty() {
        return 0.0;
    }
    let intersection = aa.intersection(&bb).count();
    2.0 * intersection as f64 / (aa.len() + bb.len()) as f64
}

/// Leading run of spaces/tabs.
fn indent_of(line: &str) -> &str {
    let idx = line.chars().position(|c| c != ' ' && c != '\t').unwrap_or(line.len());
    &line[..idx]
}

/// Indent width in space units (tabs count as 4-space units for the delta).
fn indent_width(indent: &str) -> usize {
    indent.chars().map(|c| if c == '\t' { 4 } else { 1 }).sum()
}

/// Clip `s` at `max` chars (UTF-8 boundary) and append `[…cut]`.
fn clip(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let end = s.char_indices().nth(max).map(|(i, _)| i).unwrap_or(s.len());
    format!("{}[…cut]", &s[..end])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seed(path: &Path, bytes: &[u8]) {
        std::fs::write(path, bytes).expect("seed file");
    }

    fn edit(path: &Path, edits: Vec<EditSpec>, dry_run: bool) -> Result<EditOutcome> {
        edit_text(
            path,
            &edits,
            &EditOptions { dry_run },
        )
    }

    #[test]
    fn exact_single_replace() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("single.txt");
        seed(&path, b"alpha\nbeta\n");
        let outcome = edit(
            &path,
            vec![EditSpec {
                old_text: "alpha".into(),
                new_text: "ALPHA".into(),
                expected_occurrences: None,
            }],
            false,
        )
        .expect("edit");
        assert_eq!(outcome.applied_edits, 1);
        assert!(!outcome.dry_run);
        assert_eq!(std::fs::read(&path).expect("read"), b"ALPHA\nbeta\n");
    }

    #[test]
    fn multi_match_without_expected_errors_with_lines() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("multi.txt");
        seed(&path, b"x\nx\nx\n");
        let err = edit(
            &path,
            vec![EditSpec {
                old_text: "x".into(),
                new_text: "y".into(),
                expected_occurrences: None,
            }],
            false,
        )
        .unwrap_err();
        assert!(err.to_string().contains("matches 3 places (lines 1, 2, 3)"));
        // file untouched
        assert_eq!(std::fs::read(&path).expect("read"), b"x\nx\nx\n");
    }

    #[test]
    fn expected_two_replaces_all() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("two.txt");
        seed(&path, b"x\nx\nz\n");
        let outcome = edit(
            &path,
            vec![EditSpec {
                old_text: "x".into(),
                new_text: "y".into(),
                expected_occurrences: Some(2),
            }],
            false,
        )
        .expect("edit");
        assert_eq!(outcome.applied_edits, 1);
        assert_eq!(std::fs::read(&path).expect("read"), b"y\ny\nz\n");
    }

    #[test]
    fn count_mismatch_errors_with_fix_hint() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("mismatch.txt");
        seed(&path, b"x\nx\nx\n");
        let err = edit(
            &path,
            vec![EditSpec {
                old_text: "x".into(),
                new_text: "y".into(),
                expected_occurrences: Some(2),
            }],
            false,
        )
        .unwrap_err();
        assert!(err.to_string().contains("expected 2 occurrence(s), found 3"));
        assert_eq!(std::fs::read(&path).expect("read"), b"x\nx\nx\n");
    }

    #[test]
    fn edit_preserves_crlf_byte_exact() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("crlf.txt");
        seed(&path, b"a\r\nb\r\n");
        let outcome = edit(
            &path,
            vec![EditSpec {
                old_text: "a".into(),
                new_text: "A".into(),
                expected_occurrences: None,
            }],
            false,
        )
        .expect("edit");
        assert_eq!(outcome.applied_edits, 1);
        // no stray bare \n: CRLF preserved byte-exact
        assert_eq!(std::fs::read(&path).expect("read"), b"A\r\nb\r\n");
    }

    #[test]
    fn trim_fallback_matches_and_reindents() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("indent.txt");
        seed(&path, b"    if x {\n        go()\n    }\n");
        let outcome = edit(
            &path,
            vec![EditSpec {
                old_text: "  if x {\n    go()\n  }".into(),
                new_text: "  if y {\n    go()\n  }".into(),
                expected_occurrences: None,
            }],
            false,
        )
        .expect("edit");
        assert_eq!(outcome.applied_edits, 1);
        assert_eq!(
            std::fs::read(&path).expect("read"),
            b"    if y {\n        go()\n    }\n"
        );
    }

    #[test]
    fn closest_match_error_shows_region() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("closest.txt");
        seed(&path, b"hello world\ngoodbye\n");
        let err = edit(
            &path,
            vec![EditSpec {
                old_text: "hallo world".into(),
                new_text: "x".into(),
                expected_occurrences: None,
            }],
            false,
        )
        .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("closest region (lines"));
        assert!(msg.contains("Retry with old_text"));
        assert_eq!(std::fs::read(&path).expect("read"), b"hello world\ngoodbye\n");
    }

    #[test]
    fn dry_run_writes_nothing_and_returns_diff() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("dryrun.txt");
        seed(&path, b"old line\nkept\n");
        let outcome = edit(
            &path,
            vec![EditSpec {
                old_text: "old line".into(),
                new_text: "new line".into(),
                expected_occurrences: None,
            }],
            true,
        )
        .expect("edit");
        assert!(outcome.dry_run);
        assert_eq!(outcome.applied_edits, 1);
        let diff = outcome.diff.expect("diff present");
        assert!(diff.contains("@@"));
        assert_eq!(std::fs::read(&path).expect("read"), b"old line\nkept\n");
    }

    #[test]
    fn old_equals_new_errors() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("same.txt");
        seed(&path, b"a\nb\n");
        let err = edit(
            &path,
            vec![EditSpec {
                old_text: "a".into(),
                new_text: "a".into(),
                expected_occurrences: None,
            }],
            false,
        )
        .unwrap_err();
        assert!(err
            .to_string()
            .contains("old_text equals new_text; nothing would change"));
        assert_eq!(std::fs::read(&path).expect("read"), b"a\nb\n");
    }

    #[test]
    fn all_or_nothing_second_edit_failure_writes_nothing() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("rollback.txt");
        seed(&path, b"a\nb\n");
        let err = edit(
            &path,
            vec![
                EditSpec {
                    old_text: "a".into(),
                    new_text: "A".into(),
                    expected_occurrences: None,
                },
                EditSpec {
                    old_text: "zzz".into(),
                    new_text: "z".into(),
                    expected_occurrences: None,
                },
            ],
            false,
        )
        .unwrap_err();
        assert!(err.to_string().contains("Could not find exact match"));
        // all-or-nothing: file bytes unchanged
        assert_eq!(std::fs::read(&path).expect("read"), b"a\nb\n");
    }
}
