//! Write engine: atomic writes, overwrite guard, EOL preservation.
//!
//! Produces `WriteOutcome` consumed by Task 9 service methods and Task 11
//! MCP tools. Semantics are pinned by the Task 5 brief.

use std::io::Write;
use std::path::Path;

use runtime_core::error::{Error, Result};
use serde::{Deserialize, Serialize};
use tempfile::Builder as TempBuilder;

/// Line ending of a file: `Lf` or `Crlf`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Eol {
    Lf,
    Crlf,
}

/// Options for [`write_text`].
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct WriteOptions {
    pub overwrite: bool,
    pub append: bool,
    pub want_diff: bool,
}

/// Outcome of [`write_text`].
#[derive(Debug, Clone)]
pub struct WriteOutcome {
    pub bytes: u64,
    pub eol: Eol,
    pub diff: Option<String>,
}

/// Diff cap: rendered diffs longer than this are truncated.
const DIFF_CAP: usize = 8192;
const DIFF_TRUNCATED: &str = "... diff truncated";
const TEMP_PREFIX: &str = ".yl-";

/// CRLF count > bare-LF count -> Crlf; empty or LF-only -> Lf.
pub fn detect_dominant_eol(bytes: &[u8]) -> Eol {
    let mut crlf = 0usize;
    let mut bare_lf = 0usize;
    let mut prev_was_cr = false;
    for &byte in bytes {
        if byte == b'\n' {
            if prev_was_cr {
                crlf += 1;
            } else {
                bare_lf += 1;
            }
        }
        prev_was_cr = byte == b'\r';
    }
    if crlf > bare_lf {
        Eol::Crlf
    } else {
        Eol::Lf
    }
}

/// Rewrite `\r\n` as `\n` so a diff is not polluted by EOL normalization.
fn to_lf_view(text: &str) -> String {
    text.replace("\r\n", "\n")
}

/// Render a `diffy` patch and replace its header block with `path`.
fn render_diff(old: &str, new: &str, path: &Path) -> String {
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
    if diff.len() > DIFF_CAP {
        diff = diff.chars().take(DIFF_CAP).collect();
        diff.push_str(DIFF_TRUNCATED);
    }
    diff
}

/// Write `content` to `path` atomically with an overwrite guard and EOL
/// preservation.
///
/// - When the file exists, `overwrite: false` and `append: false` is a
///   validation error.
/// - The payload is staged in a `NamedTempFile` in the target's parent
///   directory and `persist`ed (on Windows this atomically replaces an
///   existing file via `MOVEFILE_REPLACE_EXISTING`).
/// - When the existing file is CRLF dominant and `content` carries bare
///   `\n` (no `"\r\n"` already present), `\n` is normalized to `\r\n`
///   before writing; otherwise bytes are written verbatim. `append`
///   extends the file verbatim with no EOL conversion.
/// - When `want_diff` is set and the file existed, a `diffy` patch
///   between LF-normalized old and new views is returned with its headers
///   replaced by the file path, capped at `DIFF_CAP` chars.
pub fn write_text(path: &Path, content: &str, opts: &WriteOptions) -> Result<WriteOutcome> {
    let existed = path.exists();

    if existed && !opts.overwrite && !opts.append {
        return Err(Error::Validation(
            "File exists; pass overwrite: true to replace it".to_string(),
        ));
    }

    let existing = if existed {
        Some(std::fs::read(path)?)
    } else {
        None
    };
    let eol = existing
        .as_deref()
        .map_or(Eol::Lf, |bytes| detect_dominant_eol(bytes));

    let final_bytes = if opts.append {
        let mut buf = existing.as_deref().map_or_else(Vec::new, |bytes| bytes.to_vec());
        buf.extend_from_slice(content.as_bytes());
        buf
    } else if eol == Eol::Crlf && content.contains('\n') && !content.contains("\r\n") {
        content.replace('\n', "\r\n").into_bytes()
    } else {
        content.as_bytes().to_vec()
    };

    let diff = if opts.want_diff && existed {
        let old_view = to_lf_view(&*String::from_utf8_lossy(existing.as_deref().unwrap()));
        let new_view = to_lf_view(&*String::from_utf8_lossy(&final_bytes));
        Some(render_diff(&old_view, &new_view, path))
    } else {
        None
    };

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let mut temp = TempBuilder::new()
        .prefix(TEMP_PREFIX)
        .tempfile_in(parent)?;
    temp.write_all(&final_bytes)?;
    temp.flush()?;
    temp.persist(path).map_err(|e| Error::Io(e.into()))?;

    Ok(WriteOutcome {
        bytes: final_bytes.len() as u64,
        eol,
        diff,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn has_bare_lf(bytes: &[u8]) -> bool {
        bytes.iter().enumerate().any(|(i, &b)| b == b'\n' && (i == 0 || bytes[i - 1] != b'\r'))
    }

    fn seed(path: &std::path::Path, bytes: &[u8]) {
        std::fs::write(path, bytes).expect("seed file");
    }

    #[test]
    fn overwrite_guard_message_exact() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("exists.txt");
        seed(&path, b"seed");
        let err = write_text(
            &path,
            "nope",
            &WriteOptions {
                overwrite: false,
                ..Default::default()
            },
        )
        .unwrap_err();
        assert!(err.to_string().contains("pass overwrite: true"));
        // seed untouched
        assert_eq!(std::fs::read(&path).expect("read"), b"seed");
        // no temp files left behind
        assert!(dir
            .path()
            .read_dir()
            .expect("read dir")
            .into_iter()
            .map(|e| e.expect("entry").file_name().to_string_lossy().to_string())
            .all(|name| !name.starts_with(TEMP_PREFIX)));
    }

    #[test]
    fn new_file_written_verbatim() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("new.txt");
        let content = "hello\n";
        let outcome = write_text(&path, content, &WriteOptions::default()).expect("write");
        assert_eq!(outcome.eol, Eol::Lf);
        assert_eq!(outcome.bytes, content.len() as u64);
        assert_eq!(std::fs::read(&path).expect("read"), content.as_bytes());
        assert!(outcome.diff.is_none());
    }

    #[test]
    fn crlf_target_preserved_when_content_has_bare_lf() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("crlf.txt");
        seed(&path, b"a\r\nb\r\n");
        let outcome = write_text(
            &path,
            "c\nd\n",
            &WriteOptions {
                overwrite: true,
                ..Default::default()
            },
        )
        .expect("write");
        assert_eq!(outcome.eol, Eol::Crlf);
        let got = std::fs::read(&path).expect("read");
        assert_eq!(got, b"c\r\nd\r\n");
        assert!(!has_bare_lf(&got));
    }

    #[test]
    fn append_extends_without_conversion() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("append.txt");
        seed(&path, b"a\r\nb\r\n");
        let outcome = write_text(
            &path,
            "c\n",
            &WriteOptions {
                append: true,
                ..Default::default()
            },
        )
        .expect("write");
        let got = std::fs::read(&path).expect("read");
        assert_eq!(got, b"a\r\nb\r\nc\n");
        // append never converts, even when the target is CRLF dominant
        assert!(has_bare_lf(&got));
    }

    #[test]
    fn diff_returned_for_overwrite_when_requested() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("diff.txt");
        seed(&path, b"old line\nkept\n");
        let outcome = write_text(
            &path,
            "new line\nkept\n",
            &WriteOptions {
                overwrite: true,
                want_diff: true,
                ..Default::default()
            },
        )
        .expect("write");
        let diff = outcome.diff.expect("diff present");
        assert!(diff.contains("@@"));
        assert!(diff.contains(path.to_string_lossy().as_ref()));
        // headers point at the path, not at the old/new text
        assert!(!diff.lines().next().unwrap().starts_with("--- old"));
    }

    #[test]
    fn diff_none_for_new_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("new.txt");
        let outcome = write_text(
            &path,
            "content\n",
            &WriteOptions {
                want_diff: true,
                ..Default::default()
            },
        )
        .expect("write");
        assert!(outcome.diff.is_none());
    }

    #[test]
    fn persist_replaces_existing_on_overwrite() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("roundtrip.txt");
        seed(&path, b"v1\n");
        let outcome = write_text(
            &path,
            "v2\n",
            &WriteOptions {
                overwrite: true,
                ..Default::default()
            },
        )
        .expect("write");
        assert_eq!(std::fs::read(&path).expect("read"), b"v2\n");
        assert_eq!(outcome.bytes, 3);
    }

    #[test]
    fn diff_on_empty_old_does_not_panic() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("empty.txt");
        seed(&path, b"");
        let outcome = write_text(
            &path,
            "something\n",
            &WriteOptions {
                overwrite: true,
                want_diff: true,
                ..Default::default()
            },
        )
        .expect("write");
        let diff = outcome.diff.expect("diff present for empty old");
        assert!(diff.contains("@@"));
    }
}
