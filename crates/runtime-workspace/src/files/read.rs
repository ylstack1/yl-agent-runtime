//! Read engine: byte mode, line mode, binary probe, media, sha256.
//!
//! Produces `ReadOutcome` consumed by Task 9 service methods and Task 11
//! MCP tools. Semantics are pinned by the Task 4 brief.

use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use runtime_core::error::{Error, Result};
use sha2::{Digest, Sha256};

pub const READ_MAX_BYTES: u64 = 1_048_576;
pub const READ_DEFAULT_BYTES: u64 = 65_536;
pub const READ_MAX_LINES: usize = 2000;
pub const LINE_CUT_AT: usize = 4000;

/// PROBE_WINDOW is the number of leading bytes scanned for a NUL byte to
/// detect binary content.
const PROBE_WINDOW: usize = 8192;

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

#[derive(Debug, Clone)]
pub struct TextRead {
    pub content: String,
    pub truncated: bool,
    pub next_line: Option<u64>,
    pub total_lines: Option<u64>,
    pub size: u64,
    pub returned_bytes: u64,
    pub sha256: Option<String>,
}

#[derive(Debug, Clone)]
pub struct MediaRead {
    pub mime: String,
    pub base64: String,
    pub size: u64,
}

#[derive(Debug, Clone)]
pub enum ReadOutcome {
    Text(TextRead),
    Media(MediaRead),
    Binary { size: u64 },
}

/// Read a file as text (byte mode), media, or a binary-size marker.
///
/// Head/tail conflict is checked first. A binary probe decides whether
/// the file is binary: binary with `media: false` is a validation error;
/// binary with `media: true` serves a media read (or `Binary` when the
/// extension is not in the media table). Otherwise the file is read in
/// line mode (any line/head/tail parameter) or byte mode.
pub fn read_text(path: &Path, opts: &ReadOptions) -> Result<ReadOutcome> {
    if opts.head.is_some() && opts.tail.is_some() {
        return Err(Error::Validation(
            "Cannot specify both head and tail".to_string(),
        ));
    }

    let binary = detect_binary_probe(path)?;
    if binary && !opts.media {
        return Err(Error::Validation(
            "Binary file; pass media: true for image/audio content".to_string(),
        ));
    }

    if opts.media {
        return read_media(path);
    }

    let line_mode = opts.line_start.is_some()
        || opts.line_end.is_some()
        || opts.head.is_some()
        || opts.tail.is_some();

    if line_mode {
        read_lines(path, opts)
    } else {
        read_bytes(path, opts)
    }
}

/// Probe the first `PROBE_WINDOW` bytes for a NUL byte.
pub fn detect_binary_probe(path: &Path) -> std::io::Result<bool> {
    let mut file = std::fs::File::open(path)?;
    let mut buf = [0u8; PROBE_WINDOW];
    let n = file.read(&mut buf)?;
    Ok(buf[..n].iter().any(|byte| *byte == 0))
}

/// MIME table keyed by file extension (leading dot optional, case
/// insensitive). Unknown extensions map to `application/octet-stream`.
pub fn mime_for_extension(ext: &str) -> &'static str {
    let ext = ext.trim_start_matches('.').to_lowercase();
    match ext.as_str() {
        "png" => "image/png",
        "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "bmp" => "image/bmp",
        "svg" => "image/svg+xml",
        "mp3" => "audio/mpeg",
        "wav" => "audio/wav",
        "ogg" => "audio/ogg",
        "flac" => "audio/flac",
        _ => "application/octet-stream",
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// Read an entire file as a media blob.
fn read_media(path: &Path) -> Result<ReadOutcome> {
    let mut file = std::fs::File::open(path)?;
    let mut buf = Vec::new();
    file.read_to_end(&mut buf)?;
    let size = buf.len() as u64;

    let ext = path
        .extension()
        .map(|os| os.to_string_lossy().to_string())
        .unwrap_or_default();
    let mime = mime_for_extension(&ext);

    if mime == "application/octet-stream" {
        return Ok(ReadOutcome::Binary { size });
    }

    use base64::{engine::general_purpose::STANDARD, Engine as _};
    let base64 = STANDARD.encode(&buf);
    Ok(ReadOutcome::Media(MediaRead {
        mime: mime.to_string(),
        base64,
        size,
    }))
}

/// Byte mode: no line/head/tail parameters. Reads
/// `min(max_bytes, READ_MAX_BYTES) + 1` bytes from `offset`, decodes
/// lossily, and reports whether more bytes remain.
fn read_bytes(path: &Path, opts: &ReadOptions) -> Result<ReadOutcome> {
    let metadata = std::fs::metadata(path)?;
    let size = metadata.len();

    let max_bytes = opts
        .max_bytes
        .unwrap_or(READ_DEFAULT_BYTES)
        .min(READ_MAX_BYTES);
    let offset = opts.offset.unwrap_or(0);

    let mut file = std::fs::File::open(path)?;
    file.seek(SeekFrom::Start(offset))?;

    let mut buf = vec![0u8; (max_bytes + 1) as usize];
    let n = file.read(&mut buf)?;
    let available = n as u64;
    let truncated = available > max_bytes;
    let take = n.min(max_bytes as usize);

    let content = String::from_utf8_lossy(&buf[..take]).to_string();
    let returned_bytes = content.as_bytes().len() as u64;

    let sha256 = if opts.want_sha256 {
        Some(sha256_hex(content.as_bytes()))
    } else {
        None
    };

    Ok(ReadOutcome::Text(TextRead {
        content,
        truncated,
        next_line: None,
        total_lines: None,
        size,
        returned_bytes,
        sha256,
    }))
}

/// Line mode: strict UTF-8 decode, line windows of `READ_MAX_LINES`,
/// optional `"{n}\t{line}"` numbering, long-line cut at `LINE_CUT_AT`.
fn read_lines(path: &Path, opts: &ReadOptions) -> Result<ReadOutcome> {
    let metadata = std::fs::metadata(path)?;
    let size = metadata.len();

    let all = std::fs::read(path)?;
    let text = std::str::from_utf8(&all).map_err(|_| {
        Error::Validation("File is not valid UTF-8".to_string())
    })?;

    // Split on '\n'; a trailing newline produces one empty element that is
    // not a real line.
    let mut lines: Vec<&str> = text.split('\n').collect();
    if lines.last() == Some(&"") {
        lines.pop();
    }
    let total = lines.len() as u64;

    // `head`/`tail` of 0 means zero lines: an empty result, not an error.
    if opts.head == Some(0) || opts.tail == Some(0) {
        return Ok(ReadOutcome::Text(TextRead {
            content: String::new(),
            truncated: false,
            next_line: None,
            total_lines: None,
            size,
            returned_bytes: 0,
            sha256: if opts.want_sha256 {
                Some(sha256_hex(b""))
            } else {
                None
            },
        }));
    }

    let (mut start, mut end): (u64, u64) = match (opts.head, opts.tail) {
        (Some(head), None) => (1, head),
        (None, Some(tail)) => {
            let start = if tail >= total { 1 } else { total - tail + 1 };
            (start, total)
        }
        (None, None) => (
            opts.line_start.unwrap_or(1),
            opts.line_end
                .unwrap_or_else(|| opts.line_start.unwrap_or(1) + READ_MAX_LINES as u64 - 1),
        ),
        _ => unreachable!("head and tail conflict is rejected by read_text"),
    };

    if start > total {
        return Err(Error::Validation(format!(
            "line_start {start} is past the end of the file ({total} lines)"
        )));
    }
    // Line numbers are 1-based; clamp a zero `line_start` to the first line.
    start = start.max(1);

    end = end.min(total);
    let window_end = start.saturating_add(READ_MAX_LINES as u64 - 1);
    end = end.min(window_end);

    if start > end {
        return Ok(ReadOutcome::Text(TextRead {
            content: String::new(),
            truncated: false,
            next_line: None,
            total_lines: None,
            size,
            returned_bytes: 0,
            sha256: if opts.want_sha256 {
                Some(sha256_hex(b""))
            } else {
                None
            },
        }));
    }

    let mut truncated = end < total;
    let next_line = if end < total {
        Some(end + 1)
    } else {
        None
    };
    let total_lines = if end >= total { Some(total) } else { None };

    let mut out: Vec<String> = Vec::with_capacity((end - start + 1) as usize);
    for (index, line) in lines[(start as usize - 1)..(end as usize)].iter().enumerate() {
        let number = start + index as u64;
        let cut = if line.len() > LINE_CUT_AT {
            truncated = true;
            format!("{} ...[line cut]", &line[..LINE_CUT_AT])
        } else {
            line.to_string()
        };
        // Line mode defaults line_numbers to on.
        out.push(format!("{number}\t{cut}"));
    }

    let content = out.join("\n");
    let returned_bytes = content.as_bytes().len() as u64;

    let sha256 = if opts.want_sha256 {
        Some(sha256_hex(content.as_bytes()))
    } else {
        None
    };

    Ok(ReadOutcome::Text(TextRead {
        content,
        truncated,
        next_line,
        total_lines,
        size,
        returned_bytes,
        sha256,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};
    use std::io::Write;

    const SEED: &[u8] = b"l1\nl2\nl3\nl4\nl5\n";

    fn seed_file() -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().expect("tempfile");
        f.write_all(SEED).expect("write seed");
        f.flush().expect("flush");
        f
    }

    #[test]
    fn byte_mode_defaults_and_truncation_flag() {
        let file = seed_file();
        let opts = ReadOptions {
            max_bytes: Some(5),
            ..Default::default()
        };
        match read_text(file.path(), &opts) {
            Ok(ReadOutcome::Text(t)) => {
                assert_eq!(t.content, "l1\nl2");
                assert!(t.truncated);
                assert_eq!(t.next_line, None);
                assert_eq!(t.total_lines, None);
            }
            other => panic!("unexpected outcome: {other:?}"),
        }
    }

    #[test]
    fn line_mode_numbered_with_next_line() {
        let file = seed_file();
        let opts = ReadOptions {
            line_start: Some(2),
            line_end: Some(3),
            ..Default::default()
        };
        match read_text(file.path(), &opts) {
            Ok(ReadOutcome::Text(t)) => {
                assert_eq!(t.content, "2\tl2\n3\tl3");
                assert_eq!(t.next_line, Some(4));
                assert_eq!(t.total_lines, None);
            }
            other => panic!("unexpected outcome: {other:?}"),
        }
    }

    #[test]
    fn line_mode_past_eof_errors_with_message() {
        let file = seed_file();
        let opts = ReadOptions {
            line_start: Some(9),
            ..Default::default()
        };
        let err = read_text(file.path(), &opts).unwrap_err();
        assert!(matches!(err, Error::Validation(_)));
        assert!(err.to_string().contains("(5 lines)"));
    }

    #[test]
    fn head_and_tail_conflict_errors() {
        let file = seed_file();
        let opts = ReadOptions {
            head: Some(2),
            tail: Some(2),
            ..Default::default()
        };
        let err = read_text(file.path(), &opts).unwrap_err();
        assert!(matches!(err, Error::Validation(_)));
        assert!(err
            .to_string()
            .contains("Cannot specify both head and tail"));
    }

    #[test]
    fn head_zero_returns_empty_not_error() {
        let file = seed_file();
        let opts = ReadOptions {
            head: Some(0),
            ..Default::default()
        };
        match read_text(file.path(), &opts) {
            Ok(ReadOutcome::Text(t)) => assert_eq!(t.content, ""),
            other => panic!("unexpected outcome: {other:?}"),
        }
    }

    #[test]
    fn tail_returns_last_n_lines() {
        let file = seed_file();
        let opts = ReadOptions {
            tail: Some(2),
            ..Default::default()
        };
        match read_text(file.path(), &opts) {
            Ok(ReadOutcome::Text(t)) => {
                assert_eq!(t.content, "4\tl4\n5\tl5");
                assert_eq!(t.total_lines, Some(5));
                assert_eq!(t.next_line, None);
                assert!(!t.truncated);
            }
            other => panic!("unexpected outcome: {other:?}"),
        }
    }

    #[test]
    fn binary_probe_detects_nul_and_media_serves_base64() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"PNG\r\n");
        bytes.push(0u8);
        bytes.extend_from_slice(b"payload");

        let mut tf = tempfile::Builder::new()
            .suffix(".png")
            .tempfile()
            .expect("tempfile");
        tf.write_all(&bytes).expect("write");
        tf.flush().expect("flush");

        assert!(detect_binary_probe(tf.path()).expect("probe"));

        let opts = ReadOptions {
            media: true,
            ..Default::default()
        };
        match read_text(tf.path(), &opts) {
            Ok(ReadOutcome::Media(m)) => {
                assert_eq!(m.mime, "image/png");
                assert!(!m.base64.is_empty());
                use base64::{engine::general_purpose::STANDARD, Engine as _};
                let decoded = STANDARD.decode(&m.base64).expect("base64 decode");
                assert_eq!(decoded, bytes);
                assert_eq!(m.size, bytes.len() as u64);
            }
            other => panic!("unexpected outcome: {other:?}"),
        }

        // empty file probe: no NUL byte
        let empty = tempfile::NamedTempFile::new().expect("tempfile");
        assert!(!detect_binary_probe(empty.path()).expect("probe"));
    }

    #[test]
    fn long_line_cut_marks_truncation() {
        let line: String = std::iter::repeat('a').take(5000).collect();
        let content = format!("{line}\n");
        let mut tf = tempfile::NamedTempFile::new().expect("tempfile");
        tf.write_all(content.as_bytes()).expect("write");
        tf.flush().expect("flush");

        let opts = ReadOptions {
            line_start: Some(1),
            ..Default::default()
        };
        match read_text(tf.path(), &opts) {
            Ok(ReadOutcome::Text(t)) => {
                assert!(t.content.contains(" ...[line cut]"));
                assert!(t.truncated);
            }
            other => panic!("unexpected outcome: {other:?}"),
        }
    }

    #[test]
    fn sha256_hash_of_returned_slice() {
        let file = seed_file();
        let opts = ReadOptions {
            max_bytes: Some(3),
            want_sha256: true,
            ..Default::default()
        };
        match read_text(file.path(), &opts) {
            Ok(ReadOutcome::Text(t)) => {
                assert_eq!(t.content, "l1\n");
                assert!(t.truncated);
                let mut h = Sha256::new();
                h.update(b"l1\n");
                let expected: String = h
                    .finalize()
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect();
                assert_eq!(t.sha256.as_deref(), Some(expected.as_str()));
            }
            other => panic!("unexpected outcome: {other:?}"),
        }
    }
}
