//! Patch engine: diffy PatchSet parsing with two-phase all-or-nothing apply.
//!
//! Consumes `diffy::patch_set::{PatchSet, ParseOptions, FileOperation}` and
//! `diffy::apply`, enforces path safety per file op through
//! `PathValidator::validate_access`, and produces `PatchFileResult`s consumed
//! by the Task 9 service layer. Semantics are pinned by the Task 7 brief.

use std::fs;
use std::io::Write;
use std::path::{Component, Path, PathBuf};

use diffy::patch_set::{FileOperation, FilePatch, PatchKind, PatchSet, ParseOptions};
use diffy::apply;
use runtime_core::error::{Error, Result};
use runtime_core::types::ProjectId;
use tempfile::NamedTempFile;

use crate::path_safety::{AccessMode, PathValidator};

/// Diff text cap in bytes.
pub const PATCH_MAX_BYTES: usize = 262_144;
/// Maximum number of file operations a patch may contain.
pub const PATCH_MAX_FILES: usize = 10;

/// Result of applying a single file operation from a patch set.
#[derive(Debug, Clone)]
pub struct PatchFileResult {
    pub path: PathBuf,
    pub created: bool,
    pub bytes: u64,
}

/// Apply a unified/git diff `diff_text` against files under `root`.
///
/// Two-phase (binding): every file's new content is computed in memory and
/// staged to a temp file before *any* target is persisted; only after all
/// temps are built are the targets renamed into place. If a persist fails
/// mid-way, already-renamed targets are restored from their saved original
/// bytes (rollback) and the error is returned.
///
/// With `dry_run` everything is validated and planned but nothing is written;
/// results carry `bytes: 0`.
pub fn apply_patch_set(root: &Path, diff_text: &str, dry_run: bool) -> Result<Vec<PatchFileResult>> {
    // Size cap first, before any parsing or filesystem work.
    if diff_text.len() > PATCH_MAX_BYTES {
        return Err(Error::Validation(format!(
            "Patch too large (max {} bytes)",
            PATCH_MAX_BYTES
        )));
    }

    // Parse the whole patch set; any parse failure is a validation error.
    let file_patches: Vec<_> = PatchSet::parse(diff_text, ParseOptions::gitdiff())
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| Error::Validation(format!("Invalid patch: {e}")))?;

    if file_patches.len() > PATCH_MAX_FILES {
        return Err(Error::Validation(format!(
            "Patch contains {} file operations (max {})",
            file_patches.len(),
            PATCH_MAX_FILES
        )));
    }

    let project_id = ProjectId::new();
    let validator = PathValidator::new().with_root(root.to_path_buf());

    // Phase 1 (compute): validate every file op and compute its new content in
    // memory. Nothing on disk is touched yet.
    let mut plans: Vec<Plan> = Vec::with_capacity(file_patches.len());
    for file_patch in &file_patches {
        let op = file_patch.operation().strip_prefix(1);
        let (rel_cow, created) = match &op {
            FileOperation::Create(p) => (p.as_ref(), true),
            FileOperation::Delete(p) => (p.as_ref(), false),
            FileOperation::Modify { modified, .. } => (modified.as_ref(), false),
            FileOperation::Rename { to, .. } | FileOperation::Copy { to, .. } => {
                (to.as_ref(), false)
            }
        };
        let rel_str = rel_cow.to_string();
        let rel = Path::new(rel_cow);

        // Path safety per file op: relative-only; no absolute paths, drive
        // letters, leading separators, `..` components, or NUL bytes.
        validate_rel_path(rel, &rel_str)?;

        // Containment against the caller-provided root.
        let joined = root.join(rel);
        validator.validate_access(project_id, &joined, AccessMode::Write)?;

        let (original, new_content) = match &op {
            FileOperation::Delete(_) => {
                return Err(Error::Validation(
                    "Patch deletes are not supported; use workspace.delete".to_string(),
                ));
            }
            FileOperation::Rename { .. } | FileOperation::Copy { .. } => {
                return Err(Error::Validation(
                    "Patch rename and copy operations are not supported".to_string(),
                ));
            }
            FileOperation::Create(_) => {
                if joined.exists() {
                    return Err(Error::Validation(format!(
                        "Patch creates {rel_str} but it already exists"
                    )));
                }
                (None, compute_new_content("", file_patch, &rel_str)?)
            }
            FileOperation::Modify { .. } => {
                let base_bytes = fs::read(&joined)?;
                let base_text =
                    String::from_utf8(base_bytes.clone()).map_err(|_| {
                        Error::Validation(format!("Patch target {rel_str} is not valid UTF-8"))
                    })?;
                (
                    Some(base_bytes),
                    compute_new_content(&base_text, file_patch, &rel_str)?,
                )
            }
        };

        plans.push(Plan {
            target: joined,
            created,
            original,
            new_content: new_content.into_bytes(),
        });
    }

    // Dry run: report the plan with `bytes: 0` and write nothing.
    if dry_run {
        return Ok(plans
            .into_iter()
            .map(|plan| PatchFileResult {
                path: plan.target,
                created: plan.created,
                bytes: 0,
            })
            .collect());
    }

    // Phase 1b (stage): build all NamedTempFiles before any persist.
    let mut staged: Vec<(Plan, NamedTempFile)> = Vec::with_capacity(plans.len());
    for plan in plans {
        let parent = plan
            .target
            .parent()
            .expect("patch target has a parent directory");
        let mut temp = NamedTempFile::new_in(parent)?;
        temp.write_all(&plan.new_content)?;
        temp.flush()?;
        staged.push((plan, temp));
    }

    // Phase 2 (persist): rename each staged temp onto its target. If any
    // persist fails, roll back every already-renamed target from its saved
    // original bytes, then return the error.
    let mut persisted: Vec<(PathBuf, Option<Vec<u8>>)> = Vec::with_capacity(staged.len());
    for (plan, temp) in &staged {
        let target = &plan.target;
        if target.exists() {
            match fs::remove_file(target) {
                Ok(()) => {}
                Err(e) => {
                    rollback(&persisted);
                    return Err(Error::Io(e));
                }
            }
        }
        match fs::rename(temp.path(), target) {
            Ok(()) => persisted.push((target.clone(), plan.original.clone())),
            Err(e) => {
                rollback(&persisted);
                return Err(Error::Io(e));
            }
        }
    }

    Ok(staged
        .iter()
        .map(|(plan, _temp)| PatchFileResult {
            path: plan.target.clone(),
            created: plan.created,
            bytes: plan.new_content.len() as u64,
        })
        .collect())
}

/// A single file operation fully planned in phase 1.
#[derive(Clone)]
struct Plan {
    target: PathBuf,
    created: bool,
    /// Original bytes of the target, if it existed (used for rollback).
    original: Option<Vec<u8>>,
    new_content: Vec<u8>,
}

/// Reject paths that escape the base: absolute, drive letters / UNC prefixes,
/// leading separators, any `..` component, or NUL bytes.
fn validate_rel_path(rel: &Path, as_written: &str) -> Result<()> {
    if as_written.contains('\0') || rel.is_absolute() {
        return Err(Error::Validation(format!("Patch path escapes base: {as_written}")));
    }
    for component in rel.components() {
        match component {
            Component::ParentDir | Component::Prefix(_) | Component::RootDir => {
                return Err(Error::Validation(format!("Patch path escapes base: {as_written}")))
            }
            Component::Normal(_) | Component::CurDir => {}
        }
    }
    Ok(())
}

/// Compute a file's post-patch content by applying its diff hunk(s) to `base`.
fn compute_new_content(
    base: &str,
    file_patch: &FilePatch<'_, str>,
    rel: &str,
) -> Result<String> {
    let patch = match file_patch.patch() {
        PatchKind::Text(patch) => patch,
        _ => return Err(Error::Validation("binary patches are not supported".to_string())),
    };
    // `diffy::ApplyError(usize)` is opaque; the hunk number is only available
    // through its Display form ("error applying hunk #N").
    let hunk = apply(base, patch)
        .map_err(|e| {
            let n = e
                .to_string()
                .strip_prefix("error applying hunk #")
                .and_then(|n| n.parse::<usize>().ok())
                .unwrap_or(0);
            Error::Validation(format!("Patch hunk failed in {rel} (hunk {n})"))
        })?;
    Ok(hunk)
}

/// Restore every already-persisted target from its saved original bytes
/// (creates are removed), best-effort, then the caller returns the original
/// persist error.
fn rollback(persisted: &[(PathBuf, Option<Vec<u8>>)]) {
    for (target, original) in persisted.iter().rev() {
        match original {
            Some(bytes) => {
                let _ = fs::write(target, bytes);
            }
            None => {
                let _ = fs::remove_file(target);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seed(path: &Path, bytes: &[u8]) {
        std::fs::write(path, bytes).expect("seed file");
    }

    fn apply(root: &Path, diff: &str, dry_run: bool) -> Result<Vec<PatchFileResult>> {
        apply_patch_set(root, diff, dry_run)
    }

    fn temp_root() -> tempfile::TempDir {
        tempfile::tempdir().expect("tempdir")
    }

    #[test]
    fn modify_applies_and_reports_bytes() {
        let dir = temp_root();
        let path = dir.path().join("a.txt");
        seed(&path, b"alpha\n");
        let diff = "\
diff --git a/a.txt b/a.txt
--- a/a.txt
+++ b/a.txt
@@ -1 +1 @@
-alpha
+ALPHA
";
        let results = apply(dir.path(), diff, false).expect("apply");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].path, path);
        assert!(!results[0].created);
        assert_eq!(results[0].bytes, b"ALPHA\n".len() as u64);
        assert_eq!(std::fs::read(&path).expect("read"), b"ALPHA\n");
    }

    #[test]
    fn create_new_file_via_dev_null() {
        let dir = temp_root();
        let path = dir.path().join("new.txt");
        assert!(!path.exists());
        let diff = "\
diff --git a/new.txt b/new.txt
new file mode 100644
--- /dev/null
+++ b/new.txt
@@ -0,0 +1 @@
+hello
";
        let results = apply(dir.path(), diff, false).expect("apply");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].path, path);
        assert!(results[0].created);
        assert_eq!(results[0].bytes, b"hello\n".len() as u64);
        assert_eq!(std::fs::read(&path).expect("read"), b"hello\n");
    }

    #[test]
    fn failing_hunk_leaves_file_unchanged() {
        let dir = temp_root();
        let path = dir.path().join("a.txt");
        seed(&path, b"alpha\nbravo\n");
        let diff = "\
diff --git a/a.txt b/a.txt
--- a/a.txt
+++ b/a.txt
@@ -1,2 +1,2 @@
 alpha
-zebra
+ZEBRA
";
        let err = apply(dir.path(), diff, false).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("Patch hunk failed in a.txt (hunk 1)"), "unexpected: {msg}");
        // file bytes == original: all-or-nothing
        assert_eq!(std::fs::read(&path).expect("read"), b"alpha\nbravo\n");
    }

    #[test]
    fn dry_run_writes_nothing() {
        let dir = temp_root();
        let path = dir.path().join("a.txt");
        seed(&path, b"alpha\n");
        let diff = "\
diff --git a/a.txt b/a.txt
--- a/a.txt
+++ b/a.txt
@@ -1 +1 @@
-alpha
+ALPHA
";
        let results = apply(dir.path(), diff, true).expect("apply");
        assert_eq!(results.len(), 1);
        assert!(!results[0].created);
        assert_eq!(results[0].bytes, 0);
        assert_eq!(std::fs::read(&path).expect("read"), b"alpha\n");
    }

    #[test]
    fn escaping_path_rejected() {
        let dir = temp_root();
        let diff = "\
diff --git a/b/../../evil.txt b/b/../../evil.txt
--- a/b/../../evil.txt
+++ b/b/../../evil.txt
@@ -1 +1 @@
-x
+y
";
        let err = apply(dir.path(), diff, false).unwrap_err();
        assert!(
            err.to_string().contains("Patch path escapes base"),
            "unexpected: {}",
            err
        );
    }

    #[test]
    fn delete_operation_rejected() {
        let dir = temp_root();
        let diff = "\
diff --git a/gone.txt b/gone.txt
deleted file mode 100644
--- a/gone.txt
+++ /dev/null
@@ -1 +0,0 @@
-x
";
        let err = apply(dir.path(), diff, false).unwrap_err();
        assert!(
            err.to_string()
                .contains("Patch deletes are not supported; use workspace.delete"),
            "unexpected: {err}"
        );
    }

    #[test]
    fn two_files_second_failing_first_not_written() {
        let dir = temp_root();
        let a_path = dir.path().join("a.txt");
        let b_path = dir.path().join("b.txt");
        seed(&a_path, b"alpha\n");
        seed(&b_path, b"zzz\n");
        let diff = "\
diff --git a/a.txt b/a.txt
--- a/a.txt
+++ b/a.txt
@@ -1 +1 @@
-alpha
+ALPHA
diff --git a/b.txt b/b.txt
--- a/b.txt
+++ b/b.txt
@@ -1 +1 @@
 hello
-world
+WORLD
";
        let err = apply(dir.path(), diff, false).unwrap_err();
        assert!(err.to_string().contains("Patch hunk failed"), "unexpected: {err}");
        // all-or-nothing: neither file was written
        assert_eq!(std::fs::read(&a_path).expect("read"), b"alpha\n");
        assert_eq!(std::fs::read(&b_path).expect("read"), b"zzz\n");
    }

    #[test]
    fn create_over_existing_rejected() {
        let dir = temp_root();
        let path = dir.path().join("exists.txt");
        seed(&path, b"old\n");
        let diff = "\
diff --git a/exists.txt b/exists.txt
new file mode 100644
--- /dev/null
+++ b/exists.txt
@@ -0,0 +1 @@
+new
";
        let err = apply(dir.path(), diff, false).unwrap_err();
        assert!(
            err.to_string().contains("Patch creates exists.txt but it already exists"),
            "unexpected: {err}"
        );
        assert_eq!(std::fs::read(&path).expect("read"), b"old\n");
    }

    #[test]
    fn patch_too_large_rejected() {
        let dir = temp_root();
        let diff = "x".repeat(PATCH_MAX_BYTES + 1);
        let err = apply(dir.path(), &diff, false).unwrap_err();
        assert!(
            err.to_string().contains("Patch too large (max 262144 bytes)"),
            "unexpected: {err}"
        );
    }

    #[test]
    fn too_many_files_rejected() {
        let dir = temp_root();
        let mut diff = String::new();
        for i in 0..(PATCH_MAX_FILES + 1) {
            diff.push_str(&format!(
                "\
diff --git a/f{i}.txt b/f{i}.txt
--- a/f{i}.txt
+++ b/f{i}.txt
@@ -1 +1 @@
-x
+y
"
            ));
        }
        let err = apply(dir.path(), &diff, false).unwrap_err();
        assert!(err.to_string().contains("max 10"), "unexpected: {err}");
    }
}
