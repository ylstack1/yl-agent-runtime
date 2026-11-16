//! Path safety validation
//!
//! Per PRD section 8.2: Every filesystem operation must normalize, canonicalize,
//! resolve symlinks/junctions, enforce allowed roots, reject device namespaces
//! and UNC paths, validate path components, and use handle-based operations.

use runtime_core::error::{Error, Result};
use runtime_core::types::ProjectId;
use serde::{Deserialize, Serialize};
use std::ffi::OsString;
use std::fs;
use std::path::{Component, Path, PathBuf};

/// A validated, contained workspace path
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContainedPath {
    pub project_id: ProjectId,
    pub absolute_path: PathBuf,
    pub relative_path: PathBuf,
}

/// How a validated path is about to be used.
///
/// `Write` and `Move` refuse paths inside any read-only root; `Read` allows
/// them. `validate()` delegates with `AccessMode::Read`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessMode {
    Read,
    Write,
    Move,
}

/// Path validation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathValidationResult {
    pub valid: bool,
    pub resolved_path: Option<PathBuf>,
    pub relative_path: Option<PathBuf>,
    pub violations: Vec<PathViolation>,
}

/// Path violation types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PathViolation {
    PathTraversal,
    SymlinkEscape,
    JunctionEscape,
    ReparsePointEscape,
    UncPath,
    DeviceNamespace,
    AlternateDataStream,
    NullByte,
    OutsideAllowedRoot,
    SensitiveDirectory,
    InvalidComponent,
}

/// Windows reserved device names
const WINDOWS_DEVICE_NAMES: &[&str] = &[
    "CON", "PRN", "AUX", "NUL",
    "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
    "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
];

/// Sensitive directories that should be denied by default
#[cfg(windows)]
const SENSITIVE_DIRS: &[&str] = &[
    "%USERPROFILE%/.ssh",
    "%USERPROFILE%/.aws",
    "%APPDATA%/Microsoft/Credentials",
];

#[cfg(not(windows))]
const SENSITIVE_DIRS: &[&str] = &[
    "~/.ssh",
    "~/.aws",
    "~/.config/gcloud",
    "~/.config/ec2",
];

/// Path safety validator
#[derive(Clone)]
pub struct PathValidator {
    allowed_roots: Vec<PathBuf>,
    read_only_roots: Vec<PathBuf>,
    deny_paths: Vec<PathBuf>,
    follow_symlinks: bool,
    max_depth: usize,
    max_file_size: u64,
}

impl PathValidator {
    pub fn new() -> Self {
        Self {
            allowed_roots: Vec::new(),
            read_only_roots: Vec::new(),
            deny_paths: Vec::new(),
            follow_symlinks: false,
            max_depth: 256,
            max_file_size: 100_000_000, // 100 MB
        }
    }

    pub fn with_root(mut self, root: PathBuf) -> Self {
        self.allowed_roots.push(root);
        self
    }

    /// Register a root that must never be written to (only read from).
    pub fn with_read_only_root(mut self, root: PathBuf) -> Self {
        self.read_only_roots.push(root);
        self
    }

    pub fn with_deny_path(mut self, path: PathBuf) -> Self {
        self.deny_paths.push(path);
        self
    }

    pub fn allow_symlinks(mut self, allow: bool) -> Self {
        self.follow_symlinks = allow;
        self
    }

    /// Validate and resolve a path for read access within allowed roots.
    pub fn validate(&self, project_id: ProjectId, user_path: &Path) -> Result<ContainedPath> {
        self.validate_access(project_id, user_path, AccessMode::Read)
    }

    /// Full pipeline: `..`-collapse (drive prefix retained) → ADS/reserved/trailing
    /// checks → Windows drive normalization → root containment → canonicalize
    /// (realpath) → re-containment → deny/read-only enforcement.
    ///
    /// No home-directory expansion is performed (`~` stays a literal component,
    /// harmless inside a root); the ADS colon check runs before containment.
    /// Write/Move refuse paths inside any read-only root.
    pub fn validate_access(
        &self,
        project_id: ProjectId,
        user_path: &Path,
        mode: AccessMode,
    ) -> Result<ContainedPath> {
        let mut violations = Vec::new();
        let raw = user_path.to_string_lossy().to_string();

        // (1) Null byte check (existing behavior).
        if raw.contains('\0') {
            violations.push(PathViolation::NullByte);
            return Err(Error::PathEscape(format!("Null byte in path: {:?}", user_path)));
        }

        // UNC / device-namespace heads are rejected unconditionally. The check is
        // string-based on purpose: `Path::starts_with` compares components, so a
        // verbatim-free `\\server\share` head could slip through when parsed as a
        // Windows prefix.
        if raw.starts_with("\\\\") || raw.starts_with("//") {
            violations.push(PathViolation::UncPath);
            return Err(Error::PathNotAllowed("UNC paths not allowed".to_string()));
        }

        // (2) Raw-component checks. These run on the raw string because Windows path
        // parsing silently trims trailing dots/spaces, which would hide `file.`
        // (Win32 strips them) and could absorb stray colons afterwards.
        //
        // (brief step 3) ADS / stray drive colon: a ':' is only legal as the drive
        // prefix (`^[A-Za-z]:`, anchored at string offset 0). This must run before
        // root containment.
        for (start, component) in split_path_components(&raw) {
            if component.contains(':') && !(start == 0 && is_drive_prefix_component(component)) {
                violations.push(PathViolation::AlternateDataStream);
                return Err(Error::PathNotAllowed(format!(
                    "Alternate data streams / stray drive colon not allowed: {:?}",
                    user_path
                )));
            }
        }
        // (brief steps 4 + 5) reserved device names per component (incl. `CON.txt`)
        // and trailing dot/space components.
        for (_, component) in split_path_components(&raw) {
            if component == "." || component == ".." {
                continue; // navigation, handled by normalization/traversal check
            }
            if is_windows_device_component(component) {
                violations.push(PathViolation::DeviceNamespace);
                return Err(Error::PathNotAllowed(format!(
                    "Windows device name not allowed: {}",
                    component
                )));
            }
            if component.ends_with('.') || component.ends_with(' ') {
                violations.push(PathViolation::InvalidComponent);
                return Err(Error::PathNotAllowed(format!(
                    "Invalid component (Win32 strips trailing dot/space): {:?}",
                    component
                )));
            }
        }

        // (brief step 6) drive normalization on Windows before containment.
        #[cfg(windows)]
        let raw2 = normalize_windows_path(&raw);
        #[cfg(not(windows))]
        let raw2 = raw.clone();

        // (brief step 2) `..`-collapse normalization, retaining the Windows drive
        // prefix and root separator (absolute inputs stay absolute).
        let normalized = normalize_path(Path::new(&raw2));

        // Path traversal after normalization (existing behavior; leading `..`
        // components are preserved by normalization so they are visible here).
        let normalized_str = normalized.to_string_lossy();
        if normalized_str.starts_with("..")
            || normalized_str.contains("/..")
            || normalized_str.contains("\\..")
        {
            violations.push(PathViolation::PathTraversal);
            return Err(Error::PathEscape(format!("Path traversal detected: {:?}", user_path)));
        }

        // (brief step 7) root containment, separator-boundary safe, remembering
        // which root matched for re-containment.
        let (resolved, matched_root) = self.resolve_against_roots(project_id, &normalized)?;

        // Deny lists + sensitive directories (existing behavior, pre-canonical).
        self.check_deny_and_sensitive(&resolved, &mut violations)?;

        // Depth (existing behavior).
        let depth = resolved.components().count();
        if depth > self.max_depth {
            violations.push(PathViolation::OutsideAllowedRoot);
            return Err(Error::Validation(format!("Path depth {} exceeds maximum {}", depth, self.max_depth)));
        }

        // Relative path is stable regardless of canonicalization below.
        let relative_path = resolved
            .strip_prefix(&matched_root)
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|_| resolved.clone());

        // (brief step 8) realpath re-containment: junctions/symlinks that leave the
        // roots fail with PathEscape; ENOENT (new file) falls back to the deepest
        // existing ancestor so intermediate junctions are still caught.
        let final_path = self.recontain_via_realpath(&resolved)?;

        // (brief step 9) deny lists + read-only roots on the final path; denies
        // apply to every mode, read-only roots only refuse Write/Move. Read-only
        // roots are matched case-folded on Windows and canonicalized when they
        // exist, so a mis-cased registration (or an 8.3/verbatim spelling)
        // cannot let a write land inside a "read-only" root.
        self.check_deny_and_sensitive(&final_path, &mut violations)?;
        if matches!(mode, AccessMode::Write | AccessMode::Move) {
            for root in &self.read_only_roots {
                let canonical_root = fs::canonicalize(root).ok().map(|c| strip_verbatim_prefix(&c));
                let withheld = starts_with_folded(&final_path, root)
                    || starts_with_folded(&resolved, root)
                    || canonical_root
                        .map(|c| starts_with_folded(&final_path, &c) || starts_with_folded(&resolved, &c))
                        .unwrap_or(false);
                if withheld {
                    return Err(Error::PathNotAllowed(format!(
                        "Path is in a read-only root: {}",
                        root.display()
                    )));
                }
            }
        }

        Ok(ContainedPath {
            project_id,
            absolute_path: final_path,
            relative_path,
        })
    }

    /// Check if a path is within any allowed root
    pub fn is_within_roots(&self, path: &Path) -> bool {
        self.allowed_roots.iter().any(|root| path.starts_with(root))
    }

    /// Add an allowed root
    pub fn add_root(&mut self, root: PathBuf) {
        self.allowed_roots.push(root);
    }

    /// Remove an allowed root
    pub fn remove_root(&mut self, root: &Path) {
        self.allowed_roots.retain(|r| r != root);
    }

    /// Deny lists and sensitive directories, applied to both the pre-canonical
    /// and the canonical (realpath) form so a junction cannot launder a target.
    fn check_deny_and_sensitive(&self, resolved: &Path, violations: &mut Vec<PathViolation>) -> Result<()> {
        for deny in &self.deny_paths {
            let denied = starts_with_folded(resolved, deny)
                // Restriction roots are canonicalized when they exist, so a
                // junction (or 8.3 / casing difference) cannot dodge the deny by
                // spelling. Registration errors that make the deny unresolvable
                // keep the textual check above (containment itself is unaffected).
                || fs::canonicalize(deny)
                    .ok()
                    .map(|c| starts_with_folded(resolved, &strip_verbatim_prefix(&c)))
                    .unwrap_or(false);
            if denied {
                violations.push(PathViolation::SensitiveDirectory);
                return Err(Error::PathNotAllowed(format!(
                    "Path is in denied directory: {:?}",
                    resolved
                )));
            }
        }

        for sensitive in SENSITIVE_DIRS {
            let sensitive_path = Path::new(sensitive);
            if resolved.starts_with(sensitive_path) {
                violations.push(PathViolation::SensitiveDirectory);
                return Err(Error::PathNotAllowed(format!(
                    "Path is in sensitive directory: {:?}",
                    resolved
                )));
            }
        }

        Ok(())
    }

    /// Canonicalize the contained path and enforce containment a second time so
    /// junctions/symlinks inside a root cannot escape it.
    ///
    /// Fail-closed semantics: a root that exists but cannot be canonicalized is
    /// not a verifiable containment anchor and fails the validation; the
    /// ancestor walk only tolerates `NotFound` (missing components) — any other
    /// ancestor error fails, and exhausting the walk without a resolvable
    /// ancestor fails too. ENOENT (new file) is tolerated by canonicalizing the
    /// deepest existing *ancestor* instead, so an intermediate junction is still
    /// caught. The synthetic-root skip remains available only when *every* root
    /// canonicalizes with `NotFound` (not on disk at all, e.g. pure-text test
    /// registries) — there is no realpath structure to verify and the textual
    /// containment above already held.
    fn recontain_via_realpath(&self, resolved: &Path) -> Result<PathBuf> {
        // Compare realpaths against canonicalized roots: on Windows `canonicalize`
        // returns verbatim `\\?\` paths and resolves 8.3 short names, so the raw
        // registered roots cannot be prefix-matched against the canonical target.
        let mut canonical_roots: Vec<PathBuf> = Vec::new();
        for root in &self.allowed_roots {
            match fs::canonicalize(root) {
                Ok(canonical) => canonical_roots.push(strip_verbatim_prefix(&canonical)),
                // Root not on disk: nothing can be verified against it here.
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                // Fail closed: an existing root that cannot be canonicalized
                // (ACL, reparse anomaly, ...) must not disable re-containment.
                Err(err) => return Err(Error::Io(err)),
            }
        }
        if canonical_roots.is_empty() {
            // No root exists on disk (synthetic registry): fall back to the
            // textual containment that already held above.
            return Ok(resolved.to_path_buf());
        }

        match fs::canonicalize(resolved) {
            Ok(canonical) => {
                let canonical = strip_verbatim_prefix(&canonical);
                if !canonical_roots.iter().any(|root| canonical.starts_with(root)) {
                    return Err(Error::PathEscape(format!(
                        "Realpath escapes the allowed roots: {:?} -> {:?}",
                        resolved, canonical
                    )));
                }
                Ok(canonical)
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                // New file: the leaf does not exist yet, but an intermediate
                // junction/symlink may exist and must not reroute the tree.
                for ancestor in resolved.ancestors().skip(1) {
                    match fs::canonicalize(ancestor) {
                        Ok(canonical) => {
                            let canonical = strip_verbatim_prefix(&canonical);
                            if !canonical_roots.iter().any(|root| canonical.starts_with(root)) {
                                return Err(Error::PathEscape(format!(
                                    "Realpath escapes the allowed roots: {:?} -> {:?}",
                                    ancestor, canonical
                                )));
                            }
                            return Ok(resolved.to_path_buf());
                        }
                        // Missing ancestor (above the first missing component):
                        // keep walking toward the root.
                        Err(anc_err) if anc_err.kind() == std::io::ErrorKind::NotFound => continue,
                        // Fail closed: an unresolvable ancestor cannot be
                        // verified as contained.
                        Err(anc_err) => return Err(Error::Io(anc_err)),
                    }
                }
                // Walk exhausted without a resolvable ancestor (e.g. the path
                // sits under a root that is not on disk at all): containment is
                // unverifiable, so treat it as an escape risk.
                Err(Error::PathEscape(format!(
                    "Realpath chain unresolvable; cannot verify containment: {:?}",
                    resolved
                )))
            }
            Err(err) => Err(Error::Io(err)),
        }
    }

    fn resolve_against_roots(&self, project_id: ProjectId, path: &Path) -> Result<(PathBuf, PathBuf)> {
        // If path is already absolute and within a root, use it directly.
        // `Path::starts_with` is component-wise, so `C:\ws2` is never "within"
        // `C:\ws` (separator-boundary safe without string prefix tricks).
        if path.is_absolute() {
            for root in &self.allowed_roots {
                if path.starts_with(root) {
                    return Ok((path.to_path_buf(), root.clone()));
                }
            }
            return Err(Error::PathNotAllowed(format!(
                "Absolute path not within allowed roots: {:?}",
                path
            )));
        }

        // Try resolving against each allowed root
        for root in &self.allowed_roots {
            let joined = root.join(path);
            if joined.starts_with(root) {
                return Ok((joined, root.clone()));
            }
        }

        Err(Error::PathNotAllowed(format!(
            "Path not within any allowed root for project {}: {:?}",
            project_id, path
        )))
    }
}

impl Default for PathValidator {
    fn default() -> Self {
        Self::new()
    }
}

/// Split a path string into non-empty components paired with their byte offset
/// in the raw string, on both separators.
///
/// Deliberately string-based: Windows `Path` component parsing silently trims
/// trailing dots/spaces, which would hide `file.` / `NUL.` from the rejection
/// checks that must run before normalization.
fn split_path_components(raw: &str) -> Vec<(usize, &str)> {
    let mut out = Vec::new();
    let mut pos = 0usize;
    for segment in raw.split(['/', '\\']) {
        if !segment.is_empty() {
            out.push((pos, segment));
        }
        pos += segment.len() + 1;
    }
    out
}

/// `C:` and only `C:` at the very beginning of the path string: a drive prefix
/// is exactly an ASCII letter plus a colon at byte offset 0 — the split offset
/// anchors the exemption, so `/c:` (offset 1) and `\\c:` are rejected like any
/// other stray colon. Anything else — `file.txt:stream`, `C:data\evil` (drive-
/// relative), `C:\ws\C:\evil` — is an NTFS alternate data stream or a stray
/// drive reference and is rejected. Verbatim `\\?\C:` never reaches here because
/// `\\`-headed paths are rejected as device/UNC paths earlier.
fn is_drive_prefix_component(component: &str) -> bool {
    let bytes = component.as_bytes();
    bytes.len() == 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':'
}

/// Case-insensitive match against the reserved DOS device names, including the
/// `CON.txt` extension form, i.e. `^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(\..+)?$`.
fn is_windows_device_component(component: &str) -> bool {
    let upper = component.to_ascii_uppercase();
    if WINDOWS_DEVICE_NAMES.contains(&upper.as_str()) {
        return true;
    }
    match upper.split_once('.') {
        Some((stem, ext)) => !ext.is_empty() && WINDOWS_DEVICE_NAMES.contains(&stem),
        None => false,
    }
}

/// Normalize a Windows path string.
///
/// "/c/tmp/x" -> "C:\tmp\x"; "C:" -> "C:\"; lowercases→capitalizes drive letter;
/// forward slashes → backslashes; collapses `\\` runs (outside a leading UNC
/// head, which is preserved as `\\server\share`). A `\\?\` verbatim head is
/// returned untouched.
#[cfg(windows)]
pub fn normalize_windows_path(input: &str) -> String {
    let chars: Vec<char> = input.chars().collect();
    let mut out = String::with_capacity(input.len() + 1);
    let mut i = 0usize;

    // Verbatim / device namespace heads pass through unchanged.
    if chars.len() >= 4
        && ((chars[0] == '\\' && chars[1] == '\\' && (chars[2] == '.' || chars[2] == '?') && chars[3] == '\\'))
    {
        return input.to_string();
    }

    // Preserve UNC heads: `\\server\share` (also spelled `//server/share`).
    if chars.len() >= 2
        && ((chars[0] == '\\' && chars[1] == '\\') || (chars[0] == '/' && chars[1] == '/'))
    {
        out.push_str("\\\\");
        i = 2;
        while i < chars.len() {
            let c = chars[i];
            if c == '/' || c == '\\' {
                if !out.ends_with('\\') {
                    out.push('\\');
                }
            } else {
                out.push(c);
            }
            i += 1;
        }
        return out;
    }

    // `/c/tmp/x` (also `/c\tmp\x`, `/c`) is the slash-drive spelling of `C:\...`.
    if chars.len() >= 2
        && chars[0] == '/'
        && chars[1].is_ascii_alphabetic()
        && (chars.len() == 2 || chars[2] == '/' || chars[2] == '\\')
    {
        out.push(chars[1].to_ascii_uppercase());
        out.push(':');
        out.push('\\');
        i = if chars.len() > 2 { 3 } else { 2 };
    } else if chars.len() >= 2 && chars[0].is_ascii_alphabetic() && chars[1] == ':' {
        // Drive-letter form: capitalize; a bare `C:` gains its root separator.
        out.push(chars[0].to_ascii_uppercase());
        out.push(':');
        i = 2;
        if i == chars.len() {
            out.push('\\'); // "C:" -> "C:\"
        } else if chars[i] == '/' || chars[i] == '\\' {
            out.push('\\');
            i += 1;
        }
        // `C:name` (drive-relative) is left intact; the colon check rejects it.
    } else if !chars.is_empty() && (chars[0] == '/' || chars[0] == '\\') {
        // Rooted without a drive keeps its root separator.
        out.push('\\');
        i = 1;
    }

    // Body: separators become `\`, runs collapse to one.
    while i < chars.len() {
        let c = chars[i];
        if c == '/' || c == '\\' {
            if !out.ends_with('\\') {
                out.push('\\');
            }
        } else {
            out.push(c);
        }
        i += 1;
    }
    out
}

/// Normalize a path — resolve `.` and `..` components, handle separators.
///
/// Unlike the historical version this retains `Component::Prefix` and
/// `Component::RootDir`, so absolute inputs stay absolute (dropping the drive
/// prefix silently turned `C:\ws\sub` into the relative `ws\sub`). Leading `..`
/// components that climb above an *unanchored* path are preserved so the
/// traversal check can see them; an anchored path (drive/root present) cannot
/// climb above its root, so excess `..` there is a no-op, matching Win32.
fn normalize_path(path: &Path) -> PathBuf {
    enum Piece {
        Normal(OsString),
        Parent,
    }

    let mut result = PathBuf::new();
    let mut stack: Vec<Piece> = Vec::new();
    let mut anchored = false;

    for component in path.components() {
        match component {
            Component::Prefix(prefix) => {
                result.push(prefix.as_os_str());
                anchored = true;
            }
            Component::RootDir => {
                result.push(component.as_os_str());
                anchored = true;
            }
            Component::CurDir => { /* skip */ }
            Component::Normal(c) => stack.push(Piece::Normal(c.to_os_string())),
            Component::ParentDir => match stack.last() {
                Some(Piece::Normal(_)) => {
                    stack.pop();
                }
                Some(Piece::Parent) => {
                    if !anchored {
                        stack.push(Piece::Parent);
                    }
                }
                None => {
                    if !anchored {
                        // Escapes above the base stay visible for the traversal check.
                        stack.push(Piece::Parent);
                    }
                    // Anchored: e.g. `C:\..` is `C:\` on Windows; drop the excess.
                }
            },
        }
    }

    for piece in stack {
        match piece {
            Piece::Normal(c) => result.push(c),
            Piece::Parent => result.push(".."),
        }
    }
    result
}

/// Collapse MUP/verbatim drive prefixes (`\\?\C:\x` -> `C:\x`) on the canonical
/// paths produced by `fs::canonicalize` on Windows, so containment and deny
/// checks written against plain paths keep matching. `\\?\UNC\...` forms are
/// kept verbatim (they still escape drive-relative misreading). Non-UTF-8 paths
/// are returned untouched.
fn strip_verbatim_prefix(path: &Path) -> PathBuf {
    if let Some(text) = path.to_str() {
        if let Some(rest) = text.strip_prefix(r"\\?\") {
            let bytes = rest.as_bytes();
            if bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
                return PathBuf::from(rest);
            }
        }
    }
    path.to_path_buf()
}

/// Check if a path component is valid (no special characters, not reserved)
pub fn is_valid_component(component: &str) -> bool {
    if component.is_empty() || component == "." || component == ".." {
        return false;
    }
    if component.contains('\0') {
        return false;
    }
    // Windows reserved names
    #[cfg(windows)]
    {
        let upper = component.to_uppercase();
        if WINDOWS_DEVICE_NAMES.iter().any(|&d| upper == d) {
            return false;
        }
    }
    true
}

/// Check path safety without requiring a project (for validation only)
pub fn check_path_safety(user_path: &Path, allowed_roots: &[PathBuf]) -> PathValidationResult {
    let mut violations = Vec::new();
    let mut resolved_path = None;

    // Null byte check
    if user_path.to_string_lossy().contains('\0') {
        violations.push(PathViolation::NullByte);
    }

    // UNC path check (string-based: a `\\server\share` head parses as a Prefix,
    // so component-wise `starts_with` would miss it)
    if user_path.to_string_lossy().starts_with("\\\\") || user_path.to_string_lossy().starts_with("//") {
        violations.push(PathViolation::UncPath);
    }

    // Path traversal check
    let normalized = normalize_path(user_path);
    if normalized.starts_with("..") {
        violations.push(PathViolation::PathTraversal);
    }

    // Check containment
    for root in allowed_roots {
        let joined = root.join(&normalized);
        if joined.starts_with(root) {
            resolved_path = Some(joined);
            break;
        }
    }

    if resolved_path.is_none() {
        violations.push(PathViolation::OutsideAllowedRoot);
    }

    let relative_path = resolved_path.as_ref().and_then(|p| {
        allowed_roots.iter().find_map(|root| p.strip_prefix(root).ok().map(|r| r.to_path_buf()))
    });
    PathValidationResult {
        valid: violations.is_empty() && resolved_path.is_some(),
        resolved_path,
        relative_path,
        violations,
    }
}

/// Collapse `.`/`..` and report whether the result still climbs above its base
/// (shared with `operations::comprehensive_path_check`).
pub(crate) fn contains_traversal(path: &Path) -> bool {
    let normalized = normalize_path(path);
    let s = normalized.to_string_lossy();
    s.starts_with("..") || s.contains("/..") || s.contains("\\..")
}

/// Component-wise prefix test, case-insensitive on Windows (NTFS/FAT are
/// case-insensitive, so a mis-cased deny/read-only registration must not
/// escape its restriction). Exact on platforms with case-sensitive filesystems.
#[cfg(windows)]
fn starts_with_folded(path: &Path, prefix: &Path) -> bool {
    let mut path_components = path.components();
    let mut prefix_components = prefix.components();
    loop {
        match (path_components.next(), prefix_components.next()) {
            (Some(p), Some(q)) => {
                if !p
                    .as_os_str()
                    .to_string_lossy()
                    .eq_ignore_ascii_case(&q.as_os_str().to_string_lossy())
                {
                    return false;
                }
            }
            (Some(_), None) => return true,
            (None, _) => return false,
        }
    }
}

#[cfg(not(windows))]
fn starts_with_folded(path: &Path, prefix: &Path) -> bool {
    path.starts_with(prefix)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_path_traversal_detection() {
        let validator = PathValidator::new().with_root(PathBuf::from("/workspace"));
        let result = validator.validate(
            ProjectId::new(),
            Path::new("../../../etc/passwd"),
        );
        assert!(result.is_err());
        match result.err().unwrap() {
            Error::PathEscape(_) => {},
            _ => panic!("Expected PathEscape error"),
        }
    }

    #[test]
    fn test_valid_path() {
        let validator = PathValidator::new().with_root(PathBuf::from("/workspace"));
        let result = validator.validate(
            ProjectId::new(),
            Path::new("src/main.rs"),
        );
        assert!(result.is_ok());
        let contained = result.unwrap();
        assert!(contained.absolute_path.ends_with("src/main.rs"));
    }

    #[test]
    fn test_null_byte_rejection() {
        let validator = PathValidator::new().with_root(PathBuf::from("/workspace"));
        let result = validator.validate(
            ProjectId::new(),
            Path::new("src\0/main.rs"),
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_unc_path_rejection() {
        let validator = PathValidator::new().with_root(PathBuf::from("/workspace"));
        let result = validator.validate(
            ProjectId::new(),
            Path::new("\\\\server\\share\\file.txt"),
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_check_path_safety_valid() {
        let roots = vec![PathBuf::from("/workspace")];
        let result = check_path_safety(Path::new("src/main.rs"), &roots);
        assert!(result.valid);
        assert!(result.resolved_path.is_some());
    }

    #[test]
    fn test_check_path_safety_traversal() {
        let roots = vec![PathBuf::from("/workspace")];
        let result = check_path_safety(Path::new("../../../etc/passwd"), &roots);
        assert!(!result.valid);
        assert!(result.violations.contains(&PathViolation::PathTraversal));
    }

    #[test]
    fn test_is_valid_component() {
        assert!(is_valid_component("main.rs"));
        assert!(!is_valid_component(".."));
        assert!(!is_valid_component("."));
        assert!(!is_valid_component(""));
        #[cfg(windows)]
        assert!(!is_valid_component("CON"));
        #[cfg(windows)]
        assert!(!is_valid_component("NUL"));
    }

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

    /// Build the git-bash-style slash-drive spelling of an absolute Windows path:
    /// `C:\a\b` -> `/c/a/b`.
    #[cfg(windows)]
    fn to_slash_drive_form(p: &Path) -> String {
        let text = p.to_string_lossy().replace('/', "\\");
        let drive = text.chars().next().unwrap_or_default().to_ascii_lowercase();
        let rest = text.chars().skip(2).collect::<String>(); // drop `X:`
        let rest = rest.replacen('\\', "/", 1); // `\Users\...` -> `/Users/...`
        format!("/{}{}", drive, rest)
    }

    #[cfg(windows)]
    #[test]
    fn validate_converts_slash_drive_paths() {
        let tmp = std::env::temp_dir();
        let v = PathValidator::new().with_root(tmp.clone());
        // "/c/Users/..." spelling must resolve to the same drive root.
        // (Deviation from the brief's literal `format!("/{}/foo.txt", drive_char)`,
        // which yields "/c/foo.txt" — a path that can never live inside the temp
        // root. The test's own comment pins the intent: the full slash-drive
        // spelling of the registered root.)
        let slash_form = format!("{}/foo.txt", to_slash_drive_form(&tmp));
        let r = v.validate_access(ProjectId::new(), Path::new(&slash_form), AccessMode::Read);
        assert!(r.is_ok(), "slash-drive form should validate: {slash_form}");
    }

    /// Create a directory junction (NTFS mount-point reparse point). Junctions
    /// need no special privilege — exactly the mechanism unprivileged malware
    /// uses — so tests can exercise the realpath re-containment deterministically.
    #[cfg(windows)]
    fn create_junction(target: &Path, link: &Path) -> std::io::Result<()> {
        use std::ffi::OsStr;
        use std::os::windows::ffi::OsStrExt;
        use std::{io, ptr};
        use windows_sys::Win32::Foundation::{CloseHandle, GENERIC_READ, GENERIC_WRITE, INVALID_HANDLE_VALUE};
        use windows_sys::Win32::Storage::FileSystem::{
            CreateFileW, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
            FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
        };
        use windows_sys::Win32::System::Ioctl::FSCTL_SET_REPARSE_POINT;
        use windows_sys::Win32::System::IO::DeviceIoControl;

        let mut link_wide: Vec<u16> = OsStr::new(link).encode_wide().collect();
        link_wide.push(0);

        let handle = unsafe {
            CreateFileW(
                link_wide.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
                ptr::null_mut(),
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }

        // REPARSE_DATA_BUFFER (mount point):
        //   tag u32 | data_len u16 | reserved u16 |
        //   SubstituteNameOffset u16 | SubstituteNameLength u16 |
        //   PrintNameOffset u16 | PrintNameLength u16 | PathBuffer[...]
        let subst_text = format!(r"\??\{}", target.display());
        let subst: Vec<u16> = OsStr::new(subst_text.as_str()).encode_wide().chain(Some(0)).collect();
        let path_buffer_len_bytes = (subst.len() + 1) * 2; // substitute name (NUL ended) + empty print name (NUL)

        let mut buffer: Vec<u8> = Vec::new();
        buffer.extend_from_slice(&windows_sys::Win32::System::SystemServices::IO_REPARSE_TAG_MOUNT_POINT.to_le_bytes());
        buffer.extend_from_slice(&((path_buffer_len_bytes + 8) as u16).to_le_bytes()); // ReparseDataLength
        buffer.extend_from_slice(&0u16.to_le_bytes()); // Reserved
        buffer.extend_from_slice(&0u16.to_le_bytes()); // SubstituteNameOffset
        buffer.extend_from_slice(&((subst.len() as u16 - 1) * 2).to_le_bytes()); // SubstituteNameLength
        buffer.extend_from_slice(&((subst.len() as u16) * 2).to_le_bytes()); // PrintNameOffset
        buffer.extend_from_slice(&0u16.to_le_bytes()); // PrintNameLength (empty)
        for wide in subst.iter().copied().chain(std::iter::once(0)) {
            buffer.extend_from_slice(&wide.to_le_bytes());
        }

        let mut returned: u32 = 0;
        let ok = unsafe {
            DeviceIoControl(
                handle,
                FSCTL_SET_REPARSE_POINT,
                buffer.as_ptr() as *const std::ffi::c_void,
                buffer.len() as u32,
                ptr::null_mut(),
                0,
                &mut returned,
                ptr::null_mut(),
            )
        };
        unsafe { CloseHandle(handle) };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    #[cfg(windows)]
    #[test]
    fn validate_rejects_junction_escape_at_call_time() {
        let tmp = tempfile::TempDir::new().unwrap();
        let outside = tempfile::TempDir::new().unwrap();
        let root = tmp.path().join("ws");
        std::fs::create_dir_all(root.join("link")).unwrap();
        // Deviation from the brief: `std::os::windows::fs::junction` is not
        // stabilized in this toolchain (rustc 1.99.1), so the test creates the
        // junction directly through FSCTL_SET_REPARSE_POINT — privilege-free,
        // like an unprivileged junction escape attempt would be.
        if let Err(err) = create_junction(outside.path(), &root.join("link")) {
            panic!("junction creation failed (unexpected on NTFS): {err}");
        }
        let v = PathValidator::new().with_root(root.clone());
        let err = v.validate(ProjectId::new(), Path::new("link/secret.txt")).unwrap_err();
        assert!(matches!(err, Error::PathEscape(_)));
    }

    #[test]
    fn validate_access_realpath_recontainment_positive_paths() {
        // Positive control: re-containment must not fail-closed for plain
        // inside-root paths, both for an existing leaf (canonicalize success)
        // and for a new leaf whose parent chain resolves inside the roots.
        let tmp = tempfile::TempDir::new().unwrap();
        let root = tmp.path().join("ws");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("exists.txt"), b"payload").unwrap();
        let v = PathValidator::new().with_root(root.clone());

        let existing = v
            .validate_access(ProjectId::new(), Path::new("exists.txt"), AccessMode::Read)
            .expect("existing inside-root file must validate");
        assert_eq!(
            std::fs::read(&existing.absolute_path).unwrap(),
            b"payload",
            "canonical path must still point at the same real file"
        );

        let new_file = v
            .validate_access(ProjectId::new(), Path::new("newdir/new.txt"), AccessMode::Write)
            .expect("new file in an inside-root existing directory chain must validate");
        assert_eq!(new_file.relative_path, PathBuf::from("newdir").join("new.txt"));
    }

    #[cfg(windows)]
    #[test]
    fn normalize_windows_path_forms() {
        assert_eq!(normalize_windows_path("/c/tmp/x"), "C:\\tmp\\x");
        assert_eq!(normalize_windows_path("C:"), "C:\\");
        assert_eq!(normalize_windows_path("c:\\a\\b"), "C:\\a\\b");
        assert_eq!(normalize_windows_path("\\\\server\\share\\f"), "\\\\server\\share\\f");
        assert_eq!(normalize_windows_path("/Users/x"), "\\Users\\x");
    }

    #[test]
    fn validate_rejects_colon_not_at_string_start() {
        let v = PathValidator::new().with_root(PathBuf::from("C:\\ws"));
        // "/c:" parses as a drive prefix when the exemption is keyed on split
        // index; it must be rejected at the ADS colon layer (message marker
        // "stream"), anchored at string position 0, not by a downstream
        // containment miss.
        for input in ["/c:", "/c:/steal"] {
            let err = v.validate(ProjectId::new(), Path::new(input)).unwrap_err();
            assert!(
                err.to_string().contains("stream"),
                "colon check must reject {input:?} at the ADS layer, got: {err}"
            );
        }
    }

    #[test]
    fn read_only_root_enforced_regardless_of_casing() {
        #[cfg(windows)]
        {
            let tmp = tempfile::TempDir::new().unwrap();
            let vend = tmp.path().join("vendor");
            std::fs::create_dir_all(&vend).unwrap();
            // Mis-cased read-only registration: case-insensitive NTFS must still
            // refuse Write/Move through the lower-cased spelling.
            let upper = tmp.path().to_string_lossy().to_uppercase();
            let v = PathValidator::new()
                .with_root(tmp.path().to_path_buf())
                .with_read_only_root(PathBuf::from(format!("{}\\VENDOR", upper)));
            let read = v.validate_access(ProjectId::new(), Path::new("vendor/x.txt"), AccessMode::Read);
            assert!(read.is_ok(), "reads inside a read-only root are allowed: {read:?}");
            let err = v
                .validate_access(ProjectId::new(), Path::new("vendor/x.txt"), AccessMode::Write)
                .unwrap_err();
            assert!(
                err.to_string().contains("read-only"),
                "mis-cased read-only registration must still refuse writes: {err}"
            );
        }
    }

    #[cfg(windows)]
    #[test]
    fn root_canonicalize_error_fails_closed() {
        // Hole (c): a root that exists on disk but cannot be canonicalized —
        // here a reparse-point cycle (os error 1921, FilesystemLoop) — must fail
        // closed instead of silently disabling re-containment.
        let tmp = tempfile::TempDir::new().unwrap();
        let a = tmp.path().join("loopA");
        let b = tmp.path().join("loopB");
        std::fs::create_dir_all(&a).unwrap();
        std::fs::create_dir_all(&b).unwrap();
        create_junction(&b, &a).unwrap(); // a -> b
        create_junction(&a, &b).unwrap(); // b -> a  => cycle
        let v = PathValidator::new().with_root(a);
        let result = v.validate(ProjectId::new(), Path::new("x.txt"));
        assert!(
            matches!(result, Err(Error::Io(_))),
            "uncanonicalizable root must fail closed, got {result:?}"
        );
    }

    #[cfg(windows)]
    #[test]
    fn unresolvable_realpath_chain_fails_closed() {
        // Hole (b): the ancestor walk must never silently pass when every
        // ancestor fails. A path under a registered-but-nonexistent root on a
        // missing volume resolves textually, yet every ancestor canonicalize
        // fails NotFound, exhausting the walk → Err.
        let tmp = tempfile::TempDir::new().unwrap();
        let v = PathValidator::new()
            .with_root(tmp.path().to_path_buf())
            .with_root(PathBuf::from("Q:\\synthetic-root"));
        let result = v.validate_access(
            ProjectId::new(),
            Path::new("Q:\\synthetic-root\\x.txt"),
            AccessMode::Read,
        );
        assert!(
            matches!(result, Err(Error::PathEscape(_)) | Err(Error::Io(_))),
            "exhausted/unresolvable realpath chain must fail closed, got {result:?}"
        );
    }

    #[cfg(windows)]
    #[test]
    fn reparse_cycle_path_fails_closed_at_every_depth() {
        // Hole (a) per review fallback ("or use a path with a reparse point
        // cycle"): an unopenable reparse route inside the root is an Err at any
        // depth. With std::fs::canonicalize the cycle error surfaces at the
        // top-level call (probe: error 1921 at all depths); the walk-local
        // non-NotFound arm this guards alongside it is defense-in-depth — see
        // task report for the reachability analysis.
        let tmp = tempfile::TempDir::new().unwrap();
        let a = tmp.path().join("loopA");
        let b = tmp.path().join("loopB");
        std::fs::create_dir_all(&a).unwrap();
        std::fs::create_dir_all(&b).unwrap();
        create_junction(&b, &a).unwrap();
        create_junction(&a, &b).unwrap();
        let v = PathValidator::new().with_root(tmp.path().to_path_buf());
        let shallow = v.validate_access(ProjectId::new(), Path::new("loopA"), AccessMode::Read);
        assert!(matches!(shallow, Err(Error::Io(_))), "cycle at leaf depth must fail closed, got {shallow:?}");
        let deep = v.validate_access(ProjectId::new(), Path::new("loopA\\deep\\x.txt"), AccessMode::Read);
        assert!(matches!(deep, Err(Error::Io(_))), "cycle under a missing leaf must fail closed, got {deep:?}");
    }
}
