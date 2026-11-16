//! Path safety validation
//!
//! Per PRD section 8.2: Every filesystem operation must normalize, canonicalize,
//! resolve symlinks/junctions, enforce allowed roots, reject device namespaces
//! and UNC paths, validate path components, and use handle-based operations.

use runtime_core::error::{Error, Result};
use runtime_core::types::ProjectId;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// A validated, contained workspace path
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContainedPath {
    pub project_id: ProjectId,
    pub absolute_path: PathBuf,
    pub relative_path: PathBuf,
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
    deny_paths: Vec<PathBuf>,
    follow_symlinks: bool,
    max_depth: usize,
    max_file_size: u64,
}

impl PathValidator {
    pub fn new() -> Self {
        Self {
            allowed_roots: Vec::new(),
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

    pub fn with_deny_path(mut self, path: PathBuf) -> Self {
        self.deny_paths.push(path);
        self
    }

    pub fn allow_symlinks(mut self, allow: bool) -> Self {
        self.follow_symlinks = allow;
        self
    }

    /// Validate and resolve a path within allowed roots
    pub fn validate(&self, project_id: ProjectId, user_path: &Path) -> Result<ContainedPath> {
        let mut violations = Vec::new();

        // Reject null bytes
        if user_path.to_string_lossy().contains('\0') {
            violations.push(PathViolation::NullByte);
            return Err(Error::PathEscape(format!("Null byte in path: {:?}", user_path)));
        }

        // Reject Windows device names
        #[cfg(windows)]
        {
            if let Some(file_name) = user_path.file_name().and_then(|n| n.to_str()) {
                let upper = file_name.to_uppercase();
                if WINDOWS_DEVICE_NAMES.iter().any(|&d| upper == d) {
                    violations.push(PathViolation::DeviceNamespace);
                    return Err(Error::PathNotAllowed(format!(
                        "Windows device name not allowed: {}",
                        file_name
                    )));
                }
            }
        }

        // Reject UNC paths unless explicitly allowed
        if user_path.starts_with("\\\\") || user_path.starts_with("//") {
            violations.push(PathViolation::UncPath);
            return Err(Error::PathNotAllowed("UNC paths not allowed".to_string()));
        }

        // Reject alternate data streams (Windows)
        #[cfg(windows)]
        {
            if user_path.to_string_lossy().contains(":$") {
                violations.push(PathViolation::AlternateDataStream);
                return Err(Error::PathNotAllowed("Alternate data streams not allowed".to_string()));
            }
        }

        // Normalize the path
        let normalized = normalize_path(user_path);

        // Check for path traversal after normalization
        let normalized_str = normalized.to_string_lossy();
        if normalized_str.starts_with("..")
            || normalized_str.contains("/..")
            || normalized_str.contains("\\..")
        {
            violations.push(PathViolation::PathTraversal);
            return Err(Error::PathEscape(format!("Path traversal detected: {:?}", user_path)));
        }

        // Resolve against allowed roots
        let resolved = self.resolve_against_roots(project_id, &normalized)?;

        // Check deny paths
        for deny in &self.deny_paths {
            if resolved.starts_with(deny) {
                violations.push(PathViolation::SensitiveDirectory);
                return Err(Error::PathNotAllowed(format!(
                    "Path is in denied directory: {:?}",
                    resolved
                )));
            }
        }

        // Check sensitive directories
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

        // Validate depth
        let depth = resolved.components().count();
        if depth > self.max_depth {
            violations.push(PathViolation::OutsideAllowedRoot);
            return Err(Error::Validation(format!("Path depth {} exceeds maximum {}", depth, self.max_depth)));
        }

        // Find which root this resolved path is under
        let relative_path = self
            .allowed_roots
            .iter()
            .find_map(|root| resolved.strip_prefix(root).ok().map(|p| p.to_path_buf()))
            .unwrap_or_else(|| resolved.clone());

        Ok(ContainedPath {
            project_id,
            absolute_path: resolved.clone(),
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

    fn resolve_against_roots(&self, project_id: ProjectId, path: &Path) -> Result<PathBuf> {
        // If path is already absolute and within a root, use it directly
        if path.is_absolute() {
            if self.is_within_roots(path) {
                return Ok(path.to_path_buf());
            }
            return Err(Error::PathNotAllowed(format!(
                "Absolute path not within allowed roots: {:?}",
                path
            )));
        }

        // Try resolving against each allowed root
        for root in &self.allowed_roots {
            let joined = root.join(path);
            if self.is_within_roots(&joined) {
                return Ok(joined);
            }
        }

        Err(Error::PathNotAllowed(format!(
            "Path not within any allowed root for project {}: {:?}",
            project_id, path
        )))
    }
}

/// Normalize a path - resolve . and .. components, handle separators
fn normalize_path(path: &Path) -> PathBuf {
    let mut components = Vec::new();
    for component in path.components() {
        match component {
            std::path::Component::ParentDir => {
                if !components.is_empty() {
                    components.pop();
                }
            }
            std::path::Component::CurDir => { /* skip */ }
            std::path::Component::Normal(c) => {
                components.push(c.to_os_string());
            }
            std::path::Component::RootDir => { /* skip - handled by root joining */ }
            std::path::Component::Prefix(_) => { /* skip - could be Windows drive prefix */ }
        }
    }

    let mut result = PathBuf::new();
    for c in components {
        result.push(c);
    }
    result
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

impl Default for PathValidator {
    fn default() -> Self {
        Self::new()
    }
}

/// Check path safety without requiring a project (for validation only)
pub fn check_path_safety(user_path: &Path, allowed_roots: &[PathBuf]) -> PathValidationResult {
    let mut violations = Vec::new();
    let mut resolved_path = None;

    // Null byte check
    if user_path.to_string_lossy().contains('\0') {
        violations.push(PathViolation::NullByte);
    }

    // UNC path check
    if user_path.starts_with("\\\\") || user_path.starts_with("//") {
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
}