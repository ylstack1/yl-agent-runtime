//! Workspace operations - batch and composite operations
//!
//! Higher-level operations built on top of the basic workspace service.

use crate::path_safety::PathValidator;
use runtime_core::error::{Error, Result};
use runtime_core::types::*;
use std::path::{Path, PathBuf};

/// Batch file operation result
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BatchOperationResult {
    pub operation: String,
    pub path: PathBuf,
    pub success: bool,
    pub error: Option<String>,
}

/// Batch file operations
pub struct BatchOperations<'a> {
    validator: &'a PathValidator,
    project_id: ProjectId,
}

impl<'a> BatchOperations<'a> {
    pub fn new(validator: &'a PathValidator, project_id: ProjectId) -> Self {
        Self {
            validator,
            project_id,
        }
    }

    /// Validate multiple paths at once
    pub fn validate_batch(&self, paths: &[PathBuf]) -> Result<Vec<super::path_safety::ContainedPath>> {
        let mut results = Vec::new();
        for path in paths {
            let contained = self.validator.validate(self.project_id, path)?;
            results.push(contained);
        }
        Ok(results)
    }

    /// Check if all paths are within allowed roots
    pub fn all_within_roots(&self, paths: &[PathBuf]) -> bool {
        paths.iter().all(|p| {
            self.validator.is_within_roots(p)
        })
    }
}

/// File watcher for workspace changes
pub struct WorkspaceWatcher {
    project_id: ProjectId,
    watch_paths: Vec<PathBuf>,
}

impl WorkspaceWatcher {
    pub fn new(project_id: ProjectId) -> Self {
        Self {
            project_id,
            watch_paths: Vec::new(),
        }
    }

    pub fn add_watch_path(&mut self, path: PathBuf) {
        self.watch_paths.push(path);
    }

    pub fn watch_paths(&self) -> &[PathBuf] {
        &self.watch_paths
    }
}

/// Change event from workspace watcher
#[derive(Debug, Clone)]
pub struct WorkspaceChangeEvent {
    pub project_id: ProjectId,
    pub path: PathBuf,
    pub event_type: ChangeEventType,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChangeEventType {
    Created,
    Modified,
    Deleted,
    Renamed,
}

/// Workspace operation context for tracking changes
#[derive(Debug, Clone)]
pub struct OperationContext {
    pub project_id: ProjectId,
    pub session_id: SessionId,
    pub agent_id: AgentId,
    pub operation: String,
    pub timestamp: DateTime<Utc>,
}

impl OperationContext {
    pub fn new(
        project_id: ProjectId,
        session_id: SessionId,
        agent_id: AgentId,
        operation: String,
    ) -> Self {
        Self {
            project_id,
            session_id,
            agent_id,
            operation,
            timestamp: chrono::Utc::now(),
        }
    }
}

/// Validate that a path doesn't contain Windows device names
pub fn validate_no_device_names(path: &Path) -> Result<()> {
    #[cfg(windows)]
    {
        if let Some(file_name) = path.file_name().and_then(|n| n.to_str()) {
            let upper = file_name.to_uppercase();
            let device_names = [
                "CON", "PRN", "AUX", "NUL",
                "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
                "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
            ];
            if device_names.iter().any(|&d| upper == d) {
                return Err(Error::PathNotAllowed(format!(
                    "Windows device name not allowed: {}",
                    file_name
                )));
            }
        }
    }
    Ok(())
}

/// Validate that a path is not a UNC path
pub fn validate_no_unc(path: &Path) -> Result<()> {
    // String-based: `Path::starts_with` compares components, which silently
    // misses `\\server\share` heads on Windows (they parse as a Prefix).
    let raw = path.to_string_lossy();
    if raw.starts_with("\\\\") || raw.starts_with("//") {
        return Err(Error::PathNotAllowed("UNC paths not allowed".to_string()));
    }
    Ok(())
}

/// Validate that a path doesn't use alternate data streams
pub fn validate_no_ads(path: &Path) -> Result<()> {
    #[cfg(windows)]
    {
        if path.to_string_lossy().contains(":$") {
            return Err(Error::PathNotAllowed("Alternate data streams not allowed".to_string()));
        }
    }
    Ok(())
}

/// Comprehensive path safety check combining all validations
pub fn comprehensive_path_check(
    path: &Path,
    allowed_roots: &[PathBuf],
) -> Result<PathBuf> {
    validate_no_device_names(path)?;
    validate_no_unc(path)?;
    validate_no_ads(path)?;

    // Refuse `..` climbs that escape above the base after normalization.
    if crate::path_safety::contains_traversal(path) {
        return Err(Error::PathEscape(format!("Path traversal detected: {:?}", path)));
    }

    // Check containment
    for root in allowed_roots {
        let joined = root.join(path);
        if joined.starts_with(root) {
            return Ok(joined);
        }
    }

    Err(Error::PathNotAllowed(format!(
        "Path not within any allowed root: {:?}",
        path
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_comprehensive_path_check_valid() {
        let roots = vec![PathBuf::from("/workspace")];
        let result = comprehensive_path_check(Path::new("src/main.rs"), &roots);
        assert!(result.is_ok());
    }

    #[test]
    fn test_comprehensive_path_check_traversal() {
        let roots = vec![PathBuf::from("/workspace")];
        let result = comprehensive_path_check(Path::new("../../../etc/passwd"), &roots);
        assert!(result.is_err());
    }

    #[test]
    fn test_comprehensive_path_check_unc() {
        let roots = vec![PathBuf::from("/workspace")];
        let result = comprehensive_path_check(Path::new("\\\\server\\share"), &roots);
        assert!(result.is_err());
    }

    #[test]
    #[cfg(windows)]
    fn test_comprehensive_path_check_device_name() {
        let roots = vec![PathBuf::from("C:\\workspace")];
        let result = comprehensive_path_check(Path::new("CON"), &roots);
        assert!(result.is_err());
    }
}