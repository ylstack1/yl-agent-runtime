//! Workspace service implementation
//!
//! Safe project discovery and file operations per PRD section 10.

use crate::path_safety::{PathValidator, PathViolation};
use runtime_core::error::{Error, Result};
use runtime_core::traits::WorkspaceService;
use runtime_core::types::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::RwLock;

/// Registered workspace
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisteredWorkspace {
    pub id: ProjectId,
    pub root: PathBuf,
    pub profile: ExecutionProfile,
    pub registered_at: DateTime<Utc>,
    pub max_file_size: u64,
    pub deny_paths: Vec<PathBuf>,
}

/// Workspace service implementation
#[derive(Clone)]
pub struct WorkspaceServiceImpl {
    workspaces: Arc<RwLock<HashMap<ProjectId, RegisteredWorkspace>>>,
    validators: Arc<RwLock<HashMap<ProjectId, PathValidator>>>,
}

impl WorkspaceServiceImpl {
    pub fn new() -> Self {
        Self {
            workspaces: Arc::new(RwLock::new(HashMap::new())),
            validators: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn workspace_count(&self) -> usize {
        // Note: this is a sync method, would need async for real count
        0
    }
}

impl Default for WorkspaceServiceImpl {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl WorkspaceService for WorkspaceServiceImpl {
    async fn register(
        &self,
        root: PathBuf,
        profile: ExecutionProfile,
    ) -> Result<ProjectId> {
        let id = ProjectId::new();

        // Validate the root path exists and is a directory
        if !root.exists() {
            return Err(Error::Validation(format!(
                "Workspace root does not exist: {:?}",
                root
            )));
        }
        if !root.is_dir() {
            return Err(Error::Validation(format!(
                "Workspace root is not a directory: {:?}",
                root
            )));
        }

        let canonical = root.canonicalize().map_err(|e| {
            Error::Validation(format!("Cannot canonicalize workspace root: {}", e))
        })?;

        let workspace = RegisteredWorkspace {
            id,
            root: canonical.clone(),
            profile,
            registered_at: chrono::Utc::now(),
            max_file_size: 100_000_000, // 100 MB default
            deny_paths: Vec::new(),
        };

        let validator = PathValidator::new()
            .with_root(canonical)
            .allow_symlinks(false);

        self.workspaces.write().await.insert(id, workspace);
        self.validators.write().await.insert(id, validator);

        Ok(id)
    }

    async fn unregister(&self, project_id: ProjectId) -> Result<()> {
        let removed = self.workspaces.write().await.remove(&project_id).is_some();
        self.validators.write().await.remove(&project_id);
        if !removed {
            return Err(Error::WorkspaceNotFound(format!("Project {}", project_id)));
        }
        Ok(())
    }

    async fn list(
        &self,
        project_id: ProjectId,
        path: Option<PathBuf>,
    ) -> Result<Vec<FileEntry>> {
        let workspace = self.get_workspace(project_id)?;
        let validator = self.get_validator(project_id)?;

        let target_path = match path {
            Some(p) => {
                let contained = validator.validate(project_id, &p)?;
                contained.absolute_path
            }
            None => workspace.root.clone(),
        };

        if !target_path.exists() {
            return Err(Error::Validation(format!(
                "Path does not exist: {:?}",
                target_path
            )));
        }

        let mut entries = Vec::new();
        let mut dir_entries = std::fs::read_dir(&target_path)
            .map_err(|e| Error::Io(e))?;

        while let Some(entry) = dir_entries.next() {
            let entry = entry.map_err(|e| Error::Io(e))?;
            let path = entry.path();
            let metadata = entry.metadata().map_err(|e| Error::Io(e))?;

            let file_type = if metadata.is_dir() {
                FileType::Directory
            } else if path.is_symlink() {
                FileType::Symlink
            } else {
                FileType::File
            };

            entries.push(FileEntry {
                path,
                name: entry.file_name().to_string_lossy().to_string(),
                file_type,
                size: metadata.len(),
                modified: metadata.modified()
                    .unwrap_or_else(|_| std::time::SystemTime::UNIX_EPOCH)
                    .into(),
                created: metadata.created()
                    .unwrap_or_else(|_| std::time::SystemTime::UNIX_EPOCH)
                    .into(),
                permissions: FilePermissions {
                    readable: true,
                    writable: metadata.permissions().readonly() == false,
                    executable: false, // Would need platform-specific check
                },
                is_binary: detect_binary(&path),
            });
        }

        entries.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(entries)
    }

    async fn stat(&self, project_id: ProjectId, path: PathBuf) -> Result<FileEntry> {
        let workspace = self.get_workspace(project_id)?;
        let validator = self.get_validator(project_id)?;

        let contained = validator.validate(project_id, &path)?;
        let metadata = contained.absolute_path.metadata().map_err(|e| Error::Io(e))?;

        let file_type = if metadata.is_dir() {
            FileType::Directory
        } else if contained.absolute_path.is_symlink() {
            FileType::Symlink
        } else {
            FileType::File
        };

        Ok(FileEntry {
            path: contained.absolute_path,
            name: contained.relative_path.to_string_lossy().to_string(),
            file_type,
            size: metadata.len(),
            modified: metadata.modified()
                .unwrap_or_else(|_| std::time::SystemTime::UNIX_EPOCH)
                .into(),
            created: metadata.created()
                .unwrap_or_else(|_| std::time::SystemTime::UNIX_EPOCH)
                .into(),
            permissions: FilePermissions {
                readable: true,
                writable: metadata.permissions().readonly() == false,
                executable: false,
            },
            is_binary: detect_binary(&contained.absolute_path),
        })
    }

    async fn read_file(&self, project_id: ProjectId, path: PathBuf) -> Result<Vec<u8>> {
        let workspace = self.get_workspace(project_id)?;
        let validator = self.get_validator(project_id)?;

        let contained = validator.validate(project_id, &path)?;

        // Check file size limit
        let metadata = contained.absolute_path.metadata().map_err(|e| Error::Io(e))?;
        if metadata.len() > workspace.max_file_size {
            return Err(Error::Validation(format!(
                "File size {} exceeds maximum {}",
                metadata.len(),
                workspace.max_file_size
            )));
        }

        // Check if binary
        if detect_binary(&contained.absolute_path) {
            return Err(Error::Validation("File is binary, use read_range or specify binary handling".to_string()));
        }

        let content = std::fs::read(&contained.absolute_path).map_err(|e| Error::Io(e))?;
        Ok(content)
    }

    async fn read_range(
        &self,
        project_id: ProjectId,
        path: PathBuf,
        start: u64,
        end: u64,
    ) -> Result<Vec<u8>> {
        let workspace = self.get_workspace(project_id)?;
        let validator = self.get_validator(project_id)?;

        let contained = validator.validate(project_id, &path)?;

        let metadata = contained.absolute_path.metadata().map_err(|e| Error::Io(e))?;
        if start > metadata.len() {
            return Err(Error::Validation(format!(
                "Start offset {} exceeds file size {}",
                start, metadata.len()
            )));
        }

        let end = end.min(metadata.len());
        let range_size = end - start;

        use std::io::{Read, Seek, SeekFrom};
        let mut file = std::fs::File::open(&contained.absolute_path).map_err(|e| Error::Io(e))?;
        file.seek(SeekFrom::Start(start)).map_err(|e| Error::Io(e))?;

        let mut buffer = vec![0u8; range_size as usize];
        file.read_exact(&mut buffer).map_err(|e| Error::Io(e))?;

        Ok(buffer)
    }

    async fn write_file(
        &self,
        project_id: ProjectId,
        path: PathBuf,
        content: Vec<u8>,
    ) -> Result<()> {
        let workspace = self.get_workspace(project_id)?;
        let validator = self.get_validator(project_id)?;

        // Check size limit
        if content.len() as u64 > workspace.max_file_size {
            return Err(Error::Validation(format!(
                "Content size {} exceeds maximum {}",
                content.len(),
                workspace.max_file_size
            )));
        }

        let contained = validator.validate(project_id, &path)?;

        // Create parent directories if needed
        if let Some(parent) = contained.absolute_path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| Error::Io(e))?;
        }

        // Atomic write: write to temp file then rename
        let temp_path = contained.absolute_path.with_extension("tmp");
        {
            use std::io::Write;
            let mut file = std::fs::File::create(&temp_path).map_err(|e| Error::Io(e))?;
            file.write_all(&content).map_err(|e| Error::Io(e))?;
            file.sync_all().map_err(|e| Error::Io(e))?;
        }

        std::fs::rename(&temp_path, &contained.absolute_path).map_err(|e| Error::Io(e))?;

        Ok(())
    }

    async fn replace_text(
        &self,
        project_id: ProjectId,
        path: PathBuf,
        old_text: String,
        new_text: String,
    ) -> Result<()> {
        let content = self.read_file(project_id, path.clone()).await?;
        let content_str = String::from_utf8(content).map_err(|e| {
            Error::Validation(format!("File is not valid UTF-8: {}", e))
        })?;

        if !content_str.contains(&old_text) {
            return Err(Error::Validation("Old text not found in file".to_string()));
        }

        let new_content = content_str.replace(&old_text, &new_text);
        self.write_file(project_id, path, new_content.into_bytes()).await
    }

    async fn create_directory(&self, project_id: ProjectId, path: PathBuf) -> Result<()> {
        let validator = self.get_validator(project_id)?;
        let contained = validator.validate(project_id, &path)?;

        std::fs::create_dir_all(&contained.absolute_path).map_err(|e| Error::Io(e))?;
        Ok(())
    }

    async fn move_entry(
        &self,
        project_id: ProjectId,
        source: PathBuf,
        destination: PathBuf,
    ) -> Result<()> {
        let validator = self.get_validator(project_id)?;

        let source_contained = validator.validate(project_id, &source)?;
        let dest_contained = validator.validate(project_id, &destination)?;

        // Create parent dir for destination
        if let Some(parent) = dest_contained.absolute_path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| Error::Io(e))?;
        }

        std::fs::rename(&source_contained.absolute_path, &dest_contained.absolute_path)
            .map_err(|e| Error::Io(e))?;

        Ok(())
    }

    async fn copy_entry(
        &self,
        project_id: ProjectId,
        source: PathBuf,
        destination: PathBuf,
    ) -> Result<()> {
        let validator = self.get_validator(project_id)?;

        let source_contained = validator.validate(project_id, &source)?;
        let dest_contained = validator.validate(project_id, &destination)?;

        if source_contained.absolute_path.is_dir() {
            // Recursive copy
            copy_dir_recursive(&source_contained.absolute_path, &dest_contained.absolute_path)
                .map_err(|e| Error::Io(e))?;
        } else {
            // Create parent dir
            if let Some(parent) = dest_contained.absolute_path.parent() {
                std::fs::create_dir_all(parent).map_err(|e| Error::Io(e))?;
            }
            std::fs::copy(&source_contained.absolute_path, &dest_contained.absolute_path)
                .map_err(|e| Error::Io(e))?;
        }

        Ok(())
    }

    async fn delete(&self, project_id: ProjectId, path: PathBuf, recursive: bool) -> Result<()> {
        let validator = self.get_validator(project_id)?;
        let contained = validator.validate(project_id, &path)?;

        if contained.absolute_path.is_dir() {
            if recursive {
                std::fs::remove_dir_all(&contained.absolute_path).map_err(|e| Error::Io(e))?;
            } else {
                std::fs::remove_dir(&contained.absolute_path).map_err(|e| Error::Io(e))?;
            }
        } else {
            std::fs::remove_file(&contained.absolute_path).map_err(|e| Error::Io(e))?;
        }

        Ok(())
    }

    async fn search(&self, project_id: ProjectId, query: String) -> Result<Vec<SearchResult>> {
        let workspace = self.get_workspace(project_id)?;
        let validator = self.get_validator(project_id)?;

        let mut results = Vec::new();
        search_recursive(&workspace.root, &query, &mut results, 0)?;

        Ok(results)
    }

    async fn find_files(&self, project_id: ProjectId, pattern: String) -> Result<Vec<PathBuf>> {
        let workspace = self.get_workspace(project_id)?;
        let validator = self.get_validator(project_id)?;

        let mut results = Vec::new();
        find_files_recursive(&workspace.root, &pattern, &mut results)?;

        Ok(results)
    }

    async fn get_tree(
        &self,
        project_id: ProjectId,
        path: Option<PathBuf>,
        max_depth: Option<usize>,
    ) -> Result<Vec<FileEntry>> {
        let workspace = self.get_workspace(project_id)?;
        let validator = self.get_validator(project_id)?;

        let target_path = match path {
            Some(p) => {
                let contained = validator.validate(project_id, &p)?;
                contained.absolute_path
            }
            None => workspace.root.clone(),
        };

        let mut entries = Vec::new();
        get_tree_recursive(&target_path, &target_path, max_depth.unwrap_or(10), 0, &mut entries)?;

        Ok(entries)
    }
}

impl WorkspaceServiceImpl {
    async fn get_workspace(&self, project_id: ProjectId) -> Result<RegisteredWorkspace> {
        let workspaces = self.workspaces.read().await;
        workspaces
            .get(&project_id)
            .cloned()
            .ok_or_else(|| Error::WorkspaceNotFound(format!("Project {}", project_id)))
    }

    async fn get_validator(&self, project_id: ProjectId) -> Result<PathValidator> {
        let validators = self.validators.read().await;
        validators
            .get(&project_id)
            .cloned()
            .ok_or_else(|| Error::WorkspaceNotFound(format!("Project {}", project_id)))
    }
}

/// Detect if a file is likely binary
fn detect_binary(path: &Path) -> bool {
    // Check extension first
    if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
        let binary_exts = [
            "exe", "dll", "so", "dylib", "bin", "o", "obj", "a", "lib",
            "png", "jpg", "jpeg", "gif", "bmp", "ico", "webp",
            "zip", "tar", "gz", "bz2", "xz", "7z", "rar",
            "pdf", "doc", "docx", "xls", "xlsx",
            "wasm",
        ];
        if binary_exts.iter().any(|&e| e.eq_ignore_ascii_case(ext)) {
            return true;
        }
    }

    // Check first bytes for null bytes
    if let Ok(metadata) = std::fs::metadata(path) {
        if metadata.len() > 0 {
            let sample_size = metadata.len().min(4096);
            if let Ok(mut file) = std::fs::File::open(path) {
                use std::io::Read;
                let mut buffer = vec![0u8; sample_size as usize];
                if file.read_exact(&mut buffer).is_ok() {
                    if buffer.iter().any(|&b| b == 0) {
                        return true;
                    }
                }
            }
        }
    }

    false
}

/// Recursive search within a directory
fn search_recursive(
    dir: &Path,
    query: &str,
    results: &mut Vec<SearchResult>,
    depth: usize,
) -> Result<()> {
    if depth > 10 {
        return Ok(());
    }

    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return Ok(()),
    };

    for entry in entries.flatten() {
        let path = entry.path();
        let metadata = match entry.metadata() {
            Ok(m) => m,
            Err(_) => continue,
        };

        if metadata.is_dir() {
            search_recursive(&path, query, results, depth + 1)?;
        } else if metadata.is_file() {
            // Skip large files
            if metadata.len() > 1_000_000 {
                continue;
            }

            if let Ok(content) = std::fs::read_to_string(&path) {
                for (line_num, line) in content.lines().enumerate() {
                    if line.contains(query) {
                        let col = line.find(query).unwrap_or(0);
                        results.push(SearchResult {
                            path: path.clone(),
                            line_number: line_num + 1,
                            column: col,
                            match_text: query.to_string(),
                            context_before: Vec::new(),
                            context_after: Vec::new(),
                        });
                    }
                }
            }
        }
    }

    Ok(())
}

/// Recursive file find with pattern matching
fn find_files_recursive(
    dir: &Path,
    pattern: &str,
    results: &mut Vec<PathBuf>,
) -> Result<()> {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return Ok(()),
    };

    for entry in entries.flatten() {
        let path = entry.path();
        let metadata = match entry.metadata() {
            Ok(m) => m,
            Err(_) => continue,
        };

        if metadata.is_dir() {
            find_files_recursive(&path, pattern, results)?;
        } else if metadata.is_file() {
            if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                if name.contains(pattern) || glob_match(name, pattern) {
                    results.push(path);
                }
            }
        }
    }

    Ok(())
}

/// Simple glob match (supports * wildcard)
fn glob_match(name: &str, pattern: &str) -> bool {
    if pattern.contains('*') {
        let parts: Vec<&str> = pattern.split('*').collect();
        if parts.is_empty() {
            return true;
        }
        let mut pos = 0;
        for (i, part) in parts.iter().enumerate() {
            if part.is_empty() {
                continue;
            }
            if let Some(found) = name[pos..].find(part) {
                if i == 0 && found != 0 {
                    return false;
                }
                pos = found + part.len();
                if i == parts.len() - 1 && pos != name.len() {
                    return false;
                }
            } else {
                return false;
            }
        }
        true
    } else {
        name == pattern
    }
}

/// Get tree recursively
fn get_tree_recursive(
    dir: &Path,
    root: &Path,
    max_depth: usize,
    current_depth: usize,
    entries: &mut Vec<FileEntry>,
) -> Result<()> {
    if current_depth >= max_depth {
        return Ok(());
    }

    let entries_in_dir = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return Ok(()),
    };

    for entry in entries_in_dir.flatten() {
        let path = entry.path();
        let metadata = match entry.metadata() {
            Ok(m) => m,
            Err(_) => continue,
        };

        let relative = path.strip_prefix(root).unwrap_or(&path);
        let file_type = if metadata.is_dir() {
            FileType::Directory
        } else if path.is_symlink() {
            FileType::Symlink
        } else {
            FileType::File
        };

        entries.push(FileEntry {
            path,
            name: relative.to_string_lossy().to_string(),
            file_type,
            size: metadata.len(),
            modified: metadata.modified()
                .unwrap_or_else(|_| std::time::SystemTime::UNIX_EPOCH)
                .into(),
            created: metadata.created()
                .unwrap_or_else(|_| std::time::SystemTime::UNIX_EPOCH)
                .into(),
            permissions: FilePermissions {
                readable: true,
                writable: metadata.permissions().readonly() == false,
                executable: false,
            },
            is_binary: detect_binary(&path),
        });

        if metadata.is_dir() {
            get_tree_recursive(&path, root, max_depth, current_depth + 1, entries)?;
        }
    }

    Ok(())
}

/// Recursive directory copy
fn copy_dir_recursive(src: &Path, dst: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());
        if src_path.is_dir() {
            copy_dir_recursive(&src_path, &dst_path)?;
        } else {
            std::fs::copy(&src_path, &dst_path)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_register_and_list_workspace() {
        let service = WorkspaceServiceImpl::new();
        let temp = TempDir::new().unwrap();
        let root = temp.path().to_path_buf();

        // Create some test files
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::write(root.join("src").join("main.rs"), "fn main() {}").unwrap();
        std::fs::write(root.join("Cargo.toml"), "[package]").unwrap();

        let id = service.register(root.clone(), ExecutionProfile::Development).await.unwrap();
        let entries = service.list(id, None).await.unwrap();

        assert!(entries.iter().any(|e| e.name == "src"));
        assert!(entries.iter().any(|e| e.name == "Cargo.toml"));
    }

    #[tokio::test]
    async fn test_read_write_file() {
        let service = WorkspaceServiceImpl::new();
        let temp = TempDir::new().unwrap();
        let root = temp.path().to_path_buf();

        let id = service.register(root.clone(), ExecutionProfile::Development).await.unwrap();

        // Write a file
        service.write_file(id, PathBuf::from("test.txt"), b"Hello, World!".to_vec()).await.unwrap();

        // Read it back
        let content = service.read_file(id, PathBuf::from("test.txt")).await.unwrap();
        assert_eq!(content, b"Hello, World!");

        // Stat it
        let stat = service.stat(id, PathBuf::from("test.txt")).await.unwrap();
        assert_eq!(stat.name, "test.txt");
        assert_eq!(stat.size, 13);
    }

    #[tokio::test]
    async fn test_path_escape_rejected() {
        let service = WorkspaceServiceImpl::new();
        let temp = TempDir::new().unwrap();
        let root = temp.path().to_path_buf();

        let id = service.register(root.clone(), ExecutionProfile::Development).await.unwrap();

        // Try to read outside workspace
        let result = service.read_file(id, PathBuf::from("../../../etc/passwd")).await;
        assert!(result.is_err());
    }
}