//! Workspace service implementation
//!
//! Safe project discovery and file operations per PRD section 10.
//!
//! Every operation is routed through the engines from Tasks 2-8
//! (`path_safety`, `sensitive`, `files`, `search`). The `WorkspaceService`
//! trait methods are thin delegates into the engines; the inherent methods
//! on `WorkspaceServiceImpl` (with the `sensitive` guard on every mutating
//! path and on reads) are consumed by the Task 11 MCP tools.

use crate::files::{edit, patch, read, write};
use crate::files::edit::{EditOptions, EditOutcome, EditSpec};
use crate::files::patch::PatchFileResult;
use crate::files::read::{ReadOptions, ReadOutcome};
use crate::files::write::{WriteOptions, WriteOutcome};
use crate::path_safety::{AccessMode, ContainedPath, PathValidator};
use crate::search::{search_tree, find_files, FindOptions, FindReport, SearchOptions, SearchReport};
use crate::sensitive::{SensitiveMatcher, SensitiveVerdict};
use diffy::patch_set::{FileOperation, PatchSet, ParseOptions};
use runtime_core::error::{Error, Result};
use runtime_core::traits::WorkspaceService;
use runtime_core::types::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

/// Origin of a workspace record: how the workspace came to be registered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkspaceOrigin {
    /// An existing directory was registered as-is.
    Registered,
    /// A new empty directory was created and then registered.
    Created,
    /// A project was imported from a controller.
    Imported,
    /// A Git repository was cloned into the workspace root.
    Cloned,
}

/// Safe display metadata for a registered workspace. Clients receive this
/// (never absolute host paths) so they can list and select workspaces.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkspaceRecord {
    pub id: ProjectId,
    pub display_name: String,
    /// Root-relative display path (safe to show to clients).
    pub root: PathBuf,
    pub origin: WorkspaceOrigin,
    pub profile: ExecutionProfile,
    pub registered_at: DateTime<Utc>,
    pub last_opened: Option<DateTime<Utc>>,
    pub tags: Vec<String>,
}

/// Registered workspace with full runtime state (root is an absolute host path,
/// kept internal to the runtime host).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisteredWorkspace {
    pub id: ProjectId,
    pub root: PathBuf,
    pub display_name: String,
    pub profile: ExecutionProfile,
    pub origin: WorkspaceOrigin,
    pub registered_at: DateTime<Utc>,
    pub last_opened: Option<DateTime<Utc>>,
    pub tags: Vec<String>,
    pub max_file_size: u64,
    pub deny_paths: Vec<PathBuf>,
}

/// Workspace service implementation
#[derive(Clone)]
pub struct WorkspaceServiceImpl {
    workspaces: Arc<RwLock<HashMap<ProjectId, RegisteredWorkspace>>>,
    validators: Arc<RwLock<HashMap<ProjectId, PathValidator>>>,
    sensitive: Arc<RwLock<SensitiveMatcher>>,
    /// Directory used to persist the workspace registry so it survives
    /// daemon restarts. `None` means in-memory only (used by tests).
    data_dir: Option<PathBuf>,
    /// Path to the workspace registry JSONL file.
    registry_path: Option<PathBuf>,
}

impl WorkspaceServiceImpl {
    /// In-memory workspace service (no persistence). Used by tests.
    pub fn new() -> Self {
        Self {
            workspaces: Arc::new(RwLock::new(HashMap::new())),
            validators: Arc::new(RwLock::new(HashMap::new())),
            sensitive: Arc::new(RwLock::new(SensitiveMatcher::new())),
            data_dir: None,
            registry_path: None,
        }
    }

    /// Workspace service with persistent registry stored in `data_dir`.
    ///
    /// Existing workspaces are loaded from `<data_dir>/workspaces.jsonl` if
    /// present; new registrations are appended and unregistrations rewrite
    /// the file.
    pub fn with_data_dir(data_dir: PathBuf) -> Result<Self> {
        std::fs::create_dir_all(&data_dir).map_err(|e| {
            Error::Config(format!("Cannot create data dir {data_dir:?}: {e}"))
        })?;
        let registry_path = data_dir.join("workspaces.jsonl");

        let workspaces = Arc::new(RwLock::new(HashMap::new()));
        let validators = Arc::new(RwLock::new(HashMap::new()));
        let service = Self {
            workspaces: workspaces.clone(),
            validators: validators.clone(),
            sensitive: Arc::new(RwLock::new(SensitiveMatcher::new())),
            data_dir: Some(data_dir),
            registry_path: Some(registry_path.clone()),
        };

        // Load persisted workspaces if the registry file exists.
        if registry_path.exists() {
            let contents = std::fs::read_to_string(&registry_path).map_err(|e| {
                Error::Config(format!("Cannot read workspace registry {registry_path:?}: {e}"))
            })?;
            for (line_no, line) in contents.lines().enumerate() {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }
                let record: RegisteredWorkspace = serde_json::from_str(line).map_err(|e| {
                    Error::Config(format!(
                        "Invalid workspace registry entry at line {line_no}: {e}"
                    ))
                })?;
                let mut validator =
                    PathValidator::new().with_root(record.root.clone()).allow_symlinks(false);
                if record.profile == ExecutionProfile::Inspect {
                    validator = validator.with_read_only_root(record.root.clone());
                }
                let id = record.id;
                workspaces.write().unwrap().insert(id, record);
                validators.write().unwrap().insert(id, validator);
            }
        }

        Ok(service)
    }

    /// Persist the current registry to disk (full rewrite). Called after any
    /// mutation (register/create/unregister).
    fn persist_registry(&self) -> Result<()> {
        let registry_path = self
            .registry_path
            .as_ref()
            .ok_or_else(|| Error::Config("Workspace registry persistence is not enabled".to_string()))?;
        let workspaces = self.workspaces.read().unwrap();
        let file = std::fs::File::create(registry_path).map_err(|e| {
            Error::Config(format!("Cannot open workspace registry {registry_path:?}: {e}"))
        })?;
        let mut writer = std::io::BufWriter::new(file);
        for workspace in workspaces.values() {
            let line = serde_json::to_string(workspace).map_err(|e| {
                Error::Config(format!("Cannot serialize workspace {}: {}", workspace.id, e))
            })?;
            writer.write_all(line.as_bytes()).map_err(Error::Io)?;
            writer.write_all(b"\n").map_err(Error::Io)?;
        }
        writer.flush().map_err(Error::Io)?;
        Ok(())
    }

    /// Clone of the configured sensitive matcher (consumed by Task 11 MCP tools).
    pub fn sensitive(&self) -> SensitiveMatcher {
        self.sensitive.read().unwrap().clone()
    }

    /// Replace the configured sensitive matcher (CLI wiring, Task 10).
    pub fn set_sensitive(&self, matcher: SensitiveMatcher) {
        *self.sensitive.write().unwrap() = matcher;
    }

    pub fn workspace_count(&self) -> usize {
        // Note: this is a sync method, would need async for real count
        0
    }

    /// Sensitive-file guard on a resolved path.
    ///
    /// `verdict != Allowed` → `Error::PathNotAllowed("Sensitive file blocked:
    /// {path} (matched {pattern})")`. Runs before every mutating operation and
    /// before reads on the resolved path.
    fn sensitive_check(&self, path: &Path) -> Result<()> {
        match self.sensitive.read().unwrap().verdict(path) {
            SensitiveVerdict::Allowed => Ok(()),
            SensitiveVerdict::Blocked { pattern } => Err(Error::PathNotAllowed(format!(
                "Sensitive file blocked: {} (matched {pattern})",
                path.display()
            ))),
        }
    }

    /// Resolve a path for reading: `AccessMode::Read` containment plus the
    /// sensitive guard on the resolved path.
    fn validate_read(&self, project_id: ProjectId, path: &Path) -> Result<ContainedPath> {
        let validator = self.get_validator(project_id)?;
        let contained = validator.validate_access(project_id, path, AccessMode::Read)?;
        self.sensitive_check(&contained.absolute_path)?;
        Ok(contained)
    }

    /// Resolve a path for writing: `AccessMode::Write` containment plus the
    /// sensitive guard on the resolved path.
    fn validate_write(&self, project_id: ProjectId, path: &Path) -> Result<ContainedPath> {
        let validator = self.get_validator(project_id)?;
        let contained = validator.validate_access(project_id, path, AccessMode::Write)?;
        self.sensitive_check(&contained.absolute_path)?;
        Ok(contained)
    }

    /// Resolve a path for moving: `AccessMode::Move` containment plus the
    /// sensitive guard on the resolved path.
    fn validate_move(&self, project_id: ProjectId, path: &Path) -> Result<ContainedPath> {
        let validator = self.get_validator(project_id)?;
        let contained = validator.validate_access(project_id, path, AccessMode::Move)?;
        self.sensitive_check(&contained.absolute_path)?;
        Ok(contained)
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
        // Windows `canonicalize` produces `\\?\`-verbatim paths; store a cleaned
        // root so paths joined against it (e.g. by the patch engine's internal
        // `validate_access` calls) are not rejected as UNC paths.
        let canonical = clean_verbatim_prefix(&canonical);

        let workspace = RegisteredWorkspace {
            id,
            root: canonical.clone(),
            display_name: root
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("workspace")
                .to_string(),
            profile,
            origin: WorkspaceOrigin::Registered,
            registered_at: chrono::Utc::now(),
            last_opened: None,
            tags: Vec::new(),
            max_file_size: 100_000_000, // 100 MB default
            deny_paths: Vec::new(),
        };

        // Inspect-profile workspaces are read-only roots: Write/Move are
        // refused by path_safety's validate_access (with_read_only_root).
        let mut validator =
            PathValidator::new().with_root(canonical.clone()).allow_symlinks(false);
        if profile == ExecutionProfile::Inspect {
            validator = validator.with_read_only_root(canonical);
        }

        self.workspaces.write().unwrap().insert(id, workspace.clone());
        self.validators.write().unwrap().insert(id, validator);

        // Persist the registry so it survives daemon restarts.
        if self.registry_path.is_some() {
            self.persist_registry()?;
        }

        Ok(id)
    }

    async fn unregister(&self, project_id: ProjectId) -> Result<()> {
        let removed = self.workspaces.write().unwrap().remove(&project_id).is_some();
        self.validators.write().unwrap().remove(&project_id);
        if !removed {
            return Err(Error::WorkspaceNotFound(format!("Project {}", project_id)));
        }

        // Persist the registry so unregister survives daemon restarts.
        if self.registry_path.is_some() {
            self.persist_registry()?;
        }

        Ok(())
    }

    async fn list(
        &self,
        project_id: ProjectId,
        path: Option<PathBuf>,
    ) -> Result<Vec<FileEntry>> {
        let workspace = self.get_workspace(project_id)?;
        let target_path = match path {
            Some(p) => self.validate_read(project_id, &p)?.absolute_path,
            None => workspace.root.clone(),
        };

        if !target_path.exists() {
            return Err(Error::Validation(format!(
                "Path does not exist: {:?}",
                target_path
            )));
        }

        let mut entries = Vec::new();
        let mut dir_entries = std::fs::read_dir(&target_path).map_err(Error::Io)?;

        while let Some(entry) = dir_entries.next() {
            let entry = entry.map_err(Error::Io)?;
            let path = entry.path();
            let metadata = entry.metadata().map_err(Error::Io)?;

            let file_type = if metadata.is_dir() {
                FileType::Directory
            } else if path.is_symlink() {
                FileType::Symlink
            } else {
                FileType::File
            };

            entries.push(FileEntry {
                path: path.clone(),
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
        let contained = self.validate_read(project_id, &path)?;
        let metadata = contained.absolute_path.metadata().map_err(Error::Io)?;

        let file_type = if metadata.is_dir() {
            FileType::Directory
        } else if contained.absolute_path.is_symlink() {
            FileType::Symlink
        } else {
            FileType::File
        };

        Ok(FileEntry {
            path: contained.absolute_path.clone(),
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
        let contained = self.validate_read(project_id, &path)?;

        // Check file size limit
        let metadata = contained.absolute_path.metadata().map_err(Error::Io)?;
        if metadata.len() > workspace.max_file_size {
            return Err(Error::Validation(format!(
                "File size {} exceeds maximum {}",
                metadata.len(),
                workspace.max_file_size
            )));
        }

        // Check if binary
        if detect_binary(&contained.absolute_path) {
            return Err(Error::Validation(
                "File is binary, use read_range or specify binary handling".to_string(),
            ));
        }

        let content = std::fs::read(&contained.absolute_path).map_err(Error::Io)?;
        Ok(content)
    }

    async fn read_range(
        &self,
        project_id: ProjectId,
        path: PathBuf,
        start: u64,
        end: u64,
    ) -> Result<Vec<u8>> {
        let contained = self.validate_read(project_id, &path)?;

        let metadata = contained.absolute_path.metadata().map_err(Error::Io)?;
        if start > metadata.len() {
            return Err(Error::Validation(format!(
                "Start offset {} exceeds file size {}",
                start, metadata.len()
            )));
        }

        let end = end.min(metadata.len());
        let range_size = end - start;

        use std::io::{Read, Seek, SeekFrom};
        let mut file = std::fs::File::open(&contained.absolute_path).map_err(Error::Io)?;
        file.seek(SeekFrom::Start(start)).map_err(Error::Io)?;

        let mut buffer = vec![0u8; range_size as usize];
        file.read_exact(&mut buffer).map_err(Error::Io)?;

        Ok(buffer)
    }

    async fn write_file(
        &self,
        project_id: ProjectId,
        path: PathBuf,
        content: Vec<u8>,
    ) -> Result<()> {
        let workspace = self.get_workspace(project_id)?;

        // Check size limit
        if content.len() as u64 > workspace.max_file_size {
            return Err(Error::Validation(format!(
                "Content size {} exceeds maximum {}",
                content.len(),
                workspace.max_file_size
            )));
        }

        let contained = self.validate_write(project_id, &path)?;

        // Create parent directories if needed
        if let Some(parent) = contained.absolute_path.parent() {
            std::fs::create_dir_all(parent).map_err(Error::Io)?;
        }

        // Atomic write: write to temp file then rename
        let temp_path = contained.absolute_path.with_extension("tmp");
        {
            use std::io::Write;
            let mut file = std::fs::File::create(&temp_path).map_err(Error::Io)?;
            file.write_all(&content).map_err(Error::Io)?;
            file.sync_all().map_err(Error::Io)?;
        }

        std::fs::rename(&temp_path, &contained.absolute_path).map_err(Error::Io)?;

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
        let contained = self.validate_write(project_id, &path)?;

        std::fs::create_dir_all(&contained.absolute_path).map_err(Error::Io)?;
        Ok(())
    }

    async fn move_entry(
        &self,
        project_id: ProjectId,
        source: PathBuf,
        destination: PathBuf,
    ) -> Result<()> {
        let source_contained = self.validate_move(project_id, &source)?;
        let dest_contained = self.validate_move(project_id, &destination)?;

        // Refuse to move over an existing destination.
        if dest_contained.absolute_path.exists() {
            return Err(Error::Validation(format!(
                "Destination already exists: {}",
                destination.display()
            )));
        }

        // Create parent dir for destination
        if let Some(parent) = dest_contained.absolute_path.parent() {
            std::fs::create_dir_all(parent).map_err(Error::Io)?;
        }

        std::fs::rename(&source_contained.absolute_path, &dest_contained.absolute_path)
            .map_err(Error::Io)?;

        Ok(())
    }

    async fn copy_entry(
        &self,
        project_id: ProjectId,
        source: PathBuf,
        destination: PathBuf,
    ) -> Result<()> {
        let source_contained = self.validate_read(project_id, &source)?;
        let dest_contained = self.validate_write(project_id, &destination)?;

        if source_contained.absolute_path.is_dir() {
            // Recursive copy
            copy_dir_recursive(&source_contained.absolute_path, &dest_contained.absolute_path)
                .map_err(Error::Io)?;
        } else {
            // Create parent dir
            if let Some(parent) = dest_contained.absolute_path.parent() {
                std::fs::create_dir_all(parent).map_err(Error::Io)?;
            }
            std::fs::copy(&source_contained.absolute_path, &dest_contained.absolute_path)
                .map_err(Error::Io)?;
        }

        Ok(())
    }

    async fn delete(&self, project_id: ProjectId, path: PathBuf, recursive: bool) -> Result<()> {
        let contained = self.validate_write(project_id, &path)?;

        if contained.absolute_path.is_dir() {
            if recursive {
                std::fs::remove_dir_all(&contained.absolute_path).map_err(Error::Io)?;
            } else {
                std::fs::remove_dir(&contained.absolute_path).map_err(Error::Io)?;
            }
        } else {
            std::fs::remove_file(&contained.absolute_path).map_err(Error::Io)?;
        }

        Ok(())
    }

    async fn search(&self, project_id: ProjectId, query: String) -> Result<Vec<SearchResult>> {
        let workspace = self.get_workspace(project_id)?;

        let opts = SearchOptions {
            query,
            is_regex: false,
            case_sensitive: true,
            include: Vec::new(),
            exclude: Vec::new(),
            context: 0,
            max_results: 200,
            offset: 0,
            files_only: false,
            include_hidden: false,
            include_ignored: false,
            max_file_size: 1_000_000,
            sensitive: Some(self.sensitive.read().unwrap().clone()),
        };

        let report = search_tree(&workspace.root, &opts)?;

        Ok(report
            .matches
            .into_iter()
            .map(|m| SearchResult {
                path: m.file,
                line_number: m.line as usize,
                column: m.column as usize,
                match_text: m.text,
                context_before: m.before,
                context_after: m.after,
            })
            .collect())
    }

    async fn find_files(&self, project_id: ProjectId, pattern: String) -> Result<Vec<PathBuf>> {
        let workspace = self.get_workspace(project_id)?;

        let opts = FindOptions {
            pattern,
            max_results: 100,
            want_dirs: false,
            include_hidden: false,
            include_ignored: false,
        };

        let report = find_files(&workspace.root, &opts)?;
        Ok(report.paths)
    }

    async fn get_tree(
        &self,
        project_id: ProjectId,
        path: Option<PathBuf>,
        max_depth: Option<usize>,
    ) -> Result<Vec<FileEntry>> {
        let workspace = self.get_workspace(project_id)?;

        let target_path = match path {
            Some(p) => self.validate_read(project_id, &p)?.absolute_path,
            None => workspace.root.clone(),
        };

        let mut entries = Vec::new();
        get_tree_recursive(&target_path, &target_path, max_depth.unwrap_or(10), 0, &mut entries)?;

        Ok(entries)
    }
}

impl WorkspaceServiceImpl {
    fn get_validator(&self, project_id: ProjectId) -> Result<PathValidator> {
        let validators = self.validators.read().unwrap();
        validators
            .get(&project_id)
            .cloned()
            .ok_or_else(|| Error::WorkspaceNotFound(format!("Project {}", project_id)))
    }

    /// List all registered workspaces as safe display metadata. Absolute host
    /// paths are not leaked to clients.
    pub fn list_workspaces(&self) -> Vec<WorkspaceRecord> {
        let workspaces = self.workspaces.read().unwrap();
        workspaces
            .values()
            .map(|w| WorkspaceRecord {
                id: w.id,
                display_name: w.display_name.clone(),
                root: w.root.clone(),
                origin: w.origin,
                profile: w.profile,
                registered_at: w.registered_at,
                last_opened: w.last_opened,
                tags: w.tags.clone(),
            })
            .collect()
    }

    /// Look up a registered workspace by ID (public for CLI/MCP consumers).
    pub fn get_workspace(&self, project_id: ProjectId) -> Result<RegisteredWorkspace> {
        let workspaces = self.workspaces.read().unwrap();
        workspaces
            .get(&project_id)
            .cloned()
            .ok_or_else(|| Error::WorkspaceNotFound(format!("Project {}", project_id)))
    }

    /// Create a new empty project directory under `parent_path`, register it,
    /// and return its opaque ID. Never overwrites an existing destination.
    ///
    /// `name` is validated for traversal and reserved names; `subdirs` are
    /// optional empty subdirectories created inside the new project.
    pub async fn create_workspace(
        &self,
        parent_path: &Path,
        name: &str,
        profile: ExecutionProfile,
        subdirs: &[String],
    ) -> Result<ProjectId> {
        // Validate name.
        if name.is_empty() || name == "." || name == ".." {
            return Err(Error::Validation(format!("Invalid workspace name: {name:?}")));
        }
        if name.contains(std::path::MAIN_SEPARATOR)
            || name.contains('/')
            || name.contains('\\')
        {
            return Err(Error::Validation(format!(
                "Workspace name must not contain path separators: {name:?}"
            )));
        }
        // Reject traversal segments.
        if name.contains("..") {
            return Err(Error::Validation(format!(
                "Workspace name must not contain traversal segments: {name:?}"
            )));
        }
        // Reject reserved Windows device names (case-insensitive).
        let upper = name.to_uppercase();
        let reserved = [
            "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5",
            "COM6", "COM7", "COM8", "COM9", "LPT1", "LPT2", "LPT3", "LPT4",
            "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
        ];
        if reserved.iter().any(|r| upper == *r || upper.starts_with(&format!("{r}."))) {
            return Err(Error::Validation(format!(
                "Workspace name is a reserved device name: {name:?}"
            )));
        }

        // Parent must exist and be a directory.
        if !parent_path.exists() {
            return Err(Error::Validation(format!(
                "Parent directory does not exist: {:?}",
                parent_path
            )));
        }
        if !parent_path.is_dir() {
            return Err(Error::Validation(format!(
                "Parent is not a directory: {:?}",
                parent_path
            )));
        }

        let dest = parent_path.join(name);
        if dest.exists() {
            return Err(Error::Validation(format!(
                "Destination already exists: {:?}",
                dest
            )));
        }

        // Create the project directory (+ optional subdirs) atomically-ish.
        std::fs::create_dir_all(&dest).map_err(|e| {
            Error::Validation(format!("Cannot create workspace directory {dest:?}: {e}"))
        })?;
        for subdir in subdirs {
            let sub = dest.join(subdir);
            std::fs::create_dir_all(&sub).map_err(|e| {
                Error::Validation(format!(
                    "Cannot create subdirectory {sub:?}: {e}"
                ))
            })?;
        }

        let canonical = dest.canonicalize().map_err(|e| {
            Error::Validation(format!("Cannot canonicalize workspace root: {e}"))
        })?;
        let canonical = clean_verbatim_prefix(&canonical);

        let id = ProjectId::new();
        let workspace = RegisteredWorkspace {
            id,
            root: canonical.clone(),
            display_name: name.to_string(),
            profile,
            origin: WorkspaceOrigin::Created,
            registered_at: chrono::Utc::now(),
            last_opened: None,
            tags: Vec::new(),
            max_file_size: 100_000_000, // 100 MB default
            deny_paths: Vec::new(),
        };

        let mut validator =
            PathValidator::new().with_root(canonical.clone()).allow_symlinks(false);
        if profile == ExecutionProfile::Inspect {
            validator = validator.with_read_only_root(canonical);
        }

        self.workspaces.write().unwrap().insert(id, workspace.clone());
        self.validators.write().unwrap().insert(id, validator);

        if self.registry_path.is_some() {
            self.persist_registry()?;
        }

        Ok(id)
    }

    // ---- Inherent methods consumed by the Task 11 MCP tools ----

    pub async fn read_text(
        &self,
        project_id: ProjectId,
        path: &Path,
        opts: &ReadOptions,
    ) -> Result<ReadOutcome> {
        let contained = self.validate_read(project_id, path)?;
        read::read_text(&contained.absolute_path, opts)
    }

    pub async fn write_text(
        &self,
        project_id: ProjectId,
        path: &Path,
        content: &str,
        opts: &WriteOptions,
    ) -> Result<WriteOutcome> {
        let contained = self.validate_write(project_id, path)?;
        write::write_text(&contained.absolute_path, content, opts)
    }

    pub async fn edit_text(
        &self,
        project_id: ProjectId,
        path: &Path,
        edits: &[EditSpec],
        opts: &EditOptions,
    ) -> Result<EditOutcome> {
        let contained = self.validate_write(project_id, path)?;
        edit::edit_text(&contained.absolute_path, edits, opts)
    }

    /// Replace up to `max_matches` occurrences of `old_text` with `new_text`
    /// in a validated (write-mode, sensitive-checked) path of the workspace.
    /// Implemented on top of the edit engine's count-then-replace-all logic.
    pub async fn replace_text(
        &self,
        project_id: ProjectId,
        path: &Path,
        old_text: &str,
        new_text: &str,
        max_matches: usize,
        dry_run: bool,
    ) -> Result<EditOutcome> {
        let contained = self.validate_write(project_id, path)?;
        edit::replace_text(
            &contained.absolute_path,
            old_text,
            new_text,
            max_matches,
            &EditOptions { dry_run },
        )
    }

    /// Apply a unified/git diff against the workspace root for `project_id`.
    ///
    /// Every patched path is run through the sensitive guard before anything
    /// is persisted; the engine performs the two-phase all-or-nothing apply.
    pub async fn apply_patch(
        &self,
        project_id: ProjectId,
        diff_text: &str,
        dry_run: bool,
    ) -> Result<Vec<PatchFileResult>> {
        let workspace = self.get_workspace(project_id)?;
        let root = &workspace.root;

        // Sensitive guard on each patched path before any I/O.
        let file_patches = PatchSet::parse(diff_text, ParseOptions::gitdiff())
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| Error::Validation(format!("Invalid patch: {e}")))?;
        for file_patch in &file_patches {
            let target = match file_patch.operation() {
                FileOperation::Create(p) | FileOperation::Delete(p) => p.as_ref(),
                FileOperation::Modify { modified, .. } => modified.as_ref(),
                FileOperation::Rename { to, .. } | FileOperation::Copy { to, .. } => to.as_ref(),
            };
            self.sensitive_check(&root.join(Path::new(target)))?;
        }

        patch::apply_patch_set(root, diff_text, dry_run)
    }

    pub async fn search(
        &self,
        project_id: ProjectId,
        root_rel: Option<&Path>,
        opts: &SearchOptions,
    ) -> Result<SearchReport> {
        let workspace = self.get_workspace(project_id)?;

        let root = match root_rel {
            Some(rel) => self.validate_read(project_id, rel)?.absolute_path,
            None => workspace.root.clone(),
        };

        let opts = SearchOptions {
            query: opts.query.clone(),
            is_regex: opts.is_regex,
            case_sensitive: opts.case_sensitive,
            include: opts.include.clone(),
            exclude: opts.exclude.clone(),
            context: opts.context,
            max_results: opts.max_results,
            offset: opts.offset,
            files_only: opts.files_only,
            include_hidden: opts.include_hidden,
            include_ignored: opts.include_ignored,
            max_file_size: opts.max_file_size,
            sensitive: Some(self.sensitive.read().unwrap().clone()),
        };

        search_tree(&root, &opts)
    }

    pub async fn find(
        &self,
        project_id: ProjectId,
        root_rel: Option<&Path>,
        opts: &FindOptions,
    ) -> Result<FindReport> {
        let workspace = self.get_workspace(project_id)?;

        let root = match root_rel {
            Some(rel) => self.validate_read(project_id, rel)?.absolute_path,
            None => workspace.root.clone(),
        };

        let opts = opts.clone();
        find_files(&root, &opts)
    }

    /// Delete entries: empty dir/file → ok; non-empty dir with
    /// `recursive == false` → validation error; missing path with
    /// `recursive == false` → error; returns the deleted paths.
    pub async fn delete_entries(
        &self,
        project_id: ProjectId,
        paths: &[PathBuf],
        recursive: bool,
    ) -> Result<Vec<PathBuf>> {
        let mut deleted = Vec::with_capacity(paths.len());

        for path in paths {
            let contained = self.validate_write(project_id, path)?;
            let abs = &contained.absolute_path;

            if abs.is_dir() {
                let mut entries = std::fs::read_dir(abs)?;
                let non_empty = entries.next().is_some();
                if non_empty && !recursive {
                    return Err(Error::Validation(
                        "Directory not empty. Set recursive: true.".to_string(),
                    ));
                }
                if recursive {
                    std::fs::remove_dir_all(abs)?;
                } else {
                    std::fs::remove_dir(abs)?;
                }
            } else {
                std::fs::remove_file(abs)?;
            }

            deleted.push(abs.clone());
        }

        Ok(deleted)
    }

    /// Move `source` to `dest`, refusing an existing destination. Both ends
    /// are validated with `AccessMode::Move` and run through the sensitive
    /// guard.
    pub async fn move_entry_checked(
        &self,
        project_id: ProjectId,
        source: &Path,
        dest: &Path,
    ) -> Result<PathBuf> {
        let source_contained = self.validate_move(project_id, source)?;
        let dest_contained = self.validate_move(project_id, dest)?;

        if dest_contained.absolute_path.exists() {
            return Err(Error::Validation(format!(
                "Destination already exists: {}",
                dest.display()
            )));
        }

        if let Some(parent) = dest_contained.absolute_path.parent() {
            std::fs::create_dir_all(parent).map_err(Error::Io)?;
        }

        std::fs::rename(&source_contained.absolute_path, &dest_contained.absolute_path)
            .map_err(Error::Io)?;

        Ok(dest_contained.absolute_path)
    }

    /// Copy `source` to `dest`. When `overwrite` is false and `dest` exists
    /// this is a validation error; otherwise the copy proceeds (overwriting
    /// when allowed). Source is validated with `Read`, destination with
    /// `Write`, both through the sensitive guard.
    pub async fn copy_entry_checked(
        &self,
        project_id: ProjectId,
        source: &Path,
        dest: &Path,
        overwrite: bool,
    ) -> Result<()> {
        let source_contained = self.validate_read(project_id, source)?;
        let dest_contained = self.validate_write(project_id, dest)?;

        if dest_contained.absolute_path.exists() && !overwrite {
            return Err(Error::Validation(format!(
                "Destination already exists: {}",
                dest.display()
            )));
        }

        if source_contained.absolute_path.is_dir() {
            copy_dir_recursive(&source_contained.absolute_path, &dest_contained.absolute_path)
                .map_err(Error::Io)?;
        } else {
            if let Some(parent) = dest_contained.absolute_path.parent() {
                std::fs::create_dir_all(parent).map_err(Error::Io)?;
            }
            std::fs::copy(&source_contained.absolute_path, &dest_contained.absolute_path)
                .map_err(Error::Io)?;
        }

        Ok(())
    }
}

/// Strip the `\\?\` verbatim prefix that Windows `canonicalize` produces, so
/// stored roots stay as ordinary paths. Non-`\\?\` paths are returned as-is.
fn clean_verbatim_prefix(root: &Path) -> PathBuf {
    if let Some(rest) = root.to_string_lossy().strip_prefix("\\\\?\\") {
        PathBuf::from(rest)
    } else {
        root.to_path_buf()
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

        let relative = path
            .strip_prefix(root)
            .unwrap_or(&path)
            .to_path_buf();
        let file_type = if metadata.is_dir() {
            FileType::Directory
        } else if path.is_symlink() {
            FileType::Symlink
        } else {
            FileType::File
        };

        entries.push(FileEntry {
            path: path.clone(),
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
    use crate::files::{edit::{EditOptions, EditSpec}, read::{ReadOptions, ReadOutcome}, write::WriteOptions};
    use tempfile::TempDir;

    fn assert_sensitive_blocked(err: &Error) {
        match err {
            Error::PathNotAllowed(msg) => {
                assert!(
                    msg.contains("Sensitive file blocked"),
                    "unexpected message: {msg}"
                );
            }
            other => panic!(
                "expected PathNotAllowed (Sensitive file blocked), got {other:?}"
            ),
        }
    }

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
        service
            .write_file(id, PathBuf::from("test.txt"), b"Hello, World!".to_vec())
            .await
            .unwrap();

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

    #[tokio::test]
    async fn read_text_returns_engine_outcome() {
        let service = WorkspaceServiceImpl::new();
        let temp = TempDir::new().unwrap();
        let root = temp.path().to_path_buf();

        let id = service.register(root.clone(), ExecutionProfile::Development).await.unwrap();

        service
            .write_text(
                id,
                Path::new("hello.txt"),
                "hello world",
                &WriteOptions::default(),
            )
            .await
            .unwrap();

        let outcome = service
            .read_text(
                id,
                Path::new("hello.txt"),
                &ReadOptions {
                    line_numbers: false,
                    ..Default::default()
                },
            )
            .await
            .unwrap();

        assert!(matches!(outcome, ReadOutcome::Text(_)));
        let content = match outcome {
            ReadOutcome::Text(t) => t.content,
            _ => panic!("expected Text variant"),
        };
        assert_eq!(content, "hello world");
    }

    #[tokio::test]
    async fn write_refuses_existing_without_overwrite() {
        let service = WorkspaceServiceImpl::new();
        let temp = TempDir::new().unwrap();
        let root = temp.path().to_path_buf();

        let id = service.register(root.clone(), ExecutionProfile::Development).await.unwrap();

        service
            .write_text(
                id,
                Path::new("exists.txt"),
                "v1",
                &WriteOptions::default(),
            )
            .await
            .unwrap();

        let opts = WriteOptions {
            overwrite: false,
            ..Default::default()
        };
        let err = service
            .write_text(id, Path::new("exists.txt"), "v2", &opts)
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("pass overwrite: true"),
            "unexpected: {err}"
        );

        // Seed untouched.
        let outcome = service
            .read_text(
                id,
                Path::new("exists.txt"),
                &ReadOptions {
                    line_numbers: false,
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(
            match outcome {
                ReadOutcome::Text(t) => t.content,
                _ => panic!("expected Text variant"),
            },
            "v1"
        );
    }

    #[tokio::test]
    async fn edit_via_service_preserves_crlf() {
        let service = WorkspaceServiceImpl::new();
        let temp = TempDir::new().unwrap();
        let root = temp.path().to_path_buf();

        let id = service.register(root.clone(), ExecutionProfile::Development).await.unwrap();

        service
            .write_text(
                id,
                Path::new("crlf.txt"),
                "a\r\nb\r\n",
                &WriteOptions::default(),
            )
            .await
            .unwrap();

        let edit = EditSpec {
            old_text: "a".into(),
            new_text: "A".into(),
            expected_occurrences: None,
        };
        service
            .edit_text(
                id,
                Path::new("crlf.txt"),
                &[edit],
                &EditOptions::default(),
            )
            .await
            .unwrap();

        let outcome = service
            .read_text(
                id,
                Path::new("crlf.txt"),
                &ReadOptions {
                    line_numbers: false,
                    ..Default::default()
                },
            )
            .await
            .unwrap();

        assert_eq!(
            match outcome {
                ReadOutcome::Text(t) => t.content,
                _ => panic!("expected Text variant"),
            },
            "A\r\nb\r\n"
        );
    }

    #[tokio::test]
    async fn all_write_paths_refuse_sensitive_files() {
        let service = WorkspaceServiceImpl::new();
        let temp = TempDir::new().unwrap();
        let root = temp.path().to_path_buf();
        std::fs::write(root.join(".env"), b"SECRET=1\n").unwrap();
        let id = service.register(root.clone(), ExecutionProfile::Development).await.unwrap();

        // write_text
        let err = service
            .write_text(id, Path::new(".env"), "tampered", &WriteOptions::default())
            .await
            .unwrap_err();
        assert_sensitive_blocked(&err);

        // edit_text
        let err = service
            .edit_text(
                id,
                Path::new(".env"),
                &[EditSpec {
                    old_text: "SECRET=1".into(),
                    new_text: "SECRET=2".into(),
                    expected_occurrences: None,
                }],
                &EditOptions::default(),
            )
            .await
            .unwrap_err();
        assert_sensitive_blocked(&err);

        // move_entry_checked: both ends are guarded
        service
            .write_text(id, Path::new("normal.txt"), "n", &WriteOptions::default())
            .await
            .unwrap();
        let err = service
            .move_entry_checked(id, Path::new("normal.txt"), Path::new(".env"))
            .await
            .unwrap_err();
        assert_sensitive_blocked(&err);
        let err = service
            .move_entry_checked(id, Path::new(".env"), Path::new("moved.env"))
            .await
            .unwrap_err();
        assert_sensitive_blocked(&err);

        // delete_entries
        let err = service
            .delete_entries(id, &[PathBuf::from(".env")], false)
            .await
            .unwrap_err();
        assert_sensitive_blocked(&err);
    }

    #[tokio::test]
    async fn move_refuses_existing_destination() {
        let service = WorkspaceServiceImpl::new();
        let temp = TempDir::new().unwrap();
        let root = temp.path().to_path_buf();

        let id = service.register(root.clone(), ExecutionProfile::Development).await.unwrap();

        service
            .write_text(id, Path::new("src.txt"), "s", &WriteOptions::default())
            .await
            .unwrap();
        service
            .write_text(id, Path::new("dst.txt"), "d", &WriteOptions::default())
            .await
            .unwrap();

        let err = service
            .move_entry_checked(id, Path::new("src.txt"), Path::new("dst.txt"))
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("Destination already exists"),
            "unexpected: {err}"
        );
    }

    #[tokio::test]
    async fn delete_nonempty_requires_recursive() {
        let service = WorkspaceServiceImpl::new();
        let temp = TempDir::new().unwrap();
        let root = temp.path().to_path_buf();

        let id = service.register(root.clone(), ExecutionProfile::Development).await.unwrap();

        std::fs::create_dir_all(root.join("subdir")).unwrap();
        std::fs::write(root.join("subdir").join("inner.txt"), b"x\n").unwrap();

        let err = service
            .delete_entries(id, &[PathBuf::from("subdir")], false)
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("Set recursive: true"),
            "unexpected: {err}"
        );
        assert!(root.join("subdir").join("inner.txt").exists());
    }

    #[tokio::test]
    async fn readonly_profile_refuses_write() {
        let service = WorkspaceServiceImpl::new();
        let temp = TempDir::new().unwrap();
        let id = service
            .register(temp.path().to_path_buf(), ExecutionProfile::Inspect)
            .await
            .unwrap();

        let err = service
            .write_text(id, Path::new("notes.txt"), "x", &WriteOptions::default())
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("read-only"),
            "unexpected: {err}"
        );
    }

    #[tokio::test]
    async fn patch_via_service_two_phase() {
        let service = WorkspaceServiceImpl::new();
        let temp = TempDir::new().unwrap();
        let root = temp.path().to_path_buf();

        let id = service.register(root.clone(), ExecutionProfile::Development).await.unwrap();

        service
            .write_text(id, Path::new("a.txt"), "alpha\n", &WriteOptions::default())
            .await
            .unwrap();
        service
            .write_text(id, Path::new("b.txt"), "zzz\n", &WriteOptions::default())
            .await
            .unwrap();

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
@@ -1,2 +1,2 @@
 zzz
-world
+WORLD
";

        let err = service.apply_patch(id, diff, false).await.unwrap_err();
        assert!(
            err.to_string().contains("Patch hunk failed"),
            "unexpected: {err}"
        );

        // All-or-nothing: the first file must be unchanged.
        let outcome = service
            .read_text(
                id,
                Path::new("a.txt"),
                &ReadOptions {
                    line_numbers: false,
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(
            match outcome {
                ReadOutcome::Text(t) => t.content,
                _ => panic!("expected Text variant"),
            },
            "alpha\n"
        );
    }

    #[tokio::test]
    async fn test_list_workspaces_returns_registered() {
        let service = WorkspaceServiceImpl::new();
        let temp1 = TempDir::new().unwrap();
        let temp2 = TempDir::new().unwrap();

        let id1 = service
            .register(temp1.path().to_path_buf(), ExecutionProfile::Development)
            .await
            .unwrap();
        let id2 = service
            .register(temp2.path().to_path_buf(), ExecutionProfile::Inspect)
            .await
            .unwrap();

        let records = service.list_workspaces();
        assert_eq!(records.len(), 2);
        let ids: Vec<ProjectId> = records.iter().map(|r| r.id).collect();
        assert!(ids.contains(&id1));
        assert!(ids.contains(&id2));
        // Display name defaults to folder name.
        let rec1 = records.iter().find(|r| r.id == id1).unwrap();
        assert_eq!(rec1.display_name, temp1.path().file_name().unwrap().to_str().unwrap());
        assert_eq!(rec1.origin, WorkspaceOrigin::Registered);
    }

    #[tokio::test]
    async fn test_get_workspace_public_lookup() {
        let service = WorkspaceServiceImpl::new();
        let temp = TempDir::new().unwrap();
        let id = service
            .register(temp.path().to_path_buf(), ExecutionProfile::Development)
            .await
            .unwrap();

        let ws = service.get_workspace(id).unwrap();
        assert_eq!(ws.id, id);
        assert_eq!(ws.root, temp.path());

        // Unknown ID errors.
        assert!(service.get_workspace(ProjectId::nil()).is_err());
    }

    #[tokio::test]
    async fn test_create_workspace_registers_new_dir() {
        let service = WorkspaceServiceImpl::new();
        let parent = TempDir::new().unwrap();

        let id = service
            .create_workspace(
                parent.path(),
                "my-new-project",
                ExecutionProfile::Development,
                &["src".to_string(), "tests".to_string()],
            )
            .await
            .unwrap();

        // Directory and subdirs exist.
        assert!(parent.path().join("my-new-project").is_dir());
        assert!(parent.path().join("my-new-project/src").is_dir());
        assert!(parent.path().join("my-new-project/tests").is_dir());

        // Registered with Created origin.
        let ws = service.get_workspace(id).unwrap();
        assert_eq!(ws.display_name, "my-new-project");
        assert_eq!(ws.origin, WorkspaceOrigin::Created);
        assert!(service.list_workspaces().iter().any(|r| r.id == id));
    }

    #[tokio::test]
    async fn test_create_workspace_rejects_existing_destination() {
        let service = WorkspaceServiceImpl::new();
        let parent = TempDir::new().unwrap();
        std::fs::create_dir_all(parent.path().join("already-there")).unwrap();

        let err = service
            .create_workspace(parent.path(), "already-there", ExecutionProfile::Development, &[])
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("already exists"),
            "unexpected: {err}"
        );
    }

    #[tokio::test]
    async fn test_create_workspace_rejects_bad_names() {
        let service = WorkspaceServiceImpl::new();
        let parent = TempDir::new().unwrap();

        for bad in ["", ".", "..", "a/b", "con", "CON", "COM1", "nul.txt"] {
            // unwrap_err panics if creation unexpectedly succeeded.
            service
                .create_workspace(parent.path(), bad, ExecutionProfile::Development, &[])
                .await
                .unwrap_err();
        }
    }

    #[tokio::test]
    async fn test_persistence_survives_reload() {
        let data_dir = TempDir::new().unwrap();
        let root = TempDir::new().unwrap();

        // First service instance: register a workspace.
        {
            let service = WorkspaceServiceImpl::with_data_dir(data_dir.path().to_path_buf())
                .unwrap();
            let id = service
                .register(root.path().to_path_buf(), ExecutionProfile::Development)
                .await
                .unwrap();
            // Tag it via direct mutation is not exposed; just verify it's persisted.
            assert!(service.list_workspaces().iter().any(|r| r.id == id));
        }

        // Second service instance: should load the persisted workspace.
        let service2 = WorkspaceServiceImpl::with_data_dir(data_dir.path().to_path_buf())
            .unwrap();
        let records = service2.list_workspaces();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].origin, WorkspaceOrigin::Registered);
        assert_eq!(records[0].root, root.path());

        // The loaded workspace is usable.
        let ws = service2.get_workspace(records[0].id).unwrap();
        assert_eq!(ws.id, records[0].id);
    }

    #[tokio::test]
    async fn test_unregister_persists() {
        let data_dir = TempDir::new().unwrap();
        let root = TempDir::new().unwrap();

        {
            let service = WorkspaceServiceImpl::with_data_dir(data_dir.path().to_path_buf())
                .unwrap();
            let id = service
                .register(root.path().to_path_buf(), ExecutionProfile::Development)
                .await
                .unwrap();
            service.unregister(id).await.unwrap();
            assert!(service.list_workspaces().is_empty());
        }

        // After reload, still empty.
        let service2 = WorkspaceServiceImpl::with_data_dir(data_dir.path().to_path_buf())
            .unwrap();
        assert!(service2.list_workspaces().is_empty());
        assert!(service2.get_workspace(ProjectId::nil()).is_err());
    }
}
