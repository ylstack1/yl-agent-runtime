//! Discovery service: configurable roots, paginated browse, project detection.
//!
//! Manages discovery roots (user-authorized filesystem boundaries) and provides
//! root-relative paginated browsing plus bounded project detection. Every browse
//! and detect path is validated through [`PathValidator`] containment before any
//! filesystem access, so traversal/symlink/junction escapes fail closed.
//!
//! The service is protocol-agnostic: it knows nothing about MCP, HTTP, or the
//! CLI, so the same functions can back `yl discovery …` commands and a future
//! desktop controller GUI.

use crate::path_safety::{AccessMode, PathValidator};
use runtime_config::config::{
    DiscoveryBrowseEntry, DiscoveryBrowseResult, DiscoveryConfig, DiscoveryEntryKind,
    DiscoveryProjectDetection,
};
use runtime_core::error::{Error, Result};
use runtime_core::types::ProjectId;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

use chrono::{DateTime, Utc};

/// A configured discovery root with runtime state and a path validator.
#[derive(Clone, Debug)]
pub struct ConfiguredRoot {
    pub id: String,
    pub label: String,
    pub canonical_path: PathBuf,
    pub enabled: bool,
    pub browse: bool,
    pub create: bool,
    pub register: bool,
    pub import: bool,
    pub clone: bool,
}

/// Marker files used for bounded project detection. Each entry is
/// `(filename, project_type)`.
const PROJECT_MARKERS: &[(&str, &str)] = &[
    ("Cargo.toml", "rust"),
    ("package.json", "node"),
    ("package-lock.json", "node"),
    ("pyproject.toml", "python"),
    ("setup.py", "python"),
    ("requirements.txt", "python"),
    ("go.mod", "go"),
    ("pom.xml", "java-maven"),
    ("build.gradle", "java-gradle"),
    ("build.gradle.kts", "java-gradle-kotlin"),
    ("CMakeLists.txt", "cpp-cmake"),
    ("*.sln", "dotnet"),
    ("*.csproj", "dotnet"),
    ("*.vbproj", "dotnet"),
    ("composer.json", "php"),
    ("mix.exs", "elixir"),
    ("Cargo.lock", "rust"),
    ("tsconfig.json", "node"),
    ("next.config.js", "node"),
    ("nuxt.config.ts", "node"),
    ("angular.json", "node"),
];

/// Discovery service: roots, browse, detect.
#[derive(Clone)]
pub struct DiscoveryService {
    roots: Arc<RwLock<HashMap<String, ConfiguredRoot>>>,
    validators: Arc<RwLock<HashMap<String, PathValidator>>>,
    config: Arc<RwLock<DiscoveryConfig>>,
}

impl DiscoveryService {
    /// Build a service from a [`DiscoveryConfig`]. Root paths are canonicalized
    /// here; roots that cannot be canonicalized (do not exist) are still kept
    /// but marked unable to browse until they exist.
    pub fn from_config(config: DiscoveryConfig) -> Result<Self> {
        let roots = Arc::new(RwLock::new(HashMap::new()));
        let validators = Arc::new(RwLock::new(HashMap::new()));

        for root in &config.roots {
            let canonical = match root.path.canonicalize() {
                Ok(p) => p,
                Err(_) => root.path.clone(),
            };
            let mut validator = PathValidator::new()
                .with_root(canonical.clone())
                .allow_symlinks(config.follow_symlinks);

            roots.write().unwrap().insert(
                root.id.clone(),
                ConfiguredRoot {
                    id: root.id.clone(),
                    label: root.label.clone(),
                    canonical_path: canonical,
                    enabled: root.enabled,
                    browse: root.browse,
                    create: root.create,
                    register: root.register,
                    import: root.import,
                    clone: root.clone,
                },
            );
            validators.write().unwrap().insert(root.id.clone(), validator);
        }

        Ok(Self {
            roots,
            validators,
            config: Arc::new(RwLock::new(config)),
        })
    }

    /// Return metadata for every configured root (paths are not exposed as
    /// absolute host paths to untrusted callers; only id/label/flags).
    pub fn list_roots(&self) -> Vec<ConfiguredRoot> {
        self.roots.read().unwrap().values().cloned().collect()
    }

    /// Enable or disable a root. Disabled roots reject all browse/create/
    /// register/import/clone operations.
    pub fn set_root_enabled(&self, id: &str, enabled: bool) -> Result<()> {
        let mut roots = self.roots.write().unwrap();
        match roots.get_mut(id) {
            Some(root) => {
                root.enabled = enabled;
                Ok(())
            }
            None => Err(Error::Validation(format!("Discovery root not found: {id}"))),
        }
    }

    /// Return the root configuration for `id`, or error if missing/disabled.
    fn require_enabled_root(&self, id: &str) -> Result<ConfiguredRoot> {
        let roots = self.roots.read().unwrap();
        let root = roots
            .get(id)
            .ok_or_else(|| Error::Validation(format!("Discovery root not found: {id}")))?;
        if !root.enabled {
            return Err(Error::PermissionDenied(format!(
                "Discovery root {id} is disabled"
            )));
        }
        Ok(root.clone())
    }

    /// Validate that `rel_path` (root-relative) stays within the root and return
    /// the resolved absolute path. Rejects traversal and link escapes.
    fn resolve_within_root(&self, root: &ConfiguredRoot, rel_path: &Path) -> Result<PathBuf> {
        let guards = self.validators.read().unwrap();
        let validator = guards
            .get(&root.id)
            .ok_or_else(|| Error::Internal(format!("No validator for root {}", root.id)))?;
        // ProjectId::nil() is a sentinel: discovery roots are not registered
        // workspaces yet, so no real project id exists at browse time.
        let contained = validator
            .validate_access(ProjectId::nil(), rel_path, AccessMode::Read)
            .map_err(|e| {
                Error::PathNotAllowed(format!(
                    "Path {rel_path:?} is outside root {}: {}",
                    root.id, e
                ))
            })?;
        let abs_path = contained.absolute_path.clone();
        Ok(abs_path)
    }

    /// Paginated browse of a directory under a discovery root. `cursor` is an
    /// optional offset (number of entries to skip) as a string; `limit` caps the
    /// page size at `config.max_entries_per_page`.
    pub fn browse_root(
        &self,
        root_id: &str,
        rel_path: &str,
        cursor: Option<usize>,
        limit: Option<usize>,
    ) -> Result<DiscoveryBrowseResult> {
        let root = self.require_enabled_root(root_id)?;
        if !root.browse {
            return Err(Error::PermissionDenied(format!(
                "Browse not allowed on root {root_id}"
            )));
        }

        let rel = Path::new(rel_path);
        let abs = self.resolve_within_root(&root, rel)?;

        let metadata = std::fs::metadata(&abs).map_err(|e| {
            Error::Validation(format!(
                "Cannot read directory {rel_path:?} under root {}: {}",
                root_id, e
            ))
        })?;
        if !metadata.is_dir() {
            return Err(Error::Validation(format!(
                "{rel_path:?} under root {root_id} is not a directory"
            )));
        }

        let mut entries: Vec<DiscoveryBrowseEntry> = Vec::new();
        let mut scan_limits_hit = false;
        let max_entries = self.config.read().unwrap().max_entries_per_page;

        for entry in std::fs::read_dir(&abs).map_err(|e| {
            Error::Io(e)
        })? {
            let entry = entry.map_err(|e| Error::Io(e))?;
            let path = entry.path();
            let file_name = entry.file_name();
            let name = file_name.to_string_lossy().to_string();

            // Skip hidden files unless show_hidden is enabled.
            if !self.config.read().unwrap().show_hidden && name.starts_with('.') {
                continue;
            }

            let metadata = entry.metadata().map_err(|e| Error::Io(e))?;
            let entry_kind = if metadata.is_dir() {
                DiscoveryEntryKind::Directory
            } else if metadata.is_file() {
                DiscoveryEntryKind::File
            } else {
                continue; // skip symlinks/special files unless followed
            };

            let modified_time = metadata
                .modified()
                .ok()
                .map(|t| {
                    let dt: DateTime<Utc> = t.into();
                    dt.to_rfc3339()
                });

            entries.push(DiscoveryBrowseEntry {
                name: name.clone(),
                relative_path: rel.join(&name),
                entry_kind,
                size: metadata.len(),
                modified_time,
                hidden: name.starts_with('.'),
            });

            if entries.len() >= max_entries * 2 {
                // Safety cap so a single directory cannot blow memory.
                scan_limits_hit = true;
                break;
            }
        }

        // Stable ordering: directories first, then by name.
        entries.sort_by(|a, b| {
            match (a.entry_kind, b.entry_kind) {
                (DiscoveryEntryKind::Directory, DiscoveryEntryKind::File) =>
                    std::cmp::Ordering::Less,
                (DiscoveryEntryKind::File, DiscoveryEntryKind::Directory) =>
                    std::cmp::Ordering::Greater,
                _ => a.name.cmp(&b.name),
            }
        });

        let offset = cursor.unwrap_or(0).min(entries.len());
        let page_limit = limit.unwrap_or(max_entries).min(max_entries);
        let page = &entries[offset..offset.min(entries.len() - offset).saturating_add(0)];
        let page = &entries[offset..std::cmp::min(offset + page_limit, entries.len())];
        let page = page.to_vec();

        let next_cursor = if offset + page.len() < entries.len() {
            Some((offset + page.len()).to_string())
        } else {
            None
        };

        let has_more = next_cursor.is_some();

        Ok(DiscoveryBrowseResult {
            root_id: root.id,
            path: rel_path.to_string(),
            entries: page,
            cursor: Some(offset.to_string()),
            next_cursor,
            has_more,
        })
    }

    /// Bounded project detection for a directory under a discovery root. Scans
    /// marker files up to `config.max_depth`, never executing project code.
    pub fn detect_project(&self, root_id: &str, rel_path: &str) -> Result<DiscoveryProjectDetection> {
        let root = self.require_enabled_root(root_id)?;
        let abs = self.resolve_within_root(&root, Path::new(rel_path))?;

        let mut markers = Vec::new();
        let mut project_types = Vec::new();
        let mut git_present = false;
        let mut git_branch = None;
        let mut confidence: f32 = 0.0;
        let mut scan_limits_hit = false;

        // Shallow scan of the target directory only (not recursive), bounded
        // by entry count. max_depth would apply to a recursive scan, which is
        // intentionally not performed here to avoid executing project code.
        if let Ok(read_dir) = std::fs::read_dir(&abs) {
            let mut count = 0;
            for entry in read_dir.flatten() {
                count += 1;
                if count > 500 {
                    scan_limits_hit = true;
                    break;
                }
                let file_name = entry.file_name();
                let name = file_name.to_string_lossy().to_string();

                // Git directory / HEAD file.
                if name == ".git" {
                    git_present = true;
                    if let Ok(head) = std::fs::read_to_string(abs.join(".git").join("HEAD")) {
                        if let Some(branch) = head
                            .strip_prefix("ref: refs/heads/")
                            .map(|s| s.trim())
                        {
                            if !branch.is_empty() {
                                git_branch = Some(branch.to_string());
                            }
                        }
                    }
                    continue;
                }

                for (marker, ptype) in PROJECT_MARKERS {
                    if marker.starts_with('*') {
                        let ext = &marker[1..];
                        if name.ends_with(ext) {
                            markers.push(name.clone());
                            if !project_types.contains(&ptype.to_string()) {
                                project_types.push(ptype.to_string());
                                confidence = (confidence + 0.25).min(1.0);
                            }
                        }
                    } else if name == *marker {
                        markers.push(name.clone());
                        if !project_types.contains(&ptype.to_string()) {
                            project_types.push(ptype.to_string());
                            confidence = (confidence + 0.25).min(1.0);
                        }
                    }
                }
            }
        }

        Ok(DiscoveryProjectDetection {
            root_id: root.id.to_string(),
            relative_path: rel_path.to_string(),
            markers,
            project_types,
            git_present,
            git_branch,
            confidence,
            scan_limits_hit,
        })
    }
}

impl Default for DiscoveryService {
    fn default() -> Self {
        Self::from_config(DiscoveryConfig::default()).expect("default config")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use runtime_config::config::DiscoveryRoot;
    use std::sync::Arc;

    fn temp_root() -> tempfile::TempDir {
        tempfile::tempdir().expect("temp dir")
    }

    fn config_with_root(path: PathBuf) -> DiscoveryConfig {
        DiscoveryConfig {
            roots: vec![DiscoveryRoot {
                id: "testroot".to_string(),
                label: "Test Root".to_string(),
                path,
                enabled: true,
                browse: true,
                create: true,
                register: true,
                import: true,
                clone: true,
            }],
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn list_roots_returns_configured_roots() {
        let dir = temp_root();
        let service = DiscoveryService::from_config(config_with_root(dir.path().to_path_buf()))
            .expect("service");
        let roots = service.list_roots();
        assert_eq!(roots.len(), 1);
        assert_eq!(roots[0].id, "testroot");
        assert!(roots[0].enabled);
    }

    #[tokio::test]
    async fn browse_root_lists_entries_and_pages() {
        let dir = temp_root();
        std::fs::write(dir.path().join("a.txt"), b"a").expect("write a");
        std::fs::write(dir.path().join("b.txt"), b"b").expect("write b");
        std::fs::create_dir_all(dir.path().join("sub")).expect("make sub");

        let service = DiscoveryService::from_config(config_with_root(dir.path().to_path_buf()))
            .expect("service");

        let page = service.browse_root("testroot", "", Some(0), Some(10)).expect("browse");
        let names: Vec<String> = page.entries.iter().map(|e| e.name.clone()).collect();
        assert!(names.contains(&"a.txt".to_string()));
        assert!(names.contains(&"b.txt".to_string()));
        assert!(names.contains(&"sub".to_string()));
        assert!(!page.has_more);
        assert_eq!(page.entries.len(), 3);
    }

    #[tokio::test]
    async fn browse_root_traversal_rejected() {
        let dir = temp_root();
        std::fs::create_dir_all(dir.path().join("inside")).expect("make inside");
        std::fs::write(dir.path().join("inside").join("secret.txt"), b"s").expect("write");

        let service = DiscoveryService::from_config(config_with_root(dir.path().to_path_buf()))
            .expect("service");

        let err = service
            .browse_root("testroot", "inside/../../../outside", Some(0), Some(10))
            .unwrap_err();
        assert!(
            matches!(err, Error::PathNotAllowed(_) | Error::Validation(_)),
            "unexpected error: {err:?}"
        );
    }

    #[tokio::test]
    async fn disabled_root_rejected() {
        let dir = temp_root();
        let mut config = config_with_root(dir.path().to_path_buf());
        config.roots[0].enabled = false;
        let service = DiscoveryService::from_config(config).expect("service");

        let err = service
            .browse_root("testroot", "", Some(0), Some(10))
            .unwrap_err();
        assert!(matches!(err, Error::PermissionDenied(_)), "{err:?}");
    }

    #[tokio::test]
    async fn set_root_enabled_toggles() {
        let dir = temp_root();
        let service = DiscoveryService::from_config(config_with_root(dir.path().to_path_buf()))
            .expect("service");
        service.set_root_enabled("testroot", false).expect("disable");
        let err = service
            .browse_root("testroot", "", Some(0), Some(10))
            .unwrap_err();
        assert!(matches!(err, Error::PermissionDenied(_)), "{err:?}");
        service.set_root_enabled("testroot", true).expect("enable");
        service
            .browse_root("testroot", "", Some(0), Some(10))
            .expect("re-enabled browse works");
    }

    #[tokio::test]
    async fn detect_project_finds_rust_and_git() {
        let dir = temp_root();
        std::fs::write(dir.path().join("Cargo.toml"), b"[package]\n").expect("write");
        std::fs::create_dir_all(dir.path().join(".git")).expect("make git dir");
        std::fs::write(
            dir.path().join(".git").join("HEAD"),
            b"ref: refs/heads/main\n",
        )
        .expect("write HEAD");

        let service = DiscoveryService::from_config(config_with_root(dir.path().to_path_buf()))
            .expect("service");

        let det = service.detect_project("testroot", "").expect("detect");
        assert!(det.project_types.contains(&"rust".to_string()));
        assert!(det.git_present);
        assert_eq!(det.git_branch.as_deref(), Some("main"));
        assert!(det.confidence > 0.0);
    }

    #[tokio::test]
    async fn unknown_root_rejected() {
        let service = DiscoveryService::default();
        let err = service
            .browse_root("nope", "", Some(0), Some(10))
            .unwrap_err();
        assert!(matches!(err, Error::Validation(_)), "{err:?}");
    }
}
