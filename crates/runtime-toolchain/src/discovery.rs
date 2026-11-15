//! Toolchain discovery implementation
//!
//! Discovers installed development tools (Node, Python, Rust, Java, etc.)
//! without bundling any of them.

use runtime_core::error::{Error, Result};
use runtime_core::types::*;
use std::path::PathBuf;
use std::process::Command;
use std::collections::HashMap;

/// Toolchain discovery service
pub struct ToolchainDiscovery {
    known_locations: Vec<PathBuf>,
    cache: HashMap<String, Option<Toolchain>>,
}

impl ToolchainDiscovery {
    pub fn new() -> Self {
        let mut known_locations = Vec::new();

        #[cfg(windows)]
        {
            known_locations.push(PathBuf::from("C:\\Program Files\\nodejs"));
            known_locations.push(PathBuf::from("C:\\Program Files\\Python3"));
            known_locations.push(PathBuf::from("C:\\Program Files\\Git\\cmd"));
            known_locations.push(PathBuf::from("C:\\Program Files\\Rust\\cargo\\bin"));
            known_locations.push(PathBuf::from("C:\\Program Files\\Microsoft SDKs\\Azure"));
        }

        #[cfg(unix)]
        {
            known_locations.push(PathBuf::from("/usr/local/bin"));
            known_locations.push(PathBuf::from("/usr/bin"));
            known_locations.push(PathBuf::from("/opt/homebrew/bin"));
        }

        Self {
            known_locations,
            cache: HashMap::new(),
        }
    }

    pub fn with_known_location(mut self, location: PathBuf) -> Self {
        self.known_locations.push(location);
        self
    }

    /// Discover all available toolchains
    pub fn discover_all(&self) -> Result<Vec<Toolchain>> {
        let mut toolchains = Vec::new();

        // Check each known tool
        let tools_to_check = vec![
            ("node", "node"),
            ("npm", "npm"),
            ("pnpm", "pnpm"),
            ("bun", "bun"),
            ("python", "python"),
            ("python3", "python3"),
            ("git", "git"),
            ("cargo", "cargo"),
            ("rustc", "rustc"),
            ("java", "java"),
            ("mvn", "mvn"),
            ("gradle", "gradle"),
            ("dotnet", "dotnet"),
            ("cmake", "cmake"),
            ("go", "go"),
        ];

        for (name, cmd_name) in tools_to_check {
            if let Some(toolchain) = self.find_by_name_internal(name, cmd_name)? {
                toolchains.push(toolchain);
            }
        }

        Ok(toolchains)
    }

    /// Find a specific toolchain by name
    pub fn find_by_name(&self, name: &str) -> Result<Option<Toolchain>> {
        if let Some(cached) = self.cache.get(name) {
            return Ok(cached.clone());
        }

        // Try common command names for the tool
        let cmd_names = match name {
            "node" => vec!["node"],
            "npm" => vec!["npm"],
            "pnpm" => vec!["pnpm"],
            "bun" => vec!["bun"],
            "python" => vec!["python", "python3"],
            "git" => vec!["git"],
            "cargo" => vec!["cargo"],
            "rustc" => vec!["rustc"],
            "java" => vec!["java"],
            "nodejs" => vec!["node"],
            _ => vec![name],
        };

        for cmd_name in cmd_names {
            if let Some(toolchain) = self.find_by_name_internal(name, cmd_name)? {
                return Ok(Some(toolchain));
            }
        }

        Ok(None)
    }

    fn find_by_name_internal(&self, name: &str, cmd_name: &str) -> Result<Option<Toolchain>> {
        // Check cache first
        let cache_key = format!("{}:{}", name, cmd_name);
        if let Some(cached) = self.cache.get(&cache_key) {
            return Ok(cached.clone());
        }

        // Try `which` / `where` first
        if let Some(path) = find_executable(cmd_name) {
            let version = get_version(&path, cmd_name);
            let arch = detect_architecture(&path);
            let source = detect_source(&path);

            let toolchain = Toolchain {
                name: name.to_string(),
                version: version.unwrap_or_else(|| "unknown".to_string()),
                path,
                architecture: arch,
                detection_source: source,
            };

            self.cache.insert(cache_key, Some(toolchain.clone()));
            return Ok(Some(toolchain));
        }

        // Check known locations
        for location in &self.known_locations {
            let exe_path = if cfg!(windows) {
                location.join(format!("{}.exe", cmd_name))
            } else {
                location.join(cmd_name)
            };

            if exe_path.exists() && exe_path.is_file() {
                let version = get_version(&exe_path, cmd_name);
                let arch = detect_architecture(&exe_path);
                let source = ToolchainSource::KnownLocation;

                let toolchain = Toolchain {
                    name: name.to_string(),
                    version: version.unwrap_or_else(|| "unknown".to_string()),
                    path: exe_path,
                    architecture: arch,
                    detection_source: source,
                };

                self.cache.insert(cache_key, Some(toolchain.clone()));
                return Ok(Some(toolchain));
            }
        }

        // Cache negative result
        self.cache.insert(cache_key, None);
        Ok(None)
    }

    /// Check if a tool is available
    pub fn is_available(&self, name: &str) -> Result<bool> {
        Ok(self.find_by_name(name)?.is_some())
    }

    /// Get all toolchain names that were discovered
    pub fn discovered_names(&self) -> Vec<String> {
        self.discover_all()
            .map(|tcs| tcs.iter().map(|t| t.name.clone()).collect())
            .unwrap_or_default()
    }
}

impl Default for ToolchainDiscovery {
    fn default() -> Self {
        Self::new()
    }
}

/// Find an executable in PATH
fn find_executable(name: &str) -> Option<PathBuf> {
    #[cfg(windows)]
    {
        // Use `where` command on Windows
        let output = Command::new("where").arg(name).output();
        if let Ok(output) = output {
            if output.status.success() {
                let first_line = String::from_utf8_lossy(&output.stdout)
                    .lines()
                    .next()?;
                return Some(PathBuf::from(first_line.trim()));
            }
        }
        None
    }

    #[cfg(unix)]
    {
        // Use `which` command on Unix
        let output = Command::new("which").arg(name).output();
        if let Ok(output) = output {
            if output.status.success() {
                let first_line = String::from_utf8_lossy(&output.stdout)
                    .lines()
                    .next()?;
                return Some(PathBuf::from(first_line.trim()));
            }
        }
        None
    }
}

/// Get the version of a tool
fn get_version(path: &PathBuf, cmd_name: &str) -> Option<String> {
    let output = Command::new(path)
        .args(version_args(cmd_name))
        .output();

    match output {
        Ok(out) => {
            let stdout = String::from_utf8_lossy(&out.stdout);
            let stderr = String::from_utf8_lossy(&out.stderr);
            let combined = format!("{} {}", stdout, stderr);
            // Extract first line with version info
            combined.lines().next().map(|l| l.trim().to_string())
        }
        Err(_) => None,
    }
}

/// Get version arguments for a command
fn version_args(cmd_name: &str) -> Vec<String> {
    match cmd_name {
        "node" => vec!["--version".to_string()],
        "npm" => vec!["--version".to_string()],
        "pnpm" => vec!["--version".to_string()],
        "bun" => vec!["--version".to_string()],
        "python" | "python3" => vec!["--version".to_string()],
        "git" => vec!["--version".to_string()],
        "cargo" => vec!["--version".to_string()],
        "rustc" => vec!["--version".to_string()],
        "java" => vec!["-version".to_string()],
        "dotnet" => vec!["--version".to_string()],
        "cmake" => vec!["--version".to_string()],
        "go" => vec!["version".to_string()],
        _ => vec!["--version".to_string()],
    }
}

/// Detect architecture of an executable
fn detect_architecture(path: &PathBuf) -> Architecture {
    // Try to read the executable header to detect architecture
    // For now, return the host architecture as a best guess
    Architecture::current()
}

/// Detect the source of discovery
fn detect_source(path: &PathBuf) -> ToolchainSource {
    let path_str = path.to_string_lossy();

    #[cfg(windows)]
    {
        if path_str.contains("\\Program Files\\") {
            return ToolchainSource::KnownLocation;
        }
        if path_str.contains("\\Windows\\") {
            return ToolchainSource::KnownLocation;
        }
    }

    #[cfg(unix)]
    {
        if path_str.starts_with("/usr/") || path_str.starts_with("/opt/") {
            return ToolchainSource::KnownLocation;
        }
    }

    ToolchainSource::Path
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_args() {
        let args = version_args("node");
        assert_eq!(args, vec!["--version"]);

        let args = version_args("java");
        assert_eq!(args, vec!["-version"]);

        let args = version_args("go");
        assert_eq!(args, vec!["version"]);
    }

    #[test]
    fn test_detect_source() {
        let path = PathBuf::from("/usr/bin/node");
        assert_eq!(detect_source(&path), ToolchainSource::KnownLocation);

        let path = PathBuf::from("/usr/local/bin/python3");
        assert_eq!(detect_source(&path), ToolchainSource::KnownLocation);
    }

    #[test]
    fn test_find_executable_returns_none_for_nonexistent() {
        let result = find_executable("nonexistent-tool-xyz");
        assert!(result.is_none());
    }
}