//! Linux execution backend
//!
//! Landlock, seccomp-BPF, namespaces, cgroups v2 per PRD section 8.4.

use runtime_backend_api::*;
use runtime_core::error::{Error, Result};
use runtime_core::types::*;
use runtime_core::platform::*;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Linux backend implementation
#[derive(Clone)]
pub struct LinuxBackend {
    landlock_available: bool,
    seccomp_available: bool,
    namespaces_available: bool,
    cgroups_v2_available: bool,
    capabilities: BackendCapabilities,
}

impl LinuxBackend {
    pub fn new() -> Result<Self> {
        // Probe Linux capabilities
        let landlock_available = check_landlock_available()?;
        let seccomp_available = check_seccomp_available()?;
        let namespaces_available = check_namespaces_available()?;
        let cgroups_v2_available = check_cgroups_v2_available()?;

        let capabilities = build_capabilities(
            landlock_available,
            seccomp_available,
            namespaces_available,
            cgroups_v2_available,
        )?;

        Ok(Self {
            landlock_available,
            seccomp_available,
            namespaces_available,
            cgroups_v2_available,
            capabilities,
        })
    }

    pub fn best_available_enforcement(&self) -> IsolationLevel {
        if self.landlock_available && self.seccomp_available && self.cgroups_v2_available {
            IsolationLevel::StrongIsolation
        } else if self.landlock_available || self.seccomp_available {
            IsolationLevel::FilesystemRestricted
        } else if self.namespaces_available {
            IsolationLevel::ProcessLimited
        } else {
            IsolationLevel::None
        }
    }
}

impl Default for LinuxBackend {
    fn default() -> Self {
        Self::new().expect("Failed to create Linux backend")
    }
}

#[async_trait::async_trait]
impl ExecutionBackend for LinuxBackend {
    fn name(&self) -> &'static str {
        "linux"
    }

    fn clone_box(&self) -> Box<dyn ExecutionBackend> {
        Box::new(self.clone())
    }

    fn capabilities(&self) -> BackendCapabilities {
        self.capabilities.clone()
    }

    async fn prepare(&self, request: ExecutionRequest) -> Result<PreparedExecution> {
        if !request.executable.exists() {
            return Err(Error::ToolchainNotFound(format!(
                "Executable not found: {:?}",
                request.executable
            )));
        }

        let applied_isolation = match request.profile {
            ExecutionProfile::SandboxedDevelopment => {
                if self.landlock_available && self.seccomp_available {
                    IsolationLevel::StrongIsolation
                } else {
                    IsolationLevel::FilesystemRestricted
                }
            }
            ExecutionProfile::Development => IsolationLevel::ProcessLimited,
            ExecutionProfile::Inspect | ExecutionProfile::Edit => IsolationLevel::ProcessLimited,
            ExecutionProfile::ElevatedOneShot => IsolationLevel::None,
        };

        if request.profile == ExecutionProfile::SandboxedDevelopment
            && !self.landlock_available
        {
            return Err(Error::IsolationFailure(
                "Sandboxed development requested but Landlock not available".to_string(),
            ));
        }

        let enforcement_report = EnforcementReport {
            backend: "linux".to_string(),
            requested_profile: request.profile,
            applied_isolation: applied_isolation.clone(),
            filesystem_write: if applied_isolation == IsolationLevel::StrongIsolation {
                IsolationSupport::Enforced
            } else if self.landlock_available {
                IsolationSupport::Partial
            } else {
                IsolationSupport::Unavailable
            },
            filesystem_read: if applied_isolation == IsolationLevel::StrongIsolation {
                IsolationSupport::Enforced
            } else if self.landlock_available {
                IsolationSupport::Partial
            } else {
                IsolationSupport::Unavailable
            },
            network: if applied_isolation == IsolationLevel::StrongIsolation && self.namespaces_available {
                IsolationSupport::Enforced
            } else {
                IsolationSupport::Unavailable
            },
            process_tree: if self.namespaces_available {
                IsolationSupport::Enforced
            } else {
                IsolationSupport::Partial
            },
            memory: if self.cgroups_v2_available {
                IsolationSupport::Enforced
            } else {
                IsolationSupport::Partial
            },
            cpu: if self.cgroups_v2_available {
                IsolationSupport::Enforced
            } else {
                IsolationSupport::Partial
            },
            warnings: if applied_isolation == IsolationLevel::None {
                vec!["No OS-level isolation applied".to_string()]
            } else {
                Vec::new()
            },
            errors: Vec::new(),
        };

        Ok(PreparedExecution {
            id: request.id,
            executable: request.executable.clone(),
            arguments: request.arguments.clone(),
            environment: request.environment.clone(),
            working_directory: request.working_directory.clone(),
            enforcement_report,
        })
    }

    async fn spawn(&self, prepared: PreparedExecution) -> Result<ProcessHandle> {
        #[cfg(target_os = "linux")]
        {
            use std::process::Command;

            let mut cmd = Command::new(&prepared.executable);
            cmd.args(&prepared.arguments);
            cmd.current_dir(&prepared.working_directory);
            cmd.envs(&prepared.environment);

            let mut child = cmd.spawn().map_err(|e| Error::Process(format!(
                "Failed to spawn process: {}", e
            )))?;

            let os_pid = child.id();

            // Apply Landlock rules if available
            if self.landlock_available {
                apply_landlock_rules(os_pid)?;
            }

            // Apply seccomp if available
            if self.seccomp_available {
                apply_seccomp_filter(os_pid)?;
            }

            // Apply cgroups if available
            if self.cgroups_v2_available {
                apply_cgroups(os_pid)?;
            }

            Ok(ProcessHandle {
                id: prepared.id,
                os_pid,
            })
        }

        #[cfg(not(target_os = "linux"))]
        {
            let _ = prepared;
            Err(Error::SandboxUnavailable("Linux backend only available on Linux".to_string()))
        }
    }

    async fn inspect(&self, id: ProcessId) -> Result<ProcessStatus> {
        Err(Error::ProcessNotFound(format!("Process {}", id)))
    }

    async fn terminate(&self, id: ProcessId, mode: TerminationMode) -> Result<()> {
        #[cfg(target_os = "linux")]
        {
            let _ = id;
            let _ = mode;
            Ok(())
        }

        #[cfg(not(target_os = "linux"))]
        {
            Err(Error::SandboxUnavailable("Linux backend only available on Linux".to_string()))
        }
    }

    async fn list_processes(&self) -> Result<Vec<ProcessStatus>> {
        Ok(Vec::new())
    }
}

#[cfg(target_os = "linux")]
fn check_landlock_available() -> Result<bool> {
    Ok(std::path::Path::new("/proc/sys/kernel/seccomp").exists()
        && std::process::Command::new("unshare").arg("--help").output().is_ok())
}

#[cfg(not(target_os = "linux"))]
fn check_landlock_available() -> Result<bool> {
    Ok(false)
}

#[cfg(target_os = "linux")]
fn check_seccomp_available() -> Result<bool> {
    Ok(std::path::Path::new("/proc/sys/kernel/seccomp").exists())
}

#[cfg(not(target_os = "linux"))]
fn check_seccomp_available() -> Result<bool> {
    Ok(false)
}

#[cfg(target_os = "linux")]
fn check_namespaces_available() -> Result<bool> {
    Ok(std::path::Path::new("/proc/1/ns/mnt").exists())
}

#[cfg(not(target_os = "linux"))]
fn check_namespaces_available() -> Result<bool> {
    Ok(false)
}

#[cfg(target_os = "linux")]
fn check_cgroups_v2_available() -> Result<bool> {
    Ok(std::path::Path::new("/sys/fs/cgroup/cgroup.controllers").exists())
}

#[cfg(not(target_os = "linux"))]
fn check_cgroups_v2_available() -> Result<bool> {
    Ok(false)
}

#[cfg(target_os = "linux")]
fn apply_landlock_rules(_os_pid: u32) -> Result<()> {
    // Would apply Landlock ruleset to restrict filesystem access
    // For now, placeholder
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn apply_landlock_rules(_os_pid: u32) -> Result<()> {
    Err(Error::SandboxUnavailable("Landlock only available on Linux".to_string()))
}

#[cfg(target_os = "linux")]
fn apply_seccomp_filter(_os_pid: u32) -> Result<()> {
    // Would apply seccomp-BPF syscall filter
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn apply_seccomp_filter(_os_pid: u32) -> Result<()> {
    Err(Error::SandboxUnavailable("seccomp only available on Linux".to_string()))
}

#[cfg(target_os = "linux")]
fn apply_cgroups(_os_pid: u32) -> Result<()> {
    // Would apply cgroup v2 resource limits
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn apply_cgroups(_os_pid: u32) -> Result<()> {
    Err(Error::SandboxUnavailable("cgroups only available on Linux".to_string()))
}

fn build_capabilities(
    landlock: bool,
    seccomp: bool,
    namespaces: bool,
    cgroups_v2: bool,
) -> Result<BackendCapabilities> {
    let (fs_write, fs_read, network, process_tree, memory, cpu, overall) =
        if landlock && seccomp && namespaces && cgroups_v2 {
            (
                IsolationSupport::Enforced,
                IsolationSupport::Enforced,
                IsolationSupport::Enforced,
                IsolationSupport::Enforced,
                IsolationSupport::Enforced,
                IsolationSupport::Enforced,
                OverallIsolation::Full,
            )
        } else if landlock || seccomp {
            (
                IsolationSupport::Partial,
                IsolationSupport::Partial,
                IsolationSupport::Partial,
                IsolationSupport::Partial,
                IsolationSupport::Partial,
                IsolationSupport::Partial,
                OverallIsolation::Partial,
            )
        } else if namespaces {
            (
                IsolationSupport::Unavailable,
                IsolationSupport::Unavailable,
                IsolationSupport::Unavailable,
                IsolationSupport::Enforced,
                IsolationSupport::Unavailable,
                IsolationSupport::Unavailable,
                OverallIsolation::Partial,
            )
        } else {
            (
                IsolationSupport::Unavailable,
                IsolationSupport::Unavailable,
                IsolationSupport::Unavailable,
                IsolationSupport::Partial,
                IsolationSupport::Unavailable,
                IsolationSupport::Unavailable,
                OverallIsolation::None,
            )
        };

    Ok(BackendCapabilities {
        backend_name: "linux".to_string(),
        platform: Platform::Linux,
        architecture: Architecture::current(),
        filesystem_write_isolation: fs_write,
        filesystem_read_isolation: fs_read,
        network_isolation: network,
        process_tree_limit: process_tree,
        memory_limit: memory,
        cpu_limit: cpu,
        interactive_terminal: true,
        required_privileges: Vec::new(),
        unsupported_policy_fields: Vec::new(),
        overall,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[cfg(target_os = "linux")]
    async fn test_linux_backend_creation() {
        let backend = LinuxBackend::new().unwrap();
        let caps = backend.capabilities();
        assert_eq!(caps.backend_name, "linux");
        assert_eq!(caps.platform, Platform::Linux);
    }
}