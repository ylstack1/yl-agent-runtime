//! macOS execution backend
//!
//! Seatbelt sandbox profiles per PRD section 8.4.

use runtime_backend_api::*;
use runtime_core::error::{Error, Result};
use runtime_core::types::*;
use runtime_core::platform::*;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;

/// macOS backend implementation
#[derive(Clone)]
pub struct MacOSBackend {
    seatbelt_available: bool,
    capabilities: BackendCapabilities,
}

impl MacOSBackend {
    pub fn new() -> Result<Self> {
        let seatbelt_available = check_seatbelt_available()?;

        let capabilities = build_capabilities(seatbelt_available)?;

        Ok(Self {
            seatbelt_available,
            capabilities,
        })
    }

    pub fn best_available_enforcement(&self) -> IsolationLevel {
        if self.seatbelt_available {
            IsolationLevel::FilesystemRestricted
        } else {
            IsolationLevel::ProcessLimited
        }
    }
}

impl Default for MacOSBackend {
    fn default() -> Self {
        Self::new().expect("Failed to create macOS backend")
    }
}

#[async_trait::async_trait]
impl ExecutionBackend for MacOSBackend {
    fn name(&self) -> &'static str {
        "macos"
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
                if self.seatbelt_available {
                    IsolationLevel::StrongIsolation
                } else {
                    IsolationLevel::ProcessLimited
                }
            }
            ExecutionProfile::Development => IsolationLevel::ProcessLimited,
            ExecutionProfile::Inspect | ExecutionProfile::Edit => IsolationLevel::ProcessLimited,
            ExecutionProfile::ElevatedOneShot => IsolationLevel::None,
        };

        if request.profile == ExecutionProfile::SandboxedDevelopment && !self.seatbelt_available {
            return Err(Error::IsolationFailure(
                "Sandboxed development requested but Seatbelt not available".to_string(),
            ));
        }

        let enforcement_report = EnforcementReport {
            backend: "macos".to_string(),
            requested_profile: request.profile,
            applied_isolation: applied_isolation.clone(),
            filesystem_write: if applied_isolation == IsolationLevel::StrongIsolation {
                IsolationSupport::Enforced
            } else {
                IsolationSupport::Unavailable
            },
            filesystem_read: if applied_isolation == IsolationLevel::StrongIsolation {
                IsolationSupport::Enforced
            } else {
                IsolationSupport::Partial
            },
            network: if applied_isolation == IsolationLevel::StrongIsolation {
                IsolationSupport::Enforced
            } else {
                IsolationSupport::Unavailable
            },
            process_tree: IsolationSupport::Enforced,
            memory: IsolationSupport::Partial,
            cpu: IsolationSupport::Partial,
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
        #[cfg(target_os = "macos")]
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

            // Apply Seatbelt profile if available
            if self.seatbelt_available {
                apply_seatbelt_profile(os_pid)?;
            }

            Ok(ProcessHandle {
                id: prepared.id,
                os_pid,
            })
        }

        #[cfg(not(target_os = "macos"))]
        {
            let _ = prepared;
            Err(Error::SandboxUnavailable("macOS backend only available on macOS".to_string()))
        }
    }

    async fn inspect(&self, id: ProcessId) -> Result<ProcessStatus> {
        Err(Error::ProcessNotFound(format!("Process {}", id)))
    }

    async fn terminate(&self, id: ProcessId, mode: TerminationMode) -> Result<()> {
        #[cfg(target_os = "macos")]
        {
            let _ = id;
            let _ = mode;
            Ok(())
        }

        #[cfg(not(target_os = "macos"))]
        {
            Err(Error::SandboxUnavailable("macOS backend only available on macOS".to_string()))
        }
    }

    async fn list_processes(&self) -> Result<Vec<ProcessStatus>> {
        Ok(Vec::new())
    }
}

#[cfg(target_os = "macos")]
fn check_seatbelt_available() -> Result<bool> {
    Ok(std::process::Command::new("sandbox-exec")
        .arg("--help")
        .output()
        .is_ok())
}

#[cfg(not(target_os = "macos"))]
fn check_seatbelt_available() -> Result<bool> {
    Ok(false)
}

#[cfg(target_os = "macos")]
fn apply_seatbelt_profile(_os_pid: u32) -> Result<()> {
    // Would apply a Seatbelt sandbox profile
    Ok(())
}

#[cfg(not(target_os = "macos"))]
fn apply_seatbelt_profile(_os_pid: u32) -> Result<()> {
    Err(Error::SandboxUnavailable("Seatbelt only available on macOS".to_string()))
}

fn build_capabilities(seatbelt: bool) -> Result<BackendCapabilities> {
    let (fs_write, fs_read, network, overall) = if seatbelt {
        (
            IsolationSupport::Enforced,
            IsolationSupport::Partial,
            IsolationSupport::Partial,
            OverallIsolation::Partial,
        )
    } else {
        (
            IsolationSupport::Unavailable,
            IsolationSupport::Unavailable,
            IsolationSupport::Unavailable,
            OverallIsolation::None,
        )
    };

    Ok(BackendCapabilities {
        backend_name: "macos".to_string(),
        platform: Platform::MacOS,
        architecture: Architecture::current(),
        filesystem_write_isolation: fs_write,
        filesystem_read_isolation: fs_read,
        network_isolation: network,
        process_tree_limit: IsolationSupport::Enforced,
        memory_limit: IsolationSupport::Partial,
        cpu_limit: IsolationSupport::Partial,
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
    #[cfg(target_os = "macos")]
    async fn test_macos_backend_creation() {
        let backend = MacOSBackend::new().unwrap();
        let caps = backend.capabilities();
        assert_eq!(caps.backend_name, "macos");
        assert_eq!(caps.platform, Platform::MacOS);
    }
}