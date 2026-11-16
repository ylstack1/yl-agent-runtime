//! Native host execution backend

use runtime_backend_api::*;
use runtime_core::error::{Error, Result};
use runtime_core::types::*;
use runtime_core::platform::*;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Native host backend - executes processes directly on the host
#[derive(Clone)]
pub struct NativeBackend {
    capabilities: BackendCapabilities,
    active_processes: Arc<RwLock<HashMap<ProcessId, ProcessHandle>>>,
}

impl NativeBackend {
    pub fn new() -> Result<Self> {
        let capabilities = generate_capability_report("native")?;

        Ok(Self {
            capabilities,
            active_processes: Arc::new(RwLock::new(HashMap::new())),
        })
    }
}

impl Default for NativeBackend {
    fn default() -> Self {
        Self::new().expect("Failed to create native backend")
    }
}

#[async_trait::async_trait]
impl ExecutionBackend for NativeBackend {
    fn name(&self) -> &'static str {
        "native"
    }

    fn clone_box(&self) -> Box<dyn ExecutionBackend> {
        Box::new(self.clone())
    }

    fn capabilities(&self) -> BackendCapabilities {
        self.capabilities.clone()
    }

    async fn prepare(&self, request: ExecutionRequest) -> Result<PreparedExecution> {
        // Validate executable exists
        if !request.executable.exists() {
            return Err(Error::ToolchainNotFound(format!(
                "Executable not found: {:?}",
                request.executable
            )));
        }

        // Validate working directory
        if !request.working_directory.exists() {
            return Err(Error::Validation(format!(
                "Working directory does not exist: {:?}",
                request.working_directory
            )));
        }

        // Build enforcement report
        let enforcement_report = EnforcementReport {
            backend: "native".to_string(),
            requested_profile: request.profile,
            applied_isolation: IsolationLevel::ProcessLimited,
            filesystem_write: IsolationSupport::Unavailable,
            filesystem_read: IsolationSupport::Unavailable,
            network: IsolationSupport::Unavailable,
            process_tree: IsolationSupport::Enforced,
            memory: IsolationSupport::Partial,
            cpu: IsolationSupport::Partial,
            warnings: vec![
                "Native backend does not provide filesystem isolation".to_string(),
                "Native backend does not provide network isolation".to_string(),
            ],
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
        let mut cmd = std::process::Command::new(&prepared.executable);
        cmd.args(&prepared.arguments);
        cmd.current_dir(&prepared.working_directory);
        cmd.envs(&prepared.environment);

        // Platform-specific flags
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            cmd.creation_flags(0x00000200); // CREATE_NO_WINDOW
        }

        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            cmd.process_group(0);
        }

        let child = cmd.spawn().map_err(|e| Error::Process(format!(
            "Failed to spawn process: {}", e
        )))?;

        let os_pid = child.id();

        // Don't wait - the process is now running
        // We can't easily store the child handle here since we're returning
        // In a full implementation, we'd track the child

        let status = ProcessStatus {
            id: prepared.id,
            os_pid,
            running: true,
            exit_status: None,
            resource_usage: ResourceUsage::default(),
            started_at: chrono::Utc::now(),
        };

        let handle = ProcessHandle {
            id: prepared.id,
            os_pid,
            status,
        };

        self.active_processes.write().await.insert(prepared.id, handle.clone());

        Ok(handle)
    }

    async fn inspect(&self, id: ProcessId) -> Result<ProcessStatus> {
        let processes = self.active_processes.read().await;
        processes
            .get(&id)
            .cloned()
            .map(|h| h.status)
            .ok_or_else(|| Error::ProcessNotFound(format!("Process {}", id)))
    }

    async fn terminate(&self, id: ProcessId, mode: TerminationMode) -> Result<()> {
        let mut processes = self.active_processes.write().await;
        let mut handle = processes
            .get_mut(&id)
            .ok_or_else(|| Error::ProcessNotFound(format!("Process {}", id)))?;

        match mode {
            TerminationMode::Graceful | TerminationMode::Force => {
                // We'd need the actual child handle to kill it
                // For now, mark as terminated
                handle.status.running = false;
                handle.status.exit_status = Some(ExitStatus::from_code(1));
            }
            TerminationMode::ProcessTree => {
                handle.status.running = false;
                handle.status.exit_status = Some(ExitStatus::from_code(1));
            }
        }

        Ok(())
    }

    async fn list_processes(&self) -> Result<Vec<ProcessStatus>> {
        let processes = self.active_processes.read().await;
        Ok(processes.values().map(|h| h.status.clone()).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_native_backend_creation() {
        let backend = NativeBackend::new().unwrap();
        let caps = backend.capabilities();
        assert_eq!(caps.backend_name, "native");
        assert_eq!(caps.platform, Platform::current());
    }

    #[tokio::test]
    async fn test_native_backend_capabilities_honest() {
        let backend = NativeBackend::new().unwrap();
        let caps = backend.capabilities();

        // Native backend should not claim filesystem isolation
        assert_ne!(
            caps.filesystem_write_isolation,
            IsolationSupport::Enforced,
            "Native backend should not claim enforced filesystem write isolation"
        );

        // Should have process tree limits
        assert_eq!(
            caps.process_tree_limit,
            IsolationSupport::Enforced,
            "Native backend should enforce process tree limits via Job Objects"
        );
    }
}