//! Process service implementation

use crate::limits::ResourceLimits;
use crate::supervisor::ProcessTreeSupervisor;
use crate::{ProcessExecutor, resolve_executable};
use runtime_core::error::{Error, Result};
use runtime_core::traits::*;
use runtime_core::types::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};

/// Process output
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessOutput {
    pub id: ProcessId,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub exit_status: Option<ExitStatus>,
    pub truncated: bool,
}

/// A running process tracked by the runtime
#[derive(Debug)]
pub struct TrackedProcess {
    pub id: ProcessId,
    pub os_pid: u32,
    pub request: ExecutionRequest,
    pub started_at: DateTime<Utc>,
    pub status: ProcessStatus,
    /// Handle to the spawned child process (kept behind a Mutex so the
    /// service can wait on / terminate it after spawning).
    pub handle: Arc<tokio::sync::Mutex<Option<std::process::Child>>>,
}

impl Clone for TrackedProcess {
    fn clone(&self) -> Self {
        Self {
            id: self.id,
            os_pid: self.os_pid,
            request: self.request.clone(),
            started_at: self.started_at,
            status: self.status.clone(),
            handle: self.handle.clone(),
        }
    }
}

/// Process service implementation
#[derive(Clone)]
pub struct ProcessService {
    processes: Arc<RwLock<HashMap<ProcessId, TrackedProcess>>>,
    supervisor: Arc<ProcessTreeSupervisor>,
}

impl ProcessService {
    pub fn new() -> Self {
        Self {
            processes: Arc::new(RwLock::new(HashMap::new())),
            supervisor: Arc::new(ProcessTreeSupervisor::new()),
        }
    }

    async fn get_process(&self, id: ProcessId) -> Result<TrackedProcess> {
        let processes = self.processes.read().await;
        processes
            .get(&id)
            .cloned()
            .ok_or_else(|| Error::ProcessNotFound(format!("Process {}", id)))
    }
}

impl Default for ProcessService {
    fn default() -> Self {
        Self::new()
    }
}

/// Trait for process service operations
#[async_trait::async_trait]
pub trait ProcessServiceOps: Send + Sync {
    async fn exec(&self, request: ExecutionRequest) -> Result<ProcessHandle>;
    async fn start(&self, request: ExecutionRequest) -> Result<ProcessHandle>;
    async fn wait(&self, id: ProcessId) -> Result<ExitStatus>;
    async fn output(&self, id: ProcessId) -> Result<ProcessOutput>;
    async fn status(&self, id: ProcessId) -> Result<ProcessStatus>;
    async fn terminate(&self, id: ProcessId, mode: TerminationMode) -> Result<()>;
    async fn list(&self) -> Result<Vec<ProcessStatus>>;
    async fn resource_usage(&self, id: ProcessId) -> Result<ResourceUsage>;
}

#[async_trait::async_trait]
impl ProcessServiceOps for ProcessService {
    async fn exec(&self, request: ExecutionRequest) -> Result<ProcessHandle> {
        // Execute and wait for completion
        let handle = self.start(request.clone()).await?;
        let exit_status = self.wait(handle.id).await?;
        let status = ProcessStatus {
            id: handle.id,
            os_pid: handle.os_pid,
            running: false,
            exit_status: Some(exit_status),
            resource_usage: ResourceUsage::default(),
            started_at: chrono::Utc::now(),
        };
        Ok(ProcessHandle {
            id: handle.id,
            os_pid: handle.os_pid,
            status,
        })
    }

    async fn start(&self, request: ExecutionRequest) -> Result<ProcessHandle> {
        let program = request
            .executable
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("");

        // Executable allowlist (name only, no path separators).
        let executor = ProcessExecutor::new();
        if !executor.is_allowed(program) {
            return Err(Error::PolicyViolation(format!(
                "executable not in allowlist: {program}"
            )));
        }

        // Environment security: deny-listed server-env vars are a hard error;
        // the whitelisted subset becomes the child's environment.
        let environment = executor.build_env()?;

        // Resolve through PATH (bare names only; no absolute paths).
        let exe = resolve_executable(program)?;

        let id = request.id;

        // Build the child process
        let mut cmd = std::process::Command::new(&exe);
        cmd.args(&request.arguments);
        cmd.current_dir(&request.working_directory);
        cmd.envs(environment);

        // Platform-specific process setup
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            // Prevent new window, inherit handles
            cmd.creation_flags(0x00000200); // CREATE_NO_WINDOW
        }

        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            // Process group for tree management
            cmd.process_group(0);
        }

        let child = cmd.spawn().map_err(|e| Error::Process(format!(
            "Failed to spawn process: {}", e
        )))?;

        let os_pid = child.id();
        let handle = Arc::new(Mutex::new(Some(child)));

        // Register with supervisor
        self.supervisor.add_process(id, os_pid).await;

        let status = ProcessStatus {
            id,
            os_pid,
            running: true,
            exit_status: None,
            resource_usage: ResourceUsage::default(),
            started_at: chrono::Utc::now(),
        };

        let tracked = TrackedProcess {
            id,
            os_pid,
            request,
            started_at: status.started_at,
            status: status.clone(),
            handle,
        };

        self.processes.write().await.insert(id, tracked);

        Ok(ProcessHandle {
            id,
            os_pid,
            status,
        })
    }

    async fn wait(&self, id: ProcessId) -> Result<ExitStatus> {
        let mut processes = self.processes.write().await;
        let tracked = processes
            .get_mut(&id)
            .ok_or_else(|| Error::ProcessNotFound(format!("Process {}", id)))?;

        let mut guard = tracked.handle.lock().await;
        let mut child = guard
            .take()
            .ok_or_else(|| Error::Process(format!("Process {} has no running handle", id)))?;
        let exit_status = child
            .wait()
            .map_err(|e| Error::Process(format!("Failed to wait for process: {}", e)))?;

        let status = ExitStatus::from_code(exit_status.code().unwrap_or(-1));

        tracked.status.running = false;
        tracked.status.exit_status = Some(status.clone());

        Ok(status)
    }

    async fn output(&self, id: ProcessId) -> Result<ProcessOutput> {
        let process = self.get_process(id).await?;
        // In a full implementation, we'd capture stdout/stderr
        // For now, return what we have
        Ok(ProcessOutput {
            id,
            stdout: Vec::new(),
            stderr: Vec::new(),
            exit_status: process.status.exit_status,
            truncated: false,
        })
    }

    async fn status(&self, id: ProcessId) -> Result<ProcessStatus> {
        let process = self.get_process(id).await?;
        Ok(process.status)
    }

    async fn terminate(&self, id: ProcessId, mode: TerminationMode) -> Result<()> {
        let mut processes = self.processes.write().await;
        let tracked = processes
            .get_mut(&id)
            .ok_or_else(|| Error::ProcessNotFound(format!("Process {}", id)))?;

        match mode {
            TerminationMode::Graceful | TerminationMode::Force => {
                let mut guard = tracked.handle.lock().await;
                if let Some(mut child) = guard.take() {
                    child.kill().map_err(|e| {
                        Error::Process(format!("Failed to terminate process: {}", e))
                    })?;
                }
            }
            TerminationMode::ProcessTree => {
                self.supervisor.terminate_tree(id).await?;
                let mut guard = tracked.handle.lock().await;
                if let Some(mut child) = guard.take() {
                    child.kill().map_err(|e| {
                        Error::Process(format!("Failed to kill process tree: {}", e))
                    })?;
                }
            }
        }

        tracked.status.running = false;
        Ok(())
    }

    async fn list(&self) -> Result<Vec<ProcessStatus>> {
        let processes = self.processes.read().await;
        Ok(processes.values().map(|p| p.status.clone()).collect())
    }

    async fn resource_usage(&self, id: ProcessId) -> Result<ResourceUsage> {
        let process = self.get_process(id).await?;
        Ok(process.status.resource_usage.clone())
    }
}