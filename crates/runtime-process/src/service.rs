//! Process service implementation

use crate::cursor::{CursorLog, ReadPage, StreamId};
use crate::supervisor::ProcessTreeSupervisor;
use crate::{ProcessExecutor, resolve_executable};
use runtime_core::error::{Error, Result};
use runtime_core::traits::*;
use runtime_core::types::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
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
    /// Handle to the spawned child process (taken by `wait` when it needs to
    /// block on exit, and by `terminate`).
    pub handle: Arc<tokio::sync::Mutex<Option<tokio::process::Child>>>,
    /// Cursor-paged output log; reader tasks append each output line here.
    pub log: Arc<CursorLog>,
    /// Child stdin, kept open so `process.interact` can feed a running process.
    pub stdin: Arc<tokio::sync::Mutex<Option<tokio::process::ChildStdin>>>,
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
            log: self.log.clone(),
            stdin: self.stdin.clone(),
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
    /// Cursor-paged read of captured stdout/stderr. `after` is the last
    /// sequence the caller has already seen; `wait_ms` > 0 blocks until new
    /// output arrives or the wait elapses.
    async fn read_output(
        &self,
        id: ProcessId,
        after: u64,
        limit_bytes: usize,
        wait_ms: u64,
    ) -> Result<ReadPage>;
    /// Write `data` to the process's stdin. `close` drops stdin afterwards so
    /// a child waiting on EOF can finish.
    async fn write_stdin(&self, id: ProcessId, data: &str, close: bool) -> Result<()>;
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
            let allowed: Vec<String> = crate::ALLOWED_TOOLS
                .iter()
                .map(|tool| tool.to_string())
                .collect();
            return Err(Error::PolicyViolation(crate::allowlist_error(program, &allowed)));
        }

        // Environment security: deny-listed server-env vars are a hard error;
        // the whitelisted subset becomes the child's environment.
        let environment = executor.build_env()?;

        // Resolve through PATH (bare names only; no absolute paths).
        let exe = resolve_executable(program)?;

        let id = request.id;

        // Build the child process. stdin/stdout/stderr are piped so output is
        // captured into the cursor log instead of leaking into the server's
        // own console, and so `process.interact` can feed a running child.
        let mut cmd = tokio::process::Command::new(&exe);
        cmd.args(&request.arguments);
        cmd.current_dir(&request.working_directory);
        cmd.env_clear();
        cmd.envs(environment);
        cmd.stdin(Stdio::piped());
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());

        // Platform-specific process setup
        #[cfg(windows)]
        {
            // Prevent a console window; the child still gets the piped stdio.
            cmd.creation_flags(0x0000_0200); // CREATE_NO_WINDOW
        }

        #[cfg(unix)]
        {
            #[allow(unused_imports)]
            use std::os::unix::process::CommandExt;
            // Process group for tree management
            cmd.process_group(0);
        }

        let mut child = cmd.spawn().map_err(|e| Error::Process(format!(
            "Failed to spawn process: {}", e
        )))?;

        let os_pid = child.id().unwrap_or(0);
        let log = Arc::new(CursorLog::new());

        if let Some(stdout) = child.stdout.take() {
            spawn_stream_reader(stdout, log.clone(), StreamId::Stdout);
        }
        if let Some(stderr) = child.stderr.take() {
            spawn_stream_reader(stderr, log.clone(), StreamId::Stderr);
        }
        let stdin = Arc::new(Mutex::new(child.stdin.take()));
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
            handle: handle.clone(),
            log,
            stdin,
        };

        self.processes.write().await.insert(id, tracked);
        spawn_exit_watcher(self.processes.clone(), id, handle);

        Ok(ProcessHandle {
            id,
            os_pid,
            status,
        })
    }

    async fn wait(&self, id: ProcessId) -> Result<ExitStatus> {
        // Take the child out under the lock, then await outside it so a long
        // wait does not block `process.list` / `process.read`.
        let child = {
            let processes = self.processes.read().await;
            let tracked = processes
                .get(&id)
                .ok_or_else(|| Error::ProcessNotFound(format!("Process {}", id)))?;
            if let Some(status) = tracked.status.exit_status.clone() {
                return Ok(status);
            }
            let mut guard = tracked.handle.lock().await;
            guard.take()
        };

        let Some(mut child) = child else {
            // The exit watcher reaped it between the status check and the take.
            let processes = self.processes.read().await;
            let tracked = processes
                .get(&id)
                .ok_or_else(|| Error::ProcessNotFound(format!("Process {}", id)))?;
            return tracked
                .status
                .exit_status
                .clone()
                .ok_or_else(|| Error::Process(format!("Process {} has no running handle", id)));
        };

        let exit_status = child
            .wait()
            .await
            .map_err(|e| Error::Process(format!("Failed to wait for process: {}", e)))?;

        let status = ExitStatus::from_code(exit_status.code().unwrap_or(-1));

        if let Some(tracked) = self.processes.write().await.get_mut(&id) {
            tracked.status.running = false;
            tracked.status.exit_status = Some(status.clone());
        }

        Ok(status)
    }

    async fn output(&self, id: ProcessId) -> Result<ProcessOutput> {
        let process = self.get_process(id).await?;
        let page = process.log.read_after(0, usize::MAX, 0).await;
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        for chunk in page.chunks {
            match chunk.stream {
                StreamId::Stdout => stdout.extend_from_slice(chunk.text.as_bytes()),
                StreamId::Stderr => stderr.extend_from_slice(chunk.text.as_bytes()),
            }
        }
        Ok(ProcessOutput {
            id,
            stdout,
            stderr,
            exit_status: process.status.exit_status,
            truncated: false,
        })
    }

    async fn read_output(
        &self,
        id: ProcessId,
        after: u64,
        limit_bytes: usize,
        wait_ms: u64,
    ) -> Result<ReadPage> {
        let process = self.get_process(id).await?;
        Ok(process
            .log
            .read_after(after, limit_bytes.max(1), wait_ms)
            .await)
    }

    async fn write_stdin(&self, id: ProcessId, data: &str, close: bool) -> Result<()> {
        let process = self.get_process(id).await?;
        let mut guard = process.stdin.lock().await;
        let Some(stdin) = guard.as_mut() else {
            return Err(Error::Process(format!(
                "Process {} stdin is closed",
                id
            )));
        };
        stdin
            .write_all(data.as_bytes())
            .await
            .map_err(|e| Error::Process(format!("Failed to write to stdin: {}", e)))?;
        stdin
            .flush()
            .await
            .map_err(|e| Error::Process(format!("Failed to flush stdin: {}", e)))?;
        if close {
            guard.take();
        }
        Ok(())
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
                    child.start_kill().map_err(|e| {
                        Error::Process(format!("Failed to terminate process: {}", e))
                    })?;
                }
            }
            TerminationMode::ProcessTree => {
                self.supervisor.terminate_tree(id).await?;
                let mut guard = tracked.handle.lock().await;
                if let Some(mut child) = guard.take() {
                    child.start_kill().map_err(|e| {
                        Error::Process(format!("Failed to kill process tree: {}", e))
                    })?;
                }
            }
        }

        // Closing stdin lets a child blocked on read see EOF.
        tracked.stdin.lock().await.take();
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

/// Pump one child stream into the process cursor log, one line per chunk, so
/// readers get line-aligned pages. The final partial line is flushed at EOF.
fn spawn_stream_reader<R>(reader: R, log: Arc<CursorLog>, stream: StreamId)
where
    R: tokio::io::AsyncRead + Unpin + Send + 'static,
{
    tokio::spawn(async move {
        let mut lines = BufReader::new(reader).lines();
        loop {
            match lines.next_line().await {
                Ok(Some(line)) => {
                    log.push(stream, format!("{line}\n")).await;
                }
                Ok(None) => break,
                Err(_) => break,
            }
        }
    });
}

/// Poll for child exit so `process.status` / `process.list` reflect reality
/// even when nobody called `process.wait`. Lock order is map-then-handle,
/// matching `wait` and `terminate`.
fn spawn_exit_watcher(
    processes: Arc<RwLock<HashMap<ProcessId, TrackedProcess>>>,
    id: ProcessId,
    handle: Arc<Mutex<Option<tokio::process::Child>>>,
) {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_millis(150)).await;
            let mut map = processes.write().await;
            let Some(tracked) = map.get_mut(&id) else {
                break;
            };
            if !tracked.status.running {
                break;
            }
            let mut guard = handle.lock().await;
            let Some(child) = guard.as_mut() else {
                break;
            };
            match child.try_wait() {
                Ok(Some(status)) => {
                    tracked.status.running = false;
                    tracked.status.exit_status =
                        Some(ExitStatus::from_code(status.code().unwrap_or(-1)));
                    guard.take();
                    break;
                }
                Ok(None) => {}
                Err(_) => break,
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cursor::StreamId;

    fn request(program: &str, args: &[&str]) -> ExecutionRequest {
        ExecutionRequest {
            id: ProcessId::new(),
            session_id: SessionId::new(),
            project_id: ProjectId::new(),
            agent_id: AgentId::new(),
            executable: PathBuf::from(program),
            arguments: args.iter().map(|arg| arg.to_string()).collect(),
            environment: HashMap::new(),
            working_directory: std::env::current_dir().expect("cwd"),
            profile: ExecutionProfile::Development,
            capabilities: vec![],
            max_runtime_seconds: Some(60),
            max_processes: None,
            memory_limit_mb: None,
            stdin_data: None,
        }
    }

    fn stdout_of(page: &crate::cursor::ReadPage) -> String {
        page.chunks
            .iter()
            .filter(|chunk| chunk.stream == StreamId::Stdout)
            .map(|chunk| chunk.text.as_str())
            .collect()
    }

    fn stderr_of(page: &crate::cursor::ReadPage) -> String {
        page.chunks
            .iter()
            .filter(|chunk| chunk.stream == StreamId::Stderr)
            .map(|chunk| chunk.text.as_str())
            .collect()
    }

    #[tokio::test]
    async fn start_captures_stdout_instead_of_leaking_it() {
        let service = ProcessService::new();
        let handle = service
            .start(request("git", &["--version"]))
            .await
            .expect("start git");
        service.wait(handle.id).await.expect("wait");

        let page = service
            .read_output(handle.id, 0, 64_000, 0)
            .await
            .expect("read output");

        let stdout = stdout_of(&page);
        assert!(
            stdout.to_lowercase().contains("git version"),
            "expected captured git version, got {stdout:?}"
        );
        assert!(page.next_after.unwrap_or(0) >= 1);
    }

    #[tokio::test]
    async fn read_output_pages_by_cursor() {
        let service = ProcessService::new();
        let code = "process.stdout.write('one\\ntwo\\nthree\\n')";
        let handle = service
            .start(request("node", &["-e", code]))
            .await
            .expect("start node");
        service.wait(handle.id).await.expect("wait");

        let first = service
            .read_output(handle.id, 0, 4, 0)
            .await
            .expect("first page");
        assert!(!first.chunks.is_empty(), "first page should carry a line");
        let cursor = first.next_after.expect("cursor after first page");
        assert!(first.truncated, "a 4-byte page cannot hold three lines");

        let rest = service
            .read_output(handle.id, cursor, 64_000, 0)
            .await
            .expect("second page");
        let text = stdout_of(&first) + &stdout_of(&rest);
        assert!(text.contains("one"), "first line missing: {text:?}");
        assert!(text.contains("two") && text.contains("three"), "paged lines missing: {text:?}");
    }

    #[tokio::test]
    async fn write_stdin_reaches_the_child() {
        let service = ProcessService::new();
        let code =
            "process.stdin.once('data', d => { process.stdout.write('echo:' + d.toString().trim()); process.exit(0); })";
        let handle = service
            .start(request("node", &["-e", code]))
            .await
            .expect("start node");
        service
            .write_stdin(handle.id, "hello\n", false)
            .await
            .expect("write stdin");
        service.wait(handle.id).await.expect("wait");

        let page = service
            .read_output(handle.id, 0, 64_000, 0)
            .await
            .expect("read output");
        assert!(
            stdout_of(&page).contains("echo:hello"),
            "child did not receive stdin: {:?}",
            stdout_of(&page)
        );
    }

    #[tokio::test]
    async fn wait_reports_exit_status_and_stderr() {
        let service = ProcessService::new();
        let code = "process.stderr.write('boom\\n'); process.exit(3)";
        let handle = service
            .start(request("node", &["-e", code]))
            .await
            .expect("start node");
        let status = service.wait(handle.id).await.expect("wait");
        assert_eq!(status.code, Some(3));

        let page = service
            .read_output(handle.id, 0, 64_000, 0)
            .await
            .expect("read output");
        assert!(stderr_of(&page).contains("boom"), "stderr missing");
    }
}