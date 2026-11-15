//! Windows Job Objects support
//!
//! Job Objects provide process-tree lifetime, CPU, and memory controls.

use runtime_core::types::ProcessId;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Job Object handle
#[derive(Debug)]
pub struct JobObject {
    #[cfg(windows)]
    handle: windows::Win32::Foundation::HANDLE,
    #[cfg(not(windows))]
    handle: usize,
    name: Option<String>,
}

/// Job Object limits
#[derive(Debug, Clone, Default)]
pub struct JobObjectLimits {
    pub max_cpu_time_ms: Option<u64>,
    pub max_memory_bytes: Option<u64>,
    pub max_process_count: Option<u32>,
    pub kill_on_job_close: bool,
}

/// Job Object manager
pub struct JobObjectManager {
    jobs: Arc<RwLock<Vec<JobObject>>>,
}

impl JobObjectManager {
    pub fn new() -> Self {
        Self {
            jobs: Arc::new(RwLock::new(Vec::new())),
        }
    }

    pub async fn create_job(&self, name: Option<String>, limits: JobObjectLimits) -> runtime_core::error::Result<JobObject> {
        #[cfg(windows)]
        {
            use windows::Win32::Foundation::CloseHandle;
            use windows::Win32::Foundation::HANDLE;
            use windows::Win32::System::Threading::CreateJobObjectW;
            use windows::Win32::System::Threading::SetInformationJobObject;
            use windows::Win32::System::Threading::JobObjectExtendedLimitInformation;

            unsafe {
                let job = CreateJobObjectW(None, name.as_deref()).map_err(|e| {
                    crate::error::Error::Sandbox(format!("Failed to create Job Object: {}", e))
                })?;
                Ok(JobObject { handle: job as isize, name })
            }
        }

        #[cfg(not(windows))]
        {
            let _ = name;
            let _ = limits;
            Err(crate::error::Error::SandboxUnavailable(
                "Job Objects only available on Windows".to_string(),
            ))
        }
    }

    pub async fn assign_process(&self, job: &JobObject, os_pid: u32) -> runtime_core::error::Result<()> {
        #[cfg(windows)]
        {
            use windows::Win32::System::Threading::AssignProcessToJobObject;
            use windows::Win32::System::Threading::OpenProcess;
            use windows::Win32::System::Threading::PROCESS_ALL_ACCESS;

            unsafe {
                let process = OpenProcess(PROCESS_ALL_ACCESS, false, os_pid).map_err(|e| {
                    crate::error::Error::Process(format!("Failed to open process: {}", e))
                })?;
                let _ = AssignProcessToJobObject(job.handle as _, process);
                let _ = windows::Win32::Foundation::CloseHandle(process);
            }
            Ok(())
        }

        #[cfg(not(windows))]
        {
            let _ = job;
            let _ = os_pid;
            Err(crate::error::Error::SandboxUnavailable(
                "Job Objects only available on Windows".to_string(),
            ))
        }
    }

    pub async fn terminate_job(&self, job: &JobObject) -> runtime_core::error::Result<()> {
        #[cfg(windows)]
        {
            use windows::Win32::System::Threading::TerminateJobObject;
            unsafe {
                let _ = TerminateJobObject(job.handle as _, 1);
            }
            Ok(())
        }

        #[cfg(not(windows))]
        {
            let _ = job;
            Err(crate::error::Error::SandboxUnavailable(
                "Job Objects only available on Windows".to_string(),
            ))
        }
    }
}

impl Default for JobObjectManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_job_object_manager_creation() {
        let manager = JobObjectManager::new();
        let _limits = JobObjectLimits::default();
        // Can't create actual job objects in test environment
    }
}