//! Resource limits for process execution

use runtime_core::types::ResourceUsage;

/// Resource limits applied to a process
#[derive(Debug, Clone, Default)]
pub struct ResourceLimits {
    pub max_runtime_seconds: Option<u64>,
    pub max_processes: Option<u32>,
    pub memory_limit_mb: Option<u64>,
    pub cpu_limit_percent: Option<u32>,
    pub max_output_bytes: Option<u64>,
}

impl ResourceLimits {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_runtime(mut self, seconds: u64) -> Self {
        self.max_runtime_seconds = Some(seconds);
        self
    }

    pub fn with_memory(mut self, mb: u64) -> Self {
        self.memory_limit_mb = Some(mb);
        self
    }

    pub fn with_processes(mut self, max: u32) -> Self {
        self.max_processes = Some(max);
        self
    }

    pub fn with_output(mut self, bytes: u64) -> Self {
        self.max_output_bytes = Some(bytes);
        self
    }
}

/// Check if resource usage exceeds limits
pub fn check_limits(usage: &ResourceUsage, limits: &ResourceLimits) -> bool {
    if let Some(memory_limit_mb) = limits.memory_limit_mb {
        let usage_mb = usage.memory_bytes / (1024 * 1024);
        if usage_mb > memory_limit_mb {
            return false;
        }
    }

    if let Some(max_processes) = limits.max_processes {
        if usage.process_count > max_processes {
            return false;
        }
    }

    true
}

/// Platform-specific resource limit application
pub fn apply_limits(os_pid: u32, limits: &ResourceLimits) -> runtime_core::error::Result<()> {
    #[cfg(target_os = "linux")]
    {
        use nix::sys::resource::{setrlimit, Resource};
        use nix::sys::resource::{RLIMIT_AS, RLIMIT_CPU};

        if let Some(memory_limit_mb) = limits.memory_limit_mb {
            let bytes = memory_limit_mb * 1024 * 1024;
            setrlimit(RLIMIT_AS, nix::sys::resource::Rlimit {
                rlim_cur: bytes,
                rlim_max: bytes,
            }).map_err(|e| runtime_core::error::Error::ResourceLimit(format!(
                "Failed to set memory limit: {}", e
            )))?;
        }

        if let Some(seconds) = limits.max_runtime_seconds {
            setrlimit(RLIMIT_CPU, nix::sys::resource::Rlimit {
                rlim_cur: seconds,
                rlim_max: seconds,
            }).map_err(|e| runtime_core::error::Error::ResourceLimit(format!(
                "Failed to set CPU limit: {}", e
            )))?;
        }
    }

    #[cfg(windows)]
    {
        // Windows uses Job Objects for resource limits
        // This is handled in backend-windows
        let _ = os_pid;
        let _ = limits;
    }

    #[cfg(target_os = "macos")]
    {
        // macOS uses rlimit or sandbox
        let _ = os_pid;
        let _ = limits;
    }

    Ok(())
}

/// Check if a process has exceeded its runtime limit
pub fn is_runtime_exceeded(started_at: chrono::DateTime<chrono::Utc>, max_seconds: u64) -> bool {
    let elapsed = chrono::Utc::now().signed_duration_since(started_at);
    elapsed.num_seconds() > max_seconds as i64
}