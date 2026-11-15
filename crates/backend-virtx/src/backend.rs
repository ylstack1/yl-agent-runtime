//! Virtx VM backend stub
//!
//! Deferred to Phase 5. VM execution is optional, isolated from the core,
//! and never silently substituted for native execution per PRD section 9.4.

use runtime_backend_api::*;
use runtime_core::error::{Error, Result};
use runtime_core::types::*;
use runtime_core::platform::*;
use std::path::PathBuf;

/// Virtx VM backend stub
#[derive(Clone)]
pub struct VirtxBackend {
    capabilities: BackendCapabilities,
}

impl VirtxBackend {
    pub fn new() -> Result<Self> {
        let capabilities = BackendCapabilities {
            backend_name: "virtx".to_string(),
            platform: Platform::current(),
            architecture: Architecture::current(),
            filesystem_write_isolation: IsolationSupport::Unavailable,
            filesystem_read_isolation: IsolationSupport::Unavailable,
            network_isolation: IsolationSupport::Unavailable,
            process_tree_limit: IsolationSupport::Unavailable,
            memory_limit: IsolationSupport::Unavailable,
            cpu_limit: IsolationSupport::Unavailable,
            interactive_terminal: false,
            required_privileges: vec!["kvm".to_string(), "virtualization".to_string()],
            unsupported_policy_fields: vec!["virtx_backend_not_implemented".to_string()],
            overall: OverallIsolation::None,
        };

        Ok(Self { capabilities })
    }
}

impl Default for VirtxBackend {
    fn default() -> Self {
        Self::new().expect("Failed to create Virtx backend")
    }
}

#[async_trait::async_trait]
impl ExecutionBackend for VirtxBackend {
    fn name(&self) -> &'static str {
        "virtx"
    }

    fn clone_box(&self) -> Box<dyn ExecutionBackend> {
        Box::new(self.clone())
    }

    fn capabilities(&self) -> BackendCapabilities {
        self.capabilities.clone()
    }

    async fn prepare(&self, _request: ExecutionRequest) -> Result<PreparedExecution> {
        Err(Error::NotImplemented(
            "Virtx VM backend not yet implemented (Phase 5)".to_string(),
        ))
    }

    async fn spawn(&self, _prepared: PreparedExecution) -> Result<ProcessHandle> {
        Err(Error::NotImplemented(
            "Virtx VM backend not yet implemented (Phase 5)".to_string(),
        ))
    }

    async fn inspect(&self, _id: ProcessId) -> Result<ProcessStatus> {
        Err(Error::NotImplemented(
            "Virtx VM backend not yet implemented (Phase 5)".to_string(),
        ))
    }

    async fn terminate(&self, _id: ProcessId, _mode: TerminationMode) -> Result<()> {
        Ok(())
    }

    async fn list_processes(&self) -> Result<Vec<ProcessStatus>> {
        Ok(Vec::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_virtx_backend_not_implemented() {
        let backend = VirtxBackend::new().unwrap();
        let caps = backend.capabilities();
        assert_eq!(caps.overall, OverallIsolation::None);
    }
}