//! Arapuca sandbox backend integration
//!
//! This is a wrapper around the Arapuca crate. Arapuca is not yet added
//! as a dependency pending Phase 0 license and compatibility verification.
//! See ADR-001 for details.

use runtime_backend_api::*;
use runtime_core::error::{Error, Result};
use runtime_core::types::*;
use runtime_core::platform::*;
use std::path::PathBuf;

/// Arapuca backend wrapper
#[derive(Clone)]
pub struct ArapucaBackend {
    arapuca_available: bool,
    capabilities: BackendCapabilities,
}

impl ArapucaBackend {
    pub fn new() -> Result<Self> {
        // Arapuca crate not yet linked - this is a stub
        // Phase 0 will add the actual dependency
        let arapuca_available = false; // Will be true after dependency is added

        let capabilities = BackendCapabilities {
            backend_name: "arapuca".to_string(),
            platform: Platform::current(),
            architecture: Architecture::current(),
            filesystem_write_isolation: IsolationSupport::Unavailable,
            filesystem_read_isolation: IsolationSupport::Unavailable,
            network_isolation: IsolationSupport::Unavailable,
            process_tree_limit: IsolationSupport::Unavailable,
            memory_limit: IsolationSupport::Unavailable,
            cpu_limit: IsolationSupport::Unavailable,
            interactive_terminal: true,
            required_privileges: vec![],
            unsupported_policy_fields: vec!["arapuca_backend_not_linked".to_string()],
            overall: OverallIsolation::None,
        };

        Ok(Self {
            arapuca_available,
            capabilities,
        })
    }
}

impl Default for ArapucaBackend {
    fn default() -> Self {
        Self::new().expect("Failed to create Arapuca backend")
    }
}

#[async_trait::async_trait]
impl ExecutionBackend for ArapucaBackend {
    fn name(&self) -> &'static str {
        "arapuca"
    }

    fn clone_box(&self) -> Box<dyn ExecutionBackend> {
        Box::new(self.clone())
    }

    fn capabilities(&self) -> BackendCapabilities {
        self.capabilities.clone()
    }

    async fn prepare(&self, request: ExecutionRequest) -> Result<PreparedExecution> {
        if !self.arapuca_available {
            return Err(Error::SandboxUnavailable(
                "Arapuca backend not linked. Run Phase 0 evaluation first.".to_string(),
            ));
        }

        let enforcement_report = EnforcementReport {
            backend: "arapuca".to_string(),
            requested_profile: request.profile,
            applied_isolation: IsolationLevel::StrongIsolation,
            filesystem_write: IsolationSupport::Enforced,
            filesystem_read: IsolationSupport::Enforced,
            network: IsolationSupport::Enforced,
            process_tree: IsolationSupport::Enforced,
            memory: IsolationSupport::Enforced,
            cpu: IsolationSupport::Enforced,
            warnings: Vec::new(),
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

    async fn spawn(&self, _prepared: PreparedExecution) -> Result<ProcessHandle> {
        Err(Error::SandboxUnavailable(
            "Arapuca backend not linked".to_string(),
        ))
    }

    async fn inspect(&self, _id: ProcessId) -> Result<ProcessStatus> {
        Err(Error::ProcessNotFound(format!("Process {}", _id)))
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
    async fn test_arapuca_backend_not_available() {
        let backend = ArapucaBackend::new().unwrap();
        assert!(!backend.arapuca_available);
        let caps = backend.capabilities();
        assert_eq!(caps.overall, OverallIsolation::None);
    }
}