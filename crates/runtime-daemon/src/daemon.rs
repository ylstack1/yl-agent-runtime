//! Runtime daemon implementation
//!
//! Coordinates all services: policy, workspace, process, terminal, audit,
//! identity, approval, and execution backends.

use backend_native::NativeBackend;
use runtime_approval::ApprovalBroker;
use runtime_audit::AuditService;
use runtime_core::error::{Error, Result};
use runtime_core::traits::*;
use runtime_core::types::*;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Runtime daemon - coordinates all services
pub struct RuntimeDaemon {
    config: Arc<runtime_config::Config>,
    policy_engine: Arc<dyn PolicyEngine>,
    workspace_service: Arc<dyn WorkspaceService>,
    process_service: Arc<dyn runtime_process::ProcessServiceOps>,
    terminal_service: Arc<dyn runtime_terminal::TerminalService>,
    toolchain_discovery: runtime_toolchain::ToolchainDiscovery,
    audit_service: Arc<dyn AuditService>,
    identity_service: Arc<dyn runtime_identity::IdentityService>,
    approval_broker: Arc<dyn ApprovalBroker>,
    sessions: Arc<RwLock<std::collections::HashMap<SessionId, runtime_core::session::Session>>>,
    backends: Arc<RwLock<Vec<Box<dyn runtime_backend_api::ExecutionBackend>>>>,
}

impl RuntimeDaemon {
    pub fn new(config: runtime_config::Config) -> Result<Self> {
        // Register the native host backend (trusted local, ExecutionProfile
        // maps to Development) before the daemon is assembled.
        let backends: Vec<Box<dyn runtime_backend_api::ExecutionBackend>> =
            vec![Box::new(NativeBackend::new()?)];

        Ok(Self {
            config: Arc::new(config),
            policy_engine: Arc::new(runtime_policy::PolicyEngineImpl::new()),
            workspace_service: Arc::new(runtime_workspace::WorkspaceServiceImpl::new()),
            process_service: Arc::new(runtime_process::ProcessService::new()),
            terminal_service: Arc::new(runtime_terminal::TerminalServiceImpl::new()),
            toolchain_discovery: runtime_toolchain::ToolchainDiscovery::new(),
            audit_service: Arc::new(runtime_audit::AuditServiceImpl::new()),
            identity_service: Arc::new(runtime_identity::IdentityServiceImpl::new()),
            approval_broker: Arc::new(runtime_approval::ApprovalBrokerImpl::new()),
            sessions: Arc::new(RwLock::new(std::collections::HashMap::new())),
            backends: Arc::new(RwLock::new(backends)),
        })
    }

    pub async fn register_backend(&self, backend: Box<dyn runtime_backend_api::ExecutionBackend>) {
        self.backends.write().await.push(backend);
    }

    pub async fn get_backend_capabilities(&self) -> Result<Vec<runtime_core::types::BackendCapabilities>> {
        let backends = self.backends.read().await;
        Ok(backends.iter().map(|b| b.capabilities()).collect())
    }

    pub async fn select_backend(&self, profile: ExecutionProfile) -> Result<Box<dyn runtime_backend_api::ExecutionBackend>> {
        let backends = self.backends.read().await;

        // Select backend based on profile and availability
        // Per PRD section 9.5: trusted local -> native, unknown -> sandbox, hostile -> VM
        match profile {
            ExecutionProfile::SandboxedDevelopment => {
                // Look for sandbox backend first
                for backend in backends.iter() {
                    let name = backend.name();
                    if name == "windows" || name == "linux" || name == "macos" || name == "arapuca" {
                        return Ok(backend.clone_box());
                    }
                }
                // Fall back to native if no sandbox available (fail-closed: return error if no sandbox)
                for backend in backends.iter() {
                    if backend.name() == "native" {
                        return Err(Error::SandboxUnavailable(
                            "Sandboxed development requested but no OS sandbox backend available; \
                             native backend does not provide sandbox isolation".to_string(),
                        ));
                    }
                }
            }
            _ => {
                // Default to native backend for trusted profiles
                for backend in backends.iter() {
                    if backend.name() == "native" {
                        return Ok(backend.clone_box());
                    }
                }
            }
        }

        Err(Error::SandboxUnavailable("No suitable backend available".to_string()))
    }

    pub async fn start(&self) -> Result<()> {
        tracing::info!("YL Agent Runtime daemon starting");
        Ok(())
    }

    pub async fn stop(&self) -> Result<()> {
        tracing::info!("YL Agent Runtime daemon stopping");
        // Terminate all active processes
        Ok(())
    }
}

impl Default for RuntimeDaemon {
    fn default() -> Self {
        Self::new(runtime_config::Config::default()).expect("Failed to create daemon")
    }
}