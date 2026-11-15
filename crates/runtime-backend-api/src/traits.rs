//! Backend API traits

use crate::types::*;
use runtime_core::error::Result;
use runtime_core::types::*;
use async_trait::async_trait;

/// Execution backend trait - stable boundary per PRD section 9.1
#[async_trait]
pub trait ExecutionBackend: Send + Sync {
    fn name(&self) -> &'static str;
    fn capabilities(&self) -> BackendCapabilities;
    /// Clone this backend into a new Box<dyn ExecutionBackend>
    fn clone_box(&self) -> Box<dyn ExecutionBackend>;
    async fn prepare(&self, request: ExecutionRequest) -> Result<PreparedExecution>;
    async fn spawn(&self, prepared: PreparedExecution) -> Result<ProcessHandle>;
    async fn inspect(&self, id: ProcessId) -> Result<ProcessStatus>;
    async fn terminate(&self, id: ProcessId, mode: TerminationMode) -> Result<()>;
    async fn list_processes(&self) -> Result<Vec<ProcessStatus>>;
}

/// Backend factory for creating backend instances
#[async_trait]
pub trait BackendFactory: Send + Sync {
    type Backend: ExecutionBackend;
    async fn create(&self) -> Result<Self::Backend>;
}