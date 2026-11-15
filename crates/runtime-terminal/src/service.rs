//! Terminal service implementation

use runtime_core::error::{Error, Result};
use runtime_core::types::*;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Terminal service trait
#[async_trait::async_trait]
pub trait TerminalService: Send + Sync {
    async fn open(&self, session_id: SessionId, project_id: ProjectId, rows: u16, cols: u16) -> Result<TerminalId>;
    async fn write(&self, id: TerminalId, data: Vec<u8>) -> Result<()>;
    async fn read(&self, id: TerminalId) -> Result<Vec<u8>>;
    async fn resize(&self, id: TerminalId, rows: u16, cols: u16) -> Result<()>;
    async fn close(&self, id: TerminalId) -> Result<()>;
}

/// Terminal session info
#[derive(Debug, Clone)]
pub struct TerminalSessionInfo {
    pub id: TerminalId,
    pub session_id: SessionId,
    pub project_id: ProjectId,
    pub rows: u16,
    pub cols: u16,
    pub created_at: DateTime<Utc>,
    pub is_active: bool,
}

/// Terminal service implementation
#[derive(Clone, Default)]
pub struct TerminalServiceImpl {
    sessions: Arc<RwLock<HashMap<TerminalId, TerminalSessionInfo>>>,
}

impl TerminalServiceImpl {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait::async_trait]
impl TerminalService for TerminalServiceImpl {
    async fn open(&self, session_id: SessionId, project_id: ProjectId, rows: u16, cols: u16) -> Result<TerminalId> {
        let id = TerminalId::new();
        let info = TerminalSessionInfo {
            id,
            session_id,
            project_id,
            rows,
            cols,
            created_at: chrono::Utc::now(),
            is_active: true,
        };
        self.sessions.write().await.insert(id, info);
        Ok(id)
    }

    async fn write(&self, _id: TerminalId, _data: Vec<u8>) -> Result<()> {
        Err(Error::NotImplemented("Terminal write not yet implemented".to_string()))
    }

    async fn read(&self, _id: TerminalId) -> Result<Vec<u8>> {
        Err(Error::NotImplemented("Terminal read not yet implemented".to_string()))
    }

    async fn resize(&self, _id: TerminalId, _rows: u16, _cols: u16) -> Result<()> {
        Err(Error::NotImplemented("Terminal resize not yet implemented".to_string()))
    }

    async fn close(&self, _id: TerminalId) -> Result<()> {
        Ok(())
    }
}