//! Local transport - named pipe / Unix domain socket for desktop-to-daemon IPC

use runtime_core::error::{Error, Result};
use runtime_core::types::*;
use std::path::PathBuf;
use tokio::sync::RwLock;
use std::sync::Arc;

/// Local transport for IPC
pub struct LocalTransport {
    socket_path: Option<PathBuf>,
    is_running: Arc<RwLock<bool>>,
}

impl LocalTransport {
    pub fn new() -> Self {
        Self {
            socket_path: None,
            is_running: Arc::new(RwLock::new(false)),
        }
    }

    pub fn with_socket_path(mut self, path: PathBuf) -> Self {
        self.socket_path = Some(path);
        self
    }

    pub async fn start(&self) -> Result<()> {
        let mut running = self.is_running.write().await;
        *running = true;
        Ok(())
    }

    pub async fn stop(&self) -> Result<()> {
        let mut running = self.is_running.write().await;
        *running = false;
        Ok(())
    }

    pub async fn is_running(&self) -> bool {
        *self.is_running.read().await
    }
}

impl Default for LocalTransport {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_local_transport() {
        let transport = LocalTransport::new();
        assert!(!transport.is_running().await);
        transport.start().await.unwrap();
        assert!(transport.is_running().await);
        transport.stop().await.unwrap();
        assert!(!transport.is_running().await);
    }
}