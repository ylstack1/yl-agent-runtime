//! Remote transport - optional Iroh-based peer-to-peer connectivity
//!
//! Disabled by default per PRD section 14. Remote access is opt-in,
//! authenticated, and revocable.

use runtime_core::error::{Error, Result};
use runtime_core::types::*;

/// Remote transport configuration
#[derive(Debug, Clone)]
pub struct RemoteTransportConfig {
    pub enabled: bool,
    pub pairing_required: bool,
    pub session_timeout_seconds: u64,
}

/// Remote transport stub
pub struct RemoteTransport {
    config: RemoteTransportConfig,
    is_running: bool,
}

impl RemoteTransport {
    pub fn new() -> Self {
        Self {
            config: RemoteTransportConfig {
                enabled: false,
                pairing_required: true,
                session_timeout_seconds: 3600,
            },
            is_running: false,
        }
    }

    pub fn with_config(mut self, config: RemoteTransportConfig) -> Self {
        self.config = config;
        self
    }

    pub async fn start(&mut self) -> Result<()> {
        if !self.config.enabled {
            return Err(Error::SandboxUnavailable(
                "Remote transport is disabled. Enable it in configuration.".to_string(),
            ));
        }
        self.is_running = true;
        Ok(())
    }

    pub async fn stop(&mut self) -> Result<()> {
        self.is_running = false;
        Ok(())
    }

    pub fn is_running(&self) -> bool {
        self.is_running
    }
}

impl Default for RemoteTransport {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_remote_transport_disabled_by_default() {
        let mut transport = RemoteTransport::new();
        assert!(!transport.is_running());
        let result = transport.start().await;
        assert!(result.is_err());
    }
}