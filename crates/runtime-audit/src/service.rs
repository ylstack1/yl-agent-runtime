//! Audit service implementation

use runtime_core::audit::*;
use runtime_core::error::{Error, Result};
use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Audit service trait
#[async_trait::async_trait]
pub trait AuditService: Send + Sync {
    async fn record(&self, event: AuditEvent) -> Result<()>;
    async fn query(&self, filter: AuditFilter) -> Result<Vec<AuditEvent>>;
    async fn export_jsonl(&self, path: PathBuf) -> Result<()>;
}

/// In-memory audit service implementation
#[derive(Clone, Default)]
pub struct AuditServiceImpl {
    events: Arc<RwLock<Vec<AuditEvent>>>,
    log_path: Option<PathBuf>,
}

impl AuditServiceImpl {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_log_path(mut self, path: PathBuf) -> Self {
        self.log_path = Some(path);
        self
    }
}

#[async_trait::async_trait]
impl AuditService for AuditServiceImpl {
    async fn record(&self, mut event: AuditEvent) -> Result<()> {
        // Redact secrets before storing
        event.redact_secrets();

        let mut events = self.events.write().await;
        events.push(event.clone());

        // Write to log file if configured
        if let Some(ref path) = self.log_path {
            let json = serde_json::to_string(&event).map_err(|e| Error::Audit(format!("Serialization error: {}", e)))?;
            std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .map_err(|e| Error::Audit(format!("Failed to open audit log: {}", e)))?
                .write_all(format!("{}\n", json).as_bytes())
                .map_err(|e| Error::Audit(format!("Failed to write audit log: {}", e)))?;
        }

        Ok(())
    }

    async fn query(&self, filter: AuditFilter) -> Result<Vec<AuditEvent>> {
        let events = self.events.read().await;
        let mut results: Vec<AuditEvent> = events
            .iter()
            .filter(|e| {
                if let Some(ref event_type) = filter.event_type {
                    if e.event_type != *event_type {
                        return false;
                    }
                }
                if let Some(agent_id) = filter.agent_id {
                    if e.agent_id != Some(agent_id) {
                        return false;
                    }
                }
                if let Some(project_id) = filter.project_id {
                    if e.project_id != Some(project_id) {
                        return false;
                    }
                }
                if let Some(session_id) = filter.session_id {
                    if e.session_id != Some(session_id) {
                        return false;
                    }
                }
                if let Some(start_time) = filter.start_time {
                    if e.timestamp < start_time {
                        return false;
                    }
                }
                if let Some(end_time) = filter.end_time {
                    if e.timestamp > end_time {
                        return false;
                    }
                }
                true
            })
            .cloned()
            .collect();

        // Apply offset and limit
        if let Some(offset) = filter.offset {
            results = results.into_iter().skip(offset).collect();
        }
        if let Some(limit) = filter.limit {
            results = results.into_iter().take(limit).collect();
        }

        Ok(results)
    }

    async fn export_jsonl(&self, path: PathBuf) -> Result<()> {
        let events = self.events.read().await;
        let mut content = String::new();
        for event in events.iter() {
            let json = serde_json::to_string(event).map_err(|e| Error::Audit(format!("Serialization error: {}", e)))?;
            content.push_str(&json);
            content.push('\n');
        }
        std::fs::write(&path, content).map_err(|e| Error::Audit(format!("Failed to write export: {}", e)))?;
        Ok(())
    }
}

impl AuditServiceImpl {
    pub async fn event_count(&self) -> usize {
        self.events.read().await.len()
    }
}