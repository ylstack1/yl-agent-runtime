//! Session management types

use crate::types::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A session represents an authenticated agent-device-project context
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub id: SessionId,
    pub agent_id: AgentId,
    pub device_id: DeviceId,
    pub project_id: ProjectId,
    pub created_at: DateTime<Utc>,
    pub last_activity: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub profile: ExecutionProfile,
    pub capabilities: Vec<CapabilityGrant>,
    pub active_processes: Vec<ProcessId>,
    pub active_terminals: Vec<TerminalId>,
    pub is_active: bool,
}

impl Session {
    pub fn new(
        agent_id: AgentId,
        device_id: DeviceId,
        project_id: ProjectId,
        profile: ExecutionProfile,
    ) -> Self {
        Self {
            id: SessionId::new(),
            agent_id,
            device_id,
            project_id,
            created_at: Utc::now(),
            last_activity: Utc::now(),
            expires_at: None,
            profile,
            capabilities: Vec::new(),
            active_processes: Vec::new(),
            active_terminals: Vec::new(),
            is_active: true,
        }
    }

    pub fn touch(&mut self) {
        self.last_activity = Utc::now();
    }

    pub fn is_expired(&self) -> bool {
        match self.expires_at {
            Some(expires) => Utc::now() > expires,
            None => false,
        }
    }

    pub fn add_process(&mut self, process_id: ProcessId) {
        if !self.active_processes.contains(&process_id) {
            self.active_processes.push(process_id);
        }
    }

    pub fn remove_process(&mut self, process_id: ProcessId) {
        self.active_processes.retain(|p| *p != process_id);
    }

    pub fn add_terminal(&mut self, terminal_id: TerminalId) {
        if !self.active_terminals.contains(&terminal_id) {
            self.active_terminals.push(terminal_id);
        }
    }

    pub fn remove_terminal(&mut self, terminal_id: TerminalId) {
        self.active_terminals.retain(|t| *t != terminal_id);
    }
}

/// Session filter for queries
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionFilter {
    pub agent_id: Option<AgentId>,
    pub device_id: Option<DeviceId>,
    pub project_id: Option<ProjectId>,
    pub is_active: Option<bool>,
}

/// Session summary for listing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionSummary {
    pub id: SessionId,
    pub agent_id: AgentId,
    pub device_id: DeviceId,
    pub project_id: ProjectId,
    pub created_at: DateTime<Utc>,
    pub last_activity: DateTime<Utc>,
    pub profile: ExecutionProfile,
    pub is_active: bool,
    pub active_process_count: usize,
    pub active_terminal_count: usize,
}

/// Terminal session
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TerminalSession {
    pub id: TerminalId,
    pub session_id: SessionId,
    pub project_id: ProjectId,
    pub created_at: DateTime<Utc>,
    pub last_activity: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub rows: u16,
    pub cols: u16,
    pub is_active: bool,
    pub output_bytes: u64,
    pub scrollback_limit: usize,
}

impl TerminalSession {
    pub fn new(session_id: SessionId, project_id: ProjectId, rows: u16, cols: u16) -> Self {
        Self {
            id: TerminalId::new(),
            session_id,
            project_id,
            created_at: Utc::now(),
            last_activity: Utc::now(),
            expires_at: Some(Utc::now() + chrono::Duration::hours(1)), // 1 hour default
            rows,
            cols,
            is_active: true,
            output_bytes: 0,
            scrollback_limit: 10000,
        }
    }
}