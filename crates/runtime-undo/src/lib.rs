//! Undo journal for YL Agent Runtime
//!
//! Tracks mutating operations so they can be reversed via `undo` / `redo`.
//! Every journal entry is persisted to a JSONL log for restart survival.

use runtime_core::types::*;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

/// A single reversible operation recorded in the undo journal.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UndoJournalEntry {
    pub id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub operation: UndoOperation,
    pub path: PathBuf,
    /// File content before the operation (for write/edit/patch/delete).
    pub old_content: Option<String>,
    /// File content after the operation (for write/edit/patch, used by redo).
    pub new_content: Option<String>,
    /// Source path (for move operations).
    pub old_path: Option<PathBuf>,
    /// Destination path (for move operations).
    pub new_path: Option<PathBuf>,
    /// Git commit hash (for git.commit operations).
    pub commit_hash: Option<String>,
}

/// Type of reversible operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UndoOperation {
    Write,
    Edit,
    Patch,
    Delete,
    Mkdir,
    Move,
    GitCommit,
}

impl UndoOperation {
    pub fn as_str(&self) -> &'static str {
        match self {
            UndoOperation::Write => "write",
            UndoOperation::Edit => "edit",
            UndoOperation::Patch => "patch",
            UndoOperation::Delete => "delete",
            UndoOperation::Mkdir => "mkdir",
            UndoOperation::Move => "move",
            UndoOperation::GitCommit => "git.commit",
        }
    }
}

/// A single line written to the undo journal for persistence.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct JournalLine {
    id: Uuid,
    timestamp: DateTime<Utc>,
    operation: UndoOperation,
    path: PathBuf,
    old_content: Option<String>,
    new_content: Option<String>,
    old_path: Option<PathBuf>,
    new_path: Option<PathBuf>,
    commit_hash: Option<String>,
}

/// Undo journal - records mutating operations and supports undo/redo.
#[derive(Clone, Default)]
pub struct UndoJournal {
    entries: Arc<RwLock<VecDeque<UndoJournalEntry>>>,
    undone: Arc<RwLock<VecDeque<UndoJournalEntry>>>,
    log_path: Option<PathBuf>,
}

impl UndoJournal {
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a journal that persists to `path` and replays existing entries
    /// on startup.
    pub fn with_log_path(mut self, path: PathBuf) -> Self {
        if let Ok(entries) = Self::replay(&path) {
            let deque: VecDeque<_> = entries.into_iter().collect();
            self.entries = Arc::new(RwLock::new(deque));
        }
        self.log_path = Some(path);
        self
    }

    fn replay(path: &PathBuf) -> Result<Vec<UndoJournalEntry>, String> {
        if !path.exists() {
            return Ok(Vec::new());
        }
        let contents = std::fs::read_to_string(path)
            .map_err(|e| format!("failed to read undo journal: {e}"))?;
        let mut entries = Vec::new();
        for line in contents.lines() {
            if line.trim().is_empty() {
                continue;
            }
            let entry: JournalLine = serde_json::from_str(line)
                .map_err(|e| format!("failed to parse undo journal line: {e}"))?;
            entries.push(entry.into());
        }
        Ok(entries)
    }

    fn append_journal(&self, entry: &UndoJournalEntry) {
        let Some(ref path) = self.log_path else { return };
        let line = JournalLine {
            id: entry.id,
            timestamp: entry.timestamp,
            operation: entry.operation,
            path: entry.path.clone(),
            old_content: entry.old_content.clone(),
            new_content: entry.new_content.clone(),
            old_path: entry.old_path.clone(),
            new_path: entry.new_path.clone(),
            commit_hash: entry.commit_hash.clone(),
        };
        let json = match serde_json::to_string(&line) {
            Ok(j) => j,
            Err(e) => {
                tracing::warn!("failed to serialize undo journal entry: {e}");
                return;
            }
        };
        if let Err(e) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .and_then(|mut f| std::writeln!(f, "{json}"))
        {
            tracing::warn!("failed to append to undo journal: {e}");
        }
    }

    /// Record a mutating operation in the journal.
    pub async fn record(&self, entry: UndoJournalEntry) {
        self.entries.write().await.push_back(entry.clone());
        // Clear the redo stack when a new operation is recorded.
        self.undone.write().await.clear();
        self.append_journal(&entry);
    }

    /// Undo the most recent operation. Returns the entry that was undone.
    pub async fn undo(&self) -> Option<UndoJournalEntry> {
        let entry = self.entries.write().await.pop_back()?;
        self.undone.write().await.push_front(entry.clone());
        Some(entry)
    }

    /// Redo the most recently undone operation. Returns the entry that was redone.
    pub async fn redo(&self) -> Option<UndoJournalEntry> {
        let entry = self.undone.write().await.pop_front()?;
        self.entries.write().await.push_back(entry.clone());
        Some(entry)
    }

    /// List recent journal entries (newest first).
    pub async fn list(&self, limit: usize) -> Vec<UndoJournalEntry> {
        let entries = self.entries.read().await;
        entries
            .iter()
            .rev()
            .take(limit)
            .cloned()
            .collect()
    }

    /// Check if there are any entries to undo.
    pub async fn can_undo(&self) -> bool {
        self.entries.read().await.len() > 0
    }

    /// Check if there are any entries to redo.
    pub async fn can_redo(&self) -> bool {
        self.undone.read().await.len() > 0
    }
}

impl From<JournalLine> for UndoJournalEntry {
    fn from(l: JournalLine) -> Self {
        Self {
            id: l.id,
            timestamp: l.timestamp,
            operation: l.operation,
            path: l.path,
            old_content: l.old_content,
            new_content: l.new_content,
            old_path: l.old_path,
            new_path: l.new_path,
            commit_hash: l.commit_hash,
        }
    }
}
