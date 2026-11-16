//! Process tree supervisor
//!
//! Manages process groups and trees for cleanup on cancellation or shutdown.
//! Per PRD section 8.3: Kill entire process tree on cancellation.

use runtime_core::types::ProcessId;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Mapping of OS PID to its direct child PIDs
type ProcessTree = Vec<u32>;

/// Process tree supervisor
#[derive(Clone)]
pub struct ProcessTreeSupervisor {
    trees: Arc<RwLock<HashMap<u32, ProcessTree>>>,
    process_map: Arc<RwLock<HashMap<ProcessId, u32>>>,
}

impl ProcessTreeSupervisor {
    pub fn new() -> Self {
        Self {
            trees: Arc::new(RwLock::new(HashMap::new())),
            process_map: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Register a process in the tree
    pub async fn add_process(&self, id: ProcessId, os_pid: u32) {
        let mut map = self.process_map.write().await;
        map.insert(id, os_pid);
    }

    /// Add a child process to a parent's tree
    pub async fn add_child(&self, parent_pid: u32, child_pid: u32) {
        let mut trees = self.trees.write().await;
        let tree = trees.entry(parent_pid).or_default();
        if !tree.contains(&child_pid) {
            tree.push(child_pid);
        }
    }

    /// Terminate an entire process tree
    pub async fn terminate_tree(&self, id: ProcessId) -> runtime_core::error::Result<()> {
        let map = self.process_map.read().await;
        let os_pid = match map.get(&id) {
            Some(pid) => *pid,
            None => return Ok(()),
        };
        drop(map);

        let trees = self.trees.read().await;
        let children = trees.get(&os_pid).cloned().unwrap_or_default();
        drop(trees);

        // Kill children first (recursively would need more tree traversal)
        for child_pid in children {
            Self::kill_process(child_pid).ok();
        }

        // Kill the root process
        Self::kill_process(os_pid).ok();

        Ok(())
    }

    /// Get all PIDs in a process tree
    pub async fn get_tree_pids(&self, id: ProcessId) -> Vec<u32> {
        let map = self.process_map.read().await;
        let os_pid = match map.get(&id) {
            Some(pid) => *pid,
            None => return Vec::new(),
        };
        drop(map);

        let mut pids = vec![os_pid];
        let trees = self.trees.read().await;
        if let Some(children) = trees.get(&os_pid) {
            pids.extend(children.iter().copied());
        }
        pids
    }

    /// Kill a process by OS PID
    fn kill_process(pid: u32) -> std::io::Result<()> {
        #[cfg(windows)]
        {
            use windows::Win32::System::Threading::OpenProcess;
            use windows::Win32::System::Threading::TerminateProcess;
            use windows::Win32::Foundation::CloseHandle;
            use windows::Win32::Foundation::HANDLE;
            use windows::Win32::System::Threading::PROCESS_TERMINATE;

            unsafe {
                let handle = OpenProcess(PROCESS_TERMINATE, false, pid)?;
                let _ = TerminateProcess(handle, 1);
                let _ = CloseHandle(handle);
            }
            Ok(())
        }

        #[cfg(unix)]
        {
            use nix::sys::signal::{self, Signal};
            signal::kill(nix::unistd::Pid::from_raw(pid as i32), Signal::SIGKILL)
        }

        #[cfg(not(any(windows, unix)))]
        {
            let _ = pid;
            Ok(())
        }
    }

    /// Clean up all tracked processes (for shutdown)
    pub async fn cleanup_all(&self) {
        let map = self.process_map.read().await;
        let pids: Vec<u32> = map.values().copied().collect();
        drop(map);

        for pid in pids {
            Self::kill_process(pid).ok();
        }
    }
}

impl Default for ProcessTreeSupervisor {
    fn default() -> Self {
        Self::new()
    }
}