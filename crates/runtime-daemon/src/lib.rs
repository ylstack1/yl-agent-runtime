//! YL Agent Runtime daemon
//!
//! Lifecycle, configuration, session registry, and IPC per PRD section 6.1.

pub mod daemon;

pub use daemon::RuntimeDaemon;