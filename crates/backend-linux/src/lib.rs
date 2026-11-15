//! YL Agent Runtime Linux sandbox backend
//!
//! Landlock, seccomp, namespaces, cgroups v2 per PRD section 8.4.

pub mod backend;

pub use backend::LinuxBackend;