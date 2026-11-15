//! YL Agent Runtime Virtx VM backend
//!
//! Optional VM isolation for hostile workloads per PRD section 9.4.
//! Not a Windows 10 baseline dependency - deferred to Phase 5.

pub mod backend;

pub use backend::VirtxBackend;