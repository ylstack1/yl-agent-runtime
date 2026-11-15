//! YL Agent Runtime native host backend
//!
//! Fast, compatible execution for trusted local development.
//! Per PRD section 9.2: Does not claim to be a security sandbox when no
//! kernel boundary is active.

pub mod backend;

pub use backend::NativeBackend;