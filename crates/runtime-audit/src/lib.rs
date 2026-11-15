//! YL Agent Runtime audit service
//!
//! Append-only structured operation records per PRD section 15.

pub mod service;

pub use service::AuditServiceImpl;
pub use service::AuditService;