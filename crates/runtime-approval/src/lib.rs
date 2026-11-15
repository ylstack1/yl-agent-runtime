//! YL Agent Runtime approval broker
//!
//! User consent for sensitive operations per PRD section 7.4.

pub mod service;

pub use service::ApprovalBrokerImpl;
pub use service::ApprovalBroker;