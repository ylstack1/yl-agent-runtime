//! YL Agent Runtime identity service
//!
//! Local agent identities, trusted devices, pairing and revocation per PRD sections 6.1 and 14.

pub mod service;

pub use service::IdentityServiceImpl;
pub use service::IdentityService;