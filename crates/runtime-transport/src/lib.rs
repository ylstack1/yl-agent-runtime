//! YL Agent Runtime transport service
//!
//! Local IPC and optional remote connectivity per PRD sections 6.1 and 13.3.

pub mod local;
pub mod remote;

pub use local::LocalTransport;
pub use remote::RemoteTransport;