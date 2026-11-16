//! YL Agent Runtime terminal service
//!
//! Interactive PTY/ConPTY sessions per PRD section 12.

pub mod service;

pub use service::TerminalService;
pub use service::TerminalServiceImpl;