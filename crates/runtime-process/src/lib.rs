//! YL Agent Runtime process service
//!
//! Command execution, process trees, cancellation, and limits per PRD section 11.

pub mod service;
pub mod supervisor;
pub mod limits;
pub mod process;
pub mod cursor;

pub use service::ProcessService;
pub use service::ProcessServiceOps;
pub use supervisor::*;
pub use limits::*;
pub use process::{ProcessExecutor, ExecutionResult};
pub use process::{ALLOWED_TOOLS, ENV_DENY, ENV_WHITELIST};
pub use process::resolve_executable;
pub use process::allowlist_error;
pub use cursor::{Chunk, ProcessLog, ReadPage, StreamId};
