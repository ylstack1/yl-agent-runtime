//! YL Agent Runtime workspace service
//!
//! Safe project discovery and file operations with path containment.
//! Per PRD section 10 and section 8.2 (Path Safety).

pub mod service;
pub mod path_safety;
pub mod operations;

pub use service::WorkspaceService;
pub use path_safety::*;
pub use operations::*;