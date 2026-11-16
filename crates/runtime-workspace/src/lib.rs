//! YL Agent Runtime workspace service
//!
//! Safe project discovery and file operations with path containment.
//! Per PRD section 10 and section 8.2 (Path Safety).

pub mod service;
pub mod path_safety;
pub mod operations;
pub mod sensitive;
pub mod files;

pub use runtime_core::traits::WorkspaceService;
pub use service::WorkspaceServiceImpl;
pub use path_safety::*;
pub use operations::*;
pub use sensitive::*;