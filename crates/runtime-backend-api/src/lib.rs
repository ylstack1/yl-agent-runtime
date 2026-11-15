//! YL Agent Runtime backend API
//!
//! Stable trait boundary for execution backends per PRD section 9.1.

pub mod traits;
pub mod types;

pub use traits::*;
pub use types::*;