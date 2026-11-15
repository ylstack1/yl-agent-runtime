//! YL Agent Runtime - Core types, traits, and error handling
//!
//! This crate provides the fundamental building blocks used across all
//! other crates in the YL Agent Runtime workspace.

pub mod error;
pub mod types;
pub mod traits;
pub mod platform;
pub mod capability;
pub mod session;
pub mod audit;

pub use error::{Error, Result};
pub use types::*;
pub use traits::*;
pub use platform::*;
pub use capability::*;
pub use session::*;
pub use audit::*;