//! YL Agent Runtime Windows sandbox backend
//!
//! AppContainer, Job Objects, restricted tokens per PRD section 8.4.
//! Windows 10 is a required baseline.

pub mod backend;
pub mod appcontainer;
pub mod jobobjects;
pub mod restricted_token;

pub use backend::WindowsBackend;