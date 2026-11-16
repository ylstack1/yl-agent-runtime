//! Files subsystem for the YL Agent Runtime workspace service.
//!
//! Provides the read engine (byte/line modes, binary probe, media
//! handling, sha256) and the write engine (atomic writes, overwrite
//! guard, EOL preservation) consumed by Task 9 service methods and Task
//! 11 MCP tools.

pub mod read;
pub mod write;
