//! YL Agent Runtime Arapuca sandbox backend integration
//!
//! Arapuca provides cross-platform kernel-enforced sandboxing:
//! - Linux: Landlock, seccomp BPF, cgroups v2, network namespaces
//! - macOS: Seatbelt (sandbox-exec)
//! - Windows: AppContainer, Job Objects
//!
//! License: Apache-2.0 (verified via crates.io, v0.2.9)
//! Repository: https://github.com/sergio-correia/arapuca

pub mod backend;

pub use backend::ArapucaBackend;