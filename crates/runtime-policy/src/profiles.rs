//! Execution profile definitions

use runtime_core::capability::ExecutionProfileConfig;
use runtime_core::types::ExecutionProfile;

/// Re-export profile config from runtime-core
pub use runtime_core::capability::*;

/// Get default configuration for a profile
pub fn profile_config(profile: ExecutionProfile) -> ExecutionProfileConfig {
    ExecutionProfileConfig::get(profile)
}

/// List all available profiles
pub fn all_profiles() -> Vec<ExecutionProfile> {
    vec![
        ExecutionProfile::Inspect,
        ExecutionProfile::Edit,
        ExecutionProfile::Development,
        ExecutionProfile::SandboxedDevelopment,
        ExecutionProfile::ElevatedOneShot,
    ]
}