//! Policy evaluation logic

use runtime_core::capability::*;
use runtime_core::error::Result;
use runtime_core::types::*;

/// Evaluate a capability request against grants and profile
pub fn evaluate_capability(
    capability: Capability,
    resource: Option<&str>,
    profile: ExecutionProfile,
    grants: &[CapabilityGrant],
) -> Result<PolicyDecision> {
    // Check explicit grants first (most specific match wins)
    for grant in grants {
        if grant.capability != capability {
            continue;
        }

        // Resource must match if specified in both
        if let (Some(grant_resource), Some(requested_resource)) = (&grant.resource, resource) {
            if grant_resource != requested_resource {
                continue;
            }
        }

        // Check expiry
        if let Some(expires_at) = grant.expires_at {
            if chrono::Utc::now() > expires_at {
                return Ok(PolicyDecision::Deny);
            }
        }

        return Ok(grant.decision);
    }

    // No explicit grant - fall back to profile default
    Ok(default_decision(capability, profile))
}

/// Check if a capability requires approval
pub fn capability_requires_approval(capability: Capability, profile: ExecutionProfile) -> bool {
    runtime_core::capability::requires_approval(capability, profile)
}

/// Get the default decision for a capability in a profile
pub fn capability_default_decision(capability: Capability, profile: ExecutionProfile) -> PolicyDecision {
    runtime_core::capability::default_decision(capability, profile)
}