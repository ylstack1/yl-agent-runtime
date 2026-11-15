//! Windows AppContainer support
//!
//! AppContainer provides sandboxed execution with explicit capabilities.
//! Per PRD section 8.4: First choice for Windows sandboxing.

/// AppContainer profile configuration
#[derive(Debug, Clone)]
pub struct AppContainerProfile {
    pub name: String,
    pub display_name: String,
    pub capabilities: Vec<AppContainerCapability>,
    pub filesystem_paths: Vec<AppContainerPathRule>,
    pub network_rules: Vec<AppContainerNetworkRule>,
}

/// AppContainer capability
#[derive(Debug, Clone, PartialEq, Eq)]
#[repr(C)]
pub enum AppContainerCapability {
    InternetClient,
    InternetClientServer,
    PrivateNetworkClientServer,
    PicturesLibrary,
    VideosLibrary,
    MusicLibrary,
    DocumentsLibrary,
    EnterpriseAuthentication,
    SharedUserCertificates,
    RemoteSystem,
    WebTab,
}

/// Filesystem access rule for AppContainer
#[derive(Debug, Clone)]
pub struct AppContainerPathRule {
    pub path: String,
    pub read: bool,
    pub write: bool,
    pub delete: bool,
}

/// Network access rule for AppContainer
#[derive(Debug, Clone)]
pub struct AppContainerNetworkRule {
    pub direction: NetworkDirection,
    pub protocol: NetworkProtocol,
    pub remote_address: Option<String>,
    pub remote_ports: Option<String>,
}

/// Network direction
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkDirection {
    Inbound,
    Outbound,
    Both,
}

/// Network protocol
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkProtocol {
    Tcp,
    Udp,
    Both,
}

/// AppContainer token handle
pub struct AppContainerToken {
    pub handle: isize,
    pub package_name: String,
}

/// Check if AppContainer is supported on this Windows version
pub fn is_app_container_supported() -> bool {
    // AppContainer available on Windows 10 (1607+) and later
    cfg!(windows)
}

/// Create an AppContainer token
pub fn create_app_container_token(_profile: &AppContainerProfile) -> runtime_core::error::Result<AppContainerToken> {
    // Would use CreateAppContainerToken Windows API
    // For now, return a placeholder
    #[cfg(windows)]
    {
        Err(crate::error::Error::NotImplemented(
            "AppContainer token creation not yet implemented".to_string(),
        ))
    }
    #[cfg(not(windows))]
    {
        Err(crate::error::Error::SandboxUnavailable(
            "AppContainer only available on Windows".to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_app_container_supported() {
        assert!(is_app_container_supported());
    }

    #[test]
    fn test_profile_creation() {
        let profile = AppContainerProfile {
            name: "test".to_string(),
            display_name: "Test Profile".to_string(),
            capabilities: vec![AppContainerCapability::InternetClient],
            filesystem_paths: Vec::new(),
            network_rules: Vec::new(),
        };
        assert_eq!(profile.capabilities.len(), 1);
    }
}