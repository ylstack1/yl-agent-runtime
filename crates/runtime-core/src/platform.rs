//! Platform detection and capability probing

use crate::error::Result;
use crate::types::*;
use serde::{Deserialize, Serialize};
use std::process::Command;

/// Platform information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlatformInfo {
    pub platform: Platform,
    pub architecture: Architecture,
    pub os_version: String,
    pub hostname: String,
    pub is_elevated: bool,
}

/// Sandbox mechanism availability
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxMechanisms {
    pub app_container: bool,
    pub restricted_token: bool,
    pub job_objects: bool,
    pub landlock: bool,
    pub seccomp: bool,
    pub namespaces: bool,
    pub cgroups_v2: bool,
    pub seatbelt: bool,
}

/// Probe the current platform and report capabilities
pub fn probe_platform() -> Result<PlatformInfo> {
    let platform = Platform::current();
    let architecture = Architecture::current();
    let os_version = get_os_version()?;
    let hostname = get_hostname()?;
    let is_elevated = check_elevated()?;

    Ok(PlatformInfo {
        platform,
        architecture,
        os_version,
        hostname,
        is_elevated,
    })
}

/// Probe sandbox mechanisms available on this platform
pub fn probe_sandbox_mechanisms() -> Result<SandboxMechanisms> {
    let platform = Platform::current();
    Ok(match platform {
        Platform::Windows => SandboxMechanisms {
            app_container: check_app_container()?,
            restricted_token: true, // Always available on Windows
            job_objects: true,       // Always available on Windows
            landlock: false,
            seccomp: false,
            namespaces: false,
            cgroups_v2: false,
            seatbelt: false,
        },
        Platform::Linux => SandboxMechanisms {
            app_container: false,
            restricted_token: false,
            job_objects: false,
            landlock: check_landlock()?,
            seccomp: check_seccomp()?,
            namespaces: check_namespaces()?,
            cgroups_v2: check_cgroups_v2()?,
            seatbelt: false,
        },
        Platform::MacOS => SandboxMechanisms {
            app_container: false,
            restricted_token: false,
            job_objects: false,
            landlock: false,
            seccomp: false,
            namespaces: false,
            cgroups_v2: false,
            seatbelt: check_seatbelt()?,
        },
        Platform::Unknown => SandboxMechanisms {
            app_container: false,
            restricted_token: false,
            job_objects: false,
            landlock: false,
            seccomp: false,
            namespaces: false,
            cgroups_v2: false,
            seatbelt: false,
        },
    })
}

#[cfg(windows)]
fn check_app_container() -> Result<bool> {
    // AppContainer is available on Windows 10 and later
    // Probe by checking if we can create an AppContainer token
    Ok(true) // Placeholder - will be implemented in backend-windows
}

#[cfg(not(windows))]
fn check_app_container() -> Result<bool> {
    Ok(false)
}

#[cfg(windows)]
fn check_elevated() -> Result<bool> {
    let mut token = windows::Win32::Foundation::HANDLE::default();
    unsafe {
        if windows::Win32::System::Threading::OpenProcessToken(
            windows::Win32::System::Threading::GetCurrentProcess(),
            windows::Win32::Security::TOKEN_QUERY,
            &mut token,
        )
        .is_ok()
        {
            let mut elevation = windows::Win32::Security::TOKEN_ELEVATION::default();
            let mut size = std::mem::size_of::<windows::Win32::Security::TOKEN_ELEVATION>() as u32;
            if windows::Win32::Security::GetTokenInformation(
                token,
                windows::Win32::Security::TokenElevation,
                Some(&mut elevation as *mut _ as *mut _),
                size,
                &mut size,
            )
            .is_ok()
            {
                let _ = windows::Win32::Foundation::CloseHandle(token);
                return Ok(elevation.TokenIsElevated != 0);
            }
        }
        let _ = windows::Win32::Foundation::CloseHandle(token);
    }
    Ok(false)
}

#[cfg(not(windows))]
fn check_elevated() -> Result<bool> {
    Ok(nix::unistd::Uid::effective().is_root())
}

fn get_os_version() -> Result<String> {
    #[cfg(windows)]
    {
        let output = Command::new("wmic").args(["os", "get", "version"]).output();
        match output {
            Ok(out) => {
                let text = String::from_utf8_lossy(&out.stdout);
                let version = text.lines().find(|l| !l.trim().is_empty() && l.trim().chars().next().unwrap_or(' ').is_numeric()).unwrap_or("unknown");
                Ok(version.trim().to_string())
            }
            Err(_) => Ok("unknown".to_string()),
        }
    }
    #[cfg(not(windows))]
    {
        let output = Command::new("uname").args(["-r"]).output();
        match output {
            Ok(out) => Ok(String::from_utf8_lossy(&out.stdout).trim().to_string()),
            Err(_) => Ok("unknown".to_string()),
        }
    }
}

fn get_hostname() -> Result<String> {
    #[cfg(windows)]
    {
        let output = Command::new("hostname").output();
        match output {
            Ok(out) => Ok(String::from_utf8_lossy(&out.stdout).trim().to_string()),
            Err(_) => Ok("unknown".to_string()),
        }
    }
    #[cfg(not(windows))]
    {
        Ok(nix::unistd::gethostname().to_string_lossy().to_string())
    }
}

#[cfg(target_os = "linux")]
fn check_landlock() -> Result<bool> {
    landlock::create_ruleset().map(|_| true).map_err(|e| crate::error::Error::Sandbox(format!("Landlock probe failed: {}", e)))
}

#[cfg(not(target_os = "linux"))]
fn check_landlock() -> Result<bool> {
    Ok(false)
}

#[cfg(target_os = "linux")]
fn check_seccomp() -> Result<bool> {
    // Check if seccomp is available
    Ok(std::path::Path::new("/proc/sys/kernel/seccomp").exists())
}

#[cfg(not(target_os = "linux"))]
fn check_seccomp() -> Result<bool> {
    Ok(false)
}

#[cfg(target_os = "linux")]
fn check_namespaces() -> Result<bool> {
    Ok(std::path::Path::new("/proc/1/ns/mnt").exists())
}

#[cfg(not(target_os = "linux"))]
fn check_namespaces() -> Result<bool> {
    Ok(false)
}

#[cfg(target_os = "linux")]
fn check_cgroups_v2() -> Result<bool> {
    Ok(std::path::Path::new("/sys/fs/cgroup/cgroup.controllers").exists())
}

#[cfg(not(target_os = "linux"))]
fn check_cgroups_v2() -> Result<bool> {
    Ok(false)
}

#[cfg(target_os = "macos")]
fn check_seatbelt() -> Result<bool> {
    // Check if sandbox-exec is available
    Ok(Command::new("sandbox-exec").arg("--help").output().is_ok())
}

#[cfg(not(target_os = "macos"))]
fn check_seatbelt() -> Result<bool> {
    Ok(false)
}

/// Generate a BackendCapabilities report for the current platform
pub fn generate_capability_report(backend_name: &str) -> Result<BackendCapabilities> {
    let platform_info = probe_platform()?;
    let mechanisms = probe_sandbox_mechanisms()?;

    let (fs_write, fs_read, network, process_tree, memory, cpu, overall) =
        match platform_info.platform {
            Platform::Windows => {
                if mechanisms.app_container {
                    (
                        IsolationSupport::Enforced,
                        IsolationSupport::Partial,
                        IsolationSupport::Partial,
                        IsolationSupport::Enforced,
                        IsolationSupport::Enforced,
                        IsolationSupport::Partial,
                        OverallIsolation::Partial,
                    )
                } else if mechanisms.restricted_token && mechanisms.job_objects {
                    (
                        IsolationSupport::Enforced,
                        IsolationSupport::Partial,
                        IsolationSupport::Unavailable,
                        IsolationSupport::Enforced,
                        IsolationSupport::Enforced,
                        IsolationSupport::Partial,
                        OverallIsolation::Partial,
                    )
                } else {
                    (
                        IsolationSupport::Unavailable,
                        IsolationSupport::Unavailable,
                        IsolationSupport::Unavailable,
                        IsolationSupport::Partial,
                        IsolationSupport::Unavailable,
                        IsolationSupport::Unavailable,
                        OverallIsolation::None,
                    )
                }
            }
            Platform::Linux => {
                if mechanisms.landlock && mechanisms.seccomp && mechanisms.cgroups_v2 {
                    (
                        IsolationSupport::Enforced,
                        IsolationSupport::Enforced,
                        IsolationSupport::Enforced,
                        IsolationSupport::Enforced,
                        IsolationSupport::Enforced,
                        IsolationSupport::Enforced,
                        OverallIsolation::Full,
                    )
                } else if mechanisms.landlock || mechanisms.seccomp {
                    (
                        IsolationSupport::Partial,
                        IsolationSupport::Partial,
                        IsolationSupport::Partial,
                        IsolationSupport::Partial,
                        IsolationSupport::Partial,
                        IsolationSupport::Partial,
                        OverallIsolation::Partial,
                    )
                } else {
                    (
                        IsolationSupport::Unavailable,
                        IsolationSupport::Unavailable,
                        IsolationSupport::Unavailable,
                        IsolationSupport::Partial,
                        IsolationSupport::Unavailable,
                        IsolationSupport::Unavailable,
                        OverallIsolation::None,
                    )
                }
            }
            Platform::MacOS => {
                if mechanisms.seatbelt {
                    (
                        IsolationSupport::Enforced,
                        IsolationSupport::Partial,
                        IsolationSupport::Partial,
                        IsolationSupport::Enforced,
                        IsolationSupport::Partial,
                        IsolationSupport::Partial,
                        OverallIsolation::Partial,
                    )
                } else {
                    (
                        IsolationSupport::Unavailable,
                        IsolationSupport::Unavailable,
                        IsolationSupport::Unavailable,
                        IsolationSupport::Partial,
                        IsolationSupport::Unavailable,
                        IsolationSupport::Unavailable,
                        OverallIsolation::None,
                    )
                }
            }
            Platform::Unknown => (
                IsolationSupport::Unavailable,
                IsolationSupport::Unavailable,
                IsolationSupport::Unavailable,
                IsolationSupport::Unavailable,
                IsolationSupport::Unavailable,
                IsolationSupport::Unavailable,
                OverallIsolation::None,
            ),
        };

    Ok(BackendCapabilities {
        backend_name: backend_name.to_string(),
        platform: platform_info.platform,
        architecture: platform_info.architecture,
        filesystem_write_isolation: fs_write,
        filesystem_read_isolation: fs_read,
        network_isolation: network,
        process_tree_limit: process_tree,
        memory_limit: memory,
        cpu_limit: cpu,
        interactive_terminal: true,
        required_privileges: vec![],
        unsupported_policy_fields: vec![],
        overall,
    })
}