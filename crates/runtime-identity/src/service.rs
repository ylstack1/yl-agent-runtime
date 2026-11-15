//! Identity service implementation

use runtime_core::error::{Error, Result};
use runtime_core::types::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Identity service trait
#[async_trait::async_trait]
pub trait IdentityService: Send + Sync {
    async fn register_agent(&self, name: String, public_key: Vec<u8>) -> Result<AgentId>;
    async fn register_device(&self, name: String, public_key: Vec<u8>) -> Result<DeviceId>;
    async fn get_agent(&self, id: AgentId) -> Result<AgentInfo>;
    async fn get_device(&self, id: DeviceId) -> Result<DeviceInfo>;
    async fn revoke_device(&self, id: DeviceId) -> Result<()>;
    async fn list_devices(&self) -> Result<Vec<DeviceInfo>>;
    async fn list_agents(&self) -> Result<Vec<AgentInfo>>;
}

/// Agent information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentInfo {
    pub id: AgentId,
    pub name: String,
    public_key: Vec<u8>,
    pub created_at: DateTime<Utc>,
    pub is_active: bool,
}

/// Device information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceInfo {
    pub id: DeviceId,
    pub name: String,
    public_key: Vec<u8>,
    pub fingerprint: String,
    pub created_at: DateTime<Utc>,
    pub is_active: bool,
    pub is_revoked: bool,
}

/// Pairing request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairingRequest {
    pub device_name: String,
    pub device_public_key: Vec<u8>,
    pub pairing_code: String,
    pub expires_at: DateTime<Utc>,
}

/// Pairing state
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PairingState {
    Pending,
    Approved,
    Rejected,
    Expired,
}

/// Identity service implementation
#[derive(Clone, Default)]
pub struct IdentityServiceImpl {
    agents: Arc<RwLock<HashMap<AgentId, AgentInfo>>>,
    devices: Arc<RwLock<HashMap<DeviceId, DeviceInfo>>>,
    pairings: Arc<RwLock<HashMap<String, PairingRequest>>>,
}

impl IdentityServiceImpl {
    pub fn new() -> Self {
        Self::default()
    }

    /// Generate a pairing code for device pairing
    pub fn generate_pairing_code(&self) -> String {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        (0..6).map(|_| rng.gen_range(0..10)).map(|d| char::from_digit(d, 10).unwrap()).collect()
    }

    /// Compute fingerprint from public key
    pub fn compute_fingerprint(public_key: &[u8]) -> String {
        use blake3::Hasher;
        let mut hasher = Hasher::new();
        hasher.update(public_key);
        let hash = hasher.finalize();
        format!("{:x}", &hash.as_bytes()[..16])
    }
}

#[async_trait::async_trait]
impl IdentityService for IdentityServiceImpl {
    async fn register_agent(&self, name: String, public_key: Vec<u8>) -> Result<AgentId> {
        let id = AgentId::new();
        let agent = AgentInfo {
            id,
            name: name.clone(),
            public_key: public_key.clone(),
            created_at: chrono::Utc::now(),
            is_active: true,
        };
        self.agents.write().await.insert(id, agent);
        Ok(id)
    }

    async fn register_device(&self, name: String, public_key: Vec<u8>) -> Result<DeviceId> {
        let id = DeviceId::new();
        let fingerprint = Self::compute_fingerprint(&public_key);
        let device = DeviceInfo {
            id,
            name,
            public_key,
            fingerprint,
            created_at: chrono::Utc::now(),
            is_active: true,
            is_revoked: false,
        };
        self.devices.write().await.insert(id, device);
        Ok(id)
    }

    async fn get_agent(&self, id: AgentId) -> Result<AgentInfo> {
        self.agents.read().await.get(&id).cloned()
            .ok_or_else(|| Error::AgentNotFound(format!("Agent {}", id)))
    }

    async fn get_device(&self, id: DeviceId) -> Result<DeviceInfo> {
        self.devices.read().await.get(&id).cloned()
            .ok_or_else(|| Error::DeviceNotFound(format!("Device {}", id)))
    }

    async fn revoke_device(&self, id: DeviceId) -> Result<()> {
        let mut devices = self.devices.write().await;
        match devices.get_mut(&id) {
            Some(device) => {
                device.is_revoked = true;
                device.is_active = false;
                Ok(())
            }
            None => Err(Error::DeviceNotFound(format!("Device {}", id))),
        }
    }

    async fn list_devices(&self) -> Result<Vec<DeviceInfo>> {
        Ok(self.devices.read().await.values().cloned().collect())
    }

    async fn list_agents(&self) -> Result<Vec<AgentInfo>> {
        Ok(self.agents.read().await.values().cloned().collect())
    }
}