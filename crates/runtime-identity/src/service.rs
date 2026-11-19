//! Identity service implementation

use runtime_core::error::{Error, Result};
use runtime_core::types::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use ed25519_dalek::{Signature, VerifyingKey};

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

    /// Pairing lifecycle
    async fn request_pairing(&self, device_name: String, device_public_key: Vec<u8>) -> Result<PairingRequest>;
    async fn approve_pairing(&self, pairing_code: String) -> Result<DeviceId>;
    async fn reject_pairing(&self, pairing_code: String) -> Result<()>;
    async fn list_pairings(&self) -> Result<Vec<PairingRequest>>;

    /// Session authentication
    async fn authenticate_device(&self, device_id: DeviceId, signature_hex: String) -> Result<String>;
    async fn validate_session(&self, session_token: String) -> Result<DeviceId>;
    async fn revoke_session(&self, session_token: String) -> Result<()>;
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

/// Session information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionInfo {
    pub id: SessionId,
    pub device_id: DeviceId,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub is_active: bool,
}

/// Pairing request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairingRequest {
    pub device_name: String,
    pub device_public_key: Vec<u8>,
    pub pairing_code: String,
    pub state: PairingState,
    pub expires_at: DateTime<Utc>,
    /// Set once the host approves the request; the paired device signs this
    /// value to authenticate and obtain a session token.
    pub device_id: Option<DeviceId>,
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
    sessions: Arc<RwLock<HashMap<String, SessionInfo>>>,
}

impl IdentityServiceImpl {
    pub fn new() -> Self {
        Self {
            agents: Arc::new(RwLock::new(HashMap::new())),
            devices: Arc::new(RwLock::new(HashMap::new())),
            pairings: Arc::new(RwLock::new(HashMap::new())),
            sessions: Arc::new(RwLock::new(HashMap::new())),
        }
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
        hash.as_bytes()[..16]
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect()
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

    // ---- Pairing lifecycle ----

    async fn request_pairing(&self, device_name: String, device_public_key: Vec<u8>) -> Result<PairingRequest> {
        let code = self.generate_pairing_code();
        let expires_at = chrono::Utc::now() + chrono::Duration::minutes(10);
        let request = PairingRequest {
            device_name,
            device_public_key,
            pairing_code: code.clone(),
            state: PairingState::Pending,
            expires_at,
            device_id: None,
        };
        self.pairings.write().await.insert(code, request.clone());
        Ok(request)
    }

    async fn approve_pairing(&self, pairing_code: String) -> Result<DeviceId> {
        // Look up and validate the pairing request, then release the lock
        // before registering the device (to avoid holding two locks).
        let (device_name, device_public_key) = {
            let pairings = self.pairings.read().await;
            let request = pairings
                .get(&pairing_code)
                .ok_or_else(|| Error::Validation(format!("Pairing code not found: {pairing_code}")))?;

            if request.state != PairingState::Pending {
                return Err(Error::Validation(format!(
                    "Pairing code {pairing_code} is already {:?}",
                    request.state
                )));
            }

            if chrono::Utc::now() > request.expires_at {
                return Err(Error::Validation(format!(
                    "Pairing code {pairing_code} has expired"
                )));
            }

            (request.device_name.clone(), request.device_public_key.clone())
        };

        // Register the device (takes &self, no conflict with pairings lock)
        let device_id = self.register_device(device_name, device_public_key).await?;

        // Mark pairing as approved
        let mut pairings = self.pairings.write().await;
        if let Some(req) = pairings.get_mut(&pairing_code) {
            req.state = PairingState::Approved;
            req.device_id = Some(device_id);
        }

        Ok(device_id)
    }

    async fn reject_pairing(&self, pairing_code: String) -> Result<()> {
        let mut pairings = self.pairings.write().await;
        let request = pairings
            .get_mut(&pairing_code)
            .ok_or_else(|| Error::Validation(format!("Pairing code not found: {pairing_code}")))?;

        if request.state != PairingState::Pending {
            return Err(Error::Validation(format!(
                "Pairing code {pairing_code} is already {:?}",
                request.state
            )));
        }

        request.state = PairingState::Rejected;
        Ok(())
    }

    async fn list_pairings(&self) -> Result<Vec<PairingRequest>> {
        Ok(self.pairings.read().await.values().cloned().collect())
    }

    // ---- Session authentication ----

    /// Authenticate a device by verifying an ed25519 signature over its device ID.
    /// On success, issues a short-lived session token.
    async fn authenticate_device(&self, device_id: DeviceId, signature_hex: String) -> Result<String> {
        // Look up the device and verify it's not revoked
        let device = {
            let devices = self.devices.read().await;
            devices
                .get(&device_id)
                .cloned()
                .ok_or_else(|| Error::DeviceNotFound(format!("Device {}", device_id)))?
        };

        if device.is_revoked {
            return Err(Error::Validation(format!("Device {} is revoked", device_id)));
        }

        // Parse the device's public key
        let key_array: [u8; 32] = device
            .public_key
            .as_slice()
            .try_into()
            .map_err(|e| Error::Validation(format!("Invalid device public key length: {e}")))?;
        let verifying_key =
            VerifyingKey::from_bytes(&key_array).map_err(|e| {
                Error::Validation(format!("Invalid device public key: {e}"))
            })?;

        // Parse the signature
        let sig_bytes = decode_hex(&signature_hex)
            .map_err(|e| Error::Validation(format!("Invalid signature hex: {e}")))?;
        let sig_array: [u8; 64] = sig_bytes
            .as_slice()
            .try_into()
            .map_err(|e| Error::Validation(format!("Invalid signature length: {e}")))?;
        let signature = Signature::from_bytes(&sig_array);

        // The message signed is the device_id string
        let message = device_id.to_string().into_bytes();

        // Verify the signature
        verifying_key
            .verify_strict(&message, &signature)
            .map_err(|e| Error::Validation(format!("Signature verification failed: {e}")))?;

        // Issue a session token
        let token = uuid::Uuid::new_v4().to_string();
        let now = chrono::Utc::now();
        let session = SessionInfo {
            id: SessionId::new(),
            device_id,
            created_at: now,
            expires_at: now + chrono::Duration::minutes(30),
            is_active: true,
        };

        self.sessions.write().await.insert(token.clone(), session);

        Ok(token)
    }

    /// Validate a session token and return the associated device ID.
    async fn validate_session(&self, session_token: String) -> Result<DeviceId> {
        let device_id = {
            let sessions = self.sessions.read().await;
            let session = sessions
                .get(&session_token)
                .ok_or_else(|| Error::Validation("Invalid session token".to_string()))?;

            if !session.is_active {
                return Err(Error::Validation("Session is not active".to_string()));
            }

            if chrono::Utc::now() > session.expires_at {
                return Err(Error::Validation("Session has expired".to_string()));
            }

            session.device_id
        };

        // Revoking a device must immediately invalidate its live sessions;
        // otherwise a revoked token would keep working until it expires.
        {
            let devices = self.devices.read().await;
            if let Some(device) = devices.get(&device_id) {
                if device.is_revoked {
                    return Err(Error::Validation(format!(
                        "Device {device_id} is revoked"
                    )));
                }
            }
        }

        Ok(device_id)
    }

    /// Revoke a session token.
    async fn revoke_session(&self, session_token: String) -> Result<()> {
        let mut sessions = self.sessions.write().await;
        match sessions.get_mut(&session_token) {
            Some(session) => {
                session.is_active = false;
                Ok(())
            }
            None => Err(Error::Validation("Invalid session token".to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use rand::{Rng, RngCore};

    fn test_public_key() -> Vec<u8> {
        vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32]
    }

    #[tokio::test]
    async fn test_request_pairing_creates_pending_pairing() {
        let service = IdentityServiceImpl::new();
        let request = service
            .request_pairing("test-device".to_string(), test_public_key())
            .await
            .unwrap();

        assert_eq!(request.device_name, "test-device");
        assert_eq!(request.state, PairingState::Pending);
        assert!(request.pairing_code.len() == 6);
        assert!(request.pairing_code.chars().all(|c| c.is_ascii_digit()));
        assert!(request.expires_at > chrono::Utc::now());
    }

    #[tokio::test]
    async fn test_approve_pairing_registers_device() {
        let service = IdentityServiceImpl::new();
        let request = service
            .request_pairing("test-device".to_string(), test_public_key())
            .await
            .unwrap();

        let device_id = service.approve_pairing(request.pairing_code.clone()).await.unwrap();

        // Device should be registered
        let device = service.get_device(device_id).await.unwrap();
        assert_eq!(device.name, "test-device");
        assert!(!device.is_revoked);
        assert_eq!(device.public_key, test_public_key());

        // Pairing should be Approved
        let pairings = service.list_pairings().await.unwrap();
        let pairing = pairings.iter().find(|p| p.pairing_code == request.pairing_code).unwrap();
        assert_eq!(pairing.state, PairingState::Approved);
    }

    #[tokio::test]
    async fn test_reject_pairing_marks_rejected() {
        let service = IdentityServiceImpl::new();
        let request = service
            .request_pairing("test-device".to_string(), test_public_key())
            .await
            .unwrap();

        service.reject_pairing(request.pairing_code.clone()).await.unwrap();

        let pairings = service.list_pairings().await.unwrap();
        let pairing = pairings.iter().find(|p| p.pairing_code == request.pairing_code).unwrap();
        assert_eq!(pairing.state, PairingState::Rejected);
    }

    #[tokio::test]
    async fn test_approve_already_approved_fails() {
        let service = IdentityServiceImpl::new();
        let request = service
            .request_pairing("test-device".to_string(), test_public_key())
            .await
            .unwrap();

        service.approve_pairing(request.pairing_code.clone()).await.unwrap();
        let err = service.approve_pairing(request.pairing_code).await.unwrap_err();
        assert!(err.to_string().contains("already"));
    }

    #[tokio::test]
    async fn test_unknown_pairing_code_fails() {
        let service = IdentityServiceImpl::new();
        let err = service.approve_pairing("000000".to_string()).await.unwrap_err();
        assert!(err.to_string().contains("not found"));
    }

    #[tokio::test]
    async fn test_list_pairings_returns_all() {
        let service = IdentityServiceImpl::new();
        service.request_pairing("device-1".to_string(), test_public_key()).await.unwrap();
        service.request_pairing("device-2".to_string(), test_public_key()).await.unwrap();

        let pairings = service.list_pairings().await.unwrap();
        assert_eq!(pairings.len(), 2);
    }

    #[tokio::test]
    async fn test_authenticate_device_issues_session() {
        let service = IdentityServiceImpl::new();

        // Register a device with a real ed25519 keypair
        let mut key_bytes = [0u8; 32];
        rand::thread_rng().fill(&mut key_bytes);
        let signing_key = SigningKey::from_bytes(&key_bytes);
        let verifying_key: ed25519_dalek::VerifyingKey = (&signing_key).into();
        let public_key = verifying_key.as_bytes().to_vec();

        let request = service
            .request_pairing("auth-device".to_string(), public_key.clone())
            .await
            .unwrap();
        let device_id = service.approve_pairing(request.pairing_code).await.unwrap();

        // Sign the device_id string
        let message = device_id.to_string().into_bytes();
        let signature = signing_key.sign(&message);
        let signature_hex = signature.to_bytes().iter().map(|b| format!("{b:02x}")).collect::<String>();

        // Authenticate should issue a session token
        let token = service.authenticate_device(device_id, signature_hex).await.unwrap();
        assert!(!token.is_empty());

        // Validate the session returns the device_id
        let validated_id = service.validate_session(token.clone()).await.unwrap();
        assert_eq!(validated_id, device_id);

        // Revoke the session
        service.revoke_session(token.clone()).await.unwrap();
        let err = service.validate_session(token).await.unwrap_err();
        assert!(err.to_string().contains("not active"));
    }

    #[tokio::test]
    async fn test_authenticate_revoked_device_fails() {
        let service = IdentityServiceImpl::new();

        let mut key_bytes = [0u8; 32];
        rand::thread_rng().fill(&mut key_bytes);
        let signing_key = SigningKey::from_bytes(&key_bytes);
        let verifying_key: ed25519_dalek::VerifyingKey = (&signing_key).into();
        let public_key = verifying_key.as_bytes().to_vec();

        let request = service
            .request_pairing("revoked-device".to_string(), public_key.clone())
            .await
            .unwrap();
        let device_id = service.approve_pairing(request.pairing_code).await.unwrap();
        service.revoke_device(device_id).await.unwrap();

        let message = device_id.to_string().into_bytes();
        let signature = signing_key.sign(&message);
        let signature_hex = signature.to_bytes().iter().map(|b| format!("{b:02x}")).collect::<String>();

        let err = service.authenticate_device(device_id, signature_hex).await.unwrap_err();
        assert!(err.to_string().contains("revoked"));
    }

    #[tokio::test]
    async fn test_authenticate_bad_signature_fails() {
        let service = IdentityServiceImpl::new();

        let mut key_bytes = [0u8; 32];
        rand::thread_rng().fill(&mut key_bytes);
        let signing_key = SigningKey::from_bytes(&key_bytes);
        let verifying_key: ed25519_dalek::VerifyingKey = (&signing_key).into();
        let public_key = verifying_key.as_bytes().to_vec();

        let request = service
            .request_pairing("bad-sig-device".to_string(), public_key.clone())
            .await
            .unwrap();
        let device_id = service.approve_pairing(request.pairing_code).await.unwrap();

        // Use a random wrong signature
        let err = service
            .authenticate_device(device_id, "00".repeat(64))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("verification failed"));
    }

    #[tokio::test]
    async fn test_validate_nonexistent_session_fails() {
        let service = IdentityServiceImpl::new();
        let err = service.validate_session("nonexistent-token".to_string()).await.unwrap_err();
        assert!(err.to_string().contains("Invalid session"));
    }

    #[tokio::test]
    async fn test_revoking_device_invalidates_live_session() {
        let service = IdentityServiceImpl::new();

        let mut key_bytes = [0u8; 32];
        rand::thread_rng().fill(&mut key_bytes);
        let signing_key = SigningKey::from_bytes(&key_bytes);
        let verifying_key: ed25519_dalek::VerifyingKey = (&signing_key).into();
        let public_key = verifying_key.as_bytes().to_vec();

        let request = service
            .request_pairing("live-session-device".to_string(), public_key)
            .await
            .unwrap();
        let device_id = service.approve_pairing(request.pairing_code).await.unwrap();

        let message = device_id.to_string().into_bytes();
        let signature_hex = signing_key
            .sign(&message)
            .to_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        let token = service
            .authenticate_device(device_id, signature_hex)
            .await
            .unwrap();
        assert!(service.validate_session(token.clone()).await.is_ok());

        service.revoke_device(device_id).await.unwrap();
        let err = service.validate_session(token).await.unwrap_err();
        assert!(err.to_string().contains("revoked"));
    }
}

/// Decode a hex string into bytes.
fn decode_hex(hex: &str) -> Result<Vec<u8>> {
    if hex.len() % 2 != 0 {
        return Err(Error::Validation("Hex string has odd length".to_string()));
    }
    let mut bytes = Vec::with_capacity(hex.len() / 2);
    for i in (0..hex.len()).step_by(2) {
        let byte = u8::from_str_radix(&hex[i..i + 2], 16)
            .map_err(|e| Error::Validation(format!("Invalid hex: {e}")))?;
        bytes.push(byte);
    }
    Ok(bytes)
}