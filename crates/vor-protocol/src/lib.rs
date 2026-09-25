// SPDX-License-Identifier: MPL-2.0

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use thiserror::Error;

pub type Digest32 = [u8; 32];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Capability {
    pub name: String,
    #[serde(default)]
    pub constraints: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ActionEnvelope {
    pub request_id: String,
    pub organization_id: String,
    pub actor_id: String,
    pub device_id: String,
    pub action: String,
    pub target: String,
    #[serde(default)]
    pub parameters: BTreeMap<String, Value>,
    #[serde(default)]
    pub requested_capabilities: Vec<Capability>,
    pub expires_at_unix_ms: u64,
    pub nonce: Vec<u8>,
}

impl ActionEnvelope {
    fn normalized(&self) -> Self {
        let mut out = self.clone();
        for cap in &mut out.requested_capabilities {
            cap.constraints.sort();
            cap.constraints.dedup();
        }
        out.requested_capabilities
            .sort_by(|a, b| a.name.cmp(&b.name).then(a.constraints.cmp(&b.constraints)));
        out
    }

    pub fn digest(&self) -> Result<Digest32, ProtocolError> {
        let bytes = serde_json::to_vec(&self.normalized())?;
        Ok(Sha256::digest(bytes).into())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ActionRequest {
    pub envelope: ActionEnvelope,
    pub envelope_digest: Digest32,
}
impl ActionRequest {
    pub fn seal(envelope: ActionEnvelope) -> Result<Self, ProtocolError> {
        validate_envelope(&envelope)?;
        let envelope_digest = envelope.digest()?;
        Ok(Self {
            envelope,
            envelope_digest,
        })
    }

    pub fn verify(&self, now_unix_ms: u64) -> Result<(), ProtocolError> {
        validate_envelope(&self.envelope)?;
        if self.envelope.digest()? != self.envelope_digest {
            return Err(ProtocolError::DigestMismatch);
        }
        if self.envelope.expires_at_unix_ms <= now_unix_ms {
            return Err(ProtocolError::Expired);
        }
        Ok(())
    }

    pub fn digest_hex(&self) -> String {
        hex::encode(self.envelope_digest)
    }
}

fn validate_envelope(envelope: &ActionEnvelope) -> Result<(), ProtocolError> {
    for (name, value) in [
        ("request_id", envelope.request_id.as_str()),
        ("organization_id", envelope.organization_id.as_str()),
        ("actor_id", envelope.actor_id.as_str()),
        ("device_id", envelope.device_id.as_str()),
        ("action", envelope.action.as_str()),
        ("target", envelope.target.as_str()),
    ] {
        if value.trim().is_empty() {
            return Err(ProtocolError::MissingField(name));
        }
    }
    if envelope.expires_at_unix_ms == 0 {
        return Err(ProtocolError::InvalidExpiry);
    }
    if envelope.nonce.len() < 16 {
        return Err(ProtocolError::NonceTooShort);
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyDecisionKind {
    Auto,
    Approval,
    Deny,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyDecision {
    pub request_id: String,
    pub kind: PolicyDecisionKind,
    pub policy_id: String,
    pub reason_code: String,
    pub required_capability: Option<String>,
    pub envelope_digest: Digest32,
}

#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error("missing required field: {0}")]
    MissingField(&'static str),
    #[error("expiry must be non-zero")]
    InvalidExpiry,
    #[error("nonce must be at least 16 bytes")]
    NonceTooShort,
    #[error("request envelope digest does not match content")]
    DigestMismatch,
    #[error("request has expired")]
    Expired,
    #[error("serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn envelope() -> ActionEnvelope {
        ActionEnvelope {
            request_id: "req-1".into(),
            organization_id: "org-1".into(),
            actor_id: "actor-1".into(),
            device_id: "device-1".into(),
            action: "filesystem.read".into(),
            target: r"D:\Proyectos\demo\README.md".into(),
            parameters: BTreeMap::new(),
            requested_capabilities: vec![],
            expires_at_unix_ms: 2_000,
            nonce: vec![7; 16],
        }
    }

    #[test]
    fn detects_mutation_after_sealing() {
        let mut request = ActionRequest::seal(envelope()).unwrap();
        request.envelope.target.push_str(".changed");
        assert!(matches!(
            request.verify(1_000),
            Err(ProtocolError::DigestMismatch)
        ));
    }

    #[test]
    fn rejects_expired_request() {
        let request = ActionRequest::seal(envelope()).unwrap();
        assert!(matches!(request.verify(2_000), Err(ProtocolError::Expired)));
    }
}
