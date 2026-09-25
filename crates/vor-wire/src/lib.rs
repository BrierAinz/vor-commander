// SPDX-License-Identifier: MPL-2.0

use prost::Message;
use serde_json::Value as JsonValue;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
use thiserror::Error;
use vor_approval::{ApprovalChallenge, SignedApproval};
use vor_protocol::{ActionEnvelope, ActionRequest, Capability as CoreCapability};

pub mod v1 {
    include!(concat!(env!("OUT_DIR"), "/vor.commander.v1.rs"));
}

pub const WIRE_VERSION: u32 = 1;
pub const MAX_FRAME_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_ID_LEN: usize = 128;
pub type Digest32 = [u8; 32];

pub fn encode_frame(frame: &v1::RelayFrame) -> Result<Vec<u8>, WireError> {
    validate_frame_shape(frame)?;
    let len = frame.encoded_len();
    if len > MAX_FRAME_BYTES {
        return Err(WireError::FrameTooLarge(len));
    }
    Ok(frame.encode_to_vec())
}

pub fn decode_frame(bytes: &[u8]) -> Result<v1::RelayFrame, WireError> {
    if bytes.len() > MAX_FRAME_BYTES {
        return Err(WireError::FrameTooLarge(bytes.len()));
    }
    let frame = v1::RelayFrame::decode(bytes)?;
    validate_frame_shape(&frame)?;
    Ok(frame)
}
pub fn frame_digest(frame: &v1::RelayFrame) -> Result<Digest32, WireError> {
    Ok(Sha256::digest(encode_frame(frame)?).into())
}

pub fn verify_frame_at(frame: &v1::RelayFrame, now_unix_ms: u64) -> Result<(), WireError> {
    validate_frame_shape(frame)?;
    let expires = frame
        .expires_at
        .as_ref()
        .ok_or(WireError::MissingExpiry)
        .and_then(timestamp_to_ms)?;
    if expires <= now_unix_ms {
        return Err(WireError::Expired);
    }
    Ok(())
}

fn validate_frame_shape(frame: &v1::RelayFrame) -> Result<(), WireError> {
    if frame.wire_version != WIRE_VERSION {
        return Err(WireError::UnsupportedVersion(frame.wire_version));
    }
    validate_id("message_id", &frame.message_id)?;
    validate_id("device_id", &frame.device_id)?;
    if frame.nonce.len() < 16 {
        return Err(WireError::NonceTooShort);
    }
    if frame.payload.is_none() {
        return Err(WireError::MissingPayload);
    }
    Ok(())
}
fn validate_id(name: &'static str, value: &str) -> Result<(), WireError> {
    if value.trim().is_empty() || value.len() > MAX_ID_LEN {
        return Err(WireError::InvalidId(name));
    }
    Ok(())
}

fn timestamp_to_ms(value: &prost_types::Timestamp) -> Result<u64, WireError> {
    if value.seconds < 0 || value.nanos < 0 || value.nanos >= 1_000_000_000 {
        return Err(WireError::InvalidTimestamp);
    }
    let seconds = u64::try_from(value.seconds).map_err(|_| WireError::InvalidTimestamp)?;
    let millis = seconds
        .checked_mul(1000)
        .and_then(|base| base.checked_add((value.nanos as u64) / 1_000_000))
        .ok_or(WireError::InvalidTimestamp)?;
    Ok(millis)
}

pub fn action_request_from_proto(value: &v1::ActionRequest) -> Result<ActionRequest, WireError> {
    if value.envelope_digest.len() != 32 {
        return Err(WireError::InvalidActionDigest);
    }
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&value.envelope_digest);
    let expires_at_unix_ms = value
        .expires_at
        .as_ref()
        .ok_or(WireError::MissingExpiry)
        .and_then(timestamp_to_ms)?;
    let parameters = if value.parameters_json.is_empty() {
        BTreeMap::new()
    } else {
        serde_json::from_slice::<BTreeMap<String, JsonValue>>(&value.parameters_json)?
    };
    let envelope = ActionEnvelope {
        request_id: value.request_id.clone(),
        organization_id: value.organization_id.clone(),
        actor_id: value.actor_id.clone(),
        device_id: value.device_id.clone(),
        action: value.action.clone(),
        target: value.target.clone(),
        parameters,
        requested_capabilities: value
            .requested_capabilities
            .iter()
            .map(|cap| CoreCapability {
                name: cap.name.clone(),
                constraints: cap.constraints.clone(),
            })
            .collect(),
        expires_at_unix_ms,
        nonce: value.nonce.clone(),
    };
    let sealed = ActionRequest::seal(envelope)?;
    if sealed.envelope_digest != digest {
        return Err(WireError::ActionDigestMismatch);
    }
    Ok(sealed)
}

pub fn action_request_to_proto(value: &ActionRequest) -> Result<v1::ActionRequest, WireError> {
    value.verify(0)?;
    Ok(v1::ActionRequest {
        request_id: value.envelope.request_id.clone(),
        organization_id: value.envelope.organization_id.clone(),
        actor_id: value.envelope.actor_id.clone(),
        device_id: value.envelope.device_id.clone(),
        action: value.envelope.action.clone(),
        target: value.envelope.target.clone(),
        parameters_json: serde_json::to_vec(&value.envelope.parameters)?,
        requested_capabilities: value
            .envelope
            .requested_capabilities
            .iter()
            .map(|cap| v1::Capability {
                name: cap.name.clone(),
                constraints: cap.constraints.clone(),
            })
            .collect(),
        expires_at: Some(ms_to_timestamp(value.envelope.expires_at_unix_ms)?),
        nonce: value.envelope.nonce.clone(),
        envelope_digest: value.envelope_digest.to_vec(),
    })
}

pub fn approval_grant_from_proto(value: &v1::ApprovalGrant) -> Result<SignedApproval, WireError> {
    if value.request_id.trim().is_empty()
        || value.approver_id.trim().is_empty()
        || value.policy_id.trim().is_empty()
        || value.request_id.len() > MAX_ID_LEN
        || value.approver_id.len() > MAX_ID_LEN
        || value.policy_id.len() > 4096
    {
        return Err(WireError::InvalidApprovalField);
    }
    if value.envelope_digest.len() != 32 {
        return Err(WireError::InvalidApprovalDigest);
    }
    if value.signature.len() != 64 {
        return Err(WireError::InvalidApprovalSignature);
    }
    if value.approval_nonce.len() != 32 {
        return Err(WireError::InvalidApprovalNonce);
    }
    let expires_at_unix_ms = value
        .expires_at
        .as_ref()
        .ok_or(WireError::MissingExpiry)
        .and_then(timestamp_to_ms)?;
    let mut envelope_digest = [0u8; 32];
    envelope_digest.copy_from_slice(&value.envelope_digest);
    let mut signature = [0u8; 64];
    signature.copy_from_slice(&value.signature);
    let mut approval_nonce = [0u8; 32];
    approval_nonce.copy_from_slice(&value.approval_nonce);
    Ok(SignedApproval {
        challenge: ApprovalChallenge {
            request_id: value.request_id.clone(),
            envelope_digest,
            policy_id: value.policy_id.clone(),
            required_capability: if value.required_capability.is_empty() {
                None
            } else {
                Some(value.required_capability.clone())
            },
            expires_at_unix_ms,
            approval_nonce,
        },
        approver_id: value.approver_id.clone(),
        signature,
    })
}

pub fn approval_grant_to_proto(value: &SignedApproval) -> Result<v1::ApprovalGrant, WireError> {
    if value.challenge.request_id.trim().is_empty()
        || value.approver_id.trim().is_empty()
        || value.challenge.policy_id.trim().is_empty()
    {
        return Err(WireError::InvalidApprovalField);
    }
    Ok(v1::ApprovalGrant {
        request_id: value.challenge.request_id.clone(),
        approver_id: value.approver_id.clone(),
        envelope_digest: value.challenge.envelope_digest.to_vec(),
        expires_at: Some(ms_to_timestamp(value.challenge.expires_at_unix_ms)?),
        signature: value.signature.to_vec(),
        policy_id: value.challenge.policy_id.clone(),
        required_capability: value
            .challenge
            .required_capability
            .clone()
            .unwrap_or_default(),
        approval_nonce: value.challenge.approval_nonce.to_vec(),
    })
}

fn ms_to_timestamp(value: u64) -> Result<prost_types::Timestamp, WireError> {
    let seconds = i64::try_from(value / 1000).map_err(|_| WireError::InvalidTimestamp)?;
    let nanos =
        i32::try_from((value % 1000) * 1_000_000).map_err(|_| WireError::InvalidTimestamp)?;
    Ok(prost_types::Timestamp { seconds, nanos })
}

fn nonce_digest(nonce: &[u8]) -> Digest32 {
    Sha256::digest(nonce).into()
}

pub struct ReplayGuard {
    max_entries: usize,
    message_ids: HashMap<(String, String), u64>,
    nonces: HashMap<(String, Digest32), u64>,
}
impl ReplayGuard {
    pub fn new(max_entries: usize) -> Result<Self, WireError> {
        if max_entries == 0 {
            return Err(WireError::InvalidCapacity);
        }
        Ok(Self {
            max_entries,
            message_ids: HashMap::new(),
            nonces: HashMap::new(),
        })
    }

    pub fn accept(&mut self, frame: &v1::RelayFrame, now_unix_ms: u64) -> Result<(), WireError> {
        verify_frame_at(frame, now_unix_ms)?;
        self.prune(now_unix_ms);
        let expiry = timestamp_to_ms(frame.expires_at.as_ref().ok_or(WireError::MissingExpiry)?)?;
        let message_key = (frame.device_id.clone(), frame.message_id.clone());
        let nonce_key = (frame.device_id.clone(), nonce_digest(&frame.nonce));
        if self.message_ids.contains_key(&message_key) || self.nonces.contains_key(&nonce_key) {
            return Err(WireError::ReplayDetected);
        }
        if self.message_ids.len() >= self.max_entries || self.nonces.len() >= self.max_entries {
            return Err(WireError::ReplayWindowFull);
        }
        self.message_ids.insert(message_key, expiry);
        self.nonces.insert(nonce_key, expiry);
        Ok(())
    }

    pub fn prune(&mut self, now_unix_ms: u64) {
        self.message_ids.retain(|_, expiry| *expiry > now_unix_ms);
        self.nonces.retain(|_, expiry| *expiry > now_unix_ms);
    }
}
#[derive(Debug, Error)]
pub enum WireError {
    #[error("protobuf decode failed: {0}")]
    Decode(#[from] prost::DecodeError),
    #[error("relay frame exceeds maximum size: {0} bytes")]
    FrameTooLarge(usize),
    #[error("unsupported wire version: {0}")]
    UnsupportedVersion(u32),
    #[error("invalid relay identifier: {0}")]
    InvalidId(&'static str),
    #[error("relay nonce must be at least 16 bytes")]
    NonceTooShort,
    #[error("relay frame payload is missing")]
    MissingPayload,
    #[error("relay frame expiry is missing")]
    MissingExpiry,
    #[error("relay timestamp is invalid")]
    InvalidTimestamp,
    #[error("relay frame has expired")]
    Expired,
    #[error("relay frame replay detected")]
    ReplayDetected,
    #[error("replay window is full")]
    ReplayWindowFull,
    #[error("replay window capacity must be positive")]
    InvalidCapacity,
    #[error("action envelope digest must be exactly 32 bytes")]
    InvalidActionDigest,
    #[error("action envelope digest does not match canonical request")]
    ActionDigestMismatch,
    #[error("approval contains an invalid required field")]
    InvalidApprovalField,
    #[error("approval envelope digest must be exactly 32 bytes")]
    InvalidApprovalDigest,
    #[error("approval signature must be exactly 64 bytes")]
    InvalidApprovalSignature,
    #[error("approval nonce must be exactly 32 bytes")]
    InvalidApprovalNonce,
    #[error("action parameters JSON failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("core protocol validation failed: {0}")]
    Protocol(#[from] vor_protocol::ProtocolError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use v1::relay_frame::Payload;

    fn heartbeat(message_id: &str, nonce_byte: u8, expires_ms: u64) -> v1::RelayFrame {
        let timestamp = prost_types::Timestamp {
            seconds: (expires_ms / 1000) as i64,
            nanos: ((expires_ms % 1000) * 1_000_000) as i32,
        };
        v1::RelayFrame {
            wire_version: WIRE_VERSION,
            message_id: message_id.to_owned(),
            device_id: "device-1".into(),
            expires_at: Some(timestamp),
            nonce: vec![nonce_byte; 16],
            payload: Some(Payload::Heartbeat(v1::RelayHeartbeat {
                sent_at: Some(timestamp),
            })),
        }
    }

    #[test]
    fn protobuf_roundtrip_preserves_frame() {
        let frame = heartbeat("m1", 7, 5_000);
        let encoded = encode_frame(&frame).unwrap();
        let decoded = decode_frame(&encoded).unwrap();
        assert_eq!(decoded, frame);
        assert_eq!(
            frame_digest(&decoded).unwrap(),
            frame_digest(&frame).unwrap()
        );
    }

    #[test]
    fn expiry_is_enforced() {
        let frame = heartbeat("m1", 7, 1_000);
        assert!(matches!(
            verify_frame_at(&frame, 1_000),
            Err(WireError::Expired)
        ));
    }
    #[test]
    fn replay_guard_rejects_message_or_nonce_reuse() {
        let mut guard = ReplayGuard::new(8).unwrap();
        let first = heartbeat("m1", 1, 10_000);
        guard.accept(&first, 1_000).unwrap();
        assert!(matches!(
            guard.accept(&first, 1_001),
            Err(WireError::ReplayDetected)
        ));

        let same_nonce = heartbeat("m2", 1, 10_000);
        assert!(matches!(
            guard.accept(&same_nonce, 1_002),
            Err(WireError::ReplayDetected)
        ));
    }

    #[test]
    fn expired_entries_are_pruned_before_capacity_check() {
        let mut guard = ReplayGuard::new(1).unwrap();
        guard.accept(&heartbeat("m1", 1, 2_000), 1_000).unwrap();
        guard.accept(&heartbeat("m2", 2, 4_000), 2_001).unwrap();
    }

    #[test]
    fn oversized_frame_is_rejected_before_encoding() {
        let mut frame = heartbeat("m1", 3, 5_000);
        frame.payload = Some(Payload::Ack(v1::RelayAck {
            message_id: "m1".into(),
            status: "x".repeat(MAX_FRAME_BYTES),
            payload_digest: vec![],
        }));
        assert!(matches!(
            encode_frame(&frame),
            Err(WireError::FrameTooLarge(_))
        ));
    }

    #[test]
    fn canonical_action_request_roundtrip_preserves_digest() {
        use serde_json::json;
        use vor_protocol::{ActionEnvelope, ActionRequest, Capability};
        let mut parameters = BTreeMap::new();
        parameters.insert("nested".into(), json!({"a": [1, true, null], "b": "x"}));
        let request = ActionRequest::seal(ActionEnvelope {
            request_id: "req-wire-1".into(),
            organization_id: "org-1".into(),
            actor_id: "actor-1".into(),
            device_id: "device-1".into(),
            action: "filesystem.read".into(),
            target: r"D:\Proyectos\demo\README.md".into(),
            parameters,
            requested_capabilities: vec![Capability {
                name: "read".into(),
                constraints: vec!["b".into(), "a".into()],
            }],
            expires_at_unix_ms: 50_123,
            nonce: vec![8; 16],
        })
        .unwrap();
        let proto = action_request_to_proto(&request).unwrap();
        let decoded = action_request_from_proto(&proto).unwrap();
        assert_eq!(decoded, request);
    }

    #[test]
    fn canonical_action_request_rejects_tampered_digest() {
        use vor_protocol::{ActionEnvelope, ActionRequest};
        let request = ActionRequest::seal(ActionEnvelope {
            request_id: "req-wire-2".into(),
            organization_id: "org".into(),
            actor_id: "actor".into(),
            device_id: "device-1".into(),
            action: "process.list".into(),
            target: "local".into(),
            parameters: BTreeMap::new(),
            requested_capabilities: vec![],
            expires_at_unix_ms: 10_000,
            nonce: vec![9; 16],
        })
        .unwrap();
        let mut proto = action_request_to_proto(&request).unwrap();
        proto.envelope_digest[0] ^= 0xff;
        assert!(matches!(
            action_request_from_proto(&proto),
            Err(WireError::ActionDigestMismatch)
        ));
    }

    #[test]
    fn approval_grant_roundtrip_preserves_signed_fields() {
        let approval = SignedApproval {
            challenge: ApprovalChallenge {
                request_id: "req-approved-1".into(),
                envelope_digest: [4; 32],
                policy_id: "policy-1".into(),
                required_capability: Some("filesystem.write".into()),
                expires_at_unix_ms: 50_000,
                approval_nonce: [7; 32],
            },
            approver_id: "operator-1".into(),
            signature: [9; 64],
        };
        let proto = approval_grant_to_proto(&approval).unwrap();
        assert_eq!(approval_grant_from_proto(&proto).unwrap(), approval);
    }

    #[test]
    fn approval_grant_rejects_malformed_signature() {
        let proto = v1::ApprovalGrant {
            request_id: "req-approved-2".into(),
            approver_id: "operator-1".into(),
            envelope_digest: vec![1; 32],
            expires_at: Some(ms_to_timestamp(50_000).unwrap()),
            signature: vec![2; 63],
            policy_id: "policy-1".into(),
            required_capability: String::new(),
            approval_nonce: vec![3; 32],
        };
        assert!(matches!(
            approval_grant_from_proto(&proto),
            Err(WireError::InvalidApprovalSignature)
        ));
    }
}
