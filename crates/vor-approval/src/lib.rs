// SPDX-License-Identifier: MPL-2.0

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use std::collections::HashMap;
use thiserror::Error;
use vor_protocol::{ActionRequest, Digest32, PolicyDecision, PolicyDecisionKind, ProtocolError};

const APPROVAL_DOMAIN: &[u8] = b"vor-commander:approval:v1\0";
const NONCE_BYTES: usize = 32;
const MAX_FIELD_BYTES: usize = 4096;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalChallenge {
    pub request_id: String,
    pub envelope_digest: Digest32,
    pub policy_id: String,
    pub required_capability: Option<String>,
    pub expires_at_unix_ms: u64,
    pub approval_nonce: [u8; NONCE_BYTES],
}

#[derive(Clone, PartialEq, Eq)]
pub struct SignedApproval {
    pub challenge: ApprovalChallenge,
    pub approver_id: String,
    pub signature: [u8; Signature::BYTE_SIZE],
}

impl std::fmt::Debug for SignedApproval {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignedApproval")
            .field("challenge", &self.challenge)
            .field("approver_id", &self.approver_id)
            .field("signature", &"<redacted>")
            .finish()
    }
}
impl ApprovalChallenge {
    pub fn issue(
        request: &ActionRequest,
        decision: &PolicyDecision,
        now_unix_ms: u64,
        expires_at_unix_ms: u64,
    ) -> Result<Self, ApprovalError> {
        request.verify(now_unix_ms)?;
        ensure_decision_matches(request, decision)?;
        if decision.kind != PolicyDecisionKind::Approval {
            return Err(ApprovalError::DecisionDoesNotRequireApproval);
        }
        if expires_at_unix_ms <= now_unix_ms
            || expires_at_unix_ms > request.envelope.expires_at_unix_ms
        {
            return Err(ApprovalError::InvalidExpiry);
        }
        if decision.policy_id.trim().is_empty() {
            return Err(ApprovalError::InvalidChallenge);
        }
        Ok(Self {
            request_id: request.envelope.request_id.clone(),
            envelope_digest: request.envelope_digest,
            policy_id: decision.policy_id.clone(),
            required_capability: decision.required_capability.clone(),
            expires_at_unix_ms,
            approval_nonce: rand::random(),
        })
    }
}

pub fn sign_approval(
    challenge: ApprovalChallenge,
    approver_id: impl Into<String>,
    signing_key: &SigningKey,
) -> Result<SignedApproval, ApprovalError> {
    let approver_id = approver_id.into();
    validate_text("approver_id", &approver_id)?;
    let message = approval_message(&challenge, &approver_id)?;
    let signature = signing_key.sign(&message).to_bytes();
    Ok(SignedApproval {
        challenge,
        approver_id,
        signature,
    })
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ApproverAuthority {
    Approve,
    Elevated,
    Owner,
}

impl ApproverAuthority {
    pub fn parse(value: &str) -> Result<Self, ApprovalError> {
        match value.trim().to_ascii_lowercase().as_str() {
            "approve" | "approval" => Ok(Self::Approve),
            "elevated" => Ok(Self::Elevated),
            "owner" | "full_owner" => Ok(Self::Owner),
            _ => Err(ApprovalError::InvalidApproverAuthority),
        }
    }

    fn required_for(value: Option<&str>) -> Result<Self, ApprovalError> {
        match value {
            None => Ok(Self::Approve),
            Some("elevated") => Ok(Self::Elevated),
            Some("owner" | "full_owner") => Ok(Self::Owner),
            Some(_) => Err(ApprovalError::UnsupportedRequiredCapability),
        }
    }
}

#[derive(Clone)]
struct TrustedApprover {
    key: VerifyingKey,
    authority: ApproverAuthority,
    organization_id: Option<String>,
    revoked: bool,
}

#[derive(Default)]
pub struct ApprovalVerifier {
    approvers: HashMap<String, TrustedApprover>,
    require_organization_scope: bool,
}

impl ApprovalVerifier {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn require_organization_scope(&mut self) {
        self.require_organization_scope = true;
    }

    pub fn add_approver(
        &mut self,
        approver_id: impl Into<String>,
        public_key: [u8; 32],
    ) -> Result<(), ApprovalError> {
        self.add_approver_with_authority(approver_id, public_key, ApproverAuthority::Approve)
    }

    pub fn add_approver_with_authority(
        &mut self,
        approver_id: impl Into<String>,
        public_key: [u8; 32],
        authority: ApproverAuthority,
    ) -> Result<(), ApprovalError> {
        self.add_approver_for_organization(approver_id, public_key, authority, None::<String>)
    }

    pub fn add_approver_for_organization(
        &mut self,
        approver_id: impl Into<String>,
        public_key: [u8; 32],
        authority: ApproverAuthority,
        organization_id: Option<impl Into<String>>,
    ) -> Result<(), ApprovalError> {
        let approver_id = approver_id.into();
        validate_text("approver_id", &approver_id)?;
        if self.approvers.contains_key(&approver_id) {
            return Err(ApprovalError::DuplicateApprover);
        }
        let organization_id = organization_id.map(Into::into);
        if let Some(organization_id) = organization_id.as_deref() {
            validate_text("organization_id", organization_id)?;
        }
        let key =
            VerifyingKey::from_bytes(&public_key).map_err(|_| ApprovalError::InvalidPublicKey)?;
        self.approvers.insert(
            approver_id,
            TrustedApprover {
                key,
                authority,
                organization_id,
                revoked: false,
            },
        );
        Ok(())
    }

    pub fn revoke_approver(&mut self, approver_id: &str) -> Result<(), ApprovalError> {
        validate_text("approver_id", approver_id)?;
        let approver = self
            .approvers
            .get_mut(approver_id)
            .ok_or(ApprovalError::UnknownApprover)?;
        approver.revoked = true;
        Ok(())
    }

    pub fn rotate_approver_for_organization(
        &mut self,
        approver_id: impl Into<String>,
        public_key: [u8; 32],
        authority: ApproverAuthority,
        organization_id: impl Into<String>,
    ) -> Result<(), ApprovalError> {
        let approver_id = approver_id.into();
        validate_text("approver_id", &approver_id)?;
        let organization_id = organization_id.into();
        validate_text("organization_id", &organization_id)?;
        let key =
            VerifyingKey::from_bytes(&public_key).map_err(|_| ApprovalError::InvalidPublicKey)?;
        self.approvers.insert(
            approver_id,
            TrustedApprover {
                key,
                authority,
                organization_id: Some(organization_id),
                revoked: false,
            },
        );
        Ok(())
    }

    pub fn verify(
        &self,
        request: &ActionRequest,
        decision: &PolicyDecision,
        approval: &SignedApproval,
        now_unix_ms: u64,
    ) -> Result<(), ApprovalError> {
        request.verify(now_unix_ms)?;
        ensure_decision_matches(request, decision)?;
        if decision.kind != PolicyDecisionKind::Approval {
            return Err(ApprovalError::DecisionDoesNotRequireApproval);
        }
        verify_challenge_binding(request, decision, &approval.challenge, now_unix_ms)?;
        let approver = self
            .approvers
            .get(&approval.approver_id)
            .ok_or(ApprovalError::UnknownApprover)?;
        if approver.revoked {
            return Err(ApprovalError::ApproverRevoked);
        }
        let required = ApproverAuthority::required_for(decision.required_capability.as_deref())?;
        if approver.authority < required {
            return Err(ApprovalError::InsufficientApproverAuthority);
        }
        if self.require_organization_scope && approver.organization_id.is_none() {
            return Err(ApprovalError::ApproverTenantMismatch);
        }
        if let Some(organization_id) = approver.organization_id.as_deref()
            && organization_id != request.envelope.organization_id
        {
            return Err(ApprovalError::ApproverTenantMismatch);
        }
        let message = approval_message(&approval.challenge, &approval.approver_id)?;
        let signature = Signature::from_bytes(&approval.signature);
        approver
            .key
            .verify(&message, &signature)
            .map_err(|_| ApprovalError::InvalidSignature)
    }
}
fn ensure_decision_matches(
    request: &ActionRequest,
    decision: &PolicyDecision,
) -> Result<(), ApprovalError> {
    if decision.request_id != request.envelope.request_id
        || decision.envelope_digest != request.envelope_digest
    {
        return Err(ApprovalError::DecisionMismatch);
    }
    Ok(())
}

fn verify_challenge_binding(
    request: &ActionRequest,
    decision: &PolicyDecision,
    challenge: &ApprovalChallenge,
    now_unix_ms: u64,
) -> Result<(), ApprovalError> {
    if challenge.request_id != request.envelope.request_id
        || challenge.envelope_digest != request.envelope_digest
        || challenge.policy_id != decision.policy_id
        || challenge.required_capability != decision.required_capability
    {
        return Err(ApprovalError::ChallengeMismatch);
    }
    if challenge.expires_at_unix_ms <= now_unix_ms {
        return Err(ApprovalError::ApprovalExpired);
    }
    if challenge.expires_at_unix_ms > request.envelope.expires_at_unix_ms {
        return Err(ApprovalError::InvalidExpiry);
    }
    Ok(())
}

fn approval_message(
    challenge: &ApprovalChallenge,
    approver_id: &str,
) -> Result<Vec<u8>, ApprovalError> {
    let mut out = Vec::with_capacity(256);
    out.extend_from_slice(APPROVAL_DOMAIN);
    push_text(&mut out, &challenge.request_id)?;
    out.extend_from_slice(&challenge.envelope_digest);
    push_text(&mut out, &challenge.policy_id)?;
    match &challenge.required_capability {
        Some(value) => {
            out.push(1);
            push_text(&mut out, value)?;
        }
        None => out.push(0),
    }
    out.extend_from_slice(&challenge.expires_at_unix_ms.to_be_bytes());
    out.extend_from_slice(&challenge.approval_nonce);
    push_text(&mut out, approver_id)?;
    Ok(out)
}
fn push_text(out: &mut Vec<u8>, value: &str) -> Result<(), ApprovalError> {
    validate_text("signed field", value)?;
    let bytes = value.as_bytes();
    let len = u32::try_from(bytes.len()).map_err(|_| ApprovalError::InvalidChallenge)?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}

fn validate_text(_name: &'static str, value: &str) -> Result<(), ApprovalError> {
    if value.trim().is_empty() || value.len() > MAX_FIELD_BYTES || value.contains('\0') {
        return Err(ApprovalError::InvalidChallenge);
    }
    Ok(())
}

#[derive(Debug, Error)]
pub enum ApprovalError {
    #[error("request validation failed: {0}")]
    Protocol(#[from] ProtocolError),
    #[error("policy decision is not bound to the request")]
    DecisionMismatch,
    #[error("policy decision does not require approval")]
    DecisionDoesNotRequireApproval,
    #[error("approval challenge is invalid")]
    InvalidChallenge,
    #[error("approval challenge is not bound to request and policy decision")]
    ChallengeMismatch,
    #[error("approval expiry is invalid")]
    InvalidExpiry,
    #[error("approval has expired")]
    ApprovalExpired,
    #[error("approver is not trusted")]
    UnknownApprover,
    #[error("approver has been revoked")]
    ApproverRevoked,
    #[error("approver public key is invalid")]
    InvalidPublicKey,
    #[error("approver authority is invalid")]
    InvalidApproverAuthority,
    #[error("policy requires an unsupported approval capability")]
    UnsupportedRequiredCapability,
    #[error("approver lacks the authority required by policy")]
    InsufficientApproverAuthority,
    #[error("approver is not authorized for the request tenant")]
    ApproverTenantMismatch,
    #[error("approver is already registered")]
    DuplicateApprover,
    #[error("approval signature is invalid")]
    InvalidSignature,
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use vor_protocol::{ActionEnvelope, ActionRequest};

    fn request() -> ActionRequest {
        ActionRequest::seal(ActionEnvelope {
            request_id: "request-1".into(),
            organization_id: "org-1".into(),
            actor_id: "remote-client".into(),
            device_id: "device-1".into(),
            action: "terminal.elevated".into(),
            target: "powershell".into(),
            parameters: BTreeMap::new(),
            requested_capabilities: vec![],
            expires_at_unix_ms: 10_000,
            nonce: vec![5; 16],
        })
        .unwrap()
    }

    fn decision(request: &ActionRequest) -> PolicyDecision {
        PolicyDecision {
            request_id: request.envelope.request_id.clone(),
            kind: PolicyDecisionKind::Approval,
            policy_id: "local-default".into(),
            reason_code: "terminal_elevated".into(),
            required_capability: Some("elevated".into()),
            envelope_digest: request.envelope_digest,
        }
    }

    fn signer() -> SigningKey {
        SigningKey::from_bytes(&rand::random::<[u8; 32]>())
    }
    #[test]
    fn valid_signed_approval_verifies() {
        let request = request();
        let decision = decision(&request);
        let challenge = ApprovalChallenge::issue(&request, &decision, 1_000, 5_000).unwrap();
        let signing = signer();
        let approval = sign_approval(challenge, "operator-1", &signing).unwrap();
        let mut verifier = ApprovalVerifier::new();
        verifier
            .add_approver_with_authority(
                "operator-1",
                signing.verifying_key().to_bytes(),
                ApproverAuthority::Elevated,
            )
            .unwrap();
        verifier
            .verify(&request, &decision, &approval, 2_000)
            .unwrap();
    }

    #[test]
    fn tenant_scoped_approver_cannot_authorize_foreign_tenant_request() {
        let request = request();
        let decision = decision(&request);
        let challenge = ApprovalChallenge::issue(&request, &decision, 1_000, 5_000).unwrap();
        let signing = signer();
        let approval = sign_approval(challenge, "tenant-admin", &signing).unwrap();
        let mut verifier = ApprovalVerifier::new();
        verifier
            .add_approver_for_organization(
                "tenant-admin",
                signing.verifying_key().to_bytes(),
                ApproverAuthority::Elevated,
                Some("org-2"),
            )
            .unwrap();
        assert!(matches!(
            verifier.verify(&request, &decision, &approval, 2_000),
            Err(ApprovalError::ApproverTenantMismatch)
        ));

        let mut verifier = ApprovalVerifier::new();
        verifier
            .add_approver_for_organization(
                "tenant-admin",
                signing.verifying_key().to_bytes(),
                ApproverAuthority::Elevated,
                Some("org-1"),
            )
            .unwrap();
        verifier
            .verify(&request, &decision, &approval, 2_000)
            .unwrap();
    }

    #[test]
    fn tenant_mode_rejects_legacy_unscoped_approver() {
        let request = request();
        let decision = decision(&request);
        let challenge = ApprovalChallenge::issue(&request, &decision, 1_000, 5_000).unwrap();
        let signing = signer();
        let approval = sign_approval(challenge, "legacy-admin", &signing).unwrap();
        let mut verifier = ApprovalVerifier::new();
        verifier.require_organization_scope();
        verifier
            .add_approver_with_authority(
                "legacy-admin",
                signing.verifying_key().to_bytes(),
                ApproverAuthority::Elevated,
            )
            .unwrap();

        assert!(matches!(
            verifier.verify(&request, &decision, &approval, 2_000),
            Err(ApprovalError::ApproverTenantMismatch)
        ));
    }

    #[test]
    fn revoked_approver_rejects_previously_valid_signature() {
        let request = request();
        let decision = decision(&request);
        let challenge = ApprovalChallenge::issue(&request, &decision, 1_000, 5_000).unwrap();
        let signing = signer();
        let approval = sign_approval(challenge, "tenant-admin", &signing).unwrap();
        let mut verifier = ApprovalVerifier::new();
        verifier.require_organization_scope();
        verifier
            .add_approver_for_organization(
                "tenant-admin",
                signing.verifying_key().to_bytes(),
                ApproverAuthority::Elevated,
                Some("org-1"),
            )
            .unwrap();
        verifier
            .verify(&request, &decision, &approval, 2_000)
            .unwrap();
        verifier.revoke_approver("tenant-admin").unwrap();

        assert!(matches!(
            verifier.verify(&request, &decision, &approval, 2_100),
            Err(ApprovalError::ApproverRevoked)
        ));
    }

    #[test]
    fn rotated_approver_rejects_old_key_and_accepts_new_approval() {
        let request = request();
        let decision = decision(&request);
        let challenge = ApprovalChallenge::issue(&request, &decision, 1_000, 5_000).unwrap();
        let old_signing = signer();
        let old_approval = sign_approval(challenge.clone(), "tenant-admin", &old_signing).unwrap();
        let new_signing = SigningKey::from_bytes(&[9u8; 32]);
        let new_approval = sign_approval(challenge, "tenant-admin", &new_signing).unwrap();
        let mut verifier = ApprovalVerifier::new();
        verifier.require_organization_scope();
        verifier
            .add_approver_for_organization(
                "tenant-admin",
                old_signing.verifying_key().to_bytes(),
                ApproverAuthority::Elevated,
                Some("org-1"),
            )
            .unwrap();
        verifier
            .rotate_approver_for_organization(
                "tenant-admin",
                new_signing.verifying_key().to_bytes(),
                ApproverAuthority::Elevated,
                "org-1",
            )
            .unwrap();

        assert!(matches!(
            verifier.verify(&request, &decision, &old_approval, 2_000),
            Err(ApprovalError::InvalidSignature)
        ));
        verifier
            .verify(&request, &decision, &new_approval, 2_000)
            .unwrap();
    }

    #[test]
    fn policy_or_capability_mutation_is_rejected() {
        let request = request();
        let decision = decision(&request);
        let challenge = ApprovalChallenge::issue(&request, &decision, 1_000, 5_000).unwrap();
        let signing = signer();
        let mut approval = sign_approval(challenge, "operator-1", &signing).unwrap();
        let mut verifier = ApprovalVerifier::new();
        verifier
            .add_approver_with_authority(
                "operator-1",
                signing.verifying_key().to_bytes(),
                ApproverAuthority::Elevated,
            )
            .unwrap();
        approval.challenge.policy_id = "other-policy".into();
        assert!(matches!(
            verifier.verify(&request, &decision, &approval, 2_000),
            Err(ApprovalError::ChallengeMismatch)
        ));
    }

    #[test]
    fn wrong_signer_is_rejected() {
        let request = request();
        let decision = decision(&request);
        let challenge = ApprovalChallenge::issue(&request, &decision, 1_000, 5_000).unwrap();
        let signing = signer();
        let approval = sign_approval(challenge, "operator-1", &signing).unwrap();
        let trusted_other = signer();
        let mut verifier = ApprovalVerifier::new();
        verifier
            .add_approver_with_authority(
                "operator-1",
                trusted_other.verifying_key().to_bytes(),
                ApproverAuthority::Elevated,
            )
            .unwrap();
        assert!(matches!(
            verifier.verify(&request, &decision, &approval, 2_000),
            Err(ApprovalError::InvalidSignature)
        ));
    }
    #[test]
    fn expired_or_overlong_approval_is_rejected() {
        let request = request();
        let decision = decision(&request);
        assert!(matches!(
            ApprovalChallenge::issue(&request, &decision, 1_000, 11_000),
            Err(ApprovalError::InvalidExpiry)
        ));

        let challenge = ApprovalChallenge::issue(&request, &decision, 1_000, 2_000).unwrap();
        let signing = signer();
        let approval = sign_approval(challenge, "operator-1", &signing).unwrap();
        let mut verifier = ApprovalVerifier::new();
        verifier
            .add_approver_with_authority(
                "operator-1",
                signing.verifying_key().to_bytes(),
                ApproverAuthority::Elevated,
            )
            .unwrap();
        assert!(matches!(
            verifier.verify(&request, &decision, &approval, 2_000),
            Err(ApprovalError::ApprovalExpired)
        ));
    }

    #[test]
    fn default_approver_cannot_authorize_elevated_policy() {
        let request = request();
        let decision = decision(&request);
        let challenge = ApprovalChallenge::issue(&request, &decision, 1_000, 5_000).unwrap();
        let signing = signer();
        let approval = sign_approval(challenge, "reviewer", &signing).unwrap();
        let mut verifier = ApprovalVerifier::new();
        verifier
            .add_approver("reviewer", signing.verifying_key().to_bytes())
            .unwrap();
        assert!(matches!(
            verifier.verify(&request, &decision, &approval, 2_000),
            Err(ApprovalError::InsufficientApproverAuthority)
        ));
    }

    #[test]
    fn owner_satisfies_elevated_and_owner_but_elevated_does_not_satisfy_owner() {
        let request = request();
        let elevated_decision = decision(&request);
        let elevated_challenge =
            ApprovalChallenge::issue(&request, &elevated_decision, 1_000, 5_000).unwrap();
        let owner_signing = signer();
        let elevated_approval = sign_approval(elevated_challenge, "owner", &owner_signing).unwrap();
        let mut owner_verifier = ApprovalVerifier::new();
        owner_verifier
            .add_approver_with_authority(
                "owner",
                owner_signing.verifying_key().to_bytes(),
                ApproverAuthority::Owner,
            )
            .unwrap();
        owner_verifier
            .verify(&request, &elevated_decision, &elevated_approval, 2_000)
            .unwrap();

        let owner_decision = PolicyDecision {
            required_capability: Some("owner".into()),
            ..elevated_decision.clone()
        };
        let owner_challenge =
            ApprovalChallenge::issue(&request, &owner_decision, 1_000, 5_000).unwrap();
        let elevated_signing = signer();
        let rejected = sign_approval(owner_challenge.clone(), "admin", &elevated_signing).unwrap();
        let mut elevated_verifier = ApprovalVerifier::new();
        elevated_verifier
            .add_approver_with_authority(
                "admin",
                elevated_signing.verifying_key().to_bytes(),
                ApproverAuthority::Elevated,
            )
            .unwrap();
        assert!(matches!(
            elevated_verifier.verify(&request, &owner_decision, &rejected, 2_000),
            Err(ApprovalError::InsufficientApproverAuthority)
        ));

        let owner_approval = sign_approval(owner_challenge, "owner", &owner_signing).unwrap();
        owner_verifier
            .verify(&request, &owner_decision, &owner_approval, 2_000)
            .unwrap();
    }

    #[test]
    fn unknown_required_capability_fails_closed() {
        let request = request();
        let decision = PolicyDecision {
            required_capability: Some("future-root-mode".into()),
            ..decision(&request)
        };
        let challenge = ApprovalChallenge::issue(&request, &decision, 1_000, 5_000).unwrap();
        let signing = signer();
        let approval = sign_approval(challenge, "owner", &signing).unwrap();
        let mut verifier = ApprovalVerifier::new();
        verifier
            .add_approver_with_authority(
                "owner",
                signing.verifying_key().to_bytes(),
                ApproverAuthority::Owner,
            )
            .unwrap();
        assert!(matches!(
            verifier.verify(&request, &decision, &approval, 2_000),
            Err(ApprovalError::UnsupportedRequiredCapability)
        ));
    }

    #[test]
    fn signed_approval_debug_redacts_signature() {
        let request = request();
        let decision = decision(&request);
        let challenge = ApprovalChallenge::issue(&request, &decision, 1_000, 5_000).unwrap();
        let signing = signer();
        let approval = sign_approval(challenge, "operator-1", &signing).unwrap();
        let signature_hex = hex::encode(approval.signature);
        assert!(!format!("{approval:?}").contains(&signature_hex));
    }
}
