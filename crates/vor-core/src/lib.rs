// SPDX-License-Identifier: MPL-2.0

use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;
use vor_approval::{ApprovalError, ApprovalVerifier, SignedApproval};
use vor_audit::{AuditError, AuditEvent, ExecutionRecoveryState, Ledger};
use vor_policy::PolicyEngine;
use vor_protocol::{ActionRequest, PolicyDecision, PolicyDecisionKind, ProtocolError};

#[derive(Debug, Clone)]
pub struct Authorization {
    pub request: ActionRequest,
    pub decision: PolicyDecision,
}

#[derive(Debug)]
pub struct ExecutionAuthorization {
    authorization: Authorization,
    approver_id: String,
    approval_expires_at_unix_ms: u64,
}

impl ExecutionAuthorization {
    pub fn authorization(&self) -> &Authorization {
        &self.authorization
    }
    pub fn request(&self) -> &ActionRequest {
        &self.authorization.request
    }
    pub fn approver_id(&self) -> &str {
        &self.approver_id
    }
    pub fn approval_expires_at_unix_ms(&self) -> u64 {
        self.approval_expires_at_unix_ms
    }
}

impl Authorization {
    pub fn is_auto(&self) -> bool {
        self.decision.kind == PolicyDecisionKind::Auto
    }

    pub fn requires_approval(&self) -> bool {
        self.decision.kind == PolicyDecisionKind::Approval
    }

    pub fn is_denied(&self) -> bool {
        self.decision.kind == PolicyDecisionKind::Deny
    }
}

pub struct Broker {
    policy: PolicyEngine,
    ledger: Ledger,
}

impl Broker {
    pub fn new(policy: PolicyEngine, ledger: Ledger) -> Self {
        Self { policy, ledger }
    }

    pub fn authorize(&mut self, request: ActionRequest) -> Result<Authorization, CoreError> {
        let now = now_unix_ms()?;
        self.authorize_at(request, now)
    }

    pub fn authorize_at(
        &mut self,
        request: ActionRequest,
        now_unix_ms: u64,
    ) -> Result<Authorization, CoreError> {
        request.verify(now_unix_ms)?;
        let decision = self.policy.evaluate(&request);
        let outcome = match decision.kind {
            PolicyDecisionKind::Auto => "auto",
            PolicyDecisionKind::Approval => "approval",
            PolicyDecisionKind::Deny => "deny",
        };
        self.ledger.append(AuditEvent {
            timestamp_unix_ms: now_unix_ms,
            organization_id: request.envelope.organization_id.clone(),
            actor_id: request.envelope.actor_id.clone(),
            device_id: request.envelope.device_id.clone(),
            request_id: request.envelope.request_id.clone(),
            action: request.envelope.action.clone(),
            target: request.envelope.target.clone(),
            outcome: outcome.into(),
            envelope_digest: request.envelope_digest,
        })?;
        Ok(Authorization { request, decision })
    }

    pub fn consume_approval_at(
        &mut self,
        request: ActionRequest,
        approval: &SignedApproval,
        verifier: &ApprovalVerifier,
        now_unix_ms: u64,
    ) -> Result<ExecutionAuthorization, CoreError> {
        request.verify(now_unix_ms)?;
        let decision = self.policy.evaluate(&request);
        if !self.ledger.has_outcome_for(
            &request.envelope.request_id,
            &request.envelope_digest,
            "approval",
        )? {
            return Err(CoreError::ApprovalNotPrepared);
        }
        verifier.verify(&request, &decision, approval, now_unix_ms)?;
        if !self.ledger.claim_approval_consumed(
            &request.envelope.request_id,
            &request.envelope_digest,
            now_unix_ms,
        )? {
            return Err(CoreError::ApprovalAlreadyConsumed);
        }
        self.append_approval_event(
            &request,
            &approval.approver_id,
            "approval_verified",
            now_unix_ms,
        )?;
        self.append_approval_event(
            &request,
            &request.envelope.actor_id,
            "approval_consumed",
            now_unix_ms,
        )?;
        Ok(ExecutionAuthorization {
            authorization: Authorization { request, decision },
            approver_id: approval.approver_id.clone(),
            approval_expires_at_unix_ms: approval.challenge.expires_at_unix_ms,
        })
    }

    fn append_approval_event(
        &mut self,
        request: &ActionRequest,
        actor_id: &str,
        outcome: &str,
        timestamp_unix_ms: u64,
    ) -> Result<(), CoreError> {
        self.ledger.append(AuditEvent {
            timestamp_unix_ms,
            organization_id: request.envelope.organization_id.clone(),
            actor_id: actor_id.to_owned(),
            device_id: request.envelope.device_id.clone(),
            request_id: request.envelope.request_id.clone(),
            action: request.envelope.action.clone(),
            target: request.envelope.target.clone(),
            outcome: outcome.to_owned(),
            envelope_digest: request.envelope_digest,
        })?;
        Ok(())
    }

    pub fn audit_outcome(
        &mut self,
        authorization: &Authorization,
        outcome: impl Into<String>,
    ) -> Result<(), CoreError> {
        let now = now_unix_ms()?;
        self.audit_outcome_at(authorization, outcome, now)
    }

    pub fn audit_outcome_at(
        &mut self,
        authorization: &Authorization,
        outcome: impl Into<String>,
        timestamp_unix_ms: u64,
    ) -> Result<(), CoreError> {
        let request = &authorization.request;
        self.ledger.append(AuditEvent {
            timestamp_unix_ms,
            organization_id: request.envelope.organization_id.clone(),
            actor_id: request.envelope.actor_id.clone(),
            device_id: request.envelope.device_id.clone(),
            request_id: request.envelope.request_id.clone(),
            action: request.envelope.action.clone(),
            target: request.envelope.target.clone(),
            outcome: outcome.into(),
            envelope_digest: request.envelope_digest,
        })?;
        Ok(())
    }

    pub fn ledger(&self) -> &Ledger {
        &self.ledger
    }

    pub fn set_execution_recovery_state(
        &mut self,
        authorization: &Authorization,
        state: ExecutionRecoveryState,
        timestamp_unix_ms: u64,
    ) -> Result<(), CoreError> {
        self.ledger.set_execution_recovery_state(
            &authorization.request.envelope.request_id,
            &authorization.request.envelope_digest,
            state,
            timestamp_unix_ms,
        )?;
        Ok(())
    }

    pub fn execution_recovery_state(
        &self,
        request_id: &str,
        envelope_digest: &vor_protocol::Digest32,
    ) -> Result<Option<ExecutionRecoveryState>, CoreError> {
        Ok(self
            .ledger
            .execution_recovery_state(request_id, envelope_digest)?)
    }

    #[cfg(feature = "fault-injection")]
    pub fn inject_next_approval_claim_failure(&mut self) {
        self.ledger.inject_next_approval_claim_failure();
    }

    #[cfg(feature = "fault-injection")]
    pub fn inject_abandoned_audit_lock(&self) -> Result<(), CoreError> {
        self.ledger.inject_abandoned_lock()?;
        Ok(())
    }
}

fn now_unix_ms() -> Result<u64, CoreError> {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| CoreError::Clock)?;
    u64::try_from(elapsed.as_millis()).map_err(|_| CoreError::Clock)
}

#[derive(Debug, Error)]
pub enum CoreError {
    #[error("request validation failed: {0}")]
    Protocol(#[from] ProtocolError),
    #[error("approval verification failed: {0}")]
    Approval(#[from] ApprovalError),
    #[error("approval was not prepared and audited")]
    ApprovalNotPrepared,
    #[error("approval has already been consumed for this request")]
    ApprovalAlreadyConsumed,
    #[error("audit failed: {0}")]
    Audit(#[from] AuditError),
    #[error("system clock is outside supported range")]
    Clock,
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use std::collections::BTreeMap;
    use std::sync::{Arc, Barrier};
    use tempfile::tempdir;
    use vor_approval::{ApprovalChallenge, ApprovalVerifier, sign_approval};
    use vor_protocol::ActionEnvelope;

    fn request(action: &str, target: &str) -> ActionRequest {
        ActionRequest::seal(ActionEnvelope {
            request_id: "req".into(),
            organization_id: "org".into(),
            actor_id: "actor".into(),
            device_id: "device".into(),
            action: action.into(),
            target: target.into(),
            parameters: BTreeMap::new(),
            requested_capabilities: vec![],
            expires_at_unix_ms: 10_000,
            nonce: vec![3; 16],
        })
        .unwrap()
    }

    fn broker() -> (Broker, tempfile::TempDir) {
        let dir = tempdir().unwrap();
        let policy =
            PolicyEngine::from_yaml_str(include_str!("../../../config/policy.example.yaml"))
                .unwrap();
        let ledger =
            Ledger::open(dir.path().join("audit.db"), dir.path().join("audit.jsonl")).unwrap();
        (Broker::new(policy, ledger), dir)
    }

    #[test]
    fn auto_request_is_audited_before_return() {
        let (mut broker, _dir) = broker();
        let authorization = broker
            .authorize_at(request("filesystem.read", r"D:\Proyectos\x"), 1)
            .unwrap();
        assert!(authorization.is_auto());
        assert_eq!(broker.ledger().last_sequence(), 1);
    }

    #[test]
    fn unknown_action_is_denied_and_audited() {
        let (mut broker, _dir) = broker();
        let authorization = broker
            .authorize_at(request("future.magic", "x"), 1)
            .unwrap();
        assert!(authorization.is_denied());
        assert_eq!(broker.ledger().last_sequence(), 1);
    }

    #[test]
    fn signed_approval_is_consumed_once_and_survives_reopen() {
        let dir = tempdir().unwrap();
        let sqlite = dir.path().join("audit.db");
        let jsonl = dir.path().join("audit.jsonl");
        let make_broker = || {
            let policy =
                PolicyEngine::from_yaml_str(include_str!("../../../config/policy.example.yaml"))
                    .unwrap();
            let ledger = Ledger::open(&sqlite, &jsonl).unwrap();
            Broker::new(policy, ledger)
        };
        let request = request("terminal.elevated", "powershell");
        let mut broker = make_broker();
        let prepared = broker.authorize_at(request.clone(), 1).unwrap();
        assert!(prepared.requires_approval());
        let challenge = ApprovalChallenge::issue(&request, &prepared.decision, 1, 5_000).unwrap();
        let signing = SigningKey::from_bytes(&rand::random::<[u8; 32]>());
        let approval = sign_approval(challenge, "operator-1", &signing).unwrap();
        let mut verifier = ApprovalVerifier::new();
        verifier
            .add_approver("operator-1", signing.verifying_key().to_bytes())
            .unwrap();
        let execution = broker
            .consume_approval_at(request.clone(), &approval, &verifier, 2)
            .unwrap();
        assert_eq!(execution.approver_id(), "operator-1");
        assert_eq!(broker.ledger().last_sequence(), 3);
        drop(broker);
        let mut reopened = make_broker();
        let replay = reopened.consume_approval_at(request, &approval, &verifier, 3);
        assert!(matches!(replay, Err(CoreError::ApprovalAlreadyConsumed)));
        assert_eq!(reopened.ledger().last_sequence(), 3);
    }

    #[test]
    fn approval_consumption_is_claimed_once_across_independent_brokers() {
        let dir = tempdir().unwrap();
        let sqlite = dir.path().join("audit.db");
        let jsonl = dir.path().join("audit.jsonl");
        let make_broker = || {
            let policy =
                PolicyEngine::from_yaml_str(include_str!("../../../config/policy.example.yaml"))
                    .unwrap();
            let ledger = Ledger::open(&sqlite, &jsonl).unwrap();
            Broker::new(policy, ledger)
        };
        let request = request("terminal.elevated", "powershell");
        let mut prepared_broker = make_broker();
        let prepared = prepared_broker.authorize_at(request.clone(), 1).unwrap();
        assert!(prepared.requires_approval());
        drop(prepared_broker);

        let challenge = ApprovalChallenge::issue(&request, &prepared.decision, 1, 5_000).unwrap();
        let signing = SigningKey::from_bytes(&[77; 32]);
        let approval = sign_approval(challenge, "operator-1", &signing).unwrap();
        let public_key = signing.verifying_key().to_bytes();
        let barrier = Arc::new(Barrier::new(2));
        let mut handles = Vec::new();
        for offset in 0..2u64 {
            let request = request.clone();
            let approval = approval.clone();
            let barrier = Arc::clone(&barrier);
            let sqlite = sqlite.clone();
            let jsonl = jsonl.clone();
            handles.push(std::thread::spawn(move || {
                let policy = PolicyEngine::from_yaml_str(include_str!(
                    "../../../config/policy.example.yaml"
                ))
                .unwrap();
                let ledger = Ledger::open(sqlite, jsonl).unwrap();
                let mut broker = Broker::new(policy, ledger);
                let mut verifier = ApprovalVerifier::new();
                verifier.add_approver("operator-1", public_key).unwrap();
                barrier.wait();
                broker.consume_approval_at(request, &approval, &verifier, 2 + offset)
            }));
        }
        let results: Vec<_> = handles
            .into_iter()
            .map(|handle| handle.join().unwrap().map(|_| ()))
            .collect();
        let accepted = results.iter().filter(|result| result.is_ok()).count();
        let replayed = results
            .iter()
            .filter(|result| matches!(result, Err(CoreError::ApprovalAlreadyConsumed)))
            .count();
        assert_eq!(accepted, 1, "results={results:?}");
        assert_eq!(replayed, 1, "results={results:?}");
    }

    #[test]
    fn mutated_request_is_rejected_before_audit() {
        let (mut broker, _dir) = broker();
        let mut request = request("filesystem.read", r"D:\Proyectos\x");
        request.envelope.target.push_str("\\changed");
        let result = broker.authorize_at(request, 1);
        assert!(matches!(
            result,
            Err(CoreError::Protocol(ProtocolError::DigestMismatch))
        ));
        assert_eq!(broker.ledger().last_sequence(), 0);
    }
}
