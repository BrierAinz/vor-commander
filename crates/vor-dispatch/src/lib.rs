// SPDX-License-Identifier: MPL-2.0

use base64::{Engine as _, engine::general_purpose::STANDARD};
use prost::Message;
use prost_types::Timestamp;
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;
pub use vor_approval::ApproverAuthority;
use vor_approval::{ApprovalChallenge, ApprovalVerifier, SignedApproval};
#[cfg(feature = "fault-injection")]
use vor_audit::ExecutionRecoveryState;
use vor_audit::Ledger;
use vor_browser::{BrowserSessionWorker, BrowserWorkerConfig};
use vor_core::{Authorization, Broker, ExecutionAuthorization};
use vor_fs::{FsWorker, TextEdit};
use vor_git::GitWorker;
use vor_policy::PolicyEngine;
use vor_process::ProcessWorker;
use vor_protocol::{ActionEnvelope, ActionRequest};
use vor_terminal::{
    BoundedTerminal, DEFAULT_MAX_REMOTE_TERMINAL_SESSIONS, DEFAULT_REMOTE_TERMINAL_OUTPUT_BYTES,
    DEFAULT_REMOTE_TERMINAL_TIMEOUT_MS, TerminalLimits, TerminalSessionManager,
    TerminalSessionOwner, TerminalSessionState, TerminalSpec,
};
use vor_wire::v1::ActionResult;
use vor_wire::{action_request_from_proto, action_request_to_proto, approval_grant_from_proto, v1};

pub const DEFAULT_MAX_OUTPUT_BYTES: usize = 1024 * 1024;
pub const DEFAULT_MAX_REMOTE_WRITE_BYTES: usize = 1024 * 1024;
pub const DEFAULT_APPROVAL_CHALLENGE_TTL_MS: u64 = 120_000;

#[derive(Debug, Clone)]
pub struct DispatchConfig {
    pub device_id: String,
    pub policy_path: PathBuf,
    pub audit_sqlite: PathBuf,
    pub audit_jsonl: PathBuf,
    pub journal_dir: PathBuf,
    pub allowed_roots: Vec<PathBuf>,
    pub git_executable: PathBuf,
    pub max_output_bytes: usize,
    pub browser: Option<BrowserWorkerConfig>,
}
pub struct ReadOnlyDispatcher {
    device_id: String,
    broker: Broker,
    fs: FsWorker,
    git: GitWorker,
    process: ProcessWorker,
    browser: BrowserSessionWorker,
    terminal_sessions: TerminalSessionManager,
    approval_verifier: ApprovalVerifier,
    max_output_bytes: usize,
    #[cfg(feature = "fault-injection")]
    approved_worker_invocations: usize,
    #[cfg(feature = "fault-injection")]
    crash_after_approval_claim: bool,
    #[cfg(feature = "fault-injection")]
    fail_next_post_effect_audit: bool,
}

impl ReadOnlyDispatcher {
    pub fn open(config: DispatchConfig) -> Result<Self, DispatchError> {
        if config.device_id.trim().is_empty() || config.max_output_bytes == 0 {
            return Err(DispatchError::InvalidConfig);
        }
        let policy = PolicyEngine::from_yaml_file(&config.policy_path)?;
        let ledger = Ledger::open(&config.audit_sqlite, &config.audit_jsonl)?;
        let broker = Broker::new(policy, ledger);
        let fs = FsWorker::new(config.allowed_roots.clone(), config.journal_dir)?;
        let terminal =
            BoundedTerminal::new(config.allowed_roots.clone(), TerminalLimits::default())?;
        let terminal_sessions =
            TerminalSessionManager::new(terminal, DEFAULT_MAX_REMOTE_TERMINAL_SESSIONS)?;
        let git = GitWorker::new(config.git_executable, config.allowed_roots)?;
        let browser = config
            .browser
            .map(BrowserSessionWorker::new)
            .unwrap_or_else(BrowserSessionWorker::disabled);
        Ok(Self {
            device_id: config.device_id,
            broker,
            fs,
            git,
            process: ProcessWorker,
            browser,
            terminal_sessions,
            approval_verifier: ApprovalVerifier::new(),
            max_output_bytes: config.max_output_bytes,
            #[cfg(feature = "fault-injection")]
            approved_worker_invocations: 0,
            #[cfg(feature = "fault-injection")]
            crash_after_approval_claim: false,
            #[cfg(feature = "fault-injection")]
            fail_next_post_effect_audit: false,
        })
    }

    pub fn audit_sequence(&self) -> u64 {
        self.broker.ledger().last_sequence()
    }

    #[cfg(feature = "fault-injection")]
    pub fn inject_next_approval_claim_failure(&mut self) {
        self.broker.inject_next_approval_claim_failure();
    }

    #[cfg(feature = "fault-injection")]
    pub fn approved_worker_invocations(&self) -> usize {
        self.approved_worker_invocations
    }

    #[cfg(feature = "fault-injection")]
    pub fn inject_crash_after_approval_claim(&mut self) {
        self.crash_after_approval_claim = true;
    }

    #[cfg(feature = "fault-injection")]
    pub fn inject_next_post_effect_audit_failure(&mut self) {
        self.fail_next_post_effect_audit = true;
    }

    #[cfg(feature = "fault-injection")]
    pub fn inject_abandoned_audit_lock(&self) -> Result<(), DispatchError> {
        self.broker.inject_abandoned_audit_lock()?;
        Ok(())
    }

    #[cfg(feature = "fault-injection")]
    pub fn execution_recovery_state(
        &self,
        request_id: &str,
        envelope_digest: &vor_protocol::Digest32,
    ) -> Result<Option<ExecutionRecoveryState>, DispatchError> {
        Ok(self
            .broker
            .execution_recovery_state(request_id, envelope_digest)?)
    }

    pub fn add_trusted_approver(
        &mut self,
        approver_id: impl Into<String>,
        public_key: [u8; 32],
    ) -> Result<(), DispatchError> {
        self.approval_verifier
            .add_approver(approver_id, public_key)?;
        Ok(())
    }

    pub fn add_trusted_approver_with_authority(
        &mut self,
        approver_id: impl Into<String>,
        public_key: [u8; 32],
        authority: ApproverAuthority,
    ) -> Result<(), DispatchError> {
        self.approval_verifier
            .add_approver_with_authority(approver_id, public_key, authority)?;
        Ok(())
    }

    pub fn add_trusted_approver_for_organization(
        &mut self,
        approver_id: impl Into<String>,
        public_key: [u8; 32],
        authority: ApproverAuthority,
        organization_id: impl Into<String>,
    ) -> Result<(), DispatchError> {
        self.approval_verifier.add_approver_for_organization(
            approver_id,
            public_key,
            authority,
            Some(organization_id),
        )?;
        Ok(())
    }

    pub fn require_tenant_scoped_approvers(&mut self) {
        self.approval_verifier.require_organization_scope();
    }

    pub fn revoke_trusted_approver(&mut self, approver_id: &str) -> Result<(), DispatchError> {
        self.approval_verifier.revoke_approver(approver_id)?;
        Ok(())
    }

    pub fn rotate_trusted_approver_for_organization(
        &mut self,
        approver_id: impl Into<String>,
        public_key: [u8; 32],
        authority: ApproverAuthority,
        organization_id: impl Into<String>,
    ) -> Result<(), DispatchError> {
        self.approval_verifier.rotate_approver_for_organization(
            approver_id,
            public_key,
            authority,
            organization_id,
        )?;
        Ok(())
    }

    pub fn dispatch_approved_proto(
        &mut self,
        approved: &v1::ApprovedActionRequest,
    ) -> Result<ActionResult, DispatchError> {
        let now = now_unix_ms()?;
        self.dispatch_approved_proto_at(approved, now)
    }

    pub fn dispatch_approved_proto_at(
        &mut self,
        approved: &v1::ApprovedActionRequest,
        now_unix_ms: u64,
    ) -> Result<ActionResult, DispatchError> {
        let request = approved
            .request
            .as_ref()
            .ok_or(DispatchError::InvalidApprovedAction)?;
        let approval = approved
            .approval
            .as_ref()
            .ok_or(DispatchError::InvalidApprovedAction)?;
        let request = action_request_from_proto(request)?;
        let approval = approval_grant_from_proto(approval)?;
        self.dispatch_approved_at(request, &approval, now_unix_ms)
    }

    pub fn dispatch_approved_at(
        &mut self,
        request: ActionRequest,
        approval: &SignedApproval,
        now_unix_ms: u64,
    ) -> Result<ActionResult, DispatchError> {
        if request.envelope.device_id != self.device_id {
            return Err(DispatchError::WrongDevice);
        }
        if !remote_approved_action_allowed(&request.envelope.action) {
            return Err(DispatchError::RemoteActionNotAllowed);
        }

        let authorization = self.broker.authorize_at(request.clone(), now_unix_ms)?;
        if authorization.is_denied() {
            return Err(DispatchError::Denied);
        }
        if !authorization.requires_approval() {
            self.broker.audit_outcome_at(
                &authorization,
                "remote_approval_policy_required",
                now_unix_ms,
            )?;
            return Err(DispatchError::RemoteApprovalPolicyRequired);
        }

        let execution = self.broker.consume_approval_at(
            request,
            approval,
            &self.approval_verifier,
            now_unix_ms,
        )?;
        #[cfg(feature = "fault-injection")]
        if std::mem::take(&mut self.crash_after_approval_claim) {
            return Err(DispatchError::SimulatedProcessDeath);
        }
        self.broker.set_execution_recovery_state(
            execution.authorization(),
            vor_audit::ExecutionRecoveryState::EffectUncertain,
            now_unix_ms,
        )?;
        let execution_result = self.execute_approved(&execution);
        let (output, content_type) = match execution_result {
            Ok(value) => value,
            Err(error) => {
                self.broker.audit_outcome_at(
                    execution.authorization(),
                    "worker_failed",
                    now_unix_ms,
                )?;
                return Err(error);
            }
        };
        self.broker.set_execution_recovery_state(
            execution.authorization(),
            vor_audit::ExecutionRecoveryState::EffectApplied,
            now_unix_ms,
        )?;
        if output.len() > self.max_output_bytes {
            self.broker.audit_outcome_at(
                execution.authorization(),
                "output_limit_exceeded",
                now_unix_ms,
            )?;
            return Err(DispatchError::OutputTooLarge(output.len()));
        }
        #[cfg(feature = "fault-injection")]
        let audit_result = if std::mem::take(&mut self.fail_next_post_effect_audit) {
            Err(vor_core::CoreError::Audit(
                vor_audit::AuditError::FaultInjected("post-effect audit"),
            ))
        } else {
            self.broker
                .audit_outcome_at(execution.authorization(), "executed", now_unix_ms)
        };
        #[cfg(not(feature = "fault-injection"))]
        let audit_result =
            self.broker
                .audit_outcome_at(execution.authorization(), "executed", now_unix_ms);
        if let Err(error) = audit_result {
            self.broker.set_execution_recovery_state(
                execution.authorization(),
                vor_audit::ExecutionRecoveryState::PostEffectUncertain,
                now_unix_ms,
            )?;
            return Err(DispatchError::PostEffectUncertain(error.to_string()));
        }
        self.broker.set_execution_recovery_state(
            execution.authorization(),
            vor_audit::ExecutionRecoveryState::Completed,
            now_unix_ms,
        )?;
        success_result(execution.authorization(), output, content_type, now_unix_ms)
    }

    pub fn dispatch_approved_proto_report_at(
        &mut self,
        approved: &v1::ApprovedActionRequest,
        now_unix_ms: u64,
    ) -> Result<ActionResult, DispatchError> {
        let request_id = approved
            .request
            .as_ref()
            .map(|request| request.request_id.as_str())
            .unwrap_or_default();
        match self.dispatch_approved_proto_at(approved, now_unix_ms) {
            Ok(result) => Ok(result),
            Err(error) => failure_result(request_id, dispatch_status_code(&error), now_unix_ms),
        }
    }

    pub fn dispatch_approved_proto_report(
        &mut self,
        approved: &v1::ApprovedActionRequest,
    ) -> Result<ActionResult, DispatchError> {
        let now = now_unix_ms()?;
        self.dispatch_approved_proto_report_at(approved, now)
    }

    pub fn dispatch_proto(
        &mut self,
        request: &v1::ActionRequest,
    ) -> Result<ActionResult, DispatchError> {
        let now = now_unix_ms()?;
        self.dispatch_proto_at(request, now)
    }

    pub fn dispatch_proto_at(
        &mut self,
        request: &v1::ActionRequest,
        now_unix_ms: u64,
    ) -> Result<ActionResult, DispatchError> {
        let request = action_request_from_proto(request)?;
        if remote_approved_action_allowed(&request.envelope.action) {
            return self.prepare_approved_at(request, now_unix_ms);
        }
        self.dispatch_at(request, now_unix_ms)
    }

    fn prepare_approved_at(
        &mut self,
        request: ActionRequest,
        now_unix_ms: u64,
    ) -> Result<ActionResult, DispatchError> {
        if request.envelope.device_id != self.device_id {
            return Err(DispatchError::WrongDevice);
        }
        if !remote_approved_action_allowed(&request.envelope.action) {
            return Err(DispatchError::RemoteActionNotAllowed);
        }

        let mut authorization = self.broker.authorize_at(request, now_unix_ms)?;
        if authorization.is_denied() {
            return Err(DispatchError::Denied);
        }
        if !authorization.requires_approval() {
            self.broker.audit_outcome_at(
                &authorization,
                "remote_approval_policy_required",
                now_unix_ms,
            )?;
            return Err(DispatchError::RemoteApprovalPolicyRequired);
        }

        let mut edit_metadata = None;
        if let Some(value) = authorization.request.envelope.parameters.get("edit_recipe") {
            let edits: Vec<TextEdit> = serde_json::from_value(value.clone())
                .map_err(|_| DispatchError::InvalidFilesystemParameters)?;
            let prepared = self.fs.prepare_edit(&authorization, &edits)?;
            let original = &authorization.request.envelope;
            let mut parameters = std::collections::BTreeMap::new();
            parameters.insert(
                "content_base64".into(),
                serde_json::Value::String(STANDARD.encode(&prepared.content)),
            );
            parameters.insert(
                "content_sha256".into(),
                serde_json::Value::String(hex::encode(Sha256::digest(&prepared.content))),
            );
            parameters.insert(
                "expected_target_sha256".into(),
                serde_json::Value::String(prepared.original_sha256),
            );
            if let Some(workspace) = original.parameters.get("workspace_id") {
                parameters.insert("workspace_id".into(), workspace.clone());
            }
            let transformed = ActionRequest::seal(ActionEnvelope {
                request_id: original.request_id.clone(),
                organization_id: original.organization_id.clone(),
                actor_id: original.actor_id.clone(),
                device_id: original.device_id.clone(),
                action: original.action.clone(),
                target: original.target.clone(),
                parameters,
                requested_capabilities: original.requested_capabilities.clone(),
                expires_at_unix_ms: original.expires_at_unix_ms,
                nonce: original.nonce.clone(),
            })
            .map_err(|_| DispatchError::InvalidFilesystemParameters)?;
            authorization = self.broker.authorize_at(transformed, now_unix_ms)?;
            edit_metadata = Some((prepared.diff_summary, prepared.diff_truncated));
        }

        let challenge_expires_at = now_unix_ms
            .checked_add(DEFAULT_APPROVAL_CHALLENGE_TTL_MS)
            .ok_or(DispatchError::Clock)?
            .min(authorization.request.envelope.expires_at_unix_ms);
        let challenge = ApprovalChallenge::issue(
            &authorization.request,
            &authorization.decision,
            now_unix_ms,
            challenge_expires_at,
        )?;
        self.broker
            .audit_outcome_at(&authorization, "approval_challenge_issued", now_unix_ms)?;

        let mut output_value = serde_json::json!({
            "request_id": challenge.request_id,
            "envelope_digest_base64": STANDARD.encode(challenge.envelope_digest),
            "policy_id": challenge.policy_id,
            "required_capability": challenge.required_capability,
            "expires_at_unix_ms": challenge.expires_at_unix_ms,
            "approval_nonce_base64": STANDARD.encode(challenge.approval_nonce),
        });
        if let Some((diff_summary, diff_truncated)) = edit_metadata {
            let proto = action_request_to_proto(&authorization.request)?;
            output_value["request_base64"] =
                serde_json::Value::String(STANDARD.encode(proto.encode_to_vec()));
            output_value["content_sha256"] =
                authorization.request.envelope.parameters["content_sha256"].clone();
            output_value["diff_summary"] = serde_json::Value::String(diff_summary);
            output_value["diff_truncated"] = serde_json::Value::Bool(diff_truncated);
        }
        let output = serde_json::to_vec(&output_value)?;
        let stdout_digest = Sha256::digest(&output).to_vec();
        Ok(ActionResult {
            request_id: authorization.request.envelope.request_id.clone(),
            exit_code: 0,
            status: "approval_required".into(),
            stdout_digest,
            stderr_digest: Vec::new(),
            completed_at: Some(ms_to_timestamp(now_unix_ms)?),
            output,
            content_type: "application/json".into(),
            truncated: false,
        })
    }

    pub fn dispatch_at(
        &mut self,
        request: ActionRequest,
        now_unix_ms: u64,
    ) -> Result<ActionResult, DispatchError> {
        if request.envelope.device_id != self.device_id {
            return Err(DispatchError::WrongDevice);
        }
        let authorization = self.broker.authorize_at(request, now_unix_ms)?;
        if !remote_action_allowed(&authorization.request.envelope.action) {
            self.broker
                .audit_outcome_at(&authorization, "remote_scope_denied", now_unix_ms)?;
            return Err(DispatchError::RemoteActionNotAllowed);
        }
        if authorization.is_denied() {
            return Err(DispatchError::Denied);
        }
        if authorization.requires_approval() {
            self.broker.audit_outcome_at(
                &authorization,
                "remote_approval_required",
                now_unix_ms,
            )?;
            return Err(DispatchError::ApprovalRequired);
        }

        let execution = self.execute_authorized(&authorization);
        let (output, content_type) = match execution {
            Ok(value) => value,
            Err(error) => {
                self.broker
                    .audit_outcome_at(&authorization, "worker_failed", now_unix_ms)?;
                return Err(error);
            }
        };
        if output.len() > self.max_output_bytes {
            self.broker
                .audit_outcome_at(&authorization, "output_limit_exceeded", now_unix_ms)?;
            return Err(DispatchError::OutputTooLarge(output.len()));
        }
        self.broker
            .audit_outcome_at(&authorization, "executed", now_unix_ms)?;
        success_result(&authorization, output, content_type, now_unix_ms)
    }
    pub fn dispatch_proto_report_at(
        &mut self,
        request: &v1::ActionRequest,
        now_unix_ms: u64,
    ) -> Result<ActionResult, DispatchError> {
        match self.dispatch_proto_at(request, now_unix_ms) {
            Ok(result) => Ok(result),
            Err(error) => match &error {
                DispatchError::Fs(vor_fs::FsError::OccurrenceMismatch {
                    edit_index,
                    expected,
                    actual,
                    closest_line,
                }) => failure_json_result(
                    &request.request_id,
                    dispatch_status_code(&error),
                    serde_json::json!({
                        "edit_index": edit_index,
                        "expected_occurrences": expected,
                        "actual_occurrences": actual,
                        "closest_line": closest_line,
                    }),
                    now_unix_ms,
                ),
                _ => failure_result(
                    &request.request_id,
                    dispatch_status_code(&error),
                    now_unix_ms,
                ),
            },
        }
    }

    pub fn dispatch_proto_report(
        &mut self,
        request: &v1::ActionRequest,
    ) -> Result<ActionResult, DispatchError> {
        let now = now_unix_ms()?;
        self.dispatch_proto_report_at(request, now)
    }
    fn execute_authorized(
        &self,
        authorization: &Authorization,
    ) -> Result<(Vec<u8>, &'static str), DispatchError> {
        match authorization.request.envelope.action.as_str() {
            "filesystem.read" => {
                let parameters = &authorization.request.envelope.parameters;
                let output = match (
                    parameter_u64(parameters, "offset")?,
                    parameter_usize(parameters, "length")?,
                    parameter_usize(parameters, "line_start")?,
                    parameter_usize(parameters, "line_count")?,
                ) {
                    (Some(offset), Some(length), None, None) => {
                        self.fs
                            .read_range(authorization, offset, length, self.max_output_bytes)?
                    }
                    (None, None, Some(start), Some(count)) => {
                        self.fs
                            .read_lines(authorization, start, count, self.max_output_bytes)?
                    }
                    (None, None, None, None) => {
                        self.fs.read_limited(authorization, self.max_output_bytes)?
                    }
                    _ => return Err(DispatchError::InvalidFilesystemParameters),
                };
                Ok((output, "application/octet-stream"))
            }
            "filesystem.list" => Ok((
                serde_json::to_vec(&self.fs.list_directory(
                    authorization,
                    required_usize(authorization, "depth")?,
                    required_usize(authorization, "max_entries")?,
                )?)?,
                "application/json",
            )),
            "filesystem.search_files" => Ok((
                serde_json::to_vec(&self.fs.search_files(
                    authorization,
                    required_str(authorization, "pattern")?,
                    required_usize(authorization, "max_results")?,
                )?)?,
                "application/json",
            )),
            "filesystem.search_content" => Ok((
                serde_json::to_vec(&self.fs.search_content(
                    authorization,
                    required_str(authorization, "query")?,
                    required_bool(authorization, "regex")?,
                    required_str(authorization, "file_glob")?,
                    required_usize(authorization, "max_matches")?,
                    required_usize(authorization, "max_file_bytes")?,
                )?)?,
                "application/json",
            )),
            "filesystem.info" => Ok((
                serde_json::to_vec(&self.fs.file_info(authorization)?)?,
                "application/json",
            )),
            "git.status" => Ok((
                serde_json::to_vec(&self.git.status(authorization)?)?,
                "application/json",
            )),
            "git.diff" => Ok((
                serde_json::to_vec(&self.git.diff(authorization)?)?,
                "application/json",
            )),
            "process.list" => Ok((
                serde_json::to_vec(&self.process.list(authorization)?)?,
                "application/json",
            )),
            "process.inspect" => Ok((
                serde_json::to_vec(&self.process.inspect(authorization)?)?,
                "application/json",
            )),
            "terminal.poll" => {
                let owner = terminal_session_owner(&authorization.request)?;
                let session_id = authorization.request.envelope.target.as_str();
                let snapshot = self.terminal_sessions.poll(session_id, &owner)?;
                let finished = snapshot.state != TerminalSessionState::Running;
                let output = serde_json::to_vec(&serde_json::json!({
                    "session_id": snapshot.session_id,
                    "state": terminal_session_state_name(snapshot.state),
                    "exit_code": snapshot.exit_code,
                    "output_base64": STANDARD.encode(&snapshot.output),
                    "error_code": snapshot.error_code,
                }))?;
                if finished {
                    self.terminal_sessions.remove(session_id, &owner)?;
                }
                Ok((output, "application/json"))
            }
            "terminal.cancel" => {
                let owner = terminal_session_owner(&authorization.request)?;
                let session_id = authorization.request.envelope.target.as_str();
                let requested = self.terminal_sessions.cancel(session_id, &owner)?;
                Ok((
                    serde_json::to_vec(&serde_json::json!({
                        "session_id": session_id,
                        "cancel_requested": requested
                    }))?,
                    "application/json",
                ))
            }
            _ => Err(DispatchError::RemoteActionNotAllowed),
        }
    }

    fn execute_approved(
        &mut self,
        execution: &ExecutionAuthorization,
    ) -> Result<(Vec<u8>, &'static str), DispatchError> {
        #[cfg(feature = "fault-injection")]
        {
            self.approved_worker_invocations += 1;
        }
        match execution.request().envelope.action.as_str() {
            "filesystem.write" => {
                let content = remote_write_content(execution.request())?;
                let receipt = self.fs.write_approved(execution, &content)?;
                let output = serde_json::to_vec(&serde_json::json!({
                    "target": receipt.target.to_string_lossy(),
                    "content_sha256": receipt.content_sha256,
                    "backup_created": receipt.backup_path.is_some(),
                    "journaled": true
                }))?;
                Ok((output, "application/json"))
            }
            "terminal.exec" => {
                let spec = remote_terminal_spec(execution.request(), self.max_output_bytes)?;
                let owner = terminal_session_owner(execution.request())?;
                let session_id = self.terminal_sessions.start(owner, spec.clone())?;
                let output = serde_json::to_vec(&serde_json::json!({
                    "session_id": session_id,
                    "state": "running",
                    "cwd": spec.cwd.to_string_lossy(),
                    "timeout_ms": spec.timeout_ms,
                    "max_output_bytes": spec.max_output_bytes,
                    "columns": spec.columns,
                    "rows": spec.rows
                }))?;
                Ok((output, "application/json"))
            }
            "process.terminate" => Ok((
                serde_json::to_vec(&self.process.terminate_approved(execution)?)?,
                "application/json",
            )),
            "browser.session.use" => Ok((
                serde_json::to_vec(&self.browser.execute_approved(execution)?)?,
                "application/json",
            )),
            _ => Err(DispatchError::RemoteActionNotAllowed),
        }
    }
}

pub fn remote_action_allowed(action: &str) -> bool {
    matches!(
        action,
        "filesystem.read"
            | "filesystem.list"
            | "filesystem.search_files"
            | "filesystem.search_content"
            | "filesystem.info"
            | "git.status"
            | "git.diff"
            | "process.list"
            | "process.inspect"
            | "terminal.poll"
            | "terminal.cancel"
    )
}

fn parameter_u64(
    parameters: &std::collections::BTreeMap<String, serde_json::Value>,
    name: &str,
) -> Result<Option<u64>, DispatchError> {
    parameters
        .get(name)
        .map(|value| {
            value
                .as_u64()
                .ok_or(DispatchError::InvalidFilesystemParameters)
        })
        .transpose()
}
fn parameter_usize(
    parameters: &std::collections::BTreeMap<String, serde_json::Value>,
    name: &str,
) -> Result<Option<usize>, DispatchError> {
    parameter_u64(parameters, name)?
        .map(|value| usize::try_from(value).map_err(|_| DispatchError::InvalidFilesystemParameters))
        .transpose()
}
fn required_usize(request: &Authorization, name: &str) -> Result<usize, DispatchError> {
    parameter_usize(&request.request.envelope.parameters, name)?
        .ok_or(DispatchError::InvalidFilesystemParameters)
}
fn required_str<'a>(request: &'a Authorization, name: &str) -> Result<&'a str, DispatchError> {
    request
        .request
        .envelope
        .parameters
        .get(name)
        .and_then(serde_json::Value::as_str)
        .ok_or(DispatchError::InvalidFilesystemParameters)
}
fn required_bool(request: &Authorization, name: &str) -> Result<bool, DispatchError> {
    request
        .request
        .envelope
        .parameters
        .get(name)
        .and_then(serde_json::Value::as_bool)
        .ok_or(DispatchError::InvalidFilesystemParameters)
}

pub fn remote_approved_action_allowed(action: &str) -> bool {
    matches!(
        action,
        "filesystem.write" | "terminal.exec" | "process.terminate" | "browser.session.use"
    )
}

fn terminal_session_owner(request: &ActionRequest) -> Result<TerminalSessionOwner, DispatchError> {
    let workspace_id = request
        .envelope
        .parameters
        .get("workspace_id")
        .map(|value| {
            value
                .as_str()
                .map(str::to_owned)
                .ok_or(DispatchError::InvalidTerminalParameters)
        })
        .transpose()?;
    Ok(TerminalSessionOwner::with_workspace(
        request.envelope.organization_id.clone(),
        request.envelope.actor_id.clone(),
        request.envelope.device_id.clone(),
        workspace_id,
    )?)
}

fn terminal_session_state_name(state: TerminalSessionState) -> &'static str {
    match state {
        TerminalSessionState::Running => "running",
        TerminalSessionState::Completed => "completed",
        TerminalSessionState::Cancelled => "cancelled",
        TerminalSessionState::TimedOut => "timed_out",
        TerminalSessionState::Failed => "failed",
    }
}

fn remote_terminal_spec(
    request: &ActionRequest,
    dispatcher_output_limit: usize,
) -> Result<TerminalSpec, DispatchError> {
    const ALLOWED_PARAMETERS: &[&str] = &[
        "argv",
        "timeout_ms",
        "max_output_bytes",
        "columns",
        "rows",
        "workspace_id",
    ];
    if request
        .envelope
        .parameters
        .keys()
        .any(|key| !ALLOWED_PARAMETERS.contains(&key.as_str()))
    {
        return Err(DispatchError::InvalidTerminalParameters);
    }

    let argv = request
        .envelope
        .parameters
        .get("argv")
        .and_then(|value| value.as_array())
        .ok_or(DispatchError::InvalidTerminalParameters)?
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(str::to_owned)
                .ok_or(DispatchError::InvalidTerminalParameters)
        })
        .collect::<Result<Vec<_>, _>>()?;
    if argv.is_empty() {
        return Err(DispatchError::InvalidTerminalParameters);
    }

    let timeout_ms = request
        .envelope
        .parameters
        .get("timeout_ms")
        .map(|value| {
            value
                .as_u64()
                .ok_or(DispatchError::InvalidTerminalParameters)
        })
        .transpose()?
        .unwrap_or(DEFAULT_REMOTE_TERMINAL_TIMEOUT_MS);

    let json_safe_output_limit = dispatcher_output_limit
        .saturating_sub(16 * 1024)
        .saturating_mul(3)
        / 4;
    if json_safe_output_limit == 0 {
        return Err(DispatchError::InvalidTerminalParameters);
    }
    let requested_output = request
        .envelope
        .parameters
        .get("max_output_bytes")
        .map(|value| {
            value
                .as_u64()
                .ok_or(DispatchError::InvalidTerminalParameters)
        })
        .transpose()?
        .map(usize::try_from)
        .transpose()
        .map_err(|_| DispatchError::InvalidTerminalParameters)?
        .unwrap_or(DEFAULT_REMOTE_TERMINAL_OUTPUT_BYTES)
        .min(json_safe_output_limit);

    let columns = request
        .envelope
        .parameters
        .get("columns")
        .map(|value| {
            value
                .as_u64()
                .ok_or(DispatchError::InvalidTerminalParameters)
        })
        .transpose()?
        .unwrap_or(120);
    let rows = request
        .envelope
        .parameters
        .get("rows")
        .map(|value| {
            value
                .as_u64()
                .ok_or(DispatchError::InvalidTerminalParameters)
        })
        .transpose()?
        .unwrap_or(40);

    Ok(TerminalSpec {
        argv,
        cwd: PathBuf::from(&request.envelope.target),
        timeout_ms,
        max_output_bytes: requested_output,
        columns: u16::try_from(columns).map_err(|_| DispatchError::InvalidTerminalParameters)?,
        rows: u16::try_from(rows).map_err(|_| DispatchError::InvalidTerminalParameters)?,
    })
}

fn remote_write_content(request: &ActionRequest) -> Result<Vec<u8>, DispatchError> {
    let encoded = request
        .envelope
        .parameters
        .get("content_base64")
        .and_then(|value| value.as_str())
        .ok_or(DispatchError::MissingWriteContent)?;
    let max_encoded = DEFAULT_MAX_REMOTE_WRITE_BYTES
        .checked_mul(4)
        .and_then(|value| value.checked_div(3))
        .and_then(|value| value.checked_add(8))
        .ok_or(DispatchError::InvalidConfig)?;
    if encoded.len() > max_encoded {
        return Err(DispatchError::WriteTooLarge(encoded.len()));
    }
    let content = STANDARD
        .decode(encoded)
        .map_err(|_| DispatchError::InvalidWriteContent)?;
    if content.len() > DEFAULT_MAX_REMOTE_WRITE_BYTES {
        return Err(DispatchError::WriteTooLarge(content.len()));
    }
    Ok(content)
}

fn success_result(
    authorization: &Authorization,
    output: Vec<u8>,
    content_type: &str,
    completed_unix_ms: u64,
) -> Result<ActionResult, DispatchError> {
    let stdout_digest = Sha256::digest(&output).to_vec();
    Ok(ActionResult {
        request_id: authorization.request.envelope.request_id.clone(),
        exit_code: 0,
        status: "ok".into(),
        stdout_digest,
        stderr_digest: Vec::new(),
        completed_at: Some(ms_to_timestamp(completed_unix_ms)?),
        output,
        content_type: content_type.into(),
        truncated: false,
    })
}

fn ms_to_timestamp(value: u64) -> Result<Timestamp, DispatchError> {
    let seconds = i64::try_from(value / 1000).map_err(|_| DispatchError::Clock)?;
    let nanos = i32::try_from((value % 1000) * 1_000_000).map_err(|_| DispatchError::Clock)?;
    Ok(Timestamp { seconds, nanos })
}

fn now_unix_ms() -> Result<u64, DispatchError> {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| DispatchError::Clock)?;
    u64::try_from(elapsed.as_millis()).map_err(|_| DispatchError::Clock)
}
pub fn dispatch_status_code(error: &DispatchError) -> &'static str {
    match error {
        DispatchError::WrongDevice => "wrong_device",
        DispatchError::RemoteActionNotAllowed => "remote_scope_denied",
        DispatchError::Denied => "policy_denied",
        DispatchError::ApprovalRequired => "approval_required",
        DispatchError::RemoteApprovalPolicyRequired => "approval_policy_required",
        DispatchError::InvalidApprovedAction
        | DispatchError::MissingWriteContent
        | DispatchError::InvalidWriteContent
        | DispatchError::InvalidTerminalParameters
        | DispatchError::InvalidFilesystemParameters => "invalid_request",
        DispatchError::WriteTooLarge(_) => "write_limit_exceeded",
        DispatchError::OutputTooLarge(_) => "output_limit_exceeded",
        DispatchError::Wire(_) => "invalid_request",
        DispatchError::Approval(_) => "approval_invalid",
        DispatchError::Core(vor_core::CoreError::ApprovalAlreadyConsumed) => "approval_replayed",
        DispatchError::Core(vor_core::CoreError::ApprovalNotPrepared) => "approval_not_prepared",
        DispatchError::Core(vor_core::CoreError::Approval(_)) => "approval_invalid",
        DispatchError::Audit(_) | DispatchError::Core(_) => "audit_or_broker_unavailable",
        DispatchError::PostEffectUncertain(_) => "post_effect_uncertain",
        #[cfg(feature = "fault-injection")]
        DispatchError::SimulatedProcessDeath => "simulated_process_death",
        DispatchError::Fs(vor_fs::FsError::TargetPreconditionFailed) => {
            "target_precondition_failed"
        }
        DispatchError::Fs(_) => "filesystem_error",
        DispatchError::Git(_) => "git_error",
        DispatchError::Process(_) => "process_error",
        DispatchError::Terminal(vor_terminal::TerminalError::Cancelled) => "terminal_cancelled",
        DispatchError::Terminal(vor_terminal::TerminalError::Timeout { .. }) => "terminal_timeout",
        DispatchError::Terminal(vor_terminal::TerminalError::OutputLimitExceeded { .. }) => {
            "terminal_output_limit_exceeded"
        }
        DispatchError::Terminal(_) => "terminal_error",
        DispatchError::Browser(vor_browser::BrowserError::ApprovalMismatch) => {
            "browser_session_not_found"
        }
        DispatchError::Browser(vor_browser::BrowserError::NavigationOutOfScope) => {
            "browser_navigation_out_of_scope"
        }
        DispatchError::Browser(vor_browser::BrowserError::StaleElement) => "browser_stale_element",
        DispatchError::Browser(vor_browser::BrowserError::SessionNotFound) => {
            "browser_session_not_found"
        }
        DispatchError::Browser(vor_browser::BrowserError::BrowserDisabled) => "browser_disabled",
        DispatchError::Browser(_) => "browser_error",
        DispatchError::Policy(_) => "policy_error",
        DispatchError::Json(_) => "serialization_error",
        DispatchError::InvalidConfig | DispatchError::Clock => "internal_error",
    }
}

pub fn failure_result(
    request_id: &str,
    status: &str,
    completed_unix_ms: u64,
) -> Result<ActionResult, DispatchError> {
    let output = Vec::new();
    Ok(ActionResult {
        request_id: request_id.to_owned(),
        exit_code: -1,
        status: status.to_owned(),
        stdout_digest: Sha256::digest(&output).to_vec(),
        stderr_digest: Vec::new(),
        completed_at: Some(ms_to_timestamp(completed_unix_ms)?),
        output,
        content_type: "application/vnd.vor.error".into(),
        truncated: false,
    })
}

fn failure_json_result(
    request_id: &str,
    status: &str,
    value: serde_json::Value,
    completed_unix_ms: u64,
) -> Result<ActionResult, DispatchError> {
    let output = serde_json::to_vec(&value)?;
    Ok(ActionResult {
        request_id: request_id.to_owned(),
        exit_code: -1,
        status: status.to_owned(),
        stdout_digest: Sha256::digest(&output).to_vec(),
        stderr_digest: Vec::new(),
        completed_at: Some(ms_to_timestamp(completed_unix_ms)?),
        output,
        content_type: "application/json".into(),
        truncated: false,
    })
}
#[derive(Debug, Error)]
pub enum DispatchError {
    #[error("dispatcher configuration is invalid")]
    InvalidConfig,
    #[cfg(feature = "fault-injection")]
    #[error("simulated process death after approval claim")]
    SimulatedProcessDeath,
    #[error("effect completed but post-effect persistence is uncertain: {0}")]
    PostEffectUncertain(String),
    #[error("request targets a different device")]
    WrongDevice,
    #[error("action is outside the remote read-only allowlist")]
    RemoteActionNotAllowed,
    #[error("policy denied the action")]
    Denied,
    #[error("action requires approval and read-only remote dispatch has no implicit approval")]
    ApprovalRequired,
    #[error("approved remote action payload is incomplete")]
    InvalidApprovedAction,
    #[error("approved remote action requires local policy to require approval")]
    RemoteApprovalPolicyRequired,
    #[error("remote write request is missing content_base64")]
    MissingWriteContent,
    #[error("remote write content_base64 is invalid")]
    InvalidWriteContent,
    #[error("remote write payload exceeds limit: {0} bytes")]
    WriteTooLarge(usize),
    #[error("remote terminal parameters are invalid")]
    InvalidTerminalParameters,
    #[error("remote filesystem parameters are invalid")]
    InvalidFilesystemParameters,
    #[error("remote output exceeds limit: {0} bytes")]
    OutputTooLarge(usize),
    #[error("system clock is outside supported range")]
    Clock,
    #[error("wire validation failed: {0}")]
    Wire(#[from] vor_wire::WireError),
    #[error("approval configuration failed: {0}")]
    Approval(#[from] vor_approval::ApprovalError),
    #[error("policy failed: {0}")]
    Policy(#[from] vor_policy::PolicyError),
    #[error("audit failed: {0}")]
    Audit(#[from] vor_audit::AuditError),
    #[error("broker failed: {0}")]
    Core(#[from] vor_core::CoreError),
    #[error("filesystem worker failed: {0}")]
    Fs(#[from] vor_fs::FsError),
    #[error("Git worker failed: {0}")]
    Git(#[from] vor_git::GitError),
    #[error("process worker failed: {0}")]
    Process(#[from] vor_process::ProcessError),
    #[error("terminal worker failed: {0}")]
    Terminal(#[from] vor_terminal::TerminalError),
    #[error("browser worker failed: {0}")]
    Browser(#[from] vor_browser::BrowserError),
    #[error("result JSON failed: {0}")]
    Json(#[from] serde_json::Error),
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use std::collections::BTreeMap;
    use std::fs;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::path::Path;
    use std::process::{Child, Command, Stdio};
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };
    use std::thread;
    use std::time::Duration;
    use tempfile::tempdir;
    use vor_approval::{ApprovalChallenge, sign_approval};
    use vor_protocol::{ActionEnvelope, ActionRequest, PolicyDecision, PolicyDecisionKind};
    use vor_wire::{action_request_to_proto, approval_grant_to_proto};

    #[test]
    fn c12_browser_foreign_and_missing_sessions_share_public_error_code() {
        assert_eq!(
            dispatch_status_code(&DispatchError::Browser(
                vor_browser::BrowserError::ApprovalMismatch,
            )),
            dispatch_status_code(&DispatchError::Browser(
                vor_browser::BrowserError::SessionNotFound,
            )),
        );
        assert_eq!(
            dispatch_status_code(&DispatchError::Browser(
                vor_browser::BrowserError::SessionNotFound,
            )),
            "browser_session_not_found",
        );
    }

    fn find_git() -> PathBuf {
        let output = Command::new("where.exe").arg("git.exe").output().unwrap();
        assert!(output.status.success());
        PathBuf::from(
            String::from_utf8_lossy(&output.stdout)
                .lines()
                .next()
                .unwrap()
                .trim(),
        )
    }

    fn write_policy(path: &Path, root: &Path) {
        let root = root.to_string_lossy().replace('\\', "\\\\");
        let yaml = format!(
            r#"version: 1
policy_id: dispatch-test
filesystem:
  - path: "{root}"
    read: auto
    write: approval
terminal:
  default: approval
  project_tests: auto
  destructive: approval
  elevated: approval
process:
  list: auto
  inspect: auto
  terminate: approval
"#
        );
        let yaml = yaml
            + r#"browser:
  authenticated_session_use: approval
  secret_extraction: deny
  publish: approval
  purchase: deny
desktop:
  enabled: false
network:
  public_listener_fallback: deny
audit:
  required: true
  fail_if_unwritable: true
"#;
        fs::write(path, yaml).unwrap();
    }

    fn dispatcher(root: &Path, max_output_bytes: usize) -> ReadOnlyDispatcher {
        let policy = root.join("policy.yaml");
        write_policy(&policy, root);
        ReadOnlyDispatcher::open(DispatchConfig {
            device_id: "device-1".into(),
            policy_path: policy,
            audit_sqlite: root.join("audit.db"),
            audit_jsonl: root.join("audit.jsonl"),
            journal_dir: root.join("journal"),
            allowed_roots: vec![root.to_path_buf()],
            git_executable: find_git(),
            max_output_bytes,
            browser: None,
        })
        .unwrap()
    }
    fn request(action: &str, target: &str, device_id: &str) -> v1::ActionRequest {
        let request = ActionRequest::seal(ActionEnvelope {
            request_id: format!("req-{action}-{target}"),
            organization_id: "org-1".into(),
            actor_id: "remote-test".into(),
            device_id: device_id.into(),
            action: action.into(),
            target: target.into(),
            parameters: BTreeMap::new(),
            requested_capabilities: vec![],
            expires_at_unix_ms: 10_000,
            nonce: vec![7; 16],
        })
        .unwrap();
        action_request_to_proto(&request).unwrap()
    }

    struct BrowserFixtureServer {
        origin: String,
        stop: Arc<AtomicBool>,
        handle: Option<thread::JoinHandle<()>>,
    }

    impl BrowserFixtureServer {
        fn start() -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            listener.set_nonblocking(true).unwrap();
            let origin = format!("http://{}", listener.local_addr().unwrap());
            let stop = Arc::new(AtomicBool::new(false));
            let thread_stop = Arc::clone(&stop);
            let handle = thread::spawn(move || {
                while !thread_stop.load(Ordering::SeqCst) {
                    match listener.accept() {
                        Ok((mut stream, _)) => {
                            let mut request = [0u8; 2048];
                            let size = stream.read(&mut request).unwrap_or(0);
                            let request_line = String::from_utf8_lossy(&request[..size]);
                            let path = request_line
                                .lines()
                                .next()
                                .and_then(|line| line.split_whitespace().nth(1))
                                .unwrap_or("/");
                            let (content_type, body) = if path.starts_with("/download") {
                                ("text/plain", "dispatch-download-ok".to_owned())
                            } else {
                                (
                                    "text/html",
                                    r#"<!doctype html>
<title>Vor Dispatch Browser</title>
<button id="go" onclick="this.textContent='clicked-a'; document.body.dataset.clicked='1'">ready-a</button>
<a id="download" download="dispatch.txt" href="/download">download-a</a>"#
                                        .to_owned(),
                                )
                            };
                            let response = format!(
                                "HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                                body.len()
                            );
                            let _ = stream.write_all(response.as_bytes());
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(10));
                        }
                        Err(_) => break,
                    }
                }
            });
            Self {
                origin,
                stop,
                handle: Some(handle),
            }
        }

        fn origin(&self) -> &str {
            &self.origin
        }
    }

    impl Drop for BrowserFixtureServer {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::SeqCst);
            if let Some(handle) = self.handle.take() {
                let _ = handle.join();
            }
        }
    }

    fn browser_request(
        request_id: &str,
        actor_id: &str,
        parameters: BTreeMap<String, serde_json::Value>,
    ) -> ActionRequest {
        ActionRequest::seal(ActionEnvelope {
            request_id: request_id.to_owned(),
            organization_id: "org-1".into(),
            actor_id: actor_id.into(),
            device_id: "device-1".into(),
            action: "browser.session.use".into(),
            target: "local-firefox-lab".into(),
            parameters,
            requested_capabilities: vec![],
            expires_at_unix_ms: 60_000,
            nonce: vec![11; 16],
        })
        .unwrap()
    }

    fn approved_direct_for_browser(
        request: &ActionRequest,
        signing: &SigningKey,
        now_unix_ms: u64,
    ) -> vor_approval::SignedApproval {
        let decision = PolicyDecision {
            request_id: request.envelope.request_id.clone(),
            kind: PolicyDecisionKind::Approval,
            policy_id: "dispatch-test".into(),
            reason_code: "browser_rule".into(),
            required_capability: None,
            envelope_digest: request.envelope_digest,
        };
        let challenge =
            ApprovalChallenge::issue(request, &decision, now_unix_ms, now_unix_ms + 5_000).unwrap();
        sign_approval(challenge, "operator-1", signing).unwrap()
    }

    fn browser_proto(
        request_id: &str,
        actor_id: &str,
        parameters: BTreeMap<String, serde_json::Value>,
    ) -> v1::ActionRequest {
        action_request_to_proto(&browser_request(request_id, actor_id, parameters)).unwrap()
    }

    fn browser_params(operation: &str) -> BTreeMap<String, serde_json::Value> {
        let mut parameters = BTreeMap::new();
        parameters.insert(
            "operation".into(),
            serde_json::Value::String(operation.into()),
        );
        parameters
    }

    fn approved_json(
        dispatcher: &mut ReadOnlyDispatcher,
        proto: &v1::ActionRequest,
        signing: &SigningKey,
        now_unix_ms: u64,
    ) -> serde_json::Value {
        let prepared = dispatcher.dispatch_proto_at(proto, now_unix_ms).unwrap();
        assert_eq!(prepared.status, "approval_required");
        let approved = approved_from_prepared(proto, &prepared, "operator-1", signing);
        let result = dispatcher
            .dispatch_approved_proto_at(&approved, now_unix_ms + 100)
            .unwrap();
        assert_eq!(result.status, "ok");
        serde_json::from_slice(&result.output).unwrap()
    }

    fn approved_report(
        dispatcher: &mut ReadOnlyDispatcher,
        proto: &v1::ActionRequest,
        signing: &SigningKey,
        now_unix_ms: u64,
    ) -> ActionResult {
        let prepared = dispatcher.dispatch_proto_at(proto, now_unix_ms).unwrap();
        assert_eq!(prepared.status, "approval_required");
        let approved = approved_from_prepared(proto, &prepared, "operator-1", signing);
        dispatcher
            .dispatch_approved_proto_report_at(&approved, now_unix_ms + 100)
            .unwrap()
    }

    fn sha256_hex_bytes(content: &[u8]) -> String {
        Sha256::digest(content)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }

    fn write_request(
        request_id: &str,
        target: &Path,
        content: &[u8],
        expected_target_sha256: &str,
    ) -> ActionRequest {
        let mut parameters = BTreeMap::new();
        parameters.insert(
            "content_base64".into(),
            serde_json::Value::String(STANDARD.encode(content)),
        );
        parameters.insert(
            "content_sha256".into(),
            serde_json::Value::String(sha256_hex_bytes(content)),
        );
        parameters.insert(
            "expected_target_sha256".into(),
            serde_json::Value::String(expected_target_sha256.to_owned()),
        );
        ActionRequest::seal(ActionEnvelope {
            request_id: request_id.to_owned(),
            organization_id: "org-1".into(),
            actor_id: "remote-write-test".into(),
            device_id: "device-1".into(),
            action: "filesystem.write".into(),
            target: target.to_string_lossy().into_owned(),
            parameters,
            requested_capabilities: vec![],
            expires_at_unix_ms: 10_000,
            nonce: vec![8; 16],
        })
        .unwrap()
    }

    fn approved_write_request(
        request_id: &str,
        target: &Path,
        content: &[u8],
        expected_target_sha256: &str,
        signing: &SigningKey,
    ) -> v1::ApprovedActionRequest {
        let request = write_request(request_id, target, content, expected_target_sha256);
        let decision = PolicyDecision {
            request_id: request.envelope.request_id.clone(),
            kind: PolicyDecisionKind::Approval,
            policy_id: "dispatch-test".into(),
            reason_code: "filesystem_rule".into(),
            required_capability: None,
            envelope_digest: request.envelope_digest,
        };
        let challenge = ApprovalChallenge::issue(&request, &decision, 1_000, 5_000).unwrap();
        let approval = sign_approval(challenge, "operator-1", signing).unwrap();
        v1::ApprovedActionRequest {
            request: Some(action_request_to_proto(&request).unwrap()),
            approval: Some(approval_grant_to_proto(&approval).unwrap()),
        }
    }

    fn terminal_request(request_id: &str, cwd: &Path, argv: &[&str]) -> ActionRequest {
        terminal_request_with_limits(request_id, cwd, argv, 5_000, 64 * 1024)
    }

    #[cfg(windows)]
    fn system_cmd() -> PathBuf {
        PathBuf::from(std::env::var_os("SystemRoot").unwrap()).join("System32/cmd.exe")
    }

    #[cfg(windows)]
    fn spawn_lab_process(root: &Path, name: &str, count: u32) -> (PathBuf, Child) {
        let target = root.join(name);
        fs::copy(system_cmd(), &target).unwrap();
        let child = Command::new(&target)
            .args([
                "/D",
                "/Q",
                "/C",
                &format!("ping.exe 127.0.0.1 -n {count} >NUL"),
            ])
            .current_dir(root)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        (target, child)
    }

    #[cfg(windows)]
    fn process_terminate_request(
        request_id: &str,
        identity: &vor_process::ProcessIdentity,
    ) -> ActionRequest {
        let mut parameters = BTreeMap::new();
        parameters.insert(
            "executable_name".into(),
            serde_json::Value::String(identity.executable_name.clone()),
        );
        parameters.insert(
            "image_path".into(),
            serde_json::Value::String(identity.image_path.clone()),
        );
        parameters.insert(
            "created_at_windows_filetime_100ns".into(),
            serde_json::Value::from(identity.created_at_windows_filetime_100ns),
        );
        ActionRequest::seal(ActionEnvelope {
            request_id: request_id.to_owned(),
            organization_id: "org-1".into(),
            actor_id: "remote-process-test".into(),
            device_id: "device-1".into(),
            action: "process.terminate".into(),
            target: identity.pid.to_string(),
            parameters,
            requested_capabilities: vec![],
            expires_at_unix_ms: 10_000,
            nonce: vec![9; 16],
        })
        .unwrap()
    }

    fn terminal_request_with_limits(
        request_id: &str,
        cwd: &Path,
        argv: &[&str],
        timeout_ms: u64,
        max_output_bytes: u64,
    ) -> ActionRequest {
        let mut parameters = BTreeMap::new();
        parameters.insert(
            "argv".into(),
            serde_json::Value::Array(
                argv.iter()
                    .map(|value| serde_json::Value::String((*value).to_owned()))
                    .collect(),
            ),
        );
        parameters.insert("timeout_ms".into(), serde_json::Value::from(timeout_ms));
        parameters.insert(
            "max_output_bytes".into(),
            serde_json::Value::from(max_output_bytes),
        );
        parameters.insert("columns".into(), serde_json::Value::from(80u64));
        parameters.insert("rows".into(), serde_json::Value::from(25u64));
        ActionRequest::seal(ActionEnvelope {
            request_id: request_id.to_owned(),
            organization_id: "org-1".into(),
            actor_id: "remote-terminal-test".into(),
            device_id: "device-1".into(),
            action: "terminal.exec".into(),
            target: cwd.to_string_lossy().into_owned(),
            parameters,
            requested_capabilities: vec![],
            expires_at_unix_ms: 10_000,
            nonce: vec![6; 16],
        })
        .unwrap()
    }

    fn approved_from_prepared(
        proto: &v1::ActionRequest,
        prepared: &ActionResult,
        approver_id: &str,
        signing: &SigningKey,
    ) -> v1::ApprovedActionRequest {
        let challenge_json: serde_json::Value = serde_json::from_slice(&prepared.output).unwrap();
        let envelope_digest: [u8; 32] = STANDARD
            .decode(challenge_json["envelope_digest_base64"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let approval_nonce: [u8; 32] = STANDARD
            .decode(challenge_json["approval_nonce_base64"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let challenge = ApprovalChallenge {
            request_id: challenge_json["request_id"].as_str().unwrap().to_owned(),
            envelope_digest,
            policy_id: challenge_json["policy_id"].as_str().unwrap().to_owned(),
            required_capability: challenge_json["required_capability"]
                .as_str()
                .map(str::to_owned),
            expires_at_unix_ms: challenge_json["expires_at_unix_ms"].as_u64().unwrap(),
            approval_nonce,
        };
        let approval = sign_approval(challenge, approver_id, signing).unwrap();
        v1::ApprovedActionRequest {
            request: Some(proto.clone()),
            approval: Some(approval_grant_to_proto(&approval).unwrap()),
        }
    }

    #[cfg(windows)]
    #[test]
    #[ignore = "requires local Firefox and pinned geckodriver; run explicitly for A4 dispatch E2E"]
    fn a4_browser_session_enters_through_dispatcher_approval_and_audit() {
        let root = tempdir().unwrap();
        let policy = root.path().join("policy.yaml");
        write_policy(&policy, root.path());
        let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .ancestors()
            .nth(2)
            .unwrap()
            .to_path_buf();
        let geckodriver = std::env::var_os("VOR_GECKODRIVER")
            .map(PathBuf::from)
            .unwrap_or_else(|| repo_root.join(r"state\drivers\geckodriver\0.37.1\geckodriver.exe"));
        let firefox = std::env::var_os("VOR_FIREFOX")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(r"C:\Program Files\Mozilla Firefox\firefox.exe"));
        let lab_root = repo_root
            .join("state")
            .join("local")
            .join("a4-dispatch-lab")
            .join(format!("run-{}", std::process::id()));
        let _ = fs::remove_dir_all(&lab_root);

        let server = BrowserFixtureServer::start();
        let signing = SigningKey::from_bytes(&[44; 32]);
        let mut dispatcher = ReadOnlyDispatcher::open(DispatchConfig {
            device_id: "device-1".into(),
            policy_path: policy,
            audit_sqlite: root.path().join("audit.db"),
            audit_jsonl: root.path().join("audit.jsonl"),
            journal_dir: root.path().join("journal"),
            allowed_roots: vec![root.path().to_path_buf()],
            git_executable: find_git(),
            max_output_bytes: DEFAULT_MAX_OUTPUT_BYTES,
            browser: Some(BrowserWorkerConfig {
                geckodriver_path: geckodriver,
                firefox_binary: firefox,
                lab_root: lab_root.clone(),
                allowed_origin: server.origin().to_owned(),
            }),
        })
        .unwrap();
        dispatcher
            .add_trusted_approver("operator-1", signing.verifying_key().to_bytes())
            .unwrap();

        let start_proto = browser_proto("req-browser-start", "remote-browser-test", {
            browser_params("start")
        });
        let start = approved_json(&mut dispatcher, &start_proto, &signing, 1_000);
        let session_id = start["session_id"].as_str().unwrap().to_owned();
        let session_root = lab_root.join(&session_id);
        assert_eq!(start["generation"], 0);

        let mut navigate_params = browser_params("navigate");
        navigate_params.insert("session_id".into(), session_id.clone().into());
        navigate_params.insert("url".into(), format!("{}/page", server.origin()).into());
        let navigate_proto = browser_proto(
            "req-browser-navigate",
            "remote-browser-test",
            navigate_params,
        );
        let navigate = approved_json(&mut dispatcher, &navigate_proto, &signing, 2_000);
        assert_eq!(navigate["generation"], 1);

        let mut click_params = browser_params("click");
        click_params.insert("session_id".into(), session_id.clone().into());
        click_params.insert("selector".into(), "#go".into());
        click_params.insert("generation".into(), 1u64.into());
        let click_proto = browser_proto("req-browser-click", "remote-browser-test", click_params);
        let click_prepared = dispatcher.dispatch_proto_at(&click_proto, 3_000).unwrap();
        assert_eq!(click_prepared.status, "approval_required");
        let click_approved =
            approved_from_prepared(&click_proto, &click_prepared, "operator-1", &signing);
        let click = dispatcher
            .dispatch_approved_proto_at(&click_approved, 3_100)
            .unwrap();
        assert_eq!(click.status, "ok");
        let click_json: serde_json::Value = serde_json::from_slice(&click.output).unwrap();
        assert_eq!(click_json["clicked"], true);

        let replay = dispatcher
            .dispatch_approved_proto_report_at(&click_approved, 3_200)
            .unwrap();
        assert_eq!(replay.status, "approval_replayed");

        let mut wrong_actor_params = browser_params("click");
        wrong_actor_params.insert("session_id".into(), session_id.clone().into());
        wrong_actor_params.insert("selector".into(), "#go".into());
        wrong_actor_params.insert("generation".into(), 1u64.into());
        let wrong_actor_proto = browser_proto(
            "req-browser-wrong-actor",
            "different-actor",
            wrong_actor_params,
        );
        let wrong_actor_prepared = dispatcher
            .dispatch_proto_at(&wrong_actor_proto, 4_000)
            .unwrap();
        let wrong_actor_approved = approved_from_prepared(
            &wrong_actor_proto,
            &wrong_actor_prepared,
            "operator-1",
            &signing,
        );
        let wrong_actor = dispatcher
            .dispatch_approved_proto_report_at(&wrong_actor_approved, 4_100)
            .unwrap();
        assert_eq!(wrong_actor.status, "browser_session_not_found");

        let mut observe_params = browser_params("observe");
        observe_params.insert("session_id".into(), session_id.clone().into());
        let observe_proto =
            browser_proto("req-browser-observe", "remote-browser-test", observe_params);
        let observe = approved_json(&mut dispatcher, &observe_proto, &signing, 5_000);
        assert!(
            observe["nodes"]
                .as_array()
                .unwrap()
                .iter()
                .any(|node| node["text"] == "clicked-a")
        );

        let mut download_params = browser_params("download");
        download_params.insert("session_id".into(), session_id.clone().into());
        download_params.insert("selector".into(), "#download".into());
        download_params.insert("file_name".into(), "dispatch.txt".into());
        download_params.insert("operation_id".into(), "dispatch-download-op".into());
        download_params.insert("generation".into(), 1u64.into());
        let download_proto = browser_proto(
            "req-browser-download",
            "remote-browser-test",
            download_params,
        );
        let download = approved_json(&mut dispatcher, &download_proto, &signing, 6_000);
        assert_eq!(download["file_name"], "dispatch.txt");
        assert_eq!(
            download["sha256"],
            sha256_hex_bytes(b"dispatch-download-ok")
        );

        let mut close_params = browser_params("close");
        close_params.insert("session_id".into(), session_id.into());
        let close_proto = browser_proto("req-browser-close", "remote-browser-test", close_params);
        let close = approved_json(&mut dispatcher, &close_proto, &signing, 7_000);
        assert_eq!(close["state"], "closed");
        assert!(dispatcher.audit_sequence() >= 20);
        assert!(!session_root.exists());
        let _ = fs::remove_dir_all(&lab_root);
    }

    #[test]
    fn a4_browser_session_storage_uses_opaque_confined_roots_for_hostile_request_ids() {
        let root = tempdir().unwrap();
        let lab_root = root.path().join("lab");
        let sibling = root.path().join("neighbor-tenant");
        fs::create_dir_all(&sibling).unwrap();
        let sentinel = sibling.join("sentinel.txt");
        fs::write(&sentinel, "unchanged").unwrap();
        let policy = root.path().join("policy.yaml");
        write_policy(&policy, root.path());
        let signing = SigningKey::from_bytes(&[45; 32]);
        let mut dispatcher = ReadOnlyDispatcher::open(DispatchConfig {
            device_id: "device-1".into(),
            policy_path: policy,
            audit_sqlite: root.path().join("audit.db"),
            audit_jsonl: root.path().join("audit.jsonl"),
            journal_dir: root.path().join("journal"),
            allowed_roots: vec![root.path().to_path_buf()],
            git_executable: find_git(),
            max_output_bytes: DEFAULT_MAX_OUTPUT_BYTES,
            browser: Some(BrowserWorkerConfig {
                geckodriver_path: root.path().join("missing-geckodriver.exe"),
                firefox_binary: root.path().join("missing-firefox.exe"),
                lab_root: lab_root.clone(),
                allowed_origin: "http://127.0.0.1:9".into(),
            }),
        })
        .unwrap();
        dispatcher
            .add_trusted_approver("operator-1", signing.verifying_key().to_bytes())
            .unwrap();

        let hostile_request_ids = vec![
            r"..\neighbor-tenant\escape",
            "../neighbor-tenant/escape",
            r"C:\outside\escape",
            r"\\server\share\escape",
            "CON",
            "aux.txt",
        ];
        for (index, request_id) in hostile_request_ids.iter().enumerate() {
            let now = 10_000 + (index as u64 * 1_000);
            let request =
                browser_request(request_id, "remote-browser-test", browser_params("start"));
            let _ = dispatcher.dispatch_at(request.clone(), now);
            let approval = approved_direct_for_browser(&request, &signing, now + 100);
            let result = dispatcher.dispatch_approved_at(request, &approval, now + 200);
            assert!(matches!(
                result,
                Err(DispatchError::Browser(
                    vor_browser::BrowserError::MissingExecutable(_)
                ))
            ));
            assert_eq!(fs::read_to_string(&sentinel).unwrap(), "unchanged");
            assert!(!sibling.join("escape").exists());
        }

        let proto = browser_proto(
            "wire-valid-long-safe-id",
            "remote-browser-test",
            browser_params("start"),
        );
        let result = approved_report(&mut dispatcher, &proto, &signing, 30_000);
        assert_eq!(result.status, "browser_error");
        assert_eq!(fs::read_to_string(&sentinel).unwrap(), "unchanged");

        let entries: Vec<_> = fs::read_dir(&lab_root)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert!(
            entries.is_empty(),
            "unexpected lab allocations: {entries:?}"
        );
    }

    fn terminal_control_request(
        request_id: &str,
        action: &str,
        session_id: &str,
        actor_id: &str,
    ) -> ActionRequest {
        ActionRequest::seal(ActionEnvelope {
            request_id: request_id.to_owned(),
            organization_id: "org-1".into(),
            actor_id: actor_id.into(),
            device_id: "device-1".into(),
            action: action.into(),
            target: session_id.into(),
            parameters: BTreeMap::new(),
            requested_capabilities: vec![],
            expires_at_unix_ms: 10_000,
            nonce: vec![5; 16],
        })
        .unwrap()
    }

    fn terminal_control_request_for_workspace(
        request_id: &str,
        action: &str,
        session_id: &str,
        actor_id: &str,
        workspace_id: &str,
    ) -> ActionRequest {
        let mut parameters = BTreeMap::new();
        parameters.insert(
            "workspace_id".into(),
            serde_json::Value::String(workspace_id.to_owned()),
        );
        ActionRequest::seal(ActionEnvelope {
            request_id: request_id.to_owned(),
            organization_id: "org-1".into(),
            actor_id: actor_id.into(),
            device_id: "device-1".into(),
            action: action.into(),
            target: session_id.into(),
            parameters,
            requested_capabilities: vec![],
            expires_at_unix_ms: 10_000,
            nonce: vec![5; 16],
        })
        .unwrap()
    }

    fn terminal_request_for_workspace(
        request_id: &str,
        cwd: &Path,
        argv: &[&str],
        workspace_id: &str,
    ) -> ActionRequest {
        let mut parameters = BTreeMap::new();
        parameters.insert(
            "argv".into(),
            serde_json::Value::Array(
                argv.iter()
                    .map(|value| serde_json::Value::String((*value).to_owned()))
                    .collect(),
            ),
        );
        parameters.insert("timeout_ms".into(), serde_json::Value::from(5_000u64));
        parameters.insert(
            "max_output_bytes".into(),
            serde_json::Value::from(64 * 1024u64),
        );
        parameters.insert("columns".into(), serde_json::Value::from(80u64));
        parameters.insert("rows".into(), serde_json::Value::from(25u64));
        parameters.insert(
            "workspace_id".into(),
            serde_json::Value::String(workspace_id.to_owned()),
        );
        ActionRequest::seal(ActionEnvelope {
            request_id: request_id.to_owned(),
            organization_id: "org-1".into(),
            actor_id: "remote-terminal-test".into(),
            device_id: "device-1".into(),
            action: "terminal.exec".into(),
            target: cwd.to_string_lossy().into_owned(),
            parameters,
            requested_capabilities: vec![],
            expires_at_unix_ms: 10_000,
            nonce: vec![6; 16],
        })
        .unwrap()
    }

    #[cfg(windows)]
    fn wait_terminal_result(
        dispatcher: &mut ReadOnlyDispatcher,
        session_id: &str,
        start_now_unix_ms: u64,
    ) -> serde_json::Value {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(120);
        for index in 0..12_000u64 {
            let request = terminal_control_request(
                &format!("poll-{session_id}-{index}"),
                "terminal.poll",
                session_id,
                "remote-terminal-test",
            );
            let result = dispatcher
                .dispatch_at(request, start_now_unix_ms.saturating_add(index))
                .unwrap();
            assert_eq!(result.status, "ok");
            let payload: serde_json::Value = serde_json::from_slice(&result.output).unwrap();
            if payload["state"] != "running" {
                return payload;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "terminal session did not finish"
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        panic!("terminal session polling exhausted");
    }

    #[cfg(windows)]
    fn wait_terminal_result_for_workspace(
        dispatcher: &mut ReadOnlyDispatcher,
        session_id: &str,
        workspace_id: &str,
        start_now_unix_ms: u64,
    ) -> serde_json::Value {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(120);
        for index in 0..12_000u64 {
            let request = terminal_control_request_for_workspace(
                &format!("poll-{session_id}-{workspace_id}-{index}"),
                "terminal.poll",
                session_id,
                "remote-terminal-test",
                workspace_id,
            );
            let result = dispatcher
                .dispatch_at(request, start_now_unix_ms.saturating_add(index))
                .unwrap();
            assert_eq!(result.status, "ok");
            let payload: serde_json::Value = serde_json::from_slice(&result.output).unwrap();
            if payload["state"] != "running" {
                return payload;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "terminal session did not finish"
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        panic!("terminal session polling exhausted");
    }

    #[cfg(windows)]
    #[test]
    fn approved_terminal_exec_prepares_then_runs_once_with_owner_authority() {
        let dir = tempdir().unwrap();
        let marker = dir.path().join("terminal-marker.txt");
        let request = terminal_request(
            "req-terminal-approved-1",
            dir.path(),
            &[
                "cmd.exe",
                "/D",
                "/Q",
                "/C",
                "echo VOR_TERMINAL_DISPATCH>terminal-marker.txt",
            ],
        );
        let proto = action_request_to_proto(&request).unwrap();
        let signing = SigningKey::from_bytes(&[33; 32]);
        let mut dispatcher = dispatcher(dir.path(), DEFAULT_MAX_OUTPUT_BYTES);
        dispatcher
            .add_trusted_approver_with_authority(
                "owner-1",
                signing.verifying_key().to_bytes(),
                ApproverAuthority::Owner,
            )
            .unwrap();

        let prepared = dispatcher.dispatch_proto_at(&proto, 1_000).unwrap();
        assert_eq!(prepared.status, "approval_required");
        assert!(!marker.exists());

        let challenge_json: serde_json::Value = serde_json::from_slice(&prepared.output).unwrap();
        let envelope_digest: [u8; 32] = STANDARD
            .decode(challenge_json["envelope_digest_base64"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let approval_nonce: [u8; 32] = STANDARD
            .decode(challenge_json["approval_nonce_base64"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let challenge = ApprovalChallenge {
            request_id: challenge_json["request_id"].as_str().unwrap().to_owned(),
            envelope_digest,
            policy_id: challenge_json["policy_id"].as_str().unwrap().to_owned(),
            required_capability: challenge_json["required_capability"]
                .as_str()
                .map(str::to_owned),
            expires_at_unix_ms: challenge_json["expires_at_unix_ms"].as_u64().unwrap(),
            approval_nonce,
        };
        assert_eq!(challenge.required_capability.as_deref(), Some("elevated"));
        let approval = sign_approval(challenge, "owner-1", &signing).unwrap();
        let approved = v1::ApprovedActionRequest {
            request: Some(proto.clone()),
            approval: Some(approval_grant_to_proto(&approval).unwrap()),
        };

        let result = dispatcher
            .dispatch_approved_proto_at(&approved, 2_000)
            .unwrap();
        assert_eq!(result.status, "ok");
        let started: serde_json::Value = serde_json::from_slice(&result.output).unwrap();
        assert_eq!(started["state"], "running");
        let session_id = started["session_id"].as_str().unwrap().to_owned();

        let replay = dispatcher.dispatch_approved_proto_at(&approved, 2_500);
        assert!(matches!(
            replay,
            Err(DispatchError::Core(
                vor_core::CoreError::ApprovalAlreadyConsumed
            ))
        ));

        let completed = wait_terminal_result(&mut dispatcher, &session_id, 3_000);
        assert_eq!(completed["state"], "completed");
        assert_eq!(completed["exit_code"], 0);
        assert!(
            fs::read_to_string(&marker)
                .unwrap()
                .contains("VOR_TERMINAL_DISPATCH")
        );
    }

    #[cfg(windows)]
    #[test]
    fn terminal_poll_is_bound_to_workspace_and_wrong_poll_does_not_consume_result() {
        let dir = tempdir().unwrap();
        let request = terminal_request_for_workspace(
            "req-terminal-workspace-owner",
            dir.path(),
            &["cmd.exe", "/D", "/Q", "/C", "echo WORKSPACE_BOUND"],
            "ws-a1",
        );
        let proto = action_request_to_proto(&request).unwrap();
        let signing = SigningKey::from_bytes(&[53; 32]);
        let mut dispatcher = dispatcher(dir.path(), DEFAULT_MAX_OUTPUT_BYTES);
        dispatcher
            .add_trusted_approver_with_authority(
                "owner-1",
                signing.verifying_key().to_bytes(),
                ApproverAuthority::Owner,
            )
            .unwrap();

        let prepared = dispatcher.dispatch_proto_at(&proto, 1_000).unwrap();
        let approved = approved_from_prepared(&proto, &prepared, "owner-1", &signing);
        let result = dispatcher
            .dispatch_approved_proto_at(&approved, 2_000)
            .unwrap();
        let started: serde_json::Value = serde_json::from_slice(&result.output).unwrap();
        let session_id = started["session_id"].as_str().unwrap().to_owned();

        let owner = TerminalSessionOwner::with_workspace(
            "org-1",
            "remote-terminal-test",
            "device-1",
            Some("ws-a1"),
        )
        .unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(120);
        loop {
            let snapshot = dispatcher
                .terminal_sessions
                .poll(&session_id, &owner)
                .unwrap();
            if snapshot.state == TerminalSessionState::Completed {
                assert_eq!(snapshot.exit_code, Some(0));
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "terminal manager did not publish Completed before foreign poll"
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
        }

        let wrong_poll = terminal_control_request_for_workspace(
            "poll-terminal-wrong-workspace",
            "terminal.poll",
            &session_id,
            "remote-terminal-test",
            "ws-a2",
        );
        let wrong_result = dispatcher.dispatch_at(wrong_poll, 2_100);
        assert!(matches!(
            wrong_result,
            Err(DispatchError::Terminal(
                vor_terminal::TerminalError::SessionOwnerMismatch
            ))
        ));

        let completed =
            wait_terminal_result_for_workspace(&mut dispatcher, &session_id, "ws-a1", 2_200);
        assert_eq!(completed["state"], "completed");
        assert_eq!(completed["exit_code"], 0);
        let output = STANDARD
            .decode(completed["output_base64"].as_str().unwrap())
            .unwrap();
        assert!(
            output
                .windows(b"WORKSPACE_BOUND".len())
                .any(|window| window == b"WORKSPACE_BOUND")
        );
    }

    #[test]
    fn terminal_exec_without_structured_argv_fails_policy_closed() {
        let dir = tempdir().unwrap();
        let mut dispatcher = dispatcher(dir.path(), DEFAULT_MAX_OUTPUT_BYTES);
        let result = dispatcher.dispatch_proto_at(
            &request("terminal.exec", &dir.path().to_string_lossy(), "device-1"),
            1_000,
        );
        assert!(matches!(result, Err(DispatchError::Denied)));
    }

    #[cfg(windows)]
    #[test]
    fn inline_terminal_rejects_plain_approver_authority() {
        let dir = tempdir().unwrap();
        let request = terminal_request(
            "req-terminal-low-authority",
            dir.path(),
            &["cmd.exe", "/D", "/Q", "/C", "echo SHOULD_NOT_RUN"],
        );
        let proto = action_request_to_proto(&request).unwrap();
        let signing = SigningKey::from_bytes(&[34; 32]);
        let mut dispatcher = dispatcher(dir.path(), DEFAULT_MAX_OUTPUT_BYTES);
        dispatcher
            .add_trusted_approver("reviewer-1", signing.verifying_key().to_bytes())
            .unwrap();

        let prepared = dispatcher.dispatch_proto_at(&proto, 1_000).unwrap();
        let challenge: serde_json::Value = serde_json::from_slice(&prepared.output).unwrap();
        assert_eq!(challenge["required_capability"], "elevated");
        let approved = approved_from_prepared(&proto, &prepared, "reviewer-1", &signing);

        let result = dispatcher
            .dispatch_approved_proto_report_at(&approved, 2_000)
            .unwrap();
        assert_eq!(result.status, "approval_invalid");
    }

    #[cfg(windows)]
    #[test]
    fn tenant_scoped_approver_revocation_and_rotation_are_live_in_dispatcher() {
        let dir = tempdir().unwrap();
        let revoked_marker = dir.path().join("revoked-should-not-run.txt");
        let request = terminal_request(
            "req-terminal-revoked-approver",
            dir.path(),
            &[
                "cmd.exe",
                "/D",
                "/Q",
                "/C",
                "echo REVOKED_SHOULD_NOT_RUN>revoked-should-not-run.txt",
            ],
        );
        let proto = action_request_to_proto(&request).unwrap();
        let signing = SigningKey::from_bytes(&[44; 32]);
        let mut dispatcher = dispatcher(dir.path(), DEFAULT_MAX_OUTPUT_BYTES);
        dispatcher.require_tenant_scoped_approvers();
        dispatcher
            .add_trusted_approver_for_organization(
                "tenant-owner",
                signing.verifying_key().to_bytes(),
                ApproverAuthority::Owner,
                "org-1",
            )
            .unwrap();
        let prepared = dispatcher.dispatch_proto_at(&proto, 1_000).unwrap();
        let approved = approved_from_prepared(&proto, &prepared, "tenant-owner", &signing);
        dispatcher.revoke_trusted_approver("tenant-owner").unwrap();
        let result = dispatcher
            .dispatch_approved_proto_report_at(&approved, 2_000)
            .unwrap();
        assert_eq!(result.status, "approval_invalid");
        assert!(!revoked_marker.exists());

        let rotated_marker = dir.path().join("rotated-runs-once.txt");
        let rotated = terminal_request(
            "req-terminal-rotated-approver",
            dir.path(),
            &[
                "cmd.exe",
                "/D",
                "/Q",
                "/C",
                "echo ROTATED_OK>rotated-runs-once.txt",
            ],
        );
        let rotated_proto = action_request_to_proto(&rotated).unwrap();
        let old_signing = SigningKey::from_bytes(&[45; 32]);
        let new_signing = SigningKey::from_bytes(&[46; 32]);
        dispatcher
            .rotate_trusted_approver_for_organization(
                "tenant-owner",
                old_signing.verifying_key().to_bytes(),
                ApproverAuthority::Owner,
                "org-1",
            )
            .unwrap();
        let prepared = dispatcher.dispatch_proto_at(&rotated_proto, 3_000).unwrap();
        let old_approved =
            approved_from_prepared(&rotated_proto, &prepared, "tenant-owner", &old_signing);
        dispatcher
            .rotate_trusted_approver_for_organization(
                "tenant-owner",
                new_signing.verifying_key().to_bytes(),
                ApproverAuthority::Owner,
                "org-1",
            )
            .unwrap();
        let old_result = dispatcher
            .dispatch_approved_proto_report_at(&old_approved, 4_000)
            .unwrap();
        assert_eq!(old_result.status, "approval_invalid");
        assert!(!rotated_marker.exists());

        let new_approved =
            approved_from_prepared(&rotated_proto, &prepared, "tenant-owner", &new_signing);
        let result = dispatcher
            .dispatch_approved_proto_at(&new_approved, 4_100)
            .unwrap();
        assert_eq!(result.status, "ok");
        let started: serde_json::Value = serde_json::from_slice(&result.output).unwrap();
        let session_id = started["session_id"].as_str().unwrap().to_owned();
        let completed = wait_terminal_result(&mut dispatcher, &session_id, 4_200);
        assert_eq!(completed["state"], "completed");
        assert!(
            fs::read_to_string(&rotated_marker)
                .unwrap()
                .contains("ROTATED_OK")
        );
    }

    #[cfg(windows)]
    #[test]
    fn inline_terminal_accepts_elevated_approver_authority() {
        let dir = tempdir().unwrap();
        let request = terminal_request(
            "req-terminal-elevated",
            dir.path(),
            &["cmd.exe", "/D", "/Q", "/C", "echo VOR_ELEVATED_OK"],
        );
        let proto = action_request_to_proto(&request).unwrap();
        let signing = SigningKey::from_bytes(&[35; 32]);
        let mut dispatcher = dispatcher(dir.path(), DEFAULT_MAX_OUTPUT_BYTES);
        dispatcher
            .add_trusted_approver_with_authority(
                "elevated-1",
                signing.verifying_key().to_bytes(),
                ApproverAuthority::Elevated,
            )
            .unwrap();

        let prepared = dispatcher.dispatch_proto_at(&proto, 1_000).unwrap();
        let approved = approved_from_prepared(&proto, &prepared, "elevated-1", &signing);
        let result = dispatcher
            .dispatch_approved_proto_at(&approved, 2_000)
            .unwrap();
        let started: serde_json::Value = serde_json::from_slice(&result.output).unwrap();
        assert_eq!(started["state"], "running");
        let session_id = started["session_id"].as_str().unwrap().to_owned();
        let payload = wait_terminal_result(&mut dispatcher, &session_id, 2_100);
        assert_eq!(payload["state"], "completed");
        assert_eq!(payload["exit_code"], 0);
        let output = STANDARD
            .decode(payload["output_base64"].as_str().unwrap())
            .unwrap();
        assert!(
            output
                .windows(b"VOR_ELEVATED_OK".len())
                .any(|window| window == b"VOR_ELEVATED_OK")
        );
    }

    #[cfg(windows)]
    #[test]
    fn approved_terminal_rejects_cwd_outside_authorized_roots() {
        let dir = tempdir().unwrap();
        let allowed = dir.path().join("allowed");
        let outside = dir.path().join("outside");
        fs::create_dir_all(&allowed).unwrap();
        fs::create_dir_all(&outside).unwrap();

        let request = terminal_request(
            "req-terminal-outside-cwd",
            &outside,
            &["where.exe", "cmd.exe"],
        );
        let proto = action_request_to_proto(&request).unwrap();
        let signing = SigningKey::from_bytes(&[36; 32]);
        let mut dispatcher = dispatcher(&allowed, DEFAULT_MAX_OUTPUT_BYTES);
        dispatcher
            .add_trusted_approver("reviewer-1", signing.verifying_key().to_bytes())
            .unwrap();

        let prepared = dispatcher.dispatch_proto_at(&proto, 1_000).unwrap();
        let approved = approved_from_prepared(&proto, &prepared, "reviewer-1", &signing);
        let result = dispatcher.dispatch_approved_proto_at(&approved, 2_000);
        assert!(matches!(
            result,
            Err(DispatchError::Terminal(
                vor_terminal::TerminalError::CwdOutsideAllowedRoots
            ))
        ));
    }

    #[cfg(windows)]
    #[test]
    fn approved_terminal_maps_timeout_and_output_limit_failures() {
        let dir = tempdir().unwrap();
        let signing = SigningKey::from_bytes(&[37; 32]);
        let mut dispatcher = dispatcher(dir.path(), DEFAULT_MAX_OUTPUT_BYTES);
        dispatcher
            .add_trusted_approver("reviewer-1", signing.verifying_key().to_bytes())
            .unwrap();

        let timeout_request = terminal_request_with_limits(
            "req-terminal-timeout",
            dir.path(),
            &["ping.exe", "127.0.0.1", "-n", "10"],
            50,
            64 * 1024,
        );
        let timeout_proto = action_request_to_proto(&timeout_request).unwrap();
        let timeout_prepared = dispatcher.dispatch_proto_at(&timeout_proto, 1_000).unwrap();
        let timeout_approved =
            approved_from_prepared(&timeout_proto, &timeout_prepared, "reviewer-1", &signing);
        let timeout_result = dispatcher
            .dispatch_approved_proto_report_at(&timeout_approved, 2_000)
            .unwrap();
        assert_eq!(timeout_result.status, "ok");
        let timeout_started: serde_json::Value =
            serde_json::from_slice(&timeout_result.output).unwrap();
        let timeout_session = timeout_started["session_id"].as_str().unwrap().to_owned();
        let timeout_final = wait_terminal_result(&mut dispatcher, &timeout_session, 2_100);
        assert_eq!(timeout_final["state"], "timed_out");
        assert_eq!(timeout_final["error_code"], "terminal_timeout");

        let output_request = terminal_request_with_limits(
            "req-terminal-output",
            dir.path(),
            &["ping.exe", "127.0.0.1", "-n", "1"],
            5_000,
            4,
        );
        let output_proto = action_request_to_proto(&output_request).unwrap();
        let output_prepared = dispatcher.dispatch_proto_at(&output_proto, 3_000).unwrap();
        let output_approved =
            approved_from_prepared(&output_proto, &output_prepared, "reviewer-1", &signing);
        let output_result = dispatcher
            .dispatch_approved_proto_report_at(&output_approved, 4_000)
            .unwrap();
        assert_eq!(output_result.status, "ok");
        let output_started: serde_json::Value =
            serde_json::from_slice(&output_result.output).unwrap();
        let output_session = output_started["session_id"].as_str().unwrap().to_owned();
        let output_final = wait_terminal_result(&mut dispatcher, &output_session, 4_100);
        assert_eq!(output_final["state"], "failed");
        assert_eq!(output_final["error_code"], "terminal_output_limit_exceeded");
    }

    #[cfg(windows)]
    #[test]
    fn terminal_cancel_is_owner_bound_and_observed_by_poll() {
        let dir = tempdir().unwrap();
        let signing = SigningKey::from_bytes(&[38; 32]);
        let mut dispatcher = dispatcher(dir.path(), DEFAULT_MAX_OUTPUT_BYTES);
        dispatcher
            .add_trusted_approver("reviewer-1", signing.verifying_key().to_bytes())
            .unwrap();

        let request = terminal_request_with_limits(
            "req-terminal-cancel",
            dir.path(),
            &["ping.exe", "127.0.0.1", "-n", "10"],
            10_000,
            64 * 1024,
        );
        let proto = action_request_to_proto(&request).unwrap();
        let prepared = dispatcher.dispatch_proto_at(&proto, 1_000).unwrap();
        let approved = approved_from_prepared(&proto, &prepared, "reviewer-1", &signing);
        let started = dispatcher
            .dispatch_approved_proto_at(&approved, 2_000)
            .unwrap();
        let started: serde_json::Value = serde_json::from_slice(&started.output).unwrap();
        let session_id = started["session_id"].as_str().unwrap().to_owned();

        let wrong_owner = terminal_control_request(
            "cancel-wrong-owner",
            "terminal.cancel",
            &session_id,
            "other-actor",
        );
        let wrong_result = dispatcher.dispatch_at(wrong_owner, 2_100);
        assert!(matches!(
            wrong_result,
            Err(DispatchError::Terminal(
                vor_terminal::TerminalError::SessionOwnerMismatch
            ))
        ));

        let cancel = terminal_control_request(
            "cancel-owner",
            "terminal.cancel",
            &session_id,
            "remote-terminal-test",
        );
        let cancelled = dispatcher.dispatch_at(cancel, 2_200).unwrap();
        let cancelled: serde_json::Value = serde_json::from_slice(&cancelled.output).unwrap();
        assert_eq!(cancelled["cancel_requested"], true);

        let final_state = wait_terminal_result(&mut dispatcher, &session_id, 2_300);
        assert_eq!(final_state["state"], "cancelled");
        assert_eq!(final_state["error_code"], "terminal_cancelled");
    }

    #[test]
    fn filesystem_read_executes_and_is_audited_twice() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("demo.txt");
        fs::write(&file, b"remote-read-ok").unwrap();
        let mut dispatcher = dispatcher(dir.path(), 1024);
        let result = dispatcher
            .dispatch_proto_at(
                &request("filesystem.read", &file.to_string_lossy(), "device-1"),
                1_000,
            )
            .unwrap();
        assert_eq!(result.status, "ok");
        assert_eq!(result.output, b"remote-read-ok");
        assert_eq!(result.content_type, "application/octet-stream");
        assert_eq!(dispatcher.audit_sequence(), 2);
    }
    #[test]
    fn remote_scope_blocks_local_auto_terminal_action() {
        let dir = tempdir().unwrap();
        let mut dispatcher = dispatcher(dir.path(), 1024);
        let result = dispatcher.dispatch_proto_at(
            &request("terminal.project_test", "local", "device-1"),
            1_000,
        );
        assert!(matches!(result, Err(DispatchError::RemoteActionNotAllowed)));
        assert_eq!(dispatcher.audit_sequence(), 2);
    }

    #[test]
    fn wrong_device_is_rejected_before_local_audit() {
        let dir = tempdir().unwrap();
        let mut dispatcher = dispatcher(dir.path(), 1024);
        let result =
            dispatcher.dispatch_proto_at(&request("process.list", "local", "other-device"), 1_000);
        assert!(matches!(result, Err(DispatchError::WrongDevice)));
        assert_eq!(dispatcher.audit_sequence(), 0);
    }

    #[test]
    fn file_limit_is_enforced_before_read_payload_is_returned() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("large.bin");
        fs::write(&file, b"12345").unwrap();
        let mut dispatcher = dispatcher(dir.path(), 4);
        let result = dispatcher.dispatch_proto_at(
            &request("filesystem.read", &file.to_string_lossy(), "device-1"),
            1_000,
        );
        assert!(matches!(
            result,
            Err(DispatchError::Fs(vor_fs::FsError::ReadLimitExceeded { .. }))
        ));
        assert_eq!(dispatcher.audit_sequence(), 2);
    }

    #[test]
    fn process_list_is_json_and_audited() {
        let dir = tempdir().unwrap();
        let mut dispatcher = dispatcher(dir.path(), DEFAULT_MAX_OUTPUT_BYTES);
        let result = dispatcher
            .dispatch_proto_at(&request("process.list", "local", "device-1"), 1_000)
            .unwrap();
        assert_eq!(result.content_type, "application/json");
        let processes: Vec<vor_process::ProcessInfo> =
            serde_json::from_slice(&result.output).unwrap();
        assert!(
            processes
                .iter()
                .any(|process| process.pid == std::process::id())
        );
        assert_eq!(dispatcher.audit_sequence(), 2);
    }
    #[test]
    fn git_status_uses_read_only_worker() {
        let dir = tempdir().unwrap();
        let git = find_git();
        assert!(
            Command::new(&git)
                .arg("-C")
                .arg(dir.path())
                .args(["init", "--quiet"])
                .status()
                .unwrap()
                .success()
        );
        fs::write(dir.path().join("untracked.txt"), "x\n").unwrap();
        let mut dispatcher = dispatcher(dir.path(), DEFAULT_MAX_OUTPUT_BYTES);
        let result = dispatcher
            .dispatch_proto_at(
                &request("git.status", &dir.path().to_string_lossy(), "device-1"),
                1_000,
            )
            .unwrap();
        let output: vor_git::GitOutput = serde_json::from_slice(&result.output).unwrap();
        assert!(output.stdout.contains("untracked.txt"));
        assert_eq!(dispatcher.audit_sequence(), 2);
    }

    #[test]
    fn process_inspect_routes_current_pid() {
        let dir = tempdir().unwrap();
        let mut dispatcher = dispatcher(dir.path(), DEFAULT_MAX_OUTPUT_BYTES);
        let pid = std::process::id().to_string();
        let result = dispatcher
            .dispatch_proto_at(&request("process.inspect", &pid, "device-1"), 1_000)
            .unwrap();
        let process: vor_process::ProcessInfo = serde_json::from_slice(&result.output).unwrap();
        assert_eq!(process.pid, std::process::id());
        assert_eq!(dispatcher.audit_sequence(), 2);
    }

    #[cfg(windows)]
    #[test]
    fn approved_process_terminate_kills_exact_synthetic_instance_once() {
        let dir = tempdir().unwrap();
        let (_target, mut child) = spawn_lab_process(dir.path(), "a3-lab-agent.exe", 300);
        let identity = vor_process::ProcessWorker.identity(child.id()).unwrap();
        let request = process_terminate_request("req-process-terminate-ok", &identity);
        let proto = action_request_to_proto(&request).unwrap();
        let signing = SigningKey::from_bytes(&[51; 32]);
        let mut dispatcher = dispatcher(dir.path(), DEFAULT_MAX_OUTPUT_BYTES);
        dispatcher
            .add_trusted_approver("operator-1", signing.verifying_key().to_bytes())
            .unwrap();

        let prepared = dispatcher.dispatch_proto_at(&proto, 1_000).unwrap();
        assert_eq!(prepared.status, "approval_required");
        assert!(child.try_wait().unwrap().is_none());
        let approved = approved_from_prepared(&proto, &prepared, "operator-1", &signing);
        let result = dispatcher
            .dispatch_approved_proto_at(&approved, 2_000)
            .unwrap();
        let receipt: vor_process::ProcessTerminateReceipt =
            serde_json::from_slice(&result.output).unwrap();
        assert_eq!(receipt.pid, identity.pid);
        assert!(receipt.terminated);
        let _ = child.wait().unwrap();

        let replay = dispatcher.dispatch_approved_proto_at(&approved, 2_500);
        assert!(matches!(
            replay,
            Err(DispatchError::Core(
                vor_core::CoreError::ApprovalAlreadyConsumed
            ))
        ));
    }

    #[cfg(windows)]
    #[test]
    fn approved_process_terminate_rejects_stale_identity_without_kill() {
        let dir = tempdir().unwrap();
        let (_target, mut child) = spawn_lab_process(dir.path(), "a3-lab-stale.exe", 8);
        let mut identity = vor_process::ProcessWorker.identity(child.id()).unwrap();
        identity.created_at_windows_filetime_100ns =
            identity.created_at_windows_filetime_100ns.saturating_sub(1);
        let request = process_terminate_request("req-process-terminate-stale", &identity);
        let proto = action_request_to_proto(&request).unwrap();
        let signing = SigningKey::from_bytes(&[52; 32]);
        let mut dispatcher = dispatcher(dir.path(), DEFAULT_MAX_OUTPUT_BYTES);
        dispatcher
            .add_trusted_approver("operator-1", signing.verifying_key().to_bytes())
            .unwrap();
        let prepared = dispatcher.dispatch_proto_at(&proto, 1_000).unwrap();
        let approved = approved_from_prepared(&proto, &prepared, "operator-1", &signing);

        let result = dispatcher.dispatch_approved_proto_at(&approved, 2_000);
        assert!(matches!(
            result,
            Err(DispatchError::Process(
                vor_process::ProcessError::IdentityMismatch { .. }
            ))
        ));
        assert!(child.try_wait().unwrap().is_none());
        let _ = child.kill();
        let _ = child.wait();
    }

    #[cfg(windows)]
    #[test]
    fn approved_process_terminate_rejects_already_finished_process() {
        let dir = tempdir().unwrap();
        let target = dir.path().join("a3-lab-finished.exe");
        fs::copy(system_cmd(), &target).unwrap();
        let mut child = Command::new(&target)
            .args(["/D", "/Q", "/C", "ping.exe 127.0.0.1 -n 2 >NUL"])
            .current_dir(dir.path())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let identity = vor_process::ProcessWorker.identity(child.id()).unwrap();
        let request = process_terminate_request("req-process-terminate-finished", &identity);
        let proto = action_request_to_proto(&request).unwrap();
        let signing = SigningKey::from_bytes(&[53; 32]);
        let mut dispatcher = dispatcher(dir.path(), DEFAULT_MAX_OUTPUT_BYTES);
        dispatcher
            .add_trusted_approver("operator-1", signing.verifying_key().to_bytes())
            .unwrap();
        let prepared = dispatcher.dispatch_proto_at(&proto, 1_000).unwrap();
        let approved = approved_from_prepared(&proto, &prepared, "operator-1", &signing);
        let _ = child.wait();

        let result = dispatcher.dispatch_approved_proto_at(&approved, 2_000);
        assert!(matches!(
            result,
            Err(DispatchError::Process(
                vor_process::ProcessError::AlreadyExited(_)
            )) | Err(DispatchError::Process(vor_process::ProcessError::Io(_)))
        ));
    }

    #[cfg(windows)]
    #[test]
    fn approved_process_terminate_rejects_expired_approval() {
        let dir = tempdir().unwrap();
        let (_target, mut child) = spawn_lab_process(dir.path(), "a3-lab-expired.exe", 300);
        let identity = vor_process::ProcessWorker.identity(child.id()).unwrap();
        let request = process_terminate_request("req-process-terminate-expired", &identity);
        let proto = action_request_to_proto(&request).unwrap();
        let signing = SigningKey::from_bytes(&[54; 32]);
        let mut dispatcher = dispatcher(dir.path(), DEFAULT_MAX_OUTPUT_BYTES);
        dispatcher
            .add_trusted_approver("operator-1", signing.verifying_key().to_bytes())
            .unwrap();
        let prepared = dispatcher.dispatch_proto_at(&proto, 1_000).unwrap();
        let approved = approved_from_prepared(&proto, &prepared, "operator-1", &signing);

        let result = dispatcher.dispatch_approved_proto_at(&approved, 11_000);
        assert!(matches!(result, Err(DispatchError::Core(_))));
        assert!(child.try_wait().unwrap().is_none());
        let _ = child.kill();
        let _ = child.wait();
    }

    #[cfg(windows)]
    #[test]
    fn approved_process_terminate_rejects_current_control_process() {
        let dir = tempdir().unwrap();
        let identity = vor_process::ProcessWorker
            .identity(std::process::id())
            .unwrap();
        let request = process_terminate_request("req-process-terminate-self", &identity);
        let proto = action_request_to_proto(&request).unwrap();
        let signing = SigningKey::from_bytes(&[55; 32]);
        let mut dispatcher = dispatcher(dir.path(), DEFAULT_MAX_OUTPUT_BYTES);
        dispatcher
            .add_trusted_approver("operator-1", signing.verifying_key().to_bytes())
            .unwrap();
        let prepared = dispatcher.dispatch_proto_at(&proto, 1_000).unwrap();
        let approved = approved_from_prepared(&proto, &prepared, "operator-1", &signing);

        let result = dispatcher.dispatch_approved_proto_at(&approved, 2_000);
        assert!(matches!(
            result,
            Err(DispatchError::Process(
                vor_process::ProcessError::ProtectedProcess("current_process")
            ))
        ));
    }

    #[test]
    fn git_diff_routes_read_only_patch() {
        let dir = tempdir().unwrap();
        let git = find_git();
        assert!(
            Command::new(&git)
                .arg("-C")
                .arg(dir.path())
                .args(["init", "--quiet"])
                .status()
                .unwrap()
                .success()
        );
        let file = dir.path().join("tracked.txt");
        fs::write(&file, "before\n").unwrap();
        assert!(
            Command::new(&git)
                .arg("-C")
                .arg(dir.path())
                .args(["add", "tracked.txt"])
                .status()
                .unwrap()
                .success()
        );
        fs::write(&file, "after\n").unwrap();
        let mut dispatcher = dispatcher(dir.path(), DEFAULT_MAX_OUTPUT_BYTES);
        let result = dispatcher
            .dispatch_proto_at(
                &request("git.diff", &dir.path().to_string_lossy(), "device-1"),
                1_000,
            )
            .unwrap();
        let output: vor_git::GitOutput = serde_json::from_slice(&result.output).unwrap();
        assert!(output.stdout.contains("-before"));
        assert!(output.stdout.contains("+after"));
        assert_eq!(dispatcher.audit_sequence(), 2);
    }

    #[test]
    fn filesystem_write_prepare_emits_bound_challenge_without_writing() {
        let dir = tempdir().unwrap();
        let target = dir.path().join("prepare.txt");
        fs::write(&target, b"old").unwrap();
        let mut dispatcher = dispatcher(dir.path(), DEFAULT_MAX_OUTPUT_BYTES);
        let prepared = write_request(
            "req-write-prepare",
            &target,
            b"new",
            &sha256_hex_bytes(b"old"),
        );
        let proto = action_request_to_proto(&prepared).unwrap();

        let result = dispatcher.dispatch_proto_at(&proto, 1_000).unwrap();
        assert_eq!(result.status, "approval_required");
        assert_eq!(result.content_type, "application/json");
        assert_eq!(fs::read(&target).unwrap(), b"old");

        let challenge: serde_json::Value = serde_json::from_slice(&result.output).unwrap();
        assert_eq!(challenge["request_id"], "req-write-prepare");
        assert_eq!(challenge["policy_id"], "dispatch-test");
        assert_eq!(
            challenge["envelope_digest_base64"].as_str().unwrap(),
            STANDARD.encode(prepared.envelope_digest)
        );
        assert_eq!(
            challenge["expires_at_unix_ms"].as_u64().unwrap(),
            prepared.envelope.expires_at_unix_ms
        );
        let nonce = STANDARD
            .decode(challenge["approval_nonce_base64"].as_str().unwrap())
            .unwrap();
        assert_eq!(nonce.len(), 32);
        assert_eq!(dispatcher.audit_sequence(), 2);
    }

    #[test]
    fn approved_filesystem_write_is_signed_preconditioned_and_one_shot() {
        let dir = tempdir().unwrap();
        let target = dir.path().join("approved.txt");
        fs::write(&target, b"old").unwrap();
        let signing = SigningKey::from_bytes(&[11; 32]);
        let mut dispatcher = dispatcher(dir.path(), DEFAULT_MAX_OUTPUT_BYTES);
        dispatcher
            .add_trusted_approver("operator-1", signing.verifying_key().to_bytes())
            .unwrap();
        let approved = approved_write_request(
            "req-approved-write-1",
            &target,
            b"new",
            &sha256_hex_bytes(b"old"),
            &signing,
        );

        let result = dispatcher
            .dispatch_approved_proto_at(&approved, 2_000)
            .unwrap();
        assert_eq!(result.status, "ok");
        assert_eq!(fs::read(&target).unwrap(), b"new");
        assert_eq!(dispatcher.audit_sequence(), 4);

        let replay = dispatcher.dispatch_approved_proto_at(&approved, 2_500);
        assert!(matches!(
            replay,
            Err(DispatchError::Core(
                vor_core::CoreError::ApprovalAlreadyConsumed
            ))
        ));
        assert_eq!(fs::read(&target).unwrap(), b"new");
        assert_eq!(dispatcher.audit_sequence(), 5);
    }

    #[cfg(feature = "fault-injection")]
    #[test]
    fn c21_claim_persistence_failure_prevents_effect_and_retry_consumes_once() {
        let dir = tempdir().unwrap();
        let target = dir.path().join("c21.txt");
        fs::write(&target, b"old").unwrap();
        let signing = SigningKey::from_bytes(&[21; 32]);
        let mut dispatcher = dispatcher(dir.path(), DEFAULT_MAX_OUTPUT_BYTES);
        dispatcher
            .add_trusted_approver("operator-1", signing.verifying_key().to_bytes())
            .unwrap();
        let approved = approved_write_request(
            "req-c21-claim-failure",
            &target,
            b"new",
            &sha256_hex_bytes(b"old"),
            &signing,
        );

        dispatcher.inject_next_approval_claim_failure();
        let failed = dispatcher
            .dispatch_approved_proto_at(&approved, 2_000)
            .unwrap_err();
        assert!(matches!(
            &failed,
            DispatchError::Core(vor_core::CoreError::Audit(
                vor_audit::AuditError::FaultInjected("approval claim")
            ))
        ));
        assert_eq!(
            failed.to_string(),
            "broker failed: audit failed: fault injected while persisting approval claim"
        );
        assert_eq!(dispatcher.approved_worker_invocations(), 0);
        assert_eq!(fs::read(&target).unwrap(), b"old");

        let repaired = dispatcher
            .dispatch_approved_proto_at(&approved, 2_100)
            .unwrap();
        assert_eq!(repaired.status, "ok");
        assert_eq!(dispatcher.approved_worker_invocations(), 1);
        assert_eq!(fs::read(&target).unwrap(), b"new");

        let replay = dispatcher.dispatch_approved_proto_at(&approved, 2_200);
        assert!(matches!(
            replay,
            Err(DispatchError::Core(
                vor_core::CoreError::ApprovalAlreadyConsumed
            ))
        ));
    }

    #[cfg(feature = "fault-injection")]
    #[test]
    fn c22_crash_after_claim_reopens_as_not_executed_and_never_reuses_approval() {
        let dir = tempdir().unwrap();
        let target = dir.path().join("c22.txt");
        fs::write(&target, b"old").unwrap();
        let signing = SigningKey::from_bytes(&[22; 32]);
        let approved = approved_write_request(
            "req-c22-crash-before-effect",
            &target,
            b"new",
            &sha256_hex_bytes(b"old"),
            &signing,
        );
        let request = action_request_from_proto(approved.request.as_ref().unwrap()).unwrap();

        let mut first = dispatcher(dir.path(), DEFAULT_MAX_OUTPUT_BYTES);
        first
            .add_trusted_approver("operator-1", signing.verifying_key().to_bytes())
            .unwrap();
        first.inject_crash_after_approval_claim();
        let crashed = first.dispatch_approved_proto_at(&approved, 2_000);
        assert!(matches!(crashed, Err(DispatchError::SimulatedProcessDeath)));
        assert_eq!(first.approved_worker_invocations(), 0);
        assert_eq!(fs::read(&target).unwrap(), b"old");
        drop(first);

        let mut reopened = dispatcher(dir.path(), DEFAULT_MAX_OUTPUT_BYTES);
        reopened
            .add_trusted_approver("operator-1", signing.verifying_key().to_bytes())
            .unwrap();
        assert_eq!(
            reopened
                .execution_recovery_state(&request.envelope.request_id, &request.envelope_digest,)
                .unwrap(),
            Some(vor_audit::ExecutionRecoveryState::NotExecuted),
        );
        let retry = reopened.dispatch_approved_proto_at(&approved, 2_100);
        assert!(matches!(
            retry,
            Err(DispatchError::Core(
                vor_core::CoreError::ApprovalAlreadyConsumed
            ))
        ));
        assert_eq!(reopened.approved_worker_invocations(), 0);
        assert_eq!(fs::read(&target).unwrap(), b"old");
    }

    #[cfg(feature = "fault-injection")]
    #[test]
    fn c23_post_effect_audit_failure_records_uncertainty_and_never_repeats_effect() {
        let dir = tempdir().unwrap();
        let target = dir.path().join("c23.txt");
        fs::write(&target, b"old").unwrap();
        let signing = SigningKey::from_bytes(&[23; 32]);
        let approved = approved_write_request(
            "req-c23-post-effect-failure",
            &target,
            b"new",
            &sha256_hex_bytes(b"old"),
            &signing,
        );
        let request = action_request_from_proto(approved.request.as_ref().unwrap()).unwrap();

        let mut first = dispatcher(dir.path(), DEFAULT_MAX_OUTPUT_BYTES);
        first
            .add_trusted_approver("operator-1", signing.verifying_key().to_bytes())
            .unwrap();
        first.inject_next_post_effect_audit_failure();
        let uncertain = first.dispatch_approved_proto_at(&approved, 2_000);
        assert!(matches!(
            uncertain,
            Err(DispatchError::PostEffectUncertain(_))
        ));
        assert_eq!(first.approved_worker_invocations(), 1);
        assert_eq!(fs::read(&target).unwrap(), b"new");
        drop(first);

        let mut reopened = dispatcher(dir.path(), DEFAULT_MAX_OUTPUT_BYTES);
        reopened
            .add_trusted_approver("operator-1", signing.verifying_key().to_bytes())
            .unwrap();
        assert_eq!(
            reopened
                .execution_recovery_state(&request.envelope.request_id, &request.envelope_digest,)
                .unwrap(),
            Some(vor_audit::ExecutionRecoveryState::PostEffectUncertain),
        );
        let retry = reopened.dispatch_approved_proto_at(&approved, 2_100);
        assert!(matches!(
            retry,
            Err(DispatchError::Core(
                vor_core::CoreError::ApprovalAlreadyConsumed
            ))
        ));
        assert_eq!(reopened.approved_worker_invocations(), 0);
        assert_eq!(fs::read(&target).unwrap(), b"new");
    }

    #[cfg(feature = "fault-injection")]
    #[test]
    fn c24_abandoned_audit_lock_is_reclaimed_without_weakening_live_lock_exclusion() {
        let dir = tempdir().unwrap();
        let target = dir.path().join("c24.txt");
        fs::write(&target, b"old").unwrap();
        let mut dispatcher = dispatcher(dir.path(), DEFAULT_MAX_OUTPUT_BYTES);
        dispatcher.inject_abandoned_audit_lock().unwrap();
        let prepared = write_request(
            "req-c24-abandoned-lock",
            &target,
            b"new",
            &sha256_hex_bytes(b"old"),
        );

        let result = dispatcher
            .dispatch_proto_at(&action_request_to_proto(&prepared).unwrap(), 1_000)
            .unwrap();
        assert_eq!(result.status, "approval_required");
        assert_eq!(dispatcher.audit_sequence(), 2);
        assert_eq!(fs::read(&target).unwrap(), b"old");
    }

    #[test]
    fn approved_filesystem_write_rejects_stale_target_digest() {
        let dir = tempdir().unwrap();
        let target = dir.path().join("stale.txt");
        fs::write(&target, b"old").unwrap();
        let signing = SigningKey::from_bytes(&[12; 32]);
        let mut dispatcher = dispatcher(dir.path(), DEFAULT_MAX_OUTPUT_BYTES);
        dispatcher
            .add_trusted_approver("operator-1", signing.verifying_key().to_bytes())
            .unwrap();
        let approved = approved_write_request(
            "req-approved-write-stale",
            &target,
            b"new",
            &sha256_hex_bytes(b"unexpected"),
            &signing,
        );

        let result = dispatcher.dispatch_approved_proto_at(&approved, 2_000);
        assert!(matches!(
            result,
            Err(DispatchError::Fs(vor_fs::FsError::TargetPreconditionFailed))
        ));
        assert_eq!(fs::read(&target).unwrap(), b"old");
        assert_eq!(dispatcher.audit_sequence(), 4);
    }

    #[test]
    fn approved_filesystem_write_creates_only_when_target_is_absent() {
        let dir = tempdir().unwrap();
        let target = dir.path().join("created.txt");
        let signing = SigningKey::from_bytes(&[13; 32]);
        let mut dispatcher = dispatcher(dir.path(), DEFAULT_MAX_OUTPUT_BYTES);
        dispatcher
            .add_trusted_approver("operator-1", signing.verifying_key().to_bytes())
            .unwrap();
        let approved = approved_write_request(
            "req-approved-write-create",
            &target,
            b"created",
            "absent",
            &signing,
        );

        let result = dispatcher
            .dispatch_approved_proto_at(&approved, 2_000)
            .unwrap();
        assert_eq!(result.status, "ok");
        assert_eq!(fs::read(&target).unwrap(), b"created");
        assert_eq!(dispatcher.audit_sequence(), 4);
    }

    #[test]
    fn approved_filesystem_write_rejects_payload_over_limit() {
        let dir = tempdir().unwrap();
        let target = dir.path().join("large.txt");
        fs::write(&target, b"old").unwrap();
        let signing = SigningKey::from_bytes(&[14; 32]);
        let mut dispatcher = dispatcher(dir.path(), DEFAULT_MAX_OUTPUT_BYTES);
        dispatcher
            .add_trusted_approver("operator-1", signing.verifying_key().to_bytes())
            .unwrap();
        let content = vec![b'x'; DEFAULT_MAX_REMOTE_WRITE_BYTES + 1];
        let approved = approved_write_request(
            "req-approved-write-large",
            &target,
            &content,
            &sha256_hex_bytes(b"old"),
            &signing,
        );

        let result = dispatcher.dispatch_approved_proto_at(&approved, 2_000);
        assert!(matches!(result, Err(DispatchError::WriteTooLarge(_))));
        assert_eq!(fs::read(&target).unwrap(), b"old");
        assert_eq!(dispatcher.audit_sequence(), 4);
    }
}
