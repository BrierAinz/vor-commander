// SPDX-License-Identifier: MPL-2.0

use std::error::Error;
use vor_approval::ApprovalChallenge;
use vor_protocol::ActionRequest;

type AnyError = Box<dyn Error>;

pub fn approval_summary(
    request: &ActionRequest,
    challenge: &ApprovalChallenge,
) -> Result<String, AnyError> {
    let details = match request.envelope.action.as_str() {
        "filesystem.write" => {
            let content_sha256 = required_string_parameter(request, "content_sha256")?;
            let expected_target_sha256 =
                required_string_parameter(request, "expected_target_sha256")?;
            format!(
                "Vör Commander requests permission to write a file.\n\nTarget:\n{}\n\nContent SHA-256: {}\nExpected target SHA-256: {}",
                request.envelope.target, content_sha256, expected_target_sha256,
            )
        }
        "terminal.exec" => {
            let argv = request
                .envelope
                .parameters
                .get("argv")
                .and_then(|value| value.as_array())
                .ok_or("prepared terminal request is missing argv")?;
            let argv = argv
                .iter()
                .map(|value| {
                    value
                        .as_str()
                        .ok_or("terminal argv contains a non-string value")
                })
                .collect::<Result<Vec<_>, _>>()?;
            let timeout_ms = required_u64_parameter(request, "timeout_ms")?;
            let max_output_bytes = required_u64_parameter(request, "max_output_bytes")?;
            format!(
                "Vör Commander requests permission to start a bounded terminal process.\n\nCWD:\n{}\n\nARGV (structured JSON):\n{}\n\nTimeout: {} ms\nOutput budget: {} bytes\n\nPoll/cancel do not authorize a new process.",
                request.envelope.target,
                serde_json::to_string(&argv)?,
                timeout_ms,
                max_output_bytes,
            )
        }
        "maintenance.apply" | "maintenance.recover" => {
            let plan_sha256 = required_string_parameter(request, "plan_sha256")?;
            let current_sha256 = required_string_parameter(request, "expected_current_sha256")?;
            let staged_sha256 = required_string_parameter(request, "expected_staged_sha256")?;
            let staged_executable = required_string_parameter(request, "staged_executable")?;
            let allowed_root = required_string_parameter(request, "allowed_root")?;
            let current_pid = required_u64_parameter(request, "current_pid")?;
            format!(
                "Vör Commander requests OWNER permission for self-maintenance.\n\nAction: {}\nTarget:\n{}\n\nStaged executable:\n{}\nAllowed root:\n{}\n\nCurrent PID: {}\nPlan SHA-256: {}\nCurrent SHA-256: {}\nStaged SHA-256: {}\n\nThis approval is consumed before any process stop or binary swap.",
                request.envelope.action,
                request.envelope.target,
                staged_executable,
                allowed_root,
                current_pid,
                plan_sha256,
                current_sha256,
                staged_sha256,
            )
        }
        _ => {
            return Err(
                "approver signs only filesystem.write, terminal.exec, or maintenance actions"
                    .into(),
            );
        }
    };

    Ok(format!(
        "{details}\n\nActor: {}\nDevice: {}\nOrganization: {}\nPolicy: {}\nCapability: {}\nRequest: {}\nEnvelope SHA-256: {}\nExpires (Unix ms): {}\n\nThis approval is bound to this exact request and can be consumed only once.\n\nApprove?",
        request.envelope.actor_id,
        request.envelope.device_id,
        request.envelope.organization_id,
        challenge.policy_id,
        challenge
            .required_capability
            .as_deref()
            .unwrap_or("approval"),
        challenge.request_id,
        hex::encode(challenge.envelope_digest),
        challenge.expires_at_unix_ms,
    ))
}

pub fn validate_binding(
    request: &ActionRequest,
    challenge: &ApprovalChallenge,
    now_unix_ms: u64,
) -> Result<(), AnyError> {
    if !matches!(
        request.envelope.action.as_str(),
        "filesystem.write" | "terminal.exec" | "maintenance.apply" | "maintenance.recover"
    ) {
        return Err(
            "approver signs only filesystem.write, terminal.exec, or maintenance actions".into(),
        );
    }
    if request.envelope.request_id != challenge.request_id
        || request.envelope_digest != challenge.envelope_digest
    {
        return Err("approval challenge is not bound to the prepared request".into());
    }
    if request.envelope.expires_at_unix_ms <= now_unix_ms {
        return Err("prepared request has expired".into());
    }
    if challenge.expires_at_unix_ms <= now_unix_ms
        || challenge.expires_at_unix_ms > request.envelope.expires_at_unix_ms
    {
        return Err("approval challenge expiry is invalid".into());
    }
    Ok(())
}

fn required_string_parameter<'a>(
    request: &'a ActionRequest,
    name: &str,
) -> Result<&'a str, AnyError> {
    request
        .envelope
        .parameters
        .get(name)
        .and_then(|value| value.as_str())
        .ok_or_else(|| format!("prepared request is missing {name}").into())
}

fn required_u64_parameter(request: &ActionRequest, name: &str) -> Result<u64, AnyError> {
    request
        .envelope
        .parameters
        .get(name)
        .and_then(|value| value.as_u64())
        .ok_or_else(|| format!("prepared request is missing {name}").into())
}
