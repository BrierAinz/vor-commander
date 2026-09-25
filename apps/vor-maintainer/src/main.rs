// SPDX-License-Identifier: MPL-2.0

use base64::{Engine as _, engine::general_purpose::STANDARD};
use prost::Message;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::error::Error;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use vor_approval::{ApprovalChallenge, ApprovalVerifier, ApproverAuthority};
use vor_maintenance::{
    MaintenanceTransaction, UpdatePlan, ValidatedUpdate, inspect_plan, recover_previous,
    sha256_file, validate_plan, validate_recovery_plan, verify_plan_file_sha256,
};
use vor_protocol::{ActionEnvelope, ActionRequest, PolicyDecision, PolicyDecisionKind};
use vor_wire::{action_request_from_proto, action_request_to_proto, approval_grant_from_proto, v1};

#[cfg(windows)]
use std::os::windows::process::CommandExt;
#[cfg(windows)]
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, WAIT_OBJECT_0, WAIT_TIMEOUT};
#[cfg(windows)]
use windows_sys::Win32::System::Threading::{
    CREATE_NEW_PROCESS_GROUP, CREATE_NO_WINDOW, DETACHED_PROCESS, OpenProcess,
    PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE, PROCESS_TERMINATE,
    QueryFullProcessImageNameW, TerminateProcess, WaitForSingleObject,
};

const APPLY_GRACE_MS: u64 = 750;
const PROCESS_STOP_TIMEOUT_MS: u32 = 10_000;
const MAINTENANCE_POLICY_ID: &str = "maintenance-local";
const MAINTENANCE_APPROVAL_TTL_MS: u64 = 120_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MaintenanceAction {
    Apply,
    Recover,
}

impl MaintenanceAction {
    fn parse(value: &str) -> Result<Self, Box<dyn Error>> {
        match value {
            "apply" => Ok(Self::Apply),
            "recover" => Ok(Self::Recover),
            _ => Err("maintenance action must be apply or recover".into()),
        }
    }

    fn action_name(self) -> &'static str {
        match self {
            Self::Apply => "maintenance.apply",
            Self::Recover => "maintenance.recover",
        }
    }
}

#[derive(Debug, Clone)]
struct AuthorizedPlanArgs {
    plan_path: PathBuf,
    plan_sha256: String,
    request_file: PathBuf,
    approval_file: PathBuf,
    approvers_file: PathBuf,
}

#[derive(Debug, Clone, Serialize)]
struct AuthorizationEvidence {
    request_id: String,
    approver_id: String,
    action: String,
    plan_sha256: String,
    approval_sha256: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct ChallengeJson {
    request_id: String,
    envelope_digest_base64: String,
    policy_id: String,
    required_capability: Option<String>,
    expires_at_unix_ms: u64,
    approval_nonce_base64: String,
}

#[derive(Debug, Deserialize)]
struct TrustedApproversFile {
    approvers: Vec<TrustedApproverEntry>,
}

#[derive(Debug, Deserialize)]
struct TrustedApproverEntry {
    approver_id: String,
    public_key_base64: String,
    authority: String,
}

#[derive(Debug, Serialize)]
struct StatusOutput {
    status: String,
    request_id: String,
    target: String,
    staged_sha256: String,
    current_sha256: String,
    current_pid: u32,
}

#[derive(Debug, Serialize)]
struct ApplyResult {
    status: String,
    request_id: String,
    old_pid: u32,
    new_pid: Option<u32>,
    target_sha256: Option<String>,
    message: String,
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("vor-maintainer error: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    match args.first().map(String::as_str) {
        Some("check-plan") => {
            let (path, digest) = plan_args(&args[1..])?;
            let update = load_verified_update(&path, &digest)?;
            print_status("ready", &update)?;
            Ok(())
        }
        Some("status") => {
            let (path, digest) = plan_args(&args[1..])?;
            status_plan(&path, &digest)
        }
        Some("prepare-approval") => prepare_approval(&args[1..]),
        Some("queue-update") => {
            let authorized = authorized_plan_args(&args[1..])?;
            queue_update(&authorized)
        }
        Some("apply-update") => {
            let authorized = authorized_plan_args(&args[1..])?;
            apply_update(&authorized)
        }
        Some("recover") => {
            let authorized = authorized_plan_args(&args[1..])?;
            recover_update(&authorized)
        }
        Some("--help" | "-h") | None => {
            print_help();
            Ok(())
        }
        Some(other) => Err(format!("unsupported command: {other}").into()),
    }
}

fn plan_args(args: &[String]) -> Result<(PathBuf, String), Box<dyn Error>> {
    let mut path = None::<PathBuf>;
    let mut digest = None::<String>;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--plan" => {
                index += 1;
                path = Some(args.get(index).ok_or("missing --plan value")?.into());
            }
            "--plan-sha256" => {
                index += 1;
                digest = Some(
                    args.get(index)
                        .ok_or("missing --plan-sha256 value")?
                        .clone(),
                );
            }
            other => return Err(format!("unsupported option: {other}").into()),
        }
        index += 1;
    }
    Ok((
        path.ok_or("command requires --plan")?,
        digest.ok_or("command requires --plan-sha256")?,
    ))
}

fn status_plan(path: &Path, digest: &str) -> Result<(), Box<dyn Error>> {
    verify_plan_file_sha256(path, digest)?;
    let plan = UpdatePlan::load(path)?;
    let inspection = inspect_plan(plan)?;
    println!("{}", serde_json::to_string(&inspection)?);
    Ok(())
}

fn authorized_plan_args(args: &[String]) -> Result<AuthorizedPlanArgs, Box<dyn Error>> {
    let mut plan_path = None::<PathBuf>;
    let mut plan_sha256 = None::<String>;
    let mut request_file = None::<PathBuf>;
    let mut approval_file = None::<PathBuf>;
    let mut approvers_file = None::<PathBuf>;
    let mut index = 0usize;
    while index < args.len() {
        match args[index].as_str() {
            "--plan" => {
                index += 1;
                plan_path = Some(args.get(index).ok_or("missing --plan value")?.into());
            }
            "--plan-sha256" => {
                index += 1;
                plan_sha256 = Some(
                    args.get(index)
                        .ok_or("missing --plan-sha256 value")?
                        .clone(),
                );
            }
            "--request-file" => {
                index += 1;
                request_file = Some(
                    args.get(index)
                        .ok_or("missing --request-file value")?
                        .into(),
                );
            }
            "--approval-file" => {
                index += 1;
                approval_file = Some(
                    args.get(index)
                        .ok_or("missing --approval-file value")?
                        .into(),
                );
            }
            "--approvers" => {
                index += 1;
                approvers_file = Some(args.get(index).ok_or("missing --approvers value")?.into());
            }
            other => return Err(format!("unsupported option: {other}").into()),
        }
        index += 1;
    }
    Ok(AuthorizedPlanArgs {
        plan_path: plan_path.ok_or("command requires --plan")?,
        plan_sha256: plan_sha256.ok_or("command requires --plan-sha256")?,
        request_file: request_file.ok_or("command requires --request-file")?,
        approval_file: approval_file.ok_or("command requires --approval-file")?,
        approvers_file: approvers_file.ok_or("command requires --approvers")?,
    })
}

fn prepare_approval(args: &[String]) -> Result<(), Box<dyn Error>> {
    let mut plan_path = None::<PathBuf>;
    let mut plan_sha256 = None::<String>;
    let mut action = None::<MaintenanceAction>;
    let mut actor = None::<String>;
    let mut device = None::<String>;
    let mut request_out = None::<PathBuf>;
    let mut challenge_out = None::<PathBuf>;
    let mut index = 0usize;

    while index < args.len() {
        match args[index].as_str() {
            "--plan" => {
                index += 1;
                plan_path = Some(args.get(index).ok_or("missing --plan value")?.into());
            }
            "--plan-sha256" => {
                index += 1;
                plan_sha256 = Some(
                    args.get(index)
                        .ok_or("missing --plan-sha256 value")?
                        .clone(),
                );
            }
            "--action" => {
                index += 1;
                action = Some(MaintenanceAction::parse(
                    args.get(index).ok_or("missing --action value")?,
                )?);
            }
            "--actor" => {
                index += 1;
                actor = Some(args.get(index).ok_or("missing --actor value")?.clone());
            }
            "--device" => {
                index += 1;
                device = Some(args.get(index).ok_or("missing --device value")?.clone());
            }
            "--request-out" => {
                index += 1;
                request_out = Some(args.get(index).ok_or("missing --request-out value")?.into());
            }
            "--challenge-out" => {
                index += 1;
                challenge_out = Some(
                    args.get(index)
                        .ok_or("missing --challenge-out value")?
                        .into(),
                );
            }
            other => return Err(format!("unsupported prepare-approval option: {other}").into()),
        }
        index += 1;
    }

    let plan_path = plan_path.ok_or("prepare-approval requires --plan")?;
    let plan_sha256 = plan_sha256.ok_or("prepare-approval requires --plan-sha256")?;
    let action = action.ok_or("prepare-approval requires --action")?;
    let actor = actor.ok_or("prepare-approval requires --actor")?;
    let device = device.ok_or("prepare-approval requires --device")?;
    let request_out = request_out.ok_or("prepare-approval requires --request-out")?;
    let challenge_out = challenge_out.ok_or("prepare-approval requires --challenge-out")?;
    if request_out.exists() || challenge_out.exists() {
        return Err("approval preparation output already exists".into());
    }

    verify_plan_file_sha256(&plan_path, &plan_sha256)?;
    let plan = UpdatePlan::load(&plan_path)?;
    let update = match action {
        MaintenanceAction::Apply => validate_plan(plan)?,
        MaintenanceAction::Recover => validate_recovery_plan(plan)?,
    };
    let plan_sha256 = plan_sha256.trim().to_ascii_lowercase();
    let now = now_unix_ms()?;
    let request_expiry = now
        .checked_add(MAINTENANCE_APPROVAL_TTL_MS * 2)
        .ok_or("maintenance request expiry overflow")?;
    let challenge_expiry = now
        .checked_add(MAINTENANCE_APPROVAL_TTL_MS)
        .ok_or("maintenance challenge expiry overflow")?;

    let mut parameters = BTreeMap::new();
    parameters.insert("plan_sha256".into(), Value::String(plan_sha256.clone()));
    parameters.insert(
        "expected_current_sha256".into(),
        Value::String(update.plan.expected_current_sha256.to_ascii_lowercase()),
    );
    parameters.insert(
        "expected_staged_sha256".into(),
        Value::String(update.plan.expected_staged_sha256.to_ascii_lowercase()),
    );
    parameters.insert(
        "staged_executable".into(),
        Value::String(update.staged.to_string_lossy().into_owned()),
    );
    parameters.insert(
        "allowed_root".into(),
        Value::String(update.root.to_string_lossy().into_owned()),
    );
    parameters.insert("current_pid".into(), Value::from(update.plan.current_pid));

    let request = ActionRequest::seal(ActionEnvelope {
        request_id: format!(
            "maint-{}-{}",
            match action {
                MaintenanceAction::Apply => "apply",
                MaintenanceAction::Recover => "recover",
            },
            hex::encode(rand::random::<[u8; 12]>()),
        ),
        organization_id: "local".into(),
        actor_id: actor,
        device_id: device,
        action: action.action_name().into(),
        target: update.target.to_string_lossy().into_owned(),
        parameters,
        requested_capabilities: vec![],
        expires_at_unix_ms: request_expiry,
        nonce: rand::random::<[u8; 16]>().to_vec(),
    })?;
    let decision = maintenance_decision(&request);
    let challenge = ApprovalChallenge::issue(&request, &decision, now, challenge_expiry)?;

    let request_proto = action_request_to_proto(&request)?;
    write_new(
        &request_out,
        STANDARD.encode(request_proto.encode_to_vec()).as_bytes(),
    )?;
    let challenge_json = ChallengeJson {
        request_id: challenge.request_id.clone(),
        envelope_digest_base64: STANDARD.encode(challenge.envelope_digest),
        policy_id: challenge.policy_id.clone(),
        required_capability: challenge.required_capability.clone(),
        expires_at_unix_ms: challenge.expires_at_unix_ms,
        approval_nonce_base64: STANDARD.encode(challenge.approval_nonce),
    };
    write_new(&challenge_out, &serde_json::to_vec_pretty(&challenge_json)?)?;

    println!(
        "{}",
        serde_json::json!({
            "status": "approval_required",
            "action": action.action_name(),
            "request_id": request.envelope.request_id,
            "plan_request_id": update.plan.request_id,
            "plan_sha256": plan_sha256,
            "target": update.target,
            "staged_sha256": update.plan.expected_staged_sha256.to_ascii_lowercase(),
            "current_sha256": update.plan.expected_current_sha256.to_ascii_lowercase(),
            "required_capability": "owner",
            "request_file": request_out,
            "challenge_file": challenge_out,
        })
    );
    Ok(())
}

fn maintenance_decision(request: &ActionRequest) -> PolicyDecision {
    PolicyDecision {
        request_id: request.envelope.request_id.clone(),
        kind: PolicyDecisionKind::Approval,
        policy_id: MAINTENANCE_POLICY_ID.into(),
        reason_code: "maintenance_owner_approval".into(),
        required_capability: Some("owner".into()),
        envelope_digest: request.envelope_digest,
    }
}

fn now_unix_ms() -> Result<u64, Box<dyn Error>> {
    let elapsed = SystemTime::now().duration_since(UNIX_EPOCH)?;
    Ok(u64::try_from(elapsed.as_millis())?)
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<(), Box<dyn Error>> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut file = OpenOptions::new().create_new(true).write(true).open(path)?;
    file.write_all(bytes)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    Ok(())
}

fn load_verified_update(path: &Path, digest: &str) -> Result<ValidatedUpdate, Box<dyn Error>> {
    verify_plan_file_sha256(path, digest)?;
    let plan = UpdatePlan::load(path)?;
    Ok(validate_plan(plan)?)
}

fn load_verified_recovery_update(
    path: &Path,
    digest: &str,
) -> Result<ValidatedUpdate, Box<dyn Error>> {
    verify_plan_file_sha256(path, digest)?;
    let plan = UpdatePlan::load(path)?;
    Ok(validate_recovery_plan(plan)?)
}

fn verify_authorization(
    args: &AuthorizedPlanArgs,
    action: MaintenanceAction,
    update: &ValidatedUpdate,
) -> Result<AuthorizationEvidence, Box<dyn Error>> {
    verify_plan_file_sha256(&args.plan_path, &args.plan_sha256)?;
    let normalized_plan_sha = args.plan_sha256.trim().to_ascii_lowercase();
    let request_bytes = decode_base64_file(&args.request_file, 1024 * 1024)?;
    let request_proto = v1::ActionRequest::decode(request_bytes.as_slice())?;
    let request = action_request_from_proto(&request_proto)?;

    if request.envelope.action != action.action_name() {
        return Err("maintenance approval action mismatch".into());
    }
    if !same_path(Path::new(&request.envelope.target), &update.target) {
        return Err("maintenance approval target mismatch".into());
    }
    expect_string_parameter(&request, "plan_sha256", &normalized_plan_sha)?;
    expect_string_parameter(
        &request,
        "expected_current_sha256",
        &update.plan.expected_current_sha256.to_ascii_lowercase(),
    )?;
    expect_string_parameter(
        &request,
        "expected_staged_sha256",
        &update.plan.expected_staged_sha256.to_ascii_lowercase(),
    )?;
    expect_string_parameter(
        &request,
        "staged_executable",
        &update.staged.to_string_lossy(),
    )?;
    expect_string_parameter(&request, "allowed_root", &update.root.to_string_lossy())?;
    let current_pid = request
        .envelope
        .parameters
        .get("current_pid")
        .and_then(Value::as_u64)
        .ok_or("maintenance approval is missing current_pid")?;
    if current_pid != u64::from(update.plan.current_pid) {
        return Err("maintenance approval current_pid mismatch".into());
    }

    let approval_bytes = decode_base64_file(&args.approval_file, 1024 * 1024)?;
    let approval_proto = v1::ApprovalGrant::decode(approval_bytes.as_slice())?;
    let approval = approval_grant_from_proto(&approval_proto)?;
    let decision = maintenance_decision(&request);
    let verifier = load_approval_verifier(&args.approvers_file)?;
    verifier.verify(&request, &decision, &approval, now_unix_ms()?)?;

    Ok(AuthorizationEvidence {
        request_id: request.envelope.request_id,
        approver_id: approval.approver_id,
        action: action.action_name().into(),
        plan_sha256: normalized_plan_sha,
        approval_sha256: sha256_file(&args.approval_file)?,
    })
}

fn load_approval_verifier(path: &Path) -> Result<ApprovalVerifier, Box<dyn Error>> {
    let metadata = fs::metadata(path)?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > 256 * 1024 {
        return Err("trusted approver config is invalid".into());
    }
    let config: TrustedApproversFile = serde_json::from_slice(&fs::read(path)?)?;
    if config.approvers.is_empty() || config.approvers.len() > 64 {
        return Err("trusted approver config count is invalid".into());
    }
    let mut verifier = ApprovalVerifier::new();
    for entry in config.approvers {
        let key: [u8; 32] = STANDARD
            .decode(entry.public_key_base64.as_bytes())
            .map_err(|_| "trusted approver public key is not valid base64")?
            .try_into()
            .map_err(|_| "trusted approver public key must be 32 bytes")?;
        verifier.add_approver_with_authority(
            entry.approver_id,
            key,
            ApproverAuthority::parse(&entry.authority)?,
        )?;
    }
    Ok(verifier)
}

fn decode_base64_file(path: &Path, max_bytes: u64) -> Result<Vec<u8>, Box<dyn Error>> {
    let metadata = fs::metadata(path)?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > max_bytes {
        return Err("approval artifact is invalid or oversized".into());
    }
    let text = fs::read_to_string(path)?;
    Ok(STANDARD
        .decode(text.trim().as_bytes())
        .map_err(|_| "approval artifact is not valid base64")?)
}

fn expect_string_parameter(
    request: &ActionRequest,
    name: &str,
    expected: &str,
) -> Result<(), Box<dyn Error>> {
    let actual = request
        .envelope
        .parameters
        .get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("maintenance approval is missing {name}"))?;
    if name.ends_with("_sha256") {
        if !actual.eq_ignore_ascii_case(expected) {
            return Err(format!("maintenance approval {name} mismatch").into());
        }
    } else if name.ends_with("executable") || name == "allowed_root" {
        if !same_path(Path::new(actual), Path::new(expected)) {
            return Err(format!("maintenance approval {name} mismatch").into());
        }
    } else if actual != expected {
        return Err(format!("maintenance approval {name} mismatch").into());
    }
    Ok(())
}

fn consume_authorization(
    update: &ValidatedUpdate,
    evidence: &AuthorizationEvidence,
) -> Result<PathBuf, Box<dyn Error>> {
    let directory = update
        .journal
        .parent()
        .ok_or("maintenance journal has no parent")?;
    fs::create_dir_all(directory)?;
    let marker = directory.join(format!("approval-{}.consumed.json", evidence.request_id));
    let bytes = serde_json::to_vec_pretty(evidence)?;
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&marker)
        .map_err(|error| {
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                Box::<dyn Error>::from("maintenance approval was already consumed")
            } else {
                Box::<dyn Error>::from(error)
            }
        })?;
    file.write_all(&bytes)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    Ok(marker)
}

fn append_authorization_args(command: &mut Command, args: &AuthorizedPlanArgs) {
    command
        .arg("--plan")
        .arg(&args.plan_path)
        .arg("--plan-sha256")
        .arg(&args.plan_sha256)
        .arg("--request-file")
        .arg(&args.request_file)
        .arg("--approval-file")
        .arg(&args.approval_file)
        .arg("--approvers")
        .arg(&args.approvers_file);
}

fn print_status(status: &str, update: &ValidatedUpdate) -> Result<(), Box<dyn Error>> {
    println!(
        "{}",
        serde_json::to_string(&StatusOutput {
            status: status.into(),
            request_id: update.plan.request_id.clone(),
            target: update.target.to_string_lossy().into_owned(),
            staged_sha256: update.plan.expected_staged_sha256.to_ascii_lowercase(),
            current_sha256: update.plan.expected_current_sha256.to_ascii_lowercase(),
            current_pid: update.plan.current_pid,
        })?
    );
    Ok(())
}

#[cfg(windows)]
fn queue_update(args: &AuthorizedPlanArgs) -> Result<(), Box<dyn Error>> {
    let update = load_verified_update(&args.plan_path, &args.plan_sha256)?;
    let evidence = verify_authorization(args, MaintenanceAction::Apply, &update)?;
    verify_expected_process(update.plan.current_pid, &update.target)?;

    let self_exe = std::env::current_exe()?;
    let mut command = Command::new(self_exe);
    command.arg("apply-update");
    append_authorization_args(&mut command, args);
    command
        .creation_flags(DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let child = command.spawn()?;
    println!(
        "{}",
        serde_json::json!({
            "status": "queued",
            "request_id": update.plan.request_id,
            "approval_request_id": evidence.request_id,
            "approver_id": evidence.approver_id,
            "maintainer_pid": child.id()
        })
    );
    Ok(())
}

#[cfg(not(windows))]
fn queue_update(_args: &AuthorizedPlanArgs) -> Result<(), Box<dyn Error>> {
    Err("self-maintenance queue is supported only on Windows".into())
}

#[cfg(windows)]
fn apply_update(args: &AuthorizedPlanArgs) -> Result<(), Box<dyn Error>> {
    thread::sleep(Duration::from_millis(APPLY_GRACE_MS));
    let update = load_verified_update(&args.plan_path, &args.plan_sha256)?;
    let evidence = verify_authorization(args, MaintenanceAction::Apply, &update)?;
    let plan = update.plan.clone();
    create_result_parent(&update.result_file)?;

    let current_process = open_expected_process(plan.current_pid, &update.target)?;
    consume_authorization(&update, &evidence)?;
    terminate_open_process(current_process, plan.current_pid)?;

    let mut transaction = MaintenanceTransaction::begin(plan.clone())?;
    if let Err(error) = transaction.swap() {
        let result = ApplyResult {
            status: "swap_failed".into(),
            request_id: plan.request_id.clone(),
            old_pid: plan.current_pid,
            new_pid: None,
            target_sha256: sha256_file(&update.target).ok(),
            message: error.to_string(),
        };
        write_result(&update.result_file, &result)?;
        return Err(error.into());
    }

    match spawn_target(transaction.update()) {
        Ok(mut child) => {
            let new_pid = child.id();
            if remains_alive(&mut child, plan.restart.health_wait_ms)? {
                transaction.commit()?;
                let result = ApplyResult {
                    status: "committed".into(),
                    request_id: plan.request_id.clone(),
                    old_pid: plan.current_pid,
                    new_pid: Some(new_pid),
                    target_sha256: Some(sha256_file(&update.target)?),
                    message: "new agent remained alive through the bounded health window".into(),
                };
                write_result(&update.result_file, &result)?;
                return Ok(());
            }

            let _ = child.kill();
            let _ = child.wait();
            rollback_and_restart(
                &mut transaction,
                &plan,
                Some(new_pid),
                "new agent exited during health window",
            )
        }
        Err(error) => rollback_and_restart(
            &mut transaction,
            &plan,
            None,
            &format!("failed to launch new agent: {error}"),
        ),
    }
}

#[cfg(not(windows))]
fn apply_update(_args: &AuthorizedPlanArgs) -> Result<(), Box<dyn Error>> {
    Err("self-maintenance apply is supported only on Windows".into())
}

#[cfg(windows)]
fn rollback_and_restart(
    transaction: &mut MaintenanceTransaction,
    plan: &UpdatePlan,
    failed_pid: Option<u32>,
    reason: &str,
) -> Result<(), Box<dyn Error>> {
    transaction.rollback()?;
    let update = transaction.update().clone();
    match spawn_target(&update) {
        Ok(mut old_child) => {
            let old_new_pid = old_child.id();
            let alive = remains_alive(&mut old_child, plan.restart.health_wait_ms)?;
            let result = ApplyResult {
                status: if alive {
                    "rolled_back".into()
                } else {
                    "rollback_restart_failed".into()
                },
                request_id: plan.request_id.clone(),
                old_pid: plan.current_pid,
                new_pid: Some(old_new_pid),
                target_sha256: sha256_file(&update.target).ok(),
                message: format!(
                    "{reason}; failed_new_pid={failed_pid:?}; previous binary restored"
                ),
            };
            write_result(&update.result_file, &result)?;
            if alive {
                Err("new agent failed health; previous agent was restored".into())
            } else {
                Err("new agent failed and restored agent also failed health".into())
            }
        }
        Err(error) => {
            let result = ApplyResult {
                status: "rollback_restart_failed".into(),
                request_id: plan.request_id.clone(),
                old_pid: plan.current_pid,
                new_pid: None,
                target_sha256: sha256_file(&update.target).ok(),
                message: format!("{reason}; rollback launch failed: {error}"),
            };
            write_result(&update.result_file, &result)?;
            Err(format!("rollback restored binary but could not relaunch it: {error}").into())
        }
    }
}

#[cfg(windows)]
fn recover_update(args: &AuthorizedPlanArgs) -> Result<(), Box<dyn Error>> {
    let validated = load_verified_recovery_update(&args.plan_path, &args.plan_sha256)?;
    let evidence = verify_authorization(args, MaintenanceAction::Recover, &validated)?;
    consume_authorization(&validated, &evidence)?;
    let plan = validated.plan.clone();
    let update = recover_previous(plan.clone())?;
    let mut child = spawn_target(&update)?;
    let alive = remains_alive(&mut child, plan.restart.health_wait_ms)?;
    let result = ApplyResult {
        status: if alive {
            "recovered".into()
        } else {
            "recovery_restart_failed".into()
        },
        request_id: plan.request_id,
        old_pid: plan.current_pid,
        new_pid: Some(child.id()),
        target_sha256: sha256_file(&update.target).ok(),
        message: "conservative recovery restored the previous binary".into(),
    };
    write_result(&update.result_file, &result)?;
    if alive {
        Ok(())
    } else {
        Err("recovered binary did not survive the health window".into())
    }
}

#[cfg(not(windows))]
fn recover_update(_args: &AuthorizedPlanArgs) -> Result<(), Box<dyn Error>> {
    Err("self-maintenance recovery is supported only on Windows".into())
}

#[cfg(windows)]
fn spawn_target(update: &ValidatedUpdate) -> Result<std::process::Child, Box<dyn Error>> {
    create_log_parent(&update.stdout_log)?;
    create_log_parent(&update.stderr_log)?;
    let stdout = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&update.stdout_log)?;
    let stderr = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&update.stderr_log)?;
    let mut command = Command::new(&update.target);
    command
        .args(&update.plan.restart.args)
        .current_dir(&update.working_directory)
        .envs(&update.plan.restart.environment)
        .creation_flags(CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW)
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr));
    Ok(command.spawn()?)
}

#[cfg(windows)]
fn remains_alive(child: &mut std::process::Child, wait_ms: u64) -> Result<bool, Box<dyn Error>> {
    let deadline = Instant::now() + Duration::from_millis(wait_ms);
    loop {
        if child.try_wait()?.is_some() {
            return Ok(false);
        }
        if Instant::now() >= deadline {
            return Ok(true);
        }
        thread::sleep(Duration::from_millis(100));
    }
}

#[cfg(windows)]
struct ProcessHandle(HANDLE);

#[cfg(windows)]
impl Drop for ProcessHandle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
}

#[cfg(windows)]
fn open_expected_process(pid: u32, target: &Path) -> Result<ProcessHandle, Box<dyn Error>> {
    let handle = unsafe {
        OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE | PROCESS_SYNCHRONIZE,
            0,
            pid,
        )
    };
    if handle.is_null() {
        return Err(std::io::Error::last_os_error().into());
    }
    let handle = ProcessHandle(handle);
    let mut buffer = vec![0u16; 32 * 1024];
    let mut len = u32::try_from(buffer.len())?;
    let ok = unsafe { QueryFullProcessImageNameW(handle.0, 0, buffer.as_mut_ptr(), &mut len) };
    if ok == 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    buffer.truncate(usize::try_from(len)?);
    let actual = PathBuf::from(String::from_utf16(&buffer)?);
    let actual = fs::canonicalize(actual)?;
    let target = fs::canonicalize(target)?;
    if !same_path(&actual, &target) {
        return Err(format!(
            "PID {pid} belongs to {}, not {}",
            actual.display(),
            target.display()
        )
        .into());
    }
    Ok(handle)
}

#[cfg(windows)]
fn verify_expected_process(pid: u32, target: &Path) -> Result<(), Box<dyn Error>> {
    let _ = open_expected_process(pid, target)?;
    Ok(())
}

#[cfg(windows)]
fn terminate_open_process(handle: ProcessHandle, pid: u32) -> Result<(), Box<dyn Error>> {
    let status = unsafe { WaitForSingleObject(handle.0, 0) };
    if status == WAIT_OBJECT_0 {
        return Err(format!("expected agent PID {pid} already exited").into());
    }
    if status != WAIT_TIMEOUT {
        return Err(std::io::Error::last_os_error().into());
    }
    if unsafe { TerminateProcess(handle.0, 0xC000_013A) } == 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let status = unsafe { WaitForSingleObject(handle.0, PROCESS_STOP_TIMEOUT_MS) };
    if status != WAIT_OBJECT_0 {
        return Err(format!("agent PID {pid} did not stop within timeout").into());
    }
    Ok(())
}

#[cfg(windows)]
fn same_path(left: &Path, right: &Path) -> bool {
    left.to_string_lossy()
        .eq_ignore_ascii_case(&right.to_string_lossy())
}

#[cfg(not(windows))]
fn same_path(left: &Path, right: &Path) -> bool {
    left == right
}

fn create_result_parent(path: &Path) -> Result<(), Box<dyn Error>> {
    let parent = path.parent().ok_or("result file has no parent")?;
    fs::create_dir_all(parent)?;
    Ok(())
}

fn create_log_parent(path: &Path) -> Result<(), Box<dyn Error>> {
    let parent = path.parent().ok_or("log file has no parent")?;
    fs::create_dir_all(parent)?;
    Ok(())
}

fn write_result(path: &Path, result: &ApplyResult) -> Result<(), Box<dyn Error>> {
    create_result_parent(path)?;
    let parent = path.parent().ok_or("result path has no parent")?;
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or("result path has invalid file name")?;
    let temp = parent.join(format!(".{name}.tmp"));
    if temp.exists() {
        fs::remove_file(&temp)?;
    }
    let bytes = serde_json::to_vec_pretty(result)?;
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&temp)?;
    file.write_all(&bytes)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    if path.exists() {
        fs::remove_file(path)?;
    }
    fs::rename(temp, path)?;
    Ok(())
}

fn print_help() {
    println!("Vör Commander self-maintenance helper");
    println!("  vor-maintainer check-plan --plan FILE --plan-sha256 SHA256");
    println!("  vor-maintainer status --plan FILE --plan-sha256 SHA256");
    println!(
        "  vor-maintainer prepare-approval --plan FILE --plan-sha256 SHA256 --action apply|recover"
    );
    println!(
        "      --actor ID --device ID --request-out REQUEST.b64 --challenge-out CHALLENGE.json"
    );
    println!(
        "  vor-maintainer queue-update --plan FILE --plan-sha256 SHA256 --request-file REQUEST.b64"
    );
    println!("      --approval-file APPROVAL.b64 --approvers TRUSTED.json");
    println!(
        "  vor-maintainer apply-update --plan FILE --plan-sha256 SHA256 --request-file REQUEST.b64"
    );
    println!("      --approval-file APPROVAL.b64 --approvers TRUSTED.json");
    println!(
        "  vor-maintainer recover --plan FILE --plan-sha256 SHA256 --request-file REQUEST.b64"
    );
    println!("      --approval-file APPROVAL.b64 --approvers TRUSTED.json");
    println!(
        "apply/recover require a valid OWNER approval bound to the exact plan and are one-use."
    );
    println!("queue-update verifies the exact plan, approval and PID/image binding, then launches");
    println!("a detached updater so the caller can finish before the approved restart.");
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use sha2::{Digest, Sha256};
    use vor_approval::sign_approval;
    use vor_maintenance::RestartSpec;
    use vor_wire::approval_grant_to_proto;

    #[test]
    fn apply_result_serialization_is_non_secret() {
        let result = ApplyResult {
            status: "committed".into(),
            request_id: "req-1".into(),
            old_pid: 10,
            new_pid: Some(11),
            target_sha256: Some("aa".repeat(32)),
            message: "ok".into(),
        };
        let text = serde_json::to_string(&result).unwrap();
        assert!(text.contains("committed"));
        assert!(text.contains("req-1"));
    }

    #[test]
    fn plan_digest_helper_matches_sha256() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("plan.json");
        fs::write(&path, b"plan").unwrap();
        let expected = hex::encode(Sha256::digest(b"plan"));
        assert_eq!(sha256_file(&path).unwrap(), expected);
    }

    fn test_plan(root: &Path, target: &Path, staged: &Path) -> UpdatePlan {
        UpdatePlan {
            schema: vor_maintenance::UPDATE_PLAN_SCHEMA,
            request_id: "m3-test-plan".into(),
            allowed_root: root.to_path_buf(),
            target_executable: target.to_path_buf(),
            staged_executable: staged.to_path_buf(),
            expected_current_sha256: sha256_file(target).unwrap(),
            expected_staged_sha256: sha256_file(staged).unwrap(),
            journal_directory: root.join("state").join("maintenance").join("journal"),
            result_file: root.join("state").join("maintenance").join("result.json"),
            current_pid: 123,
            restart: RestartSpec {
                args: vec!["private-run".into(), "--device".into(), "device-1".into()],
                environment: BTreeMap::new(),
                working_directory: root.to_path_buf(),
                stdout_log: root.join("state").join("maintenance").join("agent.out.log"),
                stderr_log: root.join("state").join("maintenance").join("agent.err.log"),
                health_wait_ms: 1_000,
            },
        }
    }

    fn challenge_from_file(path: &Path) -> ApprovalChallenge {
        let value: ChallengeJson = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
        ApprovalChallenge {
            request_id: value.request_id,
            envelope_digest: STANDARD
                .decode(value.envelope_digest_base64.as_bytes())
                .unwrap()
                .try_into()
                .unwrap(),
            policy_id: value.policy_id,
            required_capability: value.required_capability,
            expires_at_unix_ms: value.expires_at_unix_ms,
            approval_nonce: STANDARD
                .decode(value.approval_nonce_base64.as_bytes())
                .unwrap()
                .try_into()
                .unwrap(),
        }
    }

    fn authorization_fixture(
        authority: &str,
    ) -> (tempfile::TempDir, AuthorizedPlanArgs, ValidatedUpdate) {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let target = root.join("vor-agent.exe");
        let staged = root.join("staged.exe");
        fs::write(&target, b"old-agent").unwrap();
        fs::write(&staged, b"new-agent").unwrap();

        let plan = test_plan(root, &target, &staged);
        let plan_path = root.join("plan.json");
        fs::write(&plan_path, serde_json::to_vec_pretty(&plan).unwrap()).unwrap();
        let plan_sha256 = sha256_file(&plan_path).unwrap();

        let request_file = root.join("request.b64");
        let challenge_file = root.join("challenge.json");
        let prepare_args = vec![
            "--plan".into(),
            plan_path.to_string_lossy().into_owned(),
            "--plan-sha256".into(),
            plan_sha256.clone(),
            "--action".into(),
            "apply".into(),
            "--actor".into(),
            "owner-test".into(),
            "--device".into(),
            "device-test".into(),
            "--request-out".into(),
            request_file.to_string_lossy().into_owned(),
            "--challenge-out".into(),
            challenge_file.to_string_lossy().into_owned(),
        ];
        prepare_approval(&prepare_args).unwrap();

        let signing = SigningKey::from_bytes(&[7; 32]);
        let challenge = challenge_from_file(&challenge_file);
        let approval = sign_approval(challenge, "owner-test", &signing).unwrap();
        let approval_proto = approval_grant_to_proto(&approval).unwrap();
        let approval_file = root.join("approval.b64");
        fs::write(
            &approval_file,
            STANDARD.encode(approval_proto.encode_to_vec()),
        )
        .unwrap();

        let approvers_file = root.join("approvers.json");
        fs::write(
            &approvers_file,
            serde_json::to_vec_pretty(&serde_json::json!({
                "approvers": [{
                    "approver_id": "owner-test",
                    "public_key_base64": STANDARD.encode(signing.verifying_key().to_bytes()),
                    "authority": authority
                }]
            }))
            .unwrap(),
        )
        .unwrap();

        let args = AuthorizedPlanArgs {
            plan_path: plan_path.clone(),
            plan_sha256: plan_sha256.clone(),
            request_file,
            approval_file,
            approvers_file,
        };
        let update = load_verified_update(&plan_path, &plan_sha256).unwrap();
        (dir, args, update)
    }

    #[test]
    fn owner_approval_binds_to_exact_plan_and_is_one_use() {
        let (_dir, args, update) = authorization_fixture("owner");

        let evidence = verify_authorization(&args, MaintenanceAction::Apply, &update).unwrap();
        assert_eq!(evidence.approver_id, "owner-test");
        assert_eq!(evidence.action, "maintenance.apply");
        assert_eq!(evidence.plan_sha256, args.plan_sha256.to_ascii_lowercase());

        let marker = consume_authorization(&update, &evidence).unwrap();
        assert!(marker.is_file());
        assert!(consume_authorization(&update, &evidence).is_err());
    }

    #[test]
    fn non_owner_approval_cannot_authorize_maintenance() {
        let (_dir, args, update) = authorization_fixture("approve");
        assert!(verify_authorization(&args, MaintenanceAction::Apply, &update).is_err());
    }

    #[test]
    fn plan_mutation_after_approval_is_rejected() {
        let (_dir, args, update) = authorization_fixture("owner");
        let mut bytes = fs::read(&args.plan_path).unwrap();
        bytes.extend_from_slice(b"\n ");
        fs::write(&args.plan_path, bytes).unwrap();

        assert!(verify_authorization(&args, MaintenanceAction::Apply, &update).is_err());
    }

    #[test]
    fn approval_cannot_be_reused_for_different_maintenance_action() {
        let (_dir, args, update) = authorization_fixture("owner");
        assert!(verify_authorization(&args, MaintenanceAction::Recover, &update).is_err());
    }

    #[cfg(windows)]
    fn system_cmd() -> PathBuf {
        PathBuf::from(std::env::var_os("SystemRoot").expect("SystemRoot")).join("System32/cmd.exe")
    }

    #[cfg(windows)]
    fn spawn_cmd_copy(path: &Path, working_directory: &Path) -> std::process::Child {
        fs::copy(system_cmd(), path).unwrap();
        Command::new(path)
            .args(["/D", "/Q", "/C", "ping.exe 127.0.0.1 -n 5 >NUL"])
            .current_dir(working_directory)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap()
    }

    #[cfg(windows)]
    #[test]
    fn process_identity_rejects_stale_target_path() {
        let dir = tempfile::tempdir().unwrap();
        let expected = dir.path().join("expected-agent.exe");
        let actual = dir.path().join("actual-agent.exe");
        fs::copy(system_cmd(), &expected).unwrap();
        let mut child = spawn_cmd_copy(&actual, dir.path());
        let result = verify_expected_process(child.id(), &expected);
        let _ = child.kill();
        let _ = child.wait();
        assert!(result.is_err());
    }

    #[cfg(windows)]
    #[test]
    fn termination_rejects_already_exited_verified_process() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("short-agent.exe");
        fs::copy(system_cmd(), &target).unwrap();
        let mut child = Command::new(&target)
            .args(["/D", "/Q", "/C", "exit 0"])
            .current_dir(dir.path())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let handle = open_expected_process(child.id(), &target).unwrap();
        let _ = child.wait();
        assert!(terminate_open_process(handle, child.id()).is_err());
    }
}
