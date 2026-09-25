// SPDX-License-Identifier: MPL-2.0

use base64::{Engine as _, engine::general_purpose::STANDARD};
use ed25519_dalek::SigningKey;
use prost::Message;
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use vor_approval::{ApprovalChallenge, ApproverAuthority, sign_approval};
use vor_secrets::FileSecretStore;
use vor_wire::{action_request_from_proto, approval_grant_to_proto, v1};

type AnyError = Box<dyn Error>;

#[derive(Debug, Serialize, Deserialize)]
struct TrustedApproversFile {
    approvers: Vec<TrustedApproverEntry>,
}

#[derive(Debug, Serialize, Deserialize)]
struct TrustedApproverEntry {
    approver_id: String,
    public_key_base64: String,
    authority: String,
}

#[derive(Debug, Clone, Deserialize)]
struct ChallengeJson {
    request_id: String,
    envelope_digest_base64: String,
    policy_id: String,
    required_capability: Option<String>,
    expires_at_unix_ms: u64,
    approval_nonce_base64: String,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("vor-approver error: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), AnyError> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    match args.first().map(String::as_str) {
        Some("init") => init_command(&args[1..]),
        Some("sign") => sign_command(&args[1..]),
        Some("--help" | "-h") | None => {
            print_help();
            Ok(())
        }
        Some(other) => Err(format!("unsupported command: {other}").into()),
    }
}

fn init_command(args: &[String]) -> Result<(), AnyError> {
    let mut approver_id = None::<String>;
    let mut secret_store = None::<PathBuf>;
    let mut key_name = "owner-approval-key".to_owned();
    let mut public_out = None::<PathBuf>;
    let mut index = 0;

    while index < args.len() {
        match args[index].as_str() {
            "--approver-id" => {
                approver_id = Some(next_value(args, &mut index, "--approver-id")?.into())
            }
            "--secret-store" => {
                secret_store = Some(next_value(args, &mut index, "--secret-store")?.into())
            }
            "--key-name" => key_name = next_value(args, &mut index, "--key-name")?.into(),
            "--public-out" => {
                public_out = Some(next_value(args, &mut index, "--public-out")?.into())
            }
            other => return Err(format!("unsupported init option: {other}").into()),
        }
        index += 1;
    }

    let approver_id = approver_id.ok_or("init requires --approver-id")?;
    validate_approver_id(&approver_id)?;
    let secret_store = secret_store
        .or_else(|| std::env::var_os("VOR_APPROVER_SECRET_STORE").map(PathBuf::from))
        .ok_or("init requires VOR_APPROVER_SECRET_STORE or --secret-store")?;
    let public_out = public_out.ok_or("init requires --public-out")?;
    let store = FileSecretStore::open(&secret_store)?;
    let key_exists = store.contains(&key_name)?;
    let public_exists = public_out.is_file();

    match (key_exists, public_exists) {
        (true, true) => {
            validate_existing_identity(&store, &key_name, &approver_id, &public_out)?;
            println!("approver_identity=ready");
            println!("approver_id={approver_id}");
            println!("public_config={}", public_out.display());
            Ok(())
        }
        (false, false) => {
            if let Some(parent) = public_out.parent() {
                fs::create_dir_all(parent)?;
            }
            let seed = rand::random::<[u8; 32]>();
            let signing = SigningKey::from_bytes(&seed);
            store.put(&key_name, &seed)?;

            let config = TrustedApproversFile {
                approvers: vec![TrustedApproverEntry {
                    approver_id: approver_id.clone(),
                    public_key_base64: STANDARD.encode(signing.verifying_key().to_bytes()),
                    authority: "owner".into(),
                }],
            };
            let bytes = serde_json::to_vec_pretty(&config)?;
            let mut file = OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&public_out)?;
            file.write_all(&bytes)?;
            file.write_all(b"\n")?;
            file.sync_all()?;

            println!("approver_identity=created");
            println!("approver_id={approver_id}");
            println!("public_config={}", public_out.display());
            Ok(())
        }
        _ => Err(
            "partial approver identity state detected; refusing to create or overwrite material"
                .into(),
        ),
    }
}

fn sign_command(args: &[String]) -> Result<(), AnyError> {
    let mut approver_id = None::<String>;
    let mut secret_store = None::<PathBuf>;
    let mut key_name = "owner-approval-key".to_owned();
    let mut request_file = None::<PathBuf>;
    let mut challenge_file = None::<PathBuf>;
    let mut out = None::<PathBuf>;
    let mut index = 0;

    while index < args.len() {
        match args[index].as_str() {
            "--approver-id" => {
                approver_id = Some(next_value(args, &mut index, "--approver-id")?.into())
            }
            "--secret-store" => {
                secret_store = Some(next_value(args, &mut index, "--secret-store")?.into())
            }
            "--key-name" => key_name = next_value(args, &mut index, "--key-name")?.into(),
            "--request-file" => {
                request_file = Some(next_value(args, &mut index, "--request-file")?.into())
            }
            "--challenge-file" => {
                challenge_file = Some(next_value(args, &mut index, "--challenge-file")?.into())
            }
            "--out" => out = Some(next_value(args, &mut index, "--out")?.into()),
            other => return Err(format!("unsupported sign option: {other}").into()),
        }
        index += 1;
    }

    let approver_id = approver_id.ok_or("sign requires --approver-id")?;
    validate_approver_id(&approver_id)?;
    let secret_store = secret_store
        .or_else(|| std::env::var_os("VOR_APPROVER_SECRET_STORE").map(PathBuf::from))
        .ok_or("sign requires VOR_APPROVER_SECRET_STORE or --secret-store")?;
    let request_file = request_file.ok_or("sign requires --request-file")?;
    let challenge_file = challenge_file.ok_or("sign requires --challenge-file")?;
    let out = out.ok_or("sign requires --out")?;
    if out.exists() {
        return Err("approval output already exists; refusing to overwrite".into());
    }

    let request_base64 = fs::read_to_string(&request_file)?;
    let request_bytes = STANDARD
        .decode(request_base64.trim().as_bytes())
        .map_err(|_| "request file is not valid base64")?;
    let request_proto = v1::ActionRequest::decode(request_bytes.as_slice())
        .map_err(|_| "request file is not a valid ActionRequest")?;
    let request = action_request_from_proto(&request_proto)?;

    let challenge_json: ChallengeJson = serde_json::from_slice(&fs::read(&challenge_file)?)?;
    let challenge = challenge_from_json(&challenge_json)?;
    let now = now_unix_ms()?;
    validate_binding(&request, &challenge, now)?;

    let summary = approval_summary(&request, &challenge)?;
    if !confirm_human(&summary)? {
        return Err("approval declined by user".into());
    }

    let store = FileSecretStore::open(secret_store)?;
    let secret = store.get(&key_name)?;
    let seed: [u8; 32] = secret
        .as_slice()
        .try_into()
        .map_err(|_| "stored approval key is not exactly 32 bytes")?;
    let signing = SigningKey::from_bytes(&seed);
    let signed = sign_approval(challenge, approver_id.clone(), &signing)?;
    let approval = approval_grant_to_proto(&signed)?;
    let encoded = STANDARD.encode(approval.encode_to_vec());

    if let Some(parent) = out.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut file = OpenOptions::new().create_new(true).write(true).open(&out)?;
    file.write_all(encoded.as_bytes())?;
    file.write_all(b"\n")?;
    file.sync_all()?;

    println!("approval=written");
    println!("approver_id={approver_id}");
    println!("output={}", out.display());
    Ok(())
}

fn validate_existing_identity(
    store: &FileSecretStore,
    key_name: &str,
    approver_id: &str,
    public_out: &Path,
) -> Result<(), AnyError> {
    let secret = store.get(key_name)?;
    let seed: [u8; 32] = secret
        .as_slice()
        .try_into()
        .map_err(|_| "stored approval key is not exactly 32 bytes")?;
    let signing = SigningKey::from_bytes(&seed);
    let expected = signing.verifying_key().to_bytes();

    let config: TrustedApproversFile = serde_json::from_slice(&fs::read(public_out)?)?;
    if config.approvers.len() != 1 {
        return Err("public approver config must contain exactly one owner approver".into());
    }
    let entry = &config.approvers[0];
    let decoded: [u8; 32] = STANDARD
        .decode(entry.public_key_base64.as_bytes())
        .map_err(|_| "public approver key is not valid base64")?
        .try_into()
        .map_err(|_| "public approver key must be exactly 32 bytes")?;
    let authority = ApproverAuthority::parse(&entry.authority)?;
    if entry.approver_id != approver_id
        || decoded != expected
        || authority != ApproverAuthority::Owner
    {
        return Err("public approver config does not match the DPAPI owner identity".into());
    }
    Ok(())
}

fn challenge_from_json(value: &ChallengeJson) -> Result<ApprovalChallenge, AnyError> {
    let envelope_digest: [u8; 32] = STANDARD
        .decode(value.envelope_digest_base64.as_bytes())
        .map_err(|_| "challenge envelope digest is not valid base64")?
        .try_into()
        .map_err(|_| "challenge envelope digest must be exactly 32 bytes")?;
    let approval_nonce: [u8; 32] = STANDARD
        .decode(value.approval_nonce_base64.as_bytes())
        .map_err(|_| "challenge nonce is not valid base64")?
        .try_into()
        .map_err(|_| "challenge nonce must be exactly 32 bytes")?;
    if value.request_id.trim().is_empty() || value.policy_id.trim().is_empty() {
        return Err("challenge contains an empty required field".into());
    }
    Ok(ApprovalChallenge {
        request_id: value.request_id.clone(),
        envelope_digest,
        policy_id: value.policy_id.clone(),
        required_capability: value.required_capability.clone(),
        expires_at_unix_ms: value.expires_at_unix_ms,
        approval_nonce,
    })
}

fn approval_summary(
    request: &vor_protocol::ActionRequest,
    challenge: &ApprovalChallenge,
) -> Result<String, AnyError> {
    match request.envelope.action.as_str() {
        "filesystem.write" => {
            let content_sha256 = request
                .envelope
                .parameters
                .get("content_sha256")
                .and_then(|value| value.as_str())
                .ok_or("prepared write is missing content_sha256")?;
            let expected_target_sha256 = request
                .envelope
                .parameters
                .get("expected_target_sha256")
                .and_then(|value| value.as_str())
                .ok_or("prepared write is missing expected_target_sha256")?;
            Ok(format!(
                "Vör Commander requests permission to write a file.\n\nTarget:\n{}\n\nActor: {}\nDevice: {}\nPolicy: {}\nCapability: {}\nRequest: {}\nContent SHA-256: {}\nExpected target SHA-256: {}\n\nThis approval is bound to this exact request and can be consumed only once.\n\nApprove?",
                display_truncated(&request.envelope.target, 700),
                request.envelope.actor_id,
                request.envelope.device_id,
                challenge.policy_id,
                challenge
                    .required_capability
                    .as_deref()
                    .unwrap_or("approval"),
                challenge.request_id,
                content_sha256,
                expected_target_sha256,
            ))
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
            let argv_json = serde_json::to_string(&argv)?;
            let timeout_ms = request
                .envelope
                .parameters
                .get("timeout_ms")
                .and_then(|value| value.as_u64())
                .ok_or("prepared terminal request is missing timeout_ms")?;
            let max_output_bytes = request
                .envelope
                .parameters
                .get("max_output_bytes")
                .and_then(|value| value.as_u64())
                .ok_or("prepared terminal request is missing max_output_bytes")?;
            Ok(format!(
                "Vör Commander requests permission to start a bounded terminal process.\n\nCWD:\n{}\n\nARGV (structured JSON):\n{}\n\nActor: {}\nDevice: {}\nPolicy: {}\nCapability: {}\nRequest: {}\nTimeout: {} ms\nOutput budget: {} bytes\n\nThis approval is bound to this exact request and can be consumed only once. Poll/cancel do not authorize a new process.\n\nApprove?",
                display_truncated(&request.envelope.target, 700),
                display_truncated(&argv_json, 1400),
                request.envelope.actor_id,
                request.envelope.device_id,
                challenge.policy_id,
                challenge
                    .required_capability
                    .as_deref()
                    .unwrap_or("approval"),
                challenge.request_id,
                timeout_ms,
                max_output_bytes,
            ))
        }
        "maintenance.apply" | "maintenance.recover" => {
            let plan_sha256 = required_string_parameter(request, "plan_sha256")?;
            let current_sha256 = required_string_parameter(request, "expected_current_sha256")?;
            let staged_sha256 = required_string_parameter(request, "expected_staged_sha256")?;
            let staged_executable = required_string_parameter(request, "staged_executable")?;
            let allowed_root = required_string_parameter(request, "allowed_root")?;
            let current_pid = request
                .envelope
                .parameters
                .get("current_pid")
                .and_then(|value| value.as_u64())
                .ok_or("prepared maintenance request is missing current_pid")?;
            Ok(format!(
                "Vör Commander requests OWNER permission for self-maintenance.\n\nAction: {}\nTarget:\n{}\n\nStaged executable:\n{}\nAllowed root:\n{}\n\nActor: {}\nDevice: {}\nPolicy: {}\nCapability: {}\nRequest: {}\nCurrent PID: {}\nPlan SHA-256: {}\nCurrent SHA-256: {}\nStaged SHA-256: {}\n\nThis approval is bound to the exact plan/request and is consumed before any process stop or binary swap.\n\nApprove?",
                request.envelope.action,
                display_truncated(&request.envelope.target, 700),
                display_truncated(staged_executable, 700),
                display_truncated(allowed_root, 700),
                request.envelope.actor_id,
                request.envelope.device_id,
                challenge.policy_id,
                challenge
                    .required_capability
                    .as_deref()
                    .unwrap_or("approval"),
                challenge.request_id,
                current_pid,
                plan_sha256,
                current_sha256,
                staged_sha256,
            ))
        }
        _ => Err(
            "approver signs only filesystem.write, terminal.exec, or maintenance actions".into(),
        ),
    }
}

fn required_string_parameter<'a>(
    request: &'a vor_protocol::ActionRequest,
    name: &str,
) -> Result<&'a str, AnyError> {
    request
        .envelope
        .parameters
        .get(name)
        .and_then(|value| value.as_str())
        .ok_or_else(|| format!("prepared maintenance request is missing {name}").into())
}

fn validate_binding(
    request: &vor_protocol::ActionRequest,
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

fn validate_approver_id(value: &str) -> Result<(), AnyError> {
    if value.trim().is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err("approver id is invalid".into());
    }
    Ok(())
}

fn next_value<'a>(args: &'a [String], index: &mut usize, flag: &str) -> Result<&'a str, AnyError> {
    *index += 1;
    args.get(*index)
        .map(String::as_str)
        .ok_or_else(|| format!("missing value for {flag}").into())
}

fn now_unix_ms() -> Result<u64, AnyError> {
    let elapsed = SystemTime::now().duration_since(UNIX_EPOCH)?;
    Ok(u64::try_from(elapsed.as_millis())?)
}

fn display_truncated(value: &str, max_chars: usize) -> String {
    if value.chars().count() <= max_chars {
        return value.to_owned();
    }
    let mut out = value.chars().take(max_chars).collect::<String>();
    out.push('…');
    out
}

#[cfg(windows)]
fn confirm_human(summary: &str) -> Result<bool, AnyError> {
    use windows::Win32::UI::WindowsAndMessaging::{
        IDYES, MB_ICONWARNING, MB_SETFOREGROUND, MB_TOPMOST, MB_YESNO, MessageBoxW,
    };
    use windows::core::HSTRING;
    let text = HSTRING::from(summary);
    let title = HSTRING::from("Vör Commander approval");
    let result = unsafe {
        MessageBoxW(
            None,
            &text,
            &title,
            MB_YESNO | MB_ICONWARNING | MB_SETFOREGROUND | MB_TOPMOST,
        )
    };
    Ok(result == IDYES)
}

#[cfg(not(windows))]
fn confirm_human(_summary: &str) -> Result<bool, AnyError> {
    Err("interactive owner approval is currently supported only on Windows".into())
}

fn print_help() {
    println!("Vör Commander owner approver");
    println!(
        "  vor-approver init --approver-id ID --secret-store DIR --public-out FILE [--key-name NAME]"
    );
    println!("  vor-approver sign --approver-id ID --secret-store DIR --request-file REQUEST.b64");
    println!("      --challenge-file CHALLENGE.json --out APPROVAL.b64 [--key-name NAME]");
    println!("Signing always requires an interactive Windows Yes/No confirmation.");
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;
    use std::collections::BTreeMap;
    use vor_protocol::{ActionEnvelope, ActionRequest};

    fn request(now: u64) -> ActionRequest {
        let mut parameters = BTreeMap::new();
        parameters.insert("content_sha256".into(), Value::String("11".repeat(32)));
        parameters.insert(
            "expected_target_sha256".into(),
            Value::String("22".repeat(32)),
        );
        ActionRequest::seal(ActionEnvelope {
            request_id: "req-approver-test".into(),
            organization_id: "local".into(),
            actor_id: "operator".into(),
            device_id: "device-1".into(),
            action: "filesystem.write".into(),
            target: r"D:\Proyectos\demo.txt".into(),
            parameters,
            requested_capabilities: vec![],
            expires_at_unix_ms: now + 60_000,
            nonce: vec![9; 16],
        })
        .unwrap()
    }

    fn terminal_request(now: u64) -> ActionRequest {
        let mut parameters = BTreeMap::new();
        parameters.insert(
            "argv".into(),
            Value::Array(vec![
                Value::String("cmd.exe".into()),
                Value::String("/D".into()),
                Value::String("/Q".into()),
                Value::String("/C".into()),
                Value::String("echo APPROVER_TERMINAL".into()),
            ]),
        );
        parameters.insert("timeout_ms".into(), Value::from(5_000u64));
        parameters.insert("max_output_bytes".into(), Value::from(65_536u64));
        parameters.insert("columns".into(), Value::from(80u64));
        parameters.insert("rows".into(), Value::from(25u64));
        ActionRequest::seal(ActionEnvelope {
            request_id: "req-approver-terminal".into(),
            organization_id: "local".into(),
            actor_id: "operator".into(),
            device_id: "device-1".into(),
            action: "terminal.exec".into(),
            target: r"D:\Proyectos\demo".into(),
            parameters,
            requested_capabilities: vec![],
            expires_at_unix_ms: now + 60_000,
            nonce: vec![8; 16],
        })
        .unwrap()
    }

    fn maintenance_request(now: u64, action: &str) -> ActionRequest {
        let mut parameters = BTreeMap::new();
        parameters.insert("plan_sha256".into(), Value::String("11".repeat(32)));
        parameters.insert(
            "expected_current_sha256".into(),
            Value::String("22".repeat(32)),
        );
        parameters.insert(
            "expected_staged_sha256".into(),
            Value::String("33".repeat(32)),
        );
        parameters.insert(
            "staged_executable".into(),
            Value::String(r"D:\Proyectos\vor\staged\vor-agent.exe".into()),
        );
        parameters.insert(
            "allowed_root".into(),
            Value::String(r"D:\Proyectos\vor".into()),
        );
        parameters.insert("current_pid".into(), Value::from(1234u64));
        ActionRequest::seal(ActionEnvelope {
            request_id: format!("req-{}", action.replace('.', "-")),
            organization_id: "local".into(),
            actor_id: "operator".into(),
            device_id: "device-1".into(),
            action: action.into(),
            target: r"D:\Proyectos\vor\vor-agent.exe".into(),
            parameters,
            requested_capabilities: vec![],
            expires_at_unix_ms: now + 60_000,
            nonce: vec![5; 16],
        })
        .unwrap()
    }

    #[test]
    fn exact_challenge_binding_is_accepted() {
        let now = 10_000;
        let request = request(now);
        let challenge = ApprovalChallenge {
            request_id: request.envelope.request_id.clone(),
            envelope_digest: request.envelope_digest,
            policy_id: "policy-1".into(),
            required_capability: None,
            expires_at_unix_ms: now + 30_000,
            approval_nonce: [7; 32],
        };
        validate_binding(&request, &challenge, now).unwrap();
    }

    #[test]
    fn maintenance_summary_exposes_owner_bound_plan_material() {
        let now = 10_000;
        let request = maintenance_request(now, "maintenance.apply");
        let challenge = ApprovalChallenge {
            request_id: request.envelope.request_id.clone(),
            envelope_digest: request.envelope_digest,
            policy_id: "maintenance-local".into(),
            required_capability: Some("owner".into()),
            expires_at_unix_ms: now + 30_000,
            approval_nonce: [4; 32],
        };

        validate_binding(&request, &challenge, now).unwrap();
        let summary = approval_summary(&request, &challenge).unwrap();

        assert!(summary.contains("OWNER permission for self-maintenance"));
        assert!(summary.contains("Action: maintenance.apply"));
        assert!(summary.contains("Capability: owner"));
        assert!(summary.contains("Current PID: 1234"));
        assert!(summary.contains(&"11".repeat(32)));
        assert!(summary.contains(&"22".repeat(32)));
        assert!(summary.contains(&"33".repeat(32)));
        assert!(summary.contains("consumed before any process stop or binary swap"));
    }

    #[test]
    fn maintenance_summary_rejects_missing_plan_material() {
        let now = 10_000;
        let mut request = maintenance_request(now, "maintenance.recover");
        let challenge = ApprovalChallenge {
            request_id: request.envelope.request_id.clone(),
            envelope_digest: request.envelope_digest,
            policy_id: "maintenance-local".into(),
            required_capability: Some("owner".into()),
            expires_at_unix_ms: now + 30_000,
            approval_nonce: [4; 32],
        };
        request.envelope.parameters.remove("plan_sha256");
        assert!(approval_summary(&request, &challenge).is_err());
    }

    #[test]
    fn terminal_summary_exposes_structured_command_and_budgets() {
        let now = 10_000;
        let request = terminal_request(now);
        let challenge = ApprovalChallenge {
            request_id: request.envelope.request_id.clone(),
            envelope_digest: request.envelope_digest,
            policy_id: "policy-terminal".into(),
            required_capability: Some("elevated".into()),
            expires_at_unix_ms: now + 30_000,
            approval_nonce: [6; 32],
        };

        let summary = approval_summary(&request, &challenge).unwrap();

        assert!(summary.contains("bounded terminal process"));
        assert!(summary.contains(&request.envelope.target));
        assert!(summary.contains(r#"["cmd.exe","/D","/Q","/C","echo APPROVER_TERMINAL"]"#));
        assert!(summary.contains("Capability: elevated"));
        assert!(summary.contains("Timeout: 5000 ms"));
        assert!(summary.contains("Output budget: 65536 bytes"));
        assert!(summary.contains("Poll/cancel do not authorize a new process"));
    }

    #[test]
    fn terminal_summary_rejects_unstructured_or_missing_argv() {
        let now = 10_000;
        let mut request = terminal_request(now);
        let challenge = ApprovalChallenge {
            request_id: request.envelope.request_id.clone(),
            envelope_digest: request.envelope_digest,
            policy_id: "policy-terminal".into(),
            required_capability: Some("elevated".into()),
            expires_at_unix_ms: now + 30_000,
            approval_nonce: [6; 32],
        };

        request.envelope.parameters.insert(
            "argv".into(),
            Value::String("cmd.exe /C echo unsafe".into()),
        );
        assert!(approval_summary(&request, &challenge).is_err());

        let mut request = terminal_request(now);
        request.envelope.parameters.remove("argv");
        assert!(approval_summary(&request, &challenge).is_err());
    }

    #[test]
    fn approver_refuses_non_write_non_terminal_actions() {
        let now = 10_000;
        let mut request = terminal_request(now);
        request.envelope.action = "process.terminate".into();
        let challenge = ApprovalChallenge {
            request_id: request.envelope.request_id.clone(),
            envelope_digest: request.envelope_digest,
            policy_id: "policy-terminal".into(),
            required_capability: Some("elevated".into()),
            expires_at_unix_ms: now + 30_000,
            approval_nonce: [6; 32],
        };
        assert!(approval_summary(&request, &challenge).is_err());
        assert!(validate_binding(&request, &challenge, now).is_err());
    }

    #[test]
    fn digest_mismatch_is_rejected() {
        let now = 10_000;
        let request = request(now);
        let challenge = ApprovalChallenge {
            request_id: request.envelope.request_id.clone(),
            envelope_digest: [3; 32],
            policy_id: "policy-1".into(),
            required_capability: None,
            expires_at_unix_ms: now + 30_000,
            approval_nonce: [7; 32],
        };
        assert!(validate_binding(&request, &challenge, now).is_err());
    }

    #[test]
    fn expired_challenge_is_rejected() {
        let now = 10_000;
        let request = request(now);
        let challenge = ApprovalChallenge {
            request_id: request.envelope.request_id.clone(),
            envelope_digest: request.envelope_digest,
            policy_id: "policy-1".into(),
            required_capability: None,
            expires_at_unix_ms: now,
            approval_nonce: [7; 32],
        };
        assert!(validate_binding(&request, &challenge, now).is_err());
    }
}
