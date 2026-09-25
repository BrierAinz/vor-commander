// SPDX-License-Identifier: MPL-2.0

use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::Deserialize;
use serde_json::json;
use std::env;
use std::error::Error;
use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio_util::sync::CancellationToken;
use vor_agent::AgentServer;
use vor_dispatch::{
    ApproverAuthority, DEFAULT_MAX_OUTPUT_BYTES, DispatchConfig, ReadOnlyDispatcher,
};
use vor_identity::{
    CertificateAuthority, certificate_der_to_pem, create_device_enrollment, private_key_der_to_pem,
};
use vor_private_grpc::{PrivateDeviceClientConfig, run_device_dispatch_until_cancelled};
use vor_remote::{RemoteClient, RemoteConfig, SecretToken};
use vor_secrets::FileSecretStore;
use zeroize::Zeroizing;

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("vor-agent error: {error}");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("relay-probe") => relay_command(&args[1..], true).await,
        Some("relay-run") => relay_command(&args[1..], false).await,
        Some("relay-dispatch-run") => relay_dispatch_command(&args[1..]).await,
        Some("private-run") => private_command(&args[1..]).await,
        Some("local-enroll") => local_enroll_command(&args[1..]),
        Some("listen") => listen_command(&args[1..]),
        Some("--help" | "-h") => print_help(),
        _ => listen_command(&args),
    }
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

fn load_trusted_approvers(
    dispatcher: &mut ReadOnlyDispatcher,
    path: &Path,
) -> Result<usize, Box<dyn Error>> {
    const MAX_APPROVER_FILE_BYTES: u64 = 64 * 1024;
    const MAX_APPROVERS: usize = 32;

    let metadata = fs::metadata(path)?;
    if !metadata.is_file() || metadata.len() > MAX_APPROVER_FILE_BYTES {
        return Err("trusted approver file is missing, not a file, or exceeds 64 KiB".into());
    }
    let bytes = fs::read(path)?;
    let config: TrustedApproversFile = serde_json::from_slice(&bytes)?;
    if config.approvers.is_empty() || config.approvers.len() > MAX_APPROVERS {
        return Err("trusted approver file must contain between 1 and 32 approvers".into());
    }
    let mut loaded = 0usize;
    for entry in config.approvers {
        let decoded = STANDARD
            .decode(entry.public_key_base64.as_bytes())
            .map_err(|_| "trusted approver public key is not valid base64")?;
        let public_key: [u8; 32] = decoded
            .try_into()
            .map_err(|_| "trusted approver public key must be exactly 32 bytes")?;
        let authority = ApproverAuthority::parse(&entry.authority)?;
        dispatcher.add_trusted_approver_with_authority(entry.approver_id, public_key, authority)?;
        loaded = loaded.saturating_add(1);
    }
    Ok(loaded)
}

fn listen_command(args: &[String]) -> Result<(), Box<dyn Error>> {
    let mut bind: SocketAddr = "127.0.0.1:8740".parse()?;
    let mut once = false;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--bind" => bind = next_value(args, &mut index, "--bind")?.parse()?,
            "--once" => once = true,
            other => return Err(format!("unsupported listen option: {other}").into()),
        }
        index += 1;
    }

    let server = AgentServer::bind(bind)?;
    eprintln!("vor-agent listening on {}", server.local_addr()?);
    if once {
        server.serve_once()?;
    } else {
        server.serve_forever()?;
    }
    Ok(())
}

async fn relay_command(args: &[String], probe_only: bool) -> Result<(), Box<dyn Error>> {
    let mut relay: Option<String> = None;
    let mut device: Option<String> = None;
    let mut heartbeat_seconds = 15u64;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--relay" => relay = Some(next_value(args, &mut index, "--relay")?.to_owned()),
            "--device" => device = Some(next_value(args, &mut index, "--device")?.to_owned()),
            "--heartbeat-seconds" => {
                heartbeat_seconds = next_value(args, &mut index, "--heartbeat-seconds")?.parse()?
            }
            other => return Err(format!("unsupported relay option: {other}").into()),
        }
        index += 1;
    }

    let relay = relay.ok_or("relay command requires --relay")?;
    let device = device.ok_or("relay command requires --device")?;
    let raw_token = env::var("VOR_RELAY_TOKEN")
        .map_err(|_| "VOR_RELAY_TOKEN is required for relay commands")?;
    let token = SecretToken::new(raw_token)?;
    let mut config = RemoteConfig::new(&relay, device, token, env!("CARGO_PKG_VERSION"))?;
    config.heartbeat_interval = Duration::from_secs(heartbeat_seconds);
    let client = RemoteClient::new(config);

    if probe_only {
        client.probe_once().await?;
        println!("relay_probe=ok");
        return Ok(());
    }
    let cancellation = CancellationToken::new();
    let shutdown = cancellation.clone();
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            shutdown.cancel();
        }
    });
    client.run_until_cancelled(cancellation).await?;
    Ok(())
}

async fn relay_dispatch_command(args: &[String]) -> Result<(), Box<dyn Error>> {
    let mut relay: Option<String> = None;
    let mut device: Option<String> = None;
    let mut policy_path: Option<PathBuf> = None;
    let mut roots = Vec::<PathBuf>::new();
    let mut git_path: Option<PathBuf> = None;
    let mut state_path: Option<PathBuf> = None;
    let mut approvers_path: Option<PathBuf> = None;
    let mut secret_store: Option<PathBuf> = None;
    let mut token_name = "relay-token".to_owned();
    let mut heartbeat_seconds = 15u64;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--relay" => relay = Some(next_value(args, &mut index, "--relay")?.into()),
            "--device" => device = Some(next_value(args, &mut index, "--device")?.into()),
            "--policy" => policy_path = Some(next_value(args, &mut index, "--policy")?.into()),
            "--root" => roots.push(next_value(args, &mut index, "--root")?.into()),
            "--git" => git_path = Some(next_value(args, &mut index, "--git")?.into()),
            "--state" => state_path = Some(next_value(args, &mut index, "--state")?.into()),
            "--approvers" => {
                approvers_path = Some(next_value(args, &mut index, "--approvers")?.into())
            }
            "--secret-store" => {
                secret_store = Some(next_value(args, &mut index, "--secret-store")?.into())
            }
            "--token-name" => token_name = next_value(args, &mut index, "--token-name")?.into(),
            "--heartbeat-seconds" => {
                heartbeat_seconds = next_value(args, &mut index, "--heartbeat-seconds")?.parse()?
            }
            other => return Err(format!("unsupported relay-dispatch-run option: {other}").into()),
        }
        index += 1;
    }

    let relay = relay.ok_or("relay-dispatch-run requires --relay")?;
    let device = device.ok_or("relay-dispatch-run requires --device")?;
    let policy_path = policy_path.ok_or("relay-dispatch-run requires --policy")?;
    if roots.is_empty() {
        return Err("relay-dispatch-run requires at least one --root".into());
    }
    if heartbeat_seconds == 0 {
        return Err("--heartbeat-seconds must be positive".into());
    }
    let state_path =
        state_path.unwrap_or_else(|| PathBuf::from("state").join("relay-agent").join(&device));
    fs::create_dir_all(&state_path)?;
    let git_path = match git_path {
        Some(path) => path,
        None => find_git_executable()?,
    };
    let mut dispatcher = ReadOnlyDispatcher::open(DispatchConfig {
        device_id: device.clone(),
        policy_path,
        audit_sqlite: state_path.join("audit.db"),
        audit_jsonl: state_path.join("audit.jsonl"),
        journal_dir: state_path.join("journal"),
        allowed_roots: roots,
        git_executable: git_path,
        max_output_bytes: DEFAULT_MAX_OUTPUT_BYTES,
        browser: None,
    })?;
    if let Some(path) = approvers_path.as_deref() {
        let loaded = load_trusted_approvers(&mut dispatcher, path)?;
        eprintln!("trusted_approvers={loaded}");
    }
    let dispatcher = Arc::new(Mutex::new(dispatcher));
    let raw_token = if let Some(root) = secret_store {
        let store = FileSecretStore::open(root)?;
        String::from_utf8(store.get(&token_name)?.into_vec())?
    } else {
        env::var("VOR_RELAY_TOKEN")
            .map_err(|_| "VOR_RELAY_TOKEN or --secret-store is required for relay-dispatch-run")?
    };
    let token = SecretToken::new(raw_token)?;
    let mut config = RemoteConfig::new(&relay, device, token, env!("CARGO_PKG_VERSION"))?;
    config.heartbeat_interval = Duration::from_secs(heartbeat_seconds);
    let cancellation = CancellationToken::new();
    let shutdown = cancellation.clone();
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            shutdown.cancel();
        }
    });
    RemoteClient::new(config)
        .run_dispatch_until_cancelled(dispatcher, cancellation)
        .await?;
    Ok(())
}

fn local_enroll_command(args: &[String]) -> Result<(), Box<dyn Error>> {
    let mut device: Option<String> = None;
    let mut out: Option<PathBuf> = None;
    let mut secret_store: Option<PathBuf> = None;
    let mut key_name = "device-key".to_owned();
    let mut server_name = "localhost".to_owned();
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--device" => device = Some(next_value(args, &mut index, "--device")?.into()),
            "--out" => out = Some(next_value(args, &mut index, "--out")?.into()),
            "--secret-store" => {
                secret_store = Some(next_value(args, &mut index, "--secret-store")?.into())
            }
            "--key-name" => key_name = next_value(args, &mut index, "--key-name")?.into(),
            "--server-name" => server_name = next_value(args, &mut index, "--server-name")?.into(),
            other => return Err(format!("unsupported local-enroll option: {other}").into()),
        }
        index += 1;
    }
    let device = device.ok_or("local-enroll requires --device")?;
    let out = out.ok_or("local-enroll requires --out")?;
    let secret_store = secret_store.ok_or("local-enroll requires --secret-store")?;
    fs::create_dir_all(&out)?;
    let store = FileSecretStore::open(&secret_store)?;
    let ca_path = out.join("ca.pem");
    let server_cert_path = out.join("server.pem");
    let server_key_path = out.join("server-key.pem");
    let device_cert_path = out.join("device.pem");
    let registry_path = out.join("device-registry.json");
    let files = [
        &ca_path,
        &server_cert_path,
        &server_key_path,
        &device_cert_path,
        &registry_path,
    ];
    let key_exists = store.contains(&key_name)?;
    let file_count = files.iter().filter(|path| path.is_file()).count();
    if key_exists && file_count == files.len() {
        println!("local_identity=ready");
        println!("device_id={device}");
        return Ok(());
    }
    if key_exists || file_count != 0 {
        return Err("partial local identity state detected; refusing to overwrite it".into());
    }
    let ca = CertificateAuthority::new("Vor Local Pilot CA")?;
    let enrollment = create_device_enrollment(&store, &key_name, &device)?;
    let device_cert = ca.sign_device_csr(&device, &enrollment.csr_der)?;
    let server = ca.issue_server_certificate(&server_name)?;
    let (server_cert, server_key) = server.into_parts();
    fs::write(&ca_path, certificate_der_to_pem(&ca.certificate_der()))?;
    fs::write(&device_cert_path, certificate_der_to_pem(&device_cert))?;
    fs::write(&server_cert_path, certificate_der_to_pem(&server_cert))?;
    fs::write(&server_key_path, private_key_der_to_pem(&server_key))?;
    let registry = json!({"devices":[{"device_id":device,"certificate_der_base64":STANDARD.encode(&device_cert)}]});
    fs::write(&registry_path, serde_json::to_vec_pretty(&registry)?)?;
    println!("local_identity=created");
    println!("device_id={device}");
    println!("identity_dir={}", out.display());
    Ok(())
}

async fn private_command(args: &[String]) -> Result<(), Box<dyn Error>> {
    let mut endpoint: Option<String> = None;
    let mut server_name: Option<String> = None;
    let mut device: Option<String> = None;
    let mut ca_path: Option<PathBuf> = None;
    let mut cert_path: Option<PathBuf> = None;
    let mut secret_store: Option<PathBuf> = None;
    let mut key_name = "device-key".to_owned();
    let mut policy_path: Option<PathBuf> = None;
    let mut roots = Vec::<PathBuf>::new();
    let mut git_path: Option<PathBuf> = None;
    let mut state_path: Option<PathBuf> = None;
    let mut approvers_path: Option<PathBuf> = None;
    let mut heartbeat_seconds = 15u64;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--endpoint" => endpoint = Some(next_value(args, &mut index, "--endpoint")?.into()),
            "--server-name" => {
                server_name = Some(next_value(args, &mut index, "--server-name")?.into())
            }
            "--device" => device = Some(next_value(args, &mut index, "--device")?.into()),
            "--ca" => ca_path = Some(next_value(args, &mut index, "--ca")?.into()),
            "--cert" => cert_path = Some(next_value(args, &mut index, "--cert")?.into()),
            "--secret-store" => {
                secret_store = Some(next_value(args, &mut index, "--secret-store")?.into())
            }
            "--key-name" => key_name = next_value(args, &mut index, "--key-name")?.into(),
            "--policy" => policy_path = Some(next_value(args, &mut index, "--policy")?.into()),
            "--root" => roots.push(next_value(args, &mut index, "--root")?.into()),
            "--git" => git_path = Some(next_value(args, &mut index, "--git")?.into()),
            "--state" => state_path = Some(next_value(args, &mut index, "--state")?.into()),
            "--approvers" => {
                approvers_path = Some(next_value(args, &mut index, "--approvers")?.into())
            }
            "--heartbeat-seconds" => {
                heartbeat_seconds = next_value(args, &mut index, "--heartbeat-seconds")?.parse()?
            }
            other => return Err(format!("unsupported private-run option: {other}").into()),
        }
        index += 1;
    }

    let endpoint = endpoint.ok_or("private-run requires --endpoint")?;
    let server_name = server_name.ok_or("private-run requires --server-name")?;
    let device = device.ok_or("private-run requires --device")?;
    let ca_path = ca_path.ok_or("private-run requires --ca")?;
    let cert_path = cert_path.ok_or("private-run requires --cert")?;
    let secret_store = match secret_store {
        Some(path) => path,
        None => env::var_os("VOR_DEVICE_SECRET_STORE")
            .map(PathBuf::from)
            .ok_or("private-run requires --secret-store or VOR_DEVICE_SECRET_STORE")?,
    };
    let policy_path = policy_path.ok_or("private-run requires --policy")?;
    if roots.is_empty() {
        return Err("private-run requires at least one --root".into());
    }
    if heartbeat_seconds == 0 {
        return Err("--heartbeat-seconds must be positive".into());
    }
    let state_path =
        state_path.unwrap_or_else(|| PathBuf::from("state").join("private-agent").join(&device));
    fs::create_dir_all(&state_path)?;
    let git_path = match git_path {
        Some(path) => path,
        None => find_git_executable()?,
    };
    let store = FileSecretStore::open(secret_store)?;
    let private_key = store.get(&key_name)?;
    let private_pem = Zeroizing::new(private_key_der_to_pem(private_key.as_slice()));
    let mut dispatcher = ReadOnlyDispatcher::open(DispatchConfig {
        device_id: device.clone(),
        policy_path,
        audit_sqlite: state_path.join("audit.db"),
        audit_jsonl: state_path.join("audit.jsonl"),
        journal_dir: state_path.join("journal"),
        allowed_roots: roots,
        git_executable: git_path,
        max_output_bytes: DEFAULT_MAX_OUTPUT_BYTES,
        browser: None,
    })?;
    if let Some(path) = approvers_path.as_deref() {
        let loaded = load_trusted_approvers(&mut dispatcher, path)?;
        eprintln!("trusted_approvers={loaded}");
    }
    let dispatcher = Arc::new(Mutex::new(dispatcher));
    let config = PrivateDeviceClientConfig {
        endpoint,
        server_name,
        device_id: device,
        ca_pem: fs::read(ca_path)?,
        device_cert_pem: fs::read(cert_path)?,
        device_key_pem: private_pem.as_bytes().to_vec(),
        agent_version: env!("CARGO_PKG_VERSION").into(),
        heartbeat_interval: Duration::from_secs(heartbeat_seconds),
        replay_capacity: 4096,
    };
    let cancellation = CancellationToken::new();
    let shutdown = cancellation.clone();
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            shutdown.cancel();
        }
    });
    run_device_dispatch_until_cancelled(config, dispatcher, cancellation).await?;
    Ok(())
}

fn find_git_executable() -> Result<PathBuf, Box<dyn Error>> {
    let output = std::process::Command::new("where.exe")
        .arg("git.exe")
        .output()?;
    if !output.status.success() {
        return Err("git.exe not found; pass --git with an absolute path".into());
    }
    let text = String::from_utf8(output.stdout)?;
    let path = text
        .lines()
        .next()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .ok_or("git.exe lookup returned no path")?;
    let path = Path::new(path).to_path_buf();
    if !path.is_absolute() || !path.is_file() {
        return Err("resolved git.exe path is invalid".into());
    }
    Ok(path)
}

fn next_value<'a>(
    args: &'a [String],
    index: &mut usize,
    flag: &str,
) -> Result<&'a str, Box<dyn Error>> {
    *index += 1;
    args.get(*index)
        .map(String::as_str)
        .ok_or_else(|| format!("missing value for {flag}").into())
}

fn print_help() -> Result<(), Box<dyn Error>> {
    println!("Vör Commander Device Agent");
    println!("  vor-agent listen [--bind 127.0.0.1:8740] [--once]");
    println!(
        "  vor-agent local-enroll --device ID --out DIR --secret-store DIR [--key-name NAME] [--server-name localhost]"
    );
    println!("  vor-agent relay-probe --relay URL --device ID");
    println!("  vor-agent relay-run --relay URL --device ID [--heartbeat-seconds N]");
    println!("  vor-agent relay-dispatch-run --relay URL --device ID --policy POLICY.yaml");
    println!("      --root PATH [--root PATH...] [--git GIT.exe] [--state DIR] [--approvers FILE]");
    println!("      [--secret-store DIR] [--token-name NAME]");
    println!(
        "  vor-agent private-run --endpoint https://HOST:PORT --server-name NAME --device ID \\"
    );
    println!("      --ca CA.pem --cert DEVICE.pem --secret-store DIR --key-name NAME \\");
    println!(
        "      --policy POLICY.yaml --root PATH [--root PATH...] [--git GIT.exe] [--state DIR] [--approvers FILE]"
    );
    println!();
    println!("Relay commands use VOR_RELAY_TOKEN by default.");
    println!("relay-dispatch-run can instead load the bearer from the DPAPI SecretStore.");
    println!(
        "Remote dispatch is read-only by default: file read, Git status/diff and process list/inspect."
    );
    println!("private-run loads the device private key only from the DPAPI SecretStore.");
    println!(
        "filesystem.write requires --approvers FILE, a local approval policy, and a signed one-use ApprovedActionRequest."
    );
    println!(
        "No remote terminal, browser session, process termination, or unsigned filesystem write is exposed."
    );
    Ok(())
}
