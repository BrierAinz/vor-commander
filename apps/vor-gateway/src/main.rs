// SPDX-License-Identifier: MPL-2.0

use std::env;
use std::error::Error;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio_util::sync::CancellationToken;
use vor_auth::GrantStore;
use vor_gateway::{GatewayConfig, serve};

const DEFAULT_BIND: &str = "127.0.0.1:8742";
const DEFAULT_STATE: &str = "state/gateway/auth.json";
const DEFAULT_TTL_SECONDS: u64 = 3600;

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("vor-gateway error: {error}");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("serve") => serve_command(&args[1..]).await,
        Some("grant") => grant_command(&args[1..]),
        Some("device-id") => device_id_command(&args[1..]),
        Some("--help" | "-h") | None => print_help(),
        Some(other) => Err(format!("unsupported command: {other}").into()),
    }
}

async fn serve_command(args: &[String]) -> Result<(), Box<dyn Error>> {
    let mut bind: SocketAddr = DEFAULT_BIND.parse()?;
    let mut state_path = PathBuf::from(DEFAULT_STATE);
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--bind" => bind = next_value(args, &mut index, "--bind")?.parse()?,
            "--state" => state_path = PathBuf::from(next_value(args, &mut index, "--state")?),
            other => return Err(format!("unsupported serve option: {other}").into()),
        }
        index += 1;
    }
    if !bind.ip().is_loopback() {
        return Err(format!("gateway bind must be loopback: {bind}").into());
    }
    let grants = GrantStore::open(state_path)?;
    let cancellation = CancellationToken::new();
    let shutdown = cancellation.clone();
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            shutdown.cancel();
        }
    });
    println!("vor-gateway listening on {bind}");
    serve(GatewayConfig { bind }, grants, cancellation).await?;
    Ok(())
}

fn grant_command(args: &[String]) -> Result<(), Box<dyn Error>> {
    let mut state_path = PathBuf::from(DEFAULT_STATE);
    let mut actor: Option<String> = None;
    let mut scopes: Vec<String> = Vec::new();
    let mut ttl_seconds = DEFAULT_TTL_SECONDS;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--state" => state_path = PathBuf::from(next_value(args, &mut index, "--state")?),
            "--actor" => actor = Some(next_value(args, &mut index, "--actor")?.to_owned()),
            "--scope" => scopes.push(next_value(args, &mut index, "--scope")?.to_owned()),
            "--ttl-seconds" => {
                ttl_seconds = next_value(args, &mut index, "--ttl-seconds")?.parse()?
            }
            other => return Err(format!("unsupported grant option: {other}").into()),
        }
        index += 1;
    }
    let actor = actor.ok_or("grant requires --actor")?;
    if scopes.is_empty() {
        return Err("grant requires at least one --scope".into());
    }
    let ttl_ms = ttl_seconds
        .checked_mul(1000)
        .ok_or("grant TTL is too large")?;
    let now = now_unix_ms()?;
    let store = GrantStore::open(state_path)?;
    let issued = store.issue(actor, scopes, ttl_ms, now)?;
    println!("grant_id={}", issued.record.grant_id);
    println!("expires_at_unix_ms={}", issued.record.expires_at_unix_ms);
    println!("token={}", issued.token());
    Ok(())
}

fn device_id_command(args: &[String]) -> Result<(), Box<dyn Error>> {
    let mut state_path = PathBuf::from(DEFAULT_STATE);
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--state" => state_path = PathBuf::from(next_value(args, &mut index, "--state")?),
            other => return Err(format!("unsupported device-id option: {other}").into()),
        }
        index += 1;
    }
    println!("{}", GrantStore::open(state_path)?.device_id()?);
    Ok(())
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

fn now_unix_ms() -> Result<u64, Box<dyn Error>> {
    let elapsed = SystemTime::now().duration_since(UNIX_EPOCH)?;
    Ok(u64::try_from(elapsed.as_millis())?)
}

fn print_help() -> Result<(), Box<dyn Error>> {
    println!("Vör Commander local gateway");
    println!("  vor-gateway serve [--bind 127.0.0.1:8742] [--state PATH]");
    println!("  vor-gateway device-id [--state PATH]");
    println!(
        "  vor-gateway grant --actor ID --scope SCOPE [--scope SCOPE] [--ttl-seconds N] [--state PATH]"
    );
    println!();
    println!("Defaults:");
    println!("  bind: {DEFAULT_BIND}");
    println!("  state: {DEFAULT_STATE}");
    println!("  grant TTL: {DEFAULT_TTL_SECONDS}s");
    println!("The grant token is printed once by the grant command; store it as a secret.");
    Ok(())
}
