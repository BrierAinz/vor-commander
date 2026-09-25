// SPDX-License-Identifier: MPL-2.0

use std::env;
use std::error::Error;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio_util::sync::CancellationToken;
use vor_auth::GrantStore;
use vor_relay::{RelayConfig, serve};
use vor_secrets::FileSecretStore;

const DEFAULT_BIND: &str = "127.0.0.1:8789";
const DEFAULT_STATE: &str = "state/relay/auth.json";
const DEFAULT_TTL_SECONDS: u64 = 3600;

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("vor-relay error: {error}");
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
    let mut replay_capacity = 4096usize;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--bind" => bind = next_value(args, &mut index, "--bind")?.parse()?,
            "--state" => state_path = PathBuf::from(next_value(args, &mut index, "--state")?),
            "--replay-capacity" => {
                replay_capacity = next_value(args, &mut index, "--replay-capacity")?.parse()?
            }
            other => return Err(format!("unsupported serve option: {other}").into()),
        }
        index += 1;
    }
    if !bind.ip().is_loopback() {
        return Err(
            format!("relay bind must remain loopback before deployment approval: {bind}").into(),
        );
    }
    let grants = GrantStore::open(state_path)?;
    let cancellation = CancellationToken::new();
    let shutdown = cancellation.clone();
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            shutdown.cancel();
        }
    });
    println!("vor-relay listening on {bind}");
    serve(
        RelayConfig {
            bind,
            replay_capacity,
        },
        grants,
        cancellation,
    )
    .await?;
    Ok(())
}

fn grant_command(args: &[String]) -> Result<(), Box<dyn Error>> {
    let mut state_path = PathBuf::from(DEFAULT_STATE);
    let mut device: Option<String> = None;
    let mut ttl_seconds = DEFAULT_TTL_SECONDS;
    let mut secret_store: Option<PathBuf> = None;
    let mut key_name = "relay-token".to_owned();
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--state" => state_path = PathBuf::from(next_value(args, &mut index, "--state")?),
            "--device" => device = Some(next_value(args, &mut index, "--device")?.to_owned()),
            "--ttl-seconds" => {
                ttl_seconds = next_value(args, &mut index, "--ttl-seconds")?.parse()?
            }
            "--secret-store" => {
                secret_store = Some(PathBuf::from(next_value(
                    args,
                    &mut index,
                    "--secret-store",
                )?))
            }
            "--key-name" => key_name = next_value(args, &mut index, "--key-name")?.to_owned(),
            other => return Err(format!("unsupported grant option: {other}").into()),
        }
        index += 1;
    }
    let device = device.ok_or("grant requires --device")?;
    let ttl_ms = ttl_seconds
        .checked_mul(1000)
        .ok_or("relay grant TTL is too large")?;
    let store = GrantStore::open(state_path)?;
    let issued = store.issue(device, ["relay.connect"], ttl_ms, now_unix_ms()?)?;
    println!("grant_id={}", issued.record.grant_id);
    println!("expires_at_unix_ms={}", issued.record.expires_at_unix_ms);
    if let Some(root) = secret_store {
        let secrets = FileSecretStore::open(root)?;
        secrets.put(&key_name, issued.token().as_bytes())?;
        println!("token_stored=true");
        println!("secret_name={key_name}");
    } else {
        println!("token={}", issued.token());
    }
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
    println!("VÃƒÂ¶r Commander development relay");
    println!("  vor-relay serve [--bind 127.0.0.1:8789] [--state PATH] [--replay-capacity N]");
    println!("  vor-relay grant --device DEVICE [--ttl-seconds N] [--state PATH]");
    println!("  vor-relay device-id [--state PATH]");
    println!();
    println!("Defaults:");
    println!("  bind: {DEFAULT_BIND}");
    println!("  state: {DEFAULT_STATE}");
    println!("  grant TTL: {DEFAULT_TTL_SECONDS}s");
    println!("Public binds are intentionally rejected before P4 deployment approval.");
    println!("Grant tokens are printed once; store them as secrets.");
    Ok(())
}
