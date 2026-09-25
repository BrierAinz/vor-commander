// SPDX-License-Identifier: MPL-2.0

use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::Deserialize;
use std::env;
use std::error::Error;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use tokio_util::sync::CancellationToken;
use vor_auth::GrantStore;
use vor_gateway::{GatewayConfig, serve_with_links};
use vor_private_grpc::{
    DeviceCertificateRegistry, PrivateLinkConfig, PrivateLinkHub, PrivateLinkTls,
};
use vor_relay::{RelayConfig, RelayHub};

#[derive(Debug, Deserialize)]
struct DeviceRegistryFile {
    devices: Vec<DeviceRegistryEntry>,
}

#[derive(Debug, Deserialize)]
struct DeviceRegistryEntry {
    device_id: String,
    certificate_der_base64: String,
}
#[derive(Debug)]
struct Config {
    gateway_bind: SocketAddr,
    relay_bind: SocketAddr,
    private_bind: SocketAddr,
    gateway_state: PathBuf,
    relay_state: PathBuf,
    ca_path: PathBuf,
    server_cert_path: PathBuf,
    server_key_path: PathBuf,
    registry_path: PathBuf,
}

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("vor-control-plane error: {error}");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<(), Box<dyn Error>> {
    let config = parse_args(env::args().skip(1).collect())?;
    let gateway_grants = GrantStore::open(&config.gateway_state)?;
    let relay_grants = GrantStore::open(&config.relay_state)?;
    let registry_bytes = std::fs::read(&config.registry_path)?;
    let registry_file: DeviceRegistryFile = serde_json::from_slice(&registry_bytes)?;
    let mut devices = Vec::with_capacity(registry_file.devices.len());
    for entry in registry_file.devices {
        devices.push((
            entry.device_id,
            STANDARD.decode(entry.certificate_der_base64)?,
        ));
    }
    let registry = DeviceCertificateRegistry::from_certificates(devices)?;
    let private_hub = PrivateLinkHub::default();
    let relay_hub = RelayHub::default();
    let tls = PrivateLinkTls {
        ca_pem: std::fs::read(&config.ca_path)?,
        server_cert_pem: std::fs::read(&config.server_cert_path)?,
        server_key_pem: std::fs::read(&config.server_key_path)?,
    };

    let cancellation = CancellationToken::new();
    let ctrl = cancellation.clone();
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            ctrl.cancel();
        }
    });
    let private = vor_private_grpc::serve_with_hub(
        PrivateLinkConfig {
            bind: config.private_bind,
            replay_capacity: 4096,
        },
        tls,
        registry,
        private_hub.clone(),
        cancellation.child_token(),
    );
    let relay = vor_relay::serve_with_hub(
        RelayConfig {
            bind: config.relay_bind,
            replay_capacity: 4096,
        },
        relay_grants,
        relay_hub.clone(),
        cancellation.child_token(),
    );
    let gateway = serve_with_links(
        GatewayConfig {
            bind: config.gateway_bind,
        },
        gateway_grants,
        private_hub,
        relay_hub,
        cancellation.child_token(),
    );

    tokio::pin!(private, relay, gateway);
    let result: Result<(), Box<dyn Error>> = tokio::select! {
        value = &mut private => value.map_err(|error| Box::new(error) as Box<dyn Error>),
        value = &mut relay => value.map_err(|error| Box::new(error) as Box<dyn Error>),
        value = &mut gateway => value.map_err(|error| Box::new(error) as Box<dyn Error>),
    };
    cancellation.cancel();
    result?;
    Ok(())
}
fn parse_args(args: Vec<String>) -> Result<Config, Box<dyn Error>> {
    let mut gateway_bind: SocketAddr = "127.0.0.1:8742".parse()?;
    let mut relay_bind: SocketAddr = "127.0.0.1:8789".parse()?;
    let mut private_bind: SocketAddr = "127.0.0.1:8790".parse()?;
    let mut gateway_state = None;
    let mut relay_state = None;
    let mut ca_path = None;
    let mut server_cert_path = None;
    let mut server_key_path = None;
    let mut registry_path = None;
    let mut index = 0usize;
    while index < args.len() {
        match args[index].as_str() {
            "--gateway-bind" => {
                gateway_bind = next(&args, &mut index, "--gateway-bind")?.parse()?
            }
            "--relay-bind" => relay_bind = next(&args, &mut index, "--relay-bind")?.parse()?,
            "--private-bind" => {
                private_bind = next(&args, &mut index, "--private-bind")?.parse()?
            }
            "--gateway-state" => {
                gateway_state = Some(PathBuf::from(next(&args, &mut index, "--gateway-state")?))
            }
            "--relay-state" => {
                relay_state = Some(PathBuf::from(next(&args, &mut index, "--relay-state")?))
            }
            "--ca" => ca_path = Some(PathBuf::from(next(&args, &mut index, "--ca")?)),
            "--server-cert" => {
                server_cert_path = Some(PathBuf::from(next(&args, &mut index, "--server-cert")?))
            }
            "--server-key" => {
                server_key_path = Some(PathBuf::from(next(&args, &mut index, "--server-key")?))
            }
            "--device-registry" => {
                registry_path = Some(PathBuf::from(next(&args, &mut index, "--device-registry")?))
            }
            "--help" | "-h" => return Err(help().into()),
            other => return Err(format!("unsupported option: {other}").into()),
        }
        index += 1;
    }
    Ok(Config {
        gateway_bind,
        relay_bind,
        private_bind,
        gateway_state: gateway_state.ok_or("missing --gateway-state")?,
        relay_state: relay_state.ok_or("missing --relay-state")?,
        ca_path: ca_path.ok_or("missing --ca")?,
        server_cert_path: server_cert_path.ok_or("missing --server-cert")?,
        server_key_path: server_key_path.ok_or("missing --server-key")?,
        registry_path: registry_path.ok_or("missing --device-registry")?,
    })
}

fn next<'a>(args: &'a [String], index: &mut usize, flag: &str) -> Result<&'a str, Box<dyn Error>> {
    *index += 1;
    args.get(*index)
        .map(String::as_str)
        .ok_or_else(|| format!("missing value for {flag}").into())
}

fn help() -> &'static str {
    "vor-control-plane --gateway-state PATH --relay-state PATH --ca CA.pem \
--server-cert server.pem --server-key server-key.pem --device-registry devices.json \
[--gateway-bind 127.0.0.1:8742] [--relay-bind 127.0.0.1:8789] [--private-bind 127.0.0.1:8790]"
}
