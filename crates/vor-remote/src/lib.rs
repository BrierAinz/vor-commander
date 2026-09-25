// SPDX-License-Identifier: MPL-2.0

use futures_util::{SinkExt, StreamExt};
use prost_types::Timestamp;
use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use thiserror::Error;
use tokio::time::{MissedTickBehavior, interval, sleep};
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::HeaderValue;
use tokio_tungstenite::tungstenite::http::header::AUTHORIZATION;
use tokio_util::sync::CancellationToken;
use url::{Host, Url};
use vor_dispatch::ReadOnlyDispatcher;
use vor_wire::v1::relay_frame::Payload;
use vor_wire::v1::{DeviceHello, RelayFrame, RelayHeartbeat};
use vor_wire::{
    ReplayGuard, WIRE_VERSION, decode_frame, encode_frame, frame_digest, verify_frame_at,
};

const FRAME_TTL: Duration = Duration::from_secs(30);
const DEFAULT_HEARTBEAT: Duration = Duration::from_secs(15);

#[derive(Clone)]
pub struct SecretToken(String);

impl SecretToken {
    pub fn new(value: impl Into<String>) -> Result<Self, RemoteError> {
        let value = value.into();
        if value.is_empty() || value.contains('\r') || value.contains('\n') {
            return Err(RemoteError::InvalidToken);
        }
        Ok(Self(value))
    }

    fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SecretToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretToken(<redacted>)")
    }
}
#[derive(Debug, Clone)]
pub struct ReconnectPolicy {
    pub min_delay: Duration,
    pub max_delay: Duration,
}

impl Default for ReconnectPolicy {
    fn default() -> Self {
        Self {
            min_delay: Duration::from_millis(250),
            max_delay: Duration::from_secs(30),
        }
    }
}

impl ReconnectPolicy {
    pub fn delay_for(&self, attempt: u32) -> Duration {
        let multiplier = 1u32.checked_shl(attempt.min(16)).unwrap_or(u32::MAX);
        self.min_delay
            .checked_mul(multiplier)
            .unwrap_or(self.max_delay)
            .min(self.max_delay)
    }
}

#[derive(Clone)]
pub struct RemoteConfig {
    relay_base: Url,
    pub device_id: String,
    token: SecretToken,
    pub agent_version: String,
    pub heartbeat_interval: Duration,
    pub reconnect: ReconnectPolicy,
}
impl RemoteConfig {
    pub fn new(
        relay_base: &str,
        device_id: impl Into<String>,
        token: SecretToken,
        agent_version: impl Into<String>,
    ) -> Result<Self, RemoteError> {
        let relay_base = validate_relay_url(relay_base)?;
        let device_id = device_id.into();
        validate_device_id(&device_id)?;
        let agent_version = agent_version.into();
        if agent_version.trim().is_empty() {
            return Err(RemoteError::InvalidAgentVersion);
        }
        Ok(Self {
            relay_base,
            device_id,
            token,
            agent_version,
            heartbeat_interval: DEFAULT_HEARTBEAT,
            reconnect: ReconnectPolicy::default(),
        })
    }

    pub fn device_url(&self) -> Result<Url, RemoteError> {
        let mut url = self.relay_base.clone();
        let mut path = url.path().trim_end_matches('/').to_owned();
        path.push_str("/v1/device/");
        path.push_str(&self.device_id);
        url.set_path(&path);
        Ok(url)
    }
}
fn validate_relay_url(input: &str) -> Result<Url, RemoteError> {
    let mut url = Url::parse(input).map_err(|_| RemoteError::InvalidRelayUrl)?;
    if !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(RemoteError::UnsafeRelayUrl);
    }
    match url.scheme() {
        "wss" => {}
        "ws" if is_loopback_host(url.host()) => {}
        "ws" => return Err(RemoteError::InsecureRemoteWebSocket),
        _ => return Err(RemoteError::UnsupportedScheme),
    }
    if url.host().is_none() {
        return Err(RemoteError::InvalidRelayUrl);
    }
    let normalized = url.path().trim_end_matches('/').to_owned();
    url.set_path(if normalized.is_empty() {
        "/"
    } else {
        &normalized
    });
    Ok(url)
}

fn is_loopback_host(host: Option<Host<&str>>) -> bool {
    match host {
        Some(Host::Domain(domain)) => domain.eq_ignore_ascii_case("localhost"),
        Some(Host::Ipv4(address)) => address.is_loopback(),
        Some(Host::Ipv6(address)) => address.is_loopback(),
        None => false,
    }
}

fn validate_device_id(value: &str) -> Result<(), RemoteError> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(RemoteError::InvalidDeviceId);
    }
    Ok(())
}
type DeviceSocket =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

pub struct RemoteClient {
    config: RemoteConfig,
}

impl RemoteClient {
    pub fn new(config: RemoteConfig) -> Self {
        Self { config }
    }

    pub async fn probe_once(&self) -> Result<(), RemoteError> {
        let mut socket = self.connect_and_hello().await?;
        socket.close(None).await?;
        Ok(())
    }

    pub async fn run_until_cancelled(
        &self,
        cancellation: CancellationToken,
    ) -> Result<(), RemoteError> {
        let mut attempt = 0u32;
        loop {
            if cancellation.is_cancelled() {
                return Ok(());
            }
            let connection = tokio::select! {
                _ = cancellation.cancelled() => return Ok(()),
                result = self.connect_and_hello() => result,
            };
            match connection {
                Ok(socket) => {
                    attempt = 0;
                    if self
                        .heartbeat_loop(socket, cancellation.clone())
                        .await
                        .is_err()
                    {
                        if cancellation.is_cancelled() {
                            return Ok(());
                        }
                        self.wait_reconnect(attempt, &cancellation).await?;
                        attempt = attempt.saturating_add(1);
                    } else {
                        return Ok(());
                    }
                }
                Err(_) => {
                    self.wait_reconnect(attempt, &cancellation).await?;
                    attempt = attempt.saturating_add(1);
                }
            }
        }
    }
    pub async fn run_dispatch_until_cancelled(
        &self,
        dispatcher: Arc<Mutex<ReadOnlyDispatcher>>,
        cancellation: CancellationToken,
    ) -> Result<(), RemoteError> {
        let mut attempt = 0u32;
        loop {
            if cancellation.is_cancelled() {
                return Ok(());
            }
            let connection = tokio::select! {
                _ = cancellation.cancelled() => return Ok(()),
                result = self.connect_and_hello() => result,
            };
            match connection {
                Ok(socket) => {
                    attempt = 0;
                    if self
                        .dispatch_loop(socket, dispatcher.clone(), cancellation.clone())
                        .await
                        .is_err()
                    {
                        if cancellation.is_cancelled() {
                            return Ok(());
                        }
                        self.wait_reconnect(attempt, &cancellation).await?;
                        attempt = attempt.saturating_add(1);
                    } else {
                        return Ok(());
                    }
                }
                Err(_) => {
                    self.wait_reconnect(attempt, &cancellation).await?;
                    attempt = attempt.saturating_add(1);
                }
            }
        }
    }

    async fn connect_and_hello(&self) -> Result<DeviceSocket, RemoteError> {
        let url = self.config.device_url()?.to_string();
        let mut request = url.into_client_request()?;
        let auth = HeaderValue::from_str(&format!("Bearer {}", self.config.token.expose()))
            .map_err(|_| RemoteError::InvalidToken)?;
        request.headers_mut().insert(AUTHORIZATION, auth);
        let (mut socket, _) = connect_async(request).await?;
        let hello = self.device_hello_frame(now_unix_ms()?)?;
        send_expect_ack(&mut socket, &hello).await?;
        Ok(socket)
    }

    async fn dispatch_loop(
        &self,
        mut socket: DeviceSocket,
        dispatcher: Arc<Mutex<ReadOnlyDispatcher>>,
        cancellation: CancellationToken,
    ) -> Result<(), RemoteError> {
        if self.config.heartbeat_interval.is_zero() {
            return Err(RemoteError::InvalidHeartbeat);
        }
        let mut ticker = interval(self.config.heartbeat_interval);
        ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
        ticker.tick().await;
        let mut pending_acks = HashMap::new();
        let mut replay = ReplayGuard::new(4096)?;

        loop {
            tokio::select! {
                _ = cancellation.cancelled() => {
                    let _ = socket.close(None).await;
                    return Ok(());
                }
                _ = ticker.tick() => {
                    let heartbeat = self.heartbeat_frame(now_unix_ms()?)?;
                    send_tracked(&mut socket, &heartbeat, &mut pending_acks).await?;
                }
                message = socket.next() => {
                    let Some(message) = message else { return Err(RemoteError::RelayClosed) };
                    match message? {
                        Message::Binary(bytes) => {
                            let frame = decode_frame(&bytes)?;
                            let now = now_unix_ms()?;
                            verify_frame_at(&frame, now)?;
                            if frame.device_id != self.config.device_id {
                                return Err(RemoteError::AckMismatch);
                            }
                            replay.accept(&frame, now)?;
                            match frame.payload {
                                Some(Payload::Ack(ack)) => {
                                    accept_tracked_ack(&frame.message_id, &ack, &mut pending_acks)?;
                                }
                                Some(Payload::ActionRequest(request)) => {
                                    let worker = dispatcher.clone();
                                    let result = tokio::task::spawn_blocking(move || {
                                        let mut guard = worker.lock().map_err(|_| ())?;
                                        guard.dispatch_proto_report(&request).map_err(|_| ())
                                    })
                                    .await
                                    .map_err(|_| RemoteError::DispatcherTask)?
                                    .map_err(|_| RemoteError::DispatcherUnavailable)?;
                                    let result_frame = self.frame(
                                        now_unix_ms()?,
                                        Payload::ActionResult(result),
                                    )?;
                                    send_tracked(&mut socket, &result_frame, &mut pending_acks).await?;
                                }
                                Some(Payload::ApprovedActionRequest(approved)) => {
                                    let worker = dispatcher.clone();
                                    let result = tokio::task::spawn_blocking(move || {
                                        let mut guard = worker.lock().map_err(|_| ())?;
                                        guard
                                            .dispatch_approved_proto_report(&approved)
                                            .map_err(|_| ())
                                    })
                                    .await
                                    .map_err(|_| RemoteError::DispatcherTask)?
                                    .map_err(|_| RemoteError::DispatcherUnavailable)?;
                                    let result_frame = self.frame(
                                        now_unix_ms()?,
                                        Payload::ActionResult(result),
                                    )?;
                                    send_tracked(&mut socket, &result_frame, &mut pending_acks).await?;
                                }
                                _ => return Err(RemoteError::UnexpectedRelayPayload),
                            }
                        }
                        Message::Ping(payload) => socket.send(Message::Pong(payload)).await?,
                        Message::Pong(_) => {}
                        Message::Close(_) => return Err(RemoteError::RelayClosed),
                        _ => return Err(RemoteError::UnexpectedRelayMessage),
                    }
                }
            }
        }
    }

    async fn heartbeat_loop(
        &self,
        mut socket: DeviceSocket,
        cancellation: CancellationToken,
    ) -> Result<(), RemoteError> {
        if self.config.heartbeat_interval.is_zero() {
            return Err(RemoteError::InvalidHeartbeat);
        }
        let mut ticker = interval(self.config.heartbeat_interval);
        ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
        ticker.tick().await;
        loop {
            tokio::select! {
                _ = cancellation.cancelled() => {
                    let _ = socket.close(None).await;
                    return Ok(());
                }
                _ = ticker.tick() => {
                    let heartbeat = self.heartbeat_frame(now_unix_ms()?)?;
                    send_expect_ack(&mut socket, &heartbeat).await?;
                }
            }
        }
    }

    async fn wait_reconnect(
        &self,
        attempt: u32,
        cancellation: &CancellationToken,
    ) -> Result<(), RemoteError> {
        let delay = self.config.reconnect.delay_for(attempt);
        tokio::select! {
            _ = cancellation.cancelled() => Ok(()),
            _ = sleep(delay) => Ok(()),
        }
    }
    fn device_hello_frame(&self, now_unix_ms: u64) -> Result<RelayFrame, RemoteError> {
        let transport = if self.config.relay_base.scheme() == "wss" {
            "wss+protobuf"
        } else {
            "ws-loopback-dev"
        };
        self.frame(
            now_unix_ms,
            Payload::DeviceHello(DeviceHello {
                device_id: self.config.device_id.clone(),
                agent_version: self.config.agent_version.clone(),
                transports: vec![transport.into()],
                capabilities: vec![
                    "relay.heartbeat".into(),
                    "filesystem.read".into(),
                    "filesystem.list".into(),
                    "filesystem.search_files".into(),
                    "filesystem.search_content".into(),
                    "filesystem.info".into(),
                    "git.status".into(),
                    "git.diff".into(),
                    "process.list".into(),
                    "process.inspect".into(),
                    "filesystem.write.approval".into(),
                    "terminal.exec.approval".into(),
                    "terminal.poll".into(),
                    "terminal.cancel".into(),
                ],
            }),
        )
    }

    fn heartbeat_frame(&self, now_unix_ms: u64) -> Result<RelayFrame, RemoteError> {
        self.frame(
            now_unix_ms,
            Payload::Heartbeat(RelayHeartbeat {
                sent_at: Some(timestamp_from_ms(now_unix_ms)?),
            }),
        )
    }

    fn frame(&self, now_unix_ms: u64, payload: Payload) -> Result<RelayFrame, RemoteError> {
        let expires = now_unix_ms
            .checked_add(u64::try_from(FRAME_TTL.as_millis()).map_err(|_| RemoteError::Clock)?)
            .ok_or(RemoteError::Clock)?;
        Ok(RelayFrame {
            wire_version: WIRE_VERSION,
            message_id: hex::encode(rand::random::<[u8; 16]>()),
            device_id: self.config.device_id.clone(),
            expires_at: Some(timestamp_from_ms(expires)?),
            nonce: rand::random::<[u8; 16]>().to_vec(),
            payload: Some(payload),
        })
    }
}
const MAX_PENDING_ACKS: usize = 128;

async fn send_tracked(
    socket: &mut DeviceSocket,
    frame: &RelayFrame,
    pending: &mut HashMap<String, [u8; 32]>,
) -> Result<(), RemoteError> {
    if pending.len() >= MAX_PENDING_ACKS {
        return Err(RemoteError::TooManyPendingAcks);
    }
    if pending.contains_key(&frame.message_id) {
        return Err(RemoteError::DuplicateOutboundMessage);
    }
    let digest = frame_digest(frame)?;
    socket
        .send(Message::Binary(encode_frame(frame)?.into()))
        .await?;
    pending.insert(frame.message_id.clone(), digest);
    Ok(())
}

fn accept_tracked_ack(
    frame_message_id: &str,
    ack: &vor_wire::v1::RelayAck,
    pending: &mut HashMap<String, [u8; 32]>,
) -> Result<(), RemoteError> {
    if frame_message_id != ack.message_id || ack.status != "accepted" {
        return Err(RemoteError::AckMismatch);
    }
    let expected = pending
        .remove(&ack.message_id)
        .ok_or(RemoteError::AckMismatch)?;
    if ack.payload_digest.as_slice() != expected {
        return Err(RemoteError::AckMismatch);
    }
    Ok(())
}

async fn send_expect_ack(socket: &mut DeviceSocket, frame: &RelayFrame) -> Result<(), RemoteError> {
    let expected_digest = frame_digest(frame)?;
    socket
        .send(Message::Binary(encode_frame(frame)?.into()))
        .await?;

    loop {
        let Some(message) = socket.next().await else {
            return Err(RemoteError::RelayClosed);
        };
        match message? {
            Message::Binary(bytes) => {
                let response = decode_frame(&bytes)?;
                verify_frame_at(&response, now_unix_ms()?)?;
                if response.device_id != frame.device_id {
                    return Err(RemoteError::AckMismatch);
                }
                let Some(Payload::Ack(ack)) = response.payload else {
                    return Err(RemoteError::AckMismatch);
                };
                if ack.message_id != frame.message_id
                    || ack.status != "accepted"
                    || ack.payload_digest.as_slice() != expected_digest
                {
                    return Err(RemoteError::AckMismatch);
                }
                return Ok(());
            }
            Message::Ping(payload) => socket.send(Message::Pong(payload)).await?,
            Message::Pong(_) => {}
            Message::Close(_) => return Err(RemoteError::RelayClosed),
            _ => return Err(RemoteError::UnexpectedRelayMessage),
        }
    }
}
fn now_unix_ms() -> Result<u64, RemoteError> {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| RemoteError::Clock)?;
    u64::try_from(elapsed.as_millis()).map_err(|_| RemoteError::Clock)
}

fn timestamp_from_ms(value: u64) -> Result<Timestamp, RemoteError> {
    let seconds = i64::try_from(value / 1000).map_err(|_| RemoteError::Clock)?;
    let nanos = i32::try_from((value % 1000) * 1_000_000).map_err(|_| RemoteError::Clock)?;
    Ok(Timestamp { seconds, nanos })
}

#[derive(Debug, Error)]
pub enum RemoteError {
    #[error("relay URL is invalid")]
    InvalidRelayUrl,
    #[error("relay URL must not contain credentials, query, or fragment")]
    UnsafeRelayUrl,
    #[error("remote WebSocket must use wss://; ws:// is loopback-development only")]
    InsecureRemoteWebSocket,
    #[error("relay URL scheme must be ws or wss")]
    UnsupportedScheme,
    #[error("device id is invalid")]
    InvalidDeviceId,
    #[error("agent version must not be empty")]
    InvalidAgentVersion,
    #[error("relay bearer token is invalid")]
    InvalidToken,
    #[error("heartbeat interval must be positive")]
    InvalidHeartbeat,
    #[error("system clock is outside supported range")]
    Clock,
    #[error("relay connection closed before acknowledgement")]
    RelayClosed,
    #[error("relay sent an unexpected WebSocket message")]
    UnexpectedRelayMessage,
    #[error("relay sent a payload that is not valid for device dispatch")]
    UnexpectedRelayPayload,
    #[error("dispatcher worker task failed")]
    DispatcherTask,
    #[error("dispatcher is unavailable")]
    DispatcherUnavailable,
    #[error("too many relay acknowledgements are pending")]
    TooManyPendingAcks,
    #[error("outbound relay message id was reused")]
    DuplicateOutboundMessage,
    #[error("relay acknowledgement does not match the sent frame")]
    AckMismatch,
    #[error("relay wire validation failed: {0}")]
    Wire(#[from] vor_wire::WireError),
    #[error("relay WebSocket failed: {0}")]
    WebSocket(#[from] tokio_tungstenite::tungstenite::Error),
}
#[cfg(test)]
mod tests {
    use super::*;
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use ed25519_dalek::SigningKey;
    use sha2::{Digest, Sha256};
    use std::collections::BTreeMap;
    use std::path::{Path, PathBuf};
    use tempfile::tempdir;
    use vor_approval::{ApprovalChallenge, sign_approval};
    use vor_auth::GrantStore;
    use vor_dispatch::{DEFAULT_MAX_OUTPUT_BYTES, DispatchConfig};
    use vor_protocol::{ActionEnvelope, ActionRequest, PolicyDecision, PolicyDecisionKind};
    use vor_relay::{RelayError, RelayHub, build_router, build_router_with_hub};
    use vor_wire::{action_request_to_proto, approval_grant_to_proto};

    fn find_git() -> PathBuf {
        let output = std::process::Command::new("where.exe")
            .arg("git.exe")
            .output()
            .unwrap();
        assert!(output.status.success());
        PathBuf::from(
            String::from_utf8_lossy(&output.stdout)
                .lines()
                .next()
                .unwrap()
                .trim(),
        )
    }

    fn write_dispatch_policy(path: &Path, root: &Path) {
        let root = root.to_string_lossy().replace('\\', "\\\\");
        let yaml = format!(
            r#"version: 1
policy_id: relay-dispatch-test
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
browser:
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
"#
        );
        std::fs::write(path, yaml).unwrap();
    }

    fn test_dispatcher(root: &Path) -> Arc<Mutex<ReadOnlyDispatcher>> {
        let policy = root.join("policy.yaml");
        write_dispatch_policy(&policy, root);
        Arc::new(Mutex::new(
            ReadOnlyDispatcher::open(DispatchConfig {
                device_id: "device-1".into(),
                policy_path: policy,
                audit_sqlite: root.join("audit.db"),
                audit_jsonl: root.join("audit.jsonl"),
                journal_dir: root.join("journal"),
                allowed_roots: vec![root.to_path_buf()],
                git_executable: find_git(),
                max_output_bytes: DEFAULT_MAX_OUTPUT_BYTES,
                browser: None,
            })
            .unwrap(),
        ))
    }

    fn remote_request(action: &str, target: &str) -> vor_wire::v1::ActionRequest {
        let now = now_unix_ms().unwrap();
        let request = ActionRequest::seal(ActionEnvelope {
            request_id: format!("req-{:032x}", rand::random::<u128>()),
            organization_id: "org-1".into(),
            actor_id: "relay-gateway-test".into(),
            device_id: "device-1".into(),
            action: action.into(),
            target: target.into(),
            parameters: BTreeMap::new(),
            requested_capabilities: vec![],
            expires_at_unix_ms: now + 30_000,
            nonce: rand::random::<[u8; 16]>().to_vec(),
        })
        .unwrap();
        action_request_to_proto(&request).unwrap()
    }

    fn sha256_hex_bytes(content: &[u8]) -> String {
        hex::encode(Sha256::digest(content))
    }

    fn approved_write_request(
        target: &Path,
        content: &[u8],
        expected_target: &[u8],
        signing: &SigningKey,
    ) -> (vor_wire::v1::ActionRequest, vor_wire::v1::ApprovalGrant) {
        let now = now_unix_ms().unwrap();
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
            serde_json::Value::String(sha256_hex_bytes(expected_target)),
        );
        let request = ActionRequest::seal(ActionEnvelope {
            request_id: format!("req-write-{:032x}", rand::random::<u128>()),
            organization_id: "org-1".into(),
            actor_id: "relay-gateway-test".into(),
            device_id: "device-1".into(),
            action: "filesystem.write".into(),
            target: target.to_string_lossy().into_owned(),
            parameters,
            requested_capabilities: vec![],
            expires_at_unix_ms: now + 30_000,
            nonce: rand::random::<[u8; 16]>().to_vec(),
        })
        .unwrap();
        let decision = PolicyDecision {
            request_id: request.envelope.request_id.clone(),
            kind: PolicyDecisionKind::Approval,
            policy_id: "relay-dispatch-test".into(),
            reason_code: "filesystem_rule".into(),
            required_capability: None,
            envelope_digest: request.envelope_digest,
        };
        let challenge = ApprovalChallenge::issue(&request, &decision, now, now + 20_000).unwrap();
        let approval = sign_approval(challenge, "operator-1", signing).unwrap();
        (
            action_request_to_proto(&request).unwrap(),
            approval_grant_to_proto(&approval).unwrap(),
        )
    }

    fn approved_terminal_request(
        cwd: &Path,
        argv: &[&str],
        timeout_ms: u64,
        signing: &SigningKey,
    ) -> (vor_wire::v1::ActionRequest, vor_wire::v1::ApprovalGrant) {
        let now = now_unix_ms().unwrap();
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
            serde_json::Value::from(64 * 1024u64),
        );
        parameters.insert("columns".into(), serde_json::Value::from(80u64));
        parameters.insert("rows".into(), serde_json::Value::from(25u64));
        let request = ActionRequest::seal(ActionEnvelope {
            request_id: format!("req-terminal-{:032x}", rand::random::<u128>()),
            organization_id: "org-1".into(),
            actor_id: "relay-gateway-test".into(),
            device_id: "device-1".into(),
            action: "terminal.exec".into(),
            target: cwd.to_string_lossy().into_owned(),
            parameters,
            requested_capabilities: vec![],
            expires_at_unix_ms: now + 30_000,
            nonce: rand::random::<[u8; 16]>().to_vec(),
        })
        .unwrap();
        let decision = PolicyDecision {
            request_id: request.envelope.request_id.clone(),
            kind: PolicyDecisionKind::Approval,
            policy_id: "relay-dispatch-test".into(),
            reason_code: "terminal_default".into(),
            required_capability: None,
            envelope_digest: request.envelope_digest,
        };
        let challenge = ApprovalChallenge::issue(&request, &decision, now, now + 20_000).unwrap();
        let approval = sign_approval(challenge, "operator-1", signing).unwrap();
        (
            action_request_to_proto(&request).unwrap(),
            approval_grant_to_proto(&approval).unwrap(),
        )
    }

    #[test]
    fn endpoint_policy_requires_tls_off_loopback() {
        let token = SecretToken::new("secret").unwrap();
        assert!(RemoteConfig::new("ws://127.0.0.1:8789", "device-1", token.clone(), "0.1").is_ok());
        assert!(RemoteConfig::new("ws://localhost:8789", "device-1", token.clone(), "0.1").is_ok());
        assert!(matches!(
            RemoteConfig::new("ws://example.com", "device-1", token.clone(), "0.1"),
            Err(RemoteError::InsecureRemoteWebSocket)
        ));
        assert!(RemoteConfig::new("wss://relay.example.com", "device-1", token, "0.1").is_ok());
    }

    #[test]
    fn url_credentials_and_unsafe_device_ids_are_rejected() {
        let token = SecretToken::new("secret").unwrap();
        assert!(matches!(
            RemoteConfig::new(
                "wss://user:pass@relay.example.com",
                "device-1",
                token.clone(),
                "0.1"
            ),
            Err(RemoteError::UnsafeRelayUrl)
        ));
        assert!(matches!(
            RemoteConfig::new("wss://relay.example.com", "../device", token, "0.1"),
            Err(RemoteError::InvalidDeviceId)
        ));
    }

    #[test]
    fn secret_debug_and_backoff_are_bounded() {
        let token = SecretToken::new("top-secret").unwrap();
        let debug = format!("{token:?}");
        assert!(!debug.contains("top-secret"));
        let policy = ReconnectPolicy::default();
        assert_eq!(policy.delay_for(0), Duration::from_millis(250));
        assert_eq!(policy.delay_for(100), Duration::from_secs(30));
    }
    #[tokio::test]
    async fn device_connects_outbound_and_receives_bound_ack() {
        let dir = tempdir().unwrap();
        let store = GrantStore::open(dir.path().join("relay-auth.json")).unwrap();
        let now = now_unix_ms().unwrap();
        let grant = store
            .issue("device-1", ["relay.connect"], 60_000, now)
            .unwrap();
        let router = build_router(store, 32).unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let cancellation = CancellationToken::new();
        let shutdown = cancellation.clone();
        let relay = tokio::spawn(async move {
            axum::serve(listener, router)
                .with_graceful_shutdown(async move { shutdown.cancelled_owned().await })
                .await
                .unwrap();
        });

        let config = RemoteConfig::new(
            &format!("ws://{address}"),
            "device-1",
            SecretToken::new(grant.token()).unwrap(),
            "0.1.0",
        )
        .unwrap();
        RemoteClient::new(config).probe_once().await.unwrap();
        cancellation.cancel();
        relay.await.unwrap();
    }

    #[tokio::test]
    async fn websocket_read_only_dispatch_roundtrip() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("remote.txt");
        std::fs::write(&file, b"wss-dispatch-ok").unwrap();
        let write_target = dir.path().join("approved-write.txt");
        std::fs::write(&write_target, b"before").unwrap();
        let signing = SigningKey::from_bytes(&[31; 32]);
        let dispatcher = test_dispatcher(dir.path());
        dispatcher
            .lock()
            .unwrap()
            .add_trusted_approver("operator-1", signing.verifying_key().to_bytes())
            .unwrap();

        let store = GrantStore::open(dir.path().join("relay-auth.json")).unwrap();
        let now = now_unix_ms().unwrap();
        let grant = store
            .issue("device-1", ["relay.connect"], 60_000, now)
            .unwrap();
        let hub = RelayHub::default();
        let router = build_router_with_hub(store, 64, hub.clone()).unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let relay_cancel = CancellationToken::new();
        let relay_shutdown = relay_cancel.clone();
        let relay_task = tokio::spawn(async move {
            axum::serve(listener, router)
                .with_graceful_shutdown(async move { relay_shutdown.cancelled_owned().await })
                .await
                .unwrap();
        });

        let mut config = RemoteConfig::new(
            &format!("ws://{address}"),
            "device-1",
            SecretToken::new(grant.token()).unwrap(),
            "0.1.0-test",
        )
        .unwrap();
        config.heartbeat_interval = Duration::from_secs(30);
        let client_cancel = CancellationToken::new();
        let client_shutdown = client_cancel.clone();
        let client_dispatcher = dispatcher.clone();
        let client_task = tokio::spawn(async move {
            RemoteClient::new(config)
                .run_dispatch_until_cancelled(client_dispatcher, client_shutdown)
                .await
        });

        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if hub.connected_devices().await == vec!["device-1".to_owned()] {
                    break;
                }
                sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();

        let result = hub
            .dispatch_action(
                "device-1",
                remote_request("filesystem.read", &file.to_string_lossy()),
                Duration::from_secs(2),
            )
            .await
            .unwrap();
        assert_eq!(result.status, "ok");
        assert_eq!(result.output, b"wss-dispatch-ok");

        let blocked = hub
            .dispatch_action(
                "device-1",
                remote_request("terminal.project_test", "local"),
                Duration::from_secs(1),
            )
            .await;
        assert!(matches!(blocked, Err(RelayError::RemoteActionNotAllowed)));

        let denied = hub
            .dispatch_action(
                "device-1",
                remote_request("filesystem.read", r"C:\Windows\win.ini"),
                Duration::from_secs(2),
            )
            .await
            .unwrap();
        assert_eq!(denied.status, "policy_denied");
        assert!(denied.output.is_empty());
        assert_eq!(dispatcher.lock().unwrap().audit_sequence(), 3);

        let (write_request, write_approval) =
            approved_write_request(&write_target, b"after", b"before", &signing);
        let written = hub
            .dispatch_approved_action(
                "device-1",
                write_request,
                write_approval,
                Duration::from_secs(2),
            )
            .await
            .unwrap();
        assert_eq!(written.status, "ok");
        assert_eq!(std::fs::read(&write_target).unwrap(), b"after");
        assert_eq!(dispatcher.lock().unwrap().audit_sequence(), 7);

        let (terminal_request, terminal_approval) =
            approved_terminal_request(dir.path(), &["where.exe", "cmd.exe"], 5_000, &signing);
        let terminal_started = hub
            .dispatch_approved_action(
                "device-1",
                terminal_request,
                terminal_approval,
                Duration::from_secs(2),
            )
            .await
            .unwrap();
        assert_eq!(terminal_started.status, "ok");
        let started: serde_json::Value = serde_json::from_slice(&terminal_started.output).unwrap();
        assert_eq!(started["state"], "running");
        let terminal_session = started["session_id"].as_str().unwrap().to_owned();

        let terminal_deadline = tokio::time::Instant::now() + Duration::from_secs(3);
        loop {
            let polled = hub
                .dispatch_action(
                    "device-1",
                    remote_request("terminal.poll", &terminal_session),
                    Duration::from_secs(2),
                )
                .await
                .unwrap();
            assert_eq!(polled.status, "ok");
            let payload: serde_json::Value = serde_json::from_slice(&polled.output).unwrap();
            let state = payload["state"].as_str().unwrap();
            if state != "running" {
                assert_eq!(state, "completed");
                assert_eq!(payload["exit_code"], 0);
                let output = STANDARD
                    .decode(payload["output_base64"].as_str().unwrap())
                    .unwrap();
                assert!(
                    String::from_utf8_lossy(&output)
                        .to_ascii_lowercase()
                        .contains("cmd.exe")
                );
                break;
            }
            assert!(
                tokio::time::Instant::now() < terminal_deadline,
                "WSS terminal session did not finish"
            );
            sleep(Duration::from_millis(10)).await;
        }

        let (cancel_request, cancel_approval) = approved_terminal_request(
            dir.path(),
            &["ping.exe", "127.0.0.1", "-n", "10"],
            10_000,
            &signing,
        );
        let cancel_started = hub
            .dispatch_approved_action(
                "device-1",
                cancel_request,
                cancel_approval,
                Duration::from_secs(2),
            )
            .await
            .unwrap();
        assert_eq!(cancel_started.status, "ok");
        let cancel_payload: serde_json::Value =
            serde_json::from_slice(&cancel_started.output).unwrap();
        let cancel_session = cancel_payload["session_id"].as_str().unwrap().to_owned();

        let cancelled = hub
            .dispatch_action(
                "device-1",
                remote_request("terminal.cancel", &cancel_session),
                Duration::from_secs(2),
            )
            .await
            .unwrap();
        assert_eq!(cancelled.status, "ok");
        let cancel_ack: serde_json::Value = serde_json::from_slice(&cancelled.output).unwrap();
        assert_eq!(cancel_ack["cancel_requested"], true);

        let cancel_deadline = tokio::time::Instant::now() + Duration::from_secs(3);
        loop {
            let polled = hub
                .dispatch_action(
                    "device-1",
                    remote_request("terminal.poll", &cancel_session),
                    Duration::from_secs(2),
                )
                .await
                .unwrap();
            assert_eq!(polled.status, "ok");
            let payload: serde_json::Value = serde_json::from_slice(&polled.output).unwrap();
            let state = payload["state"].as_str().unwrap();
            if state != "running" {
                assert_eq!(state, "cancelled");
                assert_eq!(payload["error_code"], "terminal_cancelled");
                break;
            }
            assert!(
                tokio::time::Instant::now() < cancel_deadline,
                "WSS terminal cancellation did not finish"
            );
            sleep(Duration::from_millis(10)).await;
        }

        client_cancel.cancel();
        tokio::time::timeout(Duration::from_secs(2), client_task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        relay_cancel.cancel();
        tokio::time::timeout(Duration::from_secs(2), relay_task)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn reconnect_wait_is_cancellable() {
        let mut config = RemoteConfig::new(
            "ws://127.0.0.1:9",
            "device-1",
            SecretToken::new("not-used").unwrap(),
            "0.1.0",
        )
        .unwrap();
        config.reconnect.min_delay = Duration::from_secs(10);
        config.reconnect.max_delay = Duration::from_secs(10);
        let client = RemoteClient::new(config);
        let cancellation = CancellationToken::new();
        let cancel = cancellation.clone();
        let task = tokio::spawn(async move { client.run_until_cancelled(cancel).await });
        sleep(Duration::from_millis(30)).await;
        cancellation.cancel();
        tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }
}
