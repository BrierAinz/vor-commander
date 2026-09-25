// SPDX-License-Identifier: MPL-2.0

use axum::extract::ws::{Message, WebSocket};
use axum::extract::{Path as AxumPath, State, WebSocketUpgrade};
use axum::http::{HeaderMap, StatusCode, header::AUTHORIZATION};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use prost_types::Timestamp;
use serde_json::json;
use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use thiserror::Error;
use tokio::sync::{RwLock, mpsc, oneshot};
use tokio_util::sync::CancellationToken;
use vor_auth::GrantStore;
use vor_dispatch::{remote_action_allowed, remote_approved_action_allowed};
use vor_wire::v1::relay_frame::Payload;
use vor_wire::v1::{ActionResult, RelayAck, RelayFrame};
use vor_wire::{
    ReplayGuard, WIRE_VERSION, action_request_from_proto, approval_grant_from_proto, decode_frame,
    encode_frame, frame_digest,
};

#[derive(Debug, Clone)]
pub struct RelayConfig {
    pub bind: SocketAddr,
    pub replay_capacity: usize,
}

impl Default for RelayConfig {
    fn default() -> Self {
        Self {
            bind: "127.0.0.1:8789".parse().expect("valid relay bind"),
            replay_capacity: 4096,
        }
    }
}

#[derive(Clone)]
struct RelayDeviceSession {
    session_id: u128,
    sender: mpsc::Sender<RelayFrame>,
}

type PendingResultMap = HashMap<(String, String), oneshot::Sender<ActionResult>>;

#[derive(Clone, Default)]
pub struct RelayHub {
    devices: Arc<RwLock<HashMap<String, RelayDeviceSession>>>,
    pending: Arc<RwLock<PendingResultMap>>,
}

impl RelayHub {
    async fn register(&self, device_id: String, sender: mpsc::Sender<RelayFrame>) -> u128 {
        let session_id = rand::random::<u128>();
        self.devices
            .write()
            .await
            .insert(device_id, RelayDeviceSession { session_id, sender });
        session_id
    }

    async fn unregister(&self, device_id: &str, session_id: u128) {
        let mut devices = self.devices.write().await;
        if devices
            .get(device_id)
            .is_some_and(|entry| entry.session_id == session_id)
        {
            devices.remove(device_id);
        }
    }

    async fn complete_result(&self, device_id: &str, result: ActionResult) -> bool {
        let key = (device_id.to_owned(), result.request_id.clone());
        if let Some(sender) = self.pending.write().await.remove(&key) {
            return sender.send(result).is_ok();
        }
        false
    }

    pub async fn connected_devices(&self) -> Vec<String> {
        let mut devices = self
            .devices
            .read()
            .await
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        devices.sort();
        devices
    }

    pub async fn dispatch_action(
        &self,
        device_id: &str,
        request: vor_wire::v1::ActionRequest,
        timeout: Duration,
    ) -> Result<ActionResult, RelayError> {
        let canonical =
            action_request_from_proto(&request).map_err(|_| RelayError::InvalidActionRequest)?;
        if canonical.envelope.device_id != device_id || request.request_id.trim().is_empty() {
            return Err(RelayError::InvalidActionRequest);
        }
        if !remote_action_allowed(&canonical.envelope.action)
            && !remote_approved_action_allowed(&canonical.envelope.action)
        {
            return Err(RelayError::RemoteActionNotAllowed);
        }
        let session = self
            .devices
            .read()
            .await
            .get(device_id)
            .cloned()
            .ok_or(RelayError::DeviceOffline)?;
        let key = (device_id.to_owned(), request.request_id.clone());
        let (result_sender, result_receiver) = oneshot::channel();
        {
            let mut pending = self.pending.write().await;
            if pending.contains_key(&key) {
                return Err(RelayError::DuplicateRequest);
            }
            pending.insert(key.clone(), result_sender);
        }
        let frame = RelayFrame {
            wire_version: WIRE_VERSION,
            message_id: format!("action-{:032x}", rand::random::<u128>()),
            device_id: device_id.to_owned(),
            expires_at: request.expires_at,
            nonce: rand::random::<[u8; 16]>().to_vec(),
            payload: Some(Payload::ActionRequest(request)),
        };
        if session.sender.send(frame).await.is_err() {
            self.pending.write().await.remove(&key);
            return Err(RelayError::DeviceOffline);
        }
        match tokio::time::timeout(timeout, result_receiver).await {
            Ok(Ok(result)) => Ok(result),
            Ok(Err(_)) => {
                self.pending.write().await.remove(&key);
                Err(RelayError::DeviceOffline)
            }
            Err(_) => {
                self.pending.write().await.remove(&key);
                Err(RelayError::ActionTimeout)
            }
        }
    }

    pub async fn dispatch_approved_action(
        &self,
        device_id: &str,
        request: vor_wire::v1::ActionRequest,
        approval: vor_wire::v1::ApprovalGrant,
        timeout: Duration,
    ) -> Result<ActionResult, RelayError> {
        let canonical =
            action_request_from_proto(&request).map_err(|_| RelayError::InvalidActionRequest)?;
        let signed =
            approval_grant_from_proto(&approval).map_err(|_| RelayError::InvalidActionRequest)?;
        if canonical.envelope.device_id != device_id
            || request.request_id.trim().is_empty()
            || signed.challenge.request_id != canonical.envelope.request_id
            || signed.challenge.envelope_digest != canonical.envelope_digest
        {
            return Err(RelayError::InvalidActionRequest);
        }
        if !remote_approved_action_allowed(&canonical.envelope.action) {
            return Err(RelayError::RemoteActionNotAllowed);
        }
        let session = self
            .devices
            .read()
            .await
            .get(device_id)
            .cloned()
            .ok_or(RelayError::DeviceOffline)?;
        let key = (device_id.to_owned(), request.request_id.clone());
        let (result_sender, result_receiver) = oneshot::channel();
        {
            let mut pending = self.pending.write().await;
            if pending.contains_key(&key) {
                return Err(RelayError::DuplicateRequest);
            }
            pending.insert(key.clone(), result_sender);
        }
        let frame = RelayFrame {
            wire_version: WIRE_VERSION,
            message_id: format!("approved-action-{:032x}", rand::random::<u128>()),
            device_id: device_id.to_owned(),
            expires_at: request.expires_at,
            nonce: rand::random::<[u8; 16]>().to_vec(),
            payload: Some(Payload::ApprovedActionRequest(
                vor_wire::v1::ApprovedActionRequest {
                    request: Some(request),
                    approval: Some(approval),
                },
            )),
        };
        if session.sender.send(frame).await.is_err() {
            self.pending.write().await.remove(&key);
            return Err(RelayError::DeviceOffline);
        }
        match tokio::time::timeout(timeout, result_receiver).await {
            Ok(Ok(result)) => Ok(result),
            Ok(Err(_)) => {
                self.pending.write().await.remove(&key);
                Err(RelayError::DeviceOffline)
            }
            Err(_) => {
                self.pending.write().await.remove(&key);
                Err(RelayError::ActionTimeout)
            }
        }
    }
}
#[derive(Clone)]
struct RelayState {
    grants: GrantStore,
    replay: Arc<Mutex<ReplayGuard>>,
    hub: RelayHub,
}

pub fn build_router(grants: GrantStore, replay_capacity: usize) -> Result<Router, RelayError> {
    build_router_with_hub(grants, replay_capacity, RelayHub::default())
}

pub fn build_router_with_hub(
    grants: GrantStore,
    replay_capacity: usize,
    hub: RelayHub,
) -> Result<Router, RelayError> {
    let replay =
        ReplayGuard::new(replay_capacity).map_err(|_| RelayError::InvalidReplayCapacity)?;
    let state = RelayState {
        grants,
        replay: Arc::new(Mutex::new(replay)),
        hub,
    };
    Ok(Router::new()
        .route("/healthz", get(health))
        .route("/v1/device/{device_id}", get(device_ws))
        .with_state(state))
}

pub async fn serve(
    config: RelayConfig,
    grants: GrantStore,
    cancellation: CancellationToken,
) -> Result<(), RelayError> {
    serve_with_hub(config, grants, RelayHub::default(), cancellation).await
}

pub async fn serve_with_hub(
    config: RelayConfig,
    grants: GrantStore,
    hub: RelayHub,
    cancellation: CancellationToken,
) -> Result<(), RelayError> {
    if !config.bind.ip().is_loopback() {
        return Err(RelayError::NonLoopbackBinding(config.bind));
    }
    let router = build_router_with_hub(grants, config.replay_capacity, hub)?;
    let listener = tokio::net::TcpListener::bind(config.bind).await?;
    axum::serve(listener, router)
        .with_graceful_shutdown(async move { cancellation.cancelled_owned().await })
        .await?;
    Ok(())
}
async fn health() -> Json<serde_json::Value> {
    Json(json!({
        "status": "ok",
        "service": "vor-relay",
        "device_ingress": "websocket-protobuf",
        "remote_worker_dispatch": "read_only"
    }))
}

async fn device_ws(
    State(state): State<RelayState>,
    AxumPath(device_id): AxumPath<String>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Response {
    let Some(token) = bearer_token(headers.get(AUTHORIZATION)) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let Ok(now) = now_unix_ms() else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    match state.grants.validate(token, "relay.connect", now) {
        Ok(grant) if grant.actor_id == device_id => {
            ws.on_upgrade(move |socket| handle_device(socket, device_id, state))
        }
        _ => StatusCode::UNAUTHORIZED.into_response(),
    }
}

async fn handle_device(mut socket: WebSocket, device_id: String, state: RelayState) {
    let (outbound_tx, mut outbound_rx) = mpsc::channel::<RelayFrame>(32);
    let mut session_id: Option<u128> = None;
    let mut bound = false;

    loop {
        tokio::select! {
            outgoing = outbound_rx.recv(), if bound => {
                let Some(frame) = outgoing else { break };
                if send_frame(&mut socket, &frame).await.is_err() {
                    break;
                }
            }
            incoming = socket.recv() => {
                let Some(message) = incoming else { break };
                let Ok(message) = message else { break };
                let result = match message {
                    Message::Binary(bytes) => process_device_frame(
                        &mut socket, &device_id, &state, &outbound_tx,
                        &mut session_id, &mut bound, &bytes,
                    ).await,
                    Message::Close(_) => break,
                    Message::Ping(payload) => socket.send(Message::Pong(payload))
                        .await.map_err(|_| RelayError::WebSocket),
                    Message::Pong(_) => Ok(()),
                    _ => Err(RelayError::UnexpectedDevicePayload),
                };
                if result.is_err() {
                    let _ = socket.send(Message::Close(None)).await;
                    break;
                }
            }
        }
    }
    if let Some(session_id) = session_id {
        state.hub.unregister(&device_id, session_id).await;
    }
}

async fn process_device_frame(
    socket: &mut WebSocket,
    device_id: &str,
    state: &RelayState,
    outbound_tx: &mpsc::Sender<RelayFrame>,
    session_id: &mut Option<u128>,
    bound: &mut bool,
    bytes: &[u8],
) -> Result<(), RelayError> {
    let frame = decode_frame(bytes).map_err(|_| RelayError::InvalidFrame)?;
    if frame.device_id != device_id {
        return Err(RelayError::DeviceMismatch);
    }
    let now = now_unix_ms()?;
    {
        let mut guard = state
            .replay
            .lock()
            .map_err(|_| RelayError::ReplayPoisoned)?;
        guard
            .accept(&frame, now)
            .map_err(|_| RelayError::InvalidFrame)?;
    }

    match (*bound, frame.payload.as_ref()) {
        (false, Some(Payload::DeviceHello(hello))) if hello.device_id == device_id => {
            let id = state
                .hub
                .register(device_id.to_owned(), outbound_tx.clone())
                .await;
            *session_id = Some(id);
            *bound = true;
        }
        (false, _) => return Err(RelayError::FirstFrameMustBeHello),
        (true, Some(Payload::Heartbeat(_))) => {}
        (true, Some(Payload::DeviceHello(hello))) if hello.device_id == device_id => {}
        (true, Some(Payload::ActionResult(result))) => {
            if !state.hub.complete_result(device_id, result.clone()).await {
                return Err(RelayError::UnsolicitedResult);
            }
        }
        (true, _) => return Err(RelayError::UnexpectedDevicePayload),
    }

    let digest = frame_digest(&frame).map_err(|_| RelayError::InvalidFrame)?;
    let ack = accepted_ack(device_id, &frame.message_id, digest, now)?;
    send_frame(socket, &ack).await
}

async fn send_frame(socket: &mut WebSocket, frame: &RelayFrame) -> Result<(), RelayError> {
    let encoded = encode_frame(frame).map_err(|_| RelayError::InvalidFrame)?;
    socket
        .send(Message::Binary(encoded.into()))
        .await
        .map_err(|_| RelayError::WebSocket)
}

fn accepted_ack(
    device_id: &str,
    message_id: &str,
    payload_digest: [u8; 32],
    now_unix_ms: u64,
) -> Result<RelayFrame, RelayError> {
    let expires = now_unix_ms.checked_add(30_000).ok_or(RelayError::Clock)?;
    Ok(RelayFrame {
        wire_version: WIRE_VERSION,
        message_id: message_id.to_owned(),
        device_id: device_id.to_owned(),
        expires_at: Some(timestamp_from_ms(expires)?),
        nonce: rand::random::<[u8; 16]>().to_vec(),
        payload: Some(Payload::Ack(RelayAck {
            message_id: message_id.to_owned(),
            status: "accepted".into(),
            payload_digest: payload_digest.to_vec(),
        })),
    })
}

fn bearer_token(value: Option<&axum::http::HeaderValue>) -> Option<&str> {
    value?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
        .filter(|token| !token.is_empty())
}

fn now_unix_ms() -> Result<u64, RelayError> {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| RelayError::Clock)?;
    u64::try_from(elapsed.as_millis()).map_err(|_| RelayError::Clock)
}
fn timestamp_from_ms(value: u64) -> Result<Timestamp, RelayError> {
    let seconds = i64::try_from(value / 1000).map_err(|_| RelayError::Clock)?;
    let nanos = i32::try_from((value % 1000) * 1_000_000).map_err(|_| RelayError::Clock)?;
    Ok(Timestamp { seconds, nanos })
}

#[derive(Debug, Error)]
pub enum RelayError {
    #[error("relay may bind only to loopback before P4 deployment approval: {0}")]
    NonLoopbackBinding(SocketAddr),
    #[error("replay capacity must be positive")]
    InvalidReplayCapacity,
    #[error("relay frame failed validation")]
    InvalidFrame,
    #[error("frame device does not match authenticated connection")]
    DeviceMismatch,
    #[error("first device frame must be DeviceHello")]
    FirstFrameMustBeHello,
    #[error("device sent a payload that is not allowed on relay ingress")]
    UnexpectedDevicePayload,
    #[error("device returned an ActionResult with no matching pending request")]
    UnsolicitedResult,
    #[error("relay action request is invalid")]
    InvalidActionRequest,
    #[error("action is outside the relay read-only allowlist")]
    RemoteActionNotAllowed,
    #[error("device is not connected to the relay")]
    DeviceOffline,
    #[error("an action with this request id is already pending")]
    DuplicateRequest,
    #[error("relay action timed out")]
    ActionTimeout,
    #[error("replay guard lock is poisoned")]
    ReplayPoisoned,
    #[error("system clock is outside supported range")]
    Clock,
    #[error("relay websocket failed")]
    WebSocket,
    #[error("relay auth failed: {0}")]
    Auth(#[from] vor_auth::AuthError),
    #[error("relay I/O failed: {0}")]
    Io(#[from] io::Error),
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::{SinkExt, StreamExt};
    use tempfile::tempdir;
    use tokio_tungstenite::connect_async;
    use tokio_tungstenite::tungstenite::Message as WsMessage;
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;
    use tokio_tungstenite::tungstenite::http::HeaderValue;
    use tokio_tungstenite::tungstenite::http::header::AUTHORIZATION as WS_AUTHORIZATION;
    use vor_wire::v1::{DeviceHello, RelayHeartbeat};

    fn hello(now: u64) -> RelayFrame {
        RelayFrame {
            wire_version: WIRE_VERSION,
            message_id: "hello-1".into(),
            device_id: "device-1".into(),
            expires_at: Some(timestamp_from_ms(now + 30_000).unwrap()),
            nonce: vec![6; 16],
            payload: Some(Payload::DeviceHello(DeviceHello {
                device_id: "device-1".into(),
                agent_version: "0.1.0-test".into(),
                transports: vec!["ws-loopback-dev".into()],
                capabilities: vec!["relay.heartbeat".into()],
            })),
        }
    }

    fn heartbeat(now: u64) -> RelayFrame {
        RelayFrame {
            wire_version: WIRE_VERSION,
            message_id: "msg-1".into(),
            device_id: "device-1".into(),
            expires_at: Some(timestamp_from_ms(now + 30_000).unwrap()),
            nonce: vec![7; 16],
            payload: Some(Payload::Heartbeat(RelayHeartbeat {
                sent_at: Some(timestamp_from_ms(now).unwrap()),
            })),
        }
    }

    #[tokio::test]
    async fn serve_rejects_non_loopback_bind() {
        let dir = tempdir().unwrap();
        let store = GrantStore::open(dir.path().join("auth.json")).unwrap();
        let config = RelayConfig {
            bind: "0.0.0.0:0".parse().unwrap(),
            replay_capacity: 16,
        };
        let result = serve(config, store, CancellationToken::new()).await;
        assert!(matches!(result, Err(RelayError::NonLoopbackBinding(_))));
    }
    #[tokio::test]
    async fn authenticated_device_gets_ack_and_replay_is_closed() {
        let dir = tempdir().unwrap();
        let store = GrantStore::open(dir.path().join("auth.json")).unwrap();
        let now = now_unix_ms().unwrap();
        let grant = store
            .issue("device-1", ["relay.connect"], 60_000, now)
            .unwrap();
        let router = build_router(store, 16).unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let cancellation = CancellationToken::new();
        let shutdown = cancellation.clone();
        let task = tokio::spawn(async move {
            axum::serve(listener, router)
                .with_graceful_shutdown(async move { shutdown.cancelled_owned().await })
                .await
                .unwrap();
        });

        let url = format!("ws://{address}/v1/device/device-1");
        let mut request = url.into_client_request().unwrap();
        request.headers_mut().insert(
            WS_AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {}", grant.token())).unwrap(),
        );
        let (mut socket, _) = connect_async(request).await.unwrap();
        let hello = hello(now_unix_ms().unwrap());
        socket
            .send(WsMessage::Binary(encode_frame(&hello).unwrap().into()))
            .await
            .unwrap();
        let hello_reply = socket.next().await.unwrap().unwrap();
        let WsMessage::Binary(hello_bytes) = hello_reply else {
            panic!("expected hello ack");
        };
        let hello_ack = decode_frame(&hello_bytes).unwrap();
        let Some(Payload::Ack(hello_ack)) = hello_ack.payload else {
            panic!("expected hello ack payload");
        };
        assert_eq!(hello_ack.message_id, hello.message_id);

        let frame = heartbeat(now_unix_ms().unwrap());
        socket
            .send(WsMessage::Binary(encode_frame(&frame).unwrap().into()))
            .await
            .unwrap();
        let reply = socket.next().await.unwrap().unwrap();
        let WsMessage::Binary(bytes) = reply else {
            panic!("expected binary ack");
        };
        let ack_frame = decode_frame(&bytes).unwrap();
        let Some(Payload::Ack(ack)) = ack_frame.payload else {
            panic!("expected ack payload");
        };
        assert_eq!(ack.message_id, frame.message_id);
        assert_eq!(ack.status, "accepted");
        assert_eq!(ack.payload_digest, frame_digest(&frame).unwrap());

        socket
            .send(WsMessage::Binary(encode_frame(&frame).unwrap().into()))
            .await
            .unwrap();
        let closed = socket.next().await;
        assert!(matches!(closed, None | Some(Ok(WsMessage::Close(_)))));
        cancellation.cancel();
        task.await.unwrap();
    }
}
