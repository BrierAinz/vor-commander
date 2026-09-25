// SPDX-License-Identifier: MPL-2.0

use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use thiserror::Error;
use tokio::sync::{RwLock, mpsc, oneshot};
use tokio_stream::Stream;
use tokio_stream::wrappers::ReceiverStream;
use tokio_util::sync::CancellationToken;
use tonic::transport::{
    Certificate, Channel, ClientTlsConfig, Endpoint, Identity, Server, ServerTlsConfig,
};
use tonic::{Request, Response, Status, Streaming};
use vor_dispatch::{ReadOnlyDispatcher, remote_action_allowed, remote_approved_action_allowed};
use vor_wire::v1;
use vor_wire::v1::relay_frame::Payload;
use vor_wire::v1::{ActionResult, RelayAck, RelayFrame};
use vor_wire::{
    MAX_FRAME_BYTES, ReplayGuard, WIRE_VERSION, action_request_from_proto,
    approval_grant_from_proto, frame_digest, verify_frame_at,
};
use zeroize::Zeroize;

pub mod grpc {
    include!(concat!(env!("OUT_DIR"), "/vor.commander.v1.rs"));
}

use grpc::device_private_link_server::{DevicePrivateLink, DevicePrivateLinkServer};

pub type CertFingerprint = [u8; 32];

#[derive(Clone, Default)]
pub struct DeviceCertificateRegistry {
    fingerprints: Arc<HashMap<String, CertFingerprint>>,
}
impl DeviceCertificateRegistry {
    pub fn from_certificates(
        entries: impl IntoIterator<Item = (String, Vec<u8>)>,
    ) -> Result<Self, PrivateLinkError> {
        let mut fingerprints = HashMap::new();
        for (device_id, certificate_der) in entries {
            validate_device_id(&device_id)?;
            if certificate_der.is_empty() {
                return Err(PrivateLinkError::InvalidCertificate);
            }
            if fingerprints
                .insert(device_id, certificate_fingerprint(&certificate_der))
                .is_some()
            {
                return Err(PrivateLinkError::DuplicateDevice);
            }
        }
        Ok(Self {
            fingerprints: Arc::new(fingerprints),
        })
    }

    pub fn contains_match(&self, device_id: &str, fingerprint: &CertFingerprint) -> bool {
        self.fingerprints
            .get(device_id)
            .is_some_and(|expected| expected == fingerprint)
    }

    pub fn len(&self) -> usize {
        self.fingerprints.len()
    }

    pub fn is_empty(&self) -> bool {
        self.fingerprints.is_empty()
    }
}

pub fn certificate_fingerprint(certificate_der: &[u8]) -> CertFingerprint {
    Sha256::digest(certificate_der).into()
}

#[derive(Clone)]
struct DeviceSession {
    session_id: u128,
    sender: mpsc::Sender<Result<RelayFrame, Status>>,
}

type PendingResultMap = HashMap<(String, String), oneshot::Sender<ActionResult>>;

/// Upper bound of in-flight actions the hub keeps per device.
pub const MAX_PENDING_ACTIONS_PER_DEVICE: usize = 256;

#[derive(Clone, Default)]
pub struct PrivateLinkHub {
    devices: Arc<RwLock<HashMap<String, DeviceSession>>>,
    pending: Arc<RwLock<PendingResultMap>>,
}

impl PrivateLinkHub {
    async fn register(
        &self,
        device_id: String,
        sender: mpsc::Sender<Result<RelayFrame, Status>>,
    ) -> u128 {
        let session_id = rand::random::<u128>();
        self.devices
            .write()
            .await
            .insert(device_id, DeviceSession { session_id, sender });
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

    async fn complete_result(&self, device_id: &str, result: ActionResult) {
        let key = (device_id.to_owned(), result.request_id.clone());
        if let Some(sender) = self.pending.write().await.remove(&key) {
            let _ = sender.send(result);
        }
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
        request: v1::ActionRequest,
        timeout: Duration,
    ) -> Result<ActionResult, PrivateLinkError> {
        if request.device_id != device_id || request.request_id.trim().is_empty() {
            return Err(PrivateLinkError::InvalidActionRequest);
        }
        if !remote_action_allowed(&request.action)
            && !remote_approved_action_allowed(&request.action)
        {
            return Err(PrivateLinkError::RemoteActionNotAllowed);
        }
        let expires_at_unix_ms = request
            .expires_at
            .as_ref()
            .and_then(timestamp_to_ms)
            .ok_or(PrivateLinkError::ActionExpired)?;
        let request_id = request.request_id.clone();
        let frame = RelayFrame {
            wire_version: WIRE_VERSION,
            message_id: format!("action-{:032x}", rand::random::<u128>()),
            device_id: device_id.to_owned(),
            expires_at: request.expires_at,
            nonce: rand::random::<[u8; 16]>().to_vec(),
            payload: Some(Payload::ActionRequest(request)),
        };
        self.send_and_wait(device_id, request_id, expires_at_unix_ms, frame, timeout)
            .await
    }

    pub async fn dispatch_approved_action(
        &self,
        device_id: &str,
        request: v1::ActionRequest,
        approval: v1::ApprovalGrant,
        timeout: Duration,
    ) -> Result<ActionResult, PrivateLinkError> {
        let canonical = action_request_from_proto(&request)
            .map_err(|_| PrivateLinkError::InvalidActionRequest)?;
        let signed = approval_grant_from_proto(&approval)
            .map_err(|_| PrivateLinkError::InvalidActionRequest)?;
        if canonical.envelope.device_id != device_id
            || request.request_id.trim().is_empty()
            || signed.challenge.request_id != canonical.envelope.request_id
            || signed.challenge.envelope_digest != canonical.envelope_digest
        {
            return Err(PrivateLinkError::InvalidActionRequest);
        }
        if !remote_approved_action_allowed(&canonical.envelope.action) {
            return Err(PrivateLinkError::RemoteActionNotAllowed);
        }
        let request_id = request.request_id.clone();
        let frame = RelayFrame {
            wire_version: WIRE_VERSION,
            message_id: format!("approved-action-{:032x}", rand::random::<u128>()),
            device_id: device_id.to_owned(),
            expires_at: request.expires_at,
            nonce: rand::random::<[u8; 16]>().to_vec(),
            payload: Some(Payload::ApprovedActionRequest(v1::ApprovedActionRequest {
                request: Some(request),
                approval: Some(approval),
            })),
        };
        self.send_and_wait(
            device_id,
            request_id,
            canonical.envelope.expires_at_unix_ms,
            frame,
            timeout,
        )
        .await
    }

    /// Registers the pending slot, sends the frame and waits for the result.
    ///
    /// The caller's `timeout` bounds the whole operation, including the wait for
    /// room in the device channel, and the pending map is capped per device so a
    /// device that stops answering cannot make the hub grow without limit.
    /// Requests that are already expired never leave the hub: the device would
    /// reject the frame anyway and tear down its session while doing so.
    async fn send_and_wait(
        &self,
        device_id: &str,
        request_id: String,
        expires_at_unix_ms: u64,
        frame: RelayFrame,
        timeout: Duration,
    ) -> Result<ActionResult, PrivateLinkError> {
        if expires_at_unix_ms <= now_unix_ms()? {
            return Err(PrivateLinkError::ActionExpired);
        }
        let session = self
            .devices
            .read()
            .await
            .get(device_id)
            .cloned()
            .ok_or(PrivateLinkError::DeviceOffline)?;
        let key = (device_id.to_owned(), request_id);
        let (result_sender, result_receiver) = oneshot::channel();
        {
            let mut pending = self.pending.write().await;
            if pending.contains_key(&key) {
                return Err(PrivateLinkError::DuplicateRequest);
            }
            let in_flight = pending
                .keys()
                .filter(|(pending_device, _)| pending_device == device_id)
                .count();
            if in_flight >= MAX_PENDING_ACTIONS_PER_DEVICE {
                return Err(PrivateLinkError::TooManyPendingActions);
            }
            pending.insert(key.clone(), result_sender);
        }
        let outcome = tokio::time::timeout(timeout, async {
            session
                .sender
                .send(Ok(frame))
                .await
                .map_err(|_| PrivateLinkError::DeviceOffline)?;
            result_receiver
                .await
                .map_err(|_| PrivateLinkError::DeviceOffline)
        })
        .await;
        match outcome {
            Ok(Ok(result)) => Ok(result),
            Ok(Err(error)) => {
                self.pending.write().await.remove(&key);
                Err(error)
            }
            Err(_) => {
                self.pending.write().await.remove(&key);
                Err(PrivateLinkError::ActionTimeout)
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct PrivateLinkConfig {
    pub bind: SocketAddr,
    pub replay_capacity: usize,
}

impl Default for PrivateLinkConfig {
    fn default() -> Self {
        Self {
            bind: "127.0.0.1:8790".parse().expect("valid private link bind"),
            replay_capacity: 4096,
        }
    }
}

#[derive(Clone)]
pub struct PrivateLinkTls {
    pub ca_pem: Vec<u8>,
    pub server_cert_pem: Vec<u8>,
    pub server_key_pem: Vec<u8>,
}

#[derive(Clone)]
pub struct PrivateDeviceClientConfig {
    pub endpoint: String,
    pub server_name: String,
    pub device_id: String,
    pub ca_pem: Vec<u8>,
    pub device_cert_pem: Vec<u8>,
    pub device_key_pem: Vec<u8>,
    pub agent_version: String,
    pub heartbeat_interval: Duration,
    pub replay_capacity: usize,
}

impl fmt::Debug for PrivateDeviceClientConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateDeviceClientConfig")
            .field("endpoint", &self.endpoint)
            .field("server_name", &self.server_name)
            .field("device_id", &self.device_id)
            .field("ca_pem", &format_args!("<{} bytes>", self.ca_pem.len()))
            .field(
                "device_cert_pem",
                &format_args!("<{} bytes>", self.device_cert_pem.len()),
            )
            .field("device_key_pem", &"<redacted>")
            .field("agent_version", &self.agent_version)
            .field("heartbeat_interval", &self.heartbeat_interval)
            .field("replay_capacity", &self.replay_capacity)
            .finish()
    }
}

impl Drop for PrivateDeviceClientConfig {
    fn drop(&mut self) {
        self.device_key_pem.zeroize();
    }
}
impl PrivateDeviceClientConfig {
    fn validate(&self) -> Result<(), PrivateLinkError> {
        validate_device_id(&self.device_id)?;
        if !self.endpoint.starts_with("https://")
            || self.server_name.trim().is_empty()
            || self.ca_pem.is_empty()
            || self.device_cert_pem.is_empty()
            || self.device_key_pem.is_empty()
            || self.heartbeat_interval.is_zero()
            || self.replay_capacity == 0
        {
            return Err(PrivateLinkError::InvalidClientConfig);
        }
        Ok(())
    }
}

#[derive(Clone)]
pub struct PrivateLinkService {
    registry: DeviceCertificateRegistry,
    replay: Arc<Mutex<ReplayGuard>>,
    hub: PrivateLinkHub,
}

impl PrivateLinkService {
    pub fn new(
        registry: DeviceCertificateRegistry,
        replay_capacity: usize,
    ) -> Result<Self, PrivateLinkError> {
        Self::with_hub(registry, replay_capacity, PrivateLinkHub::default())
    }

    pub fn with_hub(
        registry: DeviceCertificateRegistry,
        replay_capacity: usize,
        hub: PrivateLinkHub,
    ) -> Result<Self, PrivateLinkError> {
        if registry.is_empty() {
            return Err(PrivateLinkError::EmptyRegistry);
        }
        let replay = ReplayGuard::new(replay_capacity)
            .map_err(|_| PrivateLinkError::InvalidReplayCapacity)?;
        Ok(Self {
            registry,
            replay: Arc::new(Mutex::new(replay)),
            hub,
        })
    }

    pub fn hub(&self) -> PrivateLinkHub {
        self.hub.clone()
    }
}
#[tonic::async_trait]
impl DevicePrivateLink for PrivateLinkService {
    type ConnectStream = Pin<Box<dyn Stream<Item = Result<RelayFrame, Status>> + Send + 'static>>;

    async fn connect(
        &self,
        request: Request<Streaming<RelayFrame>>,
    ) -> Result<Response<Self::ConnectStream>, Status> {
        let peer_certs = request
            .peer_certs()
            .ok_or_else(|| Status::unauthenticated("client certificate required"))?;
        let leaf = peer_certs
            .first()
            .ok_or_else(|| Status::unauthenticated("client certificate required"))?;
        let peer_fingerprint = certificate_fingerprint(leaf.as_ref());
        let mut inbound = request.into_inner();
        let registry = self.registry.clone();
        let replay = self.replay.clone();
        let hub = self.hub.clone();
        let (sender, receiver) = mpsc::channel(32);

        tokio::spawn(async move {
            let mut bound_device: Option<String> = None;
            let mut session_id: Option<u128> = None;
            loop {
                let next = inbound.message().await;
                let frame = match next {
                    Ok(Some(frame)) => frame,
                    Ok(None) => break,
                    Err(status) => {
                        let _ = sender.send(Err(status)).await;
                        break;
                    }
                };
                match process_private_frame(
                    &frame,
                    &peer_fingerprint,
                    &registry,
                    &replay,
                    &mut bound_device,
                ) {
                    Ok(ack) => {
                        if session_id.is_none()
                            && let Some(device_id) = bound_device.as_ref()
                        {
                            session_id =
                                Some(hub.register(device_id.clone(), sender.clone()).await);
                        }
                        if let (Some(device_id), Some(Payload::ActionResult(result))) =
                            (bound_device.as_ref(), frame.payload.as_ref())
                        {
                            hub.complete_result(device_id, result.clone()).await;
                        }
                        if sender.send(Ok(ack)).await.is_err() {
                            break;
                        }
                    }
                    Err(status) => {
                        let _ = sender.send(Err(status)).await;
                        break;
                    }
                }
            }
            if let (Some(device_id), Some(session_id)) = (bound_device.as_ref(), session_id) {
                hub.unregister(device_id, session_id).await;
            }
        });

        Ok(Response::new(Box::pin(ReceiverStream::new(receiver))))
    }
}
fn process_private_frame(
    frame: &RelayFrame,
    peer_fingerprint: &CertFingerprint,
    registry: &DeviceCertificateRegistry,
    replay: &Arc<Mutex<ReplayGuard>>,
    bound_device: &mut Option<String>,
) -> Result<RelayFrame, Status> {
    let now = now_unix_ms().map_err(|_| Status::internal("clock failure"))?;
    verify_frame_at(frame, now).map_err(|_| Status::invalid_argument("invalid relay frame"))?;

    match (&bound_device, frame.payload.as_ref()) {
        (None, Some(Payload::DeviceHello(hello))) => {
            if hello.device_id != frame.device_id {
                return Err(Status::permission_denied("device identity mismatch"));
            }
            if !registry.contains_match(&frame.device_id, peer_fingerprint) {
                return Err(Status::permission_denied(
                    "certificate not registered for device",
                ));
            }
            *bound_device = Some(frame.device_id.clone());
        }
        (None, _) => {
            return Err(Status::failed_precondition(
                "first frame must be DeviceHello",
            ));
        }
        (Some(device_id), Some(Payload::Heartbeat(_))) if device_id == &frame.device_id => {}
        (Some(device_id), Some(Payload::DeviceHello(hello)))
            if device_id == &frame.device_id && hello.device_id == frame.device_id => {}
        (Some(device_id), Some(Payload::ActionResult(result)))
            if device_id == &frame.device_id && !result.request_id.trim().is_empty() => {}
        (Some(_), Some(Payload::ActionRequest(_)))
        | (Some(_), Some(Payload::ApprovedActionRequest(_)))
        | (Some(_), Some(Payload::ApprovalGrant(_)))
        | (Some(_), Some(Payload::PolicyDecision(_))) => {
            return Err(Status::unimplemented("inbound control frame is disabled"));
        }
        (Some(_), _) => {
            return Err(Status::permission_denied("stream device identity changed"));
        }
    }

    {
        let mut guard = replay
            .lock()
            .map_err(|_| Status::internal("replay guard unavailable"))?;
        guard
            .accept(frame, now)
            .map_err(|_| Status::already_exists("replayed or invalid relay frame"))?;
    }
    private_ack(frame, now).map_err(|_| Status::internal("ack creation failed"))
}
fn private_ack(frame: &RelayFrame, now_unix_ms: u64) -> Result<RelayFrame, PrivateLinkError> {
    let expires_at = now_unix_ms
        .checked_add(30_000)
        .ok_or(PrivateLinkError::Clock)?;
    Ok(RelayFrame {
        wire_version: WIRE_VERSION,
        message_id: frame.message_id.clone(),
        device_id: frame.device_id.clone(),
        expires_at: Some(timestamp_from_ms(expires_at)?),
        nonce: rand::random::<[u8; 16]>().to_vec(),
        payload: Some(Payload::Ack(RelayAck {
            message_id: frame.message_id.clone(),
            status: "accepted".into(),
            payload_digest: frame_digest(frame)?.to_vec(),
        })),
    })
}

pub async fn run_device_dispatch(
    config: PrivateDeviceClientConfig,
    dispatcher: Arc<Mutex<ReadOnlyDispatcher>>,
    cancellation: CancellationToken,
) -> Result<(), PrivateLinkError> {
    config.validate()?;
    let tls = ClientTlsConfig::new()
        .domain_name(config.server_name.clone())
        .ca_certificate(Certificate::from_pem(config.ca_pem.clone()))
        .identity(Identity::from_pem(
            config.device_cert_pem.clone(),
            config.device_key_pem.clone(),
        ));
    let channel: Channel = Endpoint::from_shared(config.endpoint.clone())?
        .tls_config(tls)?
        .connect()
        .await?;
    let mut client = grpc::device_private_link_client::DevicePrivateLinkClient::new(channel)
        .max_decoding_message_size(MAX_FRAME_BYTES)
        .max_encoding_message_size(MAX_FRAME_BYTES);
    let (sender, receiver) = mpsc::channel(32);
    let response = client.connect(ReceiverStream::new(receiver)).await?;
    let mut inbound = response.into_inner();
    let hello = device_outbound_frame(
        &config.device_id,
        Payload::DeviceHello(v1::DeviceHello {
            device_id: config.device_id.clone(),
            agent_version: config.agent_version.clone(),
            transports: vec!["grpc+mtls".into()],
            capabilities: vec![
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
    )?;
    sender
        .send(hello.clone())
        .await
        .map_err(|_| PrivateLinkError::ClientChannelClosed)?;
    let first = inbound
        .message()
        .await?
        .ok_or(PrivateLinkError::ClientChannelClosed)?;
    verify_server_ack(&first, &hello, &config.device_id)?;

    let mut replay = ReplayGuard::new(config.replay_capacity)
        .map_err(|_| PrivateLinkError::InvalidReplayCapacity)?;
    let mut heartbeat = tokio::time::interval(config.heartbeat_interval);
    heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    heartbeat.tick().await;
    loop {
        tokio::select! {
            _ = cancellation.cancelled() => return Ok(()),
            _ = heartbeat.tick() => {
                let sent_at = now_unix_ms()?;
                let frame = device_outbound_frame(
                    &config.device_id,
                    Payload::Heartbeat(v1::RelayHeartbeat {
                        sent_at: Some(timestamp_from_ms(sent_at)?),
                    }),
                )?;
                sender.send(frame).await.map_err(|_| PrivateLinkError::ClientChannelClosed)?;
            }
            incoming = inbound.message() => {
                let frame = incoming?.ok_or(PrivateLinkError::ClientChannelClosed)?;
                let now = now_unix_ms()?;
                verify_frame_at(&frame, now)
                    .map_err(|_| PrivateLinkError::InvalidServerFrame)?;
                if frame.device_id != config.device_id {
                    return Err(PrivateLinkError::InvalidServerFrame);
                }
                replay.accept(&frame, now)
                    .map_err(|_| PrivateLinkError::InvalidServerFrame)?;
                match frame.payload {
                    Some(Payload::Ack(_)) => {}
                    Some(Payload::ActionRequest(request)) => {
                        let local_dispatcher = dispatcher.clone();
                        let result = tokio::task::spawn_blocking(move || {
                            let mut dispatcher = lock_dispatcher(&local_dispatcher);
                            Ok::<_, PrivateLinkError>(dispatcher.dispatch_proto_report(&request)?)
                        }).await??;
                        let result_frame = device_outbound_frame(
                            &config.device_id,
                            Payload::ActionResult(result),
                        )?;
                        sender.send(result_frame).await
                            .map_err(|_| PrivateLinkError::ClientChannelClosed)?;
                    }
                    Some(Payload::ApprovedActionRequest(approved)) => {
                        let local_dispatcher = dispatcher.clone();
                        let result = tokio::task::spawn_blocking(move || {
                            let mut dispatcher = lock_dispatcher(&local_dispatcher);
                            Ok::<_, PrivateLinkError>(
                                dispatcher.dispatch_approved_proto_report(&approved)?
                            )
                        }).await??;
                        let result_frame = device_outbound_frame(
                            &config.device_id,
                            Payload::ActionResult(result),
                        )?;
                        sender.send(result_frame).await
                            .map_err(|_| PrivateLinkError::ClientChannelClosed)?;
                    }
                    _ => return Err(PrivateLinkError::InvalidServerFrame),
                }
            }
        }
    }
}

pub async fn run_device_dispatch_until_cancelled(
    config: PrivateDeviceClientConfig,
    dispatcher: Arc<Mutex<ReadOnlyDispatcher>>,
    cancellation: CancellationToken,
) -> Result<(), PrivateLinkError> {
    config.validate()?;
    let mut attempt = 0u32;

    loop {
        if cancellation.is_cancelled() {
            return Ok(());
        }

        match run_device_dispatch(config.clone(), dispatcher.clone(), cancellation.clone()).await {
            Ok(()) => return Ok(()),
            Err(_) if cancellation.is_cancelled() => return Ok(()),
            Err(_) => {
                let shift = attempt.min(4);
                let delay_ms = 250u64.saturating_mul(1u64 << shift).min(5_000);
                attempt = attempt.saturating_add(1);
                tokio::select! {
                    _ = cancellation.cancelled() => return Ok(()),
                    _ = tokio::time::sleep(Duration::from_millis(delay_ms)) => {}
                }
            }
        }
    }
}

fn device_outbound_frame(
    device_id: &str,
    payload: Payload,
) -> Result<RelayFrame, PrivateLinkError> {
    let now = now_unix_ms()?;
    Ok(RelayFrame {
        wire_version: WIRE_VERSION,
        message_id: format!("device-{:032x}", rand::random::<u128>()),
        device_id: device_id.to_owned(),
        expires_at: Some(timestamp_from_ms(
            now.checked_add(30_000).ok_or(PrivateLinkError::Clock)?,
        )?),
        nonce: rand::random::<[u8; 16]>().to_vec(),
        payload: Some(payload),
    })
}

fn verify_server_ack(
    frame: &RelayFrame,
    original: &RelayFrame,
    device_id: &str,
) -> Result<(), PrivateLinkError> {
    let now = now_unix_ms()?;
    verify_frame_at(frame, now).map_err(|_| PrivateLinkError::InvalidServerFrame)?;
    if frame.device_id != device_id {
        return Err(PrivateLinkError::InvalidServerFrame);
    }
    let Some(Payload::Ack(ack)) = frame.payload.as_ref() else {
        return Err(PrivateLinkError::InvalidServerFrame);
    };
    if ack.message_id != original.message_id
        || ack.payload_digest != frame_digest(original)?.to_vec()
        || ack.status != "accepted"
    {
        return Err(PrivateLinkError::InvalidServerFrame);
    }
    Ok(())
}

pub async fn serve(
    config: PrivateLinkConfig,
    tls: PrivateLinkTls,
    registry: DeviceCertificateRegistry,
    cancellation: CancellationToken,
) -> Result<(), PrivateLinkError> {
    serve_with_hub(
        config,
        tls,
        registry,
        PrivateLinkHub::default(),
        cancellation,
    )
    .await
}

pub async fn serve_with_hub(
    config: PrivateLinkConfig,
    tls: PrivateLinkTls,
    registry: DeviceCertificateRegistry,
    hub: PrivateLinkHub,
    cancellation: CancellationToken,
) -> Result<(), PrivateLinkError> {
    if !config.bind.ip().is_loopback() {
        return Err(PrivateLinkError::NonLoopbackBinding(config.bind));
    }
    let service = PrivateLinkService::with_hub(registry, config.replay_capacity, hub)?;
    let tls_config = ServerTlsConfig::new()
        .identity(Identity::from_pem(tls.server_cert_pem, tls.server_key_pem))
        .client_ca_root(Certificate::from_pem(tls.ca_pem));
    let grpc = DevicePrivateLinkServer::new(service)
        .max_decoding_message_size(MAX_FRAME_BYTES)
        .max_encoding_message_size(MAX_FRAME_BYTES);
    Server::builder()
        .tls_config(tls_config)?
        .add_service(grpc)
        .serve_with_shutdown(config.bind, async move {
            cancellation.cancelled_owned().await;
        })
        .await?;
    Ok(())
}
fn now_unix_ms() -> Result<u64, PrivateLinkError> {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| PrivateLinkError::Clock)?;
    u64::try_from(elapsed.as_millis()).map_err(|_| PrivateLinkError::Clock)
}

fn timestamp_from_ms(value: u64) -> Result<prost_types::Timestamp, PrivateLinkError> {
    let seconds = i64::try_from(value / 1000).map_err(|_| PrivateLinkError::Clock)?;
    let nanos = i32::try_from((value % 1000) * 1_000_000).map_err(|_| PrivateLinkError::Clock)?;
    Ok(prost_types::Timestamp { seconds, nanos })
}

fn timestamp_to_ms(value: &prost_types::Timestamp) -> Option<u64> {
    let seconds = u64::try_from(value.seconds).ok()?;
    let nanos = u64::try_from(value.nanos).ok()?;
    seconds.checked_mul(1000)?.checked_add(nanos / 1_000_000)
}

/// Device identifiers are map keys and certificate subjects today, but they are
/// also the kind of value that ends up in a file name or a URL path. Only accept
/// identifiers that cannot alias a path segment (`.`, `..`, `.hidden`,
/// `name.`) or a reserved Windows device name (`CON`, `NUL.txt`, `COM1`).
fn validate_device_id(value: &str) -> Result<(), PrivateLinkError> {
    let bytes = value.as_bytes();
    let (Some(first), Some(last)) = (bytes.first(), bytes.last()) else {
        return Err(PrivateLinkError::InvalidDeviceId);
    };
    if value.len() > 128
        || !first.is_ascii_alphanumeric()
        || !last.is_ascii_alphanumeric()
        || value.contains("..")
        || !bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        || is_reserved_windows_name(value)
    {
        return Err(PrivateLinkError::InvalidDeviceId);
    }
    Ok(())
}

fn is_reserved_windows_name(value: &str) -> bool {
    let stem = value
        .split('.')
        .next()
        .unwrap_or(value)
        .to_ascii_uppercase();
    matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || (stem.len() == 4
            && (stem.starts_with("COM") || stem.starts_with("LPT"))
            && matches!(stem.as_bytes()[3], b'1'..=b'9'))
}

/// A panic while the dispatcher lock is held must not brick the device. The
/// one-shot guarantees (approval claims, execution recovery state) live in the
/// on-disk ledger, not in the in-memory dispatcher, so recovering the guard
/// cannot re-enable a consumed approval.
fn lock_dispatcher(
    dispatcher: &Mutex<ReadOnlyDispatcher>,
) -> std::sync::MutexGuard<'_, ReadOnlyDispatcher> {
    dispatcher.lock().unwrap_or_else(|poisoned| {
        dispatcher.clear_poison();
        poisoned.into_inner()
    })
}

#[derive(Debug, Error)]
pub enum PrivateLinkError {
    #[error("private gRPC link may bind only to loopback before deployment approval: {0}")]
    NonLoopbackBinding(SocketAddr),
    #[error("device certificate registry is empty")]
    EmptyRegistry,
    #[error("device id is invalid")]
    InvalidDeviceId,
    #[error("device certificate is invalid")]
    InvalidCertificate,
    #[error("device is already registered")]
    DuplicateDevice,
    #[error("replay capacity must be positive")]
    InvalidReplayCapacity,
    #[error("action request is invalid for this device")]
    InvalidActionRequest,
    #[error("action is outside the private remote read-only allowlist")]
    RemoteActionNotAllowed,
    #[error("device is not connected")]
    DeviceOffline,
    #[error("request id is already pending for this device")]
    DuplicateRequest,
    #[error("remote action timed out")]
    ActionTimeout,
    #[error("action request is expired or has no expiry")]
    ActionExpired,
    #[error("too many actions are already pending for this device")]
    TooManyPendingActions,
    #[error("private device client configuration is invalid")]
    InvalidClientConfig,
    #[error("private device stream closed")]
    ClientChannelClosed,
    #[error("private server frame is invalid")]
    InvalidServerFrame,
    #[error("local dispatcher lock is unavailable")]
    DispatcherUnavailable,
    #[error("local dispatch failed: {0}")]
    Dispatch(#[from] vor_dispatch::DispatchError),
    #[error("gRPC request failed: {0}")]
    GrpcStatus(#[from] tonic::Status),
    #[error("dispatcher task failed: {0}")]
    TaskJoin(#[from] tokio::task::JoinError),
    #[error("system clock is outside supported range")]
    Clock,
    #[error("wire frame failed: {0}")]
    Wire(#[from] vor_wire::WireError),
    #[error("gRPC transport failed: {0}")]
    Transport(#[from] tonic::transport::Error),
    #[error("private link I/O failed: {0}")]
    Io(#[from] io::Error),
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use ed25519_dalek::SigningKey;
    use std::collections::BTreeMap;
    use std::path::{Path, PathBuf};
    use std::time::Duration;
    use tempfile::tempdir;
    use tokio::sync::mpsc as tokio_mpsc;
    use tokio_stream::wrappers::TcpListenerStream;
    use tonic::transport::{Channel, ClientTlsConfig, Endpoint};
    use vor_approval::{ApprovalChallenge, sign_approval};
    use vor_dispatch::{DEFAULT_MAX_OUTPUT_BYTES, DispatchConfig, ReadOnlyDispatcher};
    use vor_identity::{
        CertificateAuthority, certificate_der_to_pem, create_device_enrollment,
        private_key_der_to_pem,
    };
    use vor_protocol::{ActionEnvelope, ActionRequest, PolicyDecision, PolicyDecisionKind};
    use vor_secrets::FileSecretStore;
    use vor_wire::v1::{DeviceHello, RelayHeartbeat};
    use vor_wire::{action_request_to_proto, approval_grant_to_proto};

    struct MtlsFixture {
        ca_pem: String,
        server_cert_pem: String,
        server_key_pem: String,
        device_cert_der: Vec<u8>,
        device_cert_pem: String,
        device_key_pem: String,
        _dir: tempfile::TempDir,
    }

    fn mtls_fixture(device_id: &str) -> MtlsFixture {
        let dir = tempdir().unwrap();
        let store = FileSecretStore::open(dir.path()).unwrap();
        let enrollment = create_device_enrollment(&store, "device-key", device_id).unwrap();
        let ca = CertificateAuthority::new("Vör Private Link Test CA").unwrap();
        let ca_der = ca.certificate_der();
        let device_cert_der = ca.sign_device_csr(device_id, &enrollment.csr_der).unwrap();
        let key_der = store.get("device-key").unwrap().into_vec();
        let server = ca.issue_server_certificate("localhost").unwrap();
        let (server_cert_der, server_key_der) = server.into_parts();
        MtlsFixture {
            ca_pem: certificate_der_to_pem(&ca_der),
            server_cert_pem: certificate_der_to_pem(&server_cert_der),
            server_key_pem: private_key_der_to_pem(&server_key_der),
            device_cert_pem: certificate_der_to_pem(&device_cert_der),
            device_key_pem: private_key_der_to_pem(&key_der),
            device_cert_der,
            _dir: dir,
        }
    }
    async fn spawn_server(
        fixture: &MtlsFixture,
        registered_device: &str,
    ) -> (SocketAddr, CancellationToken, tokio::task::JoinHandle<()>) {
        let registry = DeviceCertificateRegistry::from_certificates([(
            registered_device.to_owned(),
            fixture.device_cert_der.clone(),
        )])
        .unwrap();
        let service = PrivateLinkService::new(registry, 64).unwrap();
        let tls = ServerTlsConfig::new()
            .identity(Identity::from_pem(
                fixture.server_cert_pem.clone(),
                fixture.server_key_pem.clone(),
            ))
            .client_ca_root(Certificate::from_pem(fixture.ca_pem.clone()));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let incoming = TcpListenerStream::new(listener);
        let cancellation = CancellationToken::new();
        let shutdown = cancellation.clone();
        let grpc = DevicePrivateLinkServer::new(service)
            .max_decoding_message_size(MAX_FRAME_BYTES)
            .max_encoding_message_size(MAX_FRAME_BYTES);
        let task = tokio::spawn(async move {
            Server::builder()
                .tls_config(tls)
                .unwrap()
                .add_service(grpc)
                .serve_with_incoming_shutdown(incoming, async move {
                    shutdown.cancelled_owned().await;
                })
                .await
                .unwrap();
        });
        (address, cancellation, task)
    }

    async fn connect_client(
        fixture: &MtlsFixture,
        address: SocketAddr,
    ) -> grpc::device_private_link_client::DevicePrivateLinkClient<Channel> {
        let tls = ClientTlsConfig::new()
            .domain_name("localhost")
            .ca_certificate(Certificate::from_pem(fixture.ca_pem.clone()))
            .identity(Identity::from_pem(
                fixture.device_cert_pem.clone(),
                fixture.device_key_pem.clone(),
            ));
        let channel = Endpoint::from_shared(format!("https://{address}"))
            .unwrap()
            .tls_config(tls)
            .unwrap()
            .connect()
            .await
            .unwrap();
        grpc::device_private_link_client::DevicePrivateLinkClient::new(channel)
            .max_decoding_message_size(MAX_FRAME_BYTES)
            .max_encoding_message_size(MAX_FRAME_BYTES)
    }
    fn test_frame(device_id: &str, message_id: &str, nonce: u8, payload: Payload) -> RelayFrame {
        let now = now_unix_ms().unwrap();
        RelayFrame {
            wire_version: WIRE_VERSION,
            message_id: message_id.into(),
            device_id: device_id.into(),
            expires_at: Some(timestamp_from_ms(now + 30_000).unwrap()),
            nonce: vec![nonce; 16],
            payload: Some(payload),
        }
    }

    fn hello_frame(device_id: &str) -> RelayFrame {
        test_frame(
            device_id,
            "hello-1",
            1,
            Payload::DeviceHello(DeviceHello {
                device_id: device_id.into(),
                agent_version: "0.1.0".into(),
                transports: vec!["grpc+mtls".into()],
                capabilities: vec!["relay.heartbeat".into()],
            }),
        )
    }

    fn heartbeat_frame(device_id: &str) -> RelayFrame {
        let now = now_unix_ms().unwrap();
        test_frame(
            device_id,
            "heartbeat-1",
            2,
            Payload::Heartbeat(RelayHeartbeat {
                sent_at: Some(timestamp_from_ms(now).unwrap()),
            }),
        )
    }

    fn assert_ack(ack_frame: RelayFrame, original: &RelayFrame) {
        let Some(Payload::Ack(ack)) = ack_frame.payload else {
            panic!("expected ack payload");
        };
        assert_eq!(ack.message_id, original.message_id);
        assert_eq!(ack.status, "accepted");
        assert_eq!(ack.payload_digest, frame_digest(original).unwrap());
    }
    #[tokio::test]
    async fn mtls_private_link_binds_certificate_to_device_and_acks_heartbeat() {
        let fixture = mtls_fixture("device-1");
        let (address, cancellation, server_task) = spawn_server(&fixture, "device-1").await;
        let mut client = connect_client(&fixture, address).await;
        let (sender, receiver) = tokio_mpsc::channel(8);
        let response = client.connect(ReceiverStream::new(receiver)).await.unwrap();
        let mut inbound = response.into_inner();

        let hello = hello_frame("device-1");
        sender.send(hello.clone()).await.unwrap();
        assert_ack(inbound.message().await.unwrap().unwrap(), &hello);

        let heartbeat = heartbeat_frame("device-1");
        sender.send(heartbeat.clone()).await.unwrap();
        assert_ack(inbound.message().await.unwrap().unwrap(), &heartbeat);

        drop(sender);
        cancellation.cancel();
        tokio::time::timeout(Duration::from_secs(2), server_task)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn valid_ca_certificate_cannot_claim_an_unregistered_device() {
        let fixture = mtls_fixture("device-1");
        let (address, cancellation, server_task) = spawn_server(&fixture, "device-1").await;
        let mut client = connect_client(&fixture, address).await;
        let (sender, receiver) = tokio_mpsc::channel(4);
        let response = client.connect(ReceiverStream::new(receiver)).await.unwrap();
        let mut inbound = response.into_inner();

        sender.send(hello_frame("device-2")).await.unwrap();
        let error = inbound.message().await.unwrap_err();
        assert_eq!(error.code(), tonic::Code::PermissionDenied);

        cancellation.cancel();
        tokio::time::timeout(Duration::from_secs(2), server_task)
            .await
            .unwrap()
            .unwrap();
    }
    #[test]
    fn action_request_is_not_enabled_by_transport_alone() {
        let fixture = mtls_fixture("device-1");
        let registry = DeviceCertificateRegistry::from_certificates([(
            "device-1".to_owned(),
            fixture.device_cert_der.clone(),
        )])
        .unwrap();
        let replay = Arc::new(Mutex::new(ReplayGuard::new(16).unwrap()));
        let fingerprint = certificate_fingerprint(&fixture.device_cert_der);
        let mut bound = Some("device-1".to_owned());
        let action = test_frame(
            "device-1",
            "action-1",
            9,
            Payload::ActionRequest(vor_wire::v1::ActionRequest::default()),
        );
        let error = process_private_frame(&action, &fingerprint, &registry, &replay, &mut bound)
            .unwrap_err();
        assert_eq!(error.code(), tonic::Code::Unimplemented);
    }

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
policy_id: private-dispatch-test
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

    fn remote_request(action: &str, target: &str) -> v1::ActionRequest {
        let now = now_unix_ms().unwrap();
        let request = ActionRequest::seal(ActionEnvelope {
            request_id: format!("req-{:032x}", rand::random::<u128>()),
            organization_id: "org-1".into(),
            actor_id: "gateway-test".into(),
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
        Sha256::digest(content)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }

    fn approved_write_request(
        target: &Path,
        content: &[u8],
        expected_target: &[u8],
        signing: &SigningKey,
    ) -> (v1::ActionRequest, v1::ApprovalGrant) {
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
            actor_id: "gateway-test".into(),
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
            policy_id: "private-dispatch-test".into(),
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
        signing: &SigningKey,
    ) -> (v1::ActionRequest, v1::ApprovalGrant) {
        let now = now_unix_ms().unwrap();
        let mut parameters = BTreeMap::new();
        parameters.insert("argv".into(), serde_json::json!(["where.exe", "cmd.exe"]));
        parameters.insert("timeout_ms".into(), serde_json::Value::from(5_000u64));
        parameters.insert(
            "max_output_bytes".into(),
            serde_json::Value::from(64 * 1024u64),
        );
        parameters.insert("columns".into(), serde_json::Value::from(80u64));
        parameters.insert("rows".into(), serde_json::Value::from(25u64));
        let request = ActionRequest::seal(ActionEnvelope {
            request_id: format!("req-terminal-{:032x}", rand::random::<u128>()),
            organization_id: "org-1".into(),
            actor_id: "gateway-test".into(),
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
            policy_id: "private-dispatch-test".into(),
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

    fn terminal_poll_request(session_id: &str) -> v1::ActionRequest {
        let now = now_unix_ms().unwrap();
        let request = ActionRequest::seal(ActionEnvelope {
            request_id: format!("req-poll-{:032x}", rand::random::<u128>()),
            organization_id: "org-1".into(),
            actor_id: "gateway-test".into(),
            device_id: "device-1".into(),
            action: "terminal.poll".into(),
            target: session_id.into(),
            parameters: BTreeMap::new(),
            requested_capabilities: vec![],
            expires_at_unix_ms: now + 30_000,
            nonce: rand::random::<[u8; 16]>().to_vec(),
        })
        .unwrap();
        action_request_to_proto(&request).unwrap()
    }

    async fn spawn_server_with_hub(
        fixture: &MtlsFixture,
    ) -> (
        SocketAddr,
        PrivateLinkHub,
        CancellationToken,
        tokio::task::JoinHandle<()>,
    ) {
        let registry = DeviceCertificateRegistry::from_certificates([(
            "device-1".to_owned(),
            fixture.device_cert_der.clone(),
        )])
        .unwrap();
        let hub = PrivateLinkHub::default();
        let service = PrivateLinkService::with_hub(registry, 64, hub.clone()).unwrap();
        let tls = ServerTlsConfig::new()
            .identity(Identity::from_pem(
                fixture.server_cert_pem.clone(),
                fixture.server_key_pem.clone(),
            ))
            .client_ca_root(Certificate::from_pem(fixture.ca_pem.clone()));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let incoming = TcpListenerStream::new(listener);
        let cancellation = CancellationToken::new();
        let shutdown = cancellation.clone();
        let grpc = DevicePrivateLinkServer::new(service)
            .max_decoding_message_size(MAX_FRAME_BYTES)
            .max_encoding_message_size(MAX_FRAME_BYTES);
        let task = tokio::spawn(async move {
            Server::builder()
                .tls_config(tls)
                .unwrap()
                .add_service(grpc)
                .serve_with_incoming_shutdown(incoming, async move {
                    shutdown.cancelled_owned().await;
                })
                .await
                .unwrap();
        });
        (address, hub, cancellation, task)
    }

    async fn spawn_server_with_hub_on(
        fixture: &MtlsFixture,
        address: SocketAddr,
    ) -> (
        PrivateLinkHub,
        CancellationToken,
        tokio::task::JoinHandle<()>,
    ) {
        let registry = DeviceCertificateRegistry::from_certificates([(
            "device-1".to_owned(),
            fixture.device_cert_der.clone(),
        )])
        .unwrap();
        let hub = PrivateLinkHub::default();
        let service = PrivateLinkService::with_hub(registry, 64, hub.clone()).unwrap();
        let tls = ServerTlsConfig::new()
            .identity(Identity::from_pem(
                fixture.server_cert_pem.clone(),
                fixture.server_key_pem.clone(),
            ))
            .client_ca_root(Certificate::from_pem(fixture.ca_pem.clone()));
        let listener = tokio::net::TcpListener::bind(address).await.unwrap();
        let incoming = TcpListenerStream::new(listener);
        let cancellation = CancellationToken::new();
        let shutdown = cancellation.clone();
        let grpc = DevicePrivateLinkServer::new(service)
            .max_decoding_message_size(MAX_FRAME_BYTES)
            .max_encoding_message_size(MAX_FRAME_BYTES);
        let task = tokio::spawn(async move {
            Server::builder()
                .tls_config(tls)
                .unwrap()
                .add_service(grpc)
                .serve_with_incoming_shutdown(incoming, async move {
                    shutdown.cancelled_owned().await;
                })
                .await
                .unwrap();
        });
        (hub, cancellation, task)
    }

    #[tokio::test]
    async fn reconnecting_private_dispatch_recovers_when_server_becomes_available() {
        let roundtrip_timeout = Duration::from_secs(120);
        let fixture = mtls_fixture("device-1");
        let data = tempdir().unwrap();
        let file = data.path().join("reconnect.txt");
        std::fs::write(&file, b"reconnected").unwrap();
        let dispatcher = test_dispatcher(data.path());

        let probe = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = probe.local_addr().unwrap();
        drop(probe);

        let client_cancel = CancellationToken::new();
        let client_config = PrivateDeviceClientConfig {
            endpoint: format!("https://{address}"),
            server_name: "localhost".into(),
            device_id: "device-1".into(),
            ca_pem: fixture.ca_pem.as_bytes().to_vec(),
            device_cert_pem: fixture.device_cert_pem.as_bytes().to_vec(),
            device_key_pem: fixture.device_key_pem.as_bytes().to_vec(),
            agent_version: "0.1.0-reconnect-test".into(),
            heartbeat_interval: Duration::from_millis(100),
            replay_capacity: 64,
        };
        let client_shutdown = client_cancel.clone();
        let client_dispatcher = dispatcher.clone();
        let client_task = tokio::spawn(async move {
            run_device_dispatch_until_cancelled(client_config, client_dispatcher, client_shutdown)
                .await
        });

        tokio::time::sleep(Duration::from_millis(600)).await;
        assert!(!client_task.is_finished());

        let (hub, server_cancel, server_task) = spawn_server_with_hub_on(&fixture, address).await;

        tokio::time::timeout(roundtrip_timeout, async {
            loop {
                if hub.connected_devices().await == vec!["device-1".to_owned()] {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap();

        let result = hub
            .dispatch_action(
                "device-1",
                remote_request("filesystem.read", &file.to_string_lossy()),
                roundtrip_timeout,
            )
            .await
            .unwrap();
        assert_eq!(result.status, "ok");
        assert_eq!(result.output, b"reconnected");

        client_cancel.cancel();
        tokio::time::timeout(roundtrip_timeout, client_task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        server_cancel.cancel();
        tokio::time::timeout(roundtrip_timeout, server_task)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn read_only_dispatch_roundtrip_over_mtls() {
        // These bounds only keep a broken test from hanging; transport latency is
        // not part of the behavior asserted by this end-to-end correctness test.
        let roundtrip_timeout = Duration::from_secs(120);
        let fixture = mtls_fixture("device-1");
        let data = tempdir().unwrap();
        let file = data.path().join("remote.txt");
        std::fs::write(&file, b"mtls-dispatch-ok").unwrap();
        let write_target = data.path().join("approved-write.txt");
        std::fs::write(&write_target, b"before").unwrap();
        let signing = SigningKey::from_bytes(&[21; 32]);
        let dispatcher = test_dispatcher(data.path());
        dispatcher
            .lock()
            .unwrap()
            .add_trusted_approver("operator-1", signing.verifying_key().to_bytes())
            .unwrap();
        let (address, hub, server_cancel, server_task) = spawn_server_with_hub(&fixture).await;
        let client_cancel = CancellationToken::new();
        let client_config = PrivateDeviceClientConfig {
            endpoint: format!("https://{address}"),
            server_name: "localhost".into(),
            device_id: "device-1".into(),
            ca_pem: fixture.ca_pem.as_bytes().to_vec(),
            device_cert_pem: fixture.device_cert_pem.as_bytes().to_vec(),
            device_key_pem: fixture.device_key_pem.as_bytes().to_vec(),
            agent_version: "0.1.0-test".into(),
            heartbeat_interval: Duration::from_secs(30),
            replay_capacity: 64,
        };
        let client_shutdown = client_cancel.clone();
        let client_dispatcher = dispatcher.clone();
        let client_task = tokio::spawn(async move {
            run_device_dispatch(client_config, client_dispatcher, client_shutdown).await
        });

        tokio::time::timeout(roundtrip_timeout, async {
            loop {
                if hub.connected_devices().await == vec!["device-1".to_owned()] {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();

        let result = hub
            .dispatch_action(
                "device-1",
                remote_request("filesystem.read", &file.to_string_lossy()),
                roundtrip_timeout,
            )
            .await
            .unwrap();
        assert_eq!(result.status, "ok");
        assert_eq!(result.output, b"mtls-dispatch-ok");

        let terminal = hub
            .dispatch_action(
                "device-1",
                remote_request("terminal.project_test", "local"),
                Duration::from_secs(1),
            )
            .await;
        assert!(matches!(
            terminal,
            Err(PrivateLinkError::RemoteActionNotAllowed)
        ));

        let denied = hub
            .dispatch_action(
                "device-1",
                remote_request("filesystem.read", r"C:\Windows\win.ini"),
                roundtrip_timeout,
            )
            .await
            .unwrap();
        assert_eq!(denied.status, "policy_denied");
        assert!(denied.output.is_empty());
        assert_eq!(dispatcher.lock().unwrap().audit_sequence(), 3);

        let (write_request, write_approval) =
            approved_write_request(&write_target, b"after", b"before", &signing);
        let written = hub
            .dispatch_approved_action("device-1", write_request, write_approval, roundtrip_timeout)
            .await
            .unwrap();
        assert_eq!(written.status, "ok");
        assert_eq!(std::fs::read(&write_target).unwrap(), b"after");
        assert_eq!(dispatcher.lock().unwrap().audit_sequence(), 7);

        let (terminal_request, terminal_approval) =
            approved_terminal_request(data.path(), &signing);
        let started = hub
            .dispatch_approved_action(
                "device-1",
                terminal_request,
                terminal_approval,
                roundtrip_timeout,
            )
            .await
            .unwrap();
        assert_eq!(started.status, "ok");
        let started: serde_json::Value = serde_json::from_slice(&started.output).unwrap();
        assert_eq!(started["state"], "running");
        let session_id = started["session_id"].as_str().unwrap().to_owned();

        let deadline = tokio::time::Instant::now() + roundtrip_timeout;
        loop {
            let polled = hub
                .dispatch_action(
                    "device-1",
                    terminal_poll_request(&session_id),
                    roundtrip_timeout,
                )
                .await
                .unwrap();
            assert_eq!(polled.status, "ok");
            let payload: serde_json::Value = serde_json::from_slice(&polled.output).unwrap();
            if payload["state"] != "running" {
                assert_eq!(payload["state"], "completed");
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
                tokio::time::Instant::now() < deadline,
                "mTLS terminal session did not finish"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        client_cancel.cancel();
        tokio::time::timeout(roundtrip_timeout, client_task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        server_cancel.cancel();
        tokio::time::timeout(roundtrip_timeout, server_task)
            .await
            .unwrap()
            .unwrap();
    }
    #[test]
    fn private_device_config_debug_redacts_key_material() {
        let config = PrivateDeviceClientConfig {
            endpoint: "https://127.0.0.1:1".into(),
            server_name: "localhost".into(),
            device_id: "device-1".into(),
            ca_pem: b"ca-public".to_vec(),
            device_cert_pem: b"cert-public".to_vec(),
            device_key_pem: b"SUPER-SECRET-PRIVATE-KEY".to_vec(),
            agent_version: "test".into(),
            heartbeat_interval: Duration::from_secs(1),
            replay_capacity: 1,
        };
        let debug = format!("{config:?}");
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("SUPER-SECRET-PRIVATE-KEY"));
    }

    /// Security sprint 1: regression tests that drive the real hub, the real
    /// mTLS device loop and the real dispatcher/ledger together.
    mod security_sprint_1 {
        use super::*;

        fn device_config(fixture: &MtlsFixture, address: SocketAddr) -> PrivateDeviceClientConfig {
            PrivateDeviceClientConfig {
                endpoint: format!("https://{address}"),
                server_name: "localhost".into(),
                device_id: "device-1".into(),
                ca_pem: fixture.ca_pem.as_bytes().to_vec(),
                device_cert_pem: fixture.device_cert_pem.as_bytes().to_vec(),
                device_key_pem: fixture.device_key_pem.as_bytes().to_vec(),
                agent_version: "0.1.0-security-sprint".into(),
                heartbeat_interval: Duration::from_secs(30),
                replay_capacity: 4096,
            }
        }

        async fn wait_connected(hub: &PrivateLinkHub) {
            tokio::time::timeout(Duration::from_secs(10), async {
                loop {
                    if hub.connected_devices().await == vec!["device-1".to_owned()] {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .expect("device did not connect to the hub");
        }

        fn read_request_expiring_at(target: &str, expires_at_unix_ms: u64) -> v1::ActionRequest {
            let request = ActionRequest::seal(ActionEnvelope {
                request_id: format!("req-expiry-{:032x}", rand::random::<u128>()),
                organization_id: "org-1".into(),
                actor_id: "gateway-test".into(),
                device_id: "device-1".into(),
                action: "filesystem.read".into(),
                target: target.into(),
                parameters: BTreeMap::new(),
                requested_capabilities: vec![],
                expires_at_unix_ms,
                nonce: rand::random::<[u8; 16]>().to_vec(),
            })
            .unwrap();
            action_request_to_proto(&request).unwrap()
        }

        fn expired_approved_write(
            target: &Path,
            content: &[u8],
            expected_target: &[u8],
            signing: &SigningKey,
        ) -> (v1::ActionRequest, v1::ApprovalGrant) {
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
                request_id: format!("req-expired-write-{:032x}", rand::random::<u128>()),
                organization_id: "org-1".into(),
                actor_id: "gateway-test".into(),
                device_id: "device-1".into(),
                action: "filesystem.write".into(),
                target: target.to_string_lossy().into_owned(),
                parameters,
                requested_capabilities: vec![],
                expires_at_unix_ms: now - 1_000,
                nonce: rand::random::<[u8; 16]>().to_vec(),
            })
            .unwrap();
            let decision = PolicyDecision {
                request_id: request.envelope.request_id.clone(),
                kind: PolicyDecisionKind::Approval,
                policy_id: "private-dispatch-test".into(),
                reason_code: "filesystem_rule".into(),
                required_capability: None,
                envelope_digest: request.envelope_digest,
            };
            // The approval was signed while the request was still valid.
            let challenge =
                ApprovalChallenge::issue(&request, &decision, now - 10_000, now - 5_000).unwrap();
            let approval = sign_approval(challenge, "operator-1", signing).unwrap();
            (
                action_request_to_proto(&request).unwrap(),
                approval_grant_to_proto(&approval).unwrap(),
            )
        }

        /// Item 1 (vor-private-grpc #4): the hub purges `pending` when the
        /// caller's timeout fires. The same signed ApprovalGrant is then sent
        /// again through the hub; the device must not apply the effect twice.
        #[tokio::test]
        async fn sec1_signed_grant_executes_once_even_after_hub_timeout_purges_pending() {
            let fixture = mtls_fixture("device-1");
            let data = tempdir().unwrap();
            let target = data.path().join("replay.txt");
            std::fs::write(&target, b"original").unwrap();
            let signing = SigningKey::from_bytes(&[21; 32]);
            let dispatcher = test_dispatcher(data.path());
            dispatcher
                .lock()
                .unwrap()
                .add_trusted_approver("operator-1", signing.verifying_key().to_bytes())
                .unwrap();
            let (address, hub, server_cancel, server_task) = spawn_server_with_hub(&fixture).await;
            let client_cancel = CancellationToken::new();
            let client_task = tokio::spawn(run_device_dispatch(
                device_config(&fixture, address),
                dispatcher.clone(),
                client_cancel.clone(),
            ));
            wait_connected(&hub).await;

            let (request, grant) = approved_write_request(&target, b"first", b"original", &signing);
            // A timeout far shorter than the mTLS round trip: the hub gives up
            // and purges its pending entry while the device still executes.
            let first = hub
                .dispatch_approved_action(
                    "device-1",
                    request.clone(),
                    grant.clone(),
                    Duration::from_millis(1),
                )
                .await;
            assert!(
                matches!(first, Err(PrivateLinkError::ActionTimeout)) || first.is_ok(),
                "unexpected first dispatch outcome: {first:?}"
            );
            tokio::time::timeout(Duration::from_secs(20), async {
                while std::fs::read(&target).unwrap() != b"first" {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .expect("device never applied the first approved write");
            assert!(
                hub.pending.read().await.is_empty(),
                "pending was not purged"
            );
            // The device holds the dispatcher lock for the whole approved
            // dispatch, so taking it proves the first execution has finished.
            // The late first result is then delivered to a hub with no pending
            // slot and dropped; give it time to arrive so that it cannot be
            // mistaken for the answer to the replay below.
            drop(dispatcher.lock().unwrap());
            tokio::time::sleep(Duration::from_millis(500)).await;

            // Restore the precondition so that a replay *could* succeed if the
            // one-shot claim were missing.
            std::fs::write(&target, b"original").unwrap();
            let replay = hub
                .dispatch_approved_action("device-1", request, grant, Duration::from_secs(20))
                .await
                .expect("device answers the replay with a failure result");
            assert_eq!(replay.status, "approval_replayed");
            assert_eq!(std::fs::read(&target).unwrap(), b"original");

            client_cancel.cancel();
            let _ = tokio::time::timeout(Duration::from_secs(5), client_task).await;
            server_cancel.cancel();
            let _ = tokio::time::timeout(Duration::from_secs(5), server_task).await;
        }

        /// Item 2 (vor-private-grpc #5), effect half: an expired ActionRequest
        /// must produce no effect. The device-side broker already enforces
        /// this (`vor-core` `authorize_at`/`consume_approval_at` call
        /// `request.verify(now)`), and the device loop rejects the expired
        /// frame before dispatching it (`verify_frame_at`). This test passes on
        /// the unfixed hub and documents that the effect is prevented below it.
        #[tokio::test]
        async fn sec2_expired_requests_have_no_effect_on_the_device() {
            let fixture = mtls_fixture("device-1");
            let data = tempdir().unwrap();
            let readable = data.path().join("readable.txt");
            std::fs::write(&readable, b"secret-content").unwrap();
            let target = data.path().join("expired-write.txt");
            std::fs::write(&target, b"original").unwrap();
            let signing = SigningKey::from_bytes(&[22; 32]);
            let dispatcher = test_dispatcher(data.path());
            dispatcher
                .lock()
                .unwrap()
                .add_trusted_approver("operator-1", signing.verifying_key().to_bytes())
                .unwrap();

            // Device layer on its own: the dispatcher refuses the expired
            // approved write and writes nothing.
            let (request, grant) =
                expired_approved_write(&target, b"should-not-land", b"original", &signing);
            let direct =
                dispatcher
                    .lock()
                    .unwrap()
                    .dispatch_approved_proto(&v1::ApprovedActionRequest {
                        request: Some(request.clone()),
                        approval: Some(grant.clone()),
                    });
            assert!(direct.is_err(), "dispatcher accepted an expired request");
            assert_eq!(std::fs::read(&target).unwrap(), b"original");

            // Full path through the hub and the mTLS device loop.
            let (address, hub, server_cancel, server_task) = spawn_server_with_hub(&fixture).await;
            let client_cancel = CancellationToken::new();
            let client_task = tokio::spawn(run_device_dispatch(
                device_config(&fixture, address),
                dispatcher.clone(),
                client_cancel.clone(),
            ));
            wait_connected(&hub).await;
            let audit_before = dispatcher.lock().unwrap().audit_sequence();

            let expired_write = hub
                .dispatch_approved_action("device-1", request, grant, Duration::from_secs(3))
                .await;
            assert!(
                !matches!(&expired_write, Ok(result) if result.status == "ok"),
                "expired write reported success: {expired_write:?}"
            );
            assert_eq!(std::fs::read(&target).unwrap(), b"original");
            assert_eq!(dispatcher.lock().unwrap().audit_sequence(), audit_before);

            client_cancel.cancel();
            let _ = tokio::time::timeout(Duration::from_secs(5), client_task).await;
            server_cancel.cancel();
            let _ = tokio::time::timeout(Duration::from_secs(5), server_task).await;
        }

        /// Item 2 (vor-private-grpc #5), availability half: the hub forwarded
        /// expired requests, and the device answered the expired frame by
        /// tearing down its whole session. The hub must reject them up front
        /// and the device must stay connected.
        #[tokio::test]
        async fn sec2_expired_requests_are_rejected_by_the_hub_and_keep_the_session() {
            let fixture = mtls_fixture("device-1");
            let data = tempdir().unwrap();
            let readable = data.path().join("readable.txt");
            std::fs::write(&readable, b"still-connected").unwrap();
            let target = data.path().join("expired-write.txt");
            std::fs::write(&target, b"original").unwrap();
            let signing = SigningKey::from_bytes(&[23; 32]);
            let dispatcher = test_dispatcher(data.path());
            dispatcher
                .lock()
                .unwrap()
                .add_trusted_approver("operator-1", signing.verifying_key().to_bytes())
                .unwrap();
            let (address, hub, server_cancel, server_task) = spawn_server_with_hub(&fixture).await;
            let client_cancel = CancellationToken::new();
            let client_task = tokio::spawn(run_device_dispatch(
                device_config(&fixture, address),
                dispatcher.clone(),
                client_cancel.clone(),
            ));
            wait_connected(&hub).await;

            let now = now_unix_ms().unwrap();
            let expired_read = hub
                .dispatch_action(
                    "device-1",
                    read_request_expiring_at(&readable.to_string_lossy(), now - 1_000),
                    Duration::from_secs(3),
                )
                .await;
            assert!(
                matches!(expired_read, Err(PrivateLinkError::ActionExpired)),
                "expired read: {expired_read:?}"
            );
            let (request, grant) =
                expired_approved_write(&target, b"should-not-land", b"original", &signing);
            let expired_write = hub
                .dispatch_approved_action("device-1", request, grant, Duration::from_secs(3))
                .await;
            assert!(
                matches!(expired_write, Err(PrivateLinkError::ActionExpired)),
                "expired write: {expired_write:?}"
            );

            // The session survives: a valid request still round-trips.
            assert_eq!(hub.connected_devices().await, vec!["device-1".to_owned()]);
            let valid = hub
                .dispatch_action(
                    "device-1",
                    remote_request("filesystem.read", &readable.to_string_lossy()),
                    Duration::from_secs(20),
                )
                .await
                .expect("device must still be connected after expired requests");
            assert_eq!(valid.status, "ok");
            assert_eq!(valid.output, b"still-connected");

            client_cancel.cancel();
            let _ = tokio::time::timeout(Duration::from_secs(5), client_task).await;
            server_cancel.cancel();
            let _ = tokio::time::timeout(Duration::from_secs(5), server_task).await;
        }

        /// Item 5 (vor-private-grpc #6/#17): identifiers that alias paths or
        /// Windows device names are rejected by every entry point of the crate.
        #[tokio::test]
        async fn sec5_device_ids_that_alias_paths_or_devices_are_rejected() {
            let fixture = mtls_fixture("device-1");
            let data = tempdir().unwrap();
            let dispatcher = test_dispatcher(data.path());
            for bad in [
                ".",
                "..",
                "...",
                ".hidden",
                "trailing.",
                "CON",
                "con",
                "Nul",
                "PRN",
                "aux",
                "COM1",
                "lpt9",
                "con.txt",
                "NUL.log",
                "a b",
                "a/b",
                r"a\b",
                "",
            ] {
                let registry = DeviceCertificateRegistry::from_certificates([(
                    bad.to_owned(),
                    fixture.device_cert_der.clone(),
                )]);
                assert!(
                    matches!(registry, Err(PrivateLinkError::InvalidDeviceId)),
                    "registry accepted {bad:?}"
                );
                let mut config = device_config(&fixture, "127.0.0.1:9".parse().unwrap());
                config.device_id = bad.to_owned();
                let result = tokio::time::timeout(
                    Duration::from_secs(5),
                    run_device_dispatch(config, dispatcher.clone(), CancellationToken::new()),
                )
                .await
                .expect("validation must fail before any network I/O");
                assert!(
                    matches!(result, Err(PrivateLinkError::InvalidDeviceId)),
                    "client accepted {bad:?}: {result:?}"
                );
            }
            for good in ["device-1", "123", "ainz-pc.local", "a", "COM10", "console"] {
                assert!(validate_device_id(good).is_ok(), "rejected {good:?}");
            }
        }

        /// Item 6 (vor-private-grpc #1): a device that stops answering must not
        /// let the hub accumulate unbounded pending entries.
        #[tokio::test]
        async fn sec6_pending_actions_per_device_are_capped() {
            let fixture = mtls_fixture("device-1");
            let data = tempdir().unwrap();
            let readable = data.path().join("readable.txt");
            std::fs::write(&readable, b"cap").unwrap();
            let dispatcher = test_dispatcher(data.path());
            let (address, hub, server_cancel, server_task) = spawn_server_with_hub(&fixture).await;
            let client_cancel = CancellationToken::new();
            let client_task = tokio::spawn(run_device_dispatch(
                device_config(&fixture, address),
                dispatcher.clone(),
                client_cancel.clone(),
            ));
            wait_connected(&hub).await;

            // Wedge the device: its dispatcher lock is held, so it never answers.
            let wedge = dispatcher.clone();
            let (wedged_tx, wedged_rx) = std::sync::mpsc::channel();
            let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
            let wedge_thread = std::thread::spawn(move || {
                let _guard = wedge.lock().unwrap();
                wedged_tx.send(()).unwrap();
                let _ = release_rx.recv();
            });
            wedged_rx.recv().unwrap();

            let mut stuck = Vec::new();
            for _ in 0..MAX_PENDING_ACTIONS_PER_DEVICE {
                let hub = hub.clone();
                let request = remote_request("filesystem.read", &readable.to_string_lossy());
                stuck.push(tokio::spawn(async move {
                    hub.dispatch_action("device-1", request, Duration::from_secs(120))
                        .await
                }));
            }
            tokio::time::timeout(Duration::from_secs(30), async {
                while hub.pending.read().await.len() < MAX_PENDING_ACTIONS_PER_DEVICE {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .expect("pending entries were not registered");

            let overflow = tokio::time::timeout(
                Duration::from_secs(5),
                hub.dispatch_action(
                    "device-1",
                    remote_request("filesystem.read", &readable.to_string_lossy()),
                    Duration::from_secs(120),
                ),
            )
            .await;
            assert!(
                matches!(overflow, Ok(Err(PrivateLinkError::TooManyPendingActions))),
                "overflow dispatch was not rejected promptly: {overflow:?}"
            );
            assert!(hub.pending.read().await.len() <= MAX_PENDING_ACTIONS_PER_DEVICE);

            client_cancel.cancel();
            for task in stuck {
                task.abort();
            }
            release_tx.send(()).unwrap();
            wedge_thread.join().unwrap();
            let _ = tokio::time::timeout(Duration::from_secs(10), client_task).await;
            server_cancel.cancel();
            let _ = tokio::time::timeout(Duration::from_secs(5), server_task).await;
        }

        /// Item 6 (vor-private-grpc #1): the caller's timeout must also bound
        /// the time spent waiting for room in a full device channel.
        #[tokio::test]
        async fn sec6_timeout_bounds_a_full_device_channel() {
            let hub = PrivateLinkHub::default();
            let (sender, _receiver) = mpsc::channel(1);
            hub.register("device-1".into(), sender).await;
            for attempt in 0..3 {
                let started = std::time::Instant::now();
                let result = tokio::time::timeout(
                    Duration::from_secs(10),
                    hub.dispatch_action(
                        "device-1",
                        remote_request("filesystem.read", r"C:\tmp\x.txt"),
                        Duration::from_millis(200),
                    ),
                )
                .await;
                assert!(
                    matches!(result, Ok(Err(PrivateLinkError::ActionTimeout))),
                    "attempt {attempt} did not honour its timeout: {result:?}"
                );
                assert!(started.elapsed() < Duration::from_secs(5));
            }
            assert!(hub.pending.read().await.is_empty());
        }

        /// Item 6 (vor-private-grpc #14): a poisoned dispatcher mutex must not
        /// leave the device permanently unable to serve requests.
        #[tokio::test]
        async fn sec6_poisoned_dispatcher_mutex_does_not_brick_the_device() {
            let fixture = mtls_fixture("device-1");
            let data = tempdir().unwrap();
            let readable = data.path().join("readable.txt");
            std::fs::write(&readable, b"recovered").unwrap();
            let dispatcher = test_dispatcher(data.path());
            let poison = dispatcher.clone();
            let _ = std::thread::spawn(move || {
                let _guard = poison.lock().unwrap();
                panic!("simulated panic while holding the dispatcher lock");
            })
            .join();
            assert!(dispatcher.is_poisoned());

            let (address, hub, server_cancel, server_task) = spawn_server_with_hub(&fixture).await;
            let client_cancel = CancellationToken::new();
            let client_task = tokio::spawn(run_device_dispatch_until_cancelled(
                device_config(&fixture, address),
                dispatcher.clone(),
                client_cancel.clone(),
            ));
            wait_connected(&hub).await;

            for _ in 0..2 {
                let result = hub
                    .dispatch_action(
                        "device-1",
                        remote_request("filesystem.read", &readable.to_string_lossy()),
                        Duration::from_secs(10),
                    )
                    .await
                    .expect("a poisoned lock must not make the device unusable");
                assert_eq!(result.status, "ok");
                assert_eq!(result.output, b"recovered");
            }

            client_cancel.cancel();
            let _ = tokio::time::timeout(Duration::from_secs(5), client_task).await;
            server_cancel.cancel();
            let _ = tokio::time::timeout(Duration::from_secs(5), server_task).await;
        }
    }
}
