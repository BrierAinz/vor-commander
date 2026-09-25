// SPDX-License-Identifier: MPL-2.0

mod billing;
mod oauth;

use axum::extract::{Extension, Request, State};
use axum::http::{
    HeaderValue, StatusCode,
    header::{AUTHORIZATION, WWW_AUTHENTICATE},
};
use axum::middleware::{self, Next};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use prost::Message;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{Extensions as McpExtensions, ProtocolVersion, ServerCapabilities, ServerConfig};
use rmcp::transport::streamable_http_server::{
    StreamableHttpServerConfig, StreamableHttpService, session::local::LocalSessionManager,
};
use rmcp::{ServerHandler, tool, tool_handler, tool_router};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::borrow::Cow;
use std::collections::BTreeMap;
use std::io;
use std::net::SocketAddr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use thiserror::Error;
use tokio_util::sync::CancellationToken;
use vor_auth::{AuthError, GrantRecord, GrantStore, TenantRole, TenantStore};
use vor_private_grpc::{PrivateLinkError, PrivateLinkHub};
use vor_protocol::{ActionEnvelope, ActionRequest};
use vor_relay::{RelayError, RelayHub};
use vor_wire::{action_request_from_proto, action_request_to_proto, v1};

#[derive(Debug, Clone)]
pub struct GrantContext(pub GrantRecord);

#[derive(Clone)]
struct GatewayState {
    grants: GrantStore,
    tenants: Option<TenantStore>,
    device_id: String,
    remote_dispatch_enabled: bool,
    oauth: oauth::OAuthRuntime,
    billing: billing::BillingConfig,
    billing_store: billing::BillingStore,
}

#[derive(Debug, Clone)]
pub struct GatewayConfig {
    pub bind: SocketAddr,
}

impl Default for GatewayConfig {
    fn default() -> Self {
        Self {
            bind: "127.0.0.1:8742".parse().expect("valid default bind"),
        }
    }
}

#[derive(Clone, Default)]
pub struct RemoteDispatchRouter {
    private: Option<PrivateLinkHub>,
    relay: Option<RelayHub>,
}
impl RemoteDispatchRouter {
    pub fn private_only(hub: PrivateLinkHub) -> Self {
        Self {
            private: Some(hub),
            relay: None,
        }
    }
    pub fn with_links(private: PrivateLinkHub, relay: RelayHub) -> Self {
        Self {
            private: Some(private),
            relay: Some(relay),
        }
    }
    pub fn is_enabled(&self) -> bool {
        self.private.is_some() || self.relay.is_some()
    }

    pub async fn connected_devices(&self) -> Vec<String> {
        let mut devices = Vec::new();
        if let Some(private) = &self.private {
            devices.extend(private.connected_devices().await);
        }
        if let Some(relay) = &self.relay {
            devices.extend(relay.connected_devices().await);
        }
        devices.sort();
        devices.dedup();
        devices
    }

    pub async fn dispatch_action(
        &self,
        device_id: &str,
        request: vor_wire::v1::ActionRequest,
        timeout: Duration,
    ) -> Result<vor_wire::v1::ActionResult, RemoteDispatchError> {
        if let Some(private) = &self.private
            && private
                .connected_devices()
                .await
                .iter()
                .any(|id| id == device_id)
        {
            return private
                .dispatch_action(device_id, request, timeout)
                .await
                .map_err(RemoteDispatchError::Private);
        }
        if let Some(relay) = &self.relay
            && relay
                .connected_devices()
                .await
                .iter()
                .any(|id| id == device_id)
        {
            return relay
                .dispatch_action(device_id, request, timeout)
                .await
                .map_err(RemoteDispatchError::Relay);
        }
        Err(RemoteDispatchError::DeviceOffline)
    }

    pub async fn dispatch_approved_action(
        &self,
        device_id: &str,
        request: vor_wire::v1::ActionRequest,
        approval: vor_wire::v1::ApprovalGrant,
        timeout: Duration,
    ) -> Result<vor_wire::v1::ActionResult, RemoteDispatchError> {
        if let Some(private) = &self.private
            && private
                .connected_devices()
                .await
                .iter()
                .any(|id| id == device_id)
        {
            return private
                .dispatch_approved_action(device_id, request, approval, timeout)
                .await
                .map_err(RemoteDispatchError::Private);
        }
        if let Some(relay) = &self.relay
            && relay
                .connected_devices()
                .await
                .iter()
                .any(|id| id == device_id)
        {
            return relay
                .dispatch_approved_action(device_id, request, approval, timeout)
                .await
                .map_err(RemoteDispatchError::Relay);
        }
        Err(RemoteDispatchError::DeviceOffline)
    }
}
#[derive(Debug, Error)]
pub enum RemoteDispatchError {
    #[error("remote device is offline")]
    DeviceOffline,
    #[error("private transport failed: {0}")]
    Private(PrivateLinkError),
    #[error("relay transport failed: {0}")]
    Relay(RelayError),
}

#[derive(Clone)]
struct CommanderServer {
    gateway_device_id: String,
    remote_links: Option<RemoteDispatchRouter>,
    tenants: Option<TenantStore>,
}

impl CommanderServer {
    fn new(
        gateway_device_id: String,
        remote_links: Option<RemoteDispatchRouter>,
        tenants: Option<TenantStore>,
    ) -> Self {
        Self {
            gateway_device_id,
            remote_links,
            tenants,
        }
    }

    fn remote_links(&self) -> Result<&RemoteDispatchRouter, rmcp::ErrorData> {
        self.remote_links
            .as_ref()
            .ok_or_else(|| rmcp::ErrorData::invalid_params("remote dispatch is disabled", None))
    }
}

#[derive(Debug, Deserialize, JsonSchema)]
struct DevicePathInput {
    device_id: String,
    workspace_id: Option<String>,
    path: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct ReadFileInput {
    device_id: String,
    workspace_id: Option<String>,
    path: String,
    offset: Option<u64>,
    length: Option<usize>,
    line_start: Option<usize>,
    line_count: Option<usize>,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct ListDirectoryInput {
    device_id: String,
    workspace_id: Option<String>,
    path: String,
    depth: Option<usize>,
    max_entries: Option<usize>,
}
#[derive(Debug, Deserialize, JsonSchema)]
struct SearchFilesInput {
    device_id: String,
    workspace_id: Option<String>,
    root: String,
    pattern: String,
    max_results: Option<usize>,
}
#[derive(Debug, Deserialize, JsonSchema)]
struct SearchContentInput {
    device_id: String,
    workspace_id: Option<String>,
    root: String,
    query: String,
    regex: bool,
    file_glob: Option<String>,
    max_matches: Option<usize>,
    max_file_bytes: Option<usize>,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct DeviceOnlyInput {
    device_id: String,
    workspace_id: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct ProcessInspectInput {
    device_id: String,
    workspace_id: Option<String>,
    pid: u32,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct PrepareWriteInput {
    device_id: String,
    workspace_id: Option<String>,
    path: String,
    content_base64: String,
    expected_target_sha256: String,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
struct EditInput {
    old_text: String,
    new_text: String,
    #[serde(default = "default_expected_occurrences")]
    expected_occurrences: usize,
}

fn default_expected_occurrences() -> usize {
    1
}

#[derive(Debug, Deserialize, JsonSchema)]
struct PrepareEditInput {
    device_id: String,
    workspace_id: Option<String>,
    path: String,
    edits: Vec<EditInput>,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct CommitWriteInput {
    device_id: String,
    workspace_id: Option<String>,
    request_base64: String,
    approval_base64: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct PrepareTerminalInput {
    device_id: String,
    workspace_id: Option<String>,
    cwd: String,
    argv: Vec<String>,
    timeout_ms: Option<u64>,
    max_output_bytes: Option<usize>,
    columns: Option<u16>,
    rows: Option<u16>,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct CommitTerminalInput {
    device_id: String,
    workspace_id: Option<String>,
    request_base64: String,
    approval_base64: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct TerminalSessionInput {
    device_id: String,
    workspace_id: Option<String>,
    session_id: String,
}

#[derive(Debug, Serialize)]
struct PrepareWriteOutput {
    request_id: String,
    status: String,
    request_base64: String,
    content_sha256: String,
    challenge: Value,
}

#[derive(Debug, Serialize)]
struct PrepareEditOutput {
    request_id: String,
    status: String,
    request_base64: String,
    content_sha256: String,
    diff_summary: String,
    diff_truncated: bool,
    challenge: Value,
}

#[derive(Debug, Serialize)]
struct PrepareTerminalOutput {
    request_id: String,
    status: String,
    request_base64: String,
    challenge: Value,
}

#[derive(Debug, Serialize)]
struct ToolOutput {
    request_id: String,
    status: String,
    content_type: String,
    encoding: String,
    data: Value,
    digest_base64: String,
}

#[tool_router]
impl CommanderServer {
    #[tool(description = "Return non-sensitive Vör Commander gateway status")]
    async fn commander_status(&self, extensions: McpExtensions) -> Result<String, rmcp::ErrorData> {
        let grant = grant_from_mcp_extensions(&extensions)?;
        let all_remote_connected_devices = if let Some(remote_links) = &self.remote_links {
            remote_links.connected_devices().await
        } else {
            Vec::new()
        };
        let remote_connected_devices =
            self.authorized_status_devices(&grant.0, all_remote_connected_devices);
        let remote_connectivity = if self.remote_links.is_none() {
            "disabled"
        } else if remote_connected_devices.is_empty() {
            "offline"
        } else {
            "connected"
        };
        let recommended_device_id = remote_connected_devices.first().cloned();
        let operator_hint = match (self.remote_links.is_some(), recommended_device_id.as_ref()) {
            (false, _) => "remote dispatch is disabled for this gateway",
            (true, Some(_)) => "use recommended_device_id for remote device tools",
            (true, None) => "start or reconnect a device agent before remote device tools",
        };
        Ok(json!({
            "service": "vor-commander",
            "phase": "P4-C/OAuth",
            "gateway_device_id": self.gateway_device_id,
            "actor_id": grant.0.actor_id,
            "remote_worker_dispatch": self.remote_links.is_some(),
            "remote_connectivity": remote_connectivity,
            "remote_connected_device_count": remote_connected_devices.len(),
            "remote_connected_devices": remote_connected_devices,
            "recommended_device_id": recommended_device_id,
            "operator_hint": operator_hint,
            "remote_scope": [
                "filesystem.read", "filesystem.list", "filesystem.search_files",
                "filesystem.search_content", "filesystem.info", "git.status", "git.diff",
                "process.list", "process.inspect",
                "terminal.poll", "terminal.cancel"
            ],
            "remote_approved_scope": ["filesystem.write", "terminal.exec"]
        })
        .to_string())
    }

    #[tool(
        name = "read_file",
        description = "Read one file from an authorized remote device. Read-only; output is base64 for arbitrary bytes."
    )]
    async fn read_file(
        &self,
        Parameters(input): Parameters<ReadFileInput>,
        extensions: McpExtensions,
    ) -> Result<String, rmcp::ErrorData> {
        let mut parameters = BTreeMap::new();
        for (name, value) in [
            ("offset", input.offset.map(Value::from)),
            ("length", input.length.map(Value::from)),
            ("line_start", input.line_start.map(Value::from)),
            ("line_count", input.line_count.map(Value::from)),
        ] {
            if let Some(value) = value {
                parameters.insert(name.into(), value);
            }
        }
        self.dispatch_mcp_parameters(
            &extensions,
            &input.device_id,
            input.workspace_id.as_deref(),
            "filesystem.read",
            &input.path,
            parameters,
        )
        .await
    }

    #[tool(
        name = "list_directory",
        description = "List an authorized remote directory without following links or junctions."
    )]
    async fn list_directory(
        &self,
        Parameters(input): Parameters<ListDirectoryInput>,
        extensions: McpExtensions,
    ) -> Result<String, rmcp::ErrorData> {
        let mut parameters = BTreeMap::new();
        parameters.insert(
            "depth".into(),
            Value::from(
                input
                    .depth
                    .unwrap_or(DEFAULT_LIST_DEPTH)
                    .min(MAX_LIST_DEPTH),
            ),
        );
        parameters.insert(
            "max_entries".into(),
            Value::from(
                input
                    .max_entries
                    .unwrap_or(DEFAULT_LIST_ENTRIES)
                    .min(MAX_LIST_ENTRIES),
            ),
        );
        self.dispatch_mcp_parameters(
            &extensions,
            &input.device_id,
            input.workspace_id.as_deref(),
            "filesystem.list",
            &input.path,
            parameters,
        )
        .await
    }

    #[tool(
        name = "search_files",
        description = "Search file paths by glob under an authorized remote root."
    )]
    async fn search_files(
        &self,
        Parameters(input): Parameters<SearchFilesInput>,
        extensions: McpExtensions,
    ) -> Result<String, rmcp::ErrorData> {
        let mut parameters = BTreeMap::new();
        parameters.insert("pattern".into(), Value::String(input.pattern));
        parameters.insert(
            "max_results".into(),
            Value::from(
                input
                    .max_results
                    .unwrap_or(DEFAULT_SEARCH_RESULTS)
                    .min(MAX_SEARCH_RESULTS),
            ),
        );
        self.dispatch_mcp_parameters(
            &extensions,
            &input.device_id,
            input.workspace_id.as_deref(),
            "filesystem.search_files",
            &input.root,
            parameters,
        )
        .await
    }

    #[tool(
        name = "search_content",
        description = "Bounded literal or regex search. Reports each match's detected encoding plus binary/size-limit skip counts. Columns are one-based UTF-8 byte offsets after decoding (including for UTF-16 input)."
    )]
    async fn search_content(
        &self,
        Parameters(input): Parameters<SearchContentInput>,
        extensions: McpExtensions,
    ) -> Result<String, rmcp::ErrorData> {
        let mut parameters = BTreeMap::new();
        parameters.insert("query".into(), Value::String(input.query));
        parameters.insert("regex".into(), Value::Bool(input.regex));
        parameters.insert(
            "file_glob".into(),
            Value::String(input.file_glob.unwrap_or_else(|| "**".into())),
        );
        parameters.insert(
            "max_matches".into(),
            Value::from(
                input
                    .max_matches
                    .unwrap_or(DEFAULT_CONTENT_MATCHES)
                    .min(MAX_CONTENT_MATCHES),
            ),
        );
        parameters.insert(
            "max_file_bytes".into(),
            Value::from(
                input
                    .max_file_bytes
                    .unwrap_or(DEFAULT_SEARCH_FILE_BYTES)
                    .min(MAX_SEARCH_FILE_BYTES),
            ),
        );
        self.dispatch_mcp_parameters(
            &extensions,
            &input.device_id,
            input.workspace_id.as_deref(),
            "filesystem.search_content",
            &input.root,
            parameters,
        )
        .await
    }

    #[tool(
        name = "file_info",
        description = "Return metadata without file content for an authorized remote path."
    )]
    async fn file_info(
        &self,
        Parameters(input): Parameters<DevicePathInput>,
        extensions: McpExtensions,
    ) -> Result<String, rmcp::ErrorData> {
        self.dispatch_mcp(
            &extensions,
            &input.device_id,
            input.workspace_id.as_deref(),
            "filesystem.info",
            &input.path,
        )
        .await
    }

    #[tool(
        name = "git_status",
        description = "Return read-only Git status for an authorized repository on a remote device."
    )]
    async fn git_status(
        &self,
        Parameters(input): Parameters<DevicePathInput>,
        extensions: McpExtensions,
    ) -> Result<String, rmcp::ErrorData> {
        self.dispatch_mcp(
            &extensions,
            &input.device_id,
            input.workspace_id.as_deref(),
            "git.status",
            &input.path,
        )
        .await
    }

    #[tool(
        name = "git_diff",
        description = "Return read-only Git diff for an authorized repository on a remote device."
    )]
    async fn git_diff(
        &self,
        Parameters(input): Parameters<DevicePathInput>,
        extensions: McpExtensions,
    ) -> Result<String, rmcp::ErrorData> {
        self.dispatch_mcp(
            &extensions,
            &input.device_id,
            input.workspace_id.as_deref(),
            "git.diff",
            &input.path,
        )
        .await
    }

    #[tool(
        name = "process_list",
        description = "List processes on an authorized remote device. Read-only."
    )]
    async fn process_list(
        &self,
        Parameters(input): Parameters<DeviceOnlyInput>,
        extensions: McpExtensions,
    ) -> Result<String, rmcp::ErrorData> {
        self.dispatch_mcp(
            &extensions,
            &input.device_id,
            input.workspace_id.as_deref(),
            "process.list",
            "local",
        )
        .await
    }

    #[tool(
        name = "process_inspect",
        description = "Inspect one PID on an authorized remote device. Read-only."
    )]
    async fn process_inspect(
        &self,
        Parameters(input): Parameters<ProcessInspectInput>,
        extensions: McpExtensions,
    ) -> Result<String, rmcp::ErrorData> {
        self.dispatch_mcp(
            &extensions,
            &input.device_id,
            input.workspace_id.as_deref(),
            "process.inspect",
            &input.pid.to_string(),
        )
        .await
    }

    #[tool(
        name = "prepare_write",
        description = "Prepare an approved filesystem write on an authorized remote device. This never writes data; it returns a device-policy approval challenge and an opaque request blob. Give request_base64 and challenge to scripts/local/approve-vor-request.ps1, review and approve there, then pass its approval_base64 output with the same request to commit_write."
    )]
    async fn prepare_write(
        &self,
        Parameters(input): Parameters<PrepareWriteInput>,
        extensions: McpExtensions,
    ) -> Result<String, rmcp::ErrorData> {
        self.prepare_write_mcp(&extensions, input).await
    }

    #[tool(
        name = "prepare_edit",
        description = "Prepare up to 20 ordered exact text replacements on an existing authorized file. The device reads and preserves the file encoding/line endings, returns a bounded unified diff and an ordinary signed filesystem.write challenge; this never writes data. Give request_base64, challenge and diff_summary to scripts/local/approve-vor-request.ps1, then use its approval_base64 with commit_write."
    )]
    async fn prepare_edit(
        &self,
        Parameters(input): Parameters<PrepareEditInput>,
        extensions: McpExtensions,
    ) -> Result<String, rmcp::ErrorData> {
        self.prepare_edit_mcp(&extensions, input).await
    }

    #[tool(
        name = "commit_write",
        description = "Commit a previously prepared filesystem write using the exact opaque request plus a signed one-use ApprovalGrant. The device revalidates policy and signature before writing."
    )]
    async fn commit_write(
        &self,
        Parameters(input): Parameters<CommitWriteInput>,
        extensions: McpExtensions,
    ) -> Result<String, rmcp::ErrorData> {
        self.commit_write_mcp(&extensions, input).await
    }

    #[tool(
        name = "prepare_terminal",
        description = "Prepare a bounded terminal.exec request on an authorized remote device. This never starts a process; it returns a device-policy approval challenge and an opaque request blob. Give request_base64 and challenge to scripts/local/approve-vor-request.ps1, review and approve there, then pass its approval_base64 output with the same request to commit_terminal."
    )]
    async fn prepare_terminal(
        &self,
        Parameters(input): Parameters<PrepareTerminalInput>,
        extensions: McpExtensions,
    ) -> Result<String, rmcp::ErrorData> {
        self.prepare_terminal_mcp(&extensions, input).await
    }

    #[tool(
        name = "commit_terminal",
        description = "Execute one previously prepared bounded terminal request using the exact opaque request plus a signed one-use ApprovalGrant. argv is structured; cwd, timeout and output budgets are device-enforced."
    )]
    async fn commit_terminal(
        &self,
        Parameters(input): Parameters<CommitTerminalInput>,
        extensions: McpExtensions,
    ) -> Result<String, rmcp::ErrorData> {
        self.commit_terminal_mcp(&extensions, input).await
    }

    #[tool(
        name = "poll_terminal",
        description = "Poll one bounded terminal session owned by the authenticated actor. Finished sessions are removed after their final result is returned."
    )]
    async fn poll_terminal(
        &self,
        Parameters(input): Parameters<TerminalSessionInput>,
        extensions: McpExtensions,
    ) -> Result<String, rmcp::ErrorData> {
        self.dispatch_mcp(
            &extensions,
            &input.device_id,
            input.workspace_id.as_deref(),
            "terminal.poll",
            &input.session_id,
        )
        .await
    }

    #[tool(
        name = "cancel_terminal",
        description = "Request cancellation of one bounded terminal session owned by the authenticated actor. Cancellation never grants permission to start a new process."
    )]
    async fn cancel_terminal(
        &self,
        Parameters(input): Parameters<TerminalSessionInput>,
        extensions: McpExtensions,
    ) -> Result<String, rmcp::ErrorData> {
        self.dispatch_mcp(
            &extensions,
            &input.device_id,
            input.workspace_id.as_deref(),
            "terminal.cancel",
            &input.session_id,
        )
        .await
    }
}

impl CommanderServer {
    async fn prepare_edit_mcp(
        &self,
        extensions: &McpExtensions,
        input: PrepareEditInput,
    ) -> Result<String, rmcp::ErrorData> {
        let grant = grant_from_mcp_extensions(extensions)?;
        let workspace_id = self.authorize_mcp(
            &grant.0,
            &input.device_id,
            input.workspace_id.as_deref(),
            TenantRole::Operator,
        )?;
        if input.edits.is_empty() || input.edits.len() > 20 {
            return Err(rmcp::ErrorData::invalid_params(
                "edits must contain between 1 and 20 replacements",
                None,
            ));
        }
        let mut parameters = BTreeMap::new();
        parameters.insert(
            "edit_recipe".into(),
            serde_json::to_value(&input.edits)
                .map_err(|_| rmcp::ErrorData::invalid_params("invalid edit recipe", None))?,
        );
        if let Some(workspace_id) = workspace_id.as_deref() {
            parameters.insert(
                "workspace_id".into(),
                Value::String(workspace_id.to_owned()),
            );
        }
        let now = now_unix_ms()
            .map_err(|_| rmcp::ErrorData::internal_error("system clock unavailable", None))?;
        let canonical = ActionRequest::seal(ActionEnvelope {
            request_id: format!("mcp-edit-{:032x}", rand::random::<u128>()),
            organization_id: grant.0.organization_id.clone(),
            actor_id: grant.0.actor_id.clone(),
            device_id: input.device_id.clone(),
            action: "filesystem.write".into(),
            target: input.path,
            parameters,
            requested_capabilities: vec![],
            expires_at_unix_ms: now
                .checked_add(WRITE_REQUEST_TTL_MS)
                .ok_or_else(|| rmcp::ErrorData::internal_error("edit expiry overflow", None))?,
            nonce: rand::random::<[u8; 16]>().to_vec(),
        })
        .map_err(|_| rmcp::ErrorData::invalid_params("invalid edit request", None))?;
        let request = action_request_to_proto(&canonical)
            .map_err(|_| rmcp::ErrorData::internal_error("failed to encode edit request", None))?;
        let result = self
            .remote_links()?
            .dispatch_action(&input.device_id, request, MCP_REMOTE_ACTION_TIMEOUT)
            .await
            .map_err(remote_tool_error)?;
        if result.status != "approval_required" {
            return render_tool_output(result).map_err(|_| {
                rmcp::ErrorData::internal_error("failed to encode remote result", None)
            });
        }
        let mut payload: Value = serde_json::from_slice(&result.output).map_err(|_| {
            rmcp::ErrorData::internal_error("device returned an invalid edit challenge", None)
        })?;
        let take_string = |payload: &mut Value, key: &str| {
            payload
                .as_object_mut()
                .and_then(|v| v.remove(key))
                .and_then(|v| v.as_str().map(str::to_owned))
                .ok_or_else(|| {
                    rmcp::ErrorData::internal_error(
                        format!("device edit response omitted {key}"),
                        None,
                    )
                })
        };
        let request_base64 = take_string(&mut payload, "request_base64")?;
        let content_sha256 = take_string(&mut payload, "content_sha256")?;
        let diff_summary = take_string(&mut payload, "diff_summary")?;
        let diff_truncated = payload
            .as_object_mut()
            .and_then(|v| v.remove("diff_truncated"))
            .and_then(|v| v.as_bool())
            .ok_or_else(|| {
                rmcp::ErrorData::internal_error("device edit response omitted diff_truncated", None)
            })?;
        serde_json::to_string(&PrepareEditOutput {
            request_id: result.request_id,
            status: result.status,
            request_base64,
            content_sha256,
            diff_summary,
            diff_truncated,
            challenge: payload,
        })
        .map_err(|_| rmcp::ErrorData::internal_error("failed to encode edit challenge", None))
    }

    async fn prepare_write_mcp(
        &self,
        extensions: &McpExtensions,
        input: PrepareWriteInput,
    ) -> Result<String, rmcp::ErrorData> {
        let grant = grant_from_mcp_extensions(extensions)?;
        let workspace_id = self.authorize_mcp(
            &grant.0,
            &input.device_id,
            input.workspace_id.as_deref(),
            TenantRole::Operator,
        )?;
        let links = self.remote_links()?;
        let (request, content_sha256) = build_remote_write_request(
            &grant.0.organization_id,
            &grant.0.actor_id,
            &input.device_id,
            workspace_id.as_deref(),
            &input.path,
            &input.content_base64,
            &input.expected_target_sha256,
        )?;
        let request_base64 = STANDARD.encode(request.encode_to_vec());
        let result = links
            .dispatch_action(&input.device_id, request, MCP_REMOTE_ACTION_TIMEOUT)
            .await
            .map_err(remote_tool_error)?;

        if result.status != "approval_required" {
            return render_tool_output(result).map_err(|_| {
                rmcp::ErrorData::internal_error("failed to encode remote result", None)
            });
        }
        let challenge: Value = serde_json::from_slice(&result.output).map_err(|_| {
            rmcp::ErrorData::internal_error("device returned an invalid approval challenge", None)
        })?;
        serde_json::to_string(&PrepareWriteOutput {
            request_id: result.request_id,
            status: result.status,
            request_base64,
            content_sha256,
            challenge,
        })
        .map_err(|_| rmcp::ErrorData::internal_error("failed to encode write challenge", None))
    }

    async fn commit_write_mcp(
        &self,
        extensions: &McpExtensions,
        input: CommitWriteInput,
    ) -> Result<String, rmcp::ErrorData> {
        let grant = grant_from_mcp_extensions(extensions)?;
        let request_bytes = STANDARD
            .decode(input.request_base64.as_bytes())
            .map_err(|_| {
                rmcp::ErrorData::invalid_params("request_base64 is not valid base64", None)
            })?;
        let approval_bytes = STANDARD
            .decode(input.approval_base64.as_bytes())
            .map_err(|_| {
                rmcp::ErrorData::invalid_params("approval_base64 is not valid base64", None)
            })?;
        let request = v1::ActionRequest::decode(request_bytes.as_slice()).map_err(|_| {
            rmcp::ErrorData::invalid_params("request_base64 is not a valid ActionRequest", None)
        })?;
        let approval = v1::ApprovalGrant::decode(approval_bytes.as_slice()).map_err(|_| {
            rmcp::ErrorData::invalid_params("approval_base64 is not a valid ApprovalGrant", None)
        })?;
        let canonical = action_request_from_proto(&request).map_err(|_| {
            rmcp::ErrorData::invalid_params("prepared request failed canonical validation", None)
        })?;
        if canonical.envelope.device_id != input.device_id
            || canonical.envelope.actor_id != grant.0.actor_id
            || canonical.envelope.organization_id != grant.0.organization_id
            || canonical.envelope.action != "filesystem.write"
        {
            return Err(rmcp::ErrorData::invalid_params(
                "prepared request is not bound to this actor, device and filesystem.write",
                None,
            ));
        }
        self.authorize_prepared_mcp(
            &grant.0,
            &canonical.envelope.device_id,
            input.workspace_id.as_deref(),
            signed_workspace_id(&canonical.envelope.parameters)?,
            TenantRole::Operator,
        )?;

        let links = self.remote_links()?;
        let result = links
            .dispatch_approved_action(
                &input.device_id,
                request,
                approval,
                MCP_REMOTE_ACTION_TIMEOUT,
            )
            .await
            .map_err(remote_tool_error)?;
        render_tool_output(result)
            .map_err(|_| rmcp::ErrorData::internal_error("failed to encode remote result", None))
    }

    async fn prepare_terminal_mcp(
        &self,
        extensions: &McpExtensions,
        input: PrepareTerminalInput,
    ) -> Result<String, rmcp::ErrorData> {
        let grant = grant_from_mcp_extensions(extensions)?;
        let workspace_id = self.authorize_mcp(
            &grant.0,
            &input.device_id,
            input.workspace_id.as_deref(),
            TenantRole::Operator,
        )?;
        let links = self.remote_links()?;
        let request = build_remote_terminal_request(
            &grant.0.organization_id,
            &grant.0.actor_id,
            workspace_id.as_deref(),
            &input,
        )?;
        let request_base64 = STANDARD.encode(request.encode_to_vec());
        let result = links
            .dispatch_action(&input.device_id, request, MCP_REMOTE_ACTION_TIMEOUT)
            .await
            .map_err(remote_tool_error)?;

        if result.status != "approval_required" {
            return render_tool_output(result).map_err(|_| {
                rmcp::ErrorData::internal_error("failed to encode remote result", None)
            });
        }
        let challenge: Value = serde_json::from_slice(&result.output).map_err(|_| {
            rmcp::ErrorData::internal_error("device returned an invalid approval challenge", None)
        })?;
        serde_json::to_string(&PrepareTerminalOutput {
            request_id: result.request_id,
            status: result.status,
            request_base64,
            challenge,
        })
        .map_err(|_| rmcp::ErrorData::internal_error("failed to encode terminal challenge", None))
    }

    async fn commit_terminal_mcp(
        &self,
        extensions: &McpExtensions,
        input: CommitTerminalInput,
    ) -> Result<String, rmcp::ErrorData> {
        let grant = grant_from_mcp_extensions(extensions)?;
        let request_bytes = STANDARD
            .decode(input.request_base64.as_bytes())
            .map_err(|_| {
                rmcp::ErrorData::invalid_params("request_base64 is not valid base64", None)
            })?;
        let approval_bytes = STANDARD
            .decode(input.approval_base64.as_bytes())
            .map_err(|_| {
                rmcp::ErrorData::invalid_params("approval_base64 is not valid base64", None)
            })?;
        let request = v1::ActionRequest::decode(request_bytes.as_slice()).map_err(|_| {
            rmcp::ErrorData::invalid_params("request_base64 is not a valid ActionRequest", None)
        })?;
        let approval = v1::ApprovalGrant::decode(approval_bytes.as_slice()).map_err(|_| {
            rmcp::ErrorData::invalid_params("approval_base64 is not a valid ApprovalGrant", None)
        })?;
        let canonical = action_request_from_proto(&request).map_err(|_| {
            rmcp::ErrorData::invalid_params("prepared request failed canonical validation", None)
        })?;
        if canonical.envelope.device_id != input.device_id
            || canonical.envelope.actor_id != grant.0.actor_id
            || canonical.envelope.organization_id != grant.0.organization_id
            || canonical.envelope.action != "terminal.exec"
        {
            return Err(rmcp::ErrorData::invalid_params(
                "prepared request is not bound to this actor, device and terminal.exec",
                None,
            ));
        }
        self.authorize_prepared_mcp(
            &grant.0,
            &canonical.envelope.device_id,
            input.workspace_id.as_deref(),
            signed_workspace_id(&canonical.envelope.parameters)?,
            TenantRole::Operator,
        )?;

        let timeout_ms = canonical
            .envelope
            .parameters
            .get("timeout_ms")
            .and_then(Value::as_u64)
            .unwrap_or(DEFAULT_MCP_TERMINAL_TIMEOUT_MS)
            .min(MAX_MCP_TERMINAL_TIMEOUT_MS);
        let transport_timeout = Duration::from_millis(timeout_ms.saturating_add(10_000));
        let links = self.remote_links()?;
        let result = links
            .dispatch_approved_action(&input.device_id, request, approval, transport_timeout)
            .await
            .map_err(remote_tool_error)?;
        render_tool_output(result)
            .map_err(|_| rmcp::ErrorData::internal_error("failed to encode remote result", None))
    }

    async fn dispatch_mcp(
        &self,
        extensions: &McpExtensions,
        device_id: &str,
        workspace_id: Option<&str>,
        action: &str,
        target: &str,
    ) -> Result<String, rmcp::ErrorData> {
        self.dispatch_mcp_parameters(
            extensions,
            device_id,
            workspace_id,
            action,
            target,
            BTreeMap::new(),
        )
        .await
    }

    async fn dispatch_mcp_parameters(
        &self,
        extensions: &McpExtensions,
        device_id: &str,
        workspace_id: Option<&str>,
        action: &str,
        target: &str,
        parameters: BTreeMap<String, Value>,
    ) -> Result<String, rmcp::ErrorData> {
        let grant = grant_from_mcp_extensions(extensions)?;
        let workspace_id = self.authorize_mcp(
            &grant.0,
            device_id,
            workspace_id,
            if action.starts_with("process.") {
                TenantRole::Viewer
            } else {
                TenantRole::Viewer
            },
        )?;
        let links = self.remote_links()?;
        let request = build_remote_request_with_parameters(
            &grant.0.organization_id,
            &grant.0.actor_id,
            device_id,
            workspace_id.as_deref(),
            action,
            target,
            parameters,
        )
        .map_err(|_| rmcp::ErrorData::internal_error("failed to build remote request", None))?;
        let result = links
            .dispatch_action(device_id, request, MCP_REMOTE_ACTION_TIMEOUT)
            .await
            .map_err(remote_tool_error)?;
        render_tool_output(result)
            .map_err(|_| rmcp::ErrorData::internal_error("failed to encode remote result", None))
    }

    fn authorize_mcp(
        &self,
        grant: &GrantRecord,
        device_id: &str,
        workspace_id: Option<&str>,
        required_role: TenantRole,
    ) -> Result<Option<String>, rmcp::ErrorData> {
        let Some(tenants) = &self.tenants else {
            return Ok(workspace_id.map(str::to_owned));
        };
        let workspace_id = workspace_id.ok_or_else(|| {
            rmcp::ErrorData::invalid_params(
                "workspace_id is required for tenant-scoped MCP actions",
                None,
            )
        })?;
        tenants
            .verify_context(
                grant,
                &grant.organization_id,
                device_id,
                Some(workspace_id),
                required_role,
            )
            .map_err(|_| rmcp::ErrorData::invalid_params("tenant authority denied", None))?;
        Ok(Some(workspace_id.to_owned()))
    }

    fn authorized_status_devices(
        &self,
        grant: &GrantRecord,
        connected_devices: Vec<String>,
    ) -> Vec<String> {
        let Some(tenants) = &self.tenants else {
            return connected_devices;
        };
        connected_devices
            .into_iter()
            .filter(|device_id| {
                grant.workspace_ids.iter().any(|workspace_id| {
                    tenants
                        .verify_context(
                            grant,
                            &grant.organization_id,
                            device_id,
                            Some(workspace_id),
                            TenantRole::Viewer,
                        )
                        .is_ok()
                })
            })
            .collect()
    }

    fn authorize_prepared_mcp(
        &self,
        grant: &GrantRecord,
        device_id: &str,
        input_workspace_id: Option<&str>,
        prepared_workspace_id: Option<&str>,
        required_role: TenantRole,
    ) -> Result<(), rmcp::ErrorData> {
        if self.tenants.is_some() {
            let input_workspace_id = input_workspace_id.ok_or_else(|| {
                rmcp::ErrorData::invalid_params(
                    "workspace_id is required for tenant-scoped MCP actions",
                    None,
                )
            })?;
            let prepared_workspace_id = prepared_workspace_id.ok_or_else(|| {
                rmcp::ErrorData::invalid_params(
                    "prepared request is missing a signed workspace_id",
                    None,
                )
            })?;
            if input_workspace_id != prepared_workspace_id {
                return Err(rmcp::ErrorData::invalid_params(
                    "prepared request is not bound to the selected workspace",
                    None,
                ));
            }
        }
        self.authorize_mcp(grant, device_id, input_workspace_id, required_role)
            .map(|_| ())
    }
}

fn signed_workspace_id(
    parameters: &BTreeMap<String, Value>,
) -> Result<Option<&str>, rmcp::ErrorData> {
    match parameters.get("workspace_id") {
        Some(Value::String(workspace_id)) if !workspace_id.trim().is_empty() => {
            Ok(Some(workspace_id.as_str()))
        }
        Some(_) => Err(rmcp::ErrorData::invalid_params(
            "prepared request workspace_id must be a non-empty string",
            None,
        )),
        None => Ok(None),
    }
}

fn grant_from_mcp_extensions(extensions: &McpExtensions) -> Result<GrantContext, rmcp::ErrorData> {
    let parts = extensions
        .get::<axum::http::request::Parts>()
        .ok_or_else(|| {
            rmcp::ErrorData::invalid_params("missing authenticated HTTP context", None)
        })?;
    let grant = parts.extensions.get::<GrantContext>().ok_or_else(|| {
        rmcp::ErrorData::invalid_params("missing authenticated grant context", None)
    })?;
    Ok(grant.clone())
}

const MAX_MCP_WRITE_BYTES: usize = 1024 * 1024;
// This is a transport liveness guard, not an action latency contract. Loaded
// Windows hosts can pause file and audit I/O long enough to exceed 15 seconds.
const MCP_REMOTE_ACTION_TIMEOUT: Duration = Duration::from_secs(120);
const WRITE_REQUEST_TTL_MS: u64 = 180_000;

fn build_remote_write_request(
    organization_id: &str,
    actor_id: &str,
    device_id: &str,
    workspace_id: Option<&str>,
    target: &str,
    content_base64: &str,
    expected_target_sha256: &str,
) -> Result<(v1::ActionRequest, String), rmcp::ErrorData> {
    let max_encoded = MAX_MCP_WRITE_BYTES
        .checked_mul(4)
        .and_then(|value| value.checked_div(3))
        .and_then(|value| value.checked_add(8))
        .ok_or_else(|| rmcp::ErrorData::internal_error("write size bound overflow", None))?;
    if content_base64.len() > max_encoded {
        return Err(rmcp::ErrorData::invalid_params(
            "write content exceeds the 1 MiB limit",
            None,
        ));
    }
    let content = STANDARD
        .decode(content_base64.as_bytes())
        .map_err(|_| rmcp::ErrorData::invalid_params("content_base64 is not valid base64", None))?;
    if content.len() > MAX_MCP_WRITE_BYTES {
        return Err(rmcp::ErrorData::invalid_params(
            "write content exceeds the 1 MiB limit",
            None,
        ));
    }

    let expected = expected_target_sha256.trim();
    let expected = if expected.eq_ignore_ascii_case("absent") {
        "absent".to_owned()
    } else if expected.len() == 64 && hex::decode(expected).is_ok_and(|bytes| bytes.len() == 32) {
        expected.to_ascii_lowercase()
    } else {
        return Err(rmcp::ErrorData::invalid_params(
            "expected_target_sha256 must be 'absent' or a 64-character SHA-256 hex digest",
            None,
        ));
    };

    let content_sha256 = hex::encode(Sha256::digest(&content));
    let mut parameters = BTreeMap::new();
    parameters.insert(
        "content_base64".into(),
        Value::String(STANDARD.encode(&content)),
    );
    parameters.insert(
        "content_sha256".into(),
        Value::String(content_sha256.clone()),
    );
    parameters.insert("expected_target_sha256".into(), Value::String(expected));
    if let Some(workspace_id) = workspace_id {
        parameters.insert(
            "workspace_id".into(),
            Value::String(workspace_id.to_owned()),
        );
    }

    let now = now_unix_ms()
        .map_err(|_| rmcp::ErrorData::internal_error("system clock unavailable", None))?;
    let request = ActionRequest::seal(ActionEnvelope {
        request_id: format!("mcp-write-{:032x}", rand::random::<u128>()),
        organization_id: organization_id.to_owned(),
        actor_id: actor_id.to_owned(),
        device_id: device_id.to_owned(),
        action: "filesystem.write".into(),
        target: target.to_owned(),
        parameters,
        requested_capabilities: vec![],
        expires_at_unix_ms: now
            .checked_add(WRITE_REQUEST_TTL_MS)
            .ok_or_else(|| rmcp::ErrorData::internal_error("write expiry overflow", None))?,
        nonce: rand::random::<[u8; 16]>().to_vec(),
    })
    .map_err(|_| rmcp::ErrorData::invalid_params("invalid write request", None))?;
    let proto = action_request_to_proto(&request)
        .map_err(|_| rmcp::ErrorData::internal_error("failed to encode write request", None))?;
    Ok((proto, content_sha256))
}

const DEFAULT_MCP_TERMINAL_TIMEOUT_MS: u64 = 30_000;
const MAX_MCP_TERMINAL_TIMEOUT_MS: u64 = 120_000;
const DEFAULT_MCP_TERMINAL_OUTPUT_BYTES: usize = 256 * 1024;
const MAX_MCP_TERMINAL_OUTPUT_BYTES: usize = 512 * 1024;
const MAX_MCP_TERMINAL_ARGC: usize = 128;
const MAX_MCP_TERMINAL_ARG_BYTES: usize = 32 * 1024;
const MAX_MCP_TERMINAL_CWD_BYTES: usize = 4096;
const MAX_MCP_TERMINAL_COLUMNS: u16 = 240;
const MAX_MCP_TERMINAL_ROWS: u16 = 120;
const TERMINAL_REQUEST_TTL_MS: u64 = 180_000;

fn build_remote_terminal_request(
    organization_id: &str,
    actor_id: &str,
    workspace_id: Option<&str>,
    input: &PrepareTerminalInput,
) -> Result<v1::ActionRequest, rmcp::ErrorData> {
    if actor_id.trim().is_empty()
        || input.device_id.trim().is_empty()
        || input.cwd.trim().is_empty()
        || input.cwd.len() > MAX_MCP_TERMINAL_CWD_BYTES
        || input.cwd.contains('\0')
    {
        return Err(rmcp::ErrorData::invalid_params(
            "terminal actor, device and cwd must be valid non-empty values",
            None,
        ));
    }
    if input.argv.is_empty() || input.argv.len() > MAX_MCP_TERMINAL_ARGC {
        return Err(rmcp::ErrorData::invalid_params(
            "terminal argv must contain between 1 and 128 arguments",
            None,
        ));
    }
    let mut arg_bytes = 0usize;
    for argument in &input.argv {
        if argument.contains('\0') {
            return Err(rmcp::ErrorData::invalid_params(
                "terminal argv contains an interior NUL",
                None,
            ));
        }
        arg_bytes = arg_bytes
            .checked_add(argument.len())
            .ok_or_else(|| rmcp::ErrorData::invalid_params("terminal argv is too large", None))?;
        if arg_bytes > MAX_MCP_TERMINAL_ARG_BYTES {
            return Err(rmcp::ErrorData::invalid_params(
                "terminal argv exceeds the 32 KiB limit",
                None,
            ));
        }
    }
    if input.argv[0].trim().is_empty() {
        return Err(rmcp::ErrorData::invalid_params(
            "terminal executable must not be empty",
            None,
        ));
    }

    let timeout_ms = input.timeout_ms.unwrap_or(DEFAULT_MCP_TERMINAL_TIMEOUT_MS);
    if timeout_ms == 0 || timeout_ms > MAX_MCP_TERMINAL_TIMEOUT_MS {
        return Err(rmcp::ErrorData::invalid_params(
            "terminal timeout must be between 1 and 120000 ms",
            None,
        ));
    }
    let max_output_bytes = input
        .max_output_bytes
        .unwrap_or(DEFAULT_MCP_TERMINAL_OUTPUT_BYTES);
    if max_output_bytes == 0 || max_output_bytes > MAX_MCP_TERMINAL_OUTPUT_BYTES {
        return Err(rmcp::ErrorData::invalid_params(
            "terminal output budget must be between 1 and 524288 bytes",
            None,
        ));
    }
    let columns = input.columns.unwrap_or(120);
    let rows = input.rows.unwrap_or(40);
    if columns == 0
        || columns > MAX_MCP_TERMINAL_COLUMNS
        || rows == 0
        || rows > MAX_MCP_TERMINAL_ROWS
    {
        return Err(rmcp::ErrorData::invalid_params(
            "terminal dimensions are outside the supported range",
            None,
        ));
    }

    let mut parameters = BTreeMap::new();
    parameters.insert(
        "argv".into(),
        Value::Array(input.argv.iter().cloned().map(Value::String).collect()),
    );
    parameters.insert("timeout_ms".into(), Value::from(timeout_ms));
    parameters.insert(
        "max_output_bytes".into(),
        Value::from(u64::try_from(max_output_bytes).map_err(|_| {
            rmcp::ErrorData::invalid_params("terminal output budget is invalid", None)
        })?),
    );
    parameters.insert("columns".into(), Value::from(columns));
    parameters.insert("rows".into(), Value::from(rows));
    if let Some(workspace_id) = workspace_id {
        parameters.insert(
            "workspace_id".into(),
            Value::String(workspace_id.to_owned()),
        );
    }

    let now = now_unix_ms()
        .map_err(|_| rmcp::ErrorData::internal_error("system clock unavailable", None))?;
    let request = ActionRequest::seal(ActionEnvelope {
        request_id: format!("mcp-terminal-{:032x}", rand::random::<u128>()),
        organization_id: organization_id.to_owned(),
        actor_id: actor_id.to_owned(),
        device_id: input.device_id.clone(),
        action: "terminal.exec".into(),
        target: input.cwd.clone(),
        parameters,
        requested_capabilities: vec![],
        expires_at_unix_ms: now
            .checked_add(TERMINAL_REQUEST_TTL_MS)
            .ok_or_else(|| rmcp::ErrorData::internal_error("terminal expiry overflow", None))?,
        nonce: rand::random::<[u8; 16]>().to_vec(),
    })
    .map_err(|_| rmcp::ErrorData::invalid_params("invalid terminal request", None))?;
    action_request_to_proto(&request)
        .map_err(|_| rmcp::ErrorData::internal_error("failed to encode terminal request", None))
}

#[cfg(test)]
fn build_remote_request(
    organization_id: &str,
    actor_id: &str,
    device_id: &str,
    workspace_id: Option<&str>,
    action: &str,
    target: &str,
) -> Result<vor_wire::v1::ActionRequest, GatewayError> {
    build_remote_request_with_parameters(
        organization_id,
        actor_id,
        device_id,
        workspace_id,
        action,
        target,
        BTreeMap::new(),
    )
}

fn build_remote_request_with_parameters(
    organization_id: &str,
    actor_id: &str,
    device_id: &str,
    workspace_id: Option<&str>,
    action: &str,
    target: &str,
    mut parameters: BTreeMap<String, Value>,
) -> Result<vor_wire::v1::ActionRequest, GatewayError> {
    let now = now_unix_ms()?;
    if let Some(workspace_id) = workspace_id {
        parameters.insert(
            "workspace_id".into(),
            Value::String(workspace_id.to_owned()),
        );
    }
    let request = ActionRequest::seal(ActionEnvelope {
        request_id: format!("mcp-{:032x}", rand::random::<u128>()),
        organization_id: organization_id.to_owned(),
        actor_id: actor_id.to_owned(),
        device_id: device_id.to_owned(),
        action: action.to_owned(),
        target: target.to_owned(),
        parameters,
        requested_capabilities: vec![],
        expires_at_unix_ms: now.checked_add(20_000).ok_or(GatewayError::Clock)?,
        nonce: rand::random::<[u8; 16]>().to_vec(),
    })?;
    Ok(action_request_to_proto(&request)?)
}

// MCP defaults and maxima keep directory/search work bounded before device-side revalidation.
const DEFAULT_LIST_DEPTH: usize = 1;
const MAX_LIST_DEPTH: usize = 16;
const DEFAULT_LIST_ENTRIES: usize = 1_000;
const MAX_LIST_ENTRIES: usize = 10_000;
const DEFAULT_SEARCH_RESULTS: usize = 1_000;
const MAX_SEARCH_RESULTS: usize = 10_000;
const DEFAULT_CONTENT_MATCHES: usize = 1_000;
const MAX_CONTENT_MATCHES: usize = 10_000;
const DEFAULT_SEARCH_FILE_BYTES: usize = 1024 * 1024;
const MAX_SEARCH_FILE_BYTES: usize = 8 * 1024 * 1024;

fn render_tool_output(result: vor_wire::v1::ActionResult) -> Result<String, serde_json::Error> {
    let (encoding, data) = if result.content_type == "application/json" {
        let value = if result.output.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&result.output)?
        };
        ("json".to_owned(), value)
    } else {
        (
            "base64".to_owned(),
            Value::String(STANDARD.encode(&result.output)),
        )
    };
    serde_json::to_string(&ToolOutput {
        request_id: result.request_id,
        status: result.status,
        content_type: result.content_type,
        encoding,
        data,
        digest_base64: STANDARD.encode(result.stdout_digest),
    })
}

fn remote_tool_error(error: RemoteDispatchError) -> rmcp::ErrorData {
    match error {
        RemoteDispatchError::DeviceOffline
        | RemoteDispatchError::Private(PrivateLinkError::DeviceOffline)
        | RemoteDispatchError::Relay(RelayError::DeviceOffline) => {
            rmcp::ErrorData::invalid_params("remote device is offline", None)
        }
        RemoteDispatchError::Private(PrivateLinkError::RemoteActionNotAllowed)
        | RemoteDispatchError::Relay(RelayError::RemoteActionNotAllowed) => {
            rmcp::ErrorData::invalid_params("remote action is not allowed", None)
        }
        RemoteDispatchError::Private(PrivateLinkError::ActionTimeout)
        | RemoteDispatchError::Relay(RelayError::ActionTimeout) => {
            rmcp::ErrorData::internal_error("remote action timed out", None)
        }
        _ => rmcp::ErrorData::internal_error("remote dispatch failed", None),
    }
}

#[tool_handler]
impl ServerHandler for CommanderServer {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_protocol_version(ProtocolVersion::V_2026_07_28)
            .with_instructions("Vör Commander authenticated local MCP gateway")
    }

    fn supported_protocol_versions(&self) -> Cow<'static, [ProtocolVersion]> {
        Cow::Owned(vec![ProtocolVersion::V_2026_07_28])
    }
}

pub fn build_router(
    grants: GrantStore,
    cancellation: CancellationToken,
) -> Result<Router, GatewayError> {
    build_router_internal(grants, cancellation, None, None)
}

pub fn build_router_with_hub(
    grants: GrantStore,
    cancellation: CancellationToken,
    hub: PrivateLinkHub,
) -> Result<Router, GatewayError> {
    build_router_internal(
        grants,
        cancellation,
        Some(RemoteDispatchRouter::private_only(hub)),
        None,
    )
}

pub fn build_router_with_tenants_and_hub(
    grants: GrantStore,
    tenants: TenantStore,
    cancellation: CancellationToken,
    hub: PrivateLinkHub,
) -> Result<Router, GatewayError> {
    build_router_internal(
        grants,
        cancellation,
        Some(RemoteDispatchRouter::private_only(hub)),
        Some(tenants),
    )
}

pub fn build_router_with_links(
    grants: GrantStore,
    cancellation: CancellationToken,
    private_hub: PrivateLinkHub,
    relay_hub: RelayHub,
) -> Result<Router, GatewayError> {
    build_router_internal(
        grants,
        cancellation,
        Some(RemoteDispatchRouter::with_links(private_hub, relay_hub)),
        None,
    )
}

pub fn build_router_with_tenants(
    grants: GrantStore,
    tenants: TenantStore,
    cancellation: CancellationToken,
) -> Result<Router, GatewayError> {
    build_router_internal(grants, cancellation, None, Some(tenants))
}

fn build_router_internal(
    grants: GrantStore,
    cancellation: CancellationToken,
    remote_links: Option<RemoteDispatchRouter>,
    tenants: Option<TenantStore>,
) -> Result<Router, GatewayError> {
    let device_id = grants.device_id()?;
    let factory_device = device_id.clone();
    let factory_links = remote_links.clone();
    let factory_tenants = tenants.clone();
    let remote_dispatch_enabled = remote_links
        .as_ref()
        .is_some_and(RemoteDispatchRouter::is_enabled);
    let mcp_config = StreamableHttpServerConfig::default()
        .with_legacy_session_mode(false)
        .with_json_response(true)
        .with_allowed_hosts(["localhost", "127.0.0.1", "::1", "mcp.vorcommander.app"])
        .with_sse_keep_alive(None)
        .with_stateless_protocol_metadata_required(true)
        .with_cancellation_token(cancellation.child_token())
        .enforce_origin_validation();
    let mcp: StreamableHttpService<CommanderServer, LocalSessionManager> =
        StreamableHttpService::new(
            move || {
                Ok(CommanderServer::new(
                    factory_device.clone(),
                    factory_links.clone(),
                    factory_tenants.clone(),
                ))
            },
            Default::default(),
            mcp_config,
        );

    let state = GatewayState {
        grants,
        tenants,
        device_id,
        remote_dispatch_enabled,
        oauth: oauth::OAuthRuntime::default(),
        billing: billing::BillingConfig::from_env(),
        billing_store: billing::BillingStore::from_env()?,
    };
    let oauth_routes = oauth::router();
    let protected = Router::new()
        .route("/v1/info", get(info))
        .route("/v1/billing/status", get(billing::status))
        .route(
            "/v1/billing/checkout-session",
            post(billing::create_checkout_session),
        )
        .route(
            "/v1/billing/customer-portal",
            post(billing::create_portal_session),
        )
        .route("/v1/admin/pairings", post(create_pairing))
        .route("/v1/admin/revoke", post(revoke_grant))
        .nest_service("/mcp", mcp)
        .route_layer(middleware::from_fn_with_state(state.clone(), require_grant));

    Ok(Router::new()
        .route("/", get(dashboard))
        .route("/dashboard", get(dashboard))
        .route("/healthz", get(health))
        .route("/v1/pair", post(redeem_pairing))
        .route("/v1/billing/webhook", post(billing::webhook))
        .merge(oauth_routes)
        .merge(protected)
        .with_state(state))
}

pub async fn serve(
    config: GatewayConfig,
    grants: GrantStore,
    cancellation: CancellationToken,
) -> Result<(), GatewayError> {
    let router = build_router(grants, cancellation.clone())?;
    serve_router(config, router, cancellation).await
}

pub async fn serve_with_hub(
    config: GatewayConfig,
    grants: GrantStore,
    hub: PrivateLinkHub,
    cancellation: CancellationToken,
) -> Result<(), GatewayError> {
    let router = build_router_with_hub(grants, cancellation.clone(), hub)?;
    serve_router(config, router, cancellation).await
}

pub async fn serve_with_links(
    config: GatewayConfig,
    grants: GrantStore,
    private_hub: PrivateLinkHub,
    relay_hub: RelayHub,
    cancellation: CancellationToken,
) -> Result<(), GatewayError> {
    let router = build_router_with_links(grants, cancellation.clone(), private_hub, relay_hub)?;
    serve_router(config, router, cancellation).await
}

async fn serve_router(
    config: GatewayConfig,
    router: Router,
    cancellation: CancellationToken,
) -> Result<(), GatewayError> {
    if !config.bind.ip().is_loopback() {
        return Err(GatewayError::NonLoopbackBinding(config.bind));
    }
    let listener = tokio::net::TcpListener::bind(config.bind).await?;
    axum::serve(listener, router)
        .with_graceful_shutdown(async move { cancellation.cancelled_owned().await })
        .await?;
    Ok(())
}
const DASHBOARD_HTML: &str = r#"<!doctype html>
<meta charset="utf-8">
<title>Vör Commander</title>
<style>body{font:16px system-ui;max-width:760px;margin:3rem auto;padding:0 1rem}input,button{font:inherit;padding:.5rem;margin:.25rem}pre{white-space:pre-wrap;background:#111;color:#eee;padding:1rem}</style>
<h1>Vör Commander</h1>
<p>P4-C/OAuth gateway. Remote dispatch is read-only and enabled only when a private Hub is explicitly attached.</p>
<label>Bearer token <input id="token" type="password" autocomplete="off"></label>
<button onclick="callApi('/healthz',false)">Health</button>
<button onclick="callApi('/v1/info',true)">Authenticated info</button>
<pre id="output">Ready.</pre>
<script>
async function callApi(path, auth) {
  const headers = {};
  if (auth) headers.Authorization = 'Bearer ' + document.getElementById('token').value;
  const response = await fetch(path, {headers, cache:'no-store'});
  document.getElementById('output').textContent = response.status + '\n' + await response.text();
}
</script>"#;

async fn dashboard() -> Html<&'static str> {
    Html(DASHBOARD_HTML)
}

async fn health() -> Json<Value> {
    Json(json!({
        "status": "ok",
        "service": "vor-gateway",
        "remote_worker_dispatch": false
    }))
}

async fn info(
    State(state): State<GatewayState>,
    Extension(grant): Extension<GrantContext>,
) -> Json<Value> {
    Json(json!({
        "service": "vor-gateway",
        "version": env!("CARGO_PKG_VERSION"),
        "device_id": state.device_id,
        "actor_id": grant.0.actor_id,
        "remote_worker_dispatch": state.remote_dispatch_enabled
    }))
}

#[derive(Debug, Deserialize)]
struct RedeemPairingBody {
    code: String,
    actor_id: String,
}

#[derive(Debug, Deserialize)]
struct CreatePairingBody {
    scopes: Vec<String>,
    pairing_ttl_seconds: Option<u64>,
    grant_ttl_seconds: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct RevokeGrantBody {
    grant_id: String,
}

async fn redeem_pairing(
    State(state): State<GatewayState>,
    Json(body): Json<RedeemPairingBody>,
) -> Response {
    let Ok(now) = now_unix_ms() else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    match state.grants.redeem_pairing(&body.code, body.actor_id, now) {
        Ok(issued) => Json(json!({
            "grant_id": issued.record.grant_id,
            "actor_id": issued.record.actor_id,
            "scopes": issued.record.scopes,
            "expires_at_unix_ms": issued.record.expires_at_unix_ms,
            "token": issued.token()
        }))
        .into_response(),
        Err(AuthError::Unauthorized) => unauthorized(),
        Err(_) => StatusCode::BAD_REQUEST.into_response(),
    }
}

async fn create_pairing(
    State(state): State<GatewayState>,
    Extension(admin): Extension<GrantContext>,
    Json(body): Json<CreatePairingBody>,
) -> Response {
    let Ok(now) = now_unix_ms() else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    let pairing_ttl = body.pairing_ttl_seconds.unwrap_or(300);
    let grant_ttl = body.grant_ttl_seconds.unwrap_or(3600);
    let Some(pairing_ttl_ms) = pairing_ttl.checked_mul(1000) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let Some(grant_ttl_ms) = grant_ttl.checked_mul(1000) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    match state
        .grants
        .create_pairing(body.scopes, pairing_ttl_ms, grant_ttl_ms, now)
    {
        Ok(pairing) => (
            StatusCode::CREATED,
            Json(json!({
                "pairing_id": pairing.record.pairing_id,
                "created_by": admin.0.actor_id,
                "expires_at_unix_ms": pairing.record.expires_at_unix_ms,
                "code": pairing.code()
            })),
        )
            .into_response(),
        Err(_) => StatusCode::BAD_REQUEST.into_response(),
    }
}

async fn revoke_grant(
    State(state): State<GatewayState>,
    Extension(admin): Extension<GrantContext>,
    Json(body): Json<RevokeGrantBody>,
) -> Response {
    match state
        .grants
        .revoke_for_tenant(&body.grant_id, &admin.0.organization_id)
    {
        Ok(true) => Json(json!({"revoked": true})).into_response(),
        Ok(false) => StatusCode::NOT_FOUND.into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

async fn require_grant(
    State(state): State<GatewayState>,
    mut request: Request,
    next: Next,
) -> Response {
    let required_scope = if request.uri().path().starts_with("/mcp") {
        "mcp"
    } else if request.uri().path().starts_with("/v1/billing/") {
        "billing.manage"
    } else if request.uri().path().starts_with("/v1/admin/") {
        "admin"
    } else {
        "gateway.read"
    };
    let Some(token) = bearer_token(request.headers().get(AUTHORIZATION)) else {
        return unauthorized();
    };
    let Ok(now) = now_unix_ms() else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    match state.grants.validate(token, required_scope, now) {
        Ok(record) => {
            let required_role = if request.uri().path().starts_with("/v1/admin/") {
                TenantRole::Admin
            } else {
                TenantRole::Viewer
            };
            if let Some(tenants) = &state.tenants {
                let role_ok = tenants.verify_context(
                    &record,
                    &record.organization_id,
                    &state.device_id,
                    None,
                    required_role,
                );
                if role_ok.is_err() {
                    return unauthorized();
                }
            }
            request.extensions_mut().insert(GrantContext(record));
            next.run(request).await
        }
        Err(_) => unauthorized(),
    }
}

fn bearer_token(value: Option<&axum::http::HeaderValue>) -> Option<&str> {
    let value = value?.to_str().ok()?;
    value
        .strip_prefix("Bearer ")
        .filter(|token| !token.is_empty())
}

fn unauthorized() -> Response {
    let challenge = HeaderValue::from_static(
        "Bearer resource_metadata=\"https://mcp.vorcommander.app/.well-known/oauth-protected-resource/mcp\"",
    );
    (
        StatusCode::UNAUTHORIZED,
        [(WWW_AUTHENTICATE, challenge)],
        "unauthorized",
    )
        .into_response()
}

fn now_unix_ms() -> Result<u64, GatewayError> {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| GatewayError::Clock)?;
    u64::try_from(elapsed.as_millis()).map_err(|_| GatewayError::Clock)
}

#[derive(Debug, Error)]
pub enum GatewayError {
    #[error("gateway may bind only to loopback: {0}")]
    NonLoopbackBinding(SocketAddr),
    #[error("system clock is outside supported range")]
    Clock,
    #[error("gateway auth failed: {0}")]
    Auth(#[from] vor_auth::AuthError),
    #[error("gateway protocol failed: {0}")]
    Protocol(#[from] vor_protocol::ProtocolError),
    #[error("gateway wire conversion failed: {0}")]
    Wire(#[from] vor_wire::WireError),
    #[error("gateway I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error("gateway billing failed: {0}")]
    Billing(#[from] billing::BillingError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::{Body, to_bytes};
    use axum::http::{Request as HttpRequest, header};
    use ed25519_dalek::SigningKey;
    use std::collections::BTreeMap;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;
    use tempfile::tempdir;
    use tower::ServiceExt;
    use vor_approval::{ApprovalChallenge, sign_approval};
    use vor_dispatch::{DEFAULT_MAX_OUTPUT_BYTES, DispatchConfig, ReadOnlyDispatcher};
    use vor_identity::{
        CertificateAuthority, certificate_der_to_pem, create_device_enrollment,
        private_key_der_to_pem,
    };
    use vor_private_grpc::{
        DeviceCertificateRegistry, PrivateDeviceClientConfig, PrivateLinkConfig, PrivateLinkTls,
        run_device_dispatch, serve_with_hub,
    };
    use vor_secrets::FileSecretStore;
    use vor_wire::approval_grant_to_proto;

    fn test_state() -> (GrantStore, String, tempfile::TempDir) {
        let dir = tempdir().unwrap();
        let store = GrantStore::open(dir.path().join("auth.json")).unwrap();
        let now = now_unix_ms().unwrap();
        let issued = store
            .issue("operator", ["gateway.read", "mcp"], 60_000, now)
            .unwrap();
        (store, issued.token().to_owned(), dir)
    }

    fn auth_value(token: &str) -> String {
        format!("Bearer {token}")
    }

    fn seed_gateway_tenants(tenants: &TenantStore, device_id: &str) {
        tenants.upsert_user("admin-a", "Admin A").unwrap();
        tenants.upsert_user("admin-b", "Admin B").unwrap();
        tenants.upsert_user("viewer-a", "Viewer A").unwrap();
        tenants.upsert_organization("org-a", "Org A").unwrap();
        tenants.upsert_organization("org-b", "Org B").unwrap();
        tenants
            .upsert_workspace("org-a", "ws-a", "Workspace A")
            .unwrap();
        tenants
            .upsert_workspace("org-b", "ws-b", "Workspace B")
            .unwrap();
        tenants
            .set_membership("org-a", "admin-a", TenantRole::Admin)
            .unwrap();
        tenants
            .set_membership("org-b", "admin-b", TenantRole::Admin)
            .unwrap();
        tenants
            .set_membership("org-a", "viewer-a", TenantRole::Viewer)
            .unwrap();
        tenants.pair_device("org-a", device_id, ["ws-a"]).unwrap();
        tenants.pair_device("org-b", device_id, ["ws-b"]).unwrap();
    }

    fn modern_request(
        method: &str,
        name: Option<&str>,
        body: &'static str,
        token: Option<&str>,
    ) -> HttpRequest<Body> {
        let mut builder = HttpRequest::builder()
            .method("POST")
            .uri("/mcp")
            .header(header::HOST, "127.0.0.1")
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::ACCEPT, "application/json, text/event-stream")
            .header("MCP-Protocol-Version", "2026-07-28")
            .header("Mcp-Method", method);
        if let Some(name) = name {
            builder = builder.header("Mcp-Name", name);
        }
        if let Some(token) = token {
            builder = builder.header(AUTHORIZATION, auth_value(token));
        }
        builder.body(Body::from(body)).unwrap()
    }

    #[tokio::test]
    async fn protected_info_rejects_missing_grant_and_attributes_valid_actor() {
        let (store, token, _dir) = test_state();
        let router = build_router(store, CancellationToken::new()).unwrap();

        let response = router
            .clone()
            .oneshot(
                HttpRequest::builder()
                    .uri("/v1/info")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let response = router
            .oneshot(
                HttpRequest::builder()
                    .uri("/v1/info")
                    .header(AUTHORIZATION, auth_value(&token))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), 64 * 1024).await.unwrap();
        let value: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["actor_id"], "operator");
        assert_eq!(value["remote_worker_dispatch"], false);
    }

    #[tokio::test]
    async fn tenant_http_auth_refreshes_revocation_and_limits_admin_revoke_scope() {
        let dir = tempdir().unwrap();
        let grants = GrantStore::open(dir.path().join("auth.json")).unwrap();
        let device_id = grants.device_id().unwrap();
        let tenants_a = TenantStore::open(dir.path().join("tenants.json")).unwrap();
        seed_gateway_tenants(&tenants_a, &device_id);
        let tenants_b = TenantStore::open(dir.path().join("tenants.json")).unwrap();
        let now = now_unix_ms().unwrap();
        let admin_a = grants
            .issue_for_tenant(
                "org-a",
                "admin-a",
                ["ws-a"],
                ["gateway.read", "admin", "billing.manage"],
                60_000,
                now,
            )
            .unwrap();
        let admin_b = grants
            .issue_for_tenant("org-b", "admin-b", ["ws-b"], ["gateway.read"], 60_000, now)
            .unwrap();
        let router =
            build_router_with_tenants(grants.clone(), tenants_b, CancellationToken::new()).unwrap();

        let response = router
            .clone()
            .oneshot(
                HttpRequest::builder()
                    .uri("/v1/info")
                    .header(AUTHORIZATION, auth_value(admin_a.token()))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let cross_revoke = router
            .clone()
            .oneshot(
                HttpRequest::builder()
                    .method("POST")
                    .uri("/v1/admin/revoke")
                    .header(AUTHORIZATION, auth_value(admin_a.token()))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        json!({"grant_id": admin_b.record.grant_id}).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(cross_revoke.status(), StatusCode::NOT_FOUND);
        grants
            .validate_for_tenant(
                admin_b.token(),
                "gateway.read",
                "org-b",
                Some("ws-b"),
                now + 1,
            )
            .unwrap();

        tenants_a.revoke_membership("org-a", "admin-a").unwrap();
        let revoked = router
            .clone()
            .oneshot(
                HttpRequest::builder()
                    .uri("/v1/info")
                    .header(AUTHORIZATION, auth_value(admin_a.token()))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(revoked.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn billing_checkout_rejects_cross_tenant_before_provider_boundary() {
        let dir = tempdir().unwrap();
        let grants = GrantStore::open(dir.path().join("auth.json")).unwrap();
        let device_id = grants.device_id().unwrap();
        let tenants = TenantStore::open(dir.path().join("tenants.json")).unwrap();
        seed_gateway_tenants(&tenants, &device_id);
        let issued = grants
            .issue_for_tenant(
                "org-a",
                "admin-a",
                ["ws-a"],
                ["billing.manage"],
                60_000,
                now_unix_ms().unwrap(),
            )
            .unwrap();
        let router = build_router_with_tenants(grants, tenants, CancellationToken::new()).unwrap();
        async fn checkout_rejection(
            router: Router,
            token: &str,
            organization_id: &str,
        ) -> (StatusCode, Vec<u8>) {
            let response = router
                .oneshot(
                    HttpRequest::builder()
                        .method("POST")
                        .uri("/v1/billing/checkout-session")
                        .header(AUTHORIZATION, auth_value(token))
                        .header(header::CONTENT_TYPE, "application/json")
                        .body(Body::from(
                            json!({
                                "organization_id": organization_id,
                                "plan_id": "personal-cloud"
                            })
                            .to_string(),
                        ))
                        .unwrap(),
                )
                .await
                .unwrap();
            let status = response.status();
            let body = to_bytes(response.into_body(), 64 * 1024)
                .await
                .unwrap()
                .to_vec();
            (status, body)
        }
        let foreign_existing = checkout_rejection(router.clone(), issued.token(), "org-b").await;
        let foreign_missing =
            checkout_rejection(router, issued.token(), "org-does-not-exist").await;
        assert_eq!(foreign_existing.0, StatusCode::BAD_REQUEST);
        assert_eq!(foreign_existing, foreign_missing);
    }

    #[tokio::test]
    async fn c14_router_exposes_no_unfiltered_audit_receipt_or_browser_listing() {
        let (store, token, _dir) = test_state();
        let router = build_router(store, CancellationToken::new()).unwrap();
        for route in [
            "/v1/audit",
            "/v1/audit/records",
            "/v1/receipts",
            "/v1/browser/sessions",
            "/v1/browser/receipts",
        ] {
            let response = router
                .clone()
                .oneshot(
                    HttpRequest::builder()
                        .uri(route)
                        .header(AUTHORIZATION, auth_value(&token))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(
                response.status(),
                StatusCode::NOT_FOUND,
                "unexpected route {route}"
            );
        }
    }

    #[tokio::test]
    async fn billing_status_requires_billing_manage_scope() {
        let (store, reader_token, _dir) = test_state();
        let billing_token = store
            .issue(
                "billing-operator",
                ["billing.manage"],
                60_000,
                now_unix_ms().unwrap(),
            )
            .unwrap()
            .token()
            .to_owned();
        let router = build_router(store, CancellationToken::new()).unwrap();

        let missing = router
            .clone()
            .oneshot(
                HttpRequest::builder()
                    .uri("/v1/billing/status")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(missing.status(), StatusCode::UNAUTHORIZED);

        let wrong_scope = router
            .clone()
            .oneshot(
                HttpRequest::builder()
                    .uri("/v1/billing/status")
                    .header(AUTHORIZATION, auth_value(&reader_token))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(wrong_scope.status(), StatusCode::UNAUTHORIZED);

        let allowed = router
            .oneshot(
                HttpRequest::builder()
                    .uri("/v1/billing/status")
                    .header(AUTHORIZATION, auth_value(&billing_token))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(allowed.status(), StatusCode::OK);
        let body = to_bytes(allowed.into_body(), 64 * 1024).await.unwrap();
        let value: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["provider"], "stripe");
        assert_eq!(value["charges_enabled"], false);
        assert_eq!(value["authority_boundary"], "hosted_capacity_only");
    }

    #[tokio::test]
    async fn mcp_tools_list_requires_grant_and_accepts_2026_stateless() {
        let (store, token, _dir) = test_state();
        let router = build_router(store, CancellationToken::new()).unwrap();
        let list = r#"{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}"#;

        let unauthorized = modern_request("tools/list", None, list, None);
        let response = router.clone().oneshot(unauthorized).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let authorized = modern_request("tools/list", None, list, Some(&token));
        let response = router.oneshot(authorized).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), 256 * 1024).await.unwrap();
        let value: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["id"], 1);
        let tools = value["result"]["tools"].as_array().unwrap();
        let names = tools
            .iter()
            .filter_map(|tool| tool["name"].as_str())
            .collect::<std::collections::BTreeSet<_>>();
        for required in [
            "commander_status",
            "read_file",
            "list_directory",
            "search_files",
            "search_content",
            "file_info",
            "git_status",
            "git_diff",
            "process_list",
            "process_inspect",
            "prepare_write",
            "prepare_edit",
            "commit_write",
            "prepare_terminal",
            "commit_terminal",
            "poll_terminal",
            "cancel_terminal",
        ] {
            assert!(
                names.contains(required),
                "missing tool {required}: {names:?}"
            );
        }
        for forbidden in [
            "terminal_exec",
            "write_file",
            "browser_use",
            "process_terminate",
        ] {
            assert!(
                !names.contains(forbidden),
                "unsafe tool exposed: {forbidden}"
            );
        }
    }

    #[tokio::test]
    async fn authenticated_mcp_status_tool_is_safe_and_stateless() {
        let (store, token, _dir) = test_state();
        let router = build_router(store, CancellationToken::new()).unwrap();
        let call = r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"commander_status","arguments":{},"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientInfo":{"name":"vor-test","version":"1.0"},"io.modelcontextprotocol/clientCapabilities":{}}}}"#;
        let request = modern_request("tools/call", Some("commander_status"), call, Some(&token));
        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), 256 * 1024).await.unwrap();
        let text = String::from_utf8(body.to_vec()).unwrap();
        assert!(text.contains("vor-commander"), "body={text}");
        assert!(text.contains("remote_worker_dispatch"), "body={text}");
        assert!(text.contains("remote_connectivity"), "body={text}");
        assert!(text.contains("recommended_device_id"), "body={text}");
        assert!(text.contains("operator_hint"), "body={text}");
        assert!(text.contains("operator"), "body={text}");
        assert!(text.contains("false"), "body={text}");
    }

    #[tokio::test]
    async fn hostile_browser_origin_is_rejected_before_mcp_dispatch() {
        let (store, token, _dir) = test_state();
        let router = build_router(store, CancellationToken::new()).unwrap();
        let list = r#"{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}"#;
        let mut request = modern_request("tools/list", None, list, Some(&token));
        request.headers_mut().insert(
            header::ORIGIN,
            header::HeaderValue::from_static("https://attacker.example"),
        );
        let response = router.oneshot(request).await.unwrap();
        assert_ne!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn dashboard_is_public_but_does_not_embed_device_identity() {
        let (store, _token, _dir) = test_state();
        let device_id = store.device_id().unwrap();
        let router = build_router(store, CancellationToken::new()).unwrap();
        let response = router
            .oneshot(
                HttpRequest::builder()
                    .uri("/dashboard")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), 128 * 1024).await.unwrap();
        let text = String::from_utf8(body.to_vec()).unwrap();
        assert!(text.contains("Vör Commander"));
        assert!(!text.contains(&device_id));
    }

    #[tokio::test]
    async fn oauth_dcr_client_persists_across_gateway_reopen() {
        let dir = tempdir().unwrap();
        let state_path = dir.path().join("auth.json");
        let store = GrantStore::open(&state_path).unwrap();
        let router = build_router(store.clone(), CancellationToken::new()).unwrap();
        let registration = json!({
            "redirect_uris": ["https://chatgpt.com/connector/oauth/callback"],
            "client_name": "ChatGPT persisted client",
            "token_endpoint_auth_method": "none",
            "grant_types": ["authorization_code"],
            "response_types": ["code"],
            "application_type": "web"
        });
        let request = HttpRequest::builder()
            .method("POST")
            .uri("/oauth/register")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(registration.to_string()))
            .unwrap();
        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);
        let bytes = to_bytes(response.into_body(), 128 * 1024).await.unwrap();
        let registered: Value = serde_json::from_slice(&bytes).unwrap();
        let client_id = registered["client_id"].as_str().unwrap().to_owned();
        assert!(store.oauth_client(&client_id).unwrap().is_some());
        drop(store);

        let reopened = GrantStore::open(&state_path).unwrap();
        assert!(reopened.oauth_client(&client_id).unwrap().is_some());
        let router = build_router(reopened, CancellationToken::new()).unwrap();
        let authorize_uri = format!(
            "/oauth/authorize?response_type=code&client_id={client_id}&redirect_uri=https%3A%2F%2Fchatgpt.com%2Fconnector%2Foauth%2Fcallback&scope=mcp%20gateway.read&state=persisted&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256&resource=https%3A%2F%2Fmcp.vorcommander.app%2Fmcp"
        );
        let response = router
            .oneshot(
                HttpRequest::builder()
                    .uri(authorize_uri)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = to_bytes(response.into_body(), 128 * 1024).await.unwrap();
        let text = String::from_utf8(bytes.to_vec()).unwrap();
        assert!(text.contains("Vör Commander"));
        assert!(text.contains("ChatGPT persisted client"));
        assert!(!text.contains("VÃ¶r"));
    }

    #[tokio::test]
    async fn admin_pairing_redeem_and_revoke_are_fail_closed() {
        let dir = tempdir().unwrap();
        let state_path = dir.path().join("auth.json");
        let store = GrantStore::open(&state_path).unwrap();
        let now = now_unix_ms().unwrap();
        let admin = store
            .issue("admin-operator", ["admin"], 60_000, now)
            .unwrap();
        let non_admin = store
            .issue("reader", ["gateway.read"], 60_000, now)
            .unwrap();
        let router = build_router(store.clone(), CancellationToken::new()).unwrap();
        let pairing_body = json!({
            "scopes": ["gateway.read"],
            "pairing_ttl_seconds": 60,
            "grant_ttl_seconds": 60
        });

        let denied = HttpRequest::builder()
            .method("POST")
            .uri("/v1/admin/pairings")
            .header(header::CONTENT_TYPE, "application/json")
            .header(AUTHORIZATION, auth_value(non_admin.token()))
            .body(Body::from(pairing_body.to_string()))
            .unwrap();
        assert_eq!(
            router.clone().oneshot(denied).await.unwrap().status(),
            StatusCode::UNAUTHORIZED
        );

        let create = HttpRequest::builder()
            .method("POST")
            .uri("/v1/admin/pairings")
            .header(header::CONTENT_TYPE, "application/json")
            .header(AUTHORIZATION, auth_value(admin.token()))
            .body(Body::from(pairing_body.to_string()))
            .unwrap();
        let response = router.clone().oneshot(create).await.unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);
        let bytes = to_bytes(response.into_body(), 128 * 1024).await.unwrap();
        let created: Value = serde_json::from_slice(&bytes).unwrap();
        let code = created["code"].as_str().unwrap().to_owned();
        let disk = fs::read_to_string(&state_path).unwrap();
        assert!(!disk.contains(&code));

        let redeem_body = json!({"code": code, "actor_id": "paired-client"});
        let redeem = HttpRequest::builder()
            .method("POST")
            .uri("/v1/pair")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(redeem_body.to_string()))
            .unwrap();
        let response = router.clone().oneshot(redeem).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = to_bytes(response.into_body(), 128 * 1024).await.unwrap();
        let redeemed: Value = serde_json::from_slice(&bytes).unwrap();
        let token = redeemed["token"].as_str().unwrap().to_owned();
        let grant_id = redeemed["grant_id"].as_str().unwrap().to_owned();
        assert!(!fs::read_to_string(&state_path).unwrap().contains(&token));

        let info = HttpRequest::builder()
            .uri("/v1/info")
            .header(AUTHORIZATION, auth_value(&token))
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            router.clone().oneshot(info).await.unwrap().status(),
            StatusCode::OK
        );

        let second = HttpRequest::builder()
            .method("POST")
            .uri("/v1/pair")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(redeem_body.to_string()))
            .unwrap();
        assert_eq!(
            router.clone().oneshot(second).await.unwrap().status(),
            StatusCode::UNAUTHORIZED
        );

        let revoke = HttpRequest::builder()
            .method("POST")
            .uri("/v1/admin/revoke")
            .header(header::CONTENT_TYPE, "application/json")
            .header(AUTHORIZATION, auth_value(admin.token()))
            .body(Body::from(json!({"grant_id": grant_id}).to_string()))
            .unwrap();
        assert_eq!(
            router.clone().oneshot(revoke).await.unwrap().status(),
            StatusCode::OK
        );

        let revoked_info = HttpRequest::builder()
            .uri("/v1/info")
            .header(AUTHORIZATION, auth_value(&token))
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            router.oneshot(revoked_info).await.unwrap().status(),
            StatusCode::UNAUTHORIZED
        );
    }

    #[tokio::test]
    async fn serve_rejects_non_loopback_bind_before_listening() {
        let dir = tempdir().unwrap();
        let store = GrantStore::open(dir.path().join("auth.json")).unwrap();
        let config = GatewayConfig {
            bind: "0.0.0.0:0".parse().unwrap(),
        };
        let result = serve(config, store, CancellationToken::new()).await;
        assert!(matches!(result, Err(GatewayError::NonLoopbackBinding(_))));
    }

    #[test]
    fn remote_requests_use_authenticated_grant_organization() {
        let write = build_remote_write_request(
            "org-a",
            "actor-a",
            "device-a",
            Some("ws-a1"),
            r"D:\Proyectos\demo.txt",
            &STANDARD.encode(b"tenant-data"),
            "absent",
        )
        .unwrap()
        .0;
        let write = action_request_from_proto(&write).unwrap();
        assert_eq!(write.envelope.organization_id, "org-a");
        assert_eq!(write.envelope.actor_id, "actor-a");

        let terminal = build_remote_terminal_request(
            "org-b",
            "actor-b",
            Some("ws-b1"),
            &PrepareTerminalInput {
                device_id: "device-b".into(),
                workspace_id: Some("ws-b1".into()),
                cwd: r"D:\Proyectos".into(),
                argv: vec!["cmd.exe".into(), "/C".into(), "echo ok".into()],
                timeout_ms: Some(1_000),
                max_output_bytes: Some(1024),
                columns: Some(80),
                rows: Some(25),
            },
        )
        .unwrap();
        let terminal = action_request_from_proto(&terminal).unwrap();
        assert_eq!(terminal.envelope.organization_id, "org-b");
        assert_eq!(terminal.envelope.actor_id, "actor-b");
        assert_eq!(
            terminal
                .envelope
                .parameters
                .get("workspace_id")
                .and_then(Value::as_str),
            Some("ws-b1")
        );

        let read = build_remote_request(
            "org-c",
            "actor-c",
            "device-c",
            Some("ws-c1"),
            "filesystem.read",
            r"D:\Proyectos\README.md",
        )
        .unwrap();
        let read = action_request_from_proto(&read).unwrap();
        assert_eq!(read.envelope.organization_id, "org-c");
        assert_eq!(read.envelope.actor_id, "actor-c");
    }

    #[test]
    fn tenant_prepare_commit_requires_signed_workspace_binding() {
        let dir = tempdir().unwrap();
        let grants = GrantStore::open(dir.path().join("auth.json")).unwrap();
        let tenants = TenantStore::open(dir.path().join("tenants.json")).unwrap();
        tenants.upsert_user("actor-a", "Actor A").unwrap();
        tenants.upsert_organization("org-a", "Org A").unwrap();
        tenants
            .upsert_workspace("org-a", "ws-a1", "Workspace A1")
            .unwrap();
        tenants
            .upsert_workspace("org-a", "ws-a2", "Workspace A2")
            .unwrap();
        tenants
            .set_membership("org-a", "actor-a", TenantRole::Operator)
            .unwrap();
        tenants
            .pair_device("org-a", "device-a", ["ws-a1", "ws-a2"])
            .unwrap();
        let grant = grants
            .issue_for_tenant(
                "org-a",
                "actor-a",
                ["ws-a1", "ws-a2"],
                ["mcp"],
                60_000,
                now_unix_ms().unwrap(),
            )
            .unwrap()
            .record
            .clone();
        let server = CommanderServer::new("gateway-a".into(), None, Some(tenants));

        let missing = server.authorize_prepared_mcp(
            &grant,
            "device-a",
            Some("ws-a1"),
            None,
            TenantRole::Operator,
        );
        assert!(missing.is_err());

        let mismatch = server.authorize_prepared_mcp(
            &grant,
            "device-a",
            Some("ws-a2"),
            Some("ws-a1"),
            TenantRole::Operator,
        );
        assert!(mismatch.is_err());

        let mut parameters = BTreeMap::new();
        parameters.insert("workspace_id".into(), Value::Null);
        assert!(signed_workspace_id(&parameters).is_err());
        parameters.insert("workspace_id".into(), Value::from(1));
        assert!(signed_workspace_id(&parameters).is_err());

        server
            .authorize_prepared_mcp(
                &grant,
                "device-a",
                Some("ws-a1"),
                Some("ws-a1"),
                TenantRole::Operator,
            )
            .unwrap();
    }

    fn find_git() -> PathBuf {
        let path = std::env::var_os("PATH").expect("PATH must be available");
        std::env::split_paths(&path)
            .map(|entry| entry.join("git.exe"))
            .find(|candidate| candidate.is_file())
            .expect("git.exe must be available on PATH")
    }

    fn e2e_policy(path: &Path, root: &Path) {
        let root = root.to_string_lossy().replace('\\', "\\\\");
        let yaml = format!(
            r#"version: 1
policy_id: gateway-e2e
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
"#
        );

        let yaml = yaml
            + r#"browser:
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
"#;
        fs::write(path, yaml).unwrap();
    }

    struct GatewayE2eFixture {
        ca_pem: String,
        server_cert_pem: String,
        server_key_pem: String,
        device_cert_der: Vec<u8>,
        device_cert_pem: String,
        device_key_pem: String,
        _cert_dir: tempfile::TempDir,
    }

    struct GatewayE2eDeviceFixture {
        cert_der: Vec<u8>,
        cert_pem: String,
        key_pem: String,
    }

    struct GatewayMultiDeviceE2eFixture {
        ca_pem: String,
        server_cert_pem: String,
        server_key_pem: String,
        devices: BTreeMap<String, GatewayE2eDeviceFixture>,
        _cert_dir: tempfile::TempDir,
    }

    fn gateway_e2e_certs() -> GatewayE2eFixture {
        let dir = tempdir().unwrap();
        let store = FileSecretStore::open(dir.path()).unwrap();
        let enrollment = create_device_enrollment(&store, "device-key", "device-e2e").unwrap();
        let ca = CertificateAuthority::new("Vör Gateway E2E CA").unwrap();
        let ca_der = ca.certificate_der();
        let device_cert_der = ca
            .sign_device_csr("device-e2e", &enrollment.csr_der)
            .unwrap();
        let device_key_der = store.get("device-key").unwrap().into_vec();
        let server = ca.issue_server_certificate("localhost").unwrap();
        let (server_cert_der, server_key_der) = server.into_parts();
        GatewayE2eFixture {
            ca_pem: certificate_der_to_pem(&ca_der),
            server_cert_pem: certificate_der_to_pem(&server_cert_der),
            server_key_pem: private_key_der_to_pem(&server_key_der),
            device_cert_pem: certificate_der_to_pem(&device_cert_der),
            device_key_pem: private_key_der_to_pem(&device_key_der),
            device_cert_der,
            _cert_dir: dir,
        }
    }

    fn gateway_e2e_certs_for_devices(device_ids: &[&str]) -> GatewayMultiDeviceE2eFixture {
        let dir = tempdir().unwrap();
        let store = FileSecretStore::open(dir.path()).unwrap();
        let ca = CertificateAuthority::new("Vör Gateway E2E CA").unwrap();
        let ca_der = ca.certificate_der();
        let server = ca.issue_server_certificate("localhost").unwrap();
        let (server_cert_der, server_key_der) = server.into_parts();
        let mut devices = BTreeMap::new();
        for device_id in device_ids {
            let secret_key = format!("device-key-{device_id}");
            let enrollment = create_device_enrollment(&store, &secret_key, device_id).unwrap();
            let cert_der = ca.sign_device_csr(device_id, &enrollment.csr_der).unwrap();
            let key_der = store.get(&secret_key).unwrap().into_vec();
            devices.insert(
                (*device_id).to_owned(),
                GatewayE2eDeviceFixture {
                    cert_pem: certificate_der_to_pem(&cert_der),
                    key_pem: private_key_der_to_pem(&key_der),
                    cert_der,
                },
            );
        }
        GatewayMultiDeviceE2eFixture {
            ca_pem: certificate_der_to_pem(&ca_der),
            server_cert_pem: certificate_der_to_pem(&server_cert_der),
            server_key_pem: private_key_der_to_pem(&server_key_der),
            devices,
            _cert_dir: dir,
        }
    }

    async fn mcp_tool_call(
        router: Router,
        token: &str,
        id: u64,
        name: &str,
        arguments: Value,
    ) -> (StatusCode, Value) {
        let call = json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "tools/call",
            "params": {
                "name": name,
                "arguments": arguments,
                "_meta": {
                    "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                    "io.modelcontextprotocol/clientInfo": {"name": "vor-e2e", "version": "1"},
                    "io.modelcontextprotocol/clientCapabilities": {}
                }
            }
        })
        .to_string();
        let request = HttpRequest::builder()
            .method("POST")
            .uri("/mcp")
            .header(header::HOST, "127.0.0.1")
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::ACCEPT, "application/json, text/event-stream")
            .header("MCP-Protocol-Version", "2026-07-28")
            .header("Mcp-Method", "tools/call")
            .header("Mcp-Name", name)
            .header(AUTHORIZATION, auth_value(token))
            .body(Body::from(call))
            .unwrap();
        let response = router.oneshot(request).await.unwrap();
        let status = response.status();
        let bytes = to_bytes(response.into_body(), 2 * 1024 * 1024)
            .await
            .unwrap();
        let value = serde_json::from_slice(&bytes).unwrap_or_else(|_| {
            json!({
                "raw": String::from_utf8_lossy(&bytes)
            })
        });
        (status, value)
    }

    fn tool_text_json(response: &Value) -> Value {
        let text = response["result"]["content"][0]["text"]
            .as_str()
            .unwrap_or_else(|| panic!("MCP response has no tool result: {response}"));
        serde_json::from_str(text)
            .unwrap_or_else(|error| panic!("MCP tool result is not JSON ({error}): {response}"))
    }

    fn sign_prepared(prepared: &Value, approver_id: &str, signing: &SigningKey) -> String {
        let challenge = &prepared["challenge"];
        let envelope_digest: [u8; 32] = STANDARD
            .decode(challenge["envelope_digest_base64"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let approval_nonce: [u8; 32] = STANDARD
            .decode(challenge["approval_nonce_base64"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let signed = sign_approval(
            ApprovalChallenge {
                request_id: challenge["request_id"].as_str().unwrap().to_owned(),
                envelope_digest,
                policy_id: challenge["policy_id"].as_str().unwrap().to_owned(),
                required_capability: challenge["required_capability"].as_str().map(str::to_owned),
                expires_at_unix_ms: challenge["expires_at_unix_ms"].as_u64().unwrap(),
                approval_nonce,
            },
            approver_id,
            signing,
        )
        .unwrap();
        STANDARD.encode(approval_grant_to_proto(&signed).unwrap().encode_to_vec())
    }

    #[tokio::test]
    async fn mcp_read_file_reaches_mtls_device_and_audits_grant_actor() {
        let certs = gateway_e2e_certs();
        let data = tempdir().unwrap();
        let file = data.path().join("mcp-e2e.txt");
        fs::write(&file, b"mcp-read-ok").unwrap();
        let policy = data.path().join("policy.yaml");
        e2e_policy(&policy, data.path());
        let audit_jsonl = data.path().join("audit.jsonl");
        let signing = SigningKey::from_bytes(&[41; 32]);
        let mut dispatcher_value = ReadOnlyDispatcher::open(DispatchConfig {
            device_id: "device-e2e".into(),
            policy_path: policy,
            audit_sqlite: data.path().join("audit.db"),
            audit_jsonl: audit_jsonl.clone(),
            journal_dir: data.path().join("journal"),
            allowed_roots: vec![data.path().to_path_buf()],
            git_executable: find_git(),
            max_output_bytes: DEFAULT_MAX_OUTPUT_BYTES,
            browser: None,
        })
        .unwrap();
        dispatcher_value
            .add_trusted_approver_for_organization(
                "operator-e2e",
                signing.verifying_key().to_bytes(),
                vor_dispatch::ApproverAuthority::Owner,
                "org-e2e",
            )
            .unwrap();
        let dispatcher = Arc::new(Mutex::new(dispatcher_value));

        let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let private_addr = probe.local_addr().unwrap();
        drop(probe);
        let hub = PrivateLinkHub::default();
        let registry = DeviceCertificateRegistry::from_certificates([(
            "device-e2e".to_owned(),
            certs.device_cert_der.clone(),
        )])
        .unwrap();
        let server_cancel = CancellationToken::new();
        let server_shutdown = server_cancel.clone();
        let server_hub = hub.clone();
        let server_tls = PrivateLinkTls {
            ca_pem: certs.ca_pem.as_bytes().to_vec(),
            server_cert_pem: certs.server_cert_pem.as_bytes().to_vec(),
            server_key_pem: certs.server_key_pem.as_bytes().to_vec(),
        };
        let server_task = tokio::spawn(async move {
            serve_with_hub(
                PrivateLinkConfig {
                    bind: private_addr,
                    replay_capacity: 64,
                },
                server_tls,
                registry,
                server_hub,
                server_shutdown,
            )
            .await
        });
        tokio::time::sleep(Duration::from_millis(50)).await;

        let client_cancel = CancellationToken::new();
        let client_shutdown = client_cancel.clone();
        let client_dispatcher = dispatcher.clone();
        let client_config = PrivateDeviceClientConfig {
            endpoint: format!("https://{private_addr}"),
            server_name: "localhost".into(),
            device_id: "device-e2e".into(),
            ca_pem: certs.ca_pem.as_bytes().to_vec(),
            device_cert_pem: certs.device_cert_pem.as_bytes().to_vec(),
            device_key_pem: certs.device_key_pem.as_bytes().to_vec(),
            agent_version: "0.1.0-e2e".into(),
            heartbeat_interval: Duration::from_secs(30),
            replay_capacity: 64,
        };
        let client_task = tokio::spawn(async move {
            run_device_dispatch(client_config, client_dispatcher, client_shutdown).await
        });
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                if hub.connected_devices().await == vec!["device-e2e".to_owned()] {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();

        let auth_dir = tempdir().unwrap();
        let grants = GrantStore::open(auth_dir.path().join("auth.json")).unwrap();
        let gateway_device_id = grants.device_id().unwrap();
        let tenants = TenantStore::open(auth_dir.path().join("tenants.json")).unwrap();
        tenants.upsert_user("operator", "Operator").unwrap();
        tenants.upsert_organization("org-e2e", "Org E2E").unwrap();
        tenants
            .upsert_workspace("org-e2e", "ws-e2e", "Workspace E2E")
            .unwrap();
        tenants
            .upsert_workspace("org-e2e", "ws-e2e-alt", "Workspace E2E Alt")
            .unwrap();
        tenants
            .upsert_workspace("org-e2e", "ws-e2e-alt", "Workspace E2E Alt")
            .unwrap();
        tenants
            .set_membership("org-e2e", "operator", TenantRole::Operator)
            .unwrap();
        tenants
            .pair_device("org-e2e", "device-e2e", ["ws-e2e", "ws-e2e-alt"])
            .unwrap();
        tenants
            .pair_device("org-e2e", &gateway_device_id, ["ws-e2e", "ws-e2e-alt"])
            .unwrap();
        let issued = grants
            .issue_for_tenant(
                "org-e2e",
                "operator",
                ["ws-e2e", "ws-e2e-alt"],
                ["mcp"],
                60_000,
                now_unix_ms().unwrap(),
            )
            .unwrap();
        let router = build_router_with_tenants_and_hub(
            grants,
            tenants.clone(),
            CancellationToken::new(),
            hub,
        )
        .unwrap();
        let missing_workspace_call = json!({
            "jsonrpc": "2.0",
            "id": 89,
            "method": "tools/call",
            "params": {
                "name": "read_file",
                "arguments": {
                    "device_id": "device-e2e",
                    "path": file.to_string_lossy()
                },
                "_meta": {
                    "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                    "io.modelcontextprotocol/clientInfo": {"name": "vor-e2e", "version": "1"},
                    "io.modelcontextprotocol/clientCapabilities": {}
                }
            }
        })
        .to_string();
        let missing_workspace_request = HttpRequest::builder()
            .method("POST")
            .uri("/mcp")
            .header(header::HOST, "127.0.0.1")
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::ACCEPT, "application/json, text/event-stream")
            .header("MCP-Protocol-Version", "2026-07-28")
            .header("Mcp-Method", "tools/call")
            .header("Mcp-Name", "read_file")
            .header(AUTHORIZATION, auth_value(issued.token()))
            .body(Body::from(missing_workspace_call))
            .unwrap();
        let response = router
            .clone()
            .oneshot(missing_workspace_request)
            .await
            .unwrap();
        assert_ne!(response.status(), StatusCode::OK);
        let call = json!({
            "jsonrpc": "2.0",
            "id": 90,
            "method": "tools/call",
            "params": {
                "name": "read_file",
                "arguments": {
                    "device_id": "device-e2e",
                    "workspace_id": "ws-e2e",
                    "path": file.to_string_lossy()
                },
                "_meta": {
                    "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                    "io.modelcontextprotocol/clientInfo": {"name": "vor-e2e", "version": "1"},
                    "io.modelcontextprotocol/clientCapabilities": {}
                }
            }
        })
        .to_string();

        let request = HttpRequest::builder()
            .method("POST")
            .uri("/mcp")
            .header(header::HOST, "127.0.0.1")
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::ACCEPT, "application/json, text/event-stream")
            .header("MCP-Protocol-Version", "2026-07-28")
            .header("Mcp-Method", "tools/call")
            .header("Mcp-Name", "read_file")
            .header(AUTHORIZATION, auth_value(issued.token()))
            .body(Body::from(call))
            .unwrap();
        let response = router.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = to_bytes(response.into_body(), 512 * 1024).await.unwrap();
        let text = String::from_utf8(bytes.to_vec()).unwrap();
        let expected = STANDARD.encode(b"mcp-read-ok");
        assert!(text.contains(&expected), "body={text}");
        assert!(text.contains("application/octet-stream"), "body={text}");
        assert!(text.contains("\\\"status\\\":\\\"ok\\\""), "body={text}");

        let (status, rpc) = mcp_tool_call(
            router.clone(), issued.token(), 900, "search_content",
            json!({"device_id":"device-e2e", "workspace_id":"ws-e2e", "root":data.path().to_string_lossy(), "query":"mcp-read-ok", "regex":false, "file_glob":"**/*.txt", "max_matches":1, "max_file_bytes":1024})
        ).await;
        assert_eq!(status, StatusCode::OK);
        let searched = tool_text_json(&rpc);
        assert_eq!(searched["status"], "ok");
        assert_eq!(searched["data"]["matches"].as_array().unwrap().len(), 1);
        assert_eq!(searched["data"]["matches"][0]["line"], 1);
        assert_eq!(searched["data"]["matches"][0]["encoding"], "utf-8");
        assert_eq!(searched["data"]["skipped_binary_files"], 0);
        assert_eq!(searched["data"]["skipped_size_limit_files"], 0);

        let (foreign_status, foreign_rpc) = mcp_tool_call(
            router.clone(), issued.token(), 901, "search_content",
            json!({"device_id":"device-e2e", "workspace_id":"ws-foreign", "root":data.path().to_string_lossy(), "query":"mcp-read-ok", "regex":false})
        ).await;
        assert_ne!(foreign_status, StatusCode::OK);
        assert!(!foreign_rpc.to_string().contains("mcp-read-ok"));

        let audit = fs::read_to_string(&audit_jsonl).unwrap();
        assert!(audit.contains("\"actor_id\":\"operator\""), "audit={audit}");
        assert!(
            audit.contains("\"action\":\"filesystem.read\""),
            "audit={audit}"
        );
        assert!(
            audit.contains("\"action\":\"filesystem.search_content\""),
            "audit={audit}"
        );

        let write_target = data.path().join("mcp-write-e2e.txt");
        fs::write(&write_target, b"before-write").unwrap();
        let expected_target_sha256 = hex::encode(Sha256::digest(b"before-write"));
        let prepare_call = json!({
            "jsonrpc": "2.0",
            "id": 91,
            "method": "tools/call",
            "params": {
                "name": "prepare_write",
                "arguments": {
                    "device_id": "device-e2e",
                    "workspace_id": "ws-e2e",
                    "path": write_target.to_string_lossy(),
                    "content_base64": STANDARD.encode(b"after-write"),
                    "expected_target_sha256": expected_target_sha256
                },
                "_meta": {
                    "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                    "io.modelcontextprotocol/clientInfo": {"name": "vor-e2e", "version": "1"},
                    "io.modelcontextprotocol/clientCapabilities": {}
                }
            }
        })
        .to_string();
        let prepare_request = HttpRequest::builder()
            .method("POST")
            .uri("/mcp")
            .header(header::HOST, "127.0.0.1")
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::ACCEPT, "application/json, text/event-stream")
            .header("MCP-Protocol-Version", "2026-07-28")
            .header("Mcp-Method", "tools/call")
            .header("Mcp-Name", "prepare_write")
            .header(AUTHORIZATION, auth_value(issued.token()))
            .body(Body::from(prepare_call))
            .unwrap();
        let response = router.clone().oneshot(prepare_request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = to_bytes(response.into_body(), 2 * 1024 * 1024)
            .await
            .unwrap();
        let rpc: Value = serde_json::from_slice(&bytes).unwrap();
        let prepare_text = rpc["result"]["content"][0]["text"].as_str().unwrap();
        let prepared: Value = serde_json::from_str(prepare_text).unwrap();
        assert_eq!(prepared["status"], "approval_required");
        assert_eq!(fs::read(&write_target).unwrap(), b"before-write");

        let challenge = &prepared["challenge"];
        let envelope_digest: [u8; 32] = STANDARD
            .decode(challenge["envelope_digest_base64"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let approval_nonce: [u8; 32] = STANDARD
            .decode(challenge["approval_nonce_base64"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let signed = sign_approval(
            ApprovalChallenge {
                request_id: challenge["request_id"].as_str().unwrap().to_owned(),
                envelope_digest,
                policy_id: challenge["policy_id"].as_str().unwrap().to_owned(),
                required_capability: challenge["required_capability"].as_str().map(str::to_owned),
                expires_at_unix_ms: challenge["expires_at_unix_ms"].as_u64().unwrap(),
                approval_nonce,
            },
            "operator-e2e",
            &signing,
        )
        .unwrap();
        let approval_base64 =
            STANDARD.encode(approval_grant_to_proto(&signed).unwrap().encode_to_vec());
        let request_base64 = prepared["request_base64"].as_str().unwrap().to_owned();

        let commit_call = json!({
            "jsonrpc": "2.0",
            "id": 92,
            "method": "tools/call",
            "params": {
                "name": "commit_write",
                "arguments": {
                    "device_id": "device-e2e",
                    "workspace_id": "ws-e2e",
                    "request_base64": request_base64,
                    "approval_base64": approval_base64
                },
                "_meta": {
                    "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                    "io.modelcontextprotocol/clientInfo": {"name": "vor-e2e", "version": "1"},
                    "io.modelcontextprotocol/clientCapabilities": {}
                }
            }
        })
        .to_string();
        let commit_request = HttpRequest::builder()
            .method("POST")
            .uri("/mcp")
            .header(header::HOST, "127.0.0.1")
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::ACCEPT, "application/json, text/event-stream")
            .header("MCP-Protocol-Version", "2026-07-28")
            .header("Mcp-Method", "tools/call")
            .header("Mcp-Name", "commit_write")
            .header(AUTHORIZATION, auth_value(issued.token()))
            .body(Body::from(commit_call.clone()))
            .unwrap();
        let response = router.clone().oneshot(commit_request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = to_bytes(response.into_body(), 512 * 1024).await.unwrap();
        let rpc: Value = serde_json::from_slice(&bytes).unwrap();
        let commit_text = rpc["result"]["content"][0]["text"].as_str().unwrap();
        let committed: Value = serde_json::from_str(commit_text).unwrap();
        assert_eq!(committed["status"], "ok");
        assert_eq!(fs::read(&write_target).unwrap(), b"after-write");

        let replay_request = HttpRequest::builder()
            .method("POST")
            .uri("/mcp")
            .header(header::HOST, "127.0.0.1")
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::ACCEPT, "application/json, text/event-stream")
            .header("MCP-Protocol-Version", "2026-07-28")
            .header("Mcp-Method", "tools/call")
            .header("Mcp-Name", "commit_write")
            .header(AUTHORIZATION, auth_value(issued.token()))
            .body(Body::from(commit_call))
            .unwrap();
        let response = router.clone().oneshot(replay_request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = to_bytes(response.into_body(), 512 * 1024).await.unwrap();
        let rpc: Value = serde_json::from_slice(&bytes).unwrap();
        let replay_text = rpc["result"]["content"][0]["text"].as_str().unwrap();
        let replayed: Value = serde_json::from_str(replay_text).unwrap();
        assert_eq!(replayed["status"], "approval_replayed");
        assert_eq!(fs::read(&write_target).unwrap(), b"after-write");

        let terminal_marker = data.path().join("mcp-terminal-e2e.txt");
        let prepare_terminal_call = json!({
            "jsonrpc": "2.0",
            "id": 93,
            "method": "tools/call",
            "params": {
                "name": "prepare_terminal",
                "arguments": {
                    "device_id": "device-e2e",
                    "workspace_id": "ws-e2e",
                    "cwd": data.path().to_string_lossy(),
                    "argv": [
                        "cmd.exe", "/D", "/Q", "/C",
                        "echo VOR_GATEWAY_TERMINAL>mcp-terminal-e2e.txt"
                    ],
                    "timeout_ms": 5000,
                    "max_output_bytes": 65536,
                    "columns": 80,
                    "rows": 25
                },
                "_meta": {
                    "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                    "io.modelcontextprotocol/clientInfo": {"name": "vor-e2e", "version": "1"},
                    "io.modelcontextprotocol/clientCapabilities": {}
                }
            }
        })
        .to_string();
        let prepare_terminal_request = HttpRequest::builder()
            .method("POST")
            .uri("/mcp")
            .header(header::HOST, "127.0.0.1")
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::ACCEPT, "application/json, text/event-stream")
            .header("MCP-Protocol-Version", "2026-07-28")
            .header("Mcp-Method", "tools/call")
            .header("Mcp-Name", "prepare_terminal")
            .header(AUTHORIZATION, auth_value(issued.token()))
            .body(Body::from(prepare_terminal_call))
            .unwrap();
        let response = router
            .clone()
            .oneshot(prepare_terminal_request)
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = to_bytes(response.into_body(), 2 * 1024 * 1024)
            .await
            .unwrap();
        let rpc: Value = serde_json::from_slice(&bytes).unwrap();
        let prepare_terminal_text = rpc["result"]["content"][0]["text"].as_str().unwrap();
        let prepared_terminal: Value = serde_json::from_str(prepare_terminal_text).unwrap();
        assert_eq!(prepared_terminal["status"], "approval_required");
        assert!(!terminal_marker.exists());

        let terminal_challenge = &prepared_terminal["challenge"];
        assert_eq!(
            terminal_challenge["required_capability"].as_str(),
            Some("elevated")
        );
        let terminal_envelope_digest: [u8; 32] = STANDARD
            .decode(
                terminal_challenge["envelope_digest_base64"]
                    .as_str()
                    .unwrap(),
            )
            .unwrap()
            .try_into()
            .unwrap();
        let terminal_approval_nonce: [u8; 32] = STANDARD
            .decode(
                terminal_challenge["approval_nonce_base64"]
                    .as_str()
                    .unwrap(),
            )
            .unwrap()
            .try_into()
            .unwrap();
        let terminal_signed = sign_approval(
            ApprovalChallenge {
                request_id: terminal_challenge["request_id"]
                    .as_str()
                    .unwrap()
                    .to_owned(),
                envelope_digest: terminal_envelope_digest,
                policy_id: terminal_challenge["policy_id"].as_str().unwrap().to_owned(),
                required_capability: terminal_challenge["required_capability"]
                    .as_str()
                    .map(str::to_owned),
                expires_at_unix_ms: terminal_challenge["expires_at_unix_ms"].as_u64().unwrap(),
                approval_nonce: terminal_approval_nonce,
            },
            "operator-e2e",
            &signing,
        )
        .unwrap();
        let terminal_approval_base64 = STANDARD.encode(
            approval_grant_to_proto(&terminal_signed)
                .unwrap()
                .encode_to_vec(),
        );
        let terminal_request_base64 = prepared_terminal["request_base64"]
            .as_str()
            .unwrap()
            .to_owned();
        let commit_terminal_call = json!({
            "jsonrpc": "2.0",
            "id": 94,
            "method": "tools/call",
            "params": {
                "name": "commit_terminal",
                "arguments": {
                    "device_id": "device-e2e",
                    "workspace_id": "ws-e2e",
                    "request_base64": terminal_request_base64,
                    "approval_base64": terminal_approval_base64
                },
                "_meta": {
                    "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                    "io.modelcontextprotocol/clientInfo": {"name": "vor-e2e", "version": "1"},
                    "io.modelcontextprotocol/clientCapabilities": {}
                }
            }
        })
        .to_string();
        let commit_terminal_request = HttpRequest::builder()
            .method("POST")
            .uri("/mcp")
            .header(header::HOST, "127.0.0.1")
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::ACCEPT, "application/json, text/event-stream")
            .header("MCP-Protocol-Version", "2026-07-28")
            .header("Mcp-Method", "tools/call")
            .header("Mcp-Name", "commit_terminal")
            .header(AUTHORIZATION, auth_value(issued.token()))
            .body(Body::from(commit_terminal_call.clone()))
            .unwrap();
        let response = router
            .clone()
            .oneshot(commit_terminal_request)
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = to_bytes(response.into_body(), 2 * 1024 * 1024)
            .await
            .unwrap();
        let rpc: Value = serde_json::from_slice(&bytes).unwrap();
        let commit_terminal_text = rpc["result"]["content"][0]["text"].as_str().unwrap();
        let committed_terminal: Value = serde_json::from_str(commit_terminal_text).unwrap();
        assert_eq!(committed_terminal["status"], "ok", "{committed_terminal}");
        assert_eq!(committed_terminal["data"]["state"], "running");
        let terminal_session_id = committed_terminal["data"]["session_id"]
            .as_str()
            .unwrap()
            .to_owned();

        let replay_terminal_request = HttpRequest::builder()
            .method("POST")
            .uri("/mcp")
            .header(header::HOST, "127.0.0.1")
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::ACCEPT, "application/json, text/event-stream")
            .header("MCP-Protocol-Version", "2026-07-28")
            .header("Mcp-Method", "tools/call")
            .header("Mcp-Name", "commit_terminal")
            .header(AUTHORIZATION, auth_value(issued.token()))
            .body(Body::from(commit_terminal_call))
            .unwrap();
        let response = router
            .clone()
            .oneshot(replay_terminal_request)
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = to_bytes(response.into_body(), 512 * 1024).await.unwrap();
        let rpc: Value = serde_json::from_slice(&bytes).unwrap();
        let replay_terminal_text = rpc["result"]["content"][0]["text"].as_str().unwrap();
        let replayed_terminal: Value = serde_json::from_str(replay_terminal_text).unwrap();
        assert_eq!(replayed_terminal["status"], "approval_replayed");

        let terminal_deadline = tokio::time::Instant::now() + Duration::from_secs(3);
        loop {
            let poll_terminal_call = json!({
                "jsonrpc": "2.0",
                "id": 95,
                "method": "tools/call",
                "params": {
                    "name": "poll_terminal",
                    "arguments": {
                        "device_id": "device-e2e",
                        "workspace_id": "ws-e2e",
                        "session_id": terminal_session_id
                    },
                    "_meta": {
                        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                        "io.modelcontextprotocol/clientInfo": {"name": "vor-e2e", "version": "1"},
                        "io.modelcontextprotocol/clientCapabilities": {}
                    }
                }
            })
            .to_string();
            let poll_terminal_request = HttpRequest::builder()
                .method("POST")
                .uri("/mcp")
                .header(header::HOST, "127.0.0.1")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ACCEPT, "application/json, text/event-stream")
                .header("MCP-Protocol-Version", "2026-07-28")
                .header("Mcp-Method", "tools/call")
                .header("Mcp-Name", "poll_terminal")
                .header(AUTHORIZATION, auth_value(issued.token()))
                .body(Body::from(poll_terminal_call))
                .unwrap();
            let response = router.clone().oneshot(poll_terminal_request).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let bytes = to_bytes(response.into_body(), 512 * 1024).await.unwrap();
            let rpc: Value = serde_json::from_slice(&bytes).unwrap();
            let poll_terminal_text = rpc["result"]["content"][0]["text"].as_str().unwrap();
            let polled_terminal: Value = serde_json::from_str(poll_terminal_text).unwrap();
            assert_eq!(polled_terminal["status"], "ok");
            let state = polled_terminal["data"]["state"].as_str().unwrap();
            if state != "running" {
                assert_eq!(state, "completed");
                assert_eq!(polled_terminal["data"]["exit_code"], 0);
                break;
            }
            assert!(
                tokio::time::Instant::now() < terminal_deadline,
                "terminal session did not finish"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(
            fs::read_to_string(&terminal_marker)
                .unwrap()
                .contains("VOR_GATEWAY_TERMINAL")
        );

        let audit = fs::read_to_string(&audit_jsonl).unwrap();
        assert!(audit.contains("\"outcome\":\"approval_challenge_issued\""));
        assert!(audit.contains("\"outcome\":\"approval_verified\""));
        assert!(audit.contains("\"outcome\":\"approval_consumed\""));

        client_cancel.cancel();
        tokio::time::timeout(Duration::from_secs(2), client_task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        server_cancel.cancel();
        tokio::time::timeout(Duration::from_secs(2), server_task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn c11_mcp_two_tenant_rejections_do_not_disclose_object_existence() {
        let auth_dir = tempdir().unwrap();
        let grants = GrantStore::open(auth_dir.path().join("auth.json")).unwrap();
        let gateway_device_id = grants.device_id().unwrap();
        let tenants = TenantStore::open(auth_dir.path().join("tenants.json")).unwrap();
        tenants.upsert_user("actor-a", "Actor A").unwrap();
        tenants.upsert_user("actor-b", "Actor B").unwrap();
        tenants.upsert_organization("org-a", "Org A").unwrap();
        tenants.upsert_organization("org-b", "Org B").unwrap();
        for (org, workspace) in [("org-a", "ws-a1"), ("org-a", "ws-a2"), ("org-b", "ws-b1")] {
            tenants.upsert_workspace(org, workspace, workspace).unwrap();
        }
        tenants
            .set_membership("org-a", "actor-a", TenantRole::Operator)
            .unwrap();
        tenants
            .set_membership("org-b", "actor-b", TenantRole::Operator)
            .unwrap();
        tenants.pair_device("org-a", "device-a", ["ws-a1"]).unwrap();
        tenants.pair_device("org-b", "device-b", ["ws-b1"]).unwrap();
        tenants
            .pair_device("org-a", &gateway_device_id, ["ws-a1", "ws-a2"])
            .unwrap();
        tenants
            .pair_device("org-b", &gateway_device_id, ["ws-b1"])
            .unwrap();
        let token_a = grants
            .issue_for_tenant(
                "org-a",
                "actor-a",
                ["ws-a1", "ws-a2"],
                ["mcp"],
                60_000,
                now_unix_ms().unwrap(),
            )
            .unwrap()
            .token()
            .to_owned();
        let router = build_router_with_tenants_and_hub(
            grants,
            tenants,
            CancellationToken::new(),
            PrivateLinkHub::default(),
        )
        .unwrap();
        let disk = tempdir().unwrap();
        let marker = disk.path().join("must-not-change.txt");
        fs::write(&marker, b"before").unwrap();

        let cases = [
            ("read_file", json!({"path": marker})),
            ("git_status", json!({"path": disk.path()})),
            ("process_list", json!({})),
            ("poll_terminal", json!({"session_id": "terminal-session"})),
            ("cancel_terminal", json!({"session_id": "terminal-session"})),
            (
                "prepare_write",
                json!({
                    "path": marker,
                    "content_base64": STANDARD.encode(b"after"),
                    "expected_target_sha256": hex::encode(Sha256::digest(b"before"))
                }),
            ),
            (
                "prepare_terminal",
                json!({
                    "cwd": disk.path(),
                    "argv": ["cmd.exe", "/D", "/Q", "/C", "exit 0"]
                }),
            ),
        ];

        for (offset, (tool, base)) in cases.into_iter().enumerate() {
            let mut foreign = base.clone();
            foreign["device_id"] = json!("device-b");
            foreign["workspace_id"] = json!("ws-b1");
            let mut missing = base.clone();
            missing["device_id"] = json!("device-does-not-exist");
            missing["workspace_id"] = json!("ws-does-not-exist");
            let id = 4_100 + offset as u64;
            let foreign_response = mcp_tool_call(router.clone(), &token_a, id, tool, foreign).await;
            let missing_response = mcp_tool_call(router.clone(), &token_a, id, tool, missing).await;
            assert!(
                foreign_response
                    .1
                    .to_string()
                    .contains("tenant authority denied"),
                "{tool} was not rejected by tenant authority: {:?}",
                foreign_response
            );
            assert_eq!(
                foreign_response, missing_response,
                "{tool} disclosed existence"
            );

            let mut other_workspace = base.clone();
            other_workspace["device_id"] = json!("device-a");
            other_workspace["workspace_id"] = json!("ws-a2");
            let mut absent_workspace = base;
            absent_workspace["device_id"] = json!("device-a");
            absent_workspace["workspace_id"] = json!("ws-does-not-exist");
            let other_response =
                mcp_tool_call(router.clone(), &token_a, id, tool, other_workspace).await;
            let absent_response =
                mcp_tool_call(router.clone(), &token_a, id, tool, absent_workspace).await;
            assert!(
                other_response
                    .1
                    .to_string()
                    .contains("tenant authority denied"),
                "{tool} workspace was not rejected by tenant authority: {:?}",
                other_response
            );
            assert_eq!(
                other_response, absent_response,
                "{tool} disclosed workspace existence"
            );
        }
        assert_eq!(fs::read(marker).unwrap(), b"before");
    }

    #[tokio::test]
    async fn mcp_status_filters_connected_devices_by_tenant_authority() {
        let certs = gateway_e2e_certs_for_devices(&["device-a", "device-b"]);
        let data = tempdir().unwrap();
        let policy_a = data.path().join("policy-a.yaml");
        let policy_b = data.path().join("policy-b.yaml");
        e2e_policy(&policy_a, data.path());
        e2e_policy(&policy_b, data.path());
        let dispatcher_a = Arc::new(Mutex::new(
            ReadOnlyDispatcher::open(DispatchConfig {
                device_id: "device-a".into(),
                policy_path: policy_a,
                audit_sqlite: data.path().join("audit-a.db"),
                audit_jsonl: data.path().join("audit-a.jsonl"),
                journal_dir: data.path().join("journal-a"),
                allowed_roots: vec![data.path().to_path_buf()],
                git_executable: find_git(),
                max_output_bytes: DEFAULT_MAX_OUTPUT_BYTES,
                browser: None,
            })
            .unwrap(),
        ));
        let dispatcher_b = Arc::new(Mutex::new(
            ReadOnlyDispatcher::open(DispatchConfig {
                device_id: "device-b".into(),
                policy_path: policy_b,
                audit_sqlite: data.path().join("audit-b.db"),
                audit_jsonl: data.path().join("audit-b.jsonl"),
                journal_dir: data.path().join("journal-b"),
                allowed_roots: vec![data.path().to_path_buf()],
                git_executable: find_git(),
                max_output_bytes: DEFAULT_MAX_OUTPUT_BYTES,
                browser: None,
            })
            .unwrap(),
        ));

        let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let private_addr = probe.local_addr().unwrap();
        drop(probe);
        let hub = PrivateLinkHub::default();
        let registry = DeviceCertificateRegistry::from_certificates(
            certs
                .devices
                .iter()
                .map(|(device_id, device)| (device_id.clone(), device.cert_der.clone())),
        )
        .unwrap();
        let server_cancel = CancellationToken::new();
        let server_shutdown = server_cancel.clone();
        let server_hub = hub.clone();
        let server_tls = PrivateLinkTls {
            ca_pem: certs.ca_pem.as_bytes().to_vec(),
            server_cert_pem: certs.server_cert_pem.as_bytes().to_vec(),
            server_key_pem: certs.server_key_pem.as_bytes().to_vec(),
        };
        let server_task = tokio::spawn(async move {
            serve_with_hub(
                PrivateLinkConfig {
                    bind: private_addr,
                    replay_capacity: 64,
                },
                server_tls,
                registry,
                server_hub,
                server_shutdown,
            )
            .await
        });
        tokio::time::sleep(Duration::from_millis(50)).await;

        let mut client_tasks = Vec::new();
        let mut client_cancels = Vec::new();
        for (device_id, dispatcher) in [
            ("device-a", dispatcher_a.clone()),
            ("device-b", dispatcher_b.clone()),
        ] {
            let device = certs.devices.get(device_id).unwrap();
            let client_cancel = CancellationToken::new();
            let client_shutdown = client_cancel.clone();
            client_cancels.push(client_cancel);
            let client_config = PrivateDeviceClientConfig {
                endpoint: format!("https://{private_addr}"),
                server_name: "localhost".into(),
                device_id: device_id.to_owned(),
                ca_pem: certs.ca_pem.as_bytes().to_vec(),
                device_cert_pem: device.cert_pem.as_bytes().to_vec(),
                device_key_pem: device.key_pem.as_bytes().to_vec(),
                agent_version: "0.1.0-e2e".into(),
                heartbeat_interval: Duration::from_secs(30),
                replay_capacity: 64,
            };
            client_tasks.push(tokio::spawn(async move {
                run_device_dispatch(client_config, dispatcher, client_shutdown).await
            }));
        }
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                if hub.connected_devices().await
                    == vec!["device-a".to_owned(), "device-b".to_owned()]
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();

        let auth_dir = tempdir().unwrap();
        let grants = GrantStore::open(auth_dir.path().join("auth.json")).unwrap();
        let gateway_device_id = grants.device_id().unwrap();
        let tenants = TenantStore::open(auth_dir.path().join("tenants.json")).unwrap();
        tenants.upsert_user("shared-actor", "Shared Actor").unwrap();
        tenants.upsert_user("empty-actor", "Empty Actor").unwrap();
        tenants.upsert_organization("org-a", "Org A").unwrap();
        tenants.upsert_organization("org-b", "Org B").unwrap();
        for (org, workspace_id) in [
            ("org-a", "ws-a1"),
            ("org-a", "ws-a2"),
            ("org-a", "ws-a-empty"),
            ("org-b", "ws-b1"),
        ] {
            tenants
                .upsert_workspace(org, workspace_id, workspace_id)
                .unwrap();
        }
        tenants
            .set_membership("org-a", "shared-actor", TenantRole::Operator)
            .unwrap();
        tenants
            .set_membership("org-b", "shared-actor", TenantRole::Viewer)
            .unwrap();
        tenants
            .set_membership("org-a", "empty-actor", TenantRole::Viewer)
            .unwrap();
        tenants
            .pair_device("org-a", "device-a", ["ws-a1", "ws-a2"])
            .unwrap();
        tenants.pair_device("org-b", "device-b", ["ws-b1"]).unwrap();
        tenants
            .pair_device(
                "org-a",
                &gateway_device_id,
                ["ws-a1", "ws-a2", "ws-a-empty"],
            )
            .unwrap();
        tenants
            .pair_device("org-b", &gateway_device_id, ["ws-b1"])
            .unwrap();
        let token_a = grants
            .issue_for_tenant(
                "org-a",
                "shared-actor",
                ["ws-a1", "ws-a2"],
                ["mcp"],
                60_000,
                now_unix_ms().unwrap(),
            )
            .unwrap()
            .token()
            .to_owned();
        let token_b = grants
            .issue_for_tenant(
                "org-b",
                "shared-actor",
                ["ws-b1"],
                ["mcp"],
                60_000,
                now_unix_ms().unwrap(),
            )
            .unwrap()
            .token()
            .to_owned();
        let token_empty = grants
            .issue_for_tenant(
                "org-a",
                "empty-actor",
                ["ws-a-empty"],
                ["mcp"],
                60_000,
                now_unix_ms().unwrap(),
            )
            .unwrap()
            .token()
            .to_owned();
        let router = build_router_with_tenants_and_hub(
            grants,
            tenants.clone(),
            CancellationToken::new(),
            hub,
        )
        .unwrap();

        let (_, rpc_a) = mcp_tool_call(
            router.clone(),
            &token_a,
            2_600,
            "commander_status",
            json!({}),
        )
        .await;
        let status_a = tool_text_json(&rpc_a);
        assert_eq!(status_a["remote_connected_devices"], json!(["device-a"]));
        assert_eq!(status_a["remote_connected_device_count"], 1);
        assert_eq!(status_a["recommended_device_id"], "device-a");
        assert!(!status_a.to_string().contains("device-b"));

        let (_, rpc_b) = mcp_tool_call(
            router.clone(),
            &token_b,
            2_601,
            "commander_status",
            json!({}),
        )
        .await;
        let status_b = tool_text_json(&rpc_b);
        assert_eq!(status_b["remote_connected_devices"], json!(["device-b"]));
        assert_eq!(status_b["remote_connected_device_count"], 1);
        assert_eq!(status_b["recommended_device_id"], "device-b");
        assert!(!status_b.to_string().contains("device-a"));

        let (_, rpc_empty) = mcp_tool_call(
            router.clone(),
            &token_empty,
            2_602,
            "commander_status",
            json!({}),
        )
        .await;
        let status_empty = tool_text_json(&rpc_empty);
        assert_eq!(status_empty["remote_connected_devices"], json!([]));
        assert_eq!(status_empty["remote_connected_device_count"], 0);
        assert!(status_empty["recommended_device_id"].is_null());
        assert_eq!(status_empty["remote_connectivity"], "offline");
        assert!(!status_empty.to_string().contains("device-a"));
        assert!(!status_empty.to_string().contains("device-b"));

        tenants.revoke_device("org-a", "device-a").unwrap();
        let (_, rpc_revoked) = mcp_tool_call(
            router.clone(),
            &token_a,
            2_603,
            "commander_status",
            json!({}),
        )
        .await;
        let status_revoked = tool_text_json(&rpc_revoked);
        assert_eq!(status_revoked["remote_connected_devices"], json!([]));
        assert_eq!(status_revoked["remote_connected_device_count"], 0);
        assert!(status_revoked["recommended_device_id"].is_null());
        assert_eq!(status_revoked["remote_connectivity"], "offline");
        assert!(!status_revoked.to_string().contains("device-a"));
        assert!(!status_revoked.to_string().contains("device-b"));

        for cancel in client_cancels {
            cancel.cancel();
        }
        server_cancel.cancel();
        for task in client_tasks {
            match task.await.unwrap() {
                Ok(()) => {}
                Err(error) => assert_eq!(error.to_string(), "cancelled"),
            }
        }
        match server_task.await.unwrap() {
            Ok(()) => {}
            Err(error) => assert_eq!(error.to_string(), "cancelled"),
        }
    }

    #[tokio::test]
    async fn mcp_prepare_commit_revalidates_authority_and_signer_without_restart() {
        let certs = gateway_e2e_certs();
        let data = tempdir().unwrap();
        let policy = data.path().join("policy.yaml");
        e2e_policy(&policy, data.path());
        let signing = SigningKey::from_bytes(&[51; 32]);
        let rotated_signing = SigningKey::from_bytes(&[52; 32]);
        let mut dispatcher_value = ReadOnlyDispatcher::open(DispatchConfig {
            device_id: "device-e2e".into(),
            policy_path: policy,
            audit_sqlite: data.path().join("audit.db"),
            audit_jsonl: data.path().join("audit.jsonl"),
            journal_dir: data.path().join("journal"),
            allowed_roots: vec![data.path().to_path_buf()],
            git_executable: find_git(),
            max_output_bytes: DEFAULT_MAX_OUTPUT_BYTES,
            browser: None,
        })
        .unwrap();
        dispatcher_value.require_tenant_scoped_approvers();
        dispatcher_value
            .add_trusted_approver_for_organization(
                "operator-e2e",
                signing.verifying_key().to_bytes(),
                vor_dispatch::ApproverAuthority::Owner,
                "org-e2e",
            )
            .unwrap();
        let dispatcher = Arc::new(Mutex::new(dispatcher_value));

        let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let private_addr = probe.local_addr().unwrap();
        drop(probe);
        let hub = PrivateLinkHub::default();
        let registry = DeviceCertificateRegistry::from_certificates([(
            "device-e2e".to_owned(),
            certs.device_cert_der.clone(),
        )])
        .unwrap();
        let server_cancel = CancellationToken::new();
        let server_shutdown = server_cancel.clone();
        let server_hub = hub.clone();
        let server_tls = PrivateLinkTls {
            ca_pem: certs.ca_pem.as_bytes().to_vec(),
            server_cert_pem: certs.server_cert_pem.as_bytes().to_vec(),
            server_key_pem: certs.server_key_pem.as_bytes().to_vec(),
        };
        let server_task = tokio::spawn(async move {
            serve_with_hub(
                PrivateLinkConfig {
                    bind: private_addr,
                    replay_capacity: 64,
                },
                server_tls,
                registry,
                server_hub,
                server_shutdown,
            )
            .await
        });
        tokio::time::sleep(Duration::from_millis(50)).await;

        let client_cancel = CancellationToken::new();
        let client_shutdown = client_cancel.clone();
        let client_dispatcher = dispatcher.clone();
        let client_config = PrivateDeviceClientConfig {
            endpoint: format!("https://{private_addr}"),
            server_name: "localhost".into(),
            device_id: "device-e2e".into(),
            ca_pem: certs.ca_pem.as_bytes().to_vec(),
            device_cert_pem: certs.device_cert_pem.as_bytes().to_vec(),
            device_key_pem: certs.device_key_pem.as_bytes().to_vec(),
            agent_version: "0.1.0-e2e".into(),
            heartbeat_interval: Duration::from_secs(30),
            replay_capacity: 64,
        };
        let client_task = tokio::spawn(async move {
            run_device_dispatch(client_config, client_dispatcher, client_shutdown).await
        });
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                if hub.connected_devices().await == vec!["device-e2e".to_owned()] {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();

        let auth_dir = tempdir().unwrap();
        let grants = GrantStore::open(auth_dir.path().join("auth.json")).unwrap();
        let gateway_device_id = grants.device_id().unwrap();
        let tenants = TenantStore::open(auth_dir.path().join("tenants.json")).unwrap();
        tenants.upsert_user("operator", "Operator").unwrap();
        tenants.upsert_organization("org-e2e", "Org E2E").unwrap();
        tenants
            .upsert_workspace("org-e2e", "ws-e2e", "Workspace E2E")
            .unwrap();
        tenants
            .upsert_workspace("org-e2e", "ws-e2e-alt", "Workspace E2E Alt")
            .unwrap();
        tenants
            .set_membership("org-e2e", "operator", TenantRole::Operator)
            .unwrap();
        tenants
            .pair_device("org-e2e", "device-e2e", ["ws-e2e", "ws-e2e-alt"])
            .unwrap();
        tenants
            .pair_device("org-e2e", &gateway_device_id, ["ws-e2e", "ws-e2e-alt"])
            .unwrap();
        let issued = grants
            .issue_for_tenant(
                "org-e2e",
                "operator",
                ["ws-e2e", "ws-e2e-alt"],
                ["mcp"],
                60_000,
                now_unix_ms().unwrap(),
            )
            .unwrap();
        let token = issued.token().to_owned();
        let grant_id = issued.record.grant_id.clone();
        let router = build_router_with_tenants_and_hub(
            grants.clone(),
            tenants.clone(),
            CancellationToken::new(),
            hub,
        )
        .unwrap();

        async fn prepare_write_case(
            router: Router,
            token: &str,
            id: u64,
            target: &Path,
            before: &[u8],
            after: &[u8],
        ) -> Value {
            prepare_write_case_for_workspace(router, token, id, "ws-e2e", target, before, after)
                .await
        }

        async fn prepare_write_case_for_workspace(
            router: Router,
            token: &str,
            id: u64,
            workspace_id: &str,
            target: &Path,
            before: &[u8],
            after: &[u8],
        ) -> Value {
            fs::write(target, before).unwrap();
            let expected_target_sha256 = hex::encode(Sha256::digest(before));
            let (status, rpc) = mcp_tool_call(
                router,
                token,
                id,
                "prepare_write",
                json!({
                    "device_id": "device-e2e",
                    "workspace_id": workspace_id,
                    "path": target.to_string_lossy(),
                    "content_base64": STANDARD.encode(after),
                    "expected_target_sha256": expected_target_sha256
                }),
            )
            .await;
            assert_eq!(status, StatusCode::OK, "{rpc}");
            let prepared = tool_text_json(&rpc);
            assert_eq!(prepared["status"], "approval_required");
            assert_eq!(fs::read(target).unwrap(), before);
            prepared
        }

        async fn commit_write_case(
            router: Router,
            token: &str,
            id: u64,
            prepared: &Value,
            approval_base64: String,
        ) -> Value {
            commit_write_case_for_workspace(router, token, id, "ws-e2e", prepared, approval_base64)
                .await
        }

        async fn commit_write_case_for_workspace(
            router: Router,
            token: &str,
            id: u64,
            workspace_id: &str,
            prepared: &Value,
            approval_base64: String,
        ) -> Value {
            let (status, rpc) = mcp_tool_call(
                router,
                token,
                id,
                "commit_write",
                json!({
                    "device_id": "device-e2e",
                    "workspace_id": workspace_id,
                    "request_base64": prepared["request_base64"].as_str().unwrap(),
                    "approval_base64": approval_base64
                }),
            )
            .await;
            assert_eq!(status, StatusCode::OK, "{rpc}");
            tool_text_json(&rpc)
        }

        async fn commit_write_rejected_for_workspace(
            router: Router,
            token: &str,
            id: u64,
            workspace_id: &str,
            prepared: &Value,
            approval_base64: String,
            expected_reason: &str,
        ) -> (StatusCode, Value) {
            let (status, rpc) = mcp_tool_call(
                router,
                token,
                id,
                "commit_write",
                json!({
                    "device_id": "device-e2e",
                    "workspace_id": workspace_id,
                    "request_base64": prepared["request_base64"].as_str().unwrap(),
                    "approval_base64": approval_base64
                }),
            )
            .await;
            assert_ne!(status, StatusCode::INTERNAL_SERVER_ERROR, "{rpc}");
            assert!(
                rpc.to_string().contains(expected_reason),
                "expected rejection reason {expected_reason:?}, got status {status} body {rpc}"
            );
            (status, rpc)
        }

        let positive_target = data.path().join("positive.txt");
        let prepared = prepare_write_case(
            router.clone(),
            &token,
            300,
            &positive_target,
            b"before-positive",
            b"after-positive",
        )
        .await;
        let approval = sign_prepared(&prepared, "operator-e2e", &signing);
        let committed = commit_write_case(router.clone(), &token, 301, &prepared, approval).await;
        assert_eq!(committed["status"], "ok", "{committed}");
        assert_eq!(fs::read(&positive_target).unwrap(), b"after-positive");

        // Real HTTP/MCP router -> private mTLS transport -> device dispatcher. The edit
        // preparation returns an ordinary filesystem.write request, so commit_write is
        // deliberately reused and its target digest detects this intervening mutation.
        let edit_target = data.path().join("edit-race.txt");
        fs::write(&edit_target, b"alpha\r\nbeta\r\n").unwrap();
        let (status, rpc) = mcp_tool_call(
            router.clone(),
            &token,
            350,
            "prepare_edit",
            json!({
                "device_id": "device-e2e",
                "workspace_id": "ws-e2e",
                "path": edit_target.to_string_lossy(),
                "edits": [{"old_text": "beta\n", "new_text": "gamma\n"}]
            }),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{rpc}");
        let edit_prepared = tool_text_json(&rpc);
        assert_eq!(edit_prepared["status"], "approval_required");
        assert!(
            edit_prepared["diff_summary"]
                .as_str()
                .unwrap()
                .contains("+gamma")
        );
        assert_eq!(fs::read(&edit_target).unwrap(), b"alpha\r\nbeta\r\n");
        let edit_approval = sign_prepared(&edit_prepared, "operator-e2e", &signing);
        fs::write(&edit_target, b"alpha\r\nchanged elsewhere\r\n").unwrap();
        let rejected =
            commit_write_case(router.clone(), &token, 351, &edit_prepared, edit_approval).await;
        assert_eq!(
            rejected["status"], "target_precondition_failed",
            "{rejected}"
        );
        assert_eq!(
            fs::read(&edit_target).unwrap(),
            b"alpha\r\nchanged elsewhere\r\n"
        );
        let (status, rpc) = mcp_tool_call(
            router.clone(),
            &token,
            352,
            "prepare_edit",
            json!({
                "device_id": "device-e2e",
                "workspace_id": "ws-e2e",
                "path": edit_target.to_string_lossy(),
                "edits": [{"old_text": "missing line", "new_text": "replacement"}]
            }),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{rpc}");
        let mismatch = tool_text_json(&rpc);
        assert_eq!(mismatch["status"], "filesystem_error");
        assert_eq!(mismatch["data"]["actual_occurrences"], 0);
        assert!(mismatch["data"]["closest_line"].as_str().is_some());
        assert_eq!(
            fs::read(&edit_target).unwrap(),
            b"alpha\r\nchanged elsewhere\r\n"
        );

        let revoked_grant_target = data.path().join("revoked-grant.txt");
        let prepared = prepare_write_case(
            router.clone(),
            &token,
            302,
            &revoked_grant_target,
            b"before-revoked-grant",
            b"after-revoked-grant",
        )
        .await;
        let approval = sign_prepared(&prepared, "operator-e2e", &signing);
        assert!(grants.revoke_for_tenant(&grant_id, "org-e2e").unwrap());
        assert!(
            grants
                .validate(&token, "mcp", now_unix_ms().unwrap())
                .is_err()
        );
        let (status, rpc) = mcp_tool_call(
            router.clone(),
            &token,
            303,
            "commit_write",
            json!({
                "device_id": "device-e2e",
                "workspace_id": "ws-e2e",
                "request_base64": prepared["request_base64"].as_str().unwrap(),
                "approval_base64": approval
            }),
        )
        .await;
        assert_ne!(status, StatusCode::OK, "{rpc}");
        assert_eq!(
            fs::read(&revoked_grant_target).unwrap(),
            b"before-revoked-grant"
        );

        let issued = grants
            .issue_for_tenant(
                "org-e2e",
                "operator",
                ["ws-e2e", "ws-e2e-alt"],
                ["mcp"],
                60_000,
                now_unix_ms().unwrap(),
            )
            .unwrap();
        let token = issued.token().to_owned();

        let expired_grant_target = data.path().join("expired-grant.txt");
        let expired_prepared = prepare_write_case(
            router.clone(),
            &token,
            313,
            &expired_grant_target,
            b"before-expired-grant",
            b"after-expired-grant",
        )
        .await;
        let expired_approval = sign_prepared(&expired_prepared, "operator-e2e", &signing);
        assert!(
            grants
                .expire_for_tenant(
                    &issued.record.grant_id,
                    "org-e2e",
                    issued.record.issued_at_unix_ms
                )
                .unwrap()
        );
        assert!(
            grants
                .validate(&token, "mcp", now_unix_ms().unwrap())
                .is_err()
        );
        let (status, _) = commit_write_rejected_for_workspace(
            router.clone(),
            &token,
            314,
            "ws-e2e",
            &expired_prepared,
            expired_approval,
            "unauthorized",
        )
        .await;
        assert_ne!(status, StatusCode::OK);
        assert_eq!(
            fs::read(&expired_grant_target).unwrap(),
            b"before-expired-grant"
        );

        let issued = grants
            .issue_for_tenant(
                "org-e2e",
                "operator",
                ["ws-e2e", "ws-e2e-alt"],
                ["mcp"],
                60_000,
                now_unix_ms().unwrap(),
            )
            .unwrap();
        let token = issued.token().to_owned();

        let downgraded_target = data.path().join("downgraded-membership.txt");
        let prepared = prepare_write_case(
            router.clone(),
            &token,
            304,
            &downgraded_target,
            b"before-downgrade",
            b"after-downgrade",
        )
        .await;
        let approval = sign_prepared(&prepared, "operator-e2e", &signing);
        tenants
            .set_membership("org-e2e", "operator", TenantRole::Viewer)
            .unwrap();
        assert!(
            tenants
                .verify_context(
                    &issued.record,
                    "org-e2e",
                    "device-e2e",
                    Some("ws-e2e"),
                    TenantRole::Operator,
                )
                .is_err()
        );
        let (status, rpc) = mcp_tool_call(
            router.clone(),
            &token,
            305,
            "commit_write",
            json!({
                "device_id": "device-e2e",
                "workspace_id": "ws-e2e",
                "request_base64": prepared["request_base64"].as_str().unwrap(),
                "approval_base64": approval
            }),
        )
        .await;
        assert_ne!(status, StatusCode::OK, "{rpc}");
        assert_eq!(fs::read(&downgraded_target).unwrap(), b"before-downgrade");
        tenants
            .set_membership("org-e2e", "operator", TenantRole::Operator)
            .unwrap();

        let revoked_membership_target = data.path().join("revoked-membership.txt");
        let prepared = prepare_write_case(
            router.clone(),
            &token,
            315,
            &revoked_membership_target,
            b"before-revoked-membership",
            b"after-revoked-membership",
        )
        .await;
        let approval = sign_prepared(&prepared, "operator-e2e", &signing);
        tenants.revoke_membership("org-e2e", "operator").unwrap();
        assert!(
            tenants
                .verify_context(
                    &issued.record,
                    "org-e2e",
                    "device-e2e",
                    Some("ws-e2e"),
                    TenantRole::Operator,
                )
                .is_err()
        );
        let (_, rpc) = commit_write_rejected_for_workspace(
            router.clone(),
            &token,
            316,
            "ws-e2e",
            &prepared,
            approval,
            "unauthorized",
        )
        .await;
        assert!(rpc.to_string().contains("unauthorized"), "{rpc}");
        assert_eq!(
            fs::read(&revoked_membership_target).unwrap(),
            b"before-revoked-membership"
        );
        tenants
            .set_membership("org-e2e", "operator", TenantRole::Operator)
            .unwrap();

        let revoked_device_target = data.path().join("revoked-device.txt");
        let prepared = prepare_write_case(
            router.clone(),
            &token,
            306,
            &revoked_device_target,
            b"before-device",
            b"after-device",
        )
        .await;
        let approval = sign_prepared(&prepared, "operator-e2e", &signing);
        tenants.revoke_device("org-e2e", "device-e2e").unwrap();
        assert!(
            tenants
                .verify_context(
                    &issued.record,
                    "org-e2e",
                    "device-e2e",
                    Some("ws-e2e"),
                    TenantRole::Operator,
                )
                .is_err()
        );
        let (status, rpc) = mcp_tool_call(
            router.clone(),
            &token,
            307,
            "commit_write",
            json!({
                "device_id": "device-e2e",
                "workspace_id": "ws-e2e",
                "request_base64": prepared["request_base64"].as_str().unwrap(),
                "approval_base64": approval
            }),
        )
        .await;
        assert_ne!(status, StatusCode::OK, "{rpc}");
        assert_eq!(fs::read(&revoked_device_target).unwrap(), b"before-device");
        tenants
            .pair_device("org-e2e", "device-e2e", ["ws-e2e", "ws-e2e-alt"])
            .unwrap();

        let device_workspace_target = data.path().join("device-workspace-removed.txt");
        let prepared = prepare_write_case(
            router.clone(),
            &token,
            317,
            &device_workspace_target,
            b"before-device-workspace",
            b"after-device-workspace",
        )
        .await;
        let approval = sign_prepared(&prepared, "operator-e2e", &signing);
        assert!(
            tenants
                .remove_device_workspace("org-e2e", "device-e2e", "ws-e2e")
                .unwrap()
        );
        assert!(
            tenants
                .verify_context(
                    &issued.record,
                    "org-e2e",
                    "device-e2e",
                    Some("ws-e2e"),
                    TenantRole::Operator,
                )
                .is_err()
        );
        tenants
            .verify_context(
                &issued.record,
                "org-e2e",
                "device-e2e",
                Some("ws-e2e-alt"),
                TenantRole::Operator,
            )
            .unwrap();
        let (_, rpc) = commit_write_rejected_for_workspace(
            router.clone(),
            &token,
            318,
            "ws-e2e",
            &prepared,
            approval,
            "tenant authority denied",
        )
        .await;
        assert!(rpc.to_string().contains("tenant authority denied"), "{rpc}");
        assert_eq!(
            fs::read(&device_workspace_target).unwrap(),
            b"before-device-workspace"
        );
        tenants
            .pair_device("org-e2e", "device-e2e", ["ws-e2e", "ws-e2e-alt"])
            .unwrap();

        let issued_for_workspace_removal = grants
            .issue_for_tenant(
                "org-e2e",
                "operator",
                ["ws-e2e", "ws-e2e-alt"],
                ["mcp"],
                60_000,
                now_unix_ms().unwrap(),
            )
            .unwrap();
        let workspace_token = issued_for_workspace_removal.token().to_owned();
        let grant_workspace_target = data.path().join("grant-workspace-removed.txt");
        let prepared = prepare_write_case(
            router.clone(),
            &workspace_token,
            319,
            &grant_workspace_target,
            b"before-grant-workspace",
            b"after-grant-workspace",
        )
        .await;
        let approval = sign_prepared(&prepared, "operator-e2e", &signing);
        assert!(
            grants
                .remove_workspace_for_tenant(
                    &issued_for_workspace_removal.record.grant_id,
                    "org-e2e",
                    "ws-e2e",
                )
                .unwrap()
        );
        assert!(
            grants
                .validate_for_tenant(
                    &workspace_token,
                    "mcp",
                    "org-e2e",
                    Some("ws-e2e"),
                    now_unix_ms().unwrap()
                )
                .is_err()
        );
        grants
            .validate_for_tenant(
                &workspace_token,
                "mcp",
                "org-e2e",
                Some("ws-e2e-alt"),
                now_unix_ms().unwrap(),
            )
            .unwrap();
        let (_, rpc) = commit_write_rejected_for_workspace(
            router.clone(),
            &workspace_token,
            320,
            "ws-e2e",
            &prepared,
            approval,
            "tenant authority denied",
        )
        .await;
        assert!(rpc.to_string().contains("tenant authority denied"), "{rpc}");
        assert_eq!(
            fs::read(&grant_workspace_target).unwrap(),
            b"before-grant-workspace"
        );

        let revoked_signer_target = data.path().join("revoked-signer.txt");
        let prepared = prepare_write_case(
            router.clone(),
            &token,
            308,
            &revoked_signer_target,
            b"before-signer",
            b"after-signer",
        )
        .await;
        let approval = sign_prepared(&prepared, "operator-e2e", &signing);
        dispatcher
            .lock()
            .unwrap()
            .revoke_trusted_approver("operator-e2e")
            .unwrap();
        let rejected = commit_write_case(router.clone(), &token, 309, &prepared, approval).await;
        assert_eq!(rejected["status"], "approval_invalid", "{rejected}");
        assert_eq!(fs::read(&revoked_signer_target).unwrap(), b"before-signer");

        dispatcher
            .lock()
            .unwrap()
            .rotate_trusted_approver_for_organization(
                "operator-e2e",
                signing.verifying_key().to_bytes(),
                vor_dispatch::ApproverAuthority::Owner,
                "org-e2e",
            )
            .unwrap();
        let rotated_target = data.path().join("rotated-signer.txt");
        let prepared = prepare_write_case(
            router.clone(),
            &token,
            310,
            &rotated_target,
            b"before-rotated",
            b"after-rotated",
        )
        .await;
        let old_approval = sign_prepared(&prepared, "operator-e2e", &signing);
        dispatcher
            .lock()
            .unwrap()
            .rotate_trusted_approver_for_organization(
                "operator-e2e",
                rotated_signing.verifying_key().to_bytes(),
                vor_dispatch::ApproverAuthority::Owner,
                "org-e2e",
            )
            .unwrap();
        let rejected =
            commit_write_case(router.clone(), &token, 311, &prepared, old_approval).await;
        assert_eq!(rejected["status"], "approval_invalid", "{rejected}");
        assert_eq!(fs::read(&rotated_target).unwrap(), b"before-rotated");
        let new_approval = sign_prepared(&prepared, "operator-e2e", &rotated_signing);
        let committed = commit_write_case(router, &token, 312, &prepared, new_approval).await;
        assert_eq!(committed["status"], "ok", "{committed}");
        assert_eq!(fs::read(&rotated_target).unwrap(), b"after-rotated");

        client_cancel.cancel();
        tokio::time::timeout(Duration::from_secs(2), client_task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        server_cancel.cancel();
        tokio::time::timeout(Duration::from_secs(2), server_task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }
}
