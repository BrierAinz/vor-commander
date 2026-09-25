// SPDX-License-Identifier: MPL-2.0

use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::net::TcpListener;
use std::path::{Component, Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};
use thiserror::Error;
use tungstenite::{Message, connect};
use vor_core::ExecutionAuthorization;

const DRIVER_POLL_INTERVAL: Duration = Duration::from_millis(50);
const DEFAULT_STARTUP_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Debug, Clone)]
pub struct BrowserConfig {
    pub geckodriver_path: PathBuf,
    pub firefox_binary: PathBuf,
    pub profile_path: PathBuf,
    pub driver_profile_root: PathBuf,
    pub download_dir: PathBuf,
    pub headless: bool,
    pub startup_timeout: Duration,
}

impl BrowserConfig {
    pub fn new(
        geckodriver_path: impl Into<PathBuf>,
        firefox_binary: impl Into<PathBuf>,
        state_root: impl AsRef<Path>,
    ) -> Self {
        let state_root = state_root.as_ref();
        Self {
            geckodriver_path: geckodriver_path.into(),
            firefox_binary: firefox_binary.into(),
            profile_path: state_root.join("profiles").join("Vor-Automation"),
            driver_profile_root: state_root.join("driver-profiles"),
            download_dir: state_root.join("downloads"),
            headless: false,
            startup_timeout: DEFAULT_STARTUP_TIMEOUT,
        }
    }

    pub fn headless(mut self, enabled: bool) -> Self {
        self.headless = enabled;
        self
    }

    fn prepare(&self) -> Result<(), BrowserError> {
        if !self.geckodriver_path.is_file() {
            return Err(BrowserError::MissingExecutable("geckodriver"));
        }
        if !self.firefox_binary.is_file() {
            return Err(BrowserError::MissingExecutable("firefox"));
        }
        fs::create_dir_all(&self.profile_path)?;
        fs::create_dir_all(&self.driver_profile_root)?;
        fs::create_dir_all(&self.download_dir)?;
        Ok(())
    }
}

struct GeckoDriverProcess {
    child: Child,
    endpoint: String,
}

impl GeckoDriverProcess {
    fn start(config: &BrowserConfig) -> Result<Self, BrowserError> {
        config.prepare()?;
        let probe = TcpListener::bind(("127.0.0.1", 0))?;
        let port = probe.local_addr()?.port();
        drop(probe);

        let child = Command::new(&config.geckodriver_path)
            .arg("--host")
            .arg("127.0.0.1")
            .arg("--port")
            .arg(port.to_string())
            .arg("--profile-root")
            .arg(&config.driver_profile_root)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;
        let endpoint = format!("http://127.0.0.1:{port}");
        let mut driver = Self { child, endpoint };
        driver.wait_until_ready(config.startup_timeout)?;
        Ok(driver)
    }

    fn wait_until_ready(&mut self, timeout: Duration) -> Result<(), BrowserError> {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if let Some(status) = self.child.try_wait()? {
                return Err(BrowserError::DriverExited(status.code()));
            }
            if driver_ready(&self.endpoint) {
                return Ok(());
            }
            thread::sleep(DRIVER_POLL_INTERVAL);
        }
        Err(BrowserError::DriverStartupTimeout)
    }
}

impl Drop for GeckoDriverProcess {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

fn driver_ready(endpoint: &str) -> bool {
    let url = format!("{endpoint}/status");
    let Ok(mut response) = ureq::get(&url).call() else {
        return false;
    };
    response
        .body_mut()
        .read_json::<Value>()
        .ok()
        .and_then(|body| {
            body.get("value")
                .and_then(|value| value.get("ready"))
                .and_then(Value::as_bool)
        })
        == Some(true)
}

const WEB_ELEMENT_KEY: &str = "element-6066-11e4-a52e-4f735466cecf";
const SEMANTIC_SNAPSHOT_SCRIPT: &str = r#"
return Array.from(document.querySelectorAll(
  'a,button,input,select,textarea,[role],[aria-label],[contenteditable="true"]'
)).slice(0, 500).map((el, index) => ({
  index,
  tag: el.tagName.toLowerCase(),
  id: el.id || null,
  role: el.getAttribute('role'),
  name: el.getAttribute('aria-label') || el.getAttribute('name'),
  element_type: el.getAttribute('type'),
  text: ((el.innerText || el.textContent || '').trim()).slice(0, 500),
  disabled: !!el.disabled || el.getAttribute('aria-disabled') === 'true'
}));
"#;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ElementRef {
    id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SemanticNode {
    pub index: u64,
    pub tag: String,
    pub id: Option<String>,
    pub role: Option<String>,
    pub name: Option<String>,
    pub element_type: Option<String>,
    pub text: String,
    pub disabled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DownloadReceipt {
    pub operation_id: String,
    pub file_name: String,
    pub size_bytes: u64,
    pub sha256: String,
    pub path: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DownloadOperation {
    operation_id: String,
    file_name: String,
    target: PathBuf,
    partial: PathBuf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BrowserCloseState {
    Open,
    Closing,
    Closed,
    CloseUnconfirmed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrowserCloseReceipt {
    pub state: BrowserCloseState,
}

pub struct BrowserBridge {
    driver: GeckoDriverProcess,
    session_id: String,
    download_dir: PathBuf,
    bidi_url: String,
    close_state: BrowserCloseState,
}

#[derive(Debug, Clone)]
pub struct BrowserWorkerConfig {
    pub geckodriver_path: PathBuf,
    pub firefox_binary: PathBuf,
    pub lab_root: PathBuf,
    pub allowed_origin: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct BrowserSessionOwner {
    organization_id: String,
    actor_id: String,
    device_id: String,
    workspace_id: Option<String>,
}

struct ManagedBrowserSession {
    owner: BrowserSessionOwner,
    bridge: BrowserBridge,
    generation: u64,
    root: PathBuf,
}

#[derive(Default)]
pub struct BrowserSessionWorker {
    config: Option<BrowserWorkerConfig>,
    sessions: BTreeMap<String, ManagedBrowserSession>,
}

impl BrowserSessionWorker {
    pub fn disabled() -> Self {
        Self {
            config: None,
            sessions: BTreeMap::new(),
        }
    }

    pub fn new(config: BrowserWorkerConfig) -> Self {
        Self {
            config: Some(config),
            sessions: BTreeMap::new(),
        }
    }

    pub fn execute_approved(
        &mut self,
        execution: &ExecutionAuthorization,
    ) -> Result<serde_json::Value, BrowserError> {
        if execution.request().envelope.action != "browser.session.use" {
            return Err(BrowserError::WrongAction);
        }
        let operation = required_str(execution, "operation")?;
        match operation {
            "start" => self.start_session(execution),
            "navigate" => self.navigate(execution),
            "observe" => self.observe(execution),
            "click" => self.click(execution),
            "download" => self.download(execution),
            "close" => self.close(execution),
            _ => Err(BrowserError::InvalidOperation),
        }
    }

    fn start_session(
        &mut self,
        execution: &ExecutionAuthorization,
    ) -> Result<serde_json::Value, BrowserError> {
        let config = self.config.clone().ok_or(BrowserError::BrowserDisabled)?;
        let request = execution.request();
        let owner = owner_from_execution(execution);
        let session_id = opaque_session_id(request.envelope_digest);
        if self.sessions.contains_key(&session_id) {
            return Err(BrowserError::DuplicateSession);
        }
        let root = allocate_session_root(&config.lab_root, &session_id)?;
        let browser_config =
            BrowserConfig::new(&config.geckodriver_path, &config.firefox_binary, &root)
                .headless(true);
        let bridge = match BrowserBridge::launch(browser_config) {
            Ok(bridge) => bridge,
            Err(error) => {
                let _ = remove_owned_session_root(&config.lab_root, &root);
                return Err(error);
            }
        };
        self.sessions.insert(
            session_id.clone(),
            ManagedBrowserSession {
                owner,
                bridge,
                generation: 0,
                root,
            },
        );
        Ok(json!({
            "session_id": session_id,
            "generation": 0,
        }))
    }

    fn navigate(
        &mut self,
        execution: &ExecutionAuthorization,
    ) -> Result<serde_json::Value, BrowserError> {
        let target = required_str(execution, "url")?.to_owned();
        let allowed_origin = self
            .config
            .as_ref()
            .ok_or(BrowserError::BrowserDisabled)?
            .allowed_origin
            .clone();
        if !same_origin_url(&target, &allowed_origin) {
            return Err(BrowserError::NavigationOutOfScope);
        }
        let session = self.session_mut(execution)?;
        session.bridge.navigate(&target)?;
        session.generation += 1;
        Ok(json!({
            "session_id": required_str(execution, "session_id")?,
            "generation": session.generation,
        }))
    }

    fn observe(
        &mut self,
        execution: &ExecutionAuthorization,
    ) -> Result<serde_json::Value, BrowserError> {
        let session = self.session_mut(execution)?;
        let snapshot = session.bridge.semantic_snapshot()?;
        Ok(json!({
            "session_id": required_str(execution, "session_id")?,
            "generation": session.generation,
            "nodes": snapshot,
        }))
    }

    fn click(
        &mut self,
        execution: &ExecutionAuthorization,
    ) -> Result<serde_json::Value, BrowserError> {
        let selector = required_str(execution, "selector")?.to_owned();
        let expected_generation = required_u64(execution, "generation")?;
        let session = self.session_mut(execution)?;
        if expected_generation != session.generation {
            return Err(BrowserError::StaleElement);
        }
        let element = session.bridge.find_css(&selector)?;
        session.bridge.click(&element)?;
        Ok(json!({
            "session_id": required_str(execution, "session_id")?,
            "generation": session.generation,
            "clicked": true,
        }))
    }

    fn download(
        &mut self,
        execution: &ExecutionAuthorization,
    ) -> Result<serde_json::Value, BrowserError> {
        let selector = required_str(execution, "selector")?.to_owned();
        let file_name = required_str(execution, "file_name")?.to_owned();
        let operation_id = required_str(execution, "operation_id")?.to_owned();
        let expected_generation = required_u64(execution, "generation")?;
        let session = self.session_mut(execution)?;
        if expected_generation != session.generation {
            return Err(BrowserError::StaleElement);
        }
        let op = session.bridge.prepare_download(&operation_id, &file_name)?;
        let element = session.bridge.find_css(&selector)?;
        session.bridge.click(&element)?;
        let receipt = session
            .bridge
            .complete_download(&op, Duration::from_secs(10))?;
        Ok(serde_json::to_value(receipt)?)
    }

    fn close(
        &mut self,
        execution: &ExecutionAuthorization,
    ) -> Result<serde_json::Value, BrowserError> {
        let session_id = required_str(execution, "session_id")?.to_owned();
        {
            let session = self.session_mut(execution)?;
            let receipt = session.bridge.close()?;
            if receipt.state != BrowserCloseState::Closed {
                return Ok(serde_json::to_value(receipt)?);
            }
        }
        if let Some(session) = self.sessions.remove(&session_id) {
            let config = self.config.as_ref().ok_or(BrowserError::BrowserDisabled)?;
            remove_owned_session_root(&config.lab_root, &session.root)?;
        }
        Ok(json!({
            "session_id": session_id,
            "state": "closed",
        }))
    }

    fn session_mut(
        &mut self,
        execution: &ExecutionAuthorization,
    ) -> Result<&mut ManagedBrowserSession, BrowserError> {
        let session_id = required_str(execution, "session_id")?;
        let owner = owner_from_execution(execution);
        let session = self
            .sessions
            .get_mut(session_id)
            .ok_or(BrowserError::SessionNotFound)?;
        if session.owner != owner {
            // Do not disclose whether a caller-supplied opaque session id exists.
            return Err(BrowserError::SessionNotFound);
        }
        Ok(session)
    }
}

fn opaque_session_id(envelope_digest: [u8; 32]) -> String {
    format!("bs-{}", hex::encode(envelope_digest))
}

fn allocate_session_root(lab_root: &Path, session_id: &str) -> Result<PathBuf, BrowserError> {
    if !is_single_safe_component(session_id) {
        return Err(BrowserError::UnsafeSessionId);
    }
    fs::create_dir_all(lab_root)?;
    let lab_root = lab_root.canonicalize()?;
    let root = lab_root.join(session_id);
    if root.exists() {
        return Err(BrowserError::DuplicateSession);
    }
    fs::create_dir(&root)?;
    let canonical_root = root.canonicalize()?;
    if !canonical_root.starts_with(&lab_root) {
        return Err(BrowserError::SessionRootEscaped);
    }
    Ok(canonical_root)
}

fn remove_owned_session_root(lab_root: &Path, root: &Path) -> Result<(), BrowserError> {
    let lab_root = lab_root.canonicalize()?;
    let root = root.canonicalize()?;
    if !root.starts_with(&lab_root) || root == lab_root {
        return Err(BrowserError::SessionRootEscaped);
    }
    fs::remove_dir_all(root).map_err(BrowserError::CleanupFailed)
}

fn is_single_safe_component(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 80
        && Path::new(value)
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}

impl BrowserBridge {
    pub fn launch(config: BrowserConfig) -> Result<Self, BrowserError> {
        let driver = GeckoDriverProcess::start(&config)?;
        let firefox = path_text(&config.firefox_binary)?;
        let profile = path_text(&config.profile_path)?;
        let download = path_text(&config.download_dir)?;
        let mut args = Vec::new();
        if config.headless {
            args.push("-headless".to_owned());
        }
        args.push("-profile".to_owned());
        args.push(profile);
        let payload = json!({
            "capabilities": {
                "alwaysMatch": {
                    "browserName": "firefox",
                    "webSocketUrl": true,
                    "moz:firefoxOptions": {
                        "binary": firefox,
                        "args": args,
                        "prefs": {
                            "browser.download.folderList": 2,
                            "browser.download.useDownloadDir": true,
                            "browser.download.dir": download,
                            "browser.download.alwaysOpenPanel": false,
                            "browser.download.manager.showWhenStarting": false,
                            "browser.helperApps.neverAsk.saveToDisk": "application/octet-stream,text/plain,application/zip,application/pdf"
                        }
                    }
                }
            }
        });
        let url = format!("{}/session", driver.endpoint);
        let mut response = ureq::post(&url).send_json(&payload)?;
        let body: Value = response.body_mut().read_json()?;
        let value = body
            .get("value")
            .ok_or(BrowserError::MissingField("value"))?;
        let session_id = value
            .get("sessionId")
            .and_then(Value::as_str)
            .ok_or(BrowserError::MissingField("sessionId"))?
            .to_owned();
        let bidi_url = value
            .get("capabilities")
            .and_then(|v| v.get("webSocketUrl"))
            .and_then(Value::as_str)
            .ok_or(BrowserError::MissingField("webSocketUrl"))?
            .to_owned();
        Ok(Self {
            driver,
            session_id,
            download_dir: config.download_dir.clone(),
            bidi_url,
            close_state: BrowserCloseState::Open,
        })
    }

    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    pub fn bidi_url(&self) -> &str {
        &self.bidi_url
    }

    pub fn navigate(&self, url: &str) -> Result<(), BrowserError> {
        self.ensure_open()?;
        self.post("url", &json!({ "url": url }))?;
        Ok(())
    }

    pub fn title(&self) -> Result<String, BrowserError> {
        self.ensure_open()?;
        value_string(self.get("title")?, "title")
    }

    pub fn page_source(&self) -> Result<String, BrowserError> {
        self.ensure_open()?;
        value_string(self.get("source")?, "source")
    }

    pub fn screenshot_png(&self) -> Result<Vec<u8>, BrowserError> {
        self.ensure_open()?;
        let encoded = value_string(self.get("screenshot")?, "screenshot")?;
        Ok(STANDARD.decode(encoded)?)
    }

    pub fn find_css(&self, selector: &str) -> Result<ElementRef, BrowserError> {
        self.ensure_open()?;
        let value = self.post(
            "element",
            &json!({ "using": "css selector", "value": selector }),
        )?;
        let id = value
            .get(WEB_ELEMENT_KEY)
            .and_then(Value::as_str)
            .ok_or(BrowserError::MissingField("web element id"))?;
        Ok(ElementRef { id: id.to_owned() })
    }

    pub fn click(&self, element: &ElementRef) -> Result<(), BrowserError> {
        self.ensure_open()?;
        self.post(&format!("element/{}/click", element.id), &json!({}))?;
        Ok(())
    }

    pub fn type_text(&self, element: &ElementRef, text: &str) -> Result<(), BrowserError> {
        self.ensure_open()?;
        self.post(
            &format!("element/{}/value", element.id),
            &json!({ "text": text }),
        )?;
        Ok(())
    }

    pub fn element_text(&self, element: &ElementRef) -> Result<String, BrowserError> {
        self.ensure_open()?;
        value_string(
            self.get(&format!("element/{}/text", element.id))?,
            "element text",
        )
    }

    pub fn semantic_snapshot(&self) -> Result<Vec<SemanticNode>, BrowserError> {
        self.ensure_open()?;
        let value = self.post(
            "execute/sync",
            &json!({ "script": SEMANTIC_SNAPSHOT_SCRIPT, "args": [] }),
        )?;
        Ok(serde_json::from_value(value)?)
    }

    pub fn wait_for_download(
        &self,
        file_name: &str,
        timeout: Duration,
    ) -> Result<PathBuf, BrowserError> {
        Ok(self
            .wait_for_download_receipt("legacy-download", file_name, timeout)?
            .path)
    }

    pub fn wait_for_download_receipt(
        &self,
        operation_id: &str,
        file_name: &str,
        timeout: Duration,
    ) -> Result<DownloadReceipt, BrowserError> {
        let operation = self.prepare_download(operation_id, file_name)?;
        self.complete_download(&operation, timeout)
    }

    pub fn prepare_download(
        &self,
        operation_id: &str,
        file_name: &str,
    ) -> Result<DownloadOperation, BrowserError> {
        self.ensure_open()?;
        if operation_id.trim().is_empty() {
            return Err(BrowserError::InvalidOperationId);
        }
        let relative = safe_download_name(file_name)?;
        let target = self.download_dir.join(relative);
        let partial = self.download_dir.join(format!("{file_name}.part"));
        if target.exists() || partial.exists() {
            return Err(BrowserError::PreexistingDownload(file_name.to_owned()));
        }
        Ok(DownloadOperation {
            operation_id: operation_id.to_owned(),
            file_name: file_name.to_owned(),
            target,
            partial,
        })
    }

    pub fn complete_download(
        &self,
        operation: &DownloadOperation,
        timeout: Duration,
    ) -> Result<DownloadReceipt, BrowserError> {
        self.ensure_open()?;
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if operation.target.is_file() && !operation.partial.exists() {
                let canonical_download_dir = self.download_dir.canonicalize()?;
                let canonical_target = operation.target.canonicalize()?;
                if !canonical_target.starts_with(&canonical_download_dir) {
                    return Err(BrowserError::DownloadEscaped);
                }
                let bytes = fs::read(&canonical_target)?;
                return Ok(DownloadReceipt {
                    operation_id: operation.operation_id.clone(),
                    file_name: operation.file_name.clone(),
                    size_bytes: bytes.len() as u64,
                    sha256: hex::encode(Sha256::digest(&bytes)),
                    path: canonical_target,
                });
            }
            thread::sleep(DRIVER_POLL_INTERVAL);
        }
        Err(BrowserError::DownloadTimeout(operation.file_name.clone()))
    }

    pub fn bidi_status(&self) -> Result<Value, BrowserError> {
        self.ensure_open()?;
        let (mut socket, _) = connect(self.bidi_url.as_str())?;
        let command = json!({ "id": 1, "method": "session.status", "params": {} });
        socket.send(Message::Text(command.to_string().into()))?;
        loop {
            match socket.read()? {
                Message::Text(text) => {
                    let value: Value = serde_json::from_str(text.as_str())?;
                    if value.get("id").and_then(Value::as_u64) == Some(1) {
                        return Ok(value);
                    }
                }
                Message::Close(_) => return Err(BrowserError::BidiClosed),
                _ => {}
            }
        }
    }

    pub fn close(&mut self) -> Result<BrowserCloseReceipt, BrowserError> {
        match self.close_state {
            BrowserCloseState::Closed => {
                return Ok(BrowserCloseReceipt {
                    state: BrowserCloseState::Closed,
                });
            }
            BrowserCloseState::Closing | BrowserCloseState::CloseUnconfirmed => {
                return Err(BrowserError::SessionClosing);
            }
            BrowserCloseState::Open => {}
        }
        self.close_state = BrowserCloseState::Closing;
        let url = format!("{}/session/{}", self.driver.endpoint, self.session_id);
        match ureq::delete(&url).call() {
            Ok(_) => {
                self.close_state = BrowserCloseState::Closed;
                Ok(BrowserCloseReceipt {
                    state: BrowserCloseState::Closed,
                })
            }
            Err(error) => {
                self.close_state = BrowserCloseState::CloseUnconfirmed;
                Err(BrowserError::CloseUnconfirmed(Box::new(error)))
            }
        }
    }

    fn get(&self, command: &str) -> Result<Value, BrowserError> {
        let url = self.command_url(command);
        let mut response = ureq::get(&url).call()?;
        webdriver_value(response.body_mut().read_json()?)
    }

    fn post(&self, command: &str, payload: &Value) -> Result<Value, BrowserError> {
        let url = self.command_url(command);
        let mut response = ureq::post(&url).send_json(payload)?;
        webdriver_value(response.body_mut().read_json()?)
    }

    fn command_url(&self, command: &str) -> String {
        format!(
            "{}/session/{}/{}",
            self.driver.endpoint,
            self.session_id,
            command.trim_start_matches('/')
        )
    }

    fn ensure_open(&self) -> Result<(), BrowserError> {
        match self.close_state {
            BrowserCloseState::Open => Ok(()),
            BrowserCloseState::Closing | BrowserCloseState::CloseUnconfirmed => {
                Err(BrowserError::SessionClosing)
            }
            BrowserCloseState::Closed => Err(BrowserError::SessionClosed),
        }
    }
}

impl Drop for BrowserBridge {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

fn webdriver_value(body: Value) -> Result<Value, BrowserError> {
    body.get("value")
        .cloned()
        .ok_or(BrowserError::MissingField("value"))
}

fn value_string(value: Value, field: &'static str) -> Result<String, BrowserError> {
    value
        .as_str()
        .map(ToOwned::to_owned)
        .ok_or(BrowserError::MissingField(field))
}

fn path_text(path: &Path) -> Result<String, BrowserError> {
    path.to_str()
        .map(ToOwned::to_owned)
        .ok_or(BrowserError::NonUtf8Path)
}

fn safe_download_name(file_name: &str) -> Result<&Path, BrowserError> {
    let relative = Path::new(file_name);
    let Some(name) = relative.to_str() else {
        return Err(BrowserError::UnsafeDownloadName);
    };
    if name.is_empty()
        || name.contains(':')
        || name.contains(['<', '>', '"', '|', '?', '*'])
        || name.ends_with(' ')
        || name.ends_with('.')
    {
        return Err(BrowserError::UnsafeDownloadName);
    }
    let mut parts = relative.components();
    if !matches!(parts.next(), Some(Component::Normal(_))) || parts.next().is_some() {
        return Err(BrowserError::UnsafeDownloadName);
    }
    let stem = name.split('.').next().unwrap_or(name).to_ascii_lowercase();
    if matches!(
        stem.as_str(),
        "con"
            | "prn"
            | "aux"
            | "nul"
            | "com1"
            | "com2"
            | "com3"
            | "com4"
            | "com5"
            | "com6"
            | "com7"
            | "com8"
            | "com9"
            | "lpt1"
            | "lpt2"
            | "lpt3"
            | "lpt4"
            | "lpt5"
            | "lpt6"
            | "lpt7"
            | "lpt8"
            | "lpt9"
    ) {
        return Err(BrowserError::UnsafeDownloadName);
    }
    Ok(relative)
}

fn owner_from_execution(execution: &ExecutionAuthorization) -> BrowserSessionOwner {
    let envelope = &execution.request().envelope;
    BrowserSessionOwner {
        organization_id: envelope.organization_id.clone(),
        actor_id: envelope.actor_id.clone(),
        device_id: envelope.device_id.clone(),
        workspace_id: envelope
            .parameters
            .get("workspace_id")
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned),
    }
}

fn required_str<'a>(
    execution: &'a ExecutionAuthorization,
    name: &'static str,
) -> Result<&'a str, BrowserError> {
    execution
        .request()
        .envelope
        .parameters
        .get(name)
        .and_then(serde_json::Value::as_str)
        .ok_or(BrowserError::MissingParameter(name))
}

fn required_u64(
    execution: &ExecutionAuthorization,
    name: &'static str,
) -> Result<u64, BrowserError> {
    execution
        .request()
        .envelope
        .parameters
        .get(name)
        .and_then(serde_json::Value::as_u64)
        .ok_or(BrowserError::MissingParameter(name))
}

fn same_origin_url(candidate: &str, allowed_origin: &str) -> bool {
    let Some((scheme, host, port, rest)) = parse_http_origin(candidate) else {
        return false;
    };
    if rest.contains('@') {
        return false;
    }
    let Some((allowed_scheme, allowed_host, allowed_port, _)) = parse_http_origin(allowed_origin)
    else {
        return false;
    };
    scheme == allowed_scheme && host == allowed_host && port == allowed_port
}

fn parse_http_origin(input: &str) -> Option<(&str, &str, u16, &str)> {
    let (scheme, rest) = input.split_once("://")?;
    if scheme != "http" && scheme != "https" {
        return None;
    }
    let (authority, path) = rest.split_once('/').unwrap_or((rest, ""));
    if authority.is_empty() || authority.contains('@') {
        return None;
    }
    let default_port = if scheme == "https" { 443 } else { 80 };
    let (host, port) = match authority.rsplit_once(':') {
        Some((host, port)) => (host, port.parse().ok()?),
        None => (authority, default_port),
    };
    if host.is_empty() {
        return None;
    }
    Some((scheme, host, port, path))
}

#[derive(Debug, Error)]
pub enum BrowserError {
    #[error("required executable is missing: {0}")]
    MissingExecutable(&'static str),
    #[error("configured path is not valid UTF-8")]
    NonUtf8Path,
    #[error("browser worker is not configured")]
    BrowserDisabled,
    #[error("browser action is unsupported")]
    WrongAction,
    #[error("browser operation is invalid")]
    InvalidOperation,
    #[error("browser request is missing parameter: {0}")]
    MissingParameter(&'static str),
    #[error("browser session already exists")]
    DuplicateSession,
    #[error("browser session id is not a safe storage component")]
    UnsafeSessionId,
    #[error("browser session root escaped its configured lab root")]
    SessionRootEscaped,
    #[error("browser session cleanup failed: {0}")]
    CleanupFailed(std::io::Error),
    #[error("browser session was not found")]
    SessionNotFound,
    #[error("geckodriver exited before becoming ready: {0:?}")]
    DriverExited(Option<i32>),
    #[error("geckodriver did not become ready before timeout")]
    DriverStartupTimeout,
    #[error("WebDriver response is missing field: {0}")]
    MissingField(&'static str),
    #[error("BiDi socket closed before the command response arrived")]
    BidiClosed,
    #[error("download filename must be a single safe path component")]
    UnsafeDownloadName,
    #[error("download did not complete before timeout: {0}")]
    DownloadTimeout(String),
    #[error("download operation id is invalid")]
    InvalidOperationId,
    #[error("download file already existed before the operation: {0}")]
    PreexistingDownload(String),
    #[error("download escaped its confined directory")]
    DownloadEscaped,
    #[error("browser session is closing or close confirmation was lost")]
    SessionClosing,
    #[error("browser session is closed")]
    SessionClosed,
    #[error("browser action requires approval")]
    ApprovalRequired,
    #[error("browser approval does not match session, actor, device or element")]
    ApprovalMismatch,
    #[error("browser element reference is stale")]
    StaleElement,
    #[error("browser navigation target is outside the allowed lab origin")]
    NavigationOutOfScope,
    #[error("browser close request was sent but not confirmed: {0}")]
    CloseUnconfirmed(Box<ureq::Error>),
    #[error("browser I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("WebDriver HTTP failed: {0}")]
    Http(#[from] ureq::Error),
    #[error("browser JSON failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("BiDi WebSocket failed: {0}")]
    WebSocket(#[from] tungstenite::Error),
    #[error("screenshot base64 decode failed: {0}")]
    Base64(#[from] base64::DecodeError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::{SocketAddr, TcpStream};
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };
    use tempfile::tempdir;

    #[test]
    fn default_profile_is_isolated_under_state_root() {
        let root = tempdir().unwrap();
        let config = BrowserConfig::new("geckodriver.exe", "firefox.exe", root.path());
        assert_eq!(
            config.profile_path,
            root.path().join("profiles").join("Vor-Automation")
        );
        assert_eq!(
            config.driver_profile_root,
            root.path().join("driver-profiles")
        );
        assert_eq!(config.download_dir, root.path().join("downloads"));
    }

    #[test]
    fn download_names_are_single_safe_components() {
        assert_eq!(
            safe_download_name("report.txt").unwrap(),
            Path::new("report.txt")
        );
        for name in [
            "",
            ".",
            "..",
            "../secret.txt",
            "nested/file.txt",
            "nested\\file.txt",
            "C:\\secret.txt",
            "/tmp/secret.txt",
            "CON",
            "aux.txt",
            "bad:name.txt",
            "trailingspace.txt ",
            "trailingdot.txt.",
        ] {
            assert!(matches!(
                safe_download_name(name),
                Err(BrowserError::UnsafeDownloadName)
            ));
        }
    }

    #[test]
    fn driver_ready_requires_ready_true() {
        assert!(!webdriver_ready_value(&json!({"value": {"ready": false}})));
        assert!(!webdriver_ready_value(&json!({"value": {}})));
        assert!(!webdriver_ready_value(&json!({"value": "not-object"})));
        assert!(webdriver_ready_value(&json!({"value": {"ready": true}})));
    }

    #[test]
    #[ignore = "requires local Firefox and pinned geckodriver"]
    fn firefox_webdriver_and_bidi_roundtrip() {
        let geckodriver = std::env::var_os("VOR_GECKODRIVER").expect("VOR_GECKODRIVER");
        let firefox = std::env::var_os("VOR_FIREFOX").expect("VOR_FIREFOX");
        let root = tempdir().unwrap();
        let config = BrowserConfig::new(geckodriver, firefox, root.path()).headless(true);
        let mut browser = BrowserBridge::launch(config).unwrap();

        let page = root.path().join("page.html");
        fs::write(
            &page,
            r#"<title>Vor Browser</title>
<input id="name" name="who">
<button id="go" onclick="document.querySelector('h1').textContent='clicked'">Go</button>
<h1>bridge-ok</h1>
<a id="download" download="probe.txt" href="data:text/plain,download-ok">Download</a>"#,
        )
        .unwrap();
        let url = format!("file:///{}", page.to_string_lossy().replace('\\', "/"));
        browser.navigate(&url).unwrap();
        assert_eq!(browser.title().unwrap(), "Vor Browser");
        assert!(browser.page_source().unwrap().contains("bridge-ok"));

        let input = browser.find_css("#name").unwrap();
        browser.type_text(&input, "typed-secret-marker").unwrap();
        let button = browser.find_css("#go").unwrap();
        browser.click(&button).unwrap();
        let heading = browser.find_css("h1").unwrap();
        assert_eq!(browser.element_text(&heading).unwrap(), "clicked");

        let snapshot = browser.semantic_snapshot().unwrap();
        assert!(
            snapshot
                .iter()
                .any(|node| node.id.as_deref() == Some("name"))
        );
        assert!(!format!("{snapshot:?}").contains("typed-secret-marker"));

        let operation = browser
            .prepare_download("op-download-roundtrip", "probe.txt")
            .unwrap();
        let download = browser.find_css("#download").unwrap();
        browser.click(&download).unwrap();
        let receipt = browser
            .complete_download(&operation, Duration::from_secs(5))
            .unwrap();
        assert_eq!(receipt.file_name, "probe.txt");
        assert_eq!(receipt.sha256, hex::encode(Sha256::digest(b"download-ok")));
        assert_eq!(fs::read_to_string(receipt.path).unwrap(), "download-ok");

        let screenshot = browser.screenshot_png().unwrap();
        assert!(screenshot.starts_with(b"\x89PNG\r\n\x1a\n"));
        let status = browser.bidi_status().unwrap();
        assert_eq!(status.get("type").and_then(Value::as_str), Some("success"));
        assert_eq!(status.get("id").and_then(Value::as_u64), Some(1));

        assert_eq!(browser.close().unwrap().state, BrowserCloseState::Closed);
        assert!(matches!(browser.title(), Err(BrowserError::SessionClosed)));
    }

    #[test]
    #[ignore = "requires local Firefox and pinned geckodriver; run explicitly for A4 local E2E"]
    fn a4_local_browser_session_e2e() {
        let geckodriver = std::env::var_os("VOR_GECKODRIVER")
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                PathBuf::from(
                    r"D:\Proyectos\10_Active\vor-commander\state\drivers\geckodriver\0.37.1\geckodriver.exe",
                )
            });
        let firefox = std::env::var_os("VOR_FIREFOX")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(r"C:\Program Files\Mozilla Firefox\firefox.exe"));
        let lab = PathBuf::from(r"D:\Proyectos\10_Active\vor-commander\state\local\a4-lab");
        fs::create_dir_all(&lab).unwrap();

        let server = FixtureServer::start();
        let root_a = lab.join("session-a");
        let root_b = lab.join("session-b");
        let _ = fs::remove_dir_all(&root_a);
        let _ = fs::remove_dir_all(&root_b);
        let mut session_a = LabBrowserSession::launch(
            "actor-a",
            "device-a",
            &server.origin(),
            BrowserConfig::new(&geckodriver, &firefox, &root_a).headless(true),
        )
        .unwrap();
        let mut session_b = LabBrowserSession::launch(
            "actor-b",
            "device-b",
            &server.origin(),
            BrowserConfig::new(&geckodriver, &firefox, &root_b).headless(true),
        )
        .unwrap();

        session_a.navigate("/page?session=a").unwrap();
        session_b.navigate("/page?session=b").unwrap();
        let a_snapshot = session_a.observe().unwrap();
        let b_snapshot = session_b.observe().unwrap();
        assert!(format!("{a_snapshot:?}").contains("download-a"));
        assert!(format!("{b_snapshot:?}").contains("download-b"));
        assert!(!format!("{a_snapshot:?}").contains("typed-secret-marker"));

        let button_a = session_a.find("#go").unwrap();
        let denied = session_a.click_without_approval(&button_a);
        assert!(matches!(denied, Err(BrowserError::ApprovalRequired)));
        assert_eq!(session_a.heading().unwrap(), "ready-a");

        let wrong_actor = ApprovedClick {
            actor_id: "actor-b".into(),
            device_id: "device-a".into(),
            session_id: session_a.session_id.clone(),
            generation: button_a.generation,
            element_id: button_a.element.id.clone(),
        };
        assert!(matches!(
            session_a.click_approved(&button_a, &wrong_actor),
            Err(BrowserError::ApprovalMismatch)
        ));
        assert_eq!(session_a.heading().unwrap(), "ready-a");

        let approval = session_a.approve_click(&button_a);
        session_a.click_approved(&button_a, &approval).unwrap();
        assert_eq!(session_a.heading().unwrap(), "clicked-a");

        let stale = session_a.find("#go").unwrap();
        session_a.navigate("/page?session=a2").unwrap();
        let stale_approval = session_a.approve_click(&stale);
        assert!(matches!(
            session_a.click_approved(&stale, &stale_approval),
            Err(BrowserError::StaleElement)
        ));

        assert!(matches!(
            session_a.navigate("https://example.com/out-of-scope"),
            Err(BrowserError::NavigationOutOfScope)
        ));

        fs::write(root_a.join("downloads").join("preexisting.txt"), b"old").unwrap();
        assert!(matches!(
            session_a
                .bridge
                .prepare_download("op-preexisting", "preexisting.txt"),
            Err(BrowserError::PreexistingDownload(_))
        ));
        assert!(matches!(
            session_a
                .bridge
                .prepare_download("op-danger", "..\\escape.txt"),
            Err(BrowserError::UnsafeDownloadName)
        ));
        let missing = session_a
            .bridge
            .prepare_download("op-incomplete", "never-finishes.txt")
            .unwrap();
        assert!(matches!(
            session_a
                .bridge
                .complete_download(&missing, Duration::from_millis(150)),
            Err(BrowserError::DownloadTimeout(_))
        ));

        session_a.navigate("/page?session=a").unwrap();
        let download_op = session_a
            .bridge
            .prepare_download("op-download-a", "download-a.txt")
            .unwrap();
        let download = session_a.find("#download").unwrap();
        let approval = session_a.approve_click(&download);
        session_a.click_approved(&download, &approval).unwrap();
        let receipt = session_a
            .bridge
            .complete_download(&download_op, Duration::from_secs(10))
            .unwrap();
        assert_eq!(receipt.operation_id, "op-download-a");
        assert_eq!(receipt.size_bytes, b"download-a".len() as u64);
        assert_eq!(receipt.sha256, hex::encode(Sha256::digest(b"download-a")));
        assert!(
            receipt
                .path
                .starts_with(root_a.join("downloads").canonicalize().unwrap())
        );
        assert!(!root_b.join("downloads").join("download-a.txt").exists());

        assert_eq!(session_a.close().unwrap().state, BrowserCloseState::Closed);
        assert!(matches!(
            session_a.heading(),
            Err(BrowserError::SessionClosed)
        ));
        assert_eq!(session_b.close().unwrap().state, BrowserCloseState::Closed);
    }

    fn webdriver_ready_value(body: &Value) -> bool {
        body.get("value")
            .and_then(|value| value.get("ready"))
            .and_then(Value::as_bool)
            == Some(true)
    }

    struct FixtureServer {
        address: SocketAddr,
        stop: Arc<AtomicBool>,
        thread: Option<std::thread::JoinHandle<()>>,
    }

    impl FixtureServer {
        fn start() -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap();
            listener.set_nonblocking(true).unwrap();
            let stop = Arc::new(AtomicBool::new(false));
            let thread_stop = Arc::clone(&stop);
            let thread = std::thread::spawn(move || {
                while !thread_stop.load(Ordering::SeqCst) {
                    match listener.accept() {
                        Ok((mut stream, _)) => handle_fixture_request(&mut stream),
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            std::thread::sleep(Duration::from_millis(10));
                        }
                        Err(_) => break,
                    }
                }
            });
            Self {
                address,
                stop,
                thread: Some(thread),
            }
        }

        fn origin(&self) -> String {
            format!("http://{}", self.address)
        }
    }

    impl Drop for FixtureServer {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::SeqCst);
            let _ = TcpStream::connect(self.address);
            if let Some(thread) = self.thread.take() {
                let _ = thread.join();
            }
        }
    }

    fn handle_fixture_request(stream: &mut TcpStream) {
        let mut buffer = [0u8; 4096];
        let Ok(read) = stream.read(&mut buffer) else {
            return;
        };
        let request = String::from_utf8_lossy(&buffer[..read]);
        let first_line = request.lines().next().unwrap_or_default();
        let path = first_line.split_whitespace().nth(1).unwrap_or("/");
        if path.starts_with("/download-a.txt") {
            respond(
                stream,
                "200 OK",
                "application/octet-stream",
                b"download-a",
                Some("attachment; filename=\"download-a.txt\""),
            );
            return;
        }
        let session = if path.contains("session=b") {
            "b"
        } else if path.contains("session=a2") {
            "a2"
        } else {
            "a"
        };
        let body = format!(
            r#"<!doctype html><title>A4 {session}</title>
<input id="secret" value="typed-secret-marker">
<button id="go" onclick="document.querySelector('h1').textContent='clicked-{session}'">go</button>
<h1>ready-{session}</h1>
<a id="download" download="download-a.txt" href="/download-a.txt">download-{session}</a>"#
        );
        respond(
            stream,
            "200 OK",
            "text/html; charset=utf-8",
            body.as_bytes(),
            None,
        );
    }

    fn respond(
        stream: &mut TcpStream,
        status: &str,
        content_type: &str,
        body: &[u8],
        disposition: Option<&str>,
    ) {
        let mut headers = format!(
            "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n",
            body.len()
        );
        if let Some(disposition) = disposition {
            headers.push_str(&format!("Content-Disposition: {disposition}\r\n"));
        }
        headers.push_str("\r\n");
        let _ = stream.write_all(headers.as_bytes());
        let _ = stream.write_all(body);
    }

    struct LabBrowserSession {
        actor_id: String,
        device_id: String,
        session_id: String,
        allowed_origin: String,
        generation: u64,
        bridge: BrowserBridge,
    }

    struct LabElementRef {
        session_id: String,
        generation: u64,
        element: ElementRef,
    }

    struct ApprovedClick {
        actor_id: String,
        device_id: String,
        session_id: String,
        generation: u64,
        element_id: String,
    }

    impl LabBrowserSession {
        fn launch(
            actor_id: &str,
            device_id: &str,
            allowed_origin: &str,
            config: BrowserConfig,
        ) -> Result<Self, BrowserError> {
            let bridge = BrowserBridge::launch(config)?;
            Ok(Self {
                actor_id: actor_id.to_owned(),
                device_id: device_id.to_owned(),
                session_id: format!("{actor_id}:{device_id}:{}", bridge.session_id()),
                allowed_origin: allowed_origin.to_owned(),
                generation: 0,
                bridge,
            })
        }

        fn navigate(&mut self, target: &str) -> Result<(), BrowserError> {
            let url = if target.starts_with('/') {
                format!("{}{}", self.allowed_origin, target)
            } else {
                target.to_owned()
            };
            if !url.starts_with(&self.allowed_origin) {
                return Err(BrowserError::NavigationOutOfScope);
            }
            self.bridge.navigate(&url)?;
            self.generation += 1;
            Ok(())
        }

        fn observe(&self) -> Result<Vec<SemanticNode>, BrowserError> {
            self.bridge.semantic_snapshot()
        }

        fn find(&self, selector: &str) -> Result<LabElementRef, BrowserError> {
            Ok(LabElementRef {
                session_id: self.session_id.clone(),
                generation: self.generation,
                element: self.bridge.find_css(selector)?,
            })
        }

        fn heading(&self) -> Result<String, BrowserError> {
            let heading = self.bridge.find_css("h1")?;
            self.bridge.element_text(&heading)
        }

        fn click_without_approval(&self, _element: &LabElementRef) -> Result<(), BrowserError> {
            Err(BrowserError::ApprovalRequired)
        }

        fn approve_click(&self, element: &LabElementRef) -> ApprovedClick {
            ApprovedClick {
                actor_id: self.actor_id.clone(),
                device_id: self.device_id.clone(),
                session_id: self.session_id.clone(),
                generation: element.generation,
                element_id: element.element.id.clone(),
            }
        }

        fn click_approved(
            &self,
            element: &LabElementRef,
            approval: &ApprovedClick,
        ) -> Result<(), BrowserError> {
            if approval.actor_id != self.actor_id
                || approval.device_id != self.device_id
                || approval.session_id != self.session_id
                || element.session_id != self.session_id
                || approval.element_id != element.element.id
            {
                return Err(BrowserError::ApprovalMismatch);
            }
            if approval.generation != self.generation || element.generation != self.generation {
                return Err(BrowserError::StaleElement);
            }
            self.bridge.click(&element.element)
        }

        fn close(&mut self) -> Result<BrowserCloseReceipt, BrowserError> {
            self.bridge.close()
        }
    }
}
