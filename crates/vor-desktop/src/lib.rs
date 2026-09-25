// SPDX-License-Identifier: MPL-2.0

use serde::{Deserialize, Serialize};
use thiserror::Error;
use vor_core::ExecutionAuthorization;
use windows::Win32::Foundation::RECT;
use windows::Win32::Graphics::Gdi::{
    BI_RGB, BITMAPINFO, BITMAPINFOHEADER, BitBlt, CreateCompatibleBitmap, CreateCompatibleDC,
    DIB_RGB_COLORS, DeleteDC, DeleteObject, GetDC, GetDIBits, HBITMAP, HDC, HGDIOBJ, ReleaseDC,
    SRCCOPY, SelectObject,
};
use windows::Win32::System::Com::{
    CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED, CoCreateInstance, CoInitializeEx, CoUninitialize,
};
use windows::Win32::UI::Accessibility::{
    CUIAutomation, IUIAutomation, IUIAutomationCondition, IUIAutomationElement,
    IUIAutomationInvokePattern, IUIAutomationValuePattern, TreeScope_Children, UIA_InvokePatternId,
    UIA_ValuePatternId,
};
use windows::Win32::UI::WindowsAndMessaging::{
    GetSystemMetrics, SM_CXVIRTUALSCREEN, SM_CYVIRTUALSCREEN, SM_XVIRTUALSCREEN, SM_YVIRTUALSCREEN,
};
use windows::core::BSTR;

const DEFAULT_MAX_DEPTH: usize = 4;
const DEFAULT_MAX_NODES: usize = 512;
const ABSOLUTE_MAX_DEPTH: usize = 12;
const ABSOLUTE_MAX_NODES: usize = 4096;
const ABSOLUTE_MAX_SCREENSHOT_PIXELS: u64 = 40_000_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DesktopRect {
    pub left: i32,
    pub top: i32,
    pub right: i32,
    pub bottom: i32,
}
impl From<RECT> for DesktopRect {
    fn from(value: RECT) -> Self {
        Self {
            left: value.left,
            top: value.top,
            right: value.right,
            bottom: value.bottom,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ElementSnapshot {
    pub name: String,
    pub automation_id: String,
    pub control_type: i32,
    pub process_id: u32,
    pub native_window_handle: i64,
    pub bounds: DesktopRect,
    pub enabled: bool,
    pub offscreen: bool,
}

#[derive(Debug, Clone)]
pub struct DesktopScreenshot {
    pub origin_x: i32,
    pub origin_y: i32,
    pub width: u32,
    pub height: u32,
    pub png: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SemanticNode {
    pub index: usize,
    pub parent_index: Option<usize>,
    pub depth: usize,
    pub element: ElementSnapshot,
}
pub struct DesktopInspector {
    automation: IUIAutomation,
    _com: ComApartment,
}

impl DesktopInspector {
    pub fn new() -> Result<Self, DesktopError> {
        let com = ComApartment::initialize()?;
        let automation = unsafe {
            CoCreateInstance::<_, IUIAutomation>(&CUIAutomation, None, CLSCTX_INPROC_SERVER)?
        };
        Ok(Self {
            automation,
            _com: com,
        })
    }

    pub fn top_level_elements(&self) -> Result<Vec<ElementSnapshot>, DesktopError> {
        let root = unsafe { self.automation.GetRootElement()? };
        let condition = unsafe { self.automation.CreateTrueCondition()? };
        let elements = unsafe { root.FindAll(TreeScope_Children, &condition)? };
        let length = unsafe { elements.Length()? };
        let mut output = Vec::with_capacity(length.max(0) as usize);
        for index in 0..length {
            let element = unsafe { elements.GetElement(index)? };
            if let Ok(snapshot) = snapshot_element(&element) {
                output.push(snapshot);
            }
        }
        Ok(output)
    }
    pub fn capture_virtual_desktop_png(&self) -> Result<DesktopScreenshot, DesktopError> {
        capture_virtual_desktop_png()
    }

    pub fn invoke(&self, execution: ExecutionAuthorization) -> Result<(), DesktopError> {
        let target = approved_target(&execution, "desktop.invoke")?;
        let element = self.find_target(target.process_id, &target.automation_id)?;
        let pattern: IUIAutomationInvokePattern =
            unsafe { element.GetCurrentPatternAs(UIA_InvokePatternId)? };
        unsafe { pattern.Invoke()? };
        Ok(())
    }

    pub fn set_value(&self, execution: ExecutionAuthorization) -> Result<(), DesktopError> {
        let target = approved_target(&execution, "desktop.set_value")?;
        let value = execution
            .request()
            .envelope
            .parameters
            .get("value")
            .and_then(|value| value.as_str())
            .ok_or(DesktopError::InvalidActionParameters)?;
        if value.len() > 16 * 1024 || value.contains('\0') {
            return Err(DesktopError::InvalidActionParameters);
        }
        let element = self.find_target(target.process_id, &target.automation_id)?;
        if unsafe { element.CurrentIsPassword()? }.as_bool() {
            return Err(DesktopError::PasswordFieldDenied);
        }
        let pattern: IUIAutomationValuePattern =
            unsafe { element.GetCurrentPatternAs(UIA_ValuePatternId)? };
        if unsafe { pattern.CurrentIsReadOnly()? }.as_bool() {
            return Err(DesktopError::ReadOnlyElement);
        }
        let value = BSTR::from(value);
        unsafe { pattern.SetValue(&value)? };
        Ok(())
    }

    fn find_target(
        &self,
        process_id: u32,
        automation_id: &str,
    ) -> Result<IUIAutomationElement, DesktopError> {
        if automation_id.is_empty() || automation_id.len() > 1024 || automation_id.contains('\0') {
            return Err(DesktopError::InvalidActionParameters);
        }
        let root = unsafe { self.automation.GetRootElement()? };
        let condition = unsafe { self.automation.CreateTrueCondition()? };
        let mut queue = std::collections::VecDeque::new();
        queue.push_back(root);
        let mut visited = 0usize;
        while let Some(element) = queue.pop_front() {
            visited += 1;
            if visited > ABSOLUTE_MAX_NODES {
                return Err(DesktopError::TargetSearchLimit);
            }
            let pid = unsafe { element.CurrentProcessId() }.ok();
            let id = unsafe { element.CurrentAutomationId() }
                .ok()
                .map(|v| v.to_string());
            if pid == i32::try_from(process_id).ok() && id.as_deref() == Some(automation_id) {
                return Ok(element);
            }
            let children = unsafe { element.FindAll(TreeScope_Children, &condition) };
            let Ok(children) = children else { continue };
            let length = unsafe { children.Length()? };
            for index in 0..length {
                if let Ok(child) = unsafe { children.GetElement(index) } {
                    queue.push_back(child);
                }
            }
        }
        Err(DesktopError::TargetNotFound)
    }

    pub fn semantic_tree(
        &self,
        max_depth: Option<usize>,
        max_nodes: Option<usize>,
    ) -> Result<Vec<SemanticNode>, DesktopError> {
        let max_depth = max_depth.unwrap_or(DEFAULT_MAX_DEPTH);
        let max_nodes = max_nodes.unwrap_or(DEFAULT_MAX_NODES);
        if max_depth > ABSOLUTE_MAX_DEPTH || max_nodes == 0 || max_nodes > ABSOLUTE_MAX_NODES {
            return Err(DesktopError::InvalidLimits);
        }
        let root = unsafe { self.automation.GetRootElement()? };
        let condition = unsafe { self.automation.CreateTrueCondition()? };
        let mut queue = std::collections::VecDeque::new();
        enqueue_children(&root, None, 0, &condition, &mut queue)?;
        let mut nodes = Vec::new();
        while let Some((element, parent_index, depth)) = queue.pop_front() {
            if nodes.len() >= max_nodes {
                break;
            }
            let Ok(snapshot) = snapshot_element(&element) else {
                continue;
            };
            let index = nodes.len();
            nodes.push(SemanticNode {
                index,
                parent_index,
                depth,
                element: snapshot,
            });
            if depth < max_depth && nodes.len() < max_nodes {
                enqueue_children(&element, Some(index), depth + 1, &condition, &mut queue)?;
            }
        }
        Ok(nodes)
    }
}
struct ApprovedDesktopTarget {
    process_id: u32,
    automation_id: String,
}

fn approved_target(
    execution: &ExecutionAuthorization,
    expected_action: &str,
) -> Result<ApprovedDesktopTarget, DesktopError> {
    let authorization = execution.authorization();
    if !authorization.requires_approval()
        || authorization.request.envelope.action != expected_action
    {
        return Err(DesktopError::AuthorizationMismatch);
    }
    let parameters = &authorization.request.envelope.parameters;
    let process_id = parameters
        .get("process_id")
        .and_then(|value| value.as_u64())
        .and_then(|value| u32::try_from(value).ok())
        .ok_or(DesktopError::InvalidActionParameters)?;
    let automation_id = parameters
        .get("automation_id")
        .and_then(|value| value.as_str())
        .filter(|value| !value.is_empty() && value.len() <= 1024 && !value.contains('\0'))
        .ok_or(DesktopError::InvalidActionParameters)?
        .to_owned();
    Ok(ApprovedDesktopTarget {
        process_id,
        automation_id,
    })
}

fn enqueue_children(
    parent: &IUIAutomationElement,
    parent_index: Option<usize>,
    depth: usize,
    condition: &IUIAutomationCondition,
    queue: &mut std::collections::VecDeque<(IUIAutomationElement, Option<usize>, usize)>,
) -> Result<(), DesktopError> {
    let children = unsafe { parent.FindAll(TreeScope_Children, condition)? };
    let length = unsafe { children.Length()? };
    for index in 0..length {
        queue.push_back((unsafe { children.GetElement(index)? }, parent_index, depth));
    }
    Ok(())
}

fn snapshot_element(element: &IUIAutomationElement) -> Result<ElementSnapshot, DesktopError> {
    let name = unsafe { element.CurrentName()? }.to_string();
    let automation_id = unsafe { element.CurrentAutomationId()? }.to_string();
    let process_id = unsafe { element.CurrentProcessId()? };
    let hwnd = unsafe { element.CurrentNativeWindowHandle()? };
    Ok(ElementSnapshot {
        name,
        automation_id,
        control_type: unsafe { element.CurrentControlType()? }.0,
        process_id: u32::try_from(process_id).unwrap_or_default(),
        native_window_handle: hwnd.0 as isize as i64,
        bounds: unsafe { element.CurrentBoundingRectangle()? }.into(),
        enabled: unsafe { element.CurrentIsEnabled()? }.as_bool(),
        offscreen: unsafe { element.CurrentIsOffscreen()? }.as_bool(),
    })
}
fn capture_virtual_desktop_png() -> Result<DesktopScreenshot, DesktopError> {
    let x = unsafe { GetSystemMetrics(SM_XVIRTUALSCREEN) };
    let y = unsafe { GetSystemMetrics(SM_YVIRTUALSCREEN) };
    let width = unsafe { GetSystemMetrics(SM_CXVIRTUALSCREEN) };
    let height = unsafe { GetSystemMetrics(SM_CYVIRTUALSCREEN) };
    if width <= 0 || height <= 0 {
        return Err(DesktopError::InvalidScreenshotDimensions);
    }
    let pixels = u64::try_from(width)?
        .checked_mul(u64::try_from(height)?)
        .ok_or(DesktopError::ScreenshotTooLarge)?;
    if pixels > ABSOLUTE_MAX_SCREENSHOT_PIXELS {
        return Err(DesktopError::ScreenshotTooLarge);
    }
    let byte_len = usize::try_from(
        pixels
            .checked_mul(4)
            .ok_or(DesktopError::ScreenshotTooLarge)?,
    )?;

    let screen = ScreenDc::acquire()?;
    let memory = MemoryDc::create(screen.0)?;
    let bitmap = Bitmap::create(screen.0, width, height)?;
    let old = unsafe { SelectObject(memory.0, HGDIOBJ(bitmap.0.0)) };
    if old.0.is_null() {
        return Err(DesktopError::Gdi("SelectObject"));
    }
    let _selection = SelectedObject { dc: memory.0, old };
    unsafe { BitBlt(memory.0, 0, 0, width, height, Some(screen.0), x, y, SRCCOPY)? };

    let mut info = BITMAPINFO {
        bmiHeader: BITMAPINFOHEADER {
            biSize: std::mem::size_of::<BITMAPINFOHEADER>() as u32,
            biWidth: width,
            biHeight: -height,
            biPlanes: 1,
            biBitCount: 32,
            biCompression: BI_RGB.0,
            ..Default::default()
        },
        ..Default::default()
    };
    let mut rgba = vec![0u8; byte_len];
    let lines = unsafe {
        GetDIBits(
            memory.0,
            bitmap.0,
            0,
            height as u32,
            Some(rgba.as_mut_ptr().cast()),
            &mut info,
            DIB_RGB_COLORS,
        )
    };
    if lines != height {
        return Err(DesktopError::Gdi("GetDIBits"));
    }
    for pixel in rgba.chunks_exact_mut(4) {
        pixel.swap(0, 2);
        pixel[3] = 255;
    }

    let mut png_bytes = Vec::new();
    {
        let mut encoder = png::Encoder::new(&mut png_bytes, width as u32, height as u32);
        encoder.set_color(png::ColorType::Rgba);
        encoder.set_depth(png::BitDepth::Eight);
        let mut writer = encoder.write_header()?;
        writer.write_image_data(&rgba)?;
    }
    Ok(DesktopScreenshot {
        origin_x: x,
        origin_y: y,
        width: width as u32,
        height: height as u32,
        png: png_bytes,
    })
}

struct ScreenDc(HDC);
impl ScreenDc {
    fn acquire() -> Result<Self, DesktopError> {
        let dc = unsafe { GetDC(None) };
        if dc.0.is_null() {
            return Err(DesktopError::Gdi("GetDC"));
        }
        Ok(Self(dc))
    }
}
impl Drop for ScreenDc {
    fn drop(&mut self) {
        unsafe {
            ReleaseDC(None, self.0);
        }
    }
}

struct MemoryDc(HDC);
impl MemoryDc {
    fn create(source: HDC) -> Result<Self, DesktopError> {
        let dc = unsafe { CreateCompatibleDC(Some(source)) };
        if dc.0.is_null() {
            return Err(DesktopError::Gdi("CreateCompatibleDC"));
        }
        Ok(Self(dc))
    }
}
impl Drop for MemoryDc {
    fn drop(&mut self) {
        unsafe {
            let _ = DeleteDC(self.0);
        }
    }
}

struct Bitmap(HBITMAP);
impl Bitmap {
    fn create(source: HDC, width: i32, height: i32) -> Result<Self, DesktopError> {
        let bitmap = unsafe { CreateCompatibleBitmap(source, width, height) };
        if bitmap.0.is_null() {
            return Err(DesktopError::Gdi("CreateCompatibleBitmap"));
        }
        Ok(Self(bitmap))
    }
}
impl Drop for Bitmap {
    fn drop(&mut self) {
        unsafe {
            let _ = DeleteObject(HGDIOBJ(self.0.0));
        }
    }
}

struct SelectedObject {
    dc: HDC,
    old: HGDIOBJ,
}
impl Drop for SelectedObject {
    fn drop(&mut self) {
        unsafe {
            let _ = SelectObject(self.dc, self.old);
        }
    }
}

struct ComApartment;

impl ComApartment {
    fn initialize() -> Result<Self, DesktopError> {
        unsafe { CoInitializeEx(None, COINIT_MULTITHREADED).ok()? };
        Ok(Self)
    }
}

impl Drop for ComApartment {
    fn drop(&mut self) {
        unsafe { CoUninitialize() };
    }
}

#[derive(Debug, Error)]
pub enum DesktopError {
    #[error("desktop snapshot limits are invalid")]
    InvalidLimits,
    #[error("desktop execution authorization does not match the requested action")]
    AuthorizationMismatch,
    #[error("desktop action parameters are invalid")]
    InvalidActionParameters,
    #[error("desktop UI Automation target was not found")]
    TargetNotFound,
    #[error("desktop target search exceeded the node limit")]
    TargetSearchLimit,
    #[error("desktop set_value refuses password controls")]
    PasswordFieldDenied,
    #[error("desktop element is read-only")]
    ReadOnlyElement,
    #[error("virtual desktop dimensions are invalid")]
    InvalidScreenshotDimensions,
    #[error("virtual desktop screenshot exceeds the pixel limit")]
    ScreenshotTooLarge,
    #[error("Windows GDI operation failed: {0}")]
    Gdi(&'static str),
    #[error("integer conversion failed: {0}")]
    Integer(#[from] std::num::TryFromIntError),
    #[error("PNG encoding failed: {0}")]
    Png(#[from] png::EncodingError),
    #[error("Windows UI Automation failed: {0}")]
    Windows(#[from] windows::core::Error),
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use serde_json::json;
    use std::collections::BTreeMap;
    use std::process::{Child, Command};
    use std::thread::sleep;
    use std::time::Duration;
    use tempfile::tempdir;
    use vor_approval::{ApprovalChallenge, ApprovalVerifier, sign_approval};
    use vor_audit::Ledger;
    use vor_core::Broker;
    use vor_policy::PolicyEngine;
    use vor_protocol::{ActionEnvelope, ActionRequest};

    struct ChildGuard(Child);
    impl Drop for ChildGuard {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    fn spawn_lab_window() -> ChildGuard {
        let script = r#"Add-Type -AssemblyName System.Windows.Forms;
$f=New-Object System.Windows.Forms.Form; $f.Text='Vor Desktop Lab'; $f.Name='VorDesktopLab';
$t=New-Object System.Windows.Forms.TextBox; $t.Name='VorInput'; $t.AccessibleName='Vor Input'; $t.SetBounds(20,20,200,30);
$b=New-Object System.Windows.Forms.Button; $b.Name='VorButton'; $b.AccessibleName='Vor Button'; $b.Text='Go'; $b.SetBounds(20,60,80,30);
$b.Add_Click({$f.Text='Vor Clicked'}); $f.Controls.Add($t); $f.Controls.Add($b); [void]$f.ShowDialog();"#;
        ChildGuard(
            Command::new("powershell.exe")
                .args(["-NoProfile", "-STA", "-Command", script])
                .spawn()
                .unwrap(),
        )
    }

    fn wait_for_named_node(inspector: &DesktopInspector, pid: u32, name: &str) -> SemanticNode {
        for _ in 0..50 {
            if let Ok(tree) = inspector.semantic_tree(Some(6), Some(4096))
                && let Some(node) = tree.into_iter().find(|node| {
                    node.element.process_id == pid
                        && node.element.name == name
                        && !node.element.automation_id.is_empty()
                })
            {
                return node;
            }
            sleep(Duration::from_millis(100));
        }
        panic!("lab UIA node not found: {name}");
    }

    #[allow(clippy::too_many_arguments)]
    fn approved_execution(
        broker: &mut Broker,
        verifier: &ApprovalVerifier,
        signing: &SigningKey,
        action: &str,
        pid: u32,
        automation_id: &str,
        value: Option<&str>,
        tick: u64,
    ) -> vor_core::ExecutionAuthorization {
        let mut parameters = BTreeMap::new();
        parameters.insert("process_id".into(), json!(pid));
        parameters.insert("automation_id".into(), json!(automation_id));
        if let Some(value) = value {
            parameters.insert("value".into(), json!(value));
        }
        let request = ActionRequest::seal(ActionEnvelope {
            request_id: format!("desktop-{tick}-{:032x}", rand::random::<u128>()),
            organization_id: "lab".into(),
            actor_id: "lab-client".into(),
            device_id: "lab-device".into(),
            action: action.into(),
            target: "uia".into(),
            parameters,
            requested_capabilities: vec![],
            expires_at_unix_ms: 20_000,
            nonce: rand::random::<[u8; 16]>().to_vec(),
        })
        .unwrap();
        let prepared = broker.authorize_at(request.clone(), tick).unwrap();
        assert!(prepared.requires_approval());
        let challenge =
            ApprovalChallenge::issue(&request, &prepared.decision, tick, tick + 5_000).unwrap();
        let approval = sign_approval(challenge, "lab-operator", signing).unwrap();
        broker
            .consume_approval_at(request, &approval, verifier, tick + 1)
            .unwrap()
    }

    fn desktop_broker() -> (Broker, ApprovalVerifier, SigningKey, tempfile::TempDir) {
        let dir = tempdir().unwrap();
        let yaml = include_str!("../../../config/policy.example.yaml")
            .replace("enabled: false", "enabled: true");
        let policy = PolicyEngine::from_yaml_str(&yaml).unwrap();
        let ledger =
            Ledger::open(dir.path().join("audit.db"), dir.path().join("audit.jsonl")).unwrap();
        let signing = SigningKey::from_bytes(&rand::random::<[u8; 32]>());
        let mut verifier = ApprovalVerifier::new();
        verifier
            .add_approver("lab-operator", signing.verifying_key().to_bytes())
            .unwrap();
        (Broker::new(policy, ledger), verifier, signing, dir)
    }

    #[test]
    fn rejects_unbounded_tree_requests() {
        let inspector = DesktopInspector::new().unwrap();
        assert!(matches!(
            inspector.semantic_tree(Some(ABSOLUTE_MAX_DEPTH + 1), Some(1)),
            Err(DesktopError::InvalidLimits)
        ));
    }

    #[test]
    #[ignore = "mutates only a self-spawned WinForms lab window"]
    fn live_approved_uia_set_value_and_invoke() {
        let lab = spawn_lab_window();
        let pid = lab.0.id();
        let inspector = DesktopInspector::new().unwrap();
        let input = wait_for_named_node(&inspector, pid, "Vor Input");
        let button = wait_for_named_node(&inspector, pid, "Vor Button");
        let (mut broker, verifier, signing, _dir) = desktop_broker();

        let set_value = approved_execution(
            &mut broker,
            &verifier,
            &signing,
            "desktop.set_value",
            pid,
            &input.element.automation_id,
            Some("typed-vor"),
            100,
        );
        inspector.set_value(set_value).unwrap();
        let input_element = inspector
            .find_target(pid, &input.element.automation_id)
            .unwrap();
        let value_pattern: IUIAutomationValuePattern = unsafe {
            input_element
                .GetCurrentPatternAs(UIA_ValuePatternId)
                .unwrap()
        };
        assert_eq!(
            unsafe { value_pattern.CurrentValue().unwrap() }.to_string(),
            "typed-vor"
        );

        let invoke = approved_execution(
            &mut broker,
            &verifier,
            &signing,
            "desktop.invoke",
            pid,
            &button.element.automation_id,
            None,
            200,
        );
        inspector.invoke(invoke).unwrap();
        let mut clicked = false;
        for _ in 0..30 {
            clicked = inspector
                .top_level_elements()
                .unwrap()
                .iter()
                .any(|node| node.process_id == pid && node.name == "Vor Clicked");
            if clicked {
                break;
            }
            sleep(Duration::from_millis(100));
        }
        assert!(
            clicked,
            "approved UIA invoke did not update the lab window title"
        );
        drop(lab);
    }

    #[test]
    #[ignore = "requires an interactive Windows desktop"]
    fn live_virtual_desktop_screenshot_is_png() {
        let inspector = DesktopInspector::new().unwrap();
        let screenshot = inspector.capture_virtual_desktop_png().unwrap();
        assert!(screenshot.width > 0 && screenshot.height > 0);
        assert!(screenshot.png.len() > 8);
        assert_eq!(&screenshot.png[..8], b"\x89PNG\r\n\x1a\n");
    }

    #[test]
    #[ignore = "requires an interactive Windows desktop"]
    fn live_uia_snapshot_is_bounded() {
        let inspector = DesktopInspector::new().unwrap();
        let top = inspector.top_level_elements().unwrap();
        assert!(!top.is_empty());
        let tree = inspector.semantic_tree(Some(2), Some(128)).unwrap();
        assert!(!tree.is_empty());
        assert!(tree.len() <= 128);
    }
}
