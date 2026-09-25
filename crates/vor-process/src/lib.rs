// SPDX-License-Identifier: MPL-2.0

use serde::{Deserialize, Serialize};
use std::io;
use thiserror::Error;
use vor_core::{Authorization, ExecutionAuthorization};
use vor_protocol::PolicyDecisionKind;

#[cfg(windows)]
use windows_sys::Win32::Foundation::{
    CloseHandle, FILETIME, HANDLE, INVALID_HANDLE_VALUE, WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
#[cfg(windows)]
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS,
};
#[cfg(windows)]
use windows_sys::Win32::System::Threading::{
    GetProcessTimes, IsProcessCritical, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
    PROCESS_SYNCHRONIZE, PROCESS_TERMINATE, QueryFullProcessImageNameW, TerminateProcess,
    WaitForSingleObject,
};

const TERMINATE_WAIT_MS: u32 = 5_000;
const TERMINATION_EXIT_CODE: u32 = 0xC000_013A;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessInfo {
    pub pid: u32,
    pub parent_pid: u32,
    pub executable_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessIdentity {
    pub pid: u32,
    pub executable_name: String,
    pub image_path: String,
    pub created_at_windows_filetime_100ns: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessTerminateReceipt {
    pub pid: u32,
    pub executable_name: String,
    pub image_path: String,
    pub created_at_windows_filetime_100ns: u64,
    pub terminated: bool,
    pub wait_result: TerminateWaitResult,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TerminateWaitResult {
    WaitObject0,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProcessAccess {
    QueryIdentity,
    Terminate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WaitStatus {
    Object0,
    Timeout,
    Failed(u32),
    Unexpected(u32),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProcessCriticality {
    Critical,
    NotCritical,
}

trait ProcessApi {
    type Handle;

    fn list_processes(&self) -> Result<Vec<ProcessInfo>, ProcessError>;
    fn open(&self, pid: u32, access: ProcessAccess) -> Result<Self::Handle, ProcessError>;
    fn wait(&self, handle: &Self::Handle, timeout_ms: u32) -> Result<WaitStatus, ProcessError>;
    fn identity(&self, pid: u32, handle: &Self::Handle) -> Result<ProcessIdentity, ProcessError>;
    fn criticality(&self, handle: &Self::Handle) -> Result<ProcessCriticality, ProcessError>;
    fn terminate(&self, handle: &Self::Handle, exit_code: u32) -> Result<(), ProcessError>;
}

#[derive(Debug, Default)]
pub struct ProcessWorker;

impl ProcessWorker {
    pub fn list(&self, authorization: &Authorization) -> Result<Vec<ProcessInfo>, ProcessError> {
        ensure_auto_action(authorization, "process.list")?;
        NativeProcessApi.list_processes()
    }

    pub fn inspect(&self, authorization: &Authorization) -> Result<ProcessInfo, ProcessError> {
        ensure_auto_action(authorization, "process.inspect")?;
        let pid: u32 = authorization
            .request
            .envelope
            .target
            .parse()
            .map_err(|_| ProcessError::InvalidPid)?;
        self.list_unchecked()?
            .into_iter()
            .find(|process| process.pid == pid)
            .ok_or(ProcessError::NotFound(pid))
    }

    pub fn identity(&self, pid: u32) -> Result<ProcessIdentity, ProcessError> {
        identity_with_api(&NativeProcessApi, pid)
    }

    pub fn terminate_approved(
        &self,
        execution: &ExecutionAuthorization,
    ) -> Result<ProcessTerminateReceipt, ProcessError> {
        if execution.request().envelope.action != "process.terminate" {
            return Err(ProcessError::WrongAction);
        }
        let pid = parse_pid(&execution.request().envelope.target)?;
        let expected = expected_identity(execution, pid)?;
        terminate_with_api(&NativeProcessApi, expected)
    }

    fn list_unchecked(&self) -> Result<Vec<ProcessInfo>, ProcessError> {
        NativeProcessApi.list_processes()
    }
}

fn identity_with_api<Api: ProcessApi>(
    api: &Api,
    pid: u32,
) -> Result<ProcessIdentity, ProcessError> {
    let handle = api.open(pid, ProcessAccess::QueryIdentity)?;
    ensure_still_running(api, pid, &handle)?;
    api.identity(pid, &handle)
}

fn expected_identity(
    execution: &ExecutionAuthorization,
    pid: u32,
) -> Result<ProcessIdentity, ProcessError> {
    let params = &execution.request().envelope.parameters;
    let executable_name = params
        .get("executable_name")
        .and_then(|value| value.as_str())
        .ok_or(ProcessError::MissingIdentity)?
        .to_owned();
    let image_path = params
        .get("image_path")
        .and_then(|value| value.as_str())
        .ok_or(ProcessError::MissingIdentity)?
        .to_owned();
    let created_at_windows_filetime_100ns = params
        .get("created_at_windows_filetime_100ns")
        .and_then(|value| value.as_u64())
        .ok_or(ProcessError::MissingIdentity)?;
    Ok(ProcessIdentity {
        pid,
        executable_name,
        image_path,
        created_at_windows_filetime_100ns,
    })
}

fn terminate_with_api<Api: ProcessApi>(
    api: &Api,
    expected: ProcessIdentity,
) -> Result<ProcessTerminateReceipt, ProcessError> {
    if expected.pid == std::process::id() {
        return Err(ProcessError::ProtectedProcess("current_process"));
    }
    let handle = api.open(expected.pid, ProcessAccess::Terminate)?;
    ensure_still_running(api, expected.pid, &handle)?;
    let actual = api.identity(expected.pid, &handle)?;
    if actual != expected {
        return Err(ProcessError::IdentityMismatch { expected, actual });
    }
    reject_protected_identity(&actual)?;
    match api.criticality(&handle)? {
        ProcessCriticality::Critical => return Err(ProcessError::CriticalProcess(actual.pid)),
        ProcessCriticality::NotCritical => {}
    }
    api.terminate(&handle, TERMINATION_EXIT_CODE)?;
    match api.wait(&handle, TERMINATE_WAIT_MS)? {
        WaitStatus::Object0 => Ok(ProcessTerminateReceipt {
            pid: actual.pid,
            executable_name: actual.executable_name,
            image_path: actual.image_path,
            created_at_windows_filetime_100ns: actual.created_at_windows_filetime_100ns,
            terminated: true,
            wait_result: TerminateWaitResult::WaitObject0,
        }),
        WaitStatus::Timeout => Err(ProcessError::TerminationUnconfirmed {
            pid: actual.pid,
            reason: TerminationUnconfirmedReason::WaitTimeout {
                timeout_ms: TERMINATE_WAIT_MS,
            },
        }),
        WaitStatus::Failed(error_code) => Err(ProcessError::TerminationUnconfirmed {
            pid: actual.pid,
            reason: TerminationUnconfirmedReason::WaitFailed { error_code },
        }),
        WaitStatus::Unexpected(status) => Err(ProcessError::TerminationUnconfirmed {
            pid: actual.pid,
            reason: TerminationUnconfirmedReason::UnexpectedWaitStatus { status },
        }),
    }
}

fn ensure_still_running<Api: ProcessApi>(
    api: &Api,
    pid: u32,
    handle: &Api::Handle,
) -> Result<(), ProcessError> {
    match api.wait(handle, 0)? {
        WaitStatus::Object0 => Err(ProcessError::AlreadyExited(pid)),
        WaitStatus::Timeout => Ok(()),
        WaitStatus::Failed(error_code) => Err(ProcessError::WaitFailed { pid, error_code }),
        WaitStatus::Unexpected(status) => Err(ProcessError::UnexpectedWaitStatus { pid, status }),
    }
}

fn parse_pid(value: &str) -> Result<u32, ProcessError> {
    value.parse().map_err(|_| ProcessError::InvalidPid)
}

fn ensure_auto_action(authorization: &Authorization, expected: &str) -> Result<(), ProcessError> {
    if authorization.request.envelope_digest != authorization.decision.envelope_digest
        || authorization.request.envelope.request_id != authorization.decision.request_id
    {
        return Err(ProcessError::AuthorizationMismatch);
    }
    match authorization.decision.kind {
        PolicyDecisionKind::Auto => {}
        PolicyDecisionKind::Approval => return Err(ProcessError::ApprovalRequired),
        PolicyDecisionKind::Deny => return Err(ProcessError::Denied),
    }
    if authorization.request.envelope.action != expected {
        return Err(ProcessError::WrongAction);
    }
    Ok(())
}

fn reject_protected_identity(identity: &ProcessIdentity) -> Result<(), ProcessError> {
    let name = identity.executable_name.to_ascii_lowercase();
    let path = identity.image_path.to_ascii_lowercase().replace('\\', "/");
    let is_vor_component = matches!(
        name.as_str(),
        "vor-agent.exe"
            | "vor-gateway.exe"
            | "vor-control-plane.exe"
            | "vor-maintainer.exe"
            | "vor-approver.exe"
    ) || path.contains("/vor-commander/");
    if is_vor_component {
        return Err(ProcessError::ProtectedProcess("vor_control_component"));
    }
    if name == "codex.exe" || path.contains("/openai/codex/") {
        return Err(ProcessError::ProtectedProcess("control_channel_component"));
    }
    Ok(())
}

#[derive(Debug, Default)]
struct NativeProcessApi;

#[cfg(windows)]
struct Snapshot(HANDLE);

#[cfg(windows)]
impl Drop for Snapshot {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.0);
        }
    }
}

#[cfg(windows)]
struct ProcessHandle(HANDLE);

#[cfg(windows)]
impl Drop for ProcessHandle {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.0);
        }
    }
}

#[cfg(windows)]
impl ProcessApi for NativeProcessApi {
    type Handle = ProcessHandle;

    fn list_processes(&self) -> Result<Vec<ProcessInfo>, ProcessError> {
        let handle = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
        if handle == INVALID_HANDLE_VALUE {
            return Err(ProcessError::Io(io::Error::last_os_error()));
        }
        let _snapshot = Snapshot(handle);
        let mut entry = PROCESSENTRY32W {
            dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
            ..Default::default()
        };
        let mut processes = Vec::new();

        if unsafe { Process32FirstW(handle, &mut entry) } == 0 {
            return Err(ProcessError::Io(io::Error::last_os_error()));
        }
        loop {
            processes.push(ProcessInfo {
                pid: entry.th32ProcessID,
                parent_pid: entry.th32ParentProcessID,
                executable_name: wide_z_to_string(&entry.szExeFile),
            });
            entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
            if unsafe { Process32NextW(handle, &mut entry) } == 0 {
                break;
            }
        }
        processes.sort_by_key(|process| process.pid);
        Ok(processes)
    }

    fn open(&self, pid: u32, access: ProcessAccess) -> Result<Self::Handle, ProcessError> {
        let rights = match access {
            ProcessAccess::QueryIdentity => PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
            ProcessAccess::Terminate => {
                PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE | PROCESS_TERMINATE
            }
        };
        let handle = unsafe { OpenProcess(rights, 0, pid) };
        if handle.is_null() {
            return Err(ProcessError::OpenDenied {
                pid,
                source: io::Error::last_os_error(),
            });
        }
        Ok(ProcessHandle(handle))
    }

    fn wait(&self, handle: &Self::Handle, timeout_ms: u32) -> Result<WaitStatus, ProcessError> {
        let status = unsafe { WaitForSingleObject(handle.0, timeout_ms) };
        Ok(match status {
            WAIT_OBJECT_0 => WaitStatus::Object0,
            WAIT_TIMEOUT => WaitStatus::Timeout,
            WAIT_FAILED => {
                WaitStatus::Failed(io::Error::last_os_error().raw_os_error().unwrap_or(0) as u32)
            }
            other => WaitStatus::Unexpected(other),
        })
    }

    fn identity(&self, pid: u32, handle: &Self::Handle) -> Result<ProcessIdentity, ProcessError> {
        let mut buffer = vec![0u16; 32 * 1024];
        let mut len = u32::try_from(buffer.len()).map_err(|_| ProcessError::PathTooLong)?;
        let ok = unsafe { QueryFullProcessImageNameW(handle.0, 0, buffer.as_mut_ptr(), &mut len) };
        if ok == 0 {
            return Err(ProcessError::IdentityQueryFailed {
                pid,
                source: io::Error::last_os_error(),
            });
        }
        buffer.truncate(usize::try_from(len).map_err(|_| ProcessError::PathTooLong)?);
        let image_path = String::from_utf16(&buffer).map_err(|_| ProcessError::InvalidImagePath)?;
        let executable_name = std::path::Path::new(&image_path)
            .file_name()
            .and_then(|value| value.to_str())
            .ok_or(ProcessError::InvalidImagePath)?
            .to_owned();

        let mut created = FILETIME {
            dwLowDateTime: 0,
            dwHighDateTime: 0,
        };
        let mut exit = FILETIME {
            dwLowDateTime: 0,
            dwHighDateTime: 0,
        };
        let mut kernel = FILETIME {
            dwLowDateTime: 0,
            dwHighDateTime: 0,
        };
        let mut user = FILETIME {
            dwLowDateTime: 0,
            dwHighDateTime: 0,
        };
        if unsafe { GetProcessTimes(handle.0, &mut created, &mut exit, &mut kernel, &mut user) }
            == 0
        {
            return Err(ProcessError::IdentityQueryFailed {
                pid,
                source: io::Error::last_os_error(),
            });
        }

        Ok(ProcessIdentity {
            pid,
            executable_name,
            image_path,
            created_at_windows_filetime_100ns: filetime_raw(created),
        })
    }

    fn criticality(&self, handle: &Self::Handle) -> Result<ProcessCriticality, ProcessError> {
        let mut critical = 0i32;
        let ok = unsafe { IsProcessCritical(handle.0, &mut critical) };
        if ok == 0 {
            return Err(ProcessError::CriticalityUnknown(io::Error::last_os_error()));
        }
        if critical == 0 {
            Ok(ProcessCriticality::NotCritical)
        } else {
            Ok(ProcessCriticality::Critical)
        }
    }

    fn terminate(&self, handle: &Self::Handle, exit_code: u32) -> Result<(), ProcessError> {
        if unsafe { TerminateProcess(handle.0, exit_code) } == 0 {
            return Err(ProcessError::TerminateFailed(io::Error::last_os_error()));
        }
        Ok(())
    }
}

#[cfg(not(windows))]
impl ProcessApi for NativeProcessApi {
    type Handle = ();

    fn list_processes(&self) -> Result<Vec<ProcessInfo>, ProcessError> {
        Err(ProcessError::UnsupportedPlatform)
    }

    fn open(&self, pid: u32, _access: ProcessAccess) -> Result<Self::Handle, ProcessError> {
        Err(ProcessError::OpenDenied {
            pid,
            source: io::Error::from(io::ErrorKind::Unsupported),
        })
    }

    fn wait(&self, _handle: &Self::Handle, _timeout_ms: u32) -> Result<WaitStatus, ProcessError> {
        Err(ProcessError::UnsupportedPlatform)
    }

    fn identity(&self, _pid: u32, _handle: &Self::Handle) -> Result<ProcessIdentity, ProcessError> {
        Err(ProcessError::UnsupportedPlatform)
    }

    fn criticality(&self, _handle: &Self::Handle) -> Result<ProcessCriticality, ProcessError> {
        Err(ProcessError::UnsupportedPlatform)
    }

    fn terminate(&self, _handle: &Self::Handle, _exit_code: u32) -> Result<(), ProcessError> {
        Err(ProcessError::UnsupportedPlatform)
    }
}

#[cfg(windows)]
fn wide_z_to_string(value: &[u16]) -> String {
    let end = value
        .iter()
        .position(|unit| *unit == 0)
        .unwrap_or(value.len());
    String::from_utf16_lossy(&value[..end])
}

#[cfg(windows)]
fn filetime_raw(value: FILETIME) -> u64 {
    (u64::from(value.dwHighDateTime) << 32) | u64::from(value.dwLowDateTime)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TerminationUnconfirmedReason {
    WaitTimeout { timeout_ms: u32 },
    WaitFailed { error_code: u32 },
    UnexpectedWaitStatus { status: u32 },
}

#[derive(Debug, Error)]
pub enum ProcessError {
    #[error("authorization request and policy decision do not match")]
    AuthorizationMismatch,
    #[error("operation requires approval before process execution")]
    ApprovalRequired,
    #[error("operation was denied by policy")]
    Denied,
    #[error("authorization is for a different process action")]
    WrongAction,
    #[error("process target is not a valid PID")]
    InvalidPid,
    #[error("process {0} was not found")]
    NotFound(u32),
    #[error("process {0} already exited")]
    AlreadyExited(u32),
    #[error("process termination request is missing complete bound identity")]
    MissingIdentity,
    #[error("process identity changed; expected {expected:?}, actual {actual:?}")]
    IdentityMismatch {
        expected: ProcessIdentity,
        actual: ProcessIdentity,
    },
    #[error("protected process target rejected: {0}")]
    ProtectedProcess(&'static str),
    #[error("process {0} is critical and cannot be terminated")]
    CriticalProcess(u32),
    #[error("process criticality could not be determined: {0}")]
    CriticalityUnknown(io::Error),
    #[error("process termination was accepted but not confirmed for {pid}: {reason:?}")]
    TerminationUnconfirmed {
        pid: u32,
        reason: TerminationUnconfirmedReason,
    },
    #[error("process wait failed for {pid}: OS error {error_code}")]
    WaitFailed { pid: u32, error_code: u32 },
    #[error("process wait returned unexpected status for {pid}: {status}")]
    UnexpectedWaitStatus { pid: u32, status: u32 },
    #[error("process image path is invalid")]
    InvalidImagePath,
    #[error("process image path is too long")]
    PathTooLong,
    #[error("process inspection is not supported on this platform")]
    UnsupportedPlatform,
    #[error("opening process {pid} failed: {source}")]
    OpenDenied {
        pid: u32,
        #[source]
        source: io::Error,
    },
    #[error("querying identity for process {pid} failed: {source}")]
    IdentityQueryFailed {
        pid: u32,
        #[source]
        source: io::Error,
    },
    #[error("terminating process failed before effect was accepted: {0}")]
    TerminateFailed(io::Error),
    #[error("process API failed: {0}")]
    Io(#[from] io::Error),
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::sync::{Arc, Mutex};
    use vor_protocol::{ActionEnvelope, ActionRequest, PolicyDecision};

    #[derive(Debug, Clone)]
    struct FakeProcess {
        identity: ProcessIdentity,
        open_denied: bool,
        identity_error: bool,
        criticality: Result<ProcessCriticality, &'static str>,
        terminate_error: bool,
        wait_before: WaitStatus,
        wait_after: WaitStatus,
    }

    #[derive(Debug, Default)]
    struct FakeApi {
        process: Mutex<Option<FakeProcess>>,
        opens: Mutex<Vec<ProcessAccess>>,
        terminate_calls: Mutex<u32>,
    }

    impl FakeApi {
        fn with(process: FakeProcess) -> Self {
            Self {
                process: Mutex::new(Some(process)),
                opens: Mutex::new(Vec::new()),
                terminate_calls: Mutex::new(0),
            }
        }

        fn terminate_calls(&self) -> u32 {
            *self.terminate_calls.lock().unwrap()
        }
    }

    #[derive(Debug, Clone)]
    struct FakeHandle {
        process: Arc<FakeProcess>,
        terminated: Arc<Mutex<bool>>,
    }

    impl ProcessApi for FakeApi {
        type Handle = FakeHandle;

        fn list_processes(&self) -> Result<Vec<ProcessInfo>, ProcessError> {
            Ok(Vec::new())
        }

        fn open(&self, pid: u32, access: ProcessAccess) -> Result<Self::Handle, ProcessError> {
            self.opens.lock().unwrap().push(access);
            let process = self
                .process
                .lock()
                .unwrap()
                .clone()
                .ok_or(ProcessError::NotFound(pid))?;
            if process.open_denied {
                return Err(ProcessError::OpenDenied {
                    pid,
                    source: io::Error::from(io::ErrorKind::PermissionDenied),
                });
            }
            Ok(FakeHandle {
                process: Arc::new(process),
                terminated: Arc::new(Mutex::new(false)),
            })
        }

        fn wait(
            &self,
            handle: &Self::Handle,
            _timeout_ms: u32,
        ) -> Result<WaitStatus, ProcessError> {
            if *handle.terminated.lock().unwrap() {
                Ok(handle.process.wait_after)
            } else {
                Ok(handle.process.wait_before)
            }
        }

        fn identity(
            &self,
            pid: u32,
            handle: &Self::Handle,
        ) -> Result<ProcessIdentity, ProcessError> {
            if handle.process.identity_error {
                return Err(ProcessError::IdentityQueryFailed {
                    pid,
                    source: io::Error::from(io::ErrorKind::Other),
                });
            }
            Ok(handle.process.identity.clone())
        }

        fn criticality(&self, handle: &Self::Handle) -> Result<ProcessCriticality, ProcessError> {
            handle.process.criticality.map_err(|_| {
                ProcessError::CriticalityUnknown(io::Error::from(io::ErrorKind::Other))
            })
        }

        fn terminate(&self, _handle: &Self::Handle, _exit_code: u32) -> Result<(), ProcessError> {
            *self.terminate_calls.lock().unwrap() += 1;
            if _handle.process.terminate_error {
                return Err(ProcessError::TerminateFailed(io::Error::from(
                    io::ErrorKind::PermissionDenied,
                )));
            }
            *_handle.terminated.lock().unwrap() = true;
            Ok(())
        }
    }

    fn authorization(action: &str, target: &str) -> Authorization {
        let request = ActionRequest::seal(ActionEnvelope {
            request_id: format!("req-{action}-{target}"),
            organization_id: "org-1".into(),
            actor_id: "actor-1".into(),
            device_id: "device-1".into(),
            action: action.into(),
            target: target.into(),
            parameters: BTreeMap::new(),
            requested_capabilities: vec![],
            expires_at_unix_ms: u64::MAX,
            nonce: vec![5; 16],
        })
        .unwrap();
        let decision = PolicyDecision {
            request_id: request.envelope.request_id.clone(),
            kind: PolicyDecisionKind::Auto,
            policy_id: "test".into(),
            reason_code: "test_auto".into(),
            required_capability: None,
            envelope_digest: request.envelope_digest,
        };
        Authorization { request, decision }
    }

    fn identity(pid: u32) -> ProcessIdentity {
        ProcessIdentity {
            pid,
            executable_name: "lab-target.exe".into(),
            image_path: "C:\\lab\\lab-target.exe".into(),
            created_at_windows_filetime_100ns: 133_456_789_000_000_001,
        }
    }

    fn fake_process(identity: ProcessIdentity) -> FakeProcess {
        FakeProcess {
            identity,
            open_denied: false,
            identity_error: false,
            criticality: Ok(ProcessCriticality::NotCritical),
            terminate_error: false,
            wait_before: WaitStatus::Timeout,
            wait_after: WaitStatus::Object0,
        }
    }

    #[test]
    fn list_contains_current_process() {
        let worker = ProcessWorker;
        let processes = worker
            .list(&authorization("process.list", "local"))
            .unwrap();
        assert!(
            processes
                .iter()
                .any(|process| process.pid == std::process::id())
        );
    }

    #[test]
    fn inspect_finds_current_process() {
        let worker = ProcessWorker;
        let pid = std::process::id();
        let process = worker
            .inspect(&authorization("process.inspect", &pid.to_string()))
            .unwrap();
        assert_eq!(process.pid, pid);
        assert!(!process.executable_name.is_empty());
    }

    #[test]
    fn approval_decision_is_not_execution_authority() {
        let worker = ProcessWorker;
        let mut auth = authorization("process.list", "local");
        auth.decision.kind = PolicyDecisionKind::Approval;
        assert!(matches!(
            worker.list(&auth),
            Err(ProcessError::ApprovalRequired)
        ));
    }

    #[test]
    fn identity_query_uses_query_rights_only() {
        let api = FakeApi::with(fake_process(identity(42)));
        let result = identity_with_api(&api, 42).unwrap();
        assert_eq!(result.pid, 42);
        assert_eq!(
            *api.opens.lock().unwrap(),
            vec![ProcessAccess::QueryIdentity]
        );
        assert_eq!(api.terminate_calls(), 0);
    }

    #[test]
    fn open_process_denied_is_pre_effect_rejection() {
        let mut process = fake_process(identity(42));
        process.open_denied = true;
        let api = FakeApi::with(process);
        let result = terminate_with_api(&api, identity(42));
        assert!(matches!(result, Err(ProcessError::OpenDenied { .. })));
        assert_eq!(api.terminate_calls(), 0);
    }

    #[test]
    fn identity_query_failed_is_pre_effect_rejection() {
        let mut process = fake_process(identity(42));
        process.identity_error = true;
        let api = FakeApi::with(process);
        let result = terminate_with_api(&api, identity(42));
        assert!(matches!(
            result,
            Err(ProcessError::IdentityQueryFailed { .. })
        ));
        assert_eq!(api.terminate_calls(), 0);
    }

    #[test]
    fn critical_process_is_rejected_before_terminate() {
        let mut process = fake_process(identity(42));
        process.criticality = Ok(ProcessCriticality::Critical);
        let api = FakeApi::with(process);
        let result = terminate_with_api(&api, identity(42));
        assert!(matches!(result, Err(ProcessError::CriticalProcess(42))));
        assert_eq!(api.terminate_calls(), 0);
    }

    #[test]
    fn criticality_query_failed_is_rejected_before_terminate() {
        let mut process = fake_process(identity(42));
        process.criticality = Err("criticality-failed");
        let api = FakeApi::with(process);
        let result = terminate_with_api(&api, identity(42));
        assert!(matches!(result, Err(ProcessError::CriticalityUnknown(_))));
        assert_eq!(api.terminate_calls(), 0);
    }

    #[test]
    fn same_millisecond_native_creation_mismatch_is_rejected() {
        let actual = identity(42);
        let mut expected = actual.clone();
        expected.created_at_windows_filetime_100ns = actual.created_at_windows_filetime_100ns + 1;
        assert_ne!(
            actual.created_at_windows_filetime_100ns,
            expected.created_at_windows_filetime_100ns
        );
        assert_eq!(
            actual.created_at_windows_filetime_100ns / 10_000,
            expected.created_at_windows_filetime_100ns / 10_000
        );
        let api = FakeApi::with(fake_process(actual));
        let result = terminate_with_api(&api, expected);
        assert!(matches!(result, Err(ProcessError::IdentityMismatch { .. })));
        assert_eq!(api.terminate_calls(), 0);
    }

    #[test]
    fn terminate_process_failed_is_pre_confirmation_failure() {
        let mut process = fake_process(identity(42));
        process.terminate_error = true;
        let api = FakeApi::with(process);
        let result = terminate_with_api(&api, identity(42));
        assert!(matches!(result, Err(ProcessError::TerminateFailed(_))));
        assert_eq!(api.terminate_calls(), 1);
    }

    #[test]
    fn wait_timeout_after_terminate_is_unconfirmed_without_receipt() {
        let mut process = fake_process(identity(42));
        process.wait_after = WaitStatus::Timeout;
        let api = FakeApi::with(process);
        let result = terminate_with_api(&api, identity(42));
        assert!(matches!(
            result,
            Err(ProcessError::TerminationUnconfirmed {
                reason: TerminationUnconfirmedReason::WaitTimeout { .. },
                ..
            })
        ));
        assert_eq!(api.terminate_calls(), 1);
    }

    #[test]
    fn wait_failed_after_terminate_is_unconfirmed_without_receipt() {
        let mut process = fake_process(identity(42));
        process.wait_after = WaitStatus::Failed(6);
        let api = FakeApi::with(process);
        let result = terminate_with_api(&api, identity(42));
        assert!(matches!(
            result,
            Err(ProcessError::TerminationUnconfirmed {
                reason: TerminationUnconfirmedReason::WaitFailed { error_code: 6 },
                ..
            })
        ));
        assert_eq!(api.terminate_calls(), 1);
    }

    #[test]
    fn unexpected_wait_after_terminate_is_unconfirmed_without_receipt() {
        let mut process = fake_process(identity(42));
        process.wait_after = WaitStatus::Unexpected(123);
        let api = FakeApi::with(process);
        let result = terminate_with_api(&api, identity(42));
        assert!(matches!(
            result,
            Err(ProcessError::TerminationUnconfirmed {
                reason: TerminationUnconfirmedReason::UnexpectedWaitStatus { status: 123 },
                ..
            })
        ));
        assert_eq!(api.terminate_calls(), 1);
    }

    #[test]
    fn exited_between_open_and_validation_is_rejected_before_terminate() {
        let mut process = fake_process(identity(42));
        process.wait_before = WaitStatus::Object0;
        let api = FakeApi::with(process);
        let result = terminate_with_api(&api, identity(42));
        assert!(matches!(result, Err(ProcessError::AlreadyExited(42))));
        assert_eq!(api.terminate_calls(), 0);
    }

    #[test]
    fn control_channel_identity_is_rejected_before_terminate() {
        let mut protected = identity(42);
        protected.executable_name = "codex.exe".into();
        protected.image_path = "C:\\Tools\\Codex\\codex.exe".into();
        let api = FakeApi::with(fake_process(protected.clone()));
        let result = terminate_with_api(&api, protected);
        assert!(matches!(
            result,
            Err(ProcessError::ProtectedProcess("control_channel_component"))
        ));
        assert_eq!(api.terminate_calls(), 0);
    }
}
