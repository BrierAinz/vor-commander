// SPDX-License-Identifier: MPL-2.0

use std::collections::HashMap;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};
use std::thread;
#[cfg(windows)]
use std::time::{Duration, Instant};
use thiserror::Error;

#[cfg(windows)]
use std::ffi::{OsStr, OsString, c_void};
#[cfg(windows)]
use std::os::windows::ffi::{OsStrExt, OsStringExt};
#[cfg(windows)]
use std::ptr::{null, null_mut};
#[cfg(windows)]
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, STILL_ACTIVE};
#[cfg(windows)]
use windows_sys::Win32::Storage::FileSystem::{ReadFile, WriteFile};
#[cfg(windows)]
use windows_sys::Win32::System::Console::{
    COORD, ClosePseudoConsole, CreatePseudoConsole, HPCON, ResizePseudoConsole,
};
#[cfg(windows)]
use windows_sys::Win32::System::Pipes::{CreatePipe, PeekNamedPipe};
#[cfg(windows)]
use windows_sys::Win32::System::Threading::{
    CreateProcessW, DeleteProcThreadAttributeList, EXTENDED_STARTUPINFO_PRESENT,
    GetExitCodeProcess, InitializeProcThreadAttributeList, LPPROC_THREAD_ATTRIBUTE_LIST,
    PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE, PROCESS_INFORMATION, STARTF_USESTDHANDLES, STARTUPINFOEXW,
    TerminateProcess, UpdateProcThreadAttribute,
};

#[cfg(windows)]
const READ_CHUNK: usize = 64 * 1024;

#[cfg(windows)]
struct OwnedHandle(HANDLE);

#[cfg(windows)]
impl OwnedHandle {
    fn raw(&self) -> HANDLE {
        self.0
    }
}

#[cfg(windows)]
impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
}

#[cfg(windows)]
struct PseudoConsole(HPCON);

#[cfg(windows)]
impl Drop for PseudoConsole {
    fn drop(&mut self) {
        if self.0 != 0 {
            unsafe {
                ClosePseudoConsole(self.0);
            }
        }
    }
}

#[cfg(windows)]
struct AttributeList {
    _storage: Vec<usize>,
    ptr: LPPROC_THREAD_ATTRIBUTE_LIST,
}

#[cfg(windows)]
impl AttributeList {
    fn new() -> Result<Self, TerminalError> {
        let mut bytes = 0usize;
        unsafe {
            InitializeProcThreadAttributeList(null_mut(), 1, 0, &mut bytes);
        }
        if bytes == 0 {
            return Err(TerminalError::Io(io::Error::last_os_error()));
        }
        let words = bytes.div_ceil(std::mem::size_of::<usize>());
        let mut storage = vec![0usize; words];
        let ptr = storage.as_mut_ptr().cast::<c_void>();
        if unsafe { InitializeProcThreadAttributeList(ptr, 1, 0, &mut bytes) } == 0 {
            return Err(TerminalError::Io(io::Error::last_os_error()));
        }
        Ok(Self {
            _storage: storage,
            ptr,
        })
    }

    fn attach_pseudoconsole(&mut self, hpcon: HPCON) -> Result<(), TerminalError> {
        let result = unsafe {
            UpdateProcThreadAttribute(
                self.ptr,
                0,
                PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE as usize,
                hpcon as *const c_void,
                std::mem::size_of::<HPCON>(),
                null_mut(),
                null(),
            )
        };
        if result == 0 {
            return Err(TerminalError::Io(io::Error::last_os_error()));
        }
        Ok(())
    }
}

#[cfg(windows)]
impl Drop for AttributeList {
    fn drop(&mut self) {
        unsafe {
            DeleteProcThreadAttributeList(self.ptr);
        }
    }
}

#[cfg(windows)]
fn create_pipe() -> Result<(OwnedHandle, OwnedHandle), TerminalError> {
    let mut read = null_mut();
    let mut write = null_mut();
    if unsafe { CreatePipe(&mut read, &mut write, null(), 0) } == 0 {
        return Err(TerminalError::Io(io::Error::last_os_error()));
    }
    Ok((OwnedHandle(read), OwnedHandle(write)))
}

#[cfg(windows)]
pub struct ConPtySession {
    input_write: OwnedHandle,
    output_read: OwnedHandle,
    process: OwnedHandle,
    pseudo: PseudoConsole,
    pid: u32,
}

#[cfg(windows)]
impl ConPtySession {
    pub fn spawn(
        command_line: &str,
        current_directory: Option<&Path>,
        columns: u16,
        rows: u16,
    ) -> Result<Self, TerminalError> {
        if command_line.trim().is_empty() {
            return Err(TerminalError::EmptyCommand);
        }
        let size = checked_coord(columns, rows)?;
        let (input_read, input_write) = create_pipe()?;
        let (output_read, output_write) = create_pipe()?;

        let mut hpcon: HPCON = 0;
        let result = unsafe {
            CreatePseudoConsole(size, input_read.raw(), output_write.raw(), 0, &mut hpcon)
        };
        if result < 0 {
            return Err(TerminalError::Hresult {
                operation: "CreatePseudoConsole",
                code: result,
            });
        }
        let pseudo = PseudoConsole(hpcon);

        let mut attributes = AttributeList::new()?;
        attributes.attach_pseudoconsole(hpcon)?;
        let mut startup = STARTUPINFOEXW::default();
        startup.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
        startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
        startup.lpAttributeList = attributes.ptr;

        let mut command = wide_nul(command_line)?;
        let current_directory = current_directory.map(path_wide_nul).transpose()?;
        let current_directory_ptr = current_directory
            .as_ref()
            .map_or(null(), |value| value.as_ptr());
        let mut process_info = PROCESS_INFORMATION::default();

        let created = unsafe {
            CreateProcessW(
                null(),
                command.as_mut_ptr(),
                null(),
                null(),
                0,
                EXTENDED_STARTUPINFO_PRESENT,
                null(),
                current_directory_ptr,
                &startup.StartupInfo,
                &mut process_info,
            )
        };
        if created == 0 {
            return Err(TerminalError::Io(io::Error::last_os_error()));
        }
        let process = OwnedHandle(process_info.hProcess);
        if !process_info.hThread.is_null() {
            unsafe {
                CloseHandle(process_info.hThread);
            }
        }
        drop(input_read);
        drop(output_write);

        Ok(Self {
            input_write,
            output_read,
            process,
            pseudo,
            pid: process_info.dwProcessId,
        })
    }

    pub fn pid(&self) -> u32 {
        self.pid
    }

    pub fn write_input(&self, data: &[u8]) -> Result<usize, TerminalError> {
        let mut offset = 0usize;
        while offset < data.len() {
            let remaining = data.len() - offset;
            let chunk = remaining.min(u32::MAX as usize);
            let mut written = 0u32;
            let ok = unsafe {
                WriteFile(
                    self.input_write.raw(),
                    data[offset..offset + chunk].as_ptr(),
                    chunk as u32,
                    &mut written,
                    null_mut(),
                )
            };
            if ok == 0 {
                return Err(TerminalError::Io(io::Error::last_os_error()));
            }
            if written == 0 {
                return Err(TerminalError::ZeroLengthWrite);
            }
            offset += written as usize;
        }
        Ok(offset)
    }

    pub fn read_available(&self) -> Result<Vec<u8>, TerminalError> {
        let mut available = 0u32;
        let ok = unsafe {
            PeekNamedPipe(
                self.output_read.raw(),
                null_mut(),
                0,
                null_mut(),
                &mut available,
                null_mut(),
            )
        };
        if ok == 0 {
            let error = io::Error::last_os_error();
            if is_broken_pipe(&error) {
                return Ok(Vec::new());
            }
            return Err(TerminalError::Io(error));
        }
        if available == 0 {
            return Ok(Vec::new());
        }
        let requested = available.min(READ_CHUNK as u32);
        let mut buffer = vec![0u8; requested as usize];
        let mut read = 0u32;
        let ok = unsafe {
            ReadFile(
                self.output_read.raw(),
                buffer.as_mut_ptr(),
                requested,
                &mut read,
                null_mut(),
            )
        };
        if ok == 0 {
            let error = io::Error::last_os_error();
            if is_broken_pipe(&error) {
                return Ok(Vec::new());
            }
            return Err(TerminalError::Io(error));
        }
        buffer.truncate(read as usize);
        Ok(buffer)
    }

    pub fn resize(&self, columns: u16, rows: u16) -> Result<(), TerminalError> {
        let size = checked_coord(columns, rows)?;
        let result = unsafe { ResizePseudoConsole(self.pseudo.0, size) };
        if result < 0 {
            return Err(TerminalError::Hresult {
                operation: "ResizePseudoConsole",
                code: result,
            });
        }
        Ok(())
    }

    pub fn exit_code(&self) -> Result<Option<u32>, TerminalError> {
        let mut code = 0u32;
        if unsafe { GetExitCodeProcess(self.process.raw(), &mut code) } == 0 {
            return Err(TerminalError::Io(io::Error::last_os_error()));
        }
        if code == STILL_ACTIVE as u32 {
            Ok(None)
        } else {
            Ok(Some(code))
        }
    }

    pub fn terminate(&self, exit_code: u32) -> Result<(), TerminalError> {
        if self.exit_code()?.is_some() {
            return Ok(());
        }
        if unsafe { TerminateProcess(self.process.raw(), exit_code) } == 0 {
            return Err(TerminalError::Io(io::Error::last_os_error()));
        }
        Ok(())
    }
}

#[cfg(windows)]
fn checked_coord(columns: u16, rows: u16) -> Result<COORD, TerminalError> {
    if columns == 0 || rows == 0 || columns > i16::MAX as u16 || rows > i16::MAX as u16 {
        return Err(TerminalError::InvalidDimensions);
    }
    Ok(COORD {
        X: columns as i16,
        Y: rows as i16,
    })
}

#[cfg(windows)]
fn wide_nul(value: &str) -> Result<Vec<u16>, TerminalError> {
    wide_os_nul(OsStr::new(value))
}

#[cfg(windows)]
fn path_wide_nul(value: &Path) -> Result<Vec<u16>, TerminalError> {
    wide_os_nul(value.as_os_str())
}

#[cfg(windows)]
fn wide_os_nul(value: &OsStr) -> Result<Vec<u16>, TerminalError> {
    let mut encoded: Vec<u16> = value.encode_wide().collect();
    if encoded.contains(&0) {
        return Err(TerminalError::InteriorNul);
    }
    encoded.push(0);
    Ok(encoded)
}

#[cfg(windows)]
fn is_broken_pipe(error: &io::Error) -> bool {
    matches!(error.raw_os_error(), Some(109 | 232 | 233))
}

#[cfg(not(windows))]
pub struct ConPtySession;

#[cfg(not(windows))]
impl ConPtySession {
    pub fn spawn(
        _command_line: &str,
        _current_directory: Option<&Path>,
        _columns: u16,
        _rows: u16,
    ) -> Result<Self, TerminalError> {
        Err(TerminalError::UnsupportedPlatform)
    }
}

pub const DEFAULT_REMOTE_TERMINAL_TIMEOUT_MS: u64 = 30_000;
pub const MAX_REMOTE_TERMINAL_TIMEOUT_MS: u64 = 120_000;
pub const DEFAULT_REMOTE_TERMINAL_OUTPUT_BYTES: usize = 256 * 1024;
pub const MAX_REMOTE_TERMINAL_OUTPUT_BYTES: usize = 1024 * 1024;
pub const MAX_REMOTE_TERMINAL_ARGC: usize = 128;
pub const MAX_REMOTE_TERMINAL_ARG_BYTES: usize = 32 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TerminalLimits {
    pub max_timeout_ms: u64,
    pub max_output_bytes: usize,
    pub max_argc: usize,
    pub max_arg_bytes: usize,
    pub max_columns: u16,
    pub max_rows: u16,
}

impl Default for TerminalLimits {
    fn default() -> Self {
        Self {
            max_timeout_ms: MAX_REMOTE_TERMINAL_TIMEOUT_MS,
            max_output_bytes: MAX_REMOTE_TERMINAL_OUTPUT_BYTES,
            max_argc: MAX_REMOTE_TERMINAL_ARGC,
            max_arg_bytes: MAX_REMOTE_TERMINAL_ARG_BYTES,
            max_columns: 240,
            max_rows: 120,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TerminalSpec {
    pub argv: Vec<String>,
    pub cwd: PathBuf,
    pub timeout_ms: u64,
    pub max_output_bytes: usize,
    pub columns: u16,
    pub rows: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TerminalRunResult {
    pub exit_code: u32,
    pub output: Vec<u8>,
}

#[derive(Debug, Clone, Default)]
pub struct CancellationFlag(Arc<AtomicBool>);

impl CancellationFlag {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn cancel(&self) {
        self.0.store(true, Ordering::SeqCst);
    }

    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }
}

#[derive(Debug, Clone)]
pub struct BoundedTerminal {
    allowed_roots: Vec<PathBuf>,
    limits: TerminalLimits,
}

impl BoundedTerminal {
    pub fn new(
        allowed_roots: impl IntoIterator<Item = PathBuf>,
        limits: TerminalLimits,
    ) -> Result<Self, TerminalError> {
        if limits.max_timeout_ms == 0
            || limits.max_output_bytes == 0
            || limits.max_argc == 0
            || limits.max_arg_bytes == 0
            || limits.max_columns == 0
            || limits.max_rows == 0
        {
            return Err(TerminalError::InvalidLimits);
        }

        let mut canonical_roots = Vec::new();
        for root in allowed_roots {
            let canonical = std::fs::canonicalize(root)?;
            if !canonical_roots
                .iter()
                .any(|existing| existing == &canonical)
            {
                canonical_roots.push(canonical);
            }
        }
        if canonical_roots.is_empty() {
            return Err(TerminalError::NoAllowedRoots);
        }

        Ok(Self {
            allowed_roots: canonical_roots,
            limits,
        })
    }

    pub fn limits(&self) -> TerminalLimits {
        self.limits
    }

    fn prepare(&self, spec: &TerminalSpec) -> Result<(String, PathBuf), TerminalError> {
        if spec.argv.is_empty() || spec.argv[0].trim().is_empty() {
            return Err(TerminalError::EmptyArguments);
        }
        if spec.argv.len() > self.limits.max_argc {
            return Err(TerminalError::ArgumentCountExceeded {
                requested: spec.argv.len(),
                limit: self.limits.max_argc,
            });
        }

        let mut total_arg_bytes = 0usize;
        for arg in &spec.argv {
            if arg.contains('\0') {
                return Err(TerminalError::InteriorNul);
            }
            total_arg_bytes = total_arg_bytes.checked_add(arg.len()).ok_or(
                TerminalError::ArgumentBytesExceeded {
                    requested: usize::MAX,
                    limit: self.limits.max_arg_bytes,
                },
            )?;
        }
        if total_arg_bytes > self.limits.max_arg_bytes {
            return Err(TerminalError::ArgumentBytesExceeded {
                requested: total_arg_bytes,
                limit: self.limits.max_arg_bytes,
            });
        }

        if spec.timeout_ms == 0 || spec.timeout_ms > self.limits.max_timeout_ms {
            return Err(TerminalError::InvalidTimeout {
                requested_ms: spec.timeout_ms,
                limit_ms: self.limits.max_timeout_ms,
            });
        }
        if spec.max_output_bytes == 0 || spec.max_output_bytes > self.limits.max_output_bytes {
            return Err(TerminalError::InvalidOutputLimit {
                requested: spec.max_output_bytes,
                limit: self.limits.max_output_bytes,
            });
        }
        if spec.columns == 0
            || spec.rows == 0
            || spec.columns > self.limits.max_columns
            || spec.rows > self.limits.max_rows
        {
            return Err(TerminalError::InvalidDimensions);
        }

        let cwd = std::fs::canonicalize(&spec.cwd)?;
        if !self.allowed_roots.iter().any(|root| cwd.starts_with(root)) {
            return Err(TerminalError::CwdOutsideAllowedRoots);
        }
        let process_cwd = process_cwd_path(&cwd)?;

        Ok((argv_to_windows_command_line(&spec.argv)?, process_cwd))
    }

    #[cfg(windows)]
    pub fn run(
        &self,
        spec: &TerminalSpec,
        cancellation: &CancellationFlag,
    ) -> Result<TerminalRunResult, TerminalError> {
        let (command_line, cwd) = self.prepare(spec)?;
        if cancellation.is_cancelled() {
            return Err(TerminalError::Cancelled);
        }

        let session = ConPtySession::spawn(&command_line, Some(&cwd), spec.columns, spec.rows)?;
        let started = Instant::now();
        let timeout = Duration::from_millis(spec.timeout_ms);
        let mut output = Vec::new();

        loop {
            if cancellation.is_cancelled() {
                session.terminate(0xC000_013A)?;
                return Err(TerminalError::Cancelled);
            }
            if started.elapsed() >= timeout {
                session.terminate(0x0000_05B4)?;
                return Err(TerminalError::Timeout {
                    timeout_ms: spec.timeout_ms,
                });
            }

            let chunk = session.read_available()?;
            append_output(&mut output, &chunk, spec.max_output_bytes, &session)?;

            if let Some(exit_code) = session.exit_code()? {
                drain_output(&session, &mut output, spec.max_output_bytes)?;
                return Ok(TerminalRunResult { exit_code, output });
            }
            thread::sleep(Duration::from_millis(10));
        }
    }

    #[cfg(not(windows))]
    pub fn run(
        &self,
        spec: &TerminalSpec,
        cancellation: &CancellationFlag,
    ) -> Result<TerminalRunResult, TerminalError> {
        let _ = self.prepare(spec)?;
        if cancellation.is_cancelled() {
            return Err(TerminalError::Cancelled);
        }
        Err(TerminalError::UnsupportedPlatform)
    }
}

pub const DEFAULT_MAX_REMOTE_TERMINAL_SESSIONS: usize = 4;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TerminalSessionOwner {
    pub organization_id: String,
    pub actor_id: String,
    pub device_id: String,
    pub workspace_id: Option<String>,
}

impl TerminalSessionOwner {
    pub fn new(
        organization_id: impl Into<String>,
        actor_id: impl Into<String>,
        device_id: impl Into<String>,
    ) -> Result<Self, TerminalError> {
        Self::with_workspace(organization_id, actor_id, device_id, None::<String>)
    }

    pub fn with_workspace(
        organization_id: impl Into<String>,
        actor_id: impl Into<String>,
        device_id: impl Into<String>,
        workspace_id: Option<impl Into<String>>,
    ) -> Result<Self, TerminalError> {
        let owner = Self {
            organization_id: organization_id.into(),
            actor_id: actor_id.into(),
            device_id: device_id.into(),
            workspace_id: workspace_id.map(Into::into),
        };
        if owner.organization_id.trim().is_empty()
            || owner.actor_id.trim().is_empty()
            || owner.device_id.trim().is_empty()
            || owner
                .workspace_id
                .as_deref()
                .is_some_and(|workspace_id| workspace_id.trim().is_empty())
        {
            return Err(TerminalError::InvalidSessionOwner);
        }
        Ok(owner)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TerminalSessionState {
    Running,
    Completed,
    Cancelled,
    TimedOut,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TerminalSessionSnapshot {
    pub session_id: String,
    pub state: TerminalSessionState,
    pub exit_code: Option<u32>,
    pub output: Vec<u8>,
    pub error_code: Option<&'static str>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TerminalSessionFailure {
    state: TerminalSessionState,
    error_code: &'static str,
}

impl TerminalSessionFailure {
    fn from_error(error: &TerminalError) -> Self {
        match error {
            TerminalError::Cancelled => Self {
                state: TerminalSessionState::Cancelled,
                error_code: "terminal_cancelled",
            },
            TerminalError::Timeout { .. } => Self {
                state: TerminalSessionState::TimedOut,
                error_code: "terminal_timeout",
            },
            TerminalError::OutputLimitExceeded { .. } => Self {
                state: TerminalSessionState::Failed,
                error_code: "terminal_output_limit_exceeded",
            },
            _ => Self {
                state: TerminalSessionState::Failed,
                error_code: "terminal_error",
            },
        }
    }
}

#[derive(Debug, Clone)]
enum ManagedTerminalState {
    Running,
    Finished(Result<TerminalRunResult, TerminalSessionFailure>),
}

#[derive(Debug, Clone)]
struct ManagedTerminalSession {
    owner: TerminalSessionOwner,
    cancellation: CancellationFlag,
    state: Arc<Mutex<ManagedTerminalState>>,
}

#[derive(Debug, Clone)]
pub struct TerminalSessionManager {
    terminal: BoundedTerminal,
    sessions: Arc<Mutex<HashMap<String, ManagedTerminalSession>>>,
    max_sessions: usize,
}

impl TerminalSessionManager {
    pub fn new(terminal: BoundedTerminal, max_sessions: usize) -> Result<Self, TerminalError> {
        if max_sessions == 0 {
            return Err(TerminalError::InvalidSessionLimit);
        }
        Ok(Self {
            terminal,
            sessions: Arc::new(Mutex::new(HashMap::new())),
            max_sessions,
        })
    }

    pub fn start(
        &self,
        owner: TerminalSessionOwner,
        spec: TerminalSpec,
    ) -> Result<String, TerminalError> {
        if owner.organization_id.trim().is_empty()
            || owner.actor_id.trim().is_empty()
            || owner.device_id.trim().is_empty()
            || owner
                .workspace_id
                .as_deref()
                .is_some_and(|workspace_id| workspace_id.trim().is_empty())
        {
            return Err(TerminalError::InvalidSessionOwner);
        }
        let _ = self.terminal.prepare(&spec)?;
        let mut sessions = self
            .sessions
            .lock()
            .map_err(|_| TerminalError::SessionRegistryUnavailable)?;
        if sessions.len() >= self.max_sessions {
            return Err(TerminalError::SessionLimitExceeded {
                limit: self.max_sessions,
            });
        }

        let session_id = (0..16)
            .map(|_| format!("{:032x}", rand::random::<u128>()))
            .find(|candidate| !sessions.contains_key(candidate))
            .ok_or(TerminalError::SessionIdExhausted)?;

        let cancellation = CancellationFlag::new();
        let state = Arc::new(Mutex::new(ManagedTerminalState::Running));
        sessions.insert(
            session_id.clone(),
            ManagedTerminalSession {
                owner,
                cancellation: cancellation.clone(),
                state: state.clone(),
            },
        );
        drop(sessions);

        let terminal = self.terminal.clone();
        let thread_session_id = session_id.clone();
        let spawn = thread::Builder::new()
            .name(format!("vor-terminal-{thread_session_id}"))
            .spawn(move || {
                let outcome = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    terminal.run(&spec, &cancellation)
                })) {
                    Ok(result) => {
                        result.map_err(|error| TerminalSessionFailure::from_error(&error))
                    }
                    Err(_) => Err(TerminalSessionFailure {
                        state: TerminalSessionState::Failed,
                        error_code: "terminal_worker_panicked",
                    }),
                };
                if let Ok(mut current) = state.lock() {
                    *current = ManagedTerminalState::Finished(outcome);
                }
            });

        if let Err(error) = spawn {
            if let Ok(mut sessions) = self.sessions.lock() {
                sessions.remove(&session_id);
            }
            return Err(TerminalError::Io(error));
        }

        Ok(session_id)
    }

    pub fn poll(
        &self,
        session_id: &str,
        owner: &TerminalSessionOwner,
    ) -> Result<TerminalSessionSnapshot, TerminalError> {
        let managed = self.session(session_id, owner)?;
        let state = managed
            .state
            .lock()
            .map_err(|_| TerminalError::SessionRegistryUnavailable)?
            .clone();
        Ok(session_snapshot(session_id, state))
    }

    pub fn cancel(
        &self,
        session_id: &str,
        owner: &TerminalSessionOwner,
    ) -> Result<bool, TerminalError> {
        let managed = self.session(session_id, owner)?;
        let running = matches!(
            *managed
                .state
                .lock()
                .map_err(|_| TerminalError::SessionRegistryUnavailable)?,
            ManagedTerminalState::Running
        );
        if running {
            managed.cancellation.cancel();
        }
        Ok(running)
    }

    pub fn remove(
        &self,
        session_id: &str,
        owner: &TerminalSessionOwner,
    ) -> Result<TerminalSessionSnapshot, TerminalError> {
        let managed = self.session(session_id, owner)?;
        let state = managed
            .state
            .lock()
            .map_err(|_| TerminalError::SessionRegistryUnavailable)?
            .clone();
        if matches!(state, ManagedTerminalState::Running) {
            return Err(TerminalError::SessionStillRunning);
        }
        let snapshot = session_snapshot(session_id, state);
        self.sessions
            .lock()
            .map_err(|_| TerminalError::SessionRegistryUnavailable)?
            .remove(session_id);
        Ok(snapshot)
    }

    pub fn session_count(&self) -> Result<usize, TerminalError> {
        Ok(self
            .sessions
            .lock()
            .map_err(|_| TerminalError::SessionRegistryUnavailable)?
            .len())
    }

    fn session(
        &self,
        session_id: &str,
        owner: &TerminalSessionOwner,
    ) -> Result<ManagedTerminalSession, TerminalError> {
        let sessions = self
            .sessions
            .lock()
            .map_err(|_| TerminalError::SessionRegistryUnavailable)?;
        let managed = sessions
            .get(session_id)
            .cloned()
            .ok_or(TerminalError::SessionNotFound)?;
        if &managed.owner != owner {
            return Err(TerminalError::SessionOwnerMismatch);
        }
        Ok(managed)
    }
}

fn session_snapshot(session_id: &str, state: ManagedTerminalState) -> TerminalSessionSnapshot {
    match state {
        ManagedTerminalState::Running => TerminalSessionSnapshot {
            session_id: session_id.to_owned(),
            state: TerminalSessionState::Running,
            exit_code: None,
            output: Vec::new(),
            error_code: None,
        },
        ManagedTerminalState::Finished(Ok(result)) => TerminalSessionSnapshot {
            session_id: session_id.to_owned(),
            state: TerminalSessionState::Completed,
            exit_code: Some(result.exit_code),
            output: result.output,
            error_code: None,
        },
        ManagedTerminalState::Finished(Err(failure)) => TerminalSessionSnapshot {
            session_id: session_id.to_owned(),
            state: failure.state,
            exit_code: None,
            output: Vec::new(),
            error_code: Some(failure.error_code),
        },
    }
}

#[cfg(windows)]
fn append_output(
    output: &mut Vec<u8>,
    chunk: &[u8],
    limit: usize,
    session: &ConPtySession,
) -> Result<(), TerminalError> {
    let requested = output
        .len()
        .checked_add(chunk.len())
        .ok_or(TerminalError::OutputLimitExceeded { limit })?;
    if requested > limit {
        session.terminate(0x0000_00EA)?;
        return Err(TerminalError::OutputLimitExceeded { limit });
    }
    output.extend_from_slice(chunk);
    Ok(())
}

#[cfg(windows)]
fn drain_output(
    session: &ConPtySession,
    output: &mut Vec<u8>,
    limit: usize,
) -> Result<(), TerminalError> {
    // ConPTY can publish the final bytes slightly after the child reports an
    // exit code. Require a short bounded quiescent window instead of treating
    // the first empty pipe read as EOF.
    let mut empty_reads = 0u8;
    for _ in 0..256 {
        let chunk = session.read_available()?;
        if chunk.is_empty() {
            empty_reads += 1;
            if empty_reads >= 5 {
                return Ok(());
            }
            thread::sleep(Duration::from_millis(5));
            continue;
        }
        empty_reads = 0;
        append_output(output, &chunk, limit, session)?;
    }
    Err(TerminalError::OutputDrainLimitExceeded)
}

#[cfg(windows)]
fn process_cwd_path(path: &Path) -> Result<PathBuf, TerminalError> {
    let wide: Vec<u16> = path.as_os_str().encode_wide().collect();
    const VERBATIM: [u16; 4] = [b'\\' as u16, b'\\' as u16, b'?' as u16, b'\\' as u16];
    if wide.starts_with(&VERBATIM) {
        if wide.get(4..8).is_some_and(|prefix| {
            matches!(prefix[0], 85 | 117)
                && matches!(prefix[1], 78 | 110)
                && matches!(prefix[2], 67 | 99)
                && prefix[3] == b'\\' as u16
        }) {
            return Err(TerminalError::UnsupportedCwd);
        }
        return Ok(PathBuf::from(OsString::from_wide(&wide[4..])));
    }
    Ok(path.to_path_buf())
}

#[cfg(not(windows))]
fn process_cwd_path(path: &Path) -> Result<PathBuf, TerminalError> {
    Ok(path.to_path_buf())
}

pub fn argv_to_windows_command_line(argv: &[String]) -> Result<String, TerminalError> {
    if argv.is_empty() || argv[0].is_empty() {
        return Err(TerminalError::EmptyArguments);
    }
    let mut encoded = Vec::with_capacity(argv.len());
    for arg in argv {
        if arg.contains('\0') {
            return Err(TerminalError::InteriorNul);
        }
        encoded.push(quote_windows_arg(arg));
    }
    Ok(encoded.join(" "))
}

fn quote_windows_arg(arg: &str) -> String {
    if arg.is_empty() {
        return "\"\"".to_owned();
    }
    if !arg.chars().any(|ch| ch.is_whitespace() || ch == '"') {
        return arg.to_owned();
    }

    let mut out = String::with_capacity(arg.len() + 2);
    out.push('"');
    let mut backslashes = 0usize;
    for ch in arg.chars() {
        if ch == '\\' {
            backslashes += 1;
            continue;
        }
        if ch == '"' {
            out.extend(std::iter::repeat_n('\\', backslashes * 2 + 1));
            out.push('"');
            backslashes = 0;
            continue;
        }
        out.extend(std::iter::repeat_n('\\', backslashes));
        backslashes = 0;
        out.push(ch);
    }
    out.extend(std::iter::repeat_n('\\', backslashes * 2));
    out.push('"');
    out
}

#[derive(Debug, Error)]
pub enum TerminalError {
    #[error("terminal limits are invalid")]
    InvalidLimits,
    #[error("terminal requires at least one allowed root")]
    NoAllowedRoots,
    #[error("terminal argv must contain a non-empty executable")]
    EmptyArguments,
    #[error("terminal argument count {requested} exceeds limit {limit}")]
    ArgumentCountExceeded { requested: usize, limit: usize },
    #[error("terminal argument bytes {requested} exceed limit {limit}")]
    ArgumentBytesExceeded { requested: usize, limit: usize },
    #[error("terminal timeout {requested_ms}ms is outside limit {limit_ms}ms")]
    InvalidTimeout { requested_ms: u64, limit_ms: u64 },
    #[error("terminal output limit {requested} is outside worker limit {limit}")]
    InvalidOutputLimit { requested: usize, limit: usize },
    #[error("terminal cwd is outside configured roots")]
    CwdOutsideAllowedRoots,
    #[error("terminal cwd uses an unsupported UNC/verbatim network form")]
    UnsupportedCwd,
    #[error("terminal execution was cancelled")]
    Cancelled,
    #[error("terminal execution exceeded timeout {timeout_ms}ms")]
    Timeout { timeout_ms: u64 },
    #[error("terminal output exceeded limit {limit}")]
    OutputLimitExceeded { limit: usize },
    #[error("terminal output did not drain within bounded iterations")]
    OutputDrainLimitExceeded,
    #[error("terminal session owner is invalid")]
    InvalidSessionOwner,
    #[error("terminal session limit is invalid")]
    InvalidSessionLimit,
    #[error("terminal session limit {limit} reached")]
    SessionLimitExceeded { limit: usize },
    #[error("terminal session id generation exhausted")]
    SessionIdExhausted,
    #[error("terminal session was not found")]
    SessionNotFound,
    #[error("terminal session owner does not match")]
    SessionOwnerMismatch,
    #[error("terminal session is still running")]
    SessionStillRunning,
    #[error("terminal session registry is unavailable")]
    SessionRegistryUnavailable,
    #[error("terminal command line cannot be empty")]
    EmptyCommand,
    #[error("terminal command or path contains an interior NUL")]
    InteriorNul,
    #[error("terminal dimensions are invalid")]
    InvalidDimensions,
    #[error("terminal pipe accepted a zero-length write")]
    ZeroLengthWrite,
    #[error("Win32 {operation} failed with HRESULT {code:#x}")]
    Hresult { operation: &'static str, code: i32 },
    #[error("ConPTY is not supported on this platform")]
    UnsupportedPlatform,
    #[error("terminal I/O failed: {0}")]
    Io(#[from] io::Error),
}

#[cfg(test)]
mod bounded_tests {
    use super::*;

    fn manifest_dir() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
    }

    fn valid_spec() -> TerminalSpec {
        TerminalSpec {
            argv: vec!["does-not-run-when-cancelled".into()],
            cwd: manifest_dir(),
            timeout_ms: 1_000,
            max_output_bytes: 4 * 1024,
            columns: 80,
            rows: 25,
        }
    }

    #[test]
    fn windows_argv_encoding_is_structured_and_deterministic() {
        assert_eq!(
            argv_to_windows_command_line(&["tool.exe".into(), "plain".into()]).unwrap(),
            "tool.exe plain"
        );
        assert_eq!(
            argv_to_windows_command_line(&[
                r"C:\Program Files\tool.exe".into(),
                "two words".into(),
                String::new(),
            ])
            .unwrap(),
            r#""C:\Program Files\tool.exe" "two words" """#
        );
        assert_eq!(
            argv_to_windows_command_line(&["tool.exe".into(), "a\"b".into()]).unwrap(),
            r#"tool.exe "a\"b""#
        );
    }

    #[test]
    fn cwd_outside_allowed_root_fails_before_spawn() {
        let root = manifest_dir();
        let outside = root.parent().unwrap().to_path_buf();
        let runner = BoundedTerminal::new([root], TerminalLimits::default()).unwrap();
        let mut spec = valid_spec();
        spec.cwd = outside;
        assert!(matches!(
            runner.run(&spec, &CancellationFlag::new()),
            Err(TerminalError::CwdOutsideAllowedRoots)
        ));
    }

    #[test]
    fn request_budgets_cannot_exceed_worker_limits() {
        let root = manifest_dir();
        let limits = TerminalLimits {
            max_timeout_ms: 2_000,
            max_output_bytes: 8 * 1024,
            max_argc: 4,
            max_arg_bytes: 128,
            max_columns: 100,
            max_rows: 50,
        };
        let runner = BoundedTerminal::new([root], limits).unwrap();

        let mut spec = valid_spec();
        spec.timeout_ms = 2_001;
        assert!(matches!(
            runner.run(&spec, &CancellationFlag::new()),
            Err(TerminalError::InvalidTimeout { .. })
        ));

        let mut spec = valid_spec();
        spec.max_output_bytes = 8 * 1024 + 1;
        assert!(matches!(
            runner.run(&spec, &CancellationFlag::new()),
            Err(TerminalError::InvalidOutputLimit { .. })
        ));

        let mut spec = valid_spec();
        spec.argv = vec!["x".into(); 5];
        assert!(matches!(
            runner.run(&spec, &CancellationFlag::new()),
            Err(TerminalError::ArgumentCountExceeded { .. })
        ));
    }

    #[test]
    fn pre_cancelled_request_never_spawns() {
        let root = manifest_dir();
        let runner = BoundedTerminal::new([root], TerminalLimits::default()).unwrap();
        let cancellation = CancellationFlag::new();
        cancellation.cancel();
        assert!(matches!(
            runner.run(&valid_spec(), &cancellation),
            Err(TerminalError::Cancelled)
        ));
    }

    #[cfg(not(windows))]
    #[test]
    fn valid_request_is_platform_closed_off_windows() {
        let root = manifest_dir();
        let runner = BoundedTerminal::new([root], TerminalLimits::default()).unwrap();
        assert!(matches!(
            runner.run(&valid_spec(), &CancellationFlag::new()),
            Err(TerminalError::UnsupportedPlatform)
        ));
    }
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    use std::thread;
    use std::time::{Duration, Instant};

    fn read_until(session: &ConPtySession, needle: &[u8]) -> Vec<u8> {
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut output = Vec::new();
        while Instant::now() < deadline {
            output.extend(session.read_available().unwrap());
            if output.windows(needle.len()).any(|window| window == needle) {
                break;
            }
            thread::sleep(Duration::from_millis(20));
        }
        output
    }

    #[test]
    fn conpty_echo_resize_and_exit_roundtrip() {
        let cwd = Path::new(env!("CARGO_MANIFEST_DIR"));
        let session = ConPtySession::spawn("cmd.exe /Q /D", Some(cwd), 80, 25).unwrap();
        assert!(session.pid() > 0);
        session.resize(100, 30).unwrap();
        session.write_input(b"echo VOR_CONPTY_OK\r\n").unwrap();
        let output = read_until(&session, b"VOR_CONPTY_OK");
        assert!(
            output
                .windows(b"VOR_CONPTY_OK".len())
                .any(|window| window == b"VOR_CONPTY_OK"),
            "output was: {}",
            String::from_utf8_lossy(&output)
        );
        session.write_input(b"exit\r\n").unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline && session.exit_code().unwrap().is_none() {
            thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(session.exit_code().unwrap(), Some(0));
    }

    #[test]
    fn bounded_terminal_runs_structured_argv_with_budgets() {
        let cwd = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let runner = BoundedTerminal::new([cwd.clone()], TerminalLimits::default()).unwrap();
        let spec = TerminalSpec {
            argv: vec![
                "cmd.exe".into(),
                "/D".into(),
                "/Q".into(),
                "/C".into(),
                "echo VOR_BOUNDED_OK".into(),
            ],
            cwd,
            timeout_ms: 5_000,
            max_output_bytes: 64 * 1024,
            columns: 80,
            rows: 25,
        };
        let result = runner.run(&spec, &CancellationFlag::new()).unwrap();
        assert_eq!(result.exit_code, 0);
        assert!(
            result
                .output
                .windows(b"VOR_BOUNDED_OK".len())
                .any(|window| window == b"VOR_BOUNDED_OK"),
            "output was: {}",
            String::from_utf8_lossy(&result.output)
        );
    }

    #[test]
    fn bounded_terminal_times_out_and_terminates_process() {
        let cwd = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let runner = BoundedTerminal::new([cwd.clone()], TerminalLimits::default()).unwrap();
        let spec = TerminalSpec {
            argv: vec![
                "ping.exe".into(),
                "127.0.0.1".into(),
                "-n".into(),
                "10".into(),
            ],
            cwd,
            timeout_ms: 50,
            max_output_bytes: 64 * 1024,
            columns: 80,
            rows: 25,
        };
        assert!(matches!(
            runner.run(&spec, &CancellationFlag::new()),
            Err(TerminalError::Timeout { timeout_ms: 50 })
        ));
    }

    #[test]
    fn bounded_terminal_enforces_output_limit_during_execution() {
        let cwd = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let runner = BoundedTerminal::new([cwd.clone()], TerminalLimits::default()).unwrap();
        let spec = TerminalSpec {
            argv: vec![
                "cmd.exe".into(),
                "/D".into(),
                "/Q".into(),
                "/C".into(),
                "echo VOR_OUTPUT_LIMIT".into(),
            ],
            cwd,
            timeout_ms: 5_000,
            max_output_bytes: 4,
            columns: 80,
            rows: 25,
        };
        assert!(matches!(
            runner.run(&spec, &CancellationFlag::new()),
            Err(TerminalError::OutputLimitExceeded { limit: 4 })
        ));
    }

    #[test]
    fn bounded_terminal_observes_external_cancellation() {
        let cwd = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let runner = BoundedTerminal::new([cwd.clone()], TerminalLimits::default()).unwrap();
        let spec = TerminalSpec {
            argv: vec![
                "ping.exe".into(),
                "127.0.0.1".into(),
                "-n".into(),
                "10".into(),
            ],
            cwd,
            timeout_ms: 10_000,
            max_output_bytes: 64 * 1024,
            columns: 80,
            rows: 25,
        };
        let cancellation = CancellationFlag::new();
        let worker_flag = cancellation.clone();
        let handle = std::thread::spawn(move || runner.run(&spec, &worker_flag));
        std::thread::sleep(Duration::from_millis(50));
        cancellation.cancel();
        assert!(matches!(
            handle.join().unwrap(),
            Err(TerminalError::Cancelled)
        ));
    }

    fn session_owner(actor_id: &str) -> TerminalSessionOwner {
        TerminalSessionOwner::new("org-1", actor_id, "device-1").unwrap()
    }

    fn wait_session(
        manager: &TerminalSessionManager,
        session_id: &str,
        owner: &TerminalSessionOwner,
    ) -> TerminalSessionSnapshot {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let snapshot = manager.poll(session_id, owner).unwrap();
            if snapshot.state != TerminalSessionState::Running {
                return snapshot;
            }
            assert!(Instant::now() < deadline, "terminal session did not finish");
            thread::sleep(Duration::from_millis(10));
        }
    }

    #[test]
    fn terminal_session_manager_runs_polls_and_removes_owned_session() {
        let cwd = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let terminal = BoundedTerminal::new([cwd.clone()], TerminalLimits::default()).unwrap();
        let manager = TerminalSessionManager::new(terminal, 2).unwrap();
        let owner = session_owner("actor-1");
        let spec = TerminalSpec {
            argv: vec![
                "cmd.exe".into(),
                "/D".into(),
                "/Q".into(),
                "/C".into(),
                "echo VOR_SESSION_OK".into(),
            ],
            cwd,
            timeout_ms: 5_000,
            max_output_bytes: 64 * 1024,
            columns: 80,
            rows: 25,
        };

        let session_id = manager.start(owner.clone(), spec).unwrap();
        assert_eq!(session_id.len(), 32);
        assert!(session_id.chars().all(|ch| ch.is_ascii_hexdigit()));
        assert_eq!(manager.session_count().unwrap(), 1);

        let snapshot = wait_session(&manager, &session_id, &owner);
        assert_eq!(snapshot.state, TerminalSessionState::Completed);
        assert_eq!(snapshot.exit_code, Some(0));
        assert!(
            snapshot
                .output
                .windows(b"VOR_SESSION_OK".len())
                .any(|window| window == b"VOR_SESSION_OK")
        );

        let removed = manager.remove(&session_id, &owner).unwrap();
        assert_eq!(removed, snapshot);
        assert_eq!(manager.session_count().unwrap(), 0);
        assert!(matches!(
            manager.poll(&session_id, &owner),
            Err(TerminalError::SessionNotFound)
        ));
    }

    #[test]
    fn terminal_session_manager_enforces_owner_limit_and_cancel() {
        let cwd = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let terminal = BoundedTerminal::new([cwd.clone()], TerminalLimits::default()).unwrap();
        let manager = TerminalSessionManager::new(terminal, 1).unwrap();
        let owner = session_owner("actor-1");
        let other = session_owner("actor-2");
        let spec = TerminalSpec {
            argv: vec![
                "ping.exe".into(),
                "127.0.0.1".into(),
                "-n".into(),
                "10".into(),
            ],
            cwd,
            timeout_ms: 10_000,
            max_output_bytes: 64 * 1024,
            columns: 80,
            rows: 25,
        };

        let session_id = manager.start(owner.clone(), spec.clone()).unwrap();
        assert!(matches!(
            manager.cancel(&session_id, &other),
            Err(TerminalError::SessionOwnerMismatch)
        ));
        assert!(matches!(
            manager.start(owner.clone(), spec),
            Err(TerminalError::SessionLimitExceeded { limit: 1 })
        ));

        assert!(manager.cancel(&session_id, &owner).unwrap());
        let snapshot = wait_session(&manager, &session_id, &owner);
        assert_eq!(snapshot.state, TerminalSessionState::Cancelled);
        assert_eq!(snapshot.error_code, Some("terminal_cancelled"));
        assert!(!manager.cancel(&session_id, &owner).unwrap());
        manager.remove(&session_id, &owner).unwrap();
        assert_eq!(manager.session_count().unwrap(), 0);
    }

    #[test]
    fn invalid_dimensions_fail_before_win32() {
        let cwd = Path::new(env!("CARGO_MANIFEST_DIR"));
        assert!(matches!(
            ConPtySession::spawn("cmd.exe", Some(cwd), 0, 25),
            Err(TerminalError::InvalidDimensions)
        ));
    }
}
