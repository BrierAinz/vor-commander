#![cfg(windows)]

use base64::{Engine as _, engine::general_purpose::STANDARD};
use ed25519_dalek::SigningKey;
use prost::Message;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Output, Stdio};
use std::sync::Once;
use std::thread;
use std::time::{Duration, Instant};
use tempfile::TempDir;
use vor_approval::{ApprovalChallenge, sign_approval};
use vor_maintenance::{
    MaintenanceTransaction, RestartSpec, UPDATE_PLAN_SCHEMA, UpdatePlan, sha256_file,
};
use vor_wire::approval_grant_to_proto;
use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, HANDLE, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows_sys::Win32::System::Diagnostics::Debug::{
    SEM_FAILCRITICALERRORS, SEM_NOGPFAULTERRORBOX, SEM_NOOPENFILEERRORBOX, SetErrorMode,
};
use windows_sys::Win32::System::Threading::{
    GetExitCodeProcess, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE,
    PROCESS_TERMINATE, QueryFullProcessImageNameW, TerminateProcess, WaitForSingleObject,
};

const OWNER_ID: &str = "lab-owner";
const LAB_AGENT_ARGS: [&str; 3] = ["--ignored", "--exact", "lab_agent_stays_alive"];

#[test]
#[ignore]
fn lab_agent_stays_alive() {
    thread::sleep(Duration::from_secs(30));
}

fn suppress_windows_error_dialogs() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| unsafe {
        // Prevent "Unsupported 16-Bit Application" from blocking the invalid-executable test.
        SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX);
    });
}

struct LabProcess {
    child: Option<Child>,
}

impl LabProcess {
    fn spawn(path: &Path, working_directory: &Path) -> Self {
        let child = Command::new(path)
            .args(LAB_AGENT_ARGS)
            .current_dir(working_directory)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn disposable cmd lab process");
        Self { child: Some(child) }
    }

    fn pid(&self) -> u32 {
        self.child.as_ref().expect("child exists").id()
    }

    fn wait_for_exit(&mut self) {
        if let Some(child) = self.child.as_mut() {
            let deadline = Instant::now() + Duration::from_secs(5);
            while Instant::now() < deadline {
                if child.try_wait().expect("query child status").is_some() {
                    return;
                }
                thread::sleep(Duration::from_millis(20));
            }
        }
    }

    fn terminate(&mut self) {
        if let Some(child) = self.child.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

impl Drop for LabProcess {
    fn drop(&mut self) {
        if let Some(child) = self.child.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

struct VerifiedProcessGuard {
    handle: HANDLE,
    kill_allowed: bool,
}

impl VerifiedProcessGuard {
    fn attach(
        pid: u32,
        expected_executable: &Path,
        fixture: &Fixture,
        run: &MaintainerRun,
        result: &Value,
    ) -> Self {
        let handle = unsafe {
            OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE | PROCESS_TERMINATE,
                0,
                pid,
            )
        };
        assert!(
            !handle.is_null(),
            "open relaunched lab process {pid}: Win32 error {}; exit_code=unavailable; parent_pid={}; {}",
            unsafe { GetLastError() },
            run.pid,
            process_diagnostics(fixture, run, result),
        );
        let expected = fs::canonicalize(expected_executable).expect("canonical expected image");
        let actual = process_image_path(handle).unwrap_or_else(|error| {
            panic!(
                "query relaunched lab process {pid}: {error}; exit_code={}; parent_pid={}; {}",
                process_exit_code(handle),
                run.pid,
                process_diagnostics(fixture, run, result),
            )
        });
        assert!(
            same_path(&actual, &expected),
            "PID {pid} belongs to {}, not {}; exit_code={}; parent_pid={}; {}",
            actual.display(),
            expected.display(),
            process_exit_code(handle),
            run.pid,
            process_diagnostics(fixture, run, result),
        );
        Self {
            handle,
            kill_allowed: true,
        }
    }
}

impl Drop for VerifiedProcessGuard {
    fn drop(&mut self) {
        unsafe {
            let status = WaitForSingleObject(self.handle, 0);
            if status == WAIT_TIMEOUT && self.kill_allowed {
                let _ = TerminateProcess(self.handle, 0xC000_013A);
                let _ = WaitForSingleObject(self.handle, 5_000);
            } else if status == WAIT_TIMEOUT {
                let _ = WaitForSingleObject(self.handle, 35_000);
            } else {
                debug_assert_eq!(status, WAIT_OBJECT_0);
            }
            CloseHandle(self.handle);
        }
    }
}

fn process_image_path(handle: HANDLE) -> std::io::Result<PathBuf> {
    let mut buffer = vec![0u16; 32 * 1024];
    let mut len = u32::try_from(buffer.len()).expect("path buffer length");
    let ok = unsafe { QueryFullProcessImageNameW(handle, 0, buffer.as_mut_ptr(), &mut len) };
    if ok == 0 {
        return Err(std::io::Error::last_os_error());
    }
    buffer.truncate(usize::try_from(len).expect("returned path length"));
    Ok(PathBuf::from(String::from_utf16_lossy(&buffer)))
}

fn process_exit_code(handle: HANDLE) -> String {
    let mut exit_code = 0;
    if unsafe { GetExitCodeProcess(handle, &mut exit_code) } == 0 {
        format!("unavailable (Win32 error {})", unsafe { GetLastError() })
    } else if exit_code == 259 {
        "STILL_ACTIVE".into()
    } else {
        format!("{exit_code:#010x}")
    }
}

fn same_path(left: &Path, right: &Path) -> bool {
    let normalize = |path: &Path| {
        let path = path.to_string_lossy();
        path.strip_prefix(r"\\?\").unwrap_or(&path).to_owned()
    };
    normalize(left).eq_ignore_ascii_case(&normalize(right))
}

struct Fixture {
    _dir: TempDir,
    target: PathBuf,
    plan_path: PathBuf,
    plan_sha256: String,
    request_file: PathBuf,
    challenge_file: PathBuf,
    approval_file: PathBuf,
    approvers_file: PathBuf,
    result_file: PathBuf,
    journal_file: PathBuf,
    old_sha256: String,
    staged_sha256: String,
    old_process: LabProcess,
}

struct MaintainerRun {
    status: ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    pid: u32,
}

fn maintainer_bin() -> &'static str {
    env!("CARGO_BIN_EXE_vor-maintainer")
}

fn copy_lab_agent(path: &Path) {
    fs::copy(std::env::current_exe().expect("current test image"), path).expect("copy lab agent");
}

fn create_fixture(staged_valid: bool, request_id: &str) -> Fixture {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().to_path_buf();
    let target = root.join("vor-agent-lab.exe");
    let staged = root.join("staged-agent.exe");
    copy_lab_agent(&target);
    if staged_valid {
        copy_lab_agent(&staged);
        // PE loaders tolerate overlay bytes; this creates a different digest while
        // preserving a runnable disposable executable.
        let mut bytes = fs::read(&staged).expect("read staged");
        bytes.extend_from_slice(b"\nVOR_M3_STAGED_OVERLAY\n");
        fs::write(&staged, bytes).expect("write staged overlay");
    } else {
        fs::write(&staged, b"not-a-valid-windows-executable").expect("write invalid staged");
    }

    let old_sha256 = sha256_file(&target).expect("old digest");
    let staged_sha256 = sha256_file(&staged).expect("staged digest");
    let mut old_process = LabProcess::spawn(&target, &root);
    thread::sleep(Duration::from_millis(100));
    assert!(
        old_process
            .child
            .as_mut()
            .unwrap()
            .try_wait()
            .unwrap()
            .is_none()
    );

    let result_file = root.join("state/maintenance/result.json");
    let plan = UpdatePlan {
        schema: UPDATE_PLAN_SCHEMA,
        request_id: request_id.into(),
        allowed_root: root.clone(),
        target_executable: target.clone(),
        staged_executable: staged.clone(),
        expected_current_sha256: old_sha256.clone(),
        expected_staged_sha256: staged_sha256.clone(),
        journal_directory: root.join("state/maintenance/journal"),
        result_file: result_file.clone(),
        current_pid: old_process.pid(),
        restart: RestartSpec {
            args: LAB_AGENT_ARGS.iter().map(|arg| (*arg).into()).collect(),
            environment: BTreeMap::new(),
            working_directory: root.clone(),
            stdout_log: root.join("state/maintenance/agent.out.log"),
            stderr_log: root.join("state/maintenance/agent.err.log"),
            health_wait_ms: 300,
        },
    };
    let plan_path = root.join("plan.json");
    fs::write(&plan_path, serde_json::to_vec_pretty(&plan).unwrap()).unwrap();
    let plan_sha256 = sha256_file(&plan_path).unwrap();

    Fixture {
        _dir: dir,
        target,
        plan_path,
        plan_sha256,
        request_file: root.join("approval/request.b64"),
        challenge_file: root.join("approval/challenge.json"),
        approval_file: root.join("approval/approval.b64"),
        approvers_file: root.join("approval/trusted.json"),
        result_file,
        journal_file: root.join(format!("state/maintenance/journal/{request_id}.jsonl")),
        old_sha256,
        staged_sha256,
        old_process,
    }
}

fn run_maintainer(args: &[String]) -> Output {
    Command::new(maintainer_bin())
        .args(args)
        .stdin(Stdio::null())
        .output()
        .expect("run vor-maintainer")
}

fn run_maintainer_for_handoff(fixture: &Fixture, args: &[String]) -> MaintainerRun {
    let stdout_path = fixture._dir.path().join("maintainer.stdout.log");
    let stderr_path = fixture._dir.path().join("maintainer.stderr.log");
    let stdout = fs::File::create(&stdout_path).expect("create maintainer stdout log");
    let stderr = fs::File::create(&stderr_path).expect("create maintainer stderr log");
    let mut child = Command::new(maintainer_bin())
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr))
        .spawn()
        .expect("run vor-maintainer");
    let pid = child.id();
    let status = child.wait().expect("wait for vor-maintainer");
    MaintainerRun {
        status,
        stdout: fs::read(stdout_path).expect("read maintainer stdout log"),
        stderr: fs::read(stderr_path).expect("read maintainer stderr log"),
        pid,
    }
}

fn process_diagnostics(fixture: &Fixture, run: &MaintainerRun, result: &Value) -> String {
    let read_log = |path: &Path| match fs::read(path) {
        Ok(bytes) => String::from_utf8_lossy(&bytes).into_owned(),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => "<not created>".into(),
        Err(error) => format!("<read failed: {error}>"),
    };
    let plan = UpdatePlan::load(&fixture.plan_path).expect("reload diagnostic plan");
    format!(
        "result={} maintainer_pid={} maintainer_status={} maintainer_stdout={:?} maintainer_stderr={:?} agent_stdout={:?} agent_stderr={:?}",
        result,
        run.pid,
        run.status,
        String::from_utf8_lossy(&run.stdout),
        String::from_utf8_lossy(&run.stderr),
        read_log(&plan.restart.stdout_log),
        read_log(&plan.restart.stderr_log),
    )
}

fn prepare_and_sign(fixture: &Fixture) {
    prepare_and_sign_action(
        fixture,
        "apply",
        &fixture.request_file,
        &fixture.challenge_file,
        &fixture.approval_file,
    );
}

fn prepare_and_sign_action(
    fixture: &Fixture,
    action: &str,
    request_file: &Path,
    challenge_file: &Path,
    approval_file: &Path,
) {
    let output = run_maintainer(&[
        "prepare-approval".into(),
        "--plan".into(),
        fixture.plan_path.to_string_lossy().into_owned(),
        "--plan-sha256".into(),
        fixture.plan_sha256.clone(),
        "--action".into(),
        action.into(),
        "--actor".into(),
        OWNER_ID.into(),
        "--device".into(),
        "m3-lab-device".into(),
        "--request-out".into(),
        request_file.to_string_lossy().into_owned(),
        "--challenge-out".into(),
        challenge_file.to_string_lossy().into_owned(),
    ]);
    assert!(
        output.status.success(),
        "prepare {action} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let prepared: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(prepared["status"], "approval_required");
    assert_eq!(prepared["required_capability"], "owner");
    assert_eq!(prepared["plan_sha256"], fixture.plan_sha256);

    let challenge: Value = serde_json::from_slice(&fs::read(challenge_file).unwrap()).unwrap();
    let approval_challenge = ApprovalChallenge {
        request_id: challenge["request_id"].as_str().unwrap().into(),
        envelope_digest: STANDARD
            .decode(challenge["envelope_digest_base64"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap(),
        policy_id: challenge["policy_id"].as_str().unwrap().into(),
        required_capability: challenge["required_capability"]
            .as_str()
            .map(ToOwned::to_owned),
        expires_at_unix_ms: challenge["expires_at_unix_ms"].as_u64().unwrap(),
        approval_nonce: STANDARD
            .decode(challenge["approval_nonce_base64"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap(),
    };
    let signing = SigningKey::from_bytes(&[41; 32]);
    let signed = sign_approval(approval_challenge, OWNER_ID, &signing).unwrap();
    let proto = approval_grant_to_proto(&signed).unwrap();
    fs::create_dir_all(approval_file.parent().unwrap()).unwrap();
    fs::write(approval_file, STANDARD.encode(proto.encode_to_vec())).unwrap();
    fs::create_dir_all(fixture.approvers_file.parent().unwrap()).unwrap();
    fs::write(
        &fixture.approvers_file,
        serde_json::to_vec_pretty(&json!({
            "approvers": [{
                "approver_id": OWNER_ID,
                "public_key_base64": STANDARD.encode(signing.verifying_key().to_bytes()),
                "authority": "owner"
            }]
        }))
        .unwrap(),
    )
    .unwrap();
}

fn apply_args(fixture: &Fixture) -> Vec<String> {
    vec![
        "apply-update".into(),
        "--plan".into(),
        fixture.plan_path.to_string_lossy().into_owned(),
        "--plan-sha256".into(),
        fixture.plan_sha256.clone(),
        "--request-file".into(),
        fixture.request_file.to_string_lossy().into_owned(),
        "--approval-file".into(),
        fixture.approval_file.to_string_lossy().into_owned(),
        "--approvers".into(),
        fixture.approvers_file.to_string_lossy().into_owned(),
    ]
}

fn result_json(path: &Path) -> Value {
    serde_json::from_slice(&fs::read(path).expect("result file")).expect("result json")
}

fn journal_states(path: &Path) -> Vec<String> {
    fs::read_to_string(path)
        .expect("journal")
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            serde_json::from_str::<Value>(line).unwrap()["state"]
                .as_str()
                .unwrap()
                .to_owned()
        })
        .collect()
}

#[test]
fn owner_approved_lab_handoff_commits_staged_binary() {
    suppress_windows_error_dialogs();
    let mut fixture = create_fixture(true, "m3-lab-commit");
    prepare_and_sign(&fixture);

    let output = run_maintainer_for_handoff(&fixture, &apply_args(&fixture));
    assert!(
        output.status.success(),
        "apply failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    fixture.old_process.wait_for_exit();

    let result = result_json(&fixture.result_file);
    assert_eq!(result["status"], "committed");
    assert_eq!(
        result["target_sha256"].as_str().unwrap(),
        fixture.staged_sha256
    );
    assert_eq!(sha256_file(&fixture.target).unwrap(), fixture.staged_sha256);
    assert_eq!(
        journal_states(&fixture.journal_file),
        ["validated", "swapped", "committed"]
    );

    let _new_guard = VerifiedProcessGuard::attach(
        result["new_pid"].as_u64().unwrap() as u32,
        &fixture.target,
        &fixture,
        &output,
        &result,
    );

    let consumed_markers = fs::read_dir(fixture.journal_file.parent().unwrap())
        .unwrap()
        .filter_map(Result::ok)
        .filter(|entry| {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            name.starts_with("approval-") && name.ends_with(".consumed.json")
        })
        .count();
    assert_eq!(consumed_markers, 1);

    let replay = run_maintainer(&apply_args(&fixture));
    assert!(
        !replay.status.success(),
        "replayed maintenance approval unexpectedly succeeded"
    );
}

#[test]
fn owner_approved_lab_failed_launch_rolls_back_previous_binary() {
    suppress_windows_error_dialogs();
    let mut fixture = create_fixture(false, "m3-lab-rollback");
    prepare_and_sign(&fixture);

    let output = run_maintainer_for_handoff(&fixture, &apply_args(&fixture));
    assert!(
        !output.status.success(),
        "invalid staged executable unexpectedly succeeded"
    );
    fixture.old_process.wait_for_exit();

    let result = result_json(&fixture.result_file);
    assert_eq!(result["status"], "rolled_back");
    assert!(
        result["message"].as_str().unwrap().contains("os error 216"),
        "expected CreateProcess ERROR_EXE_MACHINE_TYPE_MISMATCH, got: {}",
        result["message"]
    );
    assert_eq!(
        result["target_sha256"].as_str().unwrap(),
        fixture.old_sha256
    );
    assert_eq!(sha256_file(&fixture.target).unwrap(), fixture.old_sha256);
    assert_eq!(
        journal_states(&fixture.journal_file),
        ["validated", "swapped", "rolled_back"]
    );

    let _rollback_guard = VerifiedProcessGuard::attach(
        result["new_pid"].as_u64().unwrap() as u32,
        &fixture.target,
        &fixture,
        &output,
        &result,
    );
}

fn recover_args(fixture: &Fixture, request_file: &Path, approval_file: &Path) -> Vec<String> {
    vec![
        "recover".into(),
        "--plan".into(),
        fixture.plan_path.to_string_lossy().into_owned(),
        "--plan-sha256".into(),
        fixture.plan_sha256.clone(),
        "--request-file".into(),
        request_file.to_string_lossy().into_owned(),
        "--approval-file".into(),
        approval_file.to_string_lossy().into_owned(),
        "--approvers".into(),
        fixture.approvers_file.to_string_lossy().into_owned(),
    ]
}

fn status_args(fixture: &Fixture) -> Vec<String> {
    vec![
        "status".into(),
        "--plan".into(),
        fixture.plan_path.to_string_lossy().into_owned(),
        "--plan-sha256".into(),
        fixture.plan_sha256.clone(),
    ]
}

#[test]
fn owner_approved_lab_crash_recovery_restores_interrupted_swap() {
    suppress_windows_error_dialogs();
    let mut fixture = create_fixture(true, "m3-lab-crash-recover");
    fixture.old_process.terminate();

    let plan = UpdatePlan::load(&fixture.plan_path).unwrap();
    let mut transaction = MaintenanceTransaction::begin(plan).unwrap();
    transaction.swap().unwrap();
    let backup = transaction.update().backup.clone();
    drop(transaction);

    assert_eq!(sha256_file(&fixture.target).unwrap(), fixture.staged_sha256);
    assert_eq!(sha256_file(&backup).unwrap(), fixture.old_sha256);
    assert_eq!(
        journal_states(&fixture.journal_file),
        ["validated", "swapped"]
    );

    let approval_dir = fixture
        .plan_path
        .parent()
        .unwrap()
        .join("recovery-approval");
    let request_file = approval_dir.join("request.b64");
    let challenge_file = approval_dir.join("challenge.json");
    let approval_file = approval_dir.join("approval.b64");
    prepare_and_sign_action(
        &fixture,
        "recover",
        &request_file,
        &challenge_file,
        &approval_file,
    );

    let output = run_maintainer_for_handoff(
        &fixture,
        &recover_args(&fixture, &request_file, &approval_file),
    );
    assert!(
        output.status.success(),
        "recover failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let result = result_json(&fixture.result_file);
    assert_eq!(result["status"], "recovered");
    assert_eq!(
        result["target_sha256"].as_str().unwrap(),
        fixture.old_sha256
    );
    assert_eq!(sha256_file(&fixture.target).unwrap(), fixture.old_sha256);
    assert!(!backup.exists());
    assert_eq!(
        journal_states(&fixture.journal_file),
        ["validated", "swapped", "rolled_back"]
    );

    let _recovered_guard = VerifiedProcessGuard::attach(
        result["new_pid"].as_u64().unwrap() as u32,
        &fixture.target,
        &fixture,
        &output,
        &result,
    );
}

#[test]
fn status_inspects_abandoned_swapped_journal_without_mutation() {
    suppress_windows_error_dialogs();
    let mut fixture = create_fixture(true, "m3-lab-status-swapped");
    fixture.old_process.terminate();

    let plan = UpdatePlan::load(&fixture.plan_path).unwrap();
    let mut transaction = MaintenanceTransaction::begin(plan).unwrap();
    transaction.swap().unwrap();
    let backup = transaction.update().backup.clone();
    drop(transaction);

    let before_target = sha256_file(&fixture.target).unwrap();
    let before_backup = sha256_file(&backup).unwrap();
    let before_journal = fs::read_to_string(&fixture.journal_file).unwrap();
    assert_eq!(before_target, fixture.staged_sha256);
    assert_eq!(before_backup, fixture.old_sha256);
    assert_eq!(
        journal_states(&fixture.journal_file),
        ["validated", "swapped"]
    );
    assert!(!fixture.result_file.exists());

    let output = run_maintainer(&status_args(&fixture));
    assert!(
        output.status.success(),
        "status failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let status: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(status["observed_state"], "swapped");
    assert_eq!(status["journal_state"], "swapped");
    assert_eq!(status["target_sha256"], fixture.staged_sha256);
    assert_eq!(status["backup_sha256"], fixture.old_sha256);
    assert_eq!(status["result_status"], Value::Null);

    assert_eq!(sha256_file(&fixture.target).unwrap(), before_target);
    assert_eq!(sha256_file(&backup).unwrap(), before_backup);
    assert_eq!(
        fs::read_to_string(&fixture.journal_file).unwrap(),
        before_journal
    );
    assert!(!fixture.result_file.exists());
}
