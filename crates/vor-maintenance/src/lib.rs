// SPDX-License-Identifier: MPL-2.0

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Component, Path, PathBuf};
use thiserror::Error;

pub const UPDATE_PLAN_SCHEMA: u32 = 1;
pub const MAX_PLAN_BYTES: u64 = 128 * 1024;
pub const MAX_RESTART_ARGS: usize = 128;
pub const MAX_RESTART_ARG_BYTES: usize = 32 * 1024;
pub const MAX_RESTART_TOTAL_ARG_BYTES: usize = 128 * 1024;
pub const MAX_RESTART_ENV: usize = 64;
pub const MAX_HEALTH_WAIT_MS: u64 = 30_000;
pub const MAX_JOURNAL_BYTES: u64 = 1024 * 1024;
pub const MAX_JOURNAL_ENTRIES: usize = 512;
pub const MAX_RESULT_BYTES: u64 = 128 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UpdatePlan {
    pub schema: u32,
    pub request_id: String,
    pub allowed_root: PathBuf,
    pub target_executable: PathBuf,
    pub staged_executable: PathBuf,
    pub expected_current_sha256: String,
    pub expected_staged_sha256: String,
    pub journal_directory: PathBuf,
    pub result_file: PathBuf,
    pub current_pid: u32,
    pub restart: RestartSpec,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RestartSpec {
    pub args: Vec<String>,
    #[serde(default)]
    pub environment: BTreeMap<String, String>,
    pub working_directory: PathBuf,
    pub stdout_log: PathBuf,
    pub stderr_log: PathBuf,
    pub health_wait_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum JournalState {
    Validated,
    Swapped,
    Committed,
    RolledBack,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct JournalEntry {
    pub request_id: String,
    pub state: JournalState,
    pub target_executable: PathBuf,
    pub staged_executable: PathBuf,
    pub backup_executable: PathBuf,
    pub temp_executable: PathBuf,
    pub expected_current_sha256: String,
    pub expected_staged_sha256: String,
}

#[derive(Debug, Clone)]
pub struct ValidatedUpdate {
    pub plan: UpdatePlan,
    pub root: PathBuf,
    pub target: PathBuf,
    pub staged: PathBuf,
    pub working_directory: PathBuf,
    pub backup: PathBuf,
    pub temp: PathBuf,
    pub journal: PathBuf,
    pub result_file: PathBuf,
    pub stdout_log: PathBuf,
    pub stderr_log: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MaintenanceObservedState {
    Ready,
    Validated,
    Swapped,
    Committed,
    RolledBack,
    Inconsistent,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MaintenanceInspection {
    pub request_id: String,
    pub observed_state: MaintenanceObservedState,
    pub journal_state: Option<JournalState>,
    pub target_sha256: Option<String>,
    pub staged_sha256: Option<String>,
    pub backup_sha256: Option<String>,
    pub temp_sha256: Option<String>,
    pub target_matches_current: bool,
    pub target_matches_staged: bool,
    pub staged_matches_expected: bool,
    pub backup_matches_current: bool,
    pub backup_exists: bool,
    pub temp_exists: bool,
    pub journal_exists: bool,
    pub result_status: Option<String>,
}

pub struct MaintenanceTransaction {
    update: ValidatedUpdate,
    state: JournalState,
}

impl UpdatePlan {
    pub fn load(path: impl AsRef<Path>) -> Result<Self, MaintenanceError> {
        let path = path.as_ref();
        let metadata = fs::metadata(path)?;
        if !metadata.is_file() || metadata.len() == 0 || metadata.len() > MAX_PLAN_BYTES {
            return Err(MaintenanceError::InvalidPlan);
        }
        let bytes = fs::read(path)?;
        Ok(serde_json::from_slice(&bytes)?)
    }
}

impl MaintenanceTransaction {
    pub fn begin(plan: UpdatePlan) -> Result<Self, MaintenanceError> {
        let update = validate_plan(plan)?;
        create_parent(&update.journal)?;
        if update.journal.exists() {
            return Err(MaintenanceError::JournalExists);
        }
        append_journal(&update, JournalState::Validated, true)?;
        Ok(Self {
            update,
            state: JournalState::Validated,
        })
    }

    pub fn update(&self) -> &ValidatedUpdate {
        &self.update
    }

    pub fn state(&self) -> JournalState {
        self.state.clone()
    }

    pub fn swap(&mut self) -> Result<(), MaintenanceError> {
        if self.state != JournalState::Validated {
            return Err(MaintenanceError::InvalidState);
        }
        verify_file_sha256(
            &self.update.target,
            &self.update.plan.expected_current_sha256,
        )?;
        verify_file_sha256(
            &self.update.staged,
            &self.update.plan.expected_staged_sha256,
        )?;
        if self.update.backup.exists() || self.update.temp.exists() {
            return Err(MaintenanceError::StagingCollision);
        }

        copy_synced(&self.update.staged, &self.update.temp)?;
        verify_file_sha256(&self.update.temp, &self.update.plan.expected_staged_sha256)?;

        if let Err(error) = fs::rename(&self.update.target, &self.update.backup) {
            let _ = fs::remove_file(&self.update.temp);
            return Err(MaintenanceError::Io(error));
        }

        if let Err(error) = fs::rename(&self.update.temp, &self.update.target) {
            let restore = fs::rename(&self.update.backup, &self.update.target);
            let _ = fs::remove_file(&self.update.temp);
            if let Err(restore_error) = restore {
                return Err(MaintenanceError::SwapAndRollbackFailed {
                    swap: error.to_string(),
                    rollback: restore_error.to_string(),
                });
            }
            return Err(MaintenanceError::Io(error));
        }

        if let Err(error) = verify_file_sha256(
            &self.update.target,
            &self.update.plan.expected_staged_sha256,
        ) {
            let rollback = rollback_paths(&self.update);
            if let Err(rollback_error) = rollback {
                return Err(MaintenanceError::PostSwapAndRollbackFailed {
                    verification: error.to_string(),
                    rollback: rollback_error.to_string(),
                });
            }
            self.state = JournalState::RolledBack;
            append_journal(&self.update, JournalState::RolledBack, false)?;
            return Err(error);
        }

        self.state = JournalState::Swapped;
        append_journal(&self.update, JournalState::Swapped, false)?;
        Ok(())
    }

    pub fn commit(&mut self) -> Result<(), MaintenanceError> {
        if self.state != JournalState::Swapped {
            return Err(MaintenanceError::InvalidState);
        }
        verify_file_sha256(
            &self.update.target,
            &self.update.plan.expected_staged_sha256,
        )?;
        self.state = JournalState::Committed;
        append_journal(&self.update, JournalState::Committed, false)?;
        Ok(())
    }

    pub fn rollback(&mut self) -> Result<(), MaintenanceError> {
        if !matches!(self.state, JournalState::Swapped | JournalState::Validated) {
            return Err(MaintenanceError::InvalidState);
        }
        rollback_paths(&self.update)?;
        self.state = JournalState::RolledBack;
        append_journal(&self.update, JournalState::RolledBack, false)?;
        Ok(())
    }
}

pub fn validate_plan(plan: UpdatePlan) -> Result<ValidatedUpdate, MaintenanceError> {
    validate_plan_shape(&plan)?;
    let root = fs::canonicalize(&plan.allowed_root)?;
    if !root.is_dir() {
        return Err(MaintenanceError::InvalidRoot);
    }

    let target = canonical_file_within(&plan.target_executable, &root)?;
    let staged = canonical_file_within(&plan.staged_executable, &root)?;
    if same_path(&target, &staged) {
        return Err(MaintenanceError::InvalidPlan);
    }
    verify_file_sha256(&target, &plan.expected_current_sha256)?;
    verify_file_sha256(&staged, &plan.expected_staged_sha256)?;

    let working_directory = canonical_directory_within(&plan.restart.working_directory, &root)?;
    let journal_directory = output_directory_within(&plan.journal_directory, &root)?;
    let result_file = output_path_within(&plan.result_file, &root)?;
    let stdout_log = output_path_within(&plan.restart.stdout_log, &root)?;
    let stderr_log = output_path_within(&plan.restart.stderr_log, &root)?;

    let name = target
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or(MaintenanceError::InvalidPlan)?;
    let parent = target.parent().ok_or(MaintenanceError::InvalidPlan)?;
    let backup = parent.join(format!(".{name}.{}.bak", plan.request_id));
    let temp = parent.join(format!(".{name}.{}.new", plan.request_id));
    let journal = journal_directory.join(format!("{}.jsonl", plan.request_id));

    for path in [&backup, &temp, &journal] {
        ensure_output_path_within(path, &root)?;
    }

    Ok(ValidatedUpdate {
        plan,
        root,
        target,
        staged,
        working_directory,
        backup,
        temp,
        journal,
        result_file,
        stdout_log,
        stderr_log,
    })
}

pub fn validate_recovery_plan(plan: UpdatePlan) -> Result<ValidatedUpdate, MaintenanceError> {
    validate_plan_shape(&plan)?;
    let root = fs::canonicalize(&plan.allowed_root)?;
    if !root.is_dir() {
        return Err(MaintenanceError::InvalidRoot);
    }

    let target_parent = plan
        .target_executable
        .parent()
        .ok_or(MaintenanceError::InvalidPlan)?;
    let canonical_parent = fs::canonicalize(target_parent)?;
    ensure_within(&canonical_parent, &root)?;
    let target_name = plan
        .target_executable
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or(MaintenanceError::InvalidPlan)?;
    let target = canonical_parent.join(target_name);
    let staged = canonical_file_within(&plan.staged_executable, &root)?;
    let working_directory = canonical_directory_within(&plan.restart.working_directory, &root)?;
    let journal_directory = output_directory_within(&plan.journal_directory, &root)?;
    let result_file = output_path_within(&plan.result_file, &root)?;
    let stdout_log = output_path_within(&plan.restart.stdout_log, &root)?;
    let stderr_log = output_path_within(&plan.restart.stderr_log, &root)?;
    let backup = canonical_parent.join(format!(".{target_name}.{}.bak", plan.request_id));
    let temp = canonical_parent.join(format!(".{target_name}.{}.new", plan.request_id));
    let journal = journal_directory.join(format!("{}.jsonl", plan.request_id));

    let update = ValidatedUpdate {
        plan,
        root,
        target,
        staged,
        working_directory,
        backup,
        temp,
        journal,
        result_file,
        stdout_log,
        stderr_log,
    };
    if !update.backup.is_file() {
        return Err(MaintenanceError::BackupMissing);
    }
    ensure_within(&fs::canonicalize(&update.backup)?, &update.root)?;
    verify_file_sha256(&update.backup, &update.plan.expected_current_sha256)?;
    if update.target.exists() {
        let canonical_target = fs::canonicalize(&update.target)?;
        ensure_within(&canonical_target, &update.root)?;
        if !canonical_target.is_file() {
            return Err(MaintenanceError::ExpectedFile);
        }
    }
    Ok(update)
}

pub fn recover_previous(plan: UpdatePlan) -> Result<ValidatedUpdate, MaintenanceError> {
    let update = validate_recovery_plan(plan)?;
    if update.target.exists() {
        fs::remove_file(&update.target)?;
    }
    fs::rename(&update.backup, &update.target)?;
    let _ = fs::remove_file(&update.temp);
    verify_file_sha256(&update.target, &update.plan.expected_current_sha256)?;
    append_journal(&update, JournalState::RolledBack, false)?;
    Ok(update)
}

pub fn inspect_plan(plan: UpdatePlan) -> Result<MaintenanceInspection, MaintenanceError> {
    validate_plan_shape(&plan)?;
    let root = fs::canonicalize(&plan.allowed_root)?;
    if !root.is_dir() {
        return Err(MaintenanceError::InvalidRoot);
    }

    let target_parent = plan
        .target_executable
        .parent()
        .ok_or(MaintenanceError::InvalidPlan)?;
    let canonical_parent = fs::canonicalize(target_parent)?;
    ensure_within(&canonical_parent, &root)?;
    let target_name = plan
        .target_executable
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or(MaintenanceError::InvalidPlan)?;
    let target = canonical_parent.join(target_name);
    let staged = if plan.staged_executable.exists() {
        let canonical = fs::canonicalize(&plan.staged_executable)?;
        ensure_within(&canonical, &root)?;
        canonical
    } else {
        plan.staged_executable.clone()
    };

    for path in [
        &plan.target_executable,
        &plan.staged_executable,
        &plan.journal_directory,
        &plan.result_file,
        &plan.restart.stdout_log,
        &plan.restart.stderr_log,
    ] {
        ensure_output_path_within(path, &root)?;
    }
    let working_directory = fs::canonicalize(&plan.restart.working_directory)?;
    ensure_within(&working_directory, &root)?;

    let backup = canonical_parent.join(format!(".{target_name}.{}.bak", plan.request_id));
    let temp = canonical_parent.join(format!(".{target_name}.{}.new", plan.request_id));
    let journal = plan
        .journal_directory
        .join(format!("{}.jsonl", plan.request_id));
    ensure_output_path_within(&backup, &root)?;
    ensure_output_path_within(&temp, &root)?;
    ensure_output_path_within(&journal, &root)?;

    let expected_current = normalize_sha256(&plan.expected_current_sha256)?;
    let expected_staged = normalize_sha256(&plan.expected_staged_sha256)?;
    let target_sha256 = optional_file_sha256(&target, &root)?;
    let staged_sha256 = optional_file_sha256(&staged, &root)?;
    let backup_sha256 = optional_file_sha256(&backup, &root)?;
    let temp_sha256 = optional_file_sha256(&temp, &root)?;

    let target_matches_current = target_sha256.as_deref() == Some(expected_current.as_str());
    let target_matches_staged = target_sha256.as_deref() == Some(expected_staged.as_str());
    let staged_matches_expected = staged_sha256.as_deref() == Some(expected_staged.as_str());
    let backup_matches_current = backup_sha256.as_deref() == Some(expected_current.as_str());
    let journal_state = read_journal_state(&journal, &plan, &target, &staged, &backup, &temp)?;
    let result_status = read_result_status(&plan.result_file, &root)?;

    let observed_state = match journal_state {
        None if target_matches_current
            && staged_matches_expected
            && backup_sha256.is_none()
            && temp_sha256.is_none() =>
        {
            MaintenanceObservedState::Ready
        }
        Some(JournalState::Validated)
            if target_matches_current
                && staged_matches_expected
                && backup_sha256.is_none()
                && temp_sha256.is_none() =>
        {
            MaintenanceObservedState::Validated
        }
        Some(JournalState::Swapped) if target_matches_staged && backup_matches_current => {
            MaintenanceObservedState::Swapped
        }
        Some(JournalState::Committed) if target_matches_staged && backup_matches_current => {
            MaintenanceObservedState::Committed
        }
        Some(JournalState::RolledBack)
            if target_matches_current && backup_sha256.is_none() && temp_sha256.is_none() =>
        {
            MaintenanceObservedState::RolledBack
        }
        _ => MaintenanceObservedState::Inconsistent,
    };

    Ok(MaintenanceInspection {
        request_id: plan.request_id,
        observed_state,
        journal_state,
        target_sha256,
        staged_sha256,
        backup_exists: backup_sha256.is_some(),
        backup_sha256,
        temp_exists: temp_sha256.is_some(),
        temp_sha256,
        target_matches_current,
        target_matches_staged,
        staged_matches_expected,
        backup_matches_current,
        journal_exists: journal.exists(),
        result_status,
    })
}

fn optional_file_sha256(path: &Path, root: &Path) -> Result<Option<String>, MaintenanceError> {
    if !path.exists() {
        return Ok(None);
    }
    let canonical = fs::canonicalize(path)?;
    ensure_within(&canonical, root)?;
    if !canonical.is_file() {
        return Err(MaintenanceError::ExpectedFile);
    }
    Ok(Some(sha256_file(canonical)?))
}

fn read_journal_state(
    path: &Path,
    plan: &UpdatePlan,
    target: &Path,
    staged: &Path,
    backup: &Path,
    temp: &Path,
) -> Result<Option<JournalState>, MaintenanceError> {
    if !path.exists() {
        return Ok(None);
    }
    let metadata = fs::metadata(path)?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > MAX_JOURNAL_BYTES {
        return Err(MaintenanceError::JournalInvalid);
    }
    let text = fs::read_to_string(path)?;
    let mut last = None;
    let mut count = 0usize;
    for line in text.lines().filter(|line| !line.trim().is_empty()) {
        count += 1;
        if count > MAX_JOURNAL_ENTRIES {
            return Err(MaintenanceError::JournalInvalid);
        }
        let entry: JournalEntry = serde_json::from_str(line)?;
        if entry.request_id != plan.request_id
            || !same_path(&entry.target_executable, target)
            || !same_path(&entry.staged_executable, staged)
            || !same_path(&entry.backup_executable, backup)
            || !same_path(&entry.temp_executable, temp)
            || !entry
                .expected_current_sha256
                .eq_ignore_ascii_case(&plan.expected_current_sha256)
            || !entry
                .expected_staged_sha256
                .eq_ignore_ascii_case(&plan.expected_staged_sha256)
        {
            return Err(MaintenanceError::JournalInvalid);
        }
        last = Some(entry.state);
    }
    if last.is_none() {
        return Err(MaintenanceError::JournalInvalid);
    }
    Ok(last)
}

fn read_result_status(path: &Path, root: &Path) -> Result<Option<String>, MaintenanceError> {
    if !path.exists() {
        return Ok(None);
    }
    let canonical = fs::canonicalize(path)?;
    ensure_within(&canonical, root)?;
    let metadata = fs::metadata(&canonical)?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > MAX_RESULT_BYTES {
        return Err(MaintenanceError::ResultInvalid);
    }
    let value: serde_json::Value = serde_json::from_slice(&fs::read(canonical)?)?;
    let status = value
        .get("status")
        .and_then(serde_json::Value::as_str)
        .ok_or(MaintenanceError::ResultInvalid)?;
    if status.is_empty() || status.len() > 64 {
        return Err(MaintenanceError::ResultInvalid);
    }
    Ok(Some(status.to_owned()))
}

pub fn sha256_file(path: impl AsRef<Path>) -> Result<String, MaintenanceError> {
    let bytes = fs::read(path)?;
    Ok(hex::encode(Sha256::digest(bytes)))
}

pub fn verify_file_sha256(path: impl AsRef<Path>, expected: &str) -> Result<(), MaintenanceError> {
    let expected = normalize_sha256(expected)?;
    let actual = sha256_file(path)?;
    if actual != expected {
        return Err(MaintenanceError::DigestMismatch { expected, actual });
    }
    Ok(())
}

pub fn verify_plan_file_sha256(
    path: impl AsRef<Path>,
    expected: &str,
) -> Result<(), MaintenanceError> {
    verify_file_sha256(path, expected)
}

fn validate_plan_shape(plan: &UpdatePlan) -> Result<(), MaintenanceError> {
    if plan.schema != UPDATE_PLAN_SCHEMA
        || !valid_request_id(&plan.request_id)
        || plan.current_pid == 0
        || !plan.allowed_root.is_absolute()
        || !plan.target_executable.is_absolute()
        || !plan.staged_executable.is_absolute()
        || !plan.journal_directory.is_absolute()
        || !plan.result_file.is_absolute()
        || !plan.restart.working_directory.is_absolute()
        || !plan.restart.stdout_log.is_absolute()
        || !plan.restart.stderr_log.is_absolute()
    {
        return Err(MaintenanceError::InvalidPlan);
    }
    reject_relative_components(&plan.allowed_root)?;
    reject_relative_components(&plan.target_executable)?;
    reject_relative_components(&plan.staged_executable)?;
    reject_relative_components(&plan.journal_directory)?;
    reject_relative_components(&plan.result_file)?;
    reject_relative_components(&plan.restart.working_directory)?;
    reject_relative_components(&plan.restart.stdout_log)?;
    reject_relative_components(&plan.restart.stderr_log)?;

    normalize_sha256(&plan.expected_current_sha256)?;
    normalize_sha256(&plan.expected_staged_sha256)?;

    if plan.restart.args.len() > MAX_RESTART_ARGS
        || plan.restart.environment.len() > MAX_RESTART_ENV
        || plan.restart.health_wait_ms == 0
        || plan.restart.health_wait_ms > MAX_HEALTH_WAIT_MS
    {
        return Err(MaintenanceError::InvalidRestartSpec);
    }
    let mut total = 0usize;
    for argument in &plan.restart.args {
        if argument.contains(' ') || argument.len() > MAX_RESTART_ARG_BYTES {
            return Err(MaintenanceError::InvalidRestartSpec);
        }
        total = total
            .checked_add(argument.len())
            .ok_or(MaintenanceError::InvalidRestartSpec)?;
        if total > MAX_RESTART_TOTAL_ARG_BYTES {
            return Err(MaintenanceError::InvalidRestartSpec);
        }
    }
    for (key, value) in &plan.restart.environment {
        if key.trim().is_empty()
            || key.contains('=')
            || key.contains(' ')
            || value.contains(' ')
            || key.len() > 256
            || value.len() > 8192
        {
            return Err(MaintenanceError::InvalidRestartSpec);
        }
    }
    Ok(())
}

fn valid_request_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn normalize_sha256(value: &str) -> Result<String, MaintenanceError> {
    let value = value.trim();
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(MaintenanceError::InvalidDigest);
    }
    Ok(value.to_ascii_lowercase())
}

fn reject_relative_components(path: &Path) -> Result<(), MaintenanceError> {
    if path
        .components()
        .any(|part| matches!(part, Component::ParentDir | Component::CurDir))
    {
        return Err(MaintenanceError::UnsafePath);
    }
    Ok(())
}

fn canonical_file_within(path: &Path, root: &Path) -> Result<PathBuf, MaintenanceError> {
    let canonical = fs::canonicalize(path)?;
    if !canonical.is_file() {
        return Err(MaintenanceError::ExpectedFile);
    }
    ensure_within(&canonical, root)?;
    Ok(canonical)
}

fn canonical_directory_within(path: &Path, root: &Path) -> Result<PathBuf, MaintenanceError> {
    let canonical = fs::canonicalize(path)?;
    if !canonical.is_dir() {
        return Err(MaintenanceError::ExpectedDirectory);
    }
    ensure_within(&canonical, root)?;
    Ok(canonical)
}

fn output_directory_within(path: &Path, root: &Path) -> Result<PathBuf, MaintenanceError> {
    ensure_output_path_within(path, root)?;
    Ok(path.to_path_buf())
}

fn output_path_within(path: &Path, root: &Path) -> Result<PathBuf, MaintenanceError> {
    ensure_output_path_within(path, root)?;
    Ok(path.to_path_buf())
}

fn ensure_output_path_within(path: &Path, root: &Path) -> Result<(), MaintenanceError> {
    reject_relative_components(path)?;
    if !path.is_absolute() {
        return Err(MaintenanceError::UnsafePath);
    }
    let mut existing = path;
    while !existing.exists() {
        existing = existing.parent().ok_or(MaintenanceError::UnsafePath)?;
    }
    let canonical_existing = fs::canonicalize(existing)?;
    ensure_within(&canonical_existing, root)
}

fn ensure_within(path: &Path, root: &Path) -> Result<(), MaintenanceError> {
    if path_within(path, root) {
        Ok(())
    } else {
        Err(MaintenanceError::OutsideAllowedRoot)
    }
}

#[cfg(windows)]
fn path_within(path: &Path, root: &Path) -> bool {
    let path = path
        .to_string_lossy()
        .replace('/', "\\")
        .to_ascii_lowercase();
    let root = root
        .to_string_lossy()
        .replace('/', "\\")
        .to_ascii_lowercase();
    path == root
        || path
            .strip_prefix(&root)
            .is_some_and(|suffix| suffix.starts_with('\\'))
}

#[cfg(not(windows))]
fn path_within(path: &Path, root: &Path) -> bool {
    path == root || path.starts_with(root)
}

#[cfg(windows)]
fn same_path(left: &Path, right: &Path) -> bool {
    left.to_string_lossy()
        .eq_ignore_ascii_case(&right.to_string_lossy())
}

#[cfg(not(windows))]
fn same_path(left: &Path, right: &Path) -> bool {
    left == right
}

fn copy_synced(source: &Path, destination: &Path) -> Result<(), MaintenanceError> {
    let mut input = File::open(source)?;
    let mut output = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(destination)?;
    io::copy(&mut input, &mut output)?;
    output.sync_all()?;
    Ok(())
}

fn rollback_paths(update: &ValidatedUpdate) -> Result<(), MaintenanceError> {
    if !update.backup.is_file() {
        return Err(MaintenanceError::BackupMissing);
    }
    if update.target.exists() {
        fs::remove_file(&update.target)?;
    }
    fs::rename(&update.backup, &update.target)?;
    let _ = fs::remove_file(&update.temp);
    verify_file_sha256(&update.target, &update.plan.expected_current_sha256)
}

fn append_journal(
    update: &ValidatedUpdate,
    state: JournalState,
    create_new: bool,
) -> Result<(), MaintenanceError> {
    create_parent(&update.journal)?;
    let mut options = OpenOptions::new();
    options.write(true);
    if create_new {
        options.create_new(true);
    } else {
        options.create(true).append(true);
    }
    let mut file = options.open(&update.journal)?;
    let entry = JournalEntry {
        request_id: update.plan.request_id.clone(),
        state,
        target_executable: update.target.clone(),
        staged_executable: update.staged.clone(),
        backup_executable: update.backup.clone(),
        temp_executable: update.temp.clone(),
        expected_current_sha256: update.plan.expected_current_sha256.to_ascii_lowercase(),
        expected_staged_sha256: update.plan.expected_staged_sha256.to_ascii_lowercase(),
    };
    serde_json::to_writer(&mut file, &entry)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    Ok(())
}

fn create_parent(path: &Path) -> Result<(), MaintenanceError> {
    let parent = path.parent().ok_or(MaintenanceError::UnsafePath)?;
    fs::create_dir_all(parent)?;
    Ok(())
}

#[derive(Debug, Error)]
pub enum MaintenanceError {
    #[error("maintenance plan is invalid")]
    InvalidPlan,
    #[error("maintenance root is invalid")]
    InvalidRoot,
    #[error("maintenance path is unsafe")]
    UnsafePath,
    #[error("maintenance path escapes allowed root")]
    OutsideAllowedRoot,
    #[error("maintenance expected a regular file")]
    ExpectedFile,
    #[error("maintenance expected a directory")]
    ExpectedDirectory,
    #[error("maintenance SHA-256 digest is invalid")]
    InvalidDigest,
    #[error("maintenance restart specification is invalid")]
    InvalidRestartSpec,
    #[error("maintenance digest mismatch: expected {expected}, got {actual}")]
    DigestMismatch { expected: String, actual: String },
    #[error("maintenance journal already exists")]
    JournalExists,
    #[error("maintenance journal is invalid or inconsistent with the plan")]
    JournalInvalid,
    #[error("maintenance result file is invalid")]
    ResultInvalid,
    #[error("maintenance transaction state is invalid")]
    InvalidState,
    #[error("maintenance staging path already exists")]
    StagingCollision,
    #[error("maintenance rollback backup is missing")]
    BackupMissing,
    #[error("maintenance swap failed and rollback also failed: swap={swap}; rollback={rollback}")]
    SwapAndRollbackFailed { swap: String, rollback: String },
    #[error(
        "maintenance post-swap verification failed and rollback also failed: verification={verification}; rollback={rollback}"
    )]
    PostSwapAndRollbackFailed {
        verification: String,
        rollback: String,
    },
    #[error("maintenance I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error("maintenance JSON failed: {0}")]
    Json(#[from] serde_json::Error),
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn plan(root: &Path, target: &Path, staged: &Path, request_id: &str) -> UpdatePlan {
        UpdatePlan {
            schema: UPDATE_PLAN_SCHEMA,
            request_id: request_id.into(),
            allowed_root: root.to_path_buf(),
            target_executable: target.to_path_buf(),
            staged_executable: staged.to_path_buf(),
            expected_current_sha256: sha256_file(target).unwrap(),
            expected_staged_sha256: sha256_file(staged).unwrap(),
            journal_directory: root.join("state").join("maintenance").join("journal"),
            result_file: root.join("state").join("maintenance").join("result.json"),
            current_pid: 123,
            restart: RestartSpec {
                args: vec!["private-run".into(), "--device".into(), "device-1".into()],
                environment: BTreeMap::new(),
                working_directory: root.to_path_buf(),
                stdout_log: root.join("state").join("maintenance").join("agent.out.log"),
                stderr_log: root.join("state").join("maintenance").join("agent.err.log"),
                health_wait_ms: 1_000,
            },
        }
    }

    #[test]
    fn swap_commit_preserves_verified_backup() {
        let root = tempdir().unwrap();
        let target = root.path().join("vor-agent.exe");
        let staged = root.path().join("staged.exe");
        fs::write(&target, b"old-agent").unwrap();
        fs::write(&staged, b"new-agent").unwrap();

        let mut tx =
            MaintenanceTransaction::begin(plan(root.path(), &target, &staged, "update-1")).unwrap();
        tx.swap().unwrap();
        assert_eq!(fs::read(&target).unwrap(), b"new-agent");
        assert_eq!(fs::read(&tx.update().backup).unwrap(), b"old-agent");
        tx.commit().unwrap();
        assert_eq!(tx.state(), JournalState::Committed);

        let journal = fs::read_to_string(&tx.update().journal).unwrap();
        assert!(journal.contains("\"state\":\"validated\""));
        assert!(journal.contains("\"state\":\"swapped\""));
        assert!(journal.contains("\"state\":\"committed\""));
    }

    #[test]
    fn rollback_restores_previous_binary() {
        let root = tempdir().unwrap();
        let target = root.path().join("vor-agent.exe");
        let staged = root.path().join("staged.exe");
        fs::write(&target, b"old-agent").unwrap();
        fs::write(&staged, b"new-agent").unwrap();

        let mut tx =
            MaintenanceTransaction::begin(plan(root.path(), &target, &staged, "update-2")).unwrap();
        tx.swap().unwrap();
        tx.rollback().unwrap();
        assert_eq!(fs::read(&target).unwrap(), b"old-agent");
        assert!(!tx.update().backup.exists());
        assert_eq!(tx.state(), JournalState::RolledBack);
    }

    #[test]
    fn stale_current_digest_fails_before_swap() {
        let root = tempdir().unwrap();
        let target = root.path().join("vor-agent.exe");
        let staged = root.path().join("staged.exe");
        fs::write(&target, b"old-agent").unwrap();
        fs::write(&staged, b"new-agent").unwrap();
        let mut update = plan(root.path(), &target, &staged, "update-3");
        update.expected_current_sha256 = "00".repeat(32);

        assert!(matches!(
            MaintenanceTransaction::begin(update),
            Err(MaintenanceError::DigestMismatch { .. })
        ));
        assert_eq!(fs::read(&target).unwrap(), b"old-agent");
    }

    #[test]
    fn staged_mutation_after_begin_is_detected() {
        let root = tempdir().unwrap();
        let target = root.path().join("vor-agent.exe");
        let staged = root.path().join("staged.exe");
        fs::write(&target, b"old-agent").unwrap();
        fs::write(&staged, b"new-agent").unwrap();

        let mut tx =
            MaintenanceTransaction::begin(plan(root.path(), &target, &staged, "update-4")).unwrap();
        fs::write(&staged, b"tampered").unwrap();
        assert!(matches!(
            tx.swap(),
            Err(MaintenanceError::DigestMismatch { .. })
        ));
        assert_eq!(fs::read(&target).unwrap(), b"old-agent");
    }

    #[test]
    fn paths_outside_root_are_rejected() {
        let root = tempdir().unwrap();
        let outside = tempdir().unwrap();
        let target = root.path().join("vor-agent.exe");
        let staged = outside.path().join("staged.exe");
        fs::write(&target, b"old-agent").unwrap();
        fs::write(&staged, b"new-agent").unwrap();

        assert!(matches!(
            MaintenanceTransaction::begin(plan(root.path(), &target, &staged, "update-5")),
            Err(MaintenanceError::OutsideAllowedRoot)
        ));
    }

    #[test]
    fn recover_restores_backup_conservatively() {
        let root = tempdir().unwrap();
        let target = root.path().join("vor-agent.exe");
        let staged = root.path().join("staged.exe");
        fs::write(&target, b"old-agent").unwrap();
        fs::write(&staged, b"new-agent").unwrap();
        let update = plan(root.path(), &target, &staged, "update-6");
        let mut tx = MaintenanceTransaction::begin(update.clone()).unwrap();
        tx.swap().unwrap();
        drop(tx);

        let recovered = recover_previous(update).unwrap();
        assert_eq!(fs::read(&recovered.target).unwrap(), b"old-agent");
        assert!(!recovered.backup.exists());
    }

    #[test]
    fn recovery_rejects_mutated_backup_before_target_replacement() {
        let root = tempdir().unwrap();
        let target = root.path().join("vor-agent.exe");
        let staged = root.path().join("staged.exe");
        fs::write(&target, b"old-agent").unwrap();
        fs::write(&staged, b"new-agent").unwrap();
        let update = plan(root.path(), &target, &staged, "update-7");
        let mut tx = MaintenanceTransaction::begin(update.clone()).unwrap();
        tx.swap().unwrap();
        let backup = tx.update().backup.clone();
        drop(tx);

        fs::write(&backup, b"tampered-backup").unwrap();
        let before = fs::read(&target).unwrap();
        assert!(matches!(
            validate_recovery_plan(update.clone()),
            Err(MaintenanceError::DigestMismatch { .. })
        ));
        assert!(matches!(
            recover_previous(update),
            Err(MaintenanceError::DigestMismatch { .. })
        ));
        assert_eq!(fs::read(&target).unwrap(), before);
    }

    #[test]
    fn inspection_tracks_ready_validated_swapped_committed_and_rolled_back() {
        let root = tempdir().unwrap();
        let target = root.path().join("vor-agent.exe");
        let staged = root.path().join("staged.exe");
        fs::write(&target, b"old-agent").unwrap();
        fs::write(&staged, b"new-agent").unwrap();

        let commit_plan = plan(root.path(), &target, &staged, "inspect-commit");
        let ready = inspect_plan(commit_plan.clone()).unwrap();
        assert_eq!(ready.observed_state, MaintenanceObservedState::Ready);
        assert_eq!(ready.journal_state, None);
        assert!(ready.target_matches_current);
        assert!(ready.staged_matches_expected);

        let mut tx = MaintenanceTransaction::begin(commit_plan.clone()).unwrap();
        let validated = inspect_plan(commit_plan.clone()).unwrap();
        assert_eq!(
            validated.observed_state,
            MaintenanceObservedState::Validated
        );
        assert_eq!(validated.journal_state, Some(JournalState::Validated));

        tx.swap().unwrap();
        let swapped = inspect_plan(commit_plan.clone()).unwrap();
        assert_eq!(swapped.observed_state, MaintenanceObservedState::Swapped);
        assert_eq!(swapped.journal_state, Some(JournalState::Swapped));
        assert!(swapped.target_matches_staged);
        assert!(swapped.backup_matches_current);

        tx.commit().unwrap();
        let result_parent = commit_plan.result_file.parent().unwrap();
        fs::create_dir_all(result_parent).unwrap();
        fs::write(&commit_plan.result_file, br#"{"status":"committed"}"#).unwrap();
        let committed = inspect_plan(commit_plan.clone()).unwrap();
        assert_eq!(
            committed.observed_state,
            MaintenanceObservedState::Committed
        );
        assert_eq!(committed.journal_state, Some(JournalState::Committed));
        assert_eq!(committed.result_status.as_deref(), Some("committed"));

        // Restore the old bytes using the committed backup so a second,
        // independent transaction can prove the rolled-back classification.
        fs::remove_file(&target).unwrap();
        fs::rename(tx.update().backup.clone(), &target).unwrap();
        fs::remove_file(&commit_plan.result_file).unwrap();

        let rollback_plan = plan(root.path(), &target, &staged, "inspect-rollback");
        let mut rollback = MaintenanceTransaction::begin(rollback_plan.clone()).unwrap();
        rollback.swap().unwrap();
        rollback.rollback().unwrap();
        let rolled_back = inspect_plan(rollback_plan).unwrap();
        assert_eq!(
            rolled_back.observed_state,
            MaintenanceObservedState::RolledBack
        );
        assert_eq!(rolled_back.journal_state, Some(JournalState::RolledBack));
        assert!(rolled_back.target_matches_current);
        assert!(!rolled_back.backup_exists);
    }

    #[test]
    fn inspection_reports_inconsistent_material_and_rejects_tampered_journal() {
        let root = tempdir().unwrap();
        let target = root.path().join("vor-agent.exe");
        let staged = root.path().join("staged.exe");
        fs::write(&target, b"old-agent").unwrap();
        fs::write(&staged, b"new-agent").unwrap();

        let update = plan(root.path(), &target, &staged, "inspect-inconsistent");
        let transaction = MaintenanceTransaction::begin(update.clone()).unwrap();
        fs::write(&target, b"unexpected-target").unwrap();
        let inspection = inspect_plan(update.clone()).unwrap();
        assert_eq!(
            inspection.observed_state,
            MaintenanceObservedState::Inconsistent
        );
        assert_eq!(inspection.journal_state, Some(JournalState::Validated));
        drop(transaction);

        let journal = update
            .journal_directory
            .join(format!("{}.jsonl", update.request_id));
        let mut entry: JournalEntry =
            serde_json::from_str(fs::read_to_string(&journal).unwrap().trim()).unwrap();
        entry.request_id = "tampered-request".into();
        fs::write(&journal, serde_json::to_vec(&entry).unwrap()).unwrap();
        assert!(matches!(
            inspect_plan(update),
            Err(MaintenanceError::JournalInvalid)
        ));
    }

    #[test]
    fn plan_file_hash_is_enforced() {
        let root = tempdir().unwrap();
        let path = root.path().join("plan.json");
        fs::write(&path, b"{\"schema\":1}").unwrap();
        let digest = sha256_file(&path).unwrap();
        verify_plan_file_sha256(&path, &digest).unwrap();
        assert!(matches!(
            verify_plan_file_sha256(&path, &"00".repeat(32)),
            Err(MaintenanceError::DigestMismatch { .. })
        ));
    }
}
