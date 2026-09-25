// SPDX-License-Identifier: MPL-2.0

use encoding_rs::WINDOWS_1252;
use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use thiserror::Error;
use vor_core::{Authorization, ExecutionAuthorization};
use vor_protocol::PolicyDecisionKind;

#[cfg(windows)]
use std::os::windows::{ffi::OsStrExt, fs::MetadataExt};
#[cfg(windows)]
use windows_sys::Win32::Storage::FileSystem::{
    MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW,
};

#[cfg(windows)]
const REPARSE_POINT_ATTRIBUTE: u32 = 0x400;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JournalState {
    Prepared,
    Replaced,
    Committed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JournalRecord {
    pub transaction_id: String,
    pub request_id: String,
    pub target: String,
    pub temp_path: String,
    pub backup_path: Option<String>,
    pub content_sha256: String,
    pub state: JournalState,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriteReceipt {
    pub target: PathBuf,
    pub backup_path: Option<PathBuf>,
    pub journal_path: PathBuf,
    pub content_sha256: String,
}

// Device-enforced ceilings: callers may request smaller values but cannot expand these budgets.
pub const MAX_LIST_DEPTH: usize = 16;
pub const MAX_LIST_ENTRIES: usize = 10_000;
pub const MAX_SEARCH_RESULTS: usize = 10_000;
pub const MAX_CONTENT_MATCHES: usize = 10_000;
pub const MAX_SEARCH_FILE_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_SEARCH_DURATION: Duration = Duration::from_secs(5);
pub const MAX_LINE_TEXT_BYTES: usize = 4 * 1024;
pub const MAX_EDIT_FILE_BYTES: usize = 1024 * 1024;
pub const MAX_EDITS: usize = 20;
pub const MAX_DIFF_SUMMARY_BYTES: usize = 32 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TextEdit {
    pub old_text: String,
    pub new_text: String,
    #[serde(default = "default_expected_occurrences")]
    pub expected_occurrences: usize,
}

fn default_expected_occurrences() -> usize {
    1
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedEdit {
    pub content: Vec<u8>,
    pub original_sha256: String,
    pub diff_summary: String,
    pub diff_truncated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DirectoryEntry {
    pub path: String,
    pub name: String,
    pub entry_type: String,
    pub size: u64,
    pub mtime_unix_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FileInfo {
    pub path: String,
    pub entry_type: String,
    pub size: u64,
    pub created_unix_ms: Option<u64>,
    pub modified_unix_ms: Option<u64>,
    pub accessed_unix_ms: Option<u64>,
    pub read_only: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ContentMatch {
    pub file: String,
    pub encoding: String,
    pub line: usize,
    /// One-based byte offset in the decoded UTF-8 line. For UTF-16 input this is
    /// not a source-file byte offset or UTF-16 code-unit offset.
    pub column: usize,
    pub line_text: String,
    pub truncated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ContentSearchResult {
    pub matches: Vec<ContentMatch>,
    pub skipped_binary_files: usize,
    pub skipped_size_limit_files: usize,
}

pub struct FsWorker {
    allowed_roots: Vec<PathBuf>,
    journal_dir: PathBuf,
}

impl FsWorker {
    pub fn prepare_edit(
        &self,
        authorization: &Authorization,
        edits: &[TextEdit],
    ) -> Result<PreparedEdit, FsError> {
        ensure_approval_action(authorization, "filesystem.write")?;
        if edits.is_empty()
            || edits.len() > MAX_EDITS
            || edits
                .iter()
                .any(|edit| edit.old_text.is_empty() || edit.expected_occurrences == 0)
        {
            return Err(FsError::InvalidEditParameters);
        }
        let target = self.resolve_existing(Path::new(&authorization.request.envelope.target))?;
        let original = fs::read(&target)?;
        let decoded = decode_edit_text(&original)?;
        let newline = detected_newline(&decoded.text);
        let mut edited = decoded.text.clone();
        for (index, edit) in edits.iter().enumerate() {
            let old_text = normalize_newlines(&edit.old_text, newline);
            let new_text = normalize_newlines(&edit.new_text, newline);
            let actual = edited.matches(&old_text).count();
            if actual != edit.expected_occurrences {
                let closest_line = (actual == 0).then(|| closest_line(&edited, &old_text));
                return Err(FsError::OccurrenceMismatch {
                    edit_index: index,
                    expected: edit.expected_occurrences,
                    actual,
                    closest_line,
                });
            }
            edited = edited.replace(&old_text, &new_text);
        }
        let content = encode_edit_text(&edited, decoded.encoding)?;
        if content.len() > MAX_EDIT_FILE_BYTES {
            return Err(FsError::EditResultTooLarge(content.len()));
        }
        let (diff_summary, diff_truncated) = unified_diff_summary(&decoded.text, &edited);
        Ok(PreparedEdit {
            content,
            original_sha256: sha256_hex(&original),
            diff_summary,
            diff_truncated,
        })
    }

    pub fn new(
        allowed_roots: impl IntoIterator<Item = PathBuf>,
        journal_dir: impl Into<PathBuf>,
    ) -> Result<Self, FsError> {
        let mut roots = Vec::new();
        for root in allowed_roots {
            ensure_no_parent_dir(&root)?;
            reject_reparse_components(&root)?;
            roots.push(fs::canonicalize(root)?);
        }
        if roots.is_empty() {
            return Err(FsError::NoAllowedRoots);
        }
        let journal_dir = journal_dir.into();
        fs::create_dir_all(&journal_dir)?;
        reject_reparse_components(&journal_dir)?;
        Ok(Self {
            allowed_roots: roots,
            journal_dir: fs::canonicalize(journal_dir)?,
        })
    }

    pub fn read(&self, authorization: &Authorization) -> Result<Vec<u8>, FsError> {
        self.read_limited(authorization, usize::MAX)
    }

    pub fn read_limited(
        &self,
        authorization: &Authorization,
        max_bytes: usize,
    ) -> Result<Vec<u8>, FsError> {
        ensure_auto_action(authorization, "filesystem.read")?;
        let target = self.resolve_existing(Path::new(&authorization.request.envelope.target))?;
        let len = fs::metadata(&target)?.len();
        if len > max_bytes as u64 {
            return Err(FsError::ReadLimitExceeded { len, max_bytes });
        }
        Ok(fs::read(target)?)
    }

    pub fn read_range(
        &self,
        authorization: &Authorization,
        offset: u64,
        length: usize,
        max_bytes: usize,
    ) -> Result<Vec<u8>, FsError> {
        ensure_auto_action(authorization, "filesystem.read")?;
        if length > max_bytes {
            return Err(FsError::ReadLimitExceeded {
                len: length as u64,
                max_bytes,
            });
        }
        let target = self.resolve_existing(Path::new(&authorization.request.envelope.target))?;
        let mut file = fs::File::open(target)?;
        file.seek(SeekFrom::Start(offset))?;
        let mut output = Vec::new();
        file.take(length as u64).read_to_end(&mut output)?;
        Ok(output)
    }

    pub fn read_lines(
        &self,
        authorization: &Authorization,
        line_start: usize,
        line_count: usize,
        max_bytes: usize,
    ) -> Result<Vec<u8>, FsError> {
        ensure_auto_action(authorization, "filesystem.read")?;
        if line_start == 0 {
            return Err(FsError::InvalidParameters);
        }
        let target = self.resolve_existing(Path::new(&authorization.request.envelope.target))?;
        let bytes = fs::read(target)?;
        let mut output = Vec::new();
        for line in bytes
            .split_inclusive(|byte| *byte == b'\n')
            .skip(line_start - 1)
            .take(line_count)
        {
            if output.len().saturating_add(line.len()) > max_bytes {
                return Err(FsError::ReadLimitExceeded {
                    len: output.len().saturating_add(line.len()) as u64,
                    max_bytes,
                });
            }
            output.extend_from_slice(line);
        }
        Ok(output)
    }

    pub fn list_directory(
        &self,
        authorization: &Authorization,
        depth: usize,
        max_entries: usize,
    ) -> Result<Vec<DirectoryEntry>, FsError> {
        ensure_auto_action(authorization, "filesystem.list")?;
        if depth > MAX_LIST_DEPTH || max_entries == 0 || max_entries > MAX_LIST_ENTRIES {
            return Err(FsError::InvalidParameters);
        }
        let root = self.resolve_existing(Path::new(&authorization.request.envelope.target))?;
        if !fs::metadata(&root)?.is_dir() {
            return Err(FsError::UnsafePath);
        }
        let mut output = Vec::new();
        self.walk_safe(&root, depth, &mut |path, metadata| {
            if output.len() >= max_entries {
                return Ok(false);
            }
            output.push(DirectoryEntry {
                path: path.to_string_lossy().into_owned(),
                name: path
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .into_owned(),
                entry_type: if metadata.is_dir() {
                    "directory"
                } else if metadata.is_file() {
                    "file"
                } else {
                    "other"
                }
                .into(),
                size: metadata.len(),
                mtime_unix_ms: system_time_ms(metadata.modified().ok()),
            });
            Ok(output.len() < max_entries)
        })?;
        Ok(output)
    }

    pub fn search_files(
        &self,
        authorization: &Authorization,
        pattern: &str,
        max_results: usize,
    ) -> Result<Vec<String>, FsError> {
        ensure_auto_action(authorization, "filesystem.search_files")?;
        if max_results == 0 || max_results > MAX_SEARCH_RESULTS {
            return Err(FsError::InvalidParameters);
        }
        let root = self.resolve_existing(Path::new(&authorization.request.envelope.target))?;
        let matcher = glob_regex(pattern)?;
        let started = Instant::now();
        let mut output = Vec::new();
        self.walk_safe(&root, MAX_LIST_DEPTH, &mut |path, metadata| {
            if started.elapsed() > MAX_SEARCH_DURATION {
                return Err(FsError::SearchTimeout);
            }
            let relative = path
                .strip_prefix(&root)
                .unwrap_or(path)
                .to_string_lossy()
                .replace('\\', "/");
            if metadata.is_file() && matcher.is_match(&relative) {
                output.push(path.to_string_lossy().into_owned());
            }
            Ok(output.len() < max_results)
        })?;
        Ok(output)
    }

    pub fn search_content(
        &self,
        authorization: &Authorization,
        query: &str,
        regex: bool,
        file_glob: &str,
        max_matches: usize,
        max_file_bytes: usize,
    ) -> Result<ContentSearchResult, FsError> {
        self.search_content_with_timeout(
            authorization,
            query,
            regex,
            file_glob,
            max_matches,
            max_file_bytes,
            MAX_SEARCH_DURATION,
        )
    }

    fn search_content_with_timeout(
        &self,
        authorization: &Authorization,
        query: &str,
        regex: bool,
        file_glob: &str,
        max_matches: usize,
        max_file_bytes: usize,
        timeout: Duration,
    ) -> Result<ContentSearchResult, FsError> {
        ensure_auto_action(authorization, "filesystem.search_content")?;
        if query.is_empty()
            || max_matches == 0
            || max_matches > MAX_CONTENT_MATCHES
            || max_file_bytes == 0
            || max_file_bytes > MAX_SEARCH_FILE_BYTES
        {
            return Err(FsError::InvalidParameters);
        }
        let root = self.resolve_existing(Path::new(&authorization.request.envelope.target))?;
        let file_matcher = glob_regex(file_glob)?;
        let query_regex = if regex {
            Some(Regex::new(query).map_err(|_| FsError::InvalidPattern)?)
        } else {
            None
        };
        let started = Instant::now();
        let mut output = Vec::new();
        let mut skipped_binary_files = 0;
        let mut skipped_size_limit_files = 0;
        self.walk_safe(&root, MAX_LIST_DEPTH, &mut |path, metadata| {
            if started.elapsed() >= timeout {
                return Err(FsError::SearchTimeout);
            }
            if !metadata.is_file() {
                return Ok(true);
            }
            let relative = path
                .strip_prefix(&root)
                .unwrap_or(path)
                .to_string_lossy()
                .replace('\\', "/");
            if !file_matcher.is_match(&relative) {
                return Ok(true);
            }
            if metadata.len() > max_file_bytes as u64 {
                skipped_size_limit_files += 1;
                return Ok(true);
            }
            let bytes = fs::read(path)?;
            let decoded = match decode_search_text(&bytes) {
                Some(value) => value,
                None => {
                    skipped_binary_files += 1;
                    return Ok(true);
                }
            };
            for (index, line) in decoded.text.lines().enumerate() {
                let columns: Vec<usize> = if let Some(re) = &query_regex {
                    re.find_iter(line).map(|item| item.start()).collect()
                } else {
                    line.match_indices(query)
                        .map(|(column, _)| column)
                        .collect()
                };
                for column in columns {
                    let (line_text, truncated) = truncate_utf8(line, MAX_LINE_TEXT_BYTES);
                    output.push(ContentMatch {
                        file: path.to_string_lossy().into_owned(),
                        encoding: decoded.encoding.into(),
                        line: index + 1,
                        column: column + 1,
                        line_text,
                        truncated,
                    });
                    if output.len() >= max_matches {
                        return Ok(false);
                    }
                }
            }
            Ok(true)
        })?;
        Ok(ContentSearchResult {
            matches: output,
            skipped_binary_files,
            skipped_size_limit_files,
        })
    }

    pub fn file_info(&self, authorization: &Authorization) -> Result<FileInfo, FsError> {
        ensure_auto_action(authorization, "filesystem.info")?;
        let path = self.resolve_existing(Path::new(&authorization.request.envelope.target))?;
        let metadata = fs::metadata(&path)?;
        Ok(FileInfo {
            path: path.to_string_lossy().into_owned(),
            entry_type: if metadata.is_dir() {
                "directory"
            } else if metadata.is_file() {
                "file"
            } else {
                "other"
            }
            .into(),
            size: metadata.len(),
            created_unix_ms: system_time_ms(metadata.created().ok()),
            modified_unix_ms: system_time_ms(metadata.modified().ok()),
            accessed_unix_ms: system_time_ms(metadata.accessed().ok()),
            read_only: metadata.permissions().readonly(),
        })
    }

    fn walk_safe(
        &self,
        root: &Path,
        depth: usize,
        visitor: &mut impl FnMut(&Path, &fs::Metadata) -> Result<bool, FsError>,
    ) -> Result<(), FsError> {
        let mut pending = vec![(root.to_path_buf(), 0usize)];
        while let Some((directory, level)) = pending.pop() {
            if level >= depth {
                continue;
            }
            let mut entries = fs::read_dir(directory)?.collect::<Result<Vec<_>, _>>()?;
            entries.sort_by_key(|entry| entry.file_name());
            for entry in entries {
                let path = entry.path();
                let metadata = fs::symlink_metadata(&path)?;
                if is_link_or_reparse(&metadata) {
                    continue;
                }
                let resolved = fs::canonicalize(&path)?;
                self.ensure_allowed(&resolved)?;
                if !visitor(&resolved, &metadata)? {
                    return Ok(());
                }
                if metadata.is_dir() {
                    pending.push((resolved, level + 1));
                }
            }
        }
        Ok(())
    }

    pub fn write(
        &self,
        authorization: &Authorization,
        content: &[u8],
    ) -> Result<WriteReceipt, FsError> {
        ensure_auto_action(authorization, "filesystem.write")?;
        self.write_inner(authorization, content, false)
    }

    pub fn write_approved(
        &self,
        execution: &ExecutionAuthorization,
        content: &[u8],
    ) -> Result<WriteReceipt, FsError> {
        let authorization = execution.authorization();
        ensure_approved_action(authorization, "filesystem.write")?;
        self.write_inner(authorization, content, true)
    }

    fn write_inner(
        &self,
        authorization: &Authorization,
        content: &[u8],
        require_target_precondition: bool,
    ) -> Result<WriteReceipt, FsError> {
        let expected = required_content_digest(authorization)?;
        let actual = sha256_hex(content);
        if !expected.eq_ignore_ascii_case(&actual) {
            return Err(FsError::ContentDigestMismatch);
        }

        let target =
            self.resolve_write_target(Path::new(&authorization.request.envelope.target))?;
        let target_precondition = if require_target_precondition {
            Some(required_target_precondition(authorization)?)
        } else {
            None
        };
        if let Some(precondition) = &target_precondition {
            verify_target_precondition(&target, precondition)?;
        }

        let parent = target.parent().ok_or(FsError::UnsafePath)?;
        let transaction_id = authorization.request.digest_hex();
        let short_id = &transaction_id[..16];
        let temp_path = parent.join(format!(".vor-{short_id}.tmp"));
        let journal_path = self.journal_dir.join(format!("{transaction_id}.json"));
        let backup_path = if target.exists() {
            Some(self.journal_dir.join(format!("{transaction_id}.bak")))
        } else {
            None
        };

        if temp_path.exists() || journal_path.exists() {
            return Err(FsError::TransactionExists);
        }

        let mut temp = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temp_path)?;
        temp.write_all(content)?;
        temp.sync_all()?;
        drop(temp);

        if let Some(precondition) = &target_precondition
            && let Err(error) = verify_target_precondition(&target, precondition)
        {
            let _ = fs::remove_file(&temp_path);
            return Err(error);
        }

        if let Some(backup) = &backup_path {
            fs::copy(&target, backup)?;
            OpenOptions::new().write(true).open(backup)?.sync_all()?;
        }

        let mut record = JournalRecord {
            transaction_id: transaction_id.clone(),
            request_id: authorization.request.envelope.request_id.clone(),
            target: target.to_string_lossy().into_owned(),
            temp_path: temp_path.to_string_lossy().into_owned(),
            backup_path: backup_path
                .as_ref()
                .map(|path| path.to_string_lossy().into_owned()),
            content_sha256: actual.clone(),
            state: JournalState::Prepared,
        };
        self.persist_journal(&journal_path, &record)?;
        atomic_replace(&temp_path, &target)?;

        record.state = JournalState::Replaced;
        self.persist_journal(&journal_path, &record)?;
        if sha256_file(&target)? != actual {
            return Err(FsError::PostWriteVerificationFailed);
        }
        record.state = JournalState::Committed;
        self.persist_journal(&journal_path, &record)?;

        Ok(WriteReceipt {
            target,
            backup_path,
            journal_path,
            content_sha256: actual,
        })
    }

    pub fn pending_transactions(&self) -> Result<Vec<JournalRecord>, FsError> {
        let mut pending = Vec::new();
        for entry in fs::read_dir(&self.journal_dir)? {
            let path = entry?.path();
            if path.extension().and_then(|v| v.to_str()) != Some("json") {
                continue;
            }
            let record: JournalRecord = serde_json::from_slice(&fs::read(path)?)?;
            if record.state != JournalState::Committed {
                pending.push(record);
            }
        }
        Ok(pending)
    }

    fn resolve_existing(&self, target: &Path) -> Result<PathBuf, FsError> {
        ensure_no_parent_dir(target)?;
        reject_reparse_components(target)?;
        let resolved = fs::canonicalize(target)?;
        self.ensure_allowed(&resolved)?;
        Ok(resolved)
    }

    fn resolve_write_target(&self, target: &Path) -> Result<PathBuf, FsError> {
        ensure_no_parent_dir(target)?;
        reject_reparse_components(target)?;
        if target.exists() {
            if !fs::metadata(target)?.is_file() {
                return Err(FsError::UnsafePath);
            }
            return self.resolve_existing(target);
        }
        let parent = target.parent().ok_or(FsError::UnsafePath)?;
        let file_name = target.file_name().ok_or(FsError::UnsafePath)?;
        let resolved_parent = fs::canonicalize(parent)?;
        self.ensure_allowed(&resolved_parent)?;
        Ok(resolved_parent.join(file_name))
    }

    fn ensure_allowed(&self, path: &Path) -> Result<(), FsError> {
        if self
            .allowed_roots
            .iter()
            .any(|root| path_within(path, root))
        {
            Ok(())
        } else {
            Err(FsError::OutsideAllowedRoots)
        }
    }

    fn persist_journal(&self, path: &Path, record: &JournalRecord) -> Result<(), FsError> {
        let bytes = serde_json::to_vec(record)?;
        let temp = path.with_extension("json.tmp");
        let mut file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&temp)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        drop(file);
        atomic_replace(&temp, path)?;
        Ok(())
    }
}

fn ensure_auto_action(authorization: &Authorization, expected: &str) -> Result<(), FsError> {
    if authorization.request.envelope_digest != authorization.decision.envelope_digest
        || authorization.request.envelope.request_id != authorization.decision.request_id
    {
        return Err(FsError::AuthorizationMismatch);
    }
    match authorization.decision.kind {
        PolicyDecisionKind::Auto => {}
        PolicyDecisionKind::Approval => return Err(FsError::ApprovalRequired),
        PolicyDecisionKind::Deny => return Err(FsError::Denied),
    }
    if authorization.request.envelope.action != expected {
        return Err(FsError::WrongAction);
    }
    Ok(())
}

fn ensure_approved_action(authorization: &Authorization, expected: &str) -> Result<(), FsError> {
    if authorization.request.envelope_digest != authorization.decision.envelope_digest
        || authorization.request.envelope.request_id != authorization.decision.request_id
    {
        return Err(FsError::AuthorizationMismatch);
    }
    if authorization.decision.kind != PolicyDecisionKind::Approval {
        return Err(FsError::ApprovedExecutionRequired);
    }
    if authorization.request.envelope.action != expected {
        return Err(FsError::WrongAction);
    }
    Ok(())
}

fn ensure_approval_action(authorization: &Authorization, expected: &str) -> Result<(), FsError> {
    if authorization.request.envelope_digest != authorization.decision.envelope_digest
        || authorization.request.envelope.request_id != authorization.decision.request_id
    {
        return Err(FsError::AuthorizationMismatch);
    }
    if authorization.decision.kind != PolicyDecisionKind::Approval {
        return Err(FsError::ApprovedExecutionRequired);
    }
    if authorization.request.envelope.action != expected {
        return Err(FsError::WrongAction);
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum TargetPrecondition {
    Absent,
    Sha256(String),
}

fn required_target_precondition(
    authorization: &Authorization,
) -> Result<TargetPrecondition, FsError> {
    let value = authorization
        .request
        .envelope
        .parameters
        .get("expected_target_sha256")
        .and_then(|value| value.as_str())
        .ok_or(FsError::MissingTargetPrecondition)?;
    if value.eq_ignore_ascii_case("absent") {
        return Ok(TargetPrecondition::Absent);
    }
    if value.len() != 64 || hex::decode(value).map_or(true, |bytes| bytes.len() != 32) {
        return Err(FsError::InvalidTargetPrecondition);
    }
    Ok(TargetPrecondition::Sha256(value.to_ascii_lowercase()))
}

fn verify_target_precondition(
    target: &Path,
    precondition: &TargetPrecondition,
) -> Result<(), FsError> {
    match precondition {
        TargetPrecondition::Absent if !target.exists() => Ok(()),
        TargetPrecondition::Absent => Err(FsError::TargetPreconditionFailed),
        TargetPrecondition::Sha256(_) if !target.exists() => Err(FsError::TargetPreconditionFailed),
        TargetPrecondition::Sha256(expected) => {
            if sha256_file(target)?.eq_ignore_ascii_case(expected) {
                Ok(())
            } else {
                Err(FsError::TargetPreconditionFailed)
            }
        }
    }
}

fn required_content_digest(authorization: &Authorization) -> Result<String, FsError> {
    let value = authorization
        .request
        .envelope
        .parameters
        .get("content_sha256")
        .and_then(|value| value.as_str())
        .ok_or(FsError::MissingContentDigest)?;
    if value.len() != 64 || hex::decode(value).map_or(true, |bytes| bytes.len() != 32) {
        return Err(FsError::InvalidContentDigest);
    }
    Ok(value.to_ascii_lowercase())
}

fn sha256_hex(content: &[u8]) -> String {
    hex::encode(Sha256::digest(content))
}

fn sha256_file(path: &Path) -> Result<String, FsError> {
    Ok(sha256_hex(&fs::read(path)?))
}

fn ensure_no_parent_dir(path: &Path) -> Result<(), FsError> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::ParentDir))
    {
        return Err(FsError::UnsafePath);
    }
    Ok(())
}

fn path_within(path: &Path, root: &Path) -> bool {
    let normalize = |value: &Path| {
        value
            .to_string_lossy()
            .replace('/', "\\")
            .trim_end_matches('\\')
            .to_ascii_lowercase()
    };
    let path = normalize(path);
    let root = normalize(root);
    path == root || path.starts_with(&(root + "\\"))
}

fn reject_reparse_components(path: &Path) -> Result<(), FsError> {
    #[cfg(windows)]
    {
        let mut current = PathBuf::new();
        for component in path.components() {
            current.push(component.as_os_str());
            if !current.is_absolute() || !current.exists() {
                continue;
            }
            let metadata = fs::symlink_metadata(&current)?;
            if metadata.file_attributes() & REPARSE_POINT_ATTRIBUTE != 0 {
                return Err(FsError::ReparsePoint(current));
            }
        }
    }
    #[cfg(not(windows))]
    let _ = path;
    Ok(())
}

fn is_link_or_reparse(metadata: &fs::Metadata) -> bool {
    if metadata.file_type().is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        return metadata.file_attributes() & REPARSE_POINT_ATTRIBUTE != 0;
    }
    #[cfg(not(windows))]
    {
        false
    }
}

fn system_time_ms(value: Option<SystemTime>) -> Option<u64> {
    value?
        .duration_since(UNIX_EPOCH)
        .ok()?
        .as_millis()
        .try_into()
        .ok()
}

struct DecodedText {
    text: String,
    encoding: &'static str,
}

fn decode_edit_text(bytes: &[u8]) -> Result<DecodedText, FsError> {
    decode_search_text(bytes).ok_or(FsError::UnsupportedEditEncoding)
}

fn encode_edit_text(text: &str, encoding: &str) -> Result<Vec<u8>, FsError> {
    match encoding {
        "utf-8" => Ok(text.as_bytes().to_vec()),
        "utf-8-bom" => Ok([&[0xef, 0xbb, 0xbf][..], text.as_bytes()].concat()),
        "utf-16le" | "utf-16be" => {
            let mut output = if encoding == "utf-16le" {
                vec![0xff, 0xfe]
            } else {
                vec![0xfe, 0xff]
            };
            for unit in text.encode_utf16() {
                let bytes = if encoding == "utf-16le" {
                    unit.to_le_bytes()
                } else {
                    unit.to_be_bytes()
                };
                output.extend_from_slice(&bytes);
            }
            Ok(output)
        }
        "windows-1252" => {
            let (bytes, _, had_errors) = WINDOWS_1252.encode(text);
            if had_errors {
                Err(FsError::UnrepresentableEditText)
            } else {
                Ok(bytes.into_owned())
            }
        }
        _ => Err(FsError::UnsupportedEditEncoding),
    }
}

fn detected_newline(text: &str) -> &'static str {
    if text.contains("\r\n") { "\r\n" } else { "\n" }
}

fn normalize_newlines(value: &str, newline: &str) -> String {
    value
        .replace("\r\n", "\n")
        .replace('\r', "\n")
        .replace('\n', newline)
}

fn closest_line(text: &str, needle: &str) -> String {
    let wanted = needle.lines().next().unwrap_or(needle);
    let mut best = (usize::MAX, 0usize, "");
    for (index, line) in text.lines().enumerate() {
        let distance = levenshtein(wanted, line);
        if distance < best.0 {
            best = (distance, index + 1, line);
        }
    }
    let (line, _) = truncate_utf8(best.2, 512);
    format!("line {}: {}", best.1, line)
}

fn levenshtein(left: &str, right: &str) -> usize {
    let mut costs: Vec<usize> = (0..=right.chars().count()).collect();
    for (i, a) in left.chars().enumerate() {
        let mut previous = i;
        costs[0] = i + 1;
        for (j, b) in right.chars().enumerate() {
            let old = costs[j + 1];
            costs[j + 1] = (costs[j + 1] + 1)
                .min(costs[j] + 1)
                .min(previous + usize::from(a != b));
            previous = old;
        }
    }
    *costs.last().unwrap_or(&left.len())
}

fn unified_diff_summary(before: &str, after: &str) -> (String, bool) {
    let before_lines: Vec<&str> = before.lines().collect();
    let after_lines: Vec<&str> = after.lines().collect();
    let mut prefix = 0;
    while prefix < before_lines.len()
        && prefix < after_lines.len()
        && before_lines[prefix] == after_lines[prefix]
    {
        prefix += 1;
    }
    let mut suffix = 0;
    while suffix < before_lines.len().saturating_sub(prefix)
        && suffix < after_lines.len().saturating_sub(prefix)
        && before_lines[before_lines.len() - 1 - suffix]
            == after_lines[after_lines.len() - 1 - suffix]
    {
        suffix += 1;
    }
    let context_start = prefix.saturating_sub(3);
    let before_end = (before_lines.len() - suffix + 3).min(before_lines.len());
    let after_end = (after_lines.len() - suffix + 3).min(after_lines.len());
    let mut diff = format!(
        "--- current\n+++ proposed\n@@ -{},{} +{},{} @@\n",
        context_start + 1,
        before_end - context_start,
        context_start + 1,
        after_end - context_start
    );
    for line in &before_lines[context_start..prefix] {
        diff.push_str(&format!(" {line}\n"));
    }
    for line in &before_lines[prefix..before_lines.len() - suffix] {
        diff.push_str(&format!("-{line}\n"));
    }
    for line in &after_lines[prefix..after_lines.len() - suffix] {
        diff.push_str(&format!("+{line}\n"));
    }
    for line in &after_lines[after_lines.len() - suffix..after_end] {
        diff.push_str(&format!(" {line}\n"));
    }
    if diff.len() <= MAX_DIFF_SUMMARY_BYTES {
        return (diff, false);
    }
    let mut end = MAX_DIFF_SUMMARY_BYTES;
    while !diff.is_char_boundary(end) {
        end -= 1;
    }
    (format!("{}\n... diff truncated ...\n", &diff[..end]), true)
}

fn decode_search_text(bytes: &[u8]) -> Option<DecodedText> {
    if let Some(payload) = bytes.strip_prefix(&[0xef, 0xbb, 0xbf]) {
        return std::str::from_utf8(payload).ok().and_then(|text| {
            (!looks_binary(payload)).then(|| DecodedText {
                text: text.to_owned(),
                encoding: "utf-8-bom",
            })
        });
    }
    if let Some(payload) = bytes.strip_prefix(&[0xff, 0xfe]) {
        return decode_utf16(payload, u16::from_le_bytes, "utf-16le");
    }
    if let Some(payload) = bytes.strip_prefix(&[0xfe, 0xff]) {
        return decode_utf16(payload, u16::from_be_bytes, "utf-16be");
    }
    if looks_binary(bytes) {
        return None;
    }
    if let Ok(text) = std::str::from_utf8(bytes) {
        return Some(DecodedText {
            text: text.to_owned(),
            encoding: "utf-8",
        });
    }
    let (text, _, _) = WINDOWS_1252.decode(bytes);
    Some(DecodedText {
        text: text.into_owned(),
        encoding: "windows-1252",
    })
}

fn decode_utf16(
    payload: &[u8],
    convert: fn([u8; 2]) -> u16,
    encoding: &'static str,
) -> Option<DecodedText> {
    if payload.len() % 2 != 0 {
        return None;
    }
    let units = payload
        .chunks_exact(2)
        .map(|chunk| convert([chunk[0], chunk[1]]));
    let text = char::decode_utf16(units)
        .collect::<Result<String, _>>()
        .ok()?;
    (!looks_binary_text(&text)).then_some(DecodedText { text, encoding })
}

fn looks_binary(bytes: &[u8]) -> bool {
    bytes.contains(&0)
        || (!bytes.is_empty()
            && bytes
                .iter()
                .filter(|byte| matches!(byte, 0x01..=0x08 | 0x0b | 0x0c | 0x0e..=0x1f | 0x7f))
                .count()
                * 10
                > bytes.len())
}

fn looks_binary_text(text: &str) -> bool {
    let count = text.chars().count();
    count > 0
        && text
            .chars()
            .filter(|character| character.is_control() && !matches!(character, '\t' | '\n' | '\r'))
            .count()
            * 10
            > count
}

fn truncate_utf8(value: &str, max: usize) -> (String, bool) {
    if value.len() <= max {
        return (value.to_owned(), false);
    }
    let mut end = max;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    (value[..end].to_owned(), true)
}

fn glob_regex(pattern: &str) -> Result<Regex, FsError> {
    if pattern.is_empty() || pattern.contains('\0') {
        return Err(FsError::InvalidPattern);
    }
    let mut result = String::from("^");
    let chars: Vec<char> = pattern.replace('\\', "/").chars().collect();
    let mut index = 0;
    while index < chars.len() {
        match chars[index] {
            '*' if chars.get(index + 1) == Some(&'*') => {
                if chars.get(index + 2) == Some(&'/') {
                    result.push_str("(?:.*/)?");
                    index += 2;
                } else {
                    result.push_str(".*");
                    index += 1;
                }
            }
            '*' => result.push_str("[^/]*"),
            '?' => result.push_str("[^/]"),
            value => result.push_str(&regex::escape(&value.to_string())),
        }
        index += 1;
    }
    result.push('$');
    Regex::new(&result).map_err(|_| FsError::InvalidPattern)
}

#[cfg(windows)]
fn atomic_replace(source: &Path, target: &Path) -> io::Result<()> {
    let mut source_wide: Vec<u16> = source.as_os_str().encode_wide().collect();
    let mut target_wide: Vec<u16> = target.as_os_str().encode_wide().collect();
    source_wide.push(0);
    target_wide.push(0);
    let flags = MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH;
    let result = unsafe { MoveFileExW(source_wide.as_ptr(), target_wide.as_ptr(), flags) };
    if result == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(not(windows))]
fn atomic_replace(source: &Path, target: &Path) -> io::Result<()> {
    if target.exists() {
        fs::remove_file(target)?;
    }
    fs::rename(source, target)
}

#[derive(Debug, Error)]
pub enum FsError {
    #[error("no filesystem roots were configured")]
    NoAllowedRoots,
    #[error("path is unsafe or contains parent traversal")]
    UnsafePath,
    #[error("path resolves outside configured roots")]
    OutsideAllowedRoots,
    #[error("reparse point is not allowed in filesystem worker path: {0}")]
    ReparsePoint(PathBuf),
    #[error("authorization request and policy decision do not match")]
    AuthorizationMismatch,
    #[error("operation requires approval before filesystem execution")]
    ApprovalRequired,
    #[error("approved filesystem execution requires a consumed execution authorization")]
    ApprovedExecutionRequired,
    #[error("approved write request is missing expected_target_sha256")]
    MissingTargetPrecondition,
    #[error("expected_target_sha256 must be 'absent' or a 32-byte hexadecimal digest")]
    InvalidTargetPrecondition,
    #[error("target changed or does not match the expected digest")]
    TargetPreconditionFailed,
    #[error("operation was denied by policy")]
    Denied,
    #[error("authorization is for a different action")]
    WrongAction,
    #[error("read size {len} exceeds limit {max_bytes} bytes")]
    ReadLimitExceeded { len: u64, max_bytes: usize },
    #[error("filesystem parameters exceed the enforced limits")]
    InvalidParameters,
    #[error(
        "edit list must contain between 1 and 20 non-empty edits with positive expected occurrences"
    )]
    InvalidEditParameters,
    #[error("edit {edit_index} expected {expected} occurrences but found {actual}{closest}", closest = closest_line.as_deref().map(|v| format!("; closest {v}")).unwrap_or_default())]
    OccurrenceMismatch {
        edit_index: usize,
        expected: usize,
        actual: usize,
        closest_line: Option<String>,
    },
    #[error("edited file size {0} exceeds the 1 MiB limit")]
    EditResultTooLarge(usize),
    #[error("file encoding is not supported for text edits")]
    UnsupportedEditEncoding,
    #[error("replacement text cannot be represented in the original encoding")]
    UnrepresentableEditText,
    #[error("search pattern is invalid")]
    InvalidPattern,
    #[error("filesystem search exceeded its time budget")]
    SearchTimeout,
    #[error("write request is missing content_sha256")]
    MissingContentDigest,
    #[error("content_sha256 must be a 32-byte hexadecimal digest")]
    InvalidContentDigest,
    #[error("write content does not match the authorized digest")]
    ContentDigestMismatch,
    #[error("a transaction with this request digest already exists")]
    TransactionExists,
    #[error("post-write digest verification failed")]
    PostWriteVerificationFailed,
    #[error("filesystem I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error("journal serialization failed: {0}")]
    Json(#[from] serde_json::Error),
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;
    use std::collections::BTreeMap;
    use tempfile::tempdir;
    use vor_protocol::{ActionEnvelope, ActionRequest, PolicyDecision};

    fn authorization(action: &str, target: &Path, content: Option<&[u8]>) -> Authorization {
        let mut parameters = BTreeMap::new();
        if let Some(content) = content {
            parameters.insert("content_sha256".into(), Value::String(sha256_hex(content)));
        }
        let request = ActionRequest::seal(ActionEnvelope {
            request_id: "req-fs-1".into(),
            organization_id: "org-1".into(),
            actor_id: "actor-1".into(),
            device_id: "device-1".into(),
            action: action.into(),
            target: target.to_string_lossy().into_owned(),
            parameters,
            requested_capabilities: vec![],
            expires_at_unix_ms: u64::MAX,
            nonce: vec![9; 16],
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

    fn read_authorization(action: &str, target: &Path) -> Authorization {
        authorization(action, target, None)
    }

    #[test]
    fn committed_write_is_verified_and_journaled() {
        let root = tempdir().unwrap();
        let journal = root.path().join("journal");
        let target = root.path().join("demo.txt");
        fs::write(&target, b"old").unwrap();
        let worker = FsWorker::new([root.path().to_path_buf()], &journal).unwrap();
        let auth = authorization("filesystem.write", &target, Some(b"new"));
        let receipt = worker.write(&auth, b"new").unwrap();
        assert_eq!(fs::read(&target).unwrap(), b"new");
        assert_eq!(fs::read(receipt.backup_path.unwrap()).unwrap(), b"old");
        assert!(worker.pending_transactions().unwrap().is_empty());
    }

    #[test]
    fn content_mismatch_does_not_create_target() {
        let root = tempdir().unwrap();
        let journal = root.path().join("journal");
        let target = root.path().join("demo.txt");
        let worker = FsWorker::new([root.path().to_path_buf()], &journal).unwrap();
        let auth = authorization("filesystem.write", &target, Some(b"expected"));
        let result = worker.write(&auth, b"different");
        assert!(matches!(result, Err(FsError::ContentDigestMismatch)));
        assert!(!target.exists());
        assert!(worker.pending_transactions().unwrap().is_empty());
    }

    #[test]
    fn traversal_is_rejected() {
        let root = tempdir().unwrap();
        let journal = root.path().join("journal");
        let worker = FsWorker::new([root.path().to_path_buf()], &journal).unwrap();
        let target = root.path().join("sub").join("..").join("escape.txt");
        let auth = authorization("filesystem.write", &target, Some(b"x"));
        assert!(matches!(
            worker.write(&auth, b"x"),
            Err(FsError::UnsafePath)
        ));
    }

    #[test]
    fn read_requires_matching_auto_authorization() {
        let root = tempdir().unwrap();
        let journal = root.path().join("journal");
        let target = root.path().join("demo.txt");
        fs::write(&target, b"payload").unwrap();
        let worker = FsWorker::new([root.path().to_path_buf()], &journal).unwrap();
        let auth = authorization("filesystem.read", &target, None);
        assert_eq!(worker.read(&auth).unwrap(), b"payload");
    }

    #[test]
    fn ranged_and_line_reads_preserve_default_read_behavior() {
        let root = tempdir().unwrap();
        let target = root.path().join("demo.txt");
        fs::write(&target, b"alpha\nbeta\ngamma\n").unwrap();
        let worker =
            FsWorker::new([root.path().to_path_buf()], root.path().join("journal")).unwrap();
        let auth = read_authorization("filesystem.read", &target);
        assert_eq!(worker.read(&auth).unwrap(), b"alpha\nbeta\ngamma\n");
        assert_eq!(worker.read_range(&auth, 6, 4, 64).unwrap(), b"beta");
        assert_eq!(worker.read_lines(&auth, 2, 1, 64).unwrap(), b"beta\n");
    }

    #[test]
    fn list_info_and_searches_are_bounded_and_skip_binary_files() {
        let root = tempdir().unwrap();
        let nested = root.path().join("nested");
        fs::create_dir(&nested).unwrap();
        fs::write(nested.join("one.rs"), "first\nneedle here\n").unwrap();
        fs::write(nested.join("two.rs"), "needle again\n").unwrap();
        fs::write(nested.join("binary.rs"), b"needle\0hidden").unwrap();
        let worker =
            FsWorker::new([root.path().to_path_buf()], root.path().join("journal")).unwrap();

        let listed = worker
            .list_directory(&read_authorization("filesystem.list", root.path()), 2, 2)
            .unwrap();
        assert_eq!(listed.len(), 2);
        let files = worker
            .search_files(
                &read_authorization("filesystem.search_files", root.path()),
                "**/*.rs",
                1,
            )
            .unwrap();
        assert_eq!(files.len(), 1);
        let matches = worker
            .search_content(
                &read_authorization("filesystem.search_content", root.path()),
                "needle",
                false,
                "**/*.rs",
                10,
                1024,
            )
            .unwrap();
        assert_eq!(matches.matches.len(), 2);
        assert!(
            matches
                .matches
                .iter()
                .all(|item| !item.file.ends_with("binary.rs"))
        );
        assert_eq!(matches.skipped_binary_files, 1);
        let info = worker
            .file_info(&read_authorization(
                "filesystem.info",
                &nested.join("one.rs"),
            ))
            .unwrap();
        assert_eq!(info.entry_type, "file");
        assert!(info.size > 0);
    }

    #[test]
    fn every_read_only_tool_rejects_outside_roots_and_parent_traversal() {
        let root = tempdir().unwrap();
        let outside = tempdir().unwrap();
        let outside_file = outside.path().join("secret.txt");
        fs::write(&outside_file, "secret").unwrap();
        let outside_empty = tempdir().unwrap();
        let worker =
            FsWorker::new([root.path().to_path_buf()], root.path().join("journal")).unwrap();
        assert!(matches!(
            worker.list_directory(
                &read_authorization("filesystem.list", outside_empty.path()),
                1,
                10
            ),
            Err(FsError::OutsideAllowedRoots)
        ));
        assert!(matches!(
            worker.search_files(
                &read_authorization("filesystem.search_files", outside.path()),
                "**",
                10
            ),
            Err(FsError::OutsideAllowedRoots)
        ));
        assert!(matches!(
            worker.search_content(
                &read_authorization("filesystem.search_content", outside_empty.path()),
                "x",
                false,
                "**",
                10,
                10
            ),
            Err(FsError::OutsideAllowedRoots)
        ));
        assert!(matches!(
            worker.file_info(&read_authorization("filesystem.info", &outside_file)),
            Err(FsError::OutsideAllowedRoots)
        ));
        let traversal = root.path().join("child").join("..").join("secret.txt");
        for action in [
            "filesystem.list",
            "filesystem.search_files",
            "filesystem.search_content",
            "filesystem.info",
            "filesystem.read",
        ] {
            let auth = read_authorization(action, &traversal);
            let result = match action {
                "filesystem.list" => worker.list_directory(&auth, 1, 10).map(|_| ()),
                "filesystem.search_files" => worker.search_files(&auth, "**", 10).map(|_| ()),
                "filesystem.search_content" => worker
                    .search_content(&auth, "x", false, "**", 10, 10)
                    .map(|_| ()),
                "filesystem.info" => worker.file_info(&auth).map(|_| ()),
                _ => worker.read(&auth).map(|_| ()),
            };
            assert!(matches!(result, Err(FsError::UnsafePath)));
        }
    }

    #[test]
    fn content_lines_are_truncated_and_hard_limits_are_rejected() {
        let root = tempdir().unwrap();
        let target = root.path().join("large.txt");
        fs::write(
            &target,
            format!("needle{}", "x".repeat(MAX_LINE_TEXT_BYTES + 50)),
        )
        .unwrap();
        let worker =
            FsWorker::new([root.path().to_path_buf()], root.path().join("journal")).unwrap();
        let auth = read_authorization("filesystem.search_content", root.path());
        let matches = worker
            .search_content(&auth, "needle", false, "**", 1, MAX_SEARCH_FILE_BYTES)
            .unwrap();
        assert_eq!(matches.matches.len(), 1);
        assert!(matches.matches[0].truncated);
        assert_eq!(matches.matches[0].line_text.len(), MAX_LINE_TEXT_BYTES);
        assert!(matches!(
            worker.search_content(&auth, "x", false, "**", MAX_CONTENT_MATCHES + 1, 1),
            Err(FsError::InvalidParameters)
        ));
        assert!(matches!(
            worker.search_content_with_timeout(&auth, "x", false, "**", 1, 1, Duration::ZERO),
            Err(FsError::SearchTimeout)
        ));
    }

    #[test]
    fn content_search_decodes_common_windows_text_encodings() {
        let root = tempdir().unwrap();
        let fixtures = [
            (
                "windows-1252.txt",
                vec![0xe1, b' ', b'c', b'a', b'n', b'c', b'i', 0xf3, b'n'],
            ),
            (
                "utf-16le.txt",
                [
                    vec![0xff, 0xfe],
                    "á canción"
                        .encode_utf16()
                        .flat_map(u16::to_le_bytes)
                        .collect(),
                ]
                .concat(),
            ),
            (
                "utf-16be.txt",
                [
                    vec![0xfe, 0xff],
                    "á canción"
                        .encode_utf16()
                        .flat_map(u16::to_be_bytes)
                        .collect(),
                ]
                .concat(),
            ),
            (
                "utf-8-bom.txt",
                [vec![0xef, 0xbb, 0xbf], "á canción".as_bytes().to_vec()].concat(),
            ),
            ("utf-8.txt", "á canción".as_bytes().to_vec()),
        ];
        for (name, bytes) in fixtures {
            fs::write(root.path().join(name), bytes).unwrap();
        }
        let worker =
            FsWorker::new([root.path().to_path_buf()], root.path().join("journal")).unwrap();
        let result = worker
            .search_content(
                &read_authorization("filesystem.search_content", root.path()),
                "canción",
                false,
                "**/*.txt",
                10,
                1024,
            )
            .unwrap();

        assert_eq!(result.matches.len(), 5);
        let encodings = result
            .matches
            .iter()
            .map(|item| item.encoding.as_str())
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(
            encodings,
            ["utf-16be", "utf-16le", "utf-8", "utf-8-bom", "windows-1252"]
                .into_iter()
                .collect()
        );
        // `á ` is three UTF-8 bytes, so the one-based decoded UTF-8 byte column is 4,
        // including for the UTF-16 source fixtures.
        assert!(result.matches.iter().all(|item| item.column == 4));
    }

    #[test]
    fn content_search_reports_binary_and_size_limit_omissions() {
        let root = tempdir().unwrap();
        // The exact eight-byte signature from a real PNG file.
        fs::write(root.path().join("binary.png"), b"\x89PNG\r\n\x1a\n").unwrap();
        fs::write(root.path().join("too-large.txt"), "canción and more").unwrap();
        fs::write(root.path().join("match.txt"), "canción").unwrap();
        let worker =
            FsWorker::new([root.path().to_path_buf()], root.path().join("journal")).unwrap();
        let result = worker
            .search_content(
                &read_authorization("filesystem.search_content", root.path()),
                "canción",
                false,
                "**",
                10,
                10,
            )
            .unwrap();

        assert_eq!(result.matches.len(), 1);
        assert_eq!(result.skipped_binary_files, 1);
        assert_eq!(result.skipped_size_limit_files, 1);
    }

    #[cfg(windows)]
    #[test]
    fn directory_junction_escape_is_neither_listed_nor_traversed() {
        use std::process::Command;
        let root = tempdir().unwrap();
        let outside = tempdir().unwrap();
        fs::write(outside.path().join("secret.txt"), "needle").unwrap();
        let junction = root.path().join("escape");
        let status = Command::new("cmd")
            .args(["/c", "mklink", "/J"])
            .arg(&junction)
            .arg(outside.path())
            .status()
            .unwrap();
        assert!(status.success());
        let worker =
            FsWorker::new([root.path().to_path_buf()], root.path().join("journal")).unwrap();
        let listed = worker
            .list_directory(&read_authorization("filesystem.list", root.path()), 3, 10)
            .unwrap();
        assert!(listed.iter().all(|entry| entry.name != "escape"));
        let matches = worker
            .search_content(
                &read_authorization("filesystem.search_content", root.path()),
                "needle",
                false,
                "**",
                10,
                1024,
            )
            .unwrap();
        assert!(matches.matches.is_empty());
    }

    #[test]
    fn approval_is_not_execution_authority() {
        let root = tempdir().unwrap();
        let journal = root.path().join("journal");
        let target = root.path().join("demo.txt");
        let worker = FsWorker::new([root.path().to_path_buf()], &journal).unwrap();
        let mut auth = authorization("filesystem.write", &target, Some(b"x"));
        auth.decision.kind = PolicyDecisionKind::Approval;
        assert!(matches!(
            worker.write(&auth, b"x"),
            Err(FsError::ApprovalRequired)
        ));
        assert!(!target.exists());
    }

    fn edit_authorization(target: &Path) -> Authorization {
        let mut auth = authorization("filesystem.write", target, None);
        auth.decision.kind = PolicyDecisionKind::Approval;
        auth
    }

    #[test]
    fn prepare_edit_applies_single_and_ordered_multiple_replacements() {
        let root = tempdir().unwrap();
        let target = root.path().join("demo.txt");
        fs::write(&target, "alpha beta\nbeta gamma\n").unwrap();
        let worker =
            FsWorker::new([root.path().to_path_buf()], root.path().join("journal")).unwrap();
        let single = worker
            .prepare_edit(
                &edit_authorization(&target),
                &[TextEdit {
                    old_text: "gamma".into(),
                    new_text: "omega".into(),
                    expected_occurrences: 1,
                }],
            )
            .unwrap();
        assert_eq!(single.content, b"alpha beta\nbeta omega\n");
        let prepared = worker
            .prepare_edit(
                &edit_authorization(&target),
                &[
                    TextEdit {
                        old_text: "alpha".into(),
                        new_text: "beta".into(),
                        expected_occurrences: 1,
                    },
                    TextEdit {
                        old_text: "beta".into(),
                        new_text: "delta".into(),
                        expected_occurrences: 3,
                    },
                ],
            )
            .unwrap();
        assert_eq!(prepared.content, b"delta delta\ndelta gamma\n");
        assert!(prepared.diff_summary.contains("-alpha beta"));
        assert!(prepared.diff_summary.contains("+delta delta"));
        assert_eq!(fs::read(&target).unwrap(), b"alpha beta\nbeta gamma\n");
    }

    #[test]
    fn prepare_edit_rejects_absent_and_duplicate_text_with_real_counts() {
        let root = tempdir().unwrap();
        let target = root.path().join("demo.txt");
        fs::write(&target, "same\nsame\nclose\n").unwrap();
        let worker =
            FsWorker::new([root.path().to_path_buf()], root.path().join("journal")).unwrap();
        let duplicate = worker.prepare_edit(
            &edit_authorization(&target),
            &[TextEdit {
                old_text: "same".into(),
                new_text: "new".into(),
                expected_occurrences: 1,
            }],
        );
        assert!(matches!(
            duplicate,
            Err(FsError::OccurrenceMismatch { actual: 2, .. })
        ));
        let absent = worker.prepare_edit(
            &edit_authorization(&target),
            &[TextEdit {
                old_text: "cloze".into(),
                new_text: "new".into(),
                expected_occurrences: 1,
            }],
        );
        assert!(matches!(
            absent,
            Err(FsError::OccurrenceMismatch {
                actual: 0,
                closest_line: Some(_),
                ..
            })
        ));
    }

    #[test]
    fn prepare_edit_preserves_crlf_and_windows_1252() {
        let root = tempdir().unwrap();
        let target = root.path().join("legacy.txt");
        fs::write(&target, b"caf\xe9\r\nold line\r\n").unwrap();
        let worker =
            FsWorker::new([root.path().to_path_buf()], root.path().join("journal")).unwrap();
        let prepared = worker
            .prepare_edit(
                &edit_authorization(&target),
                &[TextEdit {
                    old_text: "old line\n".into(),
                    new_text: "new caf\u{e9}\n".into(),
                    expected_occurrences: 1,
                }],
            )
            .unwrap();
        assert_eq!(prepared.content, b"caf\xe9\r\nnew caf\xe9\r\n");
    }

    #[test]
    fn prepare_edit_rejects_paths_outside_allowed_root() {
        let root = tempdir().unwrap();
        let outside = tempdir().unwrap();
        let target = outside.path().join("secret.txt");
        fs::write(&target, "secret").unwrap();
        let worker =
            FsWorker::new([root.path().to_path_buf()], root.path().join("journal")).unwrap();
        let result = worker.prepare_edit(
            &edit_authorization(&target),
            &[TextEdit {
                old_text: "secret".into(),
                new_text: "x".into(),
                expected_occurrences: 1,
            }],
        );
        assert!(matches!(result, Err(FsError::OutsideAllowedRoots)));
    }

    #[cfg(windows)]
    #[test]
    fn prepare_edit_rejects_junction_escape() {
        use std::process::Command;
        let root = tempdir().unwrap();
        let outside = tempdir().unwrap();
        fs::write(outside.path().join("secret.txt"), "secret").unwrap();
        let junction = root.path().join("escape");
        assert!(
            Command::new("cmd")
                .args(["/c", "mklink", "/J"])
                .arg(&junction)
                .arg(outside.path())
                .status()
                .unwrap()
                .success()
        );
        let target = junction.join("secret.txt");
        let worker =
            FsWorker::new([root.path().to_path_buf()], root.path().join("journal")).unwrap();
        let result = worker.prepare_edit(
            &edit_authorization(&target),
            &[TextEdit {
                old_text: "secret".into(),
                new_text: "x".into(),
                expected_occurrences: 1,
            }],
        );
        assert!(matches!(result, Err(FsError::ReparsePoint(_))));
    }
}
