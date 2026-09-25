// SPDX-License-Identifier: MPL-2.0

use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use thiserror::Error;
use vor_protocol::Digest32;

const ZERO_HASH: Digest32 = [0; 32];
const LOCK_RETRY_ATTEMPTS: usize = 200;
const LOCK_RETRY_DELAY: Duration = Duration::from_millis(10);
const ABANDONED_LOCK_AGE: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEvent {
    pub timestamp_unix_ms: u64,
    pub organization_id: String,
    pub actor_id: String,
    pub device_id: String,
    pub request_id: String,
    pub action: String,
    pub target: String,
    pub outcome: String,
    pub envelope_digest: Digest32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditRecord {
    pub sequence: u64,
    pub previous_hash: Digest32,
    pub record_hash: Digest32,
    pub event: AuditEvent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionRecoveryState {
    NotExecuted,
    EffectUncertain,
    EffectApplied,
    PostEffectUncertain,
    Completed,
}

impl ExecutionRecoveryState {
    fn as_str(self) -> &'static str {
        match self {
            Self::NotExecuted => "not_executed",
            Self::EffectUncertain => "effect_uncertain",
            Self::EffectApplied => "effect_applied",
            Self::PostEffectUncertain => "post_effect_uncertain",
            Self::Completed => "completed",
        }
    }

    fn parse(value: &str) -> Result<Self, AuditError> {
        match value {
            "not_executed" => Ok(Self::NotExecuted),
            "effect_uncertain" => Ok(Self::EffectUncertain),
            "effect_applied" => Ok(Self::EffectApplied),
            "post_effect_uncertain" => Ok(Self::PostEffectUncertain),
            "completed" => Ok(Self::Completed),
            _ => Err(AuditError::InvalidExecutionState),
        }
    }
}

pub struct Ledger {
    conn: Connection,
    jsonl_path: PathBuf,
    last_sequence: u64,
    last_hash: Digest32,
    #[cfg(feature = "fault-injection")]
    fail_next_approval_claim: bool,
}

impl Ledger {
    pub fn open(
        sqlite_path: impl AsRef<Path>,
        jsonl_path: impl AsRef<Path>,
    ) -> Result<Self, AuditError> {
        ensure_parent(sqlite_path.as_ref())?;
        ensure_parent(jsonl_path.as_ref())?;
        let conn = Connection::open(sqlite_path)?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS audit_records (
                sequence INTEGER PRIMARY KEY,
                previous_hash TEXT NOT NULL,
                record_hash TEXT NOT NULL UNIQUE,
                event_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS approval_consumptions (
                request_id TEXT NOT NULL,
                envelope_digest TEXT NOT NULL,
                consumed_at_unix_ms INTEGER NOT NULL,
                PRIMARY KEY(request_id, envelope_digest)
            );
            CREATE TABLE IF NOT EXISTS approval_executions (
                request_id TEXT NOT NULL,
                envelope_digest TEXT NOT NULL,
                state TEXT NOT NULL,
                updated_at_unix_ms INTEGER NOT NULL,
                PRIMARY KEY(request_id, envelope_digest)
            );",
        )?;
        migrate_approval_consumptions(&conn)?;
        let db_last = load_db_last(&conn)?;
        let file_last = load_jsonl_last(jsonl_path.as_ref())?;
        if db_last != file_last {
            return Err(AuditError::Divergence);
        }
        let (last_sequence, last_hash) = db_last.unwrap_or((0, ZERO_HASH));
        Ok(Self {
            conn,
            jsonl_path: jsonl_path.as_ref().to_path_buf(),
            last_sequence,
            last_hash,
            #[cfg(feature = "fault-injection")]
            fail_next_approval_claim: false,
        })
    }

    pub fn append(&mut self, event: AuditEvent) -> Result<AuditRecord, AuditError> {
        let guard = LedgerFileLock::acquire(&self.jsonl_path)?;
        let db_last = load_db_last(&self.conn)?;
        let file_last = load_jsonl_last(&self.jsonl_path)?;
        if db_last != file_last {
            return Err(AuditError::Divergence);
        }
        let (last_sequence, last_hash) = db_last.unwrap_or((0, ZERO_HASH));
        self.last_sequence = last_sequence;
        self.last_hash = last_hash;
        let sequence = self.last_sequence + 1;
        let event_json = serde_json::to_string(&event)?;
        let record_hash = hash_record(sequence, self.last_hash, event_json.as_bytes());
        let record = AuditRecord {
            sequence,
            previous_hash: self.last_hash,
            record_hash,
            event,
        };
        let record_json = serde_json::to_string(&record)?;
        let tx = self.conn.transaction()?;
        tx.execute(
            "INSERT INTO audit_records(sequence, previous_hash, record_hash, event_json) VALUES (?1, ?2, ?3, ?4)",
            params![
                sequence as i64,
                hex::encode(record.previous_hash),
                hex::encode(record.record_hash),
                event_json,
            ],
        )?;
        append_jsonl(&self.jsonl_path, &record_json)?;
        tx.commit()?;
        guard.release()?;
        self.last_sequence = sequence;
        self.last_hash = record_hash;
        Ok(record)
    }

    pub fn verify_integrity(&self) -> Result<(), AuditError> {
        let mut stmt = self.conn.prepare(
            "SELECT sequence, previous_hash, record_hash, event_json FROM audit_records ORDER BY sequence ASC"
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
            ))
        })?;
        let mut previous = ZERO_HASH;
        let mut db_records = Vec::new();
        for row in rows {
            let (sequence, previous_hex, record_hex, event_json) = row?;
            let sequence = u64::try_from(sequence).map_err(|_| AuditError::InvalidSequence)?;
            let stored_previous = decode_hash(&previous_hex)?;
            let stored_record = decode_hash(&record_hex)?;
            if stored_previous != previous
                || hash_record(sequence, previous, event_json.as_bytes()) != stored_record
            {
                return Err(AuditError::HashMismatch(sequence));
            }
            let event: AuditEvent = serde_json::from_str(&event_json)?;
            db_records.push(AuditRecord {
                sequence,
                previous_hash: previous,
                record_hash: stored_record,
                event,
            });
            previous = stored_record;
        }
        let file_records = load_jsonl_records(&self.jsonl_path)?;
        if db_records != file_records {
            return Err(AuditError::Divergence);
        }
        Ok(())
    }

    pub fn last_sequence(&self) -> u64 {
        self.last_sequence
    }

    pub fn last_hash(&self) -> Digest32 {
        self.last_hash
    }

    pub fn has_outcome_for(
        &self,
        request_id: &str,
        envelope_digest: &Digest32,
        outcome: &str,
    ) -> Result<bool, AuditError> {
        let mut stmt = self
            .conn
            .prepare("SELECT event_json FROM audit_records ORDER BY sequence ASC")?;
        let mut rows = stmt.query([])?;
        while let Some(row) = rows.next()? {
            let event_json: String = row.get(0)?;
            let event: AuditEvent = serde_json::from_str(&event_json)?;
            if event.request_id == request_id
                && &event.envelope_digest == envelope_digest
                && event.outcome == outcome
            {
                return Ok(true);
            }
        }
        Ok(false)
    }

    pub fn records_for_organization(
        &self,
        organization_id: &str,
    ) -> Result<Vec<AuditRecord>, AuditError> {
        let mut stmt = self
            .conn
            .prepare("SELECT sequence, previous_hash, record_hash, event_json FROM audit_records ORDER BY sequence ASC")?;
        let mut out = Vec::new();
        let mut rows = stmt.query([])?;
        while let Some(row) = rows.next()? {
            let sequence =
                u64::try_from(row.get::<_, i64>(0)?).map_err(|_| AuditError::InvalidSequence)?;
            let previous_hash = decode_hash(&row.get::<_, String>(1)?)?;
            let record_hash = decode_hash(&row.get::<_, String>(2)?)?;
            let event: AuditEvent = serde_json::from_str(&row.get::<_, String>(3)?)?;
            let record = AuditRecord {
                sequence,
                previous_hash,
                record_hash,
                event,
            };
            if record.event.organization_id == organization_id {
                out.push(record);
            }
        }
        Ok(out)
    }

    pub fn claim_approval_consumed(
        &mut self,
        request_id: &str,
        envelope_digest: &Digest32,
        consumed_at_unix_ms: u64,
    ) -> Result<bool, AuditError> {
        #[cfg(feature = "fault-injection")]
        if std::mem::take(&mut self.fail_next_approval_claim) {
            return Err(AuditError::FaultInjected("approval claim"));
        }
        let tx = self.conn.transaction()?;
        let changed = tx.execute(
            "INSERT OR IGNORE INTO approval_consumptions(request_id, envelope_digest, consumed_at_unix_ms) VALUES (?1, ?2, ?3)",
            params![
                request_id,
                hex::encode(envelope_digest),
                i64::try_from(consumed_at_unix_ms).map_err(|_| AuditError::InvalidSequence)?,
            ],
        )?;
        if changed == 1 {
            tx.execute(
                "INSERT INTO approval_executions(request_id, envelope_digest, state, updated_at_unix_ms) VALUES (?1, ?2, ?3, ?4)",
                params![request_id, hex::encode(envelope_digest), ExecutionRecoveryState::NotExecuted.as_str(), i64::try_from(consumed_at_unix_ms).map_err(|_| AuditError::InvalidSequence)?],
            )?;
        }
        tx.commit()?;
        Ok(changed == 1)
    }

    pub fn set_execution_recovery_state(
        &mut self,
        request_id: &str,
        envelope_digest: &Digest32,
        state: ExecutionRecoveryState,
        updated_at_unix_ms: u64,
    ) -> Result<(), AuditError> {
        let changed = self.conn.execute(
            "UPDATE approval_executions SET state = ?3, updated_at_unix_ms = ?4 WHERE request_id = ?1 AND envelope_digest = ?2",
            params![request_id, hex::encode(envelope_digest), state.as_str(), i64::try_from(updated_at_unix_ms).map_err(|_| AuditError::InvalidSequence)?],
        )?;
        if changed != 1 {
            return Err(AuditError::MissingExecutionState);
        }
        Ok(())
    }

    pub fn execution_recovery_state(
        &self,
        request_id: &str,
        envelope_digest: &Digest32,
    ) -> Result<Option<ExecutionRecoveryState>, AuditError> {
        let state: Option<String> = self.conn.query_row(
            "SELECT state FROM approval_executions WHERE request_id = ?1 AND envelope_digest = ?2",
            params![request_id, hex::encode(envelope_digest)], |row| row.get(0),
        ).optional()?;
        state
            .map(|value| ExecutionRecoveryState::parse(&value))
            .transpose()
    }

    #[cfg(feature = "fault-injection")]
    pub fn inject_next_approval_claim_failure(&mut self) {
        self.fail_next_approval_claim = true;
    }

    #[cfg(feature = "fault-injection")]
    pub fn inject_abandoned_lock(&self) -> Result<(), AuditError> {
        let lock_path = self.jsonl_path.with_extension("lock");
        fs::write(lock_path, b"0")?;
        Ok(())
    }
}

struct LedgerFileLock {
    path: Option<PathBuf>,
    file: Option<File>,
}

impl LedgerFileLock {
    fn acquire(jsonl_path: &Path) -> Result<Self, AuditError> {
        let lock_path = jsonl_path.with_extension("lock");
        for _ in 0..LOCK_RETRY_ATTEMPTS {
            match OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&lock_path)
            {
                Ok(mut file) => {
                    writeln!(file, "{}", now_unix_ms()?)?;
                    file.sync_all()?;
                    return Ok(Self {
                        path: Some(lock_path),
                        file: Some(file),
                    });
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    if lock_is_abandoned(&lock_path)? {
                        match fs::remove_file(&lock_path) {
                            Ok(()) => continue,
                            Err(remove_error)
                                if remove_error.kind() == std::io::ErrorKind::NotFound
                                    || is_transient_lock_error(&remove_error) =>
                            {
                                thread::sleep(LOCK_RETRY_DELAY);
                                continue;
                            }
                            Err(remove_error) => return Err(remove_error.into()),
                        }
                    }
                    thread::sleep(LOCK_RETRY_DELAY);
                }
                Err(error) if is_transient_lock_error(&error) => {
                    thread::sleep(LOCK_RETRY_DELAY);
                }
                Err(error) => return Err(error.into()),
            }
        }
        Err(AuditError::LockTimeout)
    }

    fn release(mut self) -> Result<(), AuditError> {
        let path = self.path.take().expect("lock path exists");
        drop(self.file.take());
        remove_lock_file(&path, LOCK_RETRY_ATTEMPTS, LOCK_RETRY_DELAY)
    }
}

fn is_transient_lock_error(error: &std::io::Error) -> bool {
    error.kind() == std::io::ErrorKind::AlreadyExists
        || cfg!(windows) && matches!(error.raw_os_error(), Some(5 | 32 | 33))
}

fn now_unix_ms() -> Result<u64, AuditError> {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| AuditError::Clock)?;
    u64::try_from(elapsed.as_millis()).map_err(|_| AuditError::InvalidSequence)
}

fn lock_is_abandoned(path: &Path) -> Result<bool, AuditError> {
    let contents = match fs::read_to_string(path) {
        Ok(contents) => contents,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        // Otro handle (antivirus u otro escritor) lo tiene abierto: no es abandono, se reintenta.
        Err(error) if is_transient_lock_error(&error) => return Ok(false),
        Err(error) => return Err(error.into()),
    };
    let Ok(created_at) = contents.trim().parse::<u64>() else {
        return Ok(false);
    };
    Ok(now_unix_ms()?.saturating_sub(created_at) >= ABANDONED_LOCK_AGE.as_millis() as u64)
}

impl Drop for LedgerFileLock {
    fn drop(&mut self) {
        if let Some(path) = self.path.take() {
            drop(self.file.take());
            let _ = remove_lock_file(&path, LOCK_RETRY_ATTEMPTS, LOCK_RETRY_DELAY);
        }
    }
}

fn remove_lock_file(path: &Path, attempts: usize, delay: Duration) -> Result<(), AuditError> {
    for _ in 0..attempts {
        match fs::remove_file(path) {
            Ok(()) => return Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) if is_transient_lock_error(&error) => thread::sleep(delay),
            Err(error) => return Err(error.into()),
        }
    }
    Err(AuditError::LockTimeout)
}

fn migrate_approval_consumptions(conn: &Connection) -> Result<(), AuditError> {
    let mut stmt = conn.prepare("SELECT event_json FROM audit_records ORDER BY sequence ASC")?;
    let mut rows = stmt.query([])?;
    while let Some(row) = rows.next()? {
        let event_json: String = row.get(0)?;
        let event: AuditEvent = serde_json::from_str(&event_json)?;
        if event.outcome == "approval_consumed" {
            conn.execute(
                "INSERT OR IGNORE INTO approval_consumptions(request_id, envelope_digest, consumed_at_unix_ms) VALUES (?1, ?2, ?3)",
                params![
                    event.request_id,
                    hex::encode(event.envelope_digest),
                    i64::try_from(event.timestamp_unix_ms).map_err(|_| AuditError::InvalidSequence)?,
                ],
            )?;
        }
    }
    Ok(())
}

fn ensure_parent(path: &Path) -> Result<(), AuditError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    Ok(())
}

fn hash_record(sequence: u64, previous_hash: Digest32, payload: &[u8]) -> Digest32 {
    let mut hasher = Sha256::new();
    hasher.update(previous_hash);
    hasher.update(sequence.to_be_bytes());
    hasher.update(payload);
    hasher.finalize().into()
}

fn append_jsonl(path: &Path, line: &str) -> Result<(), AuditError> {
    let mut file = retry_transient_io(|| OpenOptions::new().create(true).append(true).open(path))?;
    writeln!(file, "{line}")?;
    file.sync_all()?;
    Ok(())
}

fn load_db_last(conn: &Connection) -> Result<Option<(u64, Digest32)>, AuditError> {
    let row: Option<(i64, String)> = conn
        .query_row(
            "SELECT sequence, record_hash FROM audit_records ORDER BY sequence DESC LIMIT 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    row.map(|(sequence, hash)| {
        Ok((
            u64::try_from(sequence).map_err(|_| AuditError::InvalidSequence)?,
            decode_hash(&hash)?,
        ))
    })
    .transpose()
}

fn load_jsonl_last(path: &Path) -> Result<Option<(u64, Digest32)>, AuditError> {
    if !path.exists() {
        return Ok(None);
    }
    let last = BufReader::new(retry_transient_io(|| File::open(path))?)
        .lines()
        .map_while(Result::ok)
        .filter(|l| !l.trim().is_empty())
        .last();
    let Some(line) = last else {
        return Ok(None);
    };
    let record: AuditRecord = serde_json::from_str(&line)?;
    Ok(Some((record.sequence, record.record_hash)))
}

fn load_jsonl_records(path: &Path) -> Result<Vec<AuditRecord>, AuditError> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let mut records = Vec::new();
    for line in BufReader::new(retry_transient_io(|| File::open(path))?).lines() {
        let line = line?;
        if !line.trim().is_empty() {
            records.push(serde_json::from_str(&line)?);
        }
    }
    Ok(records)
}

fn retry_transient_io<T>(mut operation: impl FnMut() -> std::io::Result<T>) -> std::io::Result<T> {
    for attempt in 0..LOCK_RETRY_ATTEMPTS {
        match operation() {
            Ok(value) => return Ok(value),
            Err(error) if is_transient_lock_error(&error) && attempt + 1 < LOCK_RETRY_ATTEMPTS => {
                thread::sleep(LOCK_RETRY_DELAY);
            }
            Err(error) => return Err(error),
        }
    }
    unreachable!("retry loop always returns on its final attempt")
}

fn decode_hash(value: &str) -> Result<Digest32, AuditError> {
    let bytes = hex::decode(value).map_err(|_| AuditError::InvalidHash)?;
    bytes.try_into().map_err(|_| AuditError::InvalidHash)
}

#[derive(Debug, Error)]
pub enum AuditError {
    #[cfg(feature = "fault-injection")]
    #[error("fault injected while persisting {0}")]
    FaultInjected(&'static str),
    #[error("audit stores diverged")]
    Divergence,
    #[error("audit hash mismatch at sequence {0}")]
    HashMismatch(u64),
    #[error("invalid audit hash")]
    InvalidHash,
    #[error("invalid audit sequence")]
    InvalidSequence,
    #[error("invalid approval execution state")]
    InvalidExecutionState,
    #[error("approval execution state is missing")]
    MissingExecutionState,
    #[error("audit file lock timed out")]
    LockTimeout,
    #[error("system clock is outside supported range")]
    Clock,
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("SQLite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Barrier};
    use tempfile::tempdir;

    #[cfg(windows)]
    use std::os::windows::fs::OpenOptionsExt;

    fn event(id: &str) -> AuditEvent {
        AuditEvent {
            timestamp_unix_ms: 1,
            organization_id: "org".into(),
            actor_id: "actor".into(),
            device_id: "device".into(),
            request_id: id.into(),
            action: "filesystem.read".into(),
            target: r"D:\Proyectos\x".into(),
            outcome: "auto".into(),
            envelope_digest: [9; 32],
        }
    }

    fn event_for_org(org: &str, id: &str) -> AuditEvent {
        let mut event = event(id);
        event.organization_id = org.to_owned();
        event
    }

    #[cfg(windows)]
    fn open_without_delete_sharing(path: &Path) -> File {
        const FILE_SHARE_READ: u32 = 1;
        const FILE_SHARE_WRITE: u32 = 2;
        OpenOptions::new()
            .read(true)
            .write(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .open(path)
            .unwrap()
    }

    #[cfg(windows)]
    #[test]
    fn lock_acquire_retries_windows_sharing_violation_then_succeeds() {
        let dir = tempdir().unwrap();
        let jsonl = dir.path().join("audit.jsonl");
        let lock = jsonl.with_extension("lock");
        fs::write(&lock, b"held").unwrap();
        let held = open_without_delete_sharing(&lock);
        let releaser = thread::spawn(move || {
            thread::sleep(Duration::from_millis(50));
            drop(held);
            fs::remove_file(lock).unwrap();
        });

        let acquired = LedgerFileLock::acquire(&jsonl).unwrap();
        releaser.join().unwrap();
        drop(acquired);
    }

    #[cfg(windows)]
    #[test]
    fn lock_acquire_fails_closed_when_windows_sharing_violation_persists() {
        let dir = tempdir().unwrap();
        let jsonl = dir.path().join("audit.jsonl");
        let lock = jsonl.with_extension("lock");
        fs::write(&lock, b"held").unwrap();
        let _held = open_without_delete_sharing(&lock);

        assert!(matches!(
            LedgerFileLock::acquire(&jsonl),
            Err(AuditError::LockTimeout)
        ));
    }

    #[cfg(windows)]
    #[test]
    fn lock_release_retries_windows_sharing_violation_then_succeeds() {
        let dir = tempdir().unwrap();
        let lock = dir.path().join("audit.lock");
        fs::write(&lock, b"held").unwrap();
        let held = open_without_delete_sharing(&lock);
        let releaser = thread::spawn(move || {
            thread::sleep(Duration::from_millis(50));
            drop(held);
        });

        remove_lock_file(&lock, 200, Duration::from_millis(10)).unwrap();
        releaser.join().unwrap();
        assert!(!lock.exists());
    }

    #[cfg(windows)]
    #[test]
    fn lock_release_fails_closed_when_windows_sharing_violation_persists() {
        let dir = tempdir().unwrap();
        let lock = dir.path().join("audit.lock");
        fs::write(&lock, b"held").unwrap();
        let _held = open_without_delete_sharing(&lock);

        assert!(matches!(
            remove_lock_file(&lock, 3, Duration::from_millis(1)),
            Err(AuditError::LockTimeout)
        ));
        assert!(lock.exists());
    }

    #[test]
    fn append_reopen_and_verify() {
        let dir = tempdir().unwrap();
        let db = dir.path().join("audit.db");
        let jsonl = dir.path().join("audit.jsonl");
        {
            let mut ledger = Ledger::open(&db, &jsonl).unwrap();
            ledger.append(event("r1")).unwrap();
            ledger.append(event("r2")).unwrap();
            ledger.verify_integrity().unwrap();
            assert_eq!(ledger.last_sequence(), 2);
        }
        let ledger = Ledger::open(&db, &jsonl).unwrap();
        ledger.verify_integrity().unwrap();
        assert_eq!(ledger.last_sequence(), 2);
    }

    #[test]
    fn detects_jsonl_divergence() {
        let dir = tempdir().unwrap();
        let db = dir.path().join("audit.db");
        let jsonl = dir.path().join("audit.jsonl");
        let mut ledger = Ledger::open(&db, &jsonl).unwrap();
        ledger.append(event("r1")).unwrap();
        drop(ledger);
        fs::write(&jsonl, "").unwrap();
        assert!(matches!(
            Ledger::open(&db, &jsonl),
            Err(AuditError::Divergence)
        ));
    }

    #[test]
    fn tenant_scoped_reader_returns_only_requested_organization_records() {
        let dir = tempdir().unwrap();
        let db = dir.path().join("audit.db");
        let jsonl = dir.path().join("audit.jsonl");
        let mut ledger = Ledger::open(&db, &jsonl).unwrap();
        ledger.append(event_for_org("org-a", "a1")).unwrap();
        ledger.append(event_for_org("org-b", "b1")).unwrap();
        ledger.append(event_for_org("org-a", "a2")).unwrap();

        let org_a = ledger.records_for_organization("org-a").unwrap();
        assert_eq!(org_a.len(), 2);
        assert!(
            org_a
                .iter()
                .all(|record| record.event.organization_id == "org-a")
        );
        assert!(
            org_a
                .iter()
                .all(|record| !record.event.request_id.starts_with('b'))
        );

        let org_b = ledger.records_for_organization("org-b").unwrap();
        assert_eq!(org_b.len(), 1);
        assert_eq!(org_b[0].event.request_id, "b1");

        let foreign_existing = ledger.records_for_organization("org-b").unwrap();
        let foreign_missing = ledger
            .records_for_organization("org-does-not-exist")
            .unwrap();
        assert_eq!(foreign_existing.len(), 1);
        assert!(foreign_missing.is_empty());
        assert!(
            foreign_existing
                .iter()
                .all(|record| record.event.organization_id == "org-b")
        );
    }

    #[test]
    fn legacy_consumed_event_is_migrated_into_claim_table() {
        let dir = tempdir().unwrap();
        let db = dir.path().join("audit.db");
        let jsonl = dir.path().join("audit.jsonl");
        let mut event = event("legacy-consumed");
        event.outcome = "approval_consumed".into();
        let digest = event.envelope_digest;
        {
            let mut ledger = Ledger::open(&db, &jsonl).unwrap();
            ledger.append(event).unwrap();
            ledger.verify_integrity().unwrap();
        }
        {
            let conn = Connection::open(&db).unwrap();
            conn.execute("DROP TABLE approval_consumptions", [])
                .unwrap();
        }

        let mut reopened = Ledger::open(&db, &jsonl).unwrap();
        assert!(
            !reopened
                .claim_approval_consumed("legacy-consumed", &digest, 2)
                .unwrap()
        );
    }

    #[test]
    fn independent_ledgers_append_distinct_events_without_stale_sequence_collision() {
        let dir = tempdir().unwrap();
        let db = dir.path().join("audit.db");
        let jsonl = dir.path().join("audit.jsonl");
        let mut a = Ledger::open(&db, &jsonl).unwrap();
        let mut b = Ledger::open(&db, &jsonl).unwrap();

        a.append(event("from-a")).unwrap();
        b.append(event("from-b")).unwrap();
        a.append(event("from-a-again")).unwrap();

        let reopened = Ledger::open(&db, &jsonl).unwrap();
        reopened.verify_integrity().unwrap();
        assert_eq!(reopened.last_sequence(), 3);
        let records = reopened.records_for_organization("org").unwrap();
        assert_eq!(records.len(), 3);
        assert_eq!(records[0].event.request_id, "from-a");
        assert_eq!(records[1].event.request_id, "from-b");
        assert_eq!(records[2].event.request_id, "from-a-again");
    }

    #[test]
    fn concurrent_independent_ledgers_append_distinct_events_with_unique_chain() {
        let dir = tempdir().unwrap();
        let db = Arc::new(dir.path().join("audit.db"));
        let jsonl = Arc::new(dir.path().join("audit.jsonl"));
        Ledger::open(&*db, &*jsonl).unwrap();
        let barrier = Arc::new(Barrier::new(8));
        let mut handles = Vec::new();

        for index in 0..8 {
            let db = Arc::clone(&db);
            let jsonl = Arc::clone(&jsonl);
            let barrier = Arc::clone(&barrier);
            handles.push(thread::spawn(move || {
                let mut ledger = Ledger::open(&*db, &*jsonl).unwrap();
                barrier.wait();
                ledger
                    .append(event(&format!("concurrent-{index}")))
                    .unwrap();
            }));
        }
        for handle in handles {
            handle.join().unwrap();
        }

        let reopened = Ledger::open(&*db, &*jsonl).unwrap();
        reopened.verify_integrity().unwrap();
        assert_eq!(reopened.last_sequence(), 8);
        let mut request_ids: Vec<_> = reopened
            .records_for_organization("org")
            .unwrap()
            .into_iter()
            .map(|record| record.event.request_id)
            .collect();
        request_ids.sort();
        assert_eq!(
            request_ids,
            (0..8)
                .map(|index| format!("concurrent-{index}"))
                .collect::<Vec<_>>()
        );
    }
}
