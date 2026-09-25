// SPDX-License-Identifier: MPL-2.0

use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::process::Command;
use thiserror::Error;
use vor_core::Authorization;
use vor_protocol::PolicyDecisionKind;

#[cfg(windows)]
use std::os::windows::fs::MetadataExt;

const MAX_OUTPUT_BYTES: usize = 4 * 1024 * 1024;
#[cfg(windows)]
const REPARSE_POINT_ATTRIBUTE: u32 = 0x400;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GitOutput {
    pub stdout: String,
    pub stderr: String,
}

pub struct GitWorker {
    git_executable: PathBuf,
    allowed_roots: Vec<PathBuf>,
}

impl GitWorker {
    pub fn new(
        git_executable: impl Into<PathBuf>,
        allowed_roots: impl IntoIterator<Item = PathBuf>,
    ) -> Result<Self, GitError> {
        let git_executable = git_executable.into();
        if !git_executable.is_absolute() || !git_executable.is_file() {
            return Err(GitError::InvalidExecutable);
        }
        let git_executable = fs::canonicalize(git_executable)?;
        let mut roots = Vec::new();
        for root in allowed_roots {
            ensure_safe_absolute_path(&root)?;
            reject_reparse_components(&root)?;
            roots.push(fs::canonicalize(root)?);
        }
        if roots.is_empty() {
            return Err(GitError::NoAllowedRoots);
        }
        Ok(Self {
            git_executable,
            allowed_roots: roots,
        })
    }

    pub fn status(&self, authorization: &Authorization) -> Result<GitOutput, GitError> {
        ensure_auto_action(authorization, "git.status")?;
        let repo = self.resolve_repo(Path::new(&authorization.request.envelope.target))?;
        self.run(
            &repo,
            &[
                "status",
                "--porcelain=v2",
                "--branch",
                "--untracked-files=all",
            ],
        )
    }

    pub fn diff(&self, authorization: &Authorization) -> Result<GitOutput, GitError> {
        ensure_auto_action(authorization, "git.diff")?;
        let repo = self.resolve_repo(Path::new(&authorization.request.envelope.target))?;
        self.run(
            &repo,
            &["diff", "--no-ext-diff", "--no-textconv", "--no-color", "--"],
        )
    }

    fn resolve_repo(&self, target: &Path) -> Result<PathBuf, GitError> {
        ensure_safe_absolute_path(target)?;
        reject_reparse_components(target)?;
        let repo = fs::canonicalize(target)?;
        if !repo.is_dir() {
            return Err(GitError::NotDirectory);
        }
        if !self
            .allowed_roots
            .iter()
            .any(|root| path_within(&repo, root))
        {
            return Err(GitError::OutsideAllowedRoots);
        }
        Ok(repo)
    }

    fn run(&self, repo: &Path, args: &[&str]) -> Result<GitOutput, GitError> {
        let output = Command::new(&self.git_executable)
            .env("GIT_OPTIONAL_LOCKS", "0")
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "NUL")
            .arg("-c")
            .arg("core.fsmonitor=false")
            .arg("-c")
            .arg("core.untrackedCache=false")
            .arg("-C")
            .arg(repo)
            .args(args)
            .output()?;
        if output.stdout.len() > MAX_OUTPUT_BYTES || output.stderr.len() > MAX_OUTPUT_BYTES {
            return Err(GitError::OutputLimitExceeded);
        }
        let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
        if !output.status.success() {
            return Err(GitError::CommandFailed {
                code: output.status.code(),
                stderr,
            });
        }
        Ok(GitOutput { stdout, stderr })
    }
}

fn ensure_auto_action(authorization: &Authorization, expected: &str) -> Result<(), GitError> {
    if authorization.request.envelope_digest != authorization.decision.envelope_digest
        || authorization.request.envelope.request_id != authorization.decision.request_id
    {
        return Err(GitError::AuthorizationMismatch);
    }
    match authorization.decision.kind {
        PolicyDecisionKind::Auto => {}
        PolicyDecisionKind::Approval => return Err(GitError::ApprovalRequired),
        PolicyDecisionKind::Deny => return Err(GitError::Denied),
    }
    if authorization.request.envelope.action != expected {
        return Err(GitError::WrongAction);
    }
    Ok(())
}

fn ensure_safe_absolute_path(path: &Path) -> Result<(), GitError> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::ParentDir))
    {
        return Err(GitError::UnsafePath);
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

fn reject_reparse_components(path: &Path) -> Result<(), GitError> {
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
                return Err(GitError::ReparsePoint(current));
            }
        }
    }
    #[cfg(not(windows))]
    let _ = path;
    Ok(())
}

#[derive(Debug, Error)]
pub enum GitError {
    #[error("git executable must be an existing absolute file")]
    InvalidExecutable,
    #[error("no Git roots were configured")]
    NoAllowedRoots,
    #[error("path is unsafe or contains parent traversal")]
    UnsafePath,
    #[error("path resolves outside configured roots")]
    OutsideAllowedRoots,
    #[error("repository target is not a directory")]
    NotDirectory,
    #[error("reparse point is not allowed in Git worker path: {0}")]
    ReparsePoint(PathBuf),
    #[error("authorization request and policy decision do not match")]
    AuthorizationMismatch,
    #[error("operation requires approval before Git execution")]
    ApprovalRequired,
    #[error("operation was denied by policy")]
    Denied,
    #[error("authorization is for a different Git action")]
    WrongAction,
    #[error("Git output exceeded the configured limit")]
    OutputLimitExceeded,
    #[error("Git command failed with code {code:?}: {stderr}")]
    CommandFailed { code: Option<i32>, stderr: String },
    #[error("Git I/O failed: {0}")]
    Io(#[from] std::io::Error),
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use tempfile::tempdir;
    use vor_protocol::{ActionEnvelope, ActionRequest, PolicyDecision};

    fn find_git() -> PathBuf {
        let output = Command::new("where.exe").arg("git.exe").output().unwrap();
        assert!(output.status.success());
        let stdout = String::from_utf8_lossy(&output.stdout);
        PathBuf::from(stdout.lines().next().unwrap().trim())
    }

    fn run_git(git: &Path, repo: &Path, args: &[&str]) {
        let status = Command::new(git)
            .arg("-C")
            .arg(repo)
            .args(args)
            .status()
            .unwrap();
        assert!(status.success());
    }

    fn authorization(action: &str, target: &Path) -> Authorization {
        let request = ActionRequest::seal(ActionEnvelope {
            request_id: format!("req-{action}"),
            organization_id: "org-1".into(),
            actor_id: "actor-1".into(),
            device_id: "device-1".into(),
            action: action.into(),
            target: target.to_string_lossy().into_owned(),
            parameters: BTreeMap::new(),
            requested_capabilities: vec![],
            expires_at_unix_ms: u64::MAX,
            nonce: vec![4; 16],
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

    fn initialized_repo() -> (tempfile::TempDir, PathBuf) {
        let dir = tempdir().unwrap();
        let git = find_git();
        run_git(&git, dir.path(), &["init", "--quiet"]);
        fs::write(dir.path().join("README.md"), "one\n").unwrap();
        run_git(&git, dir.path(), &["add", "README.md"]);
        run_git(
            &git,
            dir.path(),
            &[
                "-c",
                "user.name=Vör Test",
                "-c",
                "user.email=vor-test@example.invalid",
                "commit",
                "--quiet",
                "-m",
                "initial",
            ],
        );
        (dir, git)
    }

    #[test]
    fn status_reports_untracked_file() {
        let (dir, git) = initialized_repo();
        fs::write(dir.path().join("new.txt"), "new\n").unwrap();
        let worker = GitWorker::new(git, [dir.path().to_path_buf()]).unwrap();
        let output = worker
            .status(&authorization("git.status", dir.path()))
            .unwrap();
        assert!(output.stdout.lines().any(|line| line == "? new.txt"));
    }

    #[test]
    fn diff_disables_external_helpers_and_returns_patch() {
        let (dir, git) = initialized_repo();
        fs::write(dir.path().join("README.md"), "two\n").unwrap();
        let worker = GitWorker::new(git, [dir.path().to_path_buf()]).unwrap();
        let output = worker.diff(&authorization("git.diff", dir.path())).unwrap();
        assert!(output.stdout.contains("-one"));
        assert!(output.stdout.contains("+two"));
    }
}
