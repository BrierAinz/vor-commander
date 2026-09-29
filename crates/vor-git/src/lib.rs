// SPDX-License-Identifier: MPL-2.0

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;
use thiserror::Error;
use vor_core::Authorization;
use vor_protocol::PolicyDecisionKind;

#[cfg(windows)]
use std::os::windows::fs::MetadataExt;

const MAX_OUTPUT_BYTES: usize = 4 * 1024 * 1024;
#[cfg(windows)]
const REPARSE_POINT_ATTRIBUTE: u32 = 0x400;

pub const GIT_ENVIRONMENT: [(&str, &str); 7] = [
    ("GIT_OPTIONAL_LOCKS", "0"),
    ("GIT_TERMINAL_PROMPT", "0"),
    ("GIT_ATTR_NOSYSTEM", "1"),
    ("GIT_CONFIG_NOSYSTEM", "1"),
    ("GIT_CONFIG_SYSTEM", "NUL"),
    ("GIT_CONFIG_GLOBAL", "NUL"),
    ("GIT_CONFIG_COUNT", "0"),
];

pub const GIT_HARDENING_ARGUMENTS: [&str; 11] = [
    "--no-pager",
    "-c",
    "core.fsmonitor=false",
    "-c",
    "core.untrackedCache=false",
    "-c",
    "core.pager=cat",
    "-c",
    "core.attributesFile=",
    "-c",
    "diff.external=",
];

const DIFF_HARDENING_ARGUMENTS: [&str; 2] = ["--no-ext-diff", "--no-textconv"];
static EMPTY_GIT_DIRECTORY: OnceLock<tempfile::TempDir> = OnceLock::new();

fn empty_git_directory() -> Result<&'static Path, GitError> {
    if let Some(directory) = EMPTY_GIT_DIRECTORY.get() {
        return Ok(directory.path());
    }
    let directory = tempfile::Builder::new()
        .prefix("vor-git-empty-")
        .tempdir()?;
    let _ = EMPTY_GIT_DIRECTORY.set(directory);
    Ok(EMPTY_GIT_DIRECTORY
        .get()
        .expect("empty Git directory was initialized")
        .path())
}

fn hardening_arguments() -> Result<Vec<String>, GitError> {
    let empty = empty_git_directory()?.to_string_lossy();
    let mut arguments = GIT_HARDENING_ARGUMENTS
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    arguments.extend(["-c".to_owned(), format!("core.hooksPath={empty}")]);
    Ok(arguments)
}

fn harden_diff_subcommand(arguments: &mut Vec<String>, subcommand_index: usize) {
    if arguments
        .get(subcommand_index)
        .is_some_and(|value| matches!(value.as_str(), "diff" | "log" | "show"))
    {
        arguments.splice(
            subcommand_index + 1..subcommand_index + 1,
            DIFF_HARDENING_ARGUMENTS.into_iter().map(str::to_owned),
        );
    }
}

pub fn harden_terminal_git(
    argv: &mut Vec<String>,
    environment: &mut BTreeMap<String, String>,
) -> Result<(), GitError> {
    let hardening = hardening_arguments()?;
    let subcommand_index = 1 + hardening.len();
    argv.splice(1..1, hardening);
    harden_diff_subcommand(argv, subcommand_index);
    environment.extend(
        GIT_ENVIRONMENT
            .into_iter()
            .map(|(name, value)| (name.to_owned(), value.to_owned())),
    );
    environment.insert(
        "XDG_CONFIG_HOME".to_owned(),
        empty_git_directory()?.to_string_lossy().into_owned(),
    );
    Ok(())
}

pub fn reject_repo_alias(git: &Path, repo: &Path, subcommand: &str) -> Result<(), GitError> {
    let mut command = Command::new(git);
    configure_git_command(&mut command)?;
    let output = command
        .arg("-C")
        .arg(repo)
        .arg("config")
        .arg("--get")
        .arg(format!("alias.{subcommand}"))
        .output()?;
    match output.status.code() {
        Some(1) => Ok(()),
        Some(0) => Err(GitError::RepositoryAlias(subcommand.to_owned())),
        code => Err(GitError::CommandFailed {
            code,
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        }),
    }
}

fn configure_git_command(command: &mut Command) -> Result<(), GitError> {
    let program = PathBuf::from(command.get_program());
    command
        .env_clear()
        .envs(vor_terminal::safe_child_environment(Some(&program)))
        .envs(GIT_ENVIRONMENT)
        .env("XDG_CONFIG_HOME", empty_git_directory()?)
        .args(hardening_arguments()?);
    Ok(())
}

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
        self.run(&repo, &["diff", "--no-color", "--"])
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
            .any(|root| vor_path::path_within(&repo, root))
        {
            return Err(GitError::OutsideAllowedRoots);
        }
        Ok(repo)
    }

    fn run(&self, repo: &Path, args: &[&str]) -> Result<GitOutput, GitError> {
        let mut command = Command::new(&self.git_executable);
        configure_git_command(&mut command)?;
        let mut args = args
            .iter()
            .map(|value| (*value).to_owned())
            .collect::<Vec<_>>();
        harden_diff_subcommand(&mut args, 0);
        let output = command.arg("-C").arg(repo).args(args).output()?;
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
    #[error("repository defines the safe-listed Git subcommand as an alias: {0}")]
    RepositoryAlias(String),
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

    fn marker_command(dir: &Path) -> (PathBuf, PathBuf) {
        let marker = dir.join("marker.txt");
        let command = dir.join("marker.cmd");
        fs::write(
            &command,
            format!("@echo executed>\"{}\"\r\n", marker.display()),
        )
        .unwrap();
        (marker, command)
    }

    #[test]
    fn repository_alias_is_rejected_and_git_hooks_are_neutralized() {
        let (dir, git) = initialized_repo();
        let marker = dir.path().join("marker.txt");
        let hook = dir.path().join("marker.cmd");
        fs::write(
            &hook,
            format!("@echo executed>\"{}\"\r\n", marker.display()),
        )
        .unwrap();
        run_git(
            &git,
            dir.path(),
            &["config", "alias.status", "!cmd.exe /D /C marker.cmd"],
        );
        run_git(
            &git,
            dir.path(),
            &["config", "core.fsmonitor", hook.to_str().unwrap()],
        );
        run_git(
            &git,
            dir.path(),
            &["config", "core.pager", hook.to_str().unwrap()],
        );

        assert!(matches!(
            reject_repo_alias(&git, dir.path(), "status"),
            Err(GitError::RepositoryAlias(alias)) if alias == "status"
        ));
        assert!(!marker.exists());

        run_git(&git, dir.path(), &["config", "--unset", "alias.status"]);
        let worker = GitWorker::new(git, [dir.path().to_path_buf()]).unwrap();
        worker
            .status(&authorization("git.status", dir.path()))
            .unwrap();
        assert!(!marker.exists());
        assert_eq!(GIT_HARDENING_ARGUMENTS[0], "--no-pager");
        assert!(GIT_HARDENING_ARGUMENTS.contains(&"core.pager=cat"));
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

    #[test]
    fn attributes_textconv_cannot_execute_a_marker() {
        let (dir, git) = initialized_repo();
        let (marker, command) = marker_command(dir.path());
        fs::write(
            dir.path().join(".gitattributes"),
            "README.md diff=hostile\n",
        )
        .unwrap();
        run_git(
            &git,
            dir.path(),
            &["config", "diff.hostile.textconv", command.to_str().unwrap()],
        );
        fs::write(dir.path().join("README.md"), "changed\n").unwrap();

        let worker = GitWorker::new(git, [dir.path().to_path_buf()]).unwrap();
        worker.diff(&authorization("git.diff", dir.path())).unwrap();
        assert!(!marker.exists());
    }

    #[test]
    fn external_diff_cannot_execute_a_marker() {
        let (dir, git) = initialized_repo();
        let (marker, command) = marker_command(dir.path());
        run_git(
            &git,
            dir.path(),
            &["config", "diff.external", command.to_str().unwrap()],
        );
        fs::write(dir.path().join("README.md"), "changed\n").unwrap();

        let worker = GitWorker::new(git, [dir.path().to_path_buf()]).unwrap();
        worker.diff(&authorization("git.diff", dir.path())).unwrap();
        assert!(!marker.exists());
    }

    #[test]
    fn included_alias_is_rejected_without_executing_its_marker() {
        let (dir, git) = initialized_repo();
        let (marker, command) = marker_command(dir.path());
        let included = dir.path().join("hostile.conf");
        fs::write(
            &included,
            format!(
                "[alias]\n\tstatus = !\"{}\"\n",
                command.display().to_string().replace('\\', "/")
            ),
        )
        .unwrap();
        run_git(
            &git,
            dir.path(),
            &["config", "include.path", included.to_str().unwrap()],
        );

        assert!(matches!(
            reject_repo_alias(&git, dir.path(), "status"),
            Err(GitError::RepositoryAlias(alias)) if alias == "status"
        ));
        assert!(!marker.exists());
    }

    #[test]
    fn ambient_git_config_parameters_are_cleared() {
        let (dir, git) = initialized_repo();
        let (marker, command) = marker_command(dir.path());
        let parameters = format!(
            "'alias.status=!\"{}\"'",
            command.display().to_string().replace('\\', "/")
        );
        let visible = Command::new(&git)
            .env("GIT_CONFIG_PARAMETERS", &parameters)
            .arg("config")
            .arg("--get")
            .arg("alias.status")
            .output()
            .unwrap();
        assert!(visible.status.success());

        let mut hardened = Command::new(&git);
        hardened.env("GIT_CONFIG_PARAMETERS", parameters);
        configure_git_command(&mut hardened).unwrap();
        let hidden = hardened
            .arg("-C")
            .arg(dir.path())
            .arg("config")
            .arg("--get")
            .arg("alias.status")
            .output()
            .unwrap();
        assert_eq!(hidden.status.code(), Some(1));
        assert!(!marker.exists());
    }

    #[test]
    fn configured_hooks_path_is_replaced_by_an_empty_directory() {
        let (dir, git) = initialized_repo();
        let (marker, command) = marker_command(dir.path());
        let hooks = dir.path().join("hostile-hooks");
        fs::create_dir(&hooks).unwrap();
        fs::copy(&command, hooks.join("post-index-change.cmd")).unwrap();
        run_git(
            &git,
            dir.path(),
            &["config", "core.hooksPath", hooks.to_str().unwrap()],
        );

        let mut hardened = Command::new(&git);
        configure_git_command(&mut hardened).unwrap();
        let output = hardened
            .arg("-C")
            .arg(dir.path())
            .arg("config")
            .arg("--get")
            .arg("core.hooksPath")
            .output()
            .unwrap();
        assert!(output.status.success());
        let effective = PathBuf::from(String::from_utf8_lossy(&output.stdout).trim());
        assert_eq!(effective, empty_git_directory().unwrap());
        assert!(fs::read_dir(effective).unwrap().next().is_none());
        assert!(!marker.exists());
    }
}
