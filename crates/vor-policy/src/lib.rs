// SPDX-License-Identifier: MPL-2.0

use serde::Deserialize;
use sha2::Digest as _;
use std::{fs, path::Path};
use thiserror::Error;
use vor_protocol::{ActionRequest, PolicyDecision, PolicyDecisionKind};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalMode {
    #[default]
    Strict,
    Policy,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AutoWritePolicy {
    #[serde(default = "default_max_auto_write_bytes")]
    pub max_bytes: usize,
    #[serde(default = "default_max_auto_writes_per_minute")]
    pub max_files_per_minute: u32,
    #[serde(default = "default_max_auto_write_bytes_per_minute")]
    pub max_bytes_per_minute: usize,
}

impl Default for AutoWritePolicy {
    fn default() -> Self {
        Self {
            max_bytes: default_max_auto_write_bytes(),
            max_files_per_minute: default_max_auto_writes_per_minute(),
            max_bytes_per_minute: default_max_auto_write_bytes_per_minute(),
        }
    }
}

fn default_max_auto_write_bytes() -> usize {
    1024 * 1024
}
fn default_max_auto_writes_per_minute() -> u32 {
    60
}
fn default_max_auto_write_bytes_per_minute() -> usize {
    8 * 1024 * 1024
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleDecision {
    Auto,
    Approval,
    Deny,
    ElevatedApproval,
}

#[derive(Debug, Clone, Deserialize)]
pub struct FilesystemRule {
    pub path: String,
    pub read: RuleDecision,
    pub write: RuleDecision,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TerminalPolicy {
    pub default: RuleDecision,
    #[serde(default = "default_inline_eval_decision")]
    pub inline_eval: RuleDecision,
    pub project_tests: RuleDecision,
    pub destructive: RuleDecision,
    pub elevated: RuleDecision,
}

fn default_inline_eval_decision() -> RuleDecision {
    RuleDecision::ElevatedApproval
}

#[derive(Debug, Clone, Deserialize)]
pub struct ProcessPolicy {
    pub list: RuleDecision,
    pub inspect: RuleDecision,
    pub terminate: RuleDecision,
}

#[derive(Debug, Clone, Deserialize)]
pub struct BrowserPolicy {
    pub authenticated_session_use: RuleDecision,
    pub secret_extraction: RuleDecision,
    pub publish: RuleDecision,
    pub purchase: RuleDecision,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DesktopPolicy {
    pub enabled: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct NetworkPolicy {
    pub public_listener_fallback: RuleDecision,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AuditPolicy {
    pub required: bool,
    pub fail_if_unwritable: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PolicyConfig {
    pub version: u32,
    pub policy_id: String,
    #[serde(default)]
    pub mode: ApprovalMode,
    #[serde(default)]
    pub auto_write: AutoWritePolicy,
    pub filesystem: Vec<FilesystemRule>,
    pub terminal: TerminalPolicy,
    pub process: ProcessPolicy,
    pub browser: BrowserPolicy,
    pub desktop: DesktopPolicy,
    pub network: NetworkPolicy,
    pub audit: AuditPolicy,
}

pub struct PolicyEngine {
    config: PolicyConfig,
    policy_hash: String,
}

impl PolicyEngine {
    pub fn from_yaml_str(input: &str) -> Result<Self, PolicyError> {
        let input = input.trim_start_matches('\u{feff}');
        let config: PolicyConfig = yaml_serde::from_str(input)?;
        if config.version != 1 || config.policy_id.trim().is_empty() {
            return Err(PolicyError::InvalidConfig);
        }
        let policy_hash = hex::encode(sha2::Sha256::digest(input.as_bytes()));
        Ok(Self {
            config,
            policy_hash,
        })
    }

    pub fn from_yaml_file(path: impl AsRef<Path>) -> Result<Self, PolicyError> {
        Self::from_yaml_str(&fs::read_to_string(path)?)
    }

    pub fn config(&self) -> &PolicyConfig {
        &self.config
    }

    pub fn policy_hash(&self) -> &str {
        &self.policy_hash
    }

    pub fn evaluate(&self, request: &ActionRequest) -> PolicyDecision {
        let action = request.envelope.action.as_str();
        let (rule, reason) = match action {
            "filesystem.read"
            | "filesystem.list"
            | "filesystem.search_files"
            | "filesystem.search_content"
            | "filesystem.info" => (
                self.filesystem_decision(&request.envelope.target, false),
                "filesystem_rule",
            ),
            "filesystem.write" => self.filesystem_write_decision(request),
            "terminal.exec" => self.terminal_exec_decision(request),
            "terminal.poll" => (RuleDecision::Auto, "terminal_poll"),
            "terminal.cancel" => (RuleDecision::Auto, "terminal_cancel"),
            "terminal.project_test" => {
                (self.config.terminal.project_tests, "terminal_project_test")
            }
            "terminal.destructive" => (self.config.terminal.destructive, "terminal_destructive"),
            "terminal.elevated" => (self.config.terminal.elevated, "terminal_elevated"),
            "process.list" => (self.config.process.list, "process_list"),
            "process.inspect" => (self.config.process.inspect, "process_inspect"),
            "process.terminate" => (self.config.process.terminate, "process_terminate"),
            "git.status" | "git.diff" => (
                self.filesystem_decision(&request.envelope.target, false),
                "git_read",
            ),
            "browser.session.use" => (
                self.config.browser.authenticated_session_use,
                "browser_session",
            ),
            "browser.secret.extract" => (self.config.browser.secret_extraction, "browser_secret"),
            "browser.publish" => (self.config.browser.publish, "browser_publish"),
            "browser.purchase" => (self.config.browser.purchase, "browser_purchase"),
            "network.public_listener" => (
                self.config.network.public_listener_fallback,
                "public_listener",
            ),
            a if a.starts_with("desktop.") && !self.config.desktop.enabled => {
                (RuleDecision::Deny, "desktop_disabled")
            }
            a if a.starts_with("desktop.") => (RuleDecision::Approval, "desktop_approval"),
            _ => (RuleDecision::Deny, "unknown_action"),
        };
        self.decision(request, rule, reason)
    }

    fn filesystem_write_decision(&self, request: &ActionRequest) -> (RuleDecision, &'static str) {
        let base = self.filesystem_decision(&request.envelope.target, true);
        if base != RuleDecision::Auto {
            return (base, "filesystem_rule");
        }
        if self.config.mode == ApprovalMode::Strict {
            return (RuleDecision::Approval, "strict_mode");
        }
        if request
            .envelope
            .parameters
            .get("approval_path")
            .and_then(serde_json::Value::as_bool)
            == Some(true)
        {
            return (RuleDecision::Approval, "explicit_signed_path");
        }
        if normalize_windows_path(&request.envelope.target)
            .is_none_or(|path| vor_path::sensitive_windows_path(&path))
        {
            return (RuleDecision::Approval, "auto_write_sensitive_path");
        }
        let Some(size) = request
            .envelope
            .parameters
            .get("content_bytes")
            .and_then(serde_json::Value::as_u64)
        else {
            return (RuleDecision::Approval, "auto_write_size_required");
        };
        if size > self.config.auto_write.max_bytes as u64 {
            return (RuleDecision::Approval, "auto_write_size_exceeded");
        }
        let valid_precondition = request
            .envelope
            .parameters
            .get("expected_target_sha256")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|value| {
                value.eq_ignore_ascii_case("absent")
                    || (value.len() == 64 && hex::decode(value).is_ok_and(|v| v.len() == 32))
            });
        if !valid_precondition {
            return (RuleDecision::Approval, "auto_write_precondition_missing");
        }
        (RuleDecision::Auto, "auto_write_safe")
    }

    fn terminal_exec_decision(&self, request: &ActionRequest) -> (RuleDecision, &'static str) {
        let Some(argv) = terminal_argv(request) else {
            return (RuleDecision::Deny, "terminal_argv_required");
        };
        if command_is_inline_eval(&argv) {
            (self.config.terminal.inline_eval, "terminal_inline_eval")
        } else {
            (self.config.terminal.default, "terminal_default")
        }
    }

    fn filesystem_decision(&self, target: &str, write: bool) -> RuleDecision {
        let Some(target) = normalize_windows_path(target) else {
            return RuleDecision::Deny;
        };
        self.config
            .filesystem
            .iter()
            .filter_map(|rule| normalize_windows_path(&rule.path).map(|p| (p, rule)))
            .filter(|(root, _)| vor_path::windows_path_within(&target, root))
            .max_by_key(|(root, _)| root.len())
            .map(|(_, rule)| if write { rule.write } else { rule.read })
            .unwrap_or(RuleDecision::Deny)
    }

    fn decision(
        &self,
        request: &ActionRequest,
        rule: RuleDecision,
        reason: &str,
    ) -> PolicyDecision {
        let (kind, required_capability) = match rule {
            RuleDecision::Auto => (PolicyDecisionKind::Auto, None),
            RuleDecision::Approval => (PolicyDecisionKind::Approval, None),
            RuleDecision::Deny => (PolicyDecisionKind::Deny, None),
            RuleDecision::ElevatedApproval => {
                (PolicyDecisionKind::Approval, Some("elevated".to_owned()))
            }
        };
        PolicyDecision {
            request_id: request.envelope.request_id.clone(),
            kind,
            policy_id: self.config.policy_id.clone(),
            reason_code: reason.to_owned(),
            required_capability,
            envelope_digest: request.envelope_digest,
        }
    }
}

fn terminal_argv(request: &ActionRequest) -> Option<Vec<&str>> {
    let values = request.envelope.parameters.get("argv")?.as_array()?;
    if values.is_empty() {
        return None;
    }
    values.iter().map(|value| value.as_str()).collect()
}

fn command_is_inline_eval(argv: &[&str]) -> bool {
    let Some(executable) = argv.first().copied() else {
        return false;
    };
    let mut executable = executable
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or(executable)
        .to_ascii_lowercase();
    for suffix in [".exe", ".cmd", ".bat", ".com"] {
        if executable.ends_with(suffix) {
            executable.truncate(executable.len() - suffix.len());
            break;
        }
    }

    const PYTHON: &[&str] = &["-c"];
    const NODE: &[&str] = &["-e", "--eval", "-p", "--print"];
    const RUBY_PERL: &[&str] = &["-e"];
    const OSASCRIPT: &[&str] = &["-e"];
    const POWERSHELL: &[&str] = &["-command", "-encodedcommand"];
    const CMD: &[&str] = &["/c", "/k"];
    const POSIX_SHELL: &[&str] = &["-c", "--command"];

    let (triggers, powershell) = if executable == "python"
        || executable == "python3"
        || executable == "py"
        || executable.starts_with("python3.")
    {
        (PYTHON, false)
    } else if executable == "node" {
        (NODE, false)
    } else if executable == "ruby" || executable == "perl" {
        (RUBY_PERL, false)
    } else if executable == "osascript" {
        (OSASCRIPT, false)
    } else if executable == "powershell" || executable == "pwsh" {
        if powershell_is_inline_eval(argv, executable == "powershell") {
            return true;
        }
        (POWERSHELL, true)
    } else if executable == "cmd" {
        if cmd_is_inline_eval(argv) {
            return true;
        }
        (CMD, true)
    } else if matches!(
        executable.as_str(),
        "bash" | "sh" | "zsh" | "fish" | "dash" | "ksh"
    ) {
        (POSIX_SHELL, false)
    } else if executable == "wsl" {
        return argv.len() > 1;
    } else {
        return false;
    };

    for argument in argv.iter().skip(1) {
        let normalized = argument.to_ascii_lowercase();
        if normalized == "--" {
            break;
        }

        for trigger in triggers {
            if normalized == *trigger {
                return true;
            }
            if trigger.starts_with("--")
                && normalized
                    .strip_prefix(trigger)
                    .is_some_and(|rest| rest.starts_with('='))
            {
                return true;
            }
            if trigger.len() == 2
                && trigger.starts_with('-')
                && normalized.starts_with(trigger)
                && normalized.len() > trigger.len()
            {
                return true;
            }
            if powershell && *trigger == "-command" && matches!(normalized.as_str(), "-c" | "/c") {
                return true;
            }
        }

        if !(normalized.starts_with('-') || powershell && normalized.starts_with('/')) {
            break;
        }
    }
    false
}

/// cmd.exe runs the rest of its command line for `/C`, `/K` and the
/// undocumented-but-supported `/R` (a `/C` synonym), and it accepts the command
/// glued to the switch (`/cwhoami`). No other cmd switch starts with those
/// letters, so a prefix match is exact.
fn cmd_is_inline_eval(argv: &[&str]) -> bool {
    for argument in argv.iter().skip(1) {
        let normalized = argument.to_ascii_lowercase();
        if normalized.starts_with("/c")
            || normalized.starts_with("/k")
            || normalized.starts_with("/r")
        {
            return true;
        }
        if !normalized.starts_with('/') {
            break;
        }
    }
    false
}

/// PowerShell accepts `-`, `--` or `/` before a parameter name, any unambiguous
/// prefix of that name, and a few documented aliases. Windows PowerShell 5.1
/// (`powershell.exe`) also treats the first positional argument as `-Command`
/// text; `pwsh` treats it as `-File`.
fn powershell_is_inline_eval(argv: &[&str], windows_powershell: bool) -> bool {
    // Parameters that consume the next argument as their value.
    const VALUED: &[&str] = &[
        "executionpolicy",
        "windowstyle",
        "version",
        "workingdirectory",
        "configurationname",
        "configurationfile",
        "inputformat",
        "outputformat",
        "encodedarguments",
        "psconsolefile",
        "settingsfile",
        "custompipename",
    ];
    const VALUED_ALIASES: &[&str] = &["ep", "ex", "w", "v", "wd", "ea", "if", "of"];

    let mut arguments = argv.iter().skip(1);
    while let Some(argument) = arguments.next() {
        let normalized = argument.to_ascii_lowercase();
        let name = normalized
            .strip_prefix("--")
            .or_else(|| normalized.strip_prefix('-'))
            .or_else(|| normalized.strip_prefix('/'));
        let Some(name) = name else {
            return windows_powershell;
        };
        let (name, inline_value) = match name.split_once(':') {
            Some((name, _)) => (name, true),
            None => (name, false),
        };
        if name.is_empty() {
            continue;
        }
        if matches!(name, "e" | "ec" | "cwa")
            || "command".starts_with(name)
            || (name.len() >= 2 && "encodedcommand".starts_with(name))
            || (name.len() >= 8 && "commandwithargs".starts_with(name))
        {
            return true;
        }
        if name == "f" || (name.len() >= 2 && "file".starts_with(name)) {
            return false;
        }
        if !inline_value
            && (VALUED_ALIASES.contains(&name)
                || VALUED
                    .iter()
                    .any(|full| name.len() >= 3 && full.starts_with(name)))
        {
            arguments.next();
        }
    }
    false
}

/// Normalizes a drive-absolute Windows path for policy matching, or returns
/// `None` (deny) for anything ambiguous.
///
/// A component that looks like an 8.3 short name (`~<digit>`) may be an alias
/// of a sensitive or out-of-root long name, so it is never matched as text.
/// Windows also hands out legitimate paths in that form (`%TEMP%` under a long
/// account name, GitHub runners' `C:\Users\RUNNER~1`), so such a path is first
/// expanded by the filesystem to the long form it names, and the policy is
/// evaluated on that long form. A short-looking component the filesystem cannot
/// expand (it does not exist yet, or cannot be listed) stays denied: it could
/// later become an alias of something else. Paths without such a component are
/// never looked up on disk.
fn normalize_windows_path(input: &str) -> Option<String> {
    let path = input.replace('/', "\\");
    let (drive, parts) = split_windows_path(&path)?;
    if !parts.iter().any(|part| has_short_name_alias(part)) {
        return Some(join_windows_path(drive, &parts));
    }
    let expanded = expand_short_names(drive, &parts)?;
    let (drive, parts) = split_windows_path(&expanded)?;
    if parts.iter().any(|part| has_short_name_alias(part)) {
        return None;
    }
    Some(join_windows_path(drive, &parts))
}

/// Splits `X:\a\b` into its drive and components, rejecting every ambiguous
/// component except short-name lookalikes, which the caller resolves.
fn split_windows_path(path: &str) -> Option<(char, Vec<&str>)> {
    let bytes = path.as_bytes();
    if bytes.len() < 3 || !bytes[0].is_ascii_alphabetic() || bytes[1] != b':' || bytes[2] != b'\\' {
        return None;
    }
    let drive = (bytes[0] as char).to_ascii_uppercase();
    let mut parts = Vec::new();
    for part in path[3..].split('\\').filter(|p| !p.is_empty()) {
        if part == "."
            || part == ".."
            || part.ends_with(['.', ' '])
            || part.contains(':')
            || part.contains('\0')
            || is_reserved_windows_name(part)
        {
            return None;
        }
        parts.push(part);
    }
    Some((drive, parts))
}

fn join_windows_path(drive: char, parts: &[&str]) -> String {
    let suffix = parts.join("\\").to_ascii_lowercase();
    format!("{drive}:\\{suffix}")
}

/// Expands the longest existing prefix of the path to its long form and keeps
/// the non-existent tail literally (so short-looking components there are
/// denied by the caller). Reparse points are not followed: this only answers
/// which long name an 8.3 alias stands for.
#[cfg(windows)]
fn expand_short_names(drive: char, parts: &[&str]) -> Option<String> {
    (0..=parts.len()).rev().find_map(|existing| {
        let prefix = format!("{drive}:\\{}", parts[..existing].join("\\"));
        let long = long_path_name(&prefix)?;
        let mut expanded = long.trim_end_matches('\\').to_owned();
        for part in &parts[existing..] {
            expanded.push('\\');
            expanded.push_str(part);
        }
        if expanded.ends_with(':') {
            expanded.push('\\');
        }
        Some(expanded)
    })
}

#[cfg(not(windows))]
fn expand_short_names(_drive: char, _parts: &[&str]) -> Option<String> {
    None
}

#[cfg(windows)]
fn long_path_name(path: &str) -> Option<String> {
    use windows_sys::Win32::Storage::FileSystem::GetLongPathNameW;

    let wide: Vec<u16> = path.encode_utf16().chain(Some(0)).collect();
    let mut capacity = unsafe { GetLongPathNameW(wide.as_ptr(), std::ptr::null_mut(), 0) };
    // The name can grow between the size query and the copy; retry a few times.
    for _ in 0..4 {
        if capacity == 0 {
            return None;
        }
        let mut output = vec![0u16; capacity as usize];
        let written = unsafe { GetLongPathNameW(wide.as_ptr(), output.as_mut_ptr(), capacity) };
        if written == 0 {
            return None;
        }
        if written < capacity {
            return String::from_utf16(&output[..written as usize]).ok();
        }
        capacity = written;
    }
    None
}

fn is_reserved_windows_name(component: &str) -> bool {
    let stem = component
        .split_once('.')
        .map_or(component, |(stem, _)| stem)
        .to_ascii_lowercase();
    matches!(stem.as_str(), "con" | "prn" | "aux" | "nul")
        || stem.strip_prefix("com").is_some_and(|number| {
            matches!(number, "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9")
        })
        || stem.strip_prefix("lpt").is_some_and(|number| {
            matches!(number, "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9")
        })
}

fn has_short_name_alias(component: &str) -> bool {
    component
        .as_bytes()
        .windows(2)
        .any(|pair| pair[0] == b'~' && pair[1].is_ascii_digit())
}

#[derive(Debug, Error)]
pub enum PolicyError {
    #[error("policy configuration is invalid")]
    InvalidConfig,
    #[error("failed to read policy: {0}")]
    Io(#[from] std::io::Error),
    #[error("failed to parse policy: {0}")]
    Yaml(#[from] yaml_serde::Error),
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use vor_protocol::{ActionEnvelope, ActionRequest};

    fn request(action: &str, target: &str) -> ActionRequest {
        ActionRequest::seal(ActionEnvelope {
            request_id: "req-1".into(),
            organization_id: "org-1".into(),
            actor_id: "actor-1".into(),
            device_id: "device-1".into(),
            action: action.into(),
            target: target.into(),
            parameters: BTreeMap::new(),
            requested_capabilities: vec![],
            expires_at_unix_ms: u64::MAX,
            nonce: vec![1; 16],
        })
        .unwrap()
    }

    fn write_request(target: &str, size: u64, precondition: Option<&str>) -> ActionRequest {
        let mut request = request("filesystem.write", target);
        request
            .envelope
            .parameters
            .insert("content_bytes".into(), size.into());
        if let Some(value) = precondition {
            request
                .envelope
                .parameters
                .insert("expected_target_sha256".into(), value.into());
        }
        ActionRequest::seal(request.envelope).unwrap()
    }

    fn engine() -> PolicyEngine {
        PolicyEngine::from_yaml_str(include_str!("../../../config/policy.example.yaml")).unwrap()
    }

    fn terminal_request(argv_yaml: Option<&str>) -> ActionRequest {
        let mut parameters = BTreeMap::new();
        if let Some(argv_yaml) = argv_yaml {
            parameters.insert(
                "argv".into(),
                yaml_serde::from_str(argv_yaml).expect("valid test argv YAML"),
            );
        }
        ActionRequest::seal(ActionEnvelope {
            request_id: "req-terminal".into(),
            organization_id: "org-1".into(),
            actor_id: "actor-1".into(),
            device_id: "device-1".into(),
            action: "terminal.exec".into(),
            target: "local".into(),
            parameters,
            requested_capabilities: vec![],
            expires_at_unix_ms: u64::MAX,
            nonce: vec![2; 16],
        })
        .unwrap()
    }

    #[test]
    fn packaged_pilot_policy_parses() {
        let input = include_str!("../../../config/policy.pilot.example.yaml");
        assert!(PolicyEngine::from_yaml_str(input).is_ok());
    }

    #[test]
    fn accepts_utf8_bom() {
        let input = include_str!("../../../config/policy.example.yaml");
        assert!(input.starts_with('\u{feff}'));
        assert!(PolicyEngine::from_yaml_str(input).is_ok());
    }

    #[test]
    fn terminal_exec_requires_structured_argv() {
        let missing = engine().evaluate(&terminal_request(None));
        assert_eq!(missing.kind, PolicyDecisionKind::Deny);
        assert_eq!(missing.reason_code, "terminal_argv_required");

        let invalid = engine().evaluate(&terminal_request(Some(r#""python -c x""#)));
        assert_eq!(invalid.kind, PolicyDecisionKind::Deny);
        assert_eq!(invalid.reason_code, "terminal_argv_required");

        let empty = engine().evaluate(&terminal_request(Some("[]")));
        assert_eq!(empty.kind, PolicyDecisionKind::Deny);
        assert_eq!(empty.reason_code, "terminal_argv_required");
    }

    #[test]
    fn normal_terminal_exec_keeps_default_approval() {
        let decision =
            engine().evaluate(&terminal_request(Some(r#"["python", "safe_script.py"]"#)));
        assert_eq!(decision.kind, PolicyDecisionKind::Approval);
        assert_eq!(decision.required_capability, None);
        assert_eq!(decision.reason_code, "terminal_default");
    }

    #[test]
    fn inline_eval_requires_elevated_approval() {
        for argv_yaml in [
            r#"["python", "-c", "print(1)"]"#,
            r#"["python.exe", "-cprint(1)"]"#,
            r#"["py", "-3.12", "-c", "print(1)"]"#,
            r#"["node", "--eval=console.log(1)"]"#,
            r#"["node.exe", "-econsole.log(1)"]"#,
            r#"["perl", "-eprint 1"]"#,
            r#"["ruby", "-eputs(1)"]"#,
            r#"["osascript", "-e", "display dialog"]"#,
            r#"["pwsh", "-NoProfile", "-Command", "Get-Date"]"#,
            r#"["powershell.exe", "-EncodedCommand", "AAAA"]"#,
            r#"["cmd.exe", "/D", "/C", "echo hi"]"#,
            r#"["bash", "-c", "printf hi"]"#,
            r#"["wsl.exe", "bash", "-lc", "printf hi"]"#,
        ] {
            let decision = engine().evaluate(&terminal_request(Some(argv_yaml)));
            assert_eq!(decision.kind, PolicyDecisionKind::Approval);
            assert_eq!(decision.required_capability.as_deref(), Some("elevated"));
            assert_eq!(decision.reason_code, "terminal_inline_eval");
        }
    }

    #[test]
    fn inline_eval_does_not_match_script_arguments_after_positional_boundary() {
        for argv_yaml in [
            r#"["python", "script.py", "-c", "script-argument"]"#,
            r#"["node", "app.js", "-e", "script-argument"]"#,
            r#"["python", "--", "-c", "literal"]"#,
            r#"["python", "-m", "pytest", "-q"]"#,
        ] {
            let decision = engine().evaluate(&terminal_request(Some(argv_yaml)));
            assert_eq!(decision.kind, PolicyDecisionKind::Approval);
            assert_eq!(decision.required_capability, None);
            assert_eq!(decision.reason_code, "terminal_default");
        }
    }

    /// Security sprint, item 7 (vor-policy H3): every spelling of a cmd.exe
    /// inline command must require the same elevated approval as
    /// `powershell -Command`, and so must the PowerShell spellings that the
    /// shell accepts as `-Command` / `-EncodedCommand`.
    #[test]
    fn sec7_inline_eval_table_for_cmd_and_powershell_variants() {
        let inline = [
            r#"["cmd", "/c", "whoami"]"#,
            r#"["cmd", "/C", "whoami"]"#,
            r#"["cmd", "/k", "whoami"]"#,
            r#"["cmd", "/K", "whoami"]"#,
            r#"["cmd.exe", "/c", "whoami"]"#,
            r#"["CMD.EXE", "/C", "whoami"]"#,
            r#"["Cmd.Exe", "/q", "/d", "/s", "/c", "whoami"]"#,
            r#"["C:\\Windows\\System32\\cmd.exe", "/c", "whoami"]"#,
            r#"["C:/Windows/System32/CMD.EXE", "/V:ON", "/E:ON", "/C", "whoami"]"#,
            r#"["cmd", "/r", "whoami"]"#,
            r#"["cmd", "/R", "whoami"]"#,
            r#"["cmd", "/cwhoami"]"#,
            r#"["cmd", "/Kwhoami"]"#,
            r#"["powershell", "-Command", "Get-Date"]"#,
            r#"["powershell", "-c", "Get-Date"]"#,
            r#"["powershell", "/Command", "Get-Date"]"#,
            r#"["powershell", "-Com", "Get-Date"]"#,
            r#"["powershell.exe", "-e", "AAAA"]"#,
            r#"["powershell.exe", "-ec", "AAAA"]"#,
            r#"["powershell.exe", "-enc", "AAAA"]"#,
            r#"["pwsh", "-CommandWithArgs", "Get-Date"]"#,
            r#"["pwsh", "-cwa", "Get-Date"]"#,
        ];
        let mut misses = Vec::new();
        for argv_yaml in inline {
            let decision = engine().evaluate(&terminal_request(Some(argv_yaml)));
            if decision.reason_code != "terminal_inline_eval"
                || decision.required_capability.as_deref() != Some("elevated")
            {
                misses.push(argv_yaml);
            }
        }
        assert!(
            misses.is_empty(),
            "not classified as inline eval: {misses:#?}"
        );

        for argv_yaml in [
            r#"["cmd", "script.bat", "/c"]"#,
            r#"["cmdkey", "/list"]"#,
            r#"["powershell", "-File", "script.ps1"]"#,
            r#"["pwsh", "-NoProfile", "script.ps1", "-c"]"#,
        ] {
            let decision = engine().evaluate(&terminal_request(Some(argv_yaml)));
            assert_eq!(decision.reason_code, "terminal_default", "{argv_yaml}");
        }
    }

    #[test]
    fn legacy_policy_without_inline_eval_field_defaults_to_elevated_approval() {
        let input = include_str!("../../../config/policy.example.yaml")
            .replace("  inline_eval: elevated_approval\n", "");
        let engine = PolicyEngine::from_yaml_str(&input).unwrap();
        let decision = engine.evaluate(&terminal_request(Some(r#"["python", "-c", "print(1)"]"#)));
        assert_eq!(decision.kind, PolicyDecisionKind::Approval);
        assert_eq!(decision.required_capability.as_deref(), Some("elevated"));
        assert_eq!(decision.reason_code, "terminal_inline_eval");
    }

    #[test]
    fn project_read_is_auto() {
        for action in [
            "filesystem.read",
            "filesystem.list",
            "filesystem.search_files",
            "filesystem.search_content",
            "filesystem.info",
        ] {
            let decision = engine().evaluate(&request(action, r"D:\Workspaces\demo\README.md"));
            assert_eq!(decision.kind, PolicyDecisionKind::Auto, "{action}");
        }
    }

    #[test]
    fn m1_canary_write_requires_approval_without_changing_project_default() {
        let canary = engine().evaluate(&request(
            "filesystem.write",
            r"D:\Projects\vor-commander\state\local\m1-canary\live-write.txt",
        ));
        assert_eq!(canary.kind, PolicyDecisionKind::Approval);

        let ordinary = engine().evaluate(&write_request(
            r"D:\Workspaces\demo\out.txt",
            2,
            Some("absent"),
        ));
        assert_eq!(ordinary.kind, PolicyDecisionKind::Auto);
    }

    #[test]
    fn policy_auto_write_requires_bounds_and_precondition() {
        let engine = engine();
        let safe = engine.evaluate(&write_request(
            r"D:\Workspaces\demo\out.txt",
            7,
            Some("absent"),
        ));
        assert_eq!(safe.kind, PolicyDecisionKind::Auto);
        assert_eq!(safe.reason_code, "auto_write_safe");
        let missing = engine.evaluate(&write_request(r"D:\Workspaces\demo\out.txt", 7, None));
        assert_eq!(missing.kind, PolicyDecisionKind::Approval);
        assert_eq!(missing.reason_code, "auto_write_precondition_missing");
        let large = engine.evaluate(&write_request(
            r"D:\Workspaces\demo\out.txt",
            1_048_577,
            Some("absent"),
        ));
        assert_eq!(large.kind, PolicyDecisionKind::Approval);
        assert_eq!(large.reason_code, "auto_write_size_exceeded");
    }

    #[test]
    fn every_r1_sensitive_path_requires_signature() {
        let paths = [
            r"D:\Workspaces\x\a.ps1",
            r"D:\Workspaces\x\a.psm1",
            r"D:\Workspaces\x\a.psd1",
            r"D:\Workspaces\x\a.bat",
            r"D:\Workspaces\x\a.cmd",
            r"D:\Workspaces\x\a.vbs",
            r"D:\Workspaces\x\a.wsf",
            r"D:\Workspaces\x\a.hta",
            r"D:\Workspaces\x\a.exe",
            r"D:\Workspaces\x\a.dll",
            r"D:\Workspaces\x\a.msi",
            r"D:\Workspaces\x\a.lnk",
            r"D:\Workspaces\x\a.url",
            r"D:\Workspaces\x\a.reg",
            r"D:\Workspaces\x\a.scr",
            r"D:\Workspaces\x\a.sh",
            r"D:\Workspaces\x\.git\hooks\pre-commit",
            r"D:\Workspaces\x\.ssh\config",
            r"D:\Workspaces\x\.env.local",
            r"D:\Workspaces\x\.github\workflows\ci.yml",
            r"D:\Workspaces\x\Start Menu\Programs\Startup\readme.txt",
            r"D:\Workspaces\x\WindowsPowerShell\Microsoft.PowerShell_profile.ps1",
            r"D:\Workspaces\x\PowerShell\profile.ps1",
        ];
        for path in paths {
            let decision = engine().evaluate(&write_request(path, 1, Some("absent")));
            assert_eq!(decision.kind, PolicyDecisionKind::Approval, "{path}");
            assert_eq!(decision.reason_code, "auto_write_sensitive_path", "{path}");
        }
    }

    #[test]
    fn persistence_paths_require_signature() {
        let engine = engine();
        for path in [
            r"D:\Workspaces\workspace\.bashrc",
            r"D:\Workspaces\workspace\.profile",
            r"D:\Workspaces\workspace\.zshrc",
            r"D:\Workspaces\workspace\.config\systemd\user\agent.service",
            r"D:\Workspaces\workspace\etc\cron.d\agent",
            r"D:\Workspaces\workspace\var\spool\cron\crontabs\user",
            r"D:\Workspaces\workspace\Windows\System32\Tasks\agent.xml",
        ] {
            let decision = engine.evaluate(&write_request(path, 1, Some("absent")));
            assert_eq!(decision.kind, PolicyDecisionKind::Approval, "{path}");
            assert_eq!(decision.reason_code, "auto_write_sensitive_path", "{path}");
        }
    }

    #[test]
    fn ambiguous_windows_components_are_denied() {
        let paths = [
            r"D:\Workspaces\x\a.ps1.",
            r"D:\Workspaces\x\a.ps1 ",
            r"D:\Workspaces\x\.git.\config",
            r"D:\Workspaces\x\CON",
            r"D:\Workspaces\x\con.txt",
            r"D:\Workspaces\x\PRN.log",
            r"D:\Workspaces\x\AUX",
            r"D:\Workspaces\x\NUL.data",
            r"D:\Workspaces\x\COM1",
            r"D:\Workspaces\x\com9.txt",
            r"D:\Workspaces\x\LPT1",
            r"D:\Workspaces\x\lpt9.txt",
            r"D:\Workspaces\x\GIT~1\hooks\pre-commit",
            r"D:\Workspaces\x\GITHUB~1\workflows\ci.yml",
        ];
        for path in paths {
            let decision = engine().evaluate(&write_request(path, 1, Some("absent")));
            assert_eq!(decision.kind, PolicyDecisionKind::Deny, "{path}");
            assert_eq!(decision.reason_code, "filesystem_rule", "{path}");
        }
    }

    #[test]
    fn strict_mode_requires_signature_for_safe_write() {
        // Git may check the example out with CRLF endings; match the line, not its terminator.
        let input = include_str!("../../../config/policy.example.yaml").replacen(
            "mode: policy",
            "mode: strict",
            1,
        );
        assert!(input.contains("mode: strict"));
        let decision = PolicyEngine::from_yaml_str(&input)
            .unwrap()
            .evaluate(&write_request(
                r"D:\Workspaces\demo\out.txt",
                1,
                Some("absent"),
            ));
        assert_eq!(decision.kind, PolicyDecisionKind::Approval);
        assert_eq!(decision.reason_code, "strict_mode");
    }

    #[test]
    fn missing_mode_defaults_to_strict_for_safe_write() {
        let original = include_str!("../../../config/policy.example.yaml");
        let input: String = original
            .split_inclusive('\n')
            .filter(|line| line.trim_end_matches(['\r', '\n']) != "mode: policy")
            .collect();
        assert_ne!(input, original, "expected to remove the mode line");
        assert!(!input.lines().any(|line| line.starts_with("mode:")));

        let decision = PolicyEngine::from_yaml_str(&input)
            .unwrap()
            .evaluate(&write_request(
                r"D:\Workspaces\demo\out.txt",
                1,
                Some("absent"),
            ));
        assert_eq!(decision.kind, PolicyDecisionKind::Approval);
        assert_eq!(decision.reason_code, "strict_mode");
    }

    #[test]
    fn windows_write_requires_elevation_approval() {
        let decision =
            engine().evaluate(&request("filesystem.write", r"C:\Windows\System32\x.txt"));
        assert_eq!(decision.kind, PolicyDecisionKind::Approval);
        assert_eq!(decision.required_capability.as_deref(), Some("elevated"));
    }

    #[test]
    fn process_reads_are_auto_but_terminate_requires_approval() {
        assert_eq!(
            engine().evaluate(&request("process.list", "local")).kind,
            PolicyDecisionKind::Auto
        );
        assert_eq!(
            engine().evaluate(&request("process.inspect", "1234")).kind,
            PolicyDecisionKind::Auto
        );
        assert_eq!(
            engine()
                .evaluate(&request("process.terminate", "1234"))
                .kind,
            PolicyDecisionKind::Approval
        );
    }

    #[test]
    fn git_reads_in_project_inherit_filesystem_read_policy() {
        assert_eq!(
            engine()
                .evaluate(&request("git.status", r"D:\Workspaces\demo"))
                .kind,
            PolicyDecisionKind::Auto
        );
        assert_eq!(
            engine()
                .evaluate(&request("git.diff", r"C:\Windows\System32"))
                .kind,
            PolicyDecisionKind::Approval
        );
    }

    #[test]
    fn secret_extraction_is_denied() {
        let decision = engine().evaluate(&request("browser.secret.extract", "firefox"));
        assert_eq!(decision.kind, PolicyDecisionKind::Deny);
    }

    #[test]
    fn traversal_and_unknown_actions_fail_closed() {
        for action in [
            "filesystem.read",
            "filesystem.list",
            "filesystem.search_files",
            "filesystem.search_content",
            "filesystem.info",
        ] {
            let traversal = engine().evaluate(&request(action, r"D:\Workspaces\..\Windows\x"));
            assert_eq!(traversal.kind, PolicyDecisionKind::Deny, "{action}");
        }
        let unknown = engine().evaluate(&request("future.magic", "x"));
        assert_eq!(unknown.kind, PolicyDecisionKind::Deny);
    }

    /// Regression for PR #13: Windows hands out legitimate paths in 8.3 form
    /// (`%TEMP%` is `C:\Users\RUNNER~1\...` on GitHub runners, and for many users
    /// with long or spaced account names). A short alias must be evaluated as the
    /// long path it names: allowed where the long path is allowed, and still
    /// denied or escalated where the long path is.
    #[cfg(windows)]
    mod short_names {
        use super::*;
        use std::os::windows::ffi::{OsStrExt as _, OsStringExt as _};
        use std::path::{Path, PathBuf};
        use windows_sys::Win32::Storage::FileSystem::{GetLongPathNameW, GetShortPathNameW};

        type PathApi = unsafe extern "system" fn(*const u16, *mut u16, u32) -> u32;

        fn call_path_api(api: PathApi, path: &Path) -> PathBuf {
            let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
            let required = unsafe { api(wide.as_ptr(), std::ptr::null_mut(), 0) };
            assert!(required > 0, "path API failed for {}", path.display());
            let mut output = vec![0u16; required as usize];
            let written = unsafe { api(wide.as_ptr(), output.as_mut_ptr(), required) };
            assert!(
                written > 0 && written < required,
                "path API failed for {}",
                path.display()
            );
            PathBuf::from(std::ffi::OsString::from_wide(&output[..written as usize]))
        }

        /// A temporary base addressed by its long form, even when `%TMP%` itself
        /// is handed out in 8.3 form (as on GitHub runners).
        fn long_temp_base() -> (tempfile::TempDir, PathBuf) {
            let base = tempfile::tempdir().unwrap();
            let long = call_path_api(GetLongPathNameW, base.path());
            (base, long)
        }

        /// The real 8.3 alias of `long`, or `None` when the volume does not
        /// generate short names. Set `VOR_REQUIRE_SHORT_NAMES=1` to turn the skip
        /// into a failure on machines where 8.3 generation is known to be on.
        fn short_alias(long: &Path) -> Option<PathBuf> {
            let short = call_path_api(GetShortPathNameW, long);
            if short.as_os_str().eq_ignore_ascii_case(long.as_os_str()) {
                assert!(
                    std::env::var_os("VOR_REQUIRE_SHORT_NAMES").is_none(),
                    "VOR_REQUIRE_SHORT_NAMES is set but {} has no 8.3 alias",
                    long.display()
                );
                eprintln!(
                    "SKIPPED: 8.3 short names are disabled on the volume of {}; \
                     this test proves nothing here",
                    long.display()
                );
                return None;
            }
            Some(short)
        }

        fn engine_with(rules: &[(&Path, RuleDecision, RuleDecision)]) -> PolicyEngine {
            let mut engine = engine();
            engine.config.filesystem = rules
                .iter()
                .map(|(path, read, write)| FilesystemRule {
                    path: path.to_string_lossy().into_owned(),
                    read: *read,
                    write: *write,
                })
                .collect();
            engine
        }

        fn text(path: &Path) -> String {
            path.to_string_lossy().into_owned()
        }

        #[test]
        fn short_alias_inside_allowed_root_is_evaluated_as_its_long_form() {
            let (_guard, base) = long_temp_base();
            let root = base.join("allowed root with a long name");
            fs::create_dir_all(&root).unwrap();
            fs::write(root.join("notes.txt"), b"x").unwrap();
            let Some(short_root) = short_alias(&root) else {
                return;
            };
            assert!(short_root.to_string_lossy().contains('~'));
            let engine = engine_with(&[(&root, RuleDecision::Auto, RuleDecision::Auto)]);

            let long_read =
                engine.evaluate(&request("filesystem.read", &text(&root.join("notes.txt"))));
            let short_read = engine.evaluate(&request(
                "filesystem.read",
                &text(&short_root.join("notes.txt")),
            ));
            assert_eq!(long_read.kind, PolicyDecisionKind::Auto);
            assert_eq!(
                short_read.kind,
                PolicyDecisionKind::Auto,
                "{}",
                short_root.display()
            );

            let git = engine.evaluate(&request("git.status", &text(&short_root)));
            assert_eq!(git.kind, PolicyDecisionKind::Auto);

            // A new file under an existing short-named directory is still a
            // legitimate write target: only the tail that does not exist yet is
            // taken literally.
            let write = engine.evaluate(&write_request(
                &text(&short_root.join("new-file.txt")),
                1,
                Some("absent"),
            ));
            assert_eq!(
                write.kind,
                PolicyDecisionKind::Auto,
                "{}",
                write.reason_code
            );
        }

        #[test]
        fn short_alias_of_denied_or_sensitive_path_keeps_the_long_form_decision() {
            let (_guard, base) = long_temp_base();
            let secret = base.join("secret subtree with a long name");
            let workflows = base.join(".github").join("workflows");
            fs::create_dir_all(&secret).unwrap();
            fs::create_dir_all(&workflows).unwrap();
            fs::write(secret.join("key.txt"), b"x").unwrap();
            let (Some(short_secret), Some(short_github)) =
                (short_alias(&secret), short_alias(&base.join(".github")))
            else {
                return;
            };
            let engine = engine_with(&[
                (&base, RuleDecision::Auto, RuleDecision::Auto),
                (&secret, RuleDecision::Deny, RuleDecision::Deny),
            ]);
            let cases = [
                (
                    request("filesystem.read", &text(&secret.join("key.txt"))),
                    request("filesystem.read", &text(&short_secret.join("key.txt"))),
                ),
                (
                    write_request(&text(&secret.join("key.txt")), 1, Some("absent")),
                    write_request(&text(&short_secret.join("key.txt")), 1, Some("absent")),
                ),
                (
                    write_request(&text(&workflows.join("ci.yml")), 1, Some("absent")),
                    write_request(
                        &text(&short_github.join("workflows").join("ci.yml")),
                        1,
                        Some("absent"),
                    ),
                ),
            ];
            for (long, short) in cases {
                let long_decision = engine.evaluate(&long);
                let short_decision = engine.evaluate(&short);
                assert_ne!(
                    long_decision.kind,
                    PolicyDecisionKind::Auto,
                    "{}",
                    long.envelope.target
                );
                assert_eq!(
                    short_decision.kind, long_decision.kind,
                    "{}",
                    short.envelope.target
                );
                assert_eq!(
                    short_decision.reason_code, long_decision.reason_code,
                    "{}",
                    short.envelope.target
                );
            }
        }

        #[test]
        fn short_name_component_that_does_not_exist_is_denied() {
            let (_guard, base) = long_temp_base();
            let engine = engine_with(&[(&base, RuleDecision::Auto, RuleDecision::Auto)]);
            // Nothing named like this exists yet; once `.git` is created it could
            // become an alias of it, so it cannot be taken literally.
            for target in [
                base.join("GIT~1").join("hooks").join("pre-commit"),
                base.join("missing directory")
                    .join("GITHUB~1")
                    .join("ci.yml"),
            ] {
                let read = engine.evaluate(&request("filesystem.read", &text(&target)));
                let write = engine.evaluate(&write_request(&text(&target), 1, Some("absent")));
                assert_eq!(read.kind, PolicyDecisionKind::Deny, "{}", target.display());
                assert_eq!(write.kind, PolicyDecisionKind::Deny, "{}", target.display());
            }
        }
    }
}
