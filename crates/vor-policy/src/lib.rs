// SPDX-License-Identifier: MPL-2.0

use serde::Deserialize;
use std::{fs, path::Path};
use thiserror::Error;
use vor_protocol::{ActionRequest, PolicyDecision, PolicyDecisionKind};

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
}

impl PolicyEngine {
    pub fn from_yaml_str(input: &str) -> Result<Self, PolicyError> {
        let input = input.trim_start_matches('\u{feff}');
        let config: PolicyConfig = yaml_serde::from_str(input)?;
        if config.version != 1 || config.policy_id.trim().is_empty() {
            return Err(PolicyError::InvalidConfig);
        }
        Ok(Self { config })
    }

    pub fn from_yaml_file(path: impl AsRef<Path>) -> Result<Self, PolicyError> {
        Self::from_yaml_str(&fs::read_to_string(path)?)
    }

    pub fn config(&self) -> &PolicyConfig {
        &self.config
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
            "filesystem.write" => (
                self.filesystem_decision(&request.envelope.target, true),
                "filesystem_rule",
            ),
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
            .filter(|(root, _)| path_within(&target, root))
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

fn normalize_windows_path(input: &str) -> Option<String> {
    let path = input.trim().replace('/', "\\");
    let bytes = path.as_bytes();
    if bytes.len() < 3 || !bytes[0].is_ascii_alphabetic() || bytes[1] != b':' || bytes[2] != b'\\' {
        return None;
    }
    let drive = (bytes[0] as char).to_ascii_uppercase();
    let mut parts = Vec::new();
    for part in path[3..].split('\\').filter(|p| !p.is_empty()) {
        if part == "." || part == ".." || part.contains(':') || part.contains('\0') {
            return None;
        }
        parts.push(part.to_ascii_lowercase());
    }
    let suffix = parts.join("\\");
    Some(if suffix.is_empty() {
        format!("{drive}:\\")
    } else {
        format!("{drive}:\\{suffix}")
    })
}

fn path_within(target: &str, root: &str) -> bool {
    if target.eq_ignore_ascii_case(root) {
        return true;
    }
    let prefix = if root.ends_with('\\') {
        root.to_owned()
    } else {
        format!("{root}\\")
    };
    target
        .to_ascii_lowercase()
        .starts_with(&prefix.to_ascii_lowercase())
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
            let decision = engine().evaluate(&request(action, r"D:\Proyectos\demo\README.md"));
            assert_eq!(decision.kind, PolicyDecisionKind::Auto, "{action}");
        }
    }

    #[test]
    fn m1_canary_write_requires_approval_without_changing_project_default() {
        let canary = engine().evaluate(&request(
            "filesystem.write",
            r"D:\Proyectos\10_Active\vor-commander\state\local\m1-canary\live-write.txt",
        ));
        assert_eq!(canary.kind, PolicyDecisionKind::Approval);

        let ordinary =
            engine().evaluate(&request("filesystem.write", r"D:\Proyectos\demo\out.txt"));
        assert_eq!(ordinary.kind, PolicyDecisionKind::Auto);
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
                .evaluate(&request("git.status", r"D:\Proyectos\demo"))
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
            let traversal = engine().evaluate(&request(action, r"D:\Proyectos\..\Windows\x"));
            assert_eq!(traversal.kind, PolicyDecisionKind::Deny, "{action}");
        }
        let unknown = engine().evaluate(&request("future.magic", "x"));
        assert_eq!(unknown.kind, PolicyDecisionKind::Deny);
    }
}
