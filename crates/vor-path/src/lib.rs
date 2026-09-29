// SPDX-License-Identifier: MPL-2.0

use std::path::{Component, Path};

pub fn path_within(path: &Path, root: &Path) -> bool {
    #[cfg(windows)]
    {
        windows_path_within(&normalize_windows_path(path), &normalize_windows_path(root))
    }
    #[cfg(not(windows))]
    {
        path == root || path.starts_with(root)
    }
}

pub fn windows_path_within(path: &str, root: &str) -> bool {
    let path = path.trim_end_matches(['\\', '/']);
    let root = root.trim_end_matches(['\\', '/']);
    path.eq_ignore_ascii_case(root)
        || path.get(root.len()..).is_some_and(|suffix| {
            path[..root.len()].eq_ignore_ascii_case(root) && suffix.starts_with(['\\', '/'])
        })
}

#[cfg(windows)]
fn normalize_windows_path(path: &Path) -> String {
    path.to_string_lossy().replace('/', "\\")
}

pub fn sensitive_path(path: &Path) -> bool {
    let normalized = path
        .components()
        .filter_map(|component| match component {
            Component::Normal(value) => Some(value.to_string_lossy()),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("\\");
    sensitive_windows_path(&normalized)
}

pub fn sensitive_windows_path(path: &str) -> bool {
    let normalized = path.replace('/', "\\").to_ascii_lowercase();
    let parts = normalized
        .split('\\')
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>();
    if parts
        .iter()
        .any(|part| matches!(*part, ".git" | ".ssh" | "startup"))
        || parts
            .windows(2)
            .any(|pair| pair == [".github", "workflows"])
        || parts.iter().any(|part| part.starts_with(".env"))
    {
        return true;
    }
    let name = parts.last().copied().unwrap_or_default();
    if matches!(
        name,
        ".bashrc" | ".profile" | ".zshrc" | ".bash_profile" | ".zprofile"
    ) || parts
        .windows(3)
        .any(|pair| pair == [".config", "systemd", "user"])
        || parts.windows(2).any(|pair| pair == ["etc", "cron.d"])
        || parts
            .windows(4)
            .any(|pair| pair == ["var", "spool", "cron", "crontabs"])
        || parts
            .windows(3)
            .any(|pair| pair == ["windows", "system32", "tasks"])
        || normalized.contains("\\start menu\\programs\\startup\\")
        || normalized.ends_with("\\start menu\\programs\\startup")
        || ((normalized.contains("\\windowspowershell\\") || normalized.contains("\\powershell\\"))
            && name.contains("profile")
            && name.ends_with(".ps1"))
    {
        return true;
    }
    const SENSITIVE_EXTENSIONS: &[&str] = &[
        "ps1", "psm1", "psd1", "bat", "cmd", "vbs", "wsf", "hta", "exe", "dll", "msi", "lnk",
        "url", "reg", "scr", "sh", "bash", "zsh", "fish",
    ];
    SENSITIVE_EXTENSIONS
        .iter()
        .any(|extension| name.ends_with(&format!(".{extension}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn containment_requires_a_component_boundary() {
        assert!(windows_path_within(r"C:\root\child", r"c:\root"));
        assert!(!windows_path_within(r"C:\rooted", r"C:\root"));
    }

    #[test]
    fn sensitive_rules_are_shared_for_strings_and_paths() {
        for path in [
            r"C:\repo\.github\workflows\ci.yml",
            r"C:\tmp\run.ps1",
            r"C:\Users\alice\.bashrc",
            r"C:\Users\alice\.config\systemd\user\agent.service",
            r"C:\Windows\System32\Tasks\agent",
            r"C:\etc\cron.d\agent",
            r"C:\var\spool\cron\crontabs\alice",
        ] {
            assert!(sensitive_windows_path(path));
            assert!(sensitive_path(Path::new(path)));
        }
        assert!(!sensitive_windows_path(r"C:\repo\src\lib.rs"));
    }
}
