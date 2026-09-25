# Vor Commander Pilot - local installer (Form A)

This signed/signable ZIP installs the local pilot per user. It does not install a Windows service, open a public port, change Windows Firewall, or require administrator rights. The gateway binds to loopback only.

## Verify and install

1. Compare the ZIP with its adjacent `.sha256` file using `Get-FileHash -Algorithm SHA256`.
2. Extract the ZIP.
3. Run:

```powershell
.\scripts\installer\install-vor-pilot.ps1 -AllowedRoot 'D:\Projects\MyProject'
```

Pass multiple explicit folders as `-AllowedRoot @('D:\ProjectA','D:\ProjectB')`. A drive root is rejected. If omitted, the only allowed root is the current user's Documents folder. Reads are automatic inside these roots; writes and ordinary terminal commands require approval. Destructive/elevated terminal operations, browser use, desktop control, public listeners, purchases, and secret extraction are denied by the packaged default policy.

The installer uses the existing bootstrap to create the local CA, certificates, and DPAPI-protected credentials without asking the user to copy keys. It starts the control plane and agent, checks all local health endpoints, and invokes `commander_status` through MCP.

## Startup choice

The pilot uses a per-user scheduled task at logon, not a Windows service. A service normally requires elevation and would either run as SYSTEM or require storing service credentials; both conflict with the current-user DPAPI identity. The logon task runs with limited privileges as the owner. Use `-SkipStartupTask` for a session-only install.

## Client links

The installer atomically adds only `vor-commander`, backing up the previous JSON as `*.vor-backup`:

- Cursor global: `%USERPROFILE%\.cursor\mcp.json`, top-level `mcpServers`.
- VS Code user profile: `%APPDATA%\Code\User\mcp.json`, top-level `servers` with `type: http`.

Cursor documents Streamable HTTP configuration and the global `~/.cursor/mcp.json` file: https://docs.cursor.com/context/model-context-protocol

Microsoft documents the VS Code `servers` format and confirms both Cursor's global path and Claude Desktop's Windows path: https://code.visualstudio.com/docs/agents/reference/mcp-configuration

Claude Desktop is deliberately not edited. Anthropic states that remote HTTP servers configured directly in `claude_desktop_config.json` will not connect; remote servers must be added through Settings > Connectors. The local JSON format launches stdio processes, and Form A has no stdio adapter. Source: https://support.anthropic.com/en/articles/11503834-building-custom-integrations-via-remote-mcp-servers

For tests, redirect every client path with `-CursorConfigPath`, `-VsCodeConfigPath`, and `-ClaudeConfigPath`.

## Authenticode

No certificate is bundled or invented. The package builder accepts `-CertificateThumbprint` and signs every EXE and PowerShell script with SHA-256 plus an RFC 3161 timestamp. Without that parameter it produces a signable ZIP and SHA-256 manifests. Installing a Windows SDK or obtaining a certificate is an explicit owner action.

## Uninstall

```powershell
.\scripts\installer\uninstall-vor-pilot.ps1
```

Uninstall stops only processes whose PID and executable path match this installation, removes the per-user task, removes only its own client entries, and deletes installed files. Audit files are preserved by default in a timestamped sibling directory. Pass `-RemoveData` to remove them too.

## Known limitations

- Claude Desktop cannot be linked automatically for Form A without a new stdio adapter or the public HTTPS Form B connector.
- Cursor and VS Code store the bearer header in their JSON configuration. File ACL protection is delegated to each client; rotate the grant if a config is exposed.
- The logon task cannot run before the owner signs in.
- Authenticode behavior cannot be proven until the owner supplies a valid certificate.

