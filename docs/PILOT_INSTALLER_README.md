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

The installer uses the existing bootstrap to create the local CA, certificates, MCP credential, and owner approval key without asking the user to copy secrets. Both private keys are protected in the current-user DPAPI secret store. The owner key is reused on reinstall, its public key is written to the trusted approvers file, and the agent is launched with that file.

The installed policy is generated from `-AllowedRoot`. On reinstall, an existing policy is never overwritten. If the package contains a different example, it is saved beside the policy as `policy.example.yaml.new` and a warning is shown.

## Approving writes, edits, and terminal commands

`prepare_write`, `prepare_edit`, and `prepare_terminal` do not perform the action. They return `request_base64` (an opaque request) and `challenge`. For edits, they also return `diff_summary`. Pass those exact values to the installed approval script:

```powershell
$approval = .\scripts\local\approve-vor-request.ps1 `
  -RequestBase64 '<request_base64>' `
  -Challenge '<challenge JSON>' `
  -DiffSummary '<prepare_edit diff_summary>'
```

The script validates that the challenge is bound to the request, then shows the action, target path or working directory, structured terminal argv or edit diff, actor/device, expiry, timeout, and output budget. It signs only after the owner types `APPROVE`. The final output line is the `approval_base64` value to use with the unchanged request in `commit_write` or `commit_terminal`. Each approval is one-use; replay is rejected as `approval_replayed`.

`-Confirm` is an explicit non-interactive confirmation intended for controlled automation and tests. It still prints and validates the complete summary before signing. Do not use it for requests the owner has not already reviewed.

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

Client `*.vor-backup` files created by Vor are recorded with their hash. Uninstall removes them only when they are still byte-for-byte unchanged; a modified or unowned backup is retained with a warning.

## MCP grant rotation

Run `new-mcp-grant.ps1 -RevokePrevious` to issue and store a new DPAPI-protected MCP token and revoke the previously recorded grant. Without the switch, the prior grant remains valid to support deliberate overlap during client migration.

## Known limitations

- Claude Desktop cannot be linked automatically for Form A without a new stdio adapter or the public HTTPS Form B connector.
- Cursor and VS Code store the bearer header in their JSON configuration. File ACL protection is delegated to each client; rotate the grant if a config is exposed.
- The logon task cannot run before the owner signs in.
- Authenticode behavior cannot be proven until the owner supplies a valid certificate.

