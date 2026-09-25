param(
  [string]$InstallRoot = (Join-Path $env:LOCALAPPDATA 'VorCommanderPilot'),
  [string]$CursorConfigPath = (Join-Path $env:USERPROFILE '.cursor\mcp.json'),
  [string]$VsCodeConfigPath = (Join-Path $env:APPDATA 'Code\User\mcp.json'),
  [string]$ClaudeConfigPath = (Join-Path $env:APPDATA 'Claude\claude_desktop_config.json'),
  [switch]$SkipClaudeNotice
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script:BackupRecords = @{}
$oldRecordPath = Join-Path $InstallRoot 'state\local\linked-clients.json'
if (Test-Path -LiteralPath $oldRecordPath) {
  # PS 5.1 emits a JSON array as one pipeline object; assign first so @() does not nest it.
  $oldRecords = Get-Content -Raw -LiteralPath $oldRecordPath | ConvertFrom-Json
  foreach ($oldRecord in @($oldRecords)) {
    if ($oldRecord.PSObject.Properties['backup'] -and $oldRecord.backup) { $script:BackupRecords[[string]$oldRecord.path] = $oldRecord.backup }
  }
}

function Write-JsonEntry([string]$Path, [string]$Container, [hashtable]$Entry) {
  $parent = Split-Path -Parent $Path
  New-Item -ItemType Directory -Force -Path $parent | Out-Null
  $document = [pscustomobject]@{}
  if (Test-Path -LiteralPath $Path) {
    $raw = Get-Content -Raw -LiteralPath $Path
    if ($raw.Trim()) { $document = $raw | ConvertFrom-Json }
    if (-not (Test-Path -LiteralPath ($Path + '.vor-backup'))) {
      Copy-Item -LiteralPath $Path -Destination ($Path + '.vor-backup')
      $script:BackupRecords[$Path] = [ordered]@{ path=($Path + '.vor-backup'); sha256=(Get-FileHash -Algorithm SHA256 -LiteralPath ($Path + '.vor-backup')).Hash.ToLowerInvariant(); created=$true }
    }
  }
  if (-not $document.PSObject.Properties[$Container]) {
    $document | Add-Member -NotePropertyName $Container -NotePropertyValue ([pscustomobject]@{})
  }
  $servers = $document.PSObject.Properties[$Container].Value
  if ($servers.PSObject.Properties['vor-commander']) {
    $servers.PSObject.Properties.Remove('vor-commander')
  }
  $servers | Add-Member -NotePropertyName 'vor-commander' -NotePropertyValue ([pscustomobject]$Entry)
  $temp = "$Path.vor-new-$PID"
  $encoding = New-Object System.Text.UTF8Encoding($false)
  [IO.File]::WriteAllText($temp, ($document | ConvertTo-Json -Depth 20), $encoding)
  Move-Item -LiteralPath $temp -Destination $Path -Force
  Write-Host "Linked vor-commander in $Path"
}

$cred = Import-Clixml (Join-Path $InstallRoot 'state\local\mcp-credential.clixml')
$ptr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($cred.Password)
try { $token = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr) } finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr) }
$headers = @{ Authorization = "Bearer $token" }
Write-JsonEntry $CursorConfigPath 'mcpServers' @{ url = 'http://127.0.0.1:8742/mcp'; headers = $headers }
Write-JsonEntry $VsCodeConfigPath 'servers' @{ type = 'http'; url = 'http://127.0.0.1:8742/mcp'; headers = $headers }
$token = $null
if (-not $SkipClaudeNotice) {
  Write-Warning "Claude Desktop was not modified at $ClaudeConfigPath. Its documented JSON format launches local stdio servers, while Vor Form A exposes Streamable HTTP. Add the deployed HTTPS endpoint through Settings > Connectors when Form B is available."
}
$cursorFull = [IO.Path]::GetFullPath($CursorConfigPath)
$vscodeFull = [IO.Path]::GetFullPath($VsCodeConfigPath)
$records = @(
  [ordered]@{ client='cursor'; path=$cursorFull; container='mcpServers'; backup=$script:BackupRecords[$cursorFull] },
  [ordered]@{ client='vscode'; path=$vscodeFull; container='servers'; backup=$script:BackupRecords[$vscodeFull] }
)
$recordPath = Join-Path $InstallRoot 'state\local\linked-clients.json'
$encoding = New-Object System.Text.UTF8Encoding($false)
[IO.File]::WriteAllText($recordPath, ($records | ConvertTo-Json -Depth 5), $encoding)
