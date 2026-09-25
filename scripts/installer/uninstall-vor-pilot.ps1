param(
  [string]$InstallRoot = (Join-Path $env:LOCALAPPDATA 'VorCommanderPilot'),
  [switch]$RemoveData,
  [switch]$SkipStartupTask
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$installFull = [IO.Path]::GetFullPath($InstallRoot)
if (-not (Test-Path -LiteralPath $installFull)) { Write-Host 'Vor Commander Pilot is not installed.'; exit 0 }
& (Join-Path $installFull 'scripts\local\stop-vor-local.ps1')

if (-not $SkipStartupTask) {
  Unregister-ScheduledTask -TaskName 'Vor Commander Pilot' -Confirm:$false -ErrorAction SilentlyContinue
}
$recordPath = Join-Path $installFull 'state\local\linked-clients.json'
if (Test-Path -LiteralPath $recordPath) {
  $records = Get-Content -Raw -LiteralPath $recordPath | ConvertFrom-Json
  foreach ($record in $records) {
    if (-not (Test-Path -LiteralPath $record.path)) { continue }
    $document = Get-Content -Raw -LiteralPath $record.path | ConvertFrom-Json
    $containerProperty = $document.PSObject.Properties[[string]$record.container]
    if ($containerProperty -and $containerProperty.Value.PSObject.Properties['vor-commander']) {
      $containerProperty.Value.PSObject.Properties.Remove('vor-commander')
      $temp = "$($record.path).vor-new-$PID"
      $encoding = New-Object System.Text.UTF8Encoding($false)
      [IO.File]::WriteAllText($temp, ($document | ConvertTo-Json -Depth 20), $encoding)
      Move-Item -LiteralPath $temp -Destination $record.path -Force
      Write-Host "Removed vor-commander from $($record.path)"
    }
    if ($record.PSObject.Properties['backup'] -and $record.backup -and $record.backup.created -and (Test-Path -LiteralPath $record.backup.path)) {
      $backupHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $record.backup.path).Hash.ToLowerInvariant()
      if ($backupHash -eq $record.backup.sha256) {
        Remove-Item -LiteralPath $record.backup.path -Force
        Write-Host "Removed unchanged Vor backup $($record.backup.path)"
      } else {
        Write-Warning "Kept modified backup $($record.backup.path)"
      }
    }
  }
}
if (-not $RemoveData) {
  $auditSource = Join-Path $installFull 'state\local\device-runtime'
  if (Test-Path -LiteralPath $auditSource) {
    $archive = Join-Path (Split-Path -Parent $installFull) ('VorCommanderPilot-audit-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))
    New-Item -ItemType Directory -Force -Path $archive | Out-Null
    Get-ChildItem -LiteralPath $auditSource -File | Where-Object { $_.Name -match 'audit|\.db$|\.jsonl$' } | Copy-Item -Destination $archive
    Write-Host "Audit data preserved at: $archive"
  }
}
Remove-Item -LiteralPath $installFull -Recurse -Force
Write-Host "Vor Commander Pilot removed from: $installFull"
