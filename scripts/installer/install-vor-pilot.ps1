param(
  [string]$InstallRoot = (Join-Path $env:LOCALAPPDATA 'VorCommanderPilot'),
  [string[]]$AllowedRoot = @([Environment]::GetFolderPath('MyDocuments')),
  [string]$DeviceId = ('vor-' + [Environment]::MachineName.ToLowerInvariant()),
  [switch]$SkipStartupTask,
  [switch]$SkipClientLinks,
  [string]$CursorConfigPath,
  [string]$VsCodeConfigPath,
  [string]$ClaudeConfigPath
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$packageRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$installFull = [IO.Path]::GetFullPath($InstallRoot)
$packageFull = [IO.Path]::GetFullPath($packageRoot)
if ($installFull -eq $packageFull -or $installFull.StartsWith($packageFull + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
  throw 'InstallRoot must be outside the extracted package directory.'
}
if (-not $AllowedRoot -or $AllowedRoot.Count -eq 0) { throw 'At least one allowed root is required.' }
foreach ($root in $AllowedRoot) {
  if (-not (Test-Path -LiteralPath $root -PathType Container)) { throw "Allowed root does not exist: $root" }
  $resolved = (Resolve-Path -LiteralPath $root).Path
  if ([IO.Path]::GetPathRoot($resolved) -eq $resolved) { throw "A drive root is not allowed: $resolved" }
}

$stop = Join-Path $installFull 'scripts\local\stop-vor-local.ps1'
if (Test-Path -LiteralPath $stop) { & $stop }
$existingPolicy = Join-Path $installFull 'config\policy.example.yaml'
$savedPolicy = $null
if (Test-Path -LiteralPath $existingPolicy) { $savedPolicy = Get-Content -Raw -LiteralPath $existingPolicy }
New-Item -ItemType Directory -Force -Path $installFull | Out-Null
foreach ($relative in @('target','scripts','config')) {
  $source = Join-Path $packageFull $relative
  if (-not (Test-Path -LiteralPath $source)) { throw "Package is missing: $relative" }
  $destination = Join-Path $installFull $relative
  if (Test-Path -LiteralPath $destination) { Remove-Item -LiteralPath $destination -Recurse -Force }
  Copy-Item -LiteralPath $source -Destination $destination -Recurse -Force
}
if ($null -ne $savedPolicy) {
  $packagedPolicy = Get-Content -Raw -LiteralPath $existingPolicy
  if ($packagedPolicy -ne $savedPolicy) {
    $newPolicy = $existingPolicy + '.new'
    Copy-Item -LiteralPath $existingPolicy -Destination $newPolicy -Force
    Write-Warning "Kept the existing policy; the packaged policy is available at $newPolicy"
  }
  $encoding = New-Object System.Text.UTF8Encoding($false)
  [IO.File]::WriteAllText($existingPolicy, $savedPolicy, $encoding)
} else {
  Remove-Item -LiteralPath $existingPolicy -Force
}
Copy-Item -LiteralPath (Join-Path $packageFull 'README.md') -Destination $installFull -Force

$bootstrap = Join-Path $installFull 'scripts\local\bootstrap-vor-local.ps1'
& $bootstrap -DeviceId $DeviceId -AllowedRoot $AllowedRoot -SkipBuild

if (-not $SkipStartupTask) {
  $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument ('-NoProfile -ExecutionPolicy Bypass -File "{0}"' -f (Join-Path $installFull 'scripts\local\start-vor-local.ps1'))
  $trigger = New-ScheduledTaskTrigger -AtLogOn -User ([Security.Principal.WindowsIdentity]::GetCurrent().Name)
  $principal = New-ScheduledTaskPrincipal -UserId ([Security.Principal.WindowsIdentity]::GetCurrent().Name) -LogonType Interactive -RunLevel Limited
  Register-ScheduledTask -TaskName 'Vor Commander Pilot' -Action $action -Trigger $trigger -Principal $principal -Force | Out-Null
  Write-Host 'Per-user logon task installed: Vor Commander Pilot'
}

if (-not $SkipClientLinks) {
  $linkArgs = @{ InstallRoot = $installFull }
  if ($CursorConfigPath) { $linkArgs.CursorConfigPath = $CursorConfigPath }
  if ($VsCodeConfigPath) { $linkArgs.VsCodeConfigPath = $VsCodeConfigPath }
  if ($ClaudeConfigPath) { $linkArgs.ClaudeConfigPath = $ClaudeConfigPath }
  & (Join-Path $installFull 'scripts\installer\link-vor-clients.ps1') @linkArgs
}
Write-Host "Vor Commander Pilot installed at: $installFull"
