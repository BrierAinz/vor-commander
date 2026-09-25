param(
  [Parameter(Mandatory=$true)][string]$PackageZip,
  [string]$TestRoot = (Join-Path 'D:\' ('vor-pilot-installer-test-' + [guid]::NewGuid().ToString('N')))
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$extract = Join-Path $TestRoot 'package'
$install = Join-Path $TestRoot 'installed'
$allowed = Join-Path $TestRoot 'allowed'
$configs = Join-Path $TestRoot 'client-configs'
New-Item -ItemType Directory -Force -Path $extract,$allowed,$configs | Out-Null
Expand-Archive -LiteralPath $PackageZip -DestinationPath $extract
$package = Get-ChildItem -LiteralPath $extract -Directory | Select-Object -First 1
if (-not $package) { throw 'Package root was not found.' }
$manifest = Join-Path $package.FullName 'release-manifest.sha256'
foreach ($line in Get-Content -LiteralPath $manifest) {
  if ($line -notmatch '^([0-9a-f]{64})  (.+)$') { throw "Invalid manifest line: $line" }
  $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $package.FullName $Matches[2])).Hash.ToLowerInvariant()
  if ($actual -ne $Matches[1]) { throw "Manifest mismatch: $($Matches[2])" }
}
Write-Host 'PHASE manifest: PASS'
$cursor = Join-Path $configs 'cursor.json'
$vscode = Join-Path $configs 'vscode.json'
$claude = Join-Path $configs 'claude.json'
$encoding = New-Object System.Text.UTF8Encoding($false)
[IO.File]::WriteAllText($cursor, '{"mcpServers":{"other":{"command":"keep-me"}},"keep":"cursor"}', $encoding)
[IO.File]::WriteAllText($vscode, '{"servers":{"other":{"command":"keep-me"}},"keep":"vscode"}', $encoding)
[IO.File]::WriteAllText($claude, '{"mcpServers":{"other":{"command":"keep-me"}},"keep":"claude"}', $encoding)
$installScript = Join-Path $package.FullName 'scripts\installer\install-vor-pilot.ps1'
$common = @{ InstallRoot=$install; AllowedRoot=@($allowed); DeviceId='vor-installer-e2e'; SkipStartupTask=$true; CursorConfigPath=$cursor; VsCodeConfigPath=$vscode; ClaudeConfigPath=$claude }
Write-Host 'PHASE install'
& $installScript @common
& (Join-Path $install 'scripts\installer\verify-vor-pilot.ps1') -InstallRoot $install
Write-Host 'PHASE reinstall'
& $installScript @common
& (Join-Path $install 'scripts\installer\verify-vor-pilot.ps1') -InstallRoot $install
foreach ($path in @($cursor,$vscode)) {
  $json = Get-Content -Raw -LiteralPath $path | ConvertFrom-Json
  if ($json.keep -notmatch 'cursor|vscode' -or -not $json.PSObject.Properties['keep']) { throw "Unrelated config was changed: $path" }
}
if ((Get-Content -Raw -LiteralPath $claude) -notmatch 'keep-me') { throw 'Claude config was changed.' }
$uninstall = Join-Path $install 'scripts\installer\uninstall-vor-pilot.ps1'
if (-not (Test-Path -LiteralPath (Join-Path $install 'state\local\linked-clients.json'))) { throw 'Client link record is missing.' }
Write-Host 'PHASE uninstall'
& $uninstall -InstallRoot $install -SkipStartupTask
if (Test-Path -LiteralPath $install) { throw 'Install directory remains after uninstall.' }
$archives = @(Get-ChildItem -LiteralPath $TestRoot -Directory -Filter 'VorCommanderPilot-audit-*')
if ($archives.Count -ne 1 -or -not (Get-ChildItem -LiteralPath $archives[0].FullName -File)) { throw 'Default uninstall did not preserve audit data.' }
Remove-Item -LiteralPath $archives[0].FullName -Recurse -Force
$cursorJson = Get-Content -Raw -LiteralPath $cursor | ConvertFrom-Json
$vscodeJson = Get-Content -Raw -LiteralPath $vscode | ConvertFrom-Json
if ($cursorJson.mcpServers.PSObject.Properties['vor-commander']) { throw 'Cursor Vor entry remains.' }
if ($vscodeJson.servers.PSObject.Properties['vor-commander']) { throw 'VS Code Vor entry remains.' }
if (-not $cursorJson.mcpServers.PSObject.Properties['other'] -or -not $vscodeJson.servers.PSObject.Properties['other']) { throw 'Another client entry was removed.' }
Write-Host 'RESULT PASS: manifest, install, commander_status, reinstall, audit preservation, uninstall, and config preservation'
Write-Host "Test root: $TestRoot"
