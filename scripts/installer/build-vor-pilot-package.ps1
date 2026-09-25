param(
  [string]$Version = '0.1.0-beta.2',
  [string]$OutputDirectory = (Join-Path (Resolve-Path (Join-Path $PSScriptRoot '..\..')) 'target\pilot-package'),
  [string]$CertificateThumbprint,
  [string]$TimestampUrl = 'http://timestamp.digicert.com',
  [switch]$SkipBuild,
  [string]$CargoPath,
  [string]$VcVarsPath
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
. (Join-Path $repo 'scripts\local\toolchain.ps1')
if (-not $SkipBuild) {
  Invoke-VorCargoBuild -RepoRoot $repo -Packages @('vor-agent','vor-control-plane','vor-gateway','vor-approver') -CargoPath $CargoPath -VcVarsPath $VcVarsPath
}
$stage = Join-Path $OutputDirectory "VorCommanderPilot-$Version"
if (Test-Path -LiteralPath $stage) { Remove-Item -LiteralPath $stage -Recurse -Force }
New-Item -ItemType Directory -Force -Path (Join-Path $stage 'target\release'),(Join-Path $stage 'scripts\local'),(Join-Path $stage 'scripts\installer'),(Join-Path $stage 'config') | Out-Null
foreach ($name in @('vor-agent.exe','vor-control-plane.exe','vor-gateway.exe','vor-approver.exe')) {
  $source = Join-Path $repo "target\release\$name"
  if (-not (Test-Path -LiteralPath $source)) { throw "Missing release binary: $source" }
  Copy-Item -LiteralPath $source -Destination (Join-Path $stage 'target\release')
}
foreach ($name in @('common.ps1','toolchain.ps1','bootstrap-vor-local.ps1','start-vor-local.ps1','stop-vor-local.ps1','status-vor-local.ps1','new-mcp-grant.ps1','show-mcp-token.ps1','approve-vor-request.ps1')) {
  Copy-Item -LiteralPath (Join-Path $repo "scripts\local\$name") -Destination (Join-Path $stage 'scripts\local')
}
foreach ($name in @('install-vor-pilot.ps1','uninstall-vor-pilot.ps1','link-vor-clients.ps1','verify-vor-pilot.ps1')) {
  Copy-Item -LiteralPath (Join-Path $repo "scripts\installer\$name") -Destination (Join-Path $stage 'scripts\installer')
}
# The repo's policy.example.yaml is the development fixture the tests load; the package ships the generic pilot policy.
Copy-Item -LiteralPath (Join-Path $repo 'config\policy.pilot.example.yaml') -Destination (Join-Path $stage 'config\policy.example.yaml')
Copy-Item -LiteralPath (Join-Path $repo 'docs\PILOT_INSTALLER_README.md') -Destination (Join-Path $stage 'README.md')

if ($CertificateThumbprint) {
  $signtool = Get-ChildItem 'C:\Program Files (x86)\Windows Kits\10\bin' -Filter signtool.exe -Recurse -ErrorAction SilentlyContinue | Sort-Object FullName -Descending | Select-Object -First 1
  if (-not $signtool) { throw 'signtool.exe was not found. Install an approved Windows SDK only with owner approval.' }
  foreach ($file in Get-ChildItem -LiteralPath $stage -Recurse -File | Where-Object { $_.Extension -in @('.exe','.ps1') }) {
    & $signtool.FullName sign /sha1 $CertificateThumbprint /fd SHA256 /tr $TimestampUrl /td SHA256 $file.FullName
    if ($LASTEXITCODE -ne 0) { throw "Authenticode signing failed: $($file.FullName)" }
  }
}
$manifest = Join-Path $stage 'release-manifest.sha256'
$lines = Get-ChildItem -LiteralPath $stage -Recurse -File | Where-Object { $_.FullName -ne $manifest } | Sort-Object FullName | ForEach-Object {
  $relative = $_.FullName.Substring($stage.Length + 1).Replace('\','/')
  '{0}  {1}' -f (Get-FileHash -Algorithm SHA256 -LiteralPath $_.FullName).Hash.ToLowerInvariant(),$relative
}
$encoding = New-Object System.Text.UTF8Encoding($false)
[IO.File]::WriteAllText($manifest, (($lines -join "`r`n") + "`r`n"), $encoding)
$zip = Join-Path $OutputDirectory "VorCommanderPilot-$Version-win-x64.zip"
if (Test-Path -LiteralPath $zip) { Remove-Item -LiteralPath $zip -Force }
Compress-Archive -LiteralPath $stage -DestinationPath $zip -CompressionLevel Optimal
$zipHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $zip).Hash.ToLowerInvariant()
[IO.File]::WriteAllText(($zip + '.sha256'), "$zipHash  $([IO.Path]::GetFileName($zip))`r`n", $encoding)
Write-Host "Package: $zip"
Write-Host "SHA256:  $zipHash"
