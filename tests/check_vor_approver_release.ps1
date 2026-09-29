Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent $PSScriptRoot
$targetDir = if ($env:CARGO_TARGET_DIR) {
  $env:CARGO_TARGET_DIR
} else {
  Join-Path $repoRoot 'target'
}
Push-Location $repoRoot
try {
  $previousErrorActionPreference = $ErrorActionPreference
  $ErrorActionPreference = 'Continue'
  try {
    cargo build --release -p vor-approver
    $buildExitCode = $LASTEXITCODE
  } finally {
    $ErrorActionPreference = $previousErrorActionPreference
  }
  if ($buildExitCode -ne 0) { throw 'Release build of vor-approver failed.' }

  $approver = Join-Path $targetDir 'release\vor-approver.exe'
  $previousErrorActionPreference = $ErrorActionPreference
  $ErrorActionPreference = 'Continue'
  try {
    $help = (& $approver --help) -join "`n"
    $helpExitCode = $LASTEXITCODE
  } finally {
    $ErrorActionPreference = $previousErrorActionPreference
  }
  if ($helpExitCode -ne 0) { throw 'vor-approver --help failed.' }
  if ($help.Contains('--confirmed')) {
    throw 'Release help exposes the removed --confirmed bypass.'
  }

  $previousErrorActionPreference = $ErrorActionPreference
  $ErrorActionPreference = 'Continue'
  try {
    $output = (& $approver sign --confirmed 2>&1) -join "`n"
  } finally {
    $signExitCode = $LASTEXITCODE
    $ErrorActionPreference = $previousErrorActionPreference
  }
  if ($signExitCode -eq 0) { throw 'Release binary accepted the removed --confirmed bypass.' }
  if (-not $output.Contains('unsupported sign option: --confirmed')) {
    throw "Release binary rejected --confirmed unexpectedly: $output"
  }

  Write-Host 'PASS: release help omits --confirmed and the argument is rejected.'
} finally {
  Pop-Location
}
