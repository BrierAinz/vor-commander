<#
  Locates the Rust and MSVC toolchains without machine-specific paths. Dot-source it:
      . (Join-Path $PSScriptRoot 'toolchain.ps1')
      $cargo  = Resolve-VorCargo -CargoPath $CargoPath
      $vcvars = Resolve-VorVcVars -VcVarsPath $VcVarsPath   # $null when link.exe is already on PATH

  Cargo: explicit path, then CARGO_HOME\bin, then PATH, then %USERPROFILE%\.cargo\bin.
  MSVC:  explicit path, then nothing if link.exe is already on PATH (a Developer prompt),
         then vswhere (the standard Visual Studio locator).
#>

function Resolve-VorCargo {
  param([string]$CargoPath)
  if ($CargoPath) {
    if (-not (Test-Path -LiteralPath $CargoPath -PathType Leaf)) { throw "Cargo not found: $CargoPath" }
    return (Resolve-Path -LiteralPath $CargoPath).Path
  }
  if ($env:CARGO_HOME) {
    $candidate = Join-Path $env:CARGO_HOME 'bin\cargo.exe'
    if (Test-Path -LiteralPath $candidate -PathType Leaf) { return $candidate }
  }
  $onPath = Get-Command cargo.exe -ErrorAction SilentlyContinue
  if ($onPath) { return $onPath.Source }
  $candidate = Join-Path $env:USERPROFILE '.cargo\bin\cargo.exe'
  if (Test-Path -LiteralPath $candidate -PathType Leaf) { return $candidate }
  throw 'Cargo not found. Install Rust from https://rustup.rs or pass -CargoPath.'
}

function Resolve-VorVcVars {
  param([string]$VcVarsPath)
  if ($VcVarsPath) {
    if (-not (Test-Path -LiteralPath $VcVarsPath -PathType Leaf)) { throw "vcvars64.bat not found: $VcVarsPath" }
    return (Resolve-Path -LiteralPath $VcVarsPath).Path
  }
  if (Get-Command link.exe -ErrorAction SilentlyContinue) { return $null }
  $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
  if (Test-Path -LiteralPath $vswhere -PathType Leaf) {
    $install = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
    if ($install) {
      $candidate = Join-Path $install 'VC\Auxiliary\Build\vcvars64.bat'
      if (Test-Path -LiteralPath $candidate -PathType Leaf) { return $candidate }
    }
  }
  throw 'MSVC build tools not found. Install "Desktop development with C++" (Visual Studio Build Tools) or pass -VcVarsPath.'
}

function Invoke-VorCargoBuild {
  # Runs "cargo build --release" for the given packages inside the MSVC environment.
  # Native stderr must not become a terminating error under PS 5.1 with ErrorActionPreference Stop.
  param(
    [Parameter(Mandatory = $true)][string]$RepoRoot,
    [Parameter(Mandatory = $true)][string[]]$Packages,
    [string]$CargoPath,
    [string]$VcVarsPath
  )
  $cargo = Resolve-VorCargo -CargoPath $CargoPath
  $vcvars = Resolve-VorVcVars -VcVarsPath $VcVarsPath
  $packageArgs = ($Packages | ForEach-Object { "-p $_" }) -join ' '
  $build = "cd /d `"$RepoRoot`" && `"$cargo`" build --release $packageArgs"
  if ($vcvars) { $build = "call `"$vcvars`" >nul && $build" }
  $saved = $ErrorActionPreference
  try {
    $ErrorActionPreference = 'Continue'
    & cmd.exe /d /c $build
    $code = $LASTEXITCODE
  } finally {
    $ErrorActionPreference = $saved
  }
  if ($code -ne 0) { throw "Cargo release build failed: $code" }
}
