param(
  [string]$Root = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..')).Path,
  [string]$GeckoDriver = (Join-Path $Root 'state\drivers\geckodriver\0.37.1\geckodriver.exe'),
  [string]$Firefox = 'C:\Program Files\Mozilla Firefox\firefox.exe'
)

$ErrorActionPreference = 'Stop'
$rootPath = (Resolve-Path -LiteralPath $Root).Path
$geckoPath = (Resolve-Path -LiteralPath $GeckoDriver).Path
$firefoxPath = (Resolve-Path -LiteralPath $Firefox).Path
$cargo = Join-Path $env:USERPROFILE '.cargo\bin\cargo.exe'
$vcvars = 'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat'

if (-not (Test-Path -LiteralPath $cargo -PathType Leaf)) {
  throw "cargo not found at $cargo"
}
if (-not (Test-Path -LiteralPath $vcvars -PathType Leaf)) {
  throw "MSVC vcvars64.bat not found at $vcvars"
}

$geckoVersion = & $geckoPath --version
$firefoxVersion = ((& $firefoxPath --version 2>&1) | Out-String).Trim()
if ([string]::IsNullOrWhiteSpace($firefoxVersion)) {
  $firefoxVersion = (Get-Item -LiteralPath $firefoxPath).VersionInfo.ProductVersion
}

Write-Host '== A4 browser lab preflight =='
[pscustomobject]@{
  Root = $rootPath
  GeckoDriver = $geckoPath
  GeckoDriverVersion = ($geckoVersion | Select-Object -First 1)
  Firefox = $firefoxPath
  FirefoxVersion = $firefoxVersion
  LabRoot = (Join-Path $rootPath 'state\local\a4-lab')
} | Format-List

$env:VOR_GECKODRIVER = $geckoPath
$env:VOR_FIREFOX = $firefoxPath

Push-Location $rootPath
try {
  & cmd.exe /c "call `"$vcvars`" >nul && `"$cargo`" test --locked --offline -p vor-browser a4_local_browser_session_e2e -- --ignored --nocapture"
  if ($LASTEXITCODE -ne 0) {
    throw "A4 browser lab failed with exit code $LASTEXITCODE"
  }
} finally {
  Pop-Location
}
