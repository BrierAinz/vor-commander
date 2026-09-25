Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script:RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$script:LocalState = Join-Path $RepoRoot 'state\local'
$script:BinDir = Join-Path $RepoRoot 'target\release'

function Get-LocalConfig {
  $path = Join-Path $LocalState 'config.json'
  if (-not (Test-Path $path)) { throw "Missing local config: $path. Run bootstrap-vor-local.ps1 first." }
  Get-Content -Raw $path | ConvertFrom-Json
}

function Test-VorProcess([string]$PidFile, [string]$ExpectedExe) {
  if (-not (Test-Path $PidFile)) { return $false }
  $id = [int](Get-Content -Raw $PidFile)
  $p = Get-Process -Id $id -ErrorAction SilentlyContinue
  if (-not $p) { return $false }
  try { return ([IO.Path]::GetFullPath($p.Path) -eq [IO.Path]::GetFullPath($ExpectedExe)) } catch { return $false }
}

function Wait-VorHttp([string]$Uri, [int]$Seconds = 20) {
  $deadline = (Get-Date).AddSeconds($Seconds)
  do {
    try { $r = Invoke-RestMethod -Uri $Uri -TimeoutSec 2; if ($r.status -eq 'ok') { return $true } } catch {}
    Start-Sleep -Milliseconds 300
  } while ((Get-Date) -lt $deadline)
  return $false
}

function Write-Utf8NoBom([string]$Path, [string]$Content) {
  $encoding = New-Object System.Text.UTF8Encoding($false)
  [IO.File]::WriteAllText($Path, $Content, $encoding)
}
