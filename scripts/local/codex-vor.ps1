param(
  [Parameter(ValueFromRemainingArguments=$true)]
  [string[]]$CodexArgs
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'common.ps1')

$credentialPath = Join-Path $LocalState 'mcp-credential.clixml'
if (-not (Test-Path $credentialPath)) {
  throw 'No DPAPI MCP credential found. Run bootstrap-vor-local.ps1 first.'
}

$codex = Get-Command codex -ErrorAction SilentlyContinue
if (-not $codex) {
  throw 'codex.exe was not found in PATH.'
} else {
  $codexPath = $codex.Source
}

$cred = Import-Clixml $credentialPath
$ptr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($cred.Password)
$previous = $env:VOR_MCP_TOKEN
try {
  $env:VOR_MCP_TOKEN = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr)
  & $codexPath @CodexArgs
  $exitCode = $LASTEXITCODE
} finally {
  if ($null -eq $previous) {
    Remove-Item Env:VOR_MCP_TOKEN -ErrorAction SilentlyContinue
  } else {
    $env:VOR_MCP_TOKEN = $previous
  }
  [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr)
}

if ($null -ne $exitCode) { exit $exitCode }
