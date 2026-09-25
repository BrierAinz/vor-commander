. (Join-Path $PSScriptRoot 'common.ps1')
$path = Join-Path $LocalState 'mcp-credential.clixml'
if (-not (Test-Path $path)) { throw 'No local MCP credential. Run bootstrap-vor-local.ps1 or new-mcp-grant.ps1.' }
$cred = Import-Clixml $path
$ptr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($cred.Password)
try {
  [Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr)
} finally {
  [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr)
}