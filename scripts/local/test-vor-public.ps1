. (Join-Path $PSScriptRoot 'common.ps1')
$ErrorActionPreference = 'Stop'
$credentialPath = Join-Path $LocalState 'mcp-credential.clixml'
if (-not (Test-Path $credentialPath)) { throw 'No local MCP credential.' }
$cred = Import-Clixml $credentialPath
$ptr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($cred.Password)
try { $token = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr) }
finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr) }
$headers = @{
  Authorization = "Bearer $token"
  Accept = 'application/json, text/event-stream'
  'MCP-Protocol-Version' = '2026-07-28'
  'Mcp-Method' = 'tools/list'
  'Content-Type' = 'application/json'
}
$body = '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}'
try {
  $response = Invoke-RestMethod -Uri 'https://mcp.vorcommander.app/mcp' -Method Post -Headers $headers -Body $body -TimeoutSec 15
  $tools = @($response.result.tools | ForEach-Object { $_.name })
  [pscustomobject]@{ PublicMcp='OK'; ToolCount=$tools.Count; Tools=($tools -join ', '); DangerousTerminalExposed=($tools -contains 'terminal') } | Format-List
} finally { $token = $null }
