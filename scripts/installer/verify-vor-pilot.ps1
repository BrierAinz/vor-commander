param([string]$InstallRoot = (Join-Path $env:LOCALAPPDATA 'VorCommanderPilot'))
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
& (Join-Path $InstallRoot 'scripts\local\status-vor-local.ps1')
if ($LASTEXITCODE -ne 0) { throw 'Local process verification failed.' }
$cred = Import-Clixml (Join-Path $InstallRoot 'state\local\mcp-credential.clixml')
$ptr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($cred.Password)
try { $token = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr) } finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr) }
$headers = @{ Authorization = "Bearer $token"; Accept = 'application/json, text/event-stream'; 'MCP-Protocol-Version' = '2026-07-28'; 'Mcp-Method' = 'tools/call'; 'Mcp-Name' = 'commander_status' }
$body = '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"commander_status","arguments":{},"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientInfo":{"name":"vor-installer","version":"1.0"},"io.modelcontextprotocol/clientCapabilities":{}}}}'
$response = Invoke-WebRequest -UseBasicParsing -Uri 'http://127.0.0.1:8742/mcp' -Method Post -Headers $headers -ContentType 'application/json' -Body $body
$token = $null
if ($response.StatusCode -ne 200 -or $response.Content -notmatch 'commander_status|remote_connectivity|recommended_device_id') {
  throw 'commander_status did not return a recognizable response.'
}
Write-Host 'commander_status verification: PASS'
