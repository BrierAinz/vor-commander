. (Join-Path $PSScriptRoot 'common.ps1')
$ErrorActionPreference = 'Stop'

$credentialPath = Join-Path $LocalState 'mcp-credential.clixml'
if (-not (Test-Path $credentialPath)) { throw 'No local MCP credential.' }

$cred = Import-Clixml $credentialPath
$ptr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($cred.Password)
try { $token = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr) }
finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr) }

function Invoke-VorMcpTool {
  param(
    [Parameter(Mandatory=$true)][string]$Name,
    [Parameter(Mandatory=$true)][hashtable]$Arguments,
    [int]$Id = 1
  )
  $headers = @{
    Authorization = "Bearer $token"
    Accept = 'application/json, text/event-stream'
    'MCP-Protocol-Version' = '2026-07-28'
    'Mcp-Method' = 'tools/call'
    'Mcp-Name' = $Name
    'Content-Type' = 'application/json'
  }
  $body = @{
    jsonrpc = '2.0'
    id = $Id
    method = 'tools/call'
    params = @{
      name = $Name
      arguments = $Arguments
      _meta = @{
        'io.modelcontextprotocol/protocolVersion' = '2026-07-28'
        'io.modelcontextprotocol/clientInfo' = @{ name = 'vor-status-flow-canary'; version = '1.0' }
        'io.modelcontextprotocol/clientCapabilities' = @{}
      }
    }
  } | ConvertTo-Json -Depth 12 -Compress

  $response = Invoke-RestMethod -Uri 'https://mcp.vorcommander.app/mcp' -Method Post -Headers $headers -Body $body -TimeoutSec 20
  if ($response.PSObject.Properties['error']) { throw "MCP $Name failed: $($response.error.message)" }
  $text = $response.result.content[0].text
  if ([string]::IsNullOrWhiteSpace($text)) { throw "MCP $Name returned no text content." }
  $text | ConvertFrom-Json
}

try {
  $status = Invoke-VorMcpTool -Name 'commander_status' -Arguments @{} -Id 31
  foreach ($field in @('remote_connectivity','recommended_device_id','remote_connected_device_count','operator_hint')) {
    if (-not $status.PSObject.Properties[$field]) {
      throw "commander_status is missing $field. Promote the updated VPS control-plane before running this canary."
    }
  }
  if ($status.remote_connectivity -ne 'connected') {
    throw "remote_connectivity is $($status.remote_connectivity), expected connected"
  }
  if ([string]::IsNullOrWhiteSpace($status.recommended_device_id)) {
    throw 'commander_status did not return recommended_device_id'
  }

  $repoStatus = Invoke-VorMcpTool -Name 'git_status' -Id 32 -Arguments @{
    device_id = [string]$status.recommended_device_id
    path = $RepoRoot
  }
  if ($repoStatus.status -ne 'ok') { throw "git_status status=$($repoStatus.status)" }

  [pscustomobject]@{
    StatusFlow = 'PASS'
    Device = $status.recommended_device_id
    Connectivity = $status.remote_connectivity
    ConnectedDeviceCount = $status.remote_connected_device_count
    Hint = $status.operator_hint
    GitStatus = $repoStatus.status
  } | Format-List
} finally {
  $token = $null
}
