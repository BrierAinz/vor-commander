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
        'io.modelcontextprotocol/clientInfo' = @{ name = 'vor-operator-status'; version = '1.0' }
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
  $status = Invoke-VorMcpTool -Name 'commander_status' -Arguments @{} -Id 41
  $hasNewFlow = $null -ne $status.PSObject.Properties['remote_connectivity'] -and
    $null -ne $status.PSObject.Properties['recommended_device_id']
  $recommended = if ($hasNewFlow) { [string]$status.recommended_device_id } else { '' }
  $nextAction = if (-not $hasNewFlow) {
    'Promote the updated VPS control-plane before relying on recommended_device_id.'
  } elseif ([string]::IsNullOrWhiteSpace($recommended)) {
    'Reconnect a device agent before remote device tools.'
  } else {
    'Use recommended_device_id for remote device tools and run test-vor-status-flow.ps1.'
  }

  [pscustomobject]@{
    OperatorStatus = if ($hasNewFlow) { 'CURRENT_FLOW' } else { 'LEGACY_LIVE_GATEWAY' }
    Phase = $status.phase
    Actor = $status.actor_id
    GatewayDeviceId = $status.gateway_device_id
    RemoteDispatch = $status.remote_worker_dispatch
    Connectivity = if ($hasNewFlow) { $status.remote_connectivity } else { 'unknown-old-status-payload' }
    RecommendedDevice = $recommended
    ConnectedDeviceCount = if ($hasNewFlow) { $status.remote_connected_device_count } else { $null }
    NextAction = $nextAction
  } | Format-List
} finally {
  $token = $null
}
