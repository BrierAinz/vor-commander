. (Join-Path $PSScriptRoot 'common.ps1')
$ErrorActionPreference = 'Stop'

$config = Get-LocalConfig
$approverExe = Join-Path $BinDir 'vor-approver.exe'
$approverPublic = Join-Path $LocalState 'approval\trusted-approvers.json'
$approverSecrets = Join-Path $LocalState 'approval-secrets'
$canaryRoot = Join-Path $LocalState 'm1-canary'
$target = Join-Path $canaryRoot 'live-write.txt'
$token = [Environment]::GetEnvironmentVariable('VOR_M1_OAUTH_BEARER')

if ([string]::IsNullOrWhiteSpace($token)) {
  throw 'VOR_M1_OAUTH_BEARER is required. Use an OAuth-authorized MCP access token; local vor-gateway grants are not valid against the public VPS GrantStore.'
}
if (-not (Test-Path -LiteralPath $approverExe -PathType Leaf)) { throw 'Release vor-approver.exe is missing.' }
if (-not (Test-Path -LiteralPath $approverPublic -PathType Leaf)) { throw 'Trusted approver config is missing.' }

New-Item -ItemType Directory -Force -Path $canaryRoot | Out-Null
$runStamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$runDir = Join-Path $canaryRoot "run-$runStamp"
New-Item -ItemType Directory -Path $runDir | Out-Null

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
        'io.modelcontextprotocol/clientInfo' = @{ name = 'vor-m1-live-canary'; version = '1.0' }
        'io.modelcontextprotocol/clientCapabilities' = @{}
      }
    }
  } | ConvertTo-Json -Depth 12 -Compress

  $response = Invoke-RestMethod -Uri 'https://mcp.vorcommander.app/mcp' -Method Post -Headers $headers -Body $body -TimeoutSec 20
  if ($response.error) { throw "MCP $Name failed: $($response.error.message)" }
  $text = $response.result.content[0].text
  if ([string]::IsNullOrWhiteSpace($text)) { throw "MCP $Name returned no text content." }
  $text | ConvertFrom-Json
}

try {
  $listHeaders = @{
    Authorization = "Bearer $token"
    Accept = 'application/json, text/event-stream'
    'MCP-Protocol-Version' = '2026-07-28'
    'Mcp-Method' = 'tools/list'
    'Content-Type' = 'application/json'
  }
  $listBody = @{
    jsonrpc = '2.0'
    id = 10
    method = 'tools/list'
    params = @{
      _meta = @{
        'io.modelcontextprotocol/protocolVersion' = '2026-07-28'
        'io.modelcontextprotocol/clientCapabilities' = @{}
      }
    }
  } | ConvertTo-Json -Depth 8 -Compress
  $listResponse = Invoke-RestMethod -Uri 'https://mcp.vorcommander.app/mcp' -Method Post -Headers $listHeaders -Body $listBody -TimeoutSec 20
  $toolNames = @($listResponse.result.tools | ForEach-Object { $_.name })
  foreach ($required in @('prepare_write','commit_write')) {
    if ($toolNames -notcontains $required) { throw "Live MCP is missing required tool: $required" }
  }
  foreach ($forbidden in @('terminal_exec','write_file','process_terminate')) {
    if ($toolNames -contains $forbidden) { throw "Unsafe live MCP tool exposed: $forbidden" }
  }

  $content = "VOR_M1_CANARY $((Get-Date).ToUniversalTime().ToString('o'))" + [Environment]::NewLine
  $contentBytes = [Text.Encoding]::UTF8.GetBytes($content)
  $contentBase64 = [Convert]::ToBase64String($contentBytes)
  if (Test-Path -LiteralPath $target -PathType Leaf) {
    $expectedTargetSha256 = (Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash.ToLowerInvariant()
  } else {
    $expectedTargetSha256 = 'absent'
  }

  $prepared = Invoke-VorMcpTool -Name 'prepare_write' -Id 11 -Arguments @{
    device_id = $config.device_id
    path = $target
    content_base64 = $contentBase64
    expected_target_sha256 = $expectedTargetSha256
  }
  if ($prepared.status -ne 'approval_required') { throw "prepare_write status=$($prepared.status)" }

  $utf8NoBom = [Text.UTF8Encoding]::new($false)
  $requestPath = Join-Path $runDir 'request.b64'
  $challengePath = Join-Path $runDir 'challenge.json'
  $approvalPath = Join-Path $runDir 'approval.b64'
  [IO.File]::WriteAllText($requestPath, [string]$prepared.request_base64, $utf8NoBom)
  [IO.File]::WriteAllText($challengePath, ($prepared.challenge | ConvertTo-Json -Depth 10 -Compress), $utf8NoBom)

  $previousApproverStore = $env:VOR_APPROVER_SECRET_STORE
  $env:VOR_APPROVER_SECRET_STORE = $approverSecrets
  try {
    & $approverExe sign --approver-id owner-local --request-file $requestPath --challenge-file $challengePath --out $approvalPath
    if ($LASTEXITCODE -ne 0) { throw "vor-approver exited with code $LASTEXITCODE" }
  } finally {
    $env:VOR_APPROVER_SECRET_STORE = $previousApproverStore
  }

  $approvalBase64 = (Get-Content -Raw -LiteralPath $approvalPath).Trim()
  $committed = Invoke-VorMcpTool -Name 'commit_write' -Id 12 -Arguments @{
    device_id = $config.device_id
    request_base64 = [string]$prepared.request_base64
    approval_base64 = $approvalBase64
  }
  if ($committed.status -ne 'ok') { throw "commit_write status=$($committed.status)" }

  $actual = [IO.File]::ReadAllText($target)
  if ($actual -ne $content) { throw 'Committed file content does not match canary payload.' }

  $replayed = Invoke-VorMcpTool -Name 'commit_write' -Id 13 -Arguments @{
    device_id = $config.device_id
    request_base64 = [string]$prepared.request_base64
    approval_base64 = $approvalBase64
  }
  if ($replayed.status -ne 'approval_replayed') { throw "replay status=$($replayed.status)" }

  [pscustomobject]@{
    LiveM1 = 'PASS'
    Device = $config.device_id
    Prepare = $prepared.status
    Commit = $committed.status
    Replay = $replayed.status
    Target = $target
    ContentSha256 = $prepared.content_sha256
    ApprovalPrompt = 'native Windows Yes/No'
    DirectWriteToolExposed = ($toolNames -contains 'write_file')
    TerminalToolExposed = ($toolNames -contains 'terminal_exec')
    ProcessTerminateToolExposed = ($toolNames -contains 'process_terminate')
  } | Format-List
} finally {
  $token = $null
}
