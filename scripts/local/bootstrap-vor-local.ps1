param(
  [string]$DeviceId = ('vor-' + [Environment]::MachineName.ToLowerInvariant()),
  [string[]]$AllowedRoot = @([Environment]::GetFolderPath('MyDocuments')),
  [int]$GrantTtlSeconds = 604800,
  [switch]$SkipBuild,
  [string]$CargoPath,
  [string]$VcVarsPath
)
. (Join-Path $PSScriptRoot 'common.ps1')
. (Join-Path $PSScriptRoot 'toolchain.ps1')
$identity = Join-Path $LocalState 'identity'
$secretStore = Join-Path $LocalState 'device-secrets'
$gatewayState = Join-Path $LocalState 'gateway\auth.json'
$relayState = Join-Path $LocalState 'relay\auth.json'
$agentState = Join-Path $LocalState 'device-runtime'
$policy = Join-Path $RepoRoot 'config\policy.example.yaml'
$credPath = Join-Path $LocalState 'mcp-credential.clixml'
$approvers = Join-Path $LocalState 'trusted-approvers.json'
New-Item -ItemType Directory -Force -Path $LocalState,$identity,$secretStore,$agentState | Out-Null
if (-not $AllowedRoot -or $AllowedRoot.Count -eq 0) { throw 'At least one allowed root is required.' }
$resolvedRoots = @()
foreach ($root in $AllowedRoot) {
  if (-not $root -or -not (Test-Path -LiteralPath $root -PathType Container)) { throw "Allowed root does not exist: $root" }
  $resolved = (Resolve-Path -LiteralPath $root).Path
  if ([IO.Path]::GetPathRoot($resolved) -eq $resolved) { throw "A drive root is not allowed: $resolved" }
  $resolvedRoots += $resolved
}
$git = (Get-Command git.exe -ErrorAction Stop).Source
if (-not $SkipBuild) {
  Write-Host 'Building Vor release binaries...'
  Invoke-VorCargoBuild -RepoRoot $RepoRoot -Packages @('vor-agent','vor-control-plane','vor-gateway','vor-approver') -CargoPath $CargoPath -VcVarsPath $VcVarsPath
}
$agent = Join-Path $BinDir 'vor-agent.exe'
$gateway = Join-Path $BinDir 'vor-gateway.exe'
$control = Join-Path $BinDir 'vor-control-plane.exe'
$approver = Join-Path $BinDir 'vor-approver.exe'
foreach ($bin in $agent,$gateway,$control,$approver) { if (-not (Test-Path $bin)) { throw "Missing binary: $bin" } }
Write-Host 'Creating/verifying local mTLS identity...'
& $agent local-enroll --device $DeviceId --out $identity --secret-store $secretStore --server-name localhost
if ($LASTEXITCODE -ne 0) { throw 'Local identity enrollment failed.' }
$account = [Security.Principal.WindowsIdentity]::GetCurrent().Name
& icacls.exe $LocalState /inheritance:r /grant:r "${account}:(OI)(CI)F" 'SYSTEM:(OI)(CI)F' | Out-Null
& icacls.exe "$LocalState\*" /reset /T /C | Out-Null
$policyLines = @('version: 1','policy_id: local-pilot','','filesystem:')
foreach ($root in $resolvedRoots) {
  $escaped = $root.Replace('\','\\').Replace('"','\"')
  $policyLines += "  - path: `"$escaped`""
  $policyLines += '    read: auto'
  $policyLines += '    write: approval'
}
$policyLines += @('','terminal:','  default: approval','  inline_eval: elevated_approval','  project_tests: approval','  destructive: deny','  elevated: deny','','process:','  list: auto','  inspect: auto','  terminate: approval','','browser:','  authenticated_session_use: deny','  secret_extraction: deny','  publish: deny','  purchase: deny','','desktop:','  enabled: false','','network:','  public_listener_fallback: deny','','audit:','  required: true','  fail_if_unwritable: true','')
if (-not (Test-Path -LiteralPath $policy)) {
  Write-Utf8NoBom $policy ($policyLines -join "`r`n")
} else {
  Write-Host "Keeping existing policy: $policy"
}
Write-Host 'Creating/verifying the DPAPI-protected owner approval identity...'
& $approver init --approver-id 'local-owner' --secret-store $secretStore --public-out $approvers
if ($LASTEXITCODE -ne 0) { throw 'Owner approval identity initialization failed.' }
$config = [ordered]@{
  device_id=$DeviceId; allowed_roots=$resolvedRoots; git=$git; policy=$policy
  gateway_state=$gatewayState; relay_state=$relayState; agent_state=$agentState
  secret_store=$secretStore; approvers=$approvers; approver_id='local-owner'; ca=(Join-Path $identity 'ca.pem')
  server_cert=(Join-Path $identity 'server.pem'); server_key=(Join-Path $identity 'server-key.pem')
  device_cert=(Join-Path $identity 'device.pem'); device_registry=(Join-Path $identity 'device-registry.json')
}
Write-Utf8NoBom (Join-Path $LocalState 'config.json') ($config | ConvertTo-Json)
if (-not (Test-Path $credPath)) {
  Write-Host 'Issuing first local MCP grant (stored with Windows DPAPI)...'
  $grant = & $gateway grant --state $gatewayState --actor 'local-pilot' --scope mcp --scope gateway.read --ttl-seconds $GrantTtlSeconds
  if ($LASTEXITCODE -ne 0) { throw 'MCP grant creation failed.' }
  $tokenLine = $grant | Where-Object { $_ -like 'token=*' } | Select-Object -First 1
  $grantIdLine = $grant | Where-Object { $_ -like 'grant_id=*' } | Select-Object -First 1
  if (-not $tokenLine -or -not $grantIdLine) { throw 'Grant command did not return a token and grant id.' }
  $token = $tokenLine.Substring(6)
  $grantId = $grantIdLine.Substring(9)
  $secure = ConvertTo-SecureString $token -AsPlainText -Force
  [pscredential]::new("vor-mcp:$grantId",$secure) | Export-Clixml -Path $credPath
  $token = $null; $secure = $null
}
Write-Host 'Starting Vor Local Pilot...'
& (Join-Path $PSScriptRoot 'start-vor-local.ps1')
$status = & (Join-Path $PSScriptRoot 'status-vor-local.ps1')
if (-not $status -or -not ($status.ControlPlane -and $status.Agent -and $status.Gateway8742 -and $status.Relay8789 -and $status.PrivateGrpc8790)) { throw 'Vor health verification failed.' }
Write-Host ''
Write-Host 'Bootstrap complete.'
Write-Host 'MCP endpoint: http://127.0.0.1:8742/mcp'
Write-Host 'The MCP bearer token is DPAPI-protected. Run show-mcp-token.ps1 only when you need to copy it.'
Write-Host 'No public ports, Windows services, startup persistence, Tailscale, or Cloudflare changes were made.'
