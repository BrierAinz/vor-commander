param(
  [string]$DeviceId = ('vor-' + [Environment]::MachineName.ToLowerInvariant()),
  [string]$AllowedRoot = 'D:\Proyectos',
  [int]$GrantTtlSeconds = 604800,
  [switch]$SkipBuild
)
. (Join-Path $PSScriptRoot 'common.ps1')
$identity = Join-Path $LocalState 'identity'
$secretStore = Join-Path $LocalState 'device-secrets'
$gatewayState = Join-Path $LocalState 'gateway\auth.json'
$relayState = Join-Path $LocalState 'relay\auth.json'
$agentState = Join-Path $LocalState 'device-runtime'
$policy = Join-Path $RepoRoot 'config\policy.example.yaml'
$credPath = Join-Path $LocalState 'mcp-credential.clixml'
New-Item -ItemType Directory -Force -Path $LocalState,$identity,$secretStore,$agentState | Out-Null
if (-not (Test-Path $AllowedRoot)) { throw "Allowed root does not exist: $AllowedRoot" }
$git = (Get-Command git.exe -ErrorAction Stop).Source
$cargo = Join-Path $env:USERPROFILE '.cargo\bin\cargo.exe'
if (-not (Test-Path $cargo)) { $cargo = (Get-Command cargo.exe -ErrorAction Stop).Source }
$vcvars = 'D:\Toolchains\Microsoft\VisualStudio2026\BuildTools\VC\Auxiliary\Build\vcvars64.bat'
if (-not (Test-Path $vcvars)) { throw "MSVC environment not found: $vcvars" }
if (-not $SkipBuild) {
  Write-Host 'Building Vör release binaries...'
  $cmd = "call `"$vcvars`" >nul && cd /d `"$RepoRoot`" && `"$cargo`" build --release -p vor-agent -p vor-control-plane -p vor-gateway"
  & cmd.exe /d /c $cmd
  if ($LASTEXITCODE -ne 0) { throw "Cargo release build failed: $LASTEXITCODE" }
}
$agent = Join-Path $BinDir 'vor-agent.exe'
$gateway = Join-Path $BinDir 'vor-gateway.exe'
$control = Join-Path $BinDir 'vor-control-plane.exe'
foreach ($bin in $agent,$gateway,$control) { if (-not (Test-Path $bin)) { throw "Missing binary: $bin" } }
Write-Host 'Creating/verifying local mTLS identity...'
& $agent local-enroll --device $DeviceId --out $identity --secret-store $secretStore --server-name localhost
if ($LASTEXITCODE -ne 0) { throw 'Local identity enrollment failed.' }
$account = [Security.Principal.WindowsIdentity]::GetCurrent().Name
& icacls.exe $LocalState /inheritance:r /grant:r "${account}:(OI)(CI)F" 'SYSTEM:(OI)(CI)F' | Out-Null
& icacls.exe "$LocalState\*" /reset /T /C | Out-Null
$config = [ordered]@{
  device_id=$DeviceId; allowed_root=(Resolve-Path $AllowedRoot).Path; git=$git; policy=$policy
  gateway_state=$gatewayState; relay_state=$relayState; agent_state=$agentState
  secret_store=$secretStore; ca=(Join-Path $identity 'ca.pem')
  server_cert=(Join-Path $identity 'server.pem'); server_key=(Join-Path $identity 'server-key.pem')
  device_cert=(Join-Path $identity 'device.pem'); device_registry=(Join-Path $identity 'device-registry.json')
}
$config | ConvertTo-Json | Set-Content -Encoding UTF8 (Join-Path $LocalState 'config.json')
if (-not (Test-Path $credPath)) {
  Write-Host 'Issuing first local MCP grant (stored with Windows DPAPI)...'
  $grant = & $gateway grant --state $gatewayState --actor 'local-pilot' --scope mcp --scope gateway.read --ttl-seconds $GrantTtlSeconds
  if ($LASTEXITCODE -ne 0) { throw 'MCP grant creation failed.' }
  $tokenLine = $grant | Where-Object { $_ -like 'token=*' } | Select-Object -First 1
  if (-not $tokenLine) { throw 'Grant command did not return a token.' }
  $token = $tokenLine.Substring(6)
  $secure = ConvertTo-SecureString $token -AsPlainText -Force
  [pscredential]::new('vor-mcp',$secure) | Export-Clixml -Path $credPath
  $token = $null; $secure = $null
}
Write-Host 'Starting Vör Local Pilot...'
& (Join-Path $PSScriptRoot 'start-vor-local.ps1')
if ($LASTEXITCODE -ne 0) { throw 'Vör start failed.' }
& (Join-Path $PSScriptRoot 'status-vor-local.ps1')
if ($LASTEXITCODE -ne 0) { throw 'Vör health verification failed.' }
Write-Host ''
Write-Host 'Bootstrap complete.'
Write-Host 'MCP endpoint: http://127.0.0.1:8742/mcp'
Write-Host 'The MCP bearer token is DPAPI-protected. Run show-mcp-token.ps1 only when you need to copy it.'
Write-Host 'No public ports, Windows services, startup persistence, Tailscale, or Cloudflare changes were made.'