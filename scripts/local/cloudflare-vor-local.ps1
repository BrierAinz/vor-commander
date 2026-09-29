param(
  [Parameter(Mandatory=$true, Position=0)]
  [ValidateSet('set-token','start','stop','status','doctor')]
  [string]$Command
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'common.ps1')

$CloudflaredVersion = '2026.9.1'
$ExpectedSha256 = '2837888cc0f5d58f15b6dc478376de90b4d3ba5241c7947455d1e0a0df429712'
$Cloudflared = Join-Path $RepoRoot "state\tooling\cloudflared\$CloudflaredVersion\cloudflared.exe"
$CfState = Join-Path $LocalState 'cloudflare'
$TokenXml = Join-Path $CfState 'tunnel-token.xml'
$StaleTokenFile = Join-Path $CfState '.tunnel-token.runtime'
$PidFile = Join-Path $CfState 'cloudflared.pid'
$StdoutLog = Join-Path $CfState 'cloudflared.out.log'
$StderrLog = Join-Path $CfState 'cloudflared.err.log'
New-Item -ItemType Directory -Force -Path $CfState | Out-Null

function Get-CloudflaredProcess {
  if (-not (Test-Path $PidFile)) { return $null }
  $pidValue = (Get-Content $PidFile -Raw).Trim()
  if (-not $pidValue) { return $null }
  Get-Process -Id ([int]$pidValue) -ErrorAction SilentlyContinue
}

function Read-TunnelTokenPlain {
  if (-not (Test-Path $TokenXml)) { throw 'No Cloudflare tunnel token stored. Run set-token first.' }
  $secure = Import-Clixml $TokenXml
  $ptr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
  try { [Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr) }
  finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr) }
}

function Test-CloudflaredBinary {
  if (-not (Test-Path $Cloudflared)) { throw "cloudflared missing: $Cloudflared" }
  $hash = (Get-FileHash -Algorithm SHA256 $Cloudflared).Hash.ToLowerInvariant()
  if ($hash -ne $ExpectedSha256) { throw "cloudflared SHA256 mismatch: $hash" }
  $signature = Get-AuthenticodeSignature $Cloudflared
  if ($signature.Status -ne 'Valid') { throw "cloudflared signature is not valid: $($signature.Status)" }
  $true
}

switch ($Command) {
  'set-token' {
    $secure = Read-Host 'Paste the Cloudflare Tunnel token (input hidden)' -AsSecureString
    $secure | Export-Clixml -Path $TokenXml
    Write-Host 'Cloudflare tunnel token stored with Windows DPAPI.'
  }
  'start' {
    Test-CloudflaredBinary | Out-Null
    if (Get-CloudflaredProcess) { Write-Host 'cloudflared is already running.'; break }
    $plain = Read-TunnelTokenPlain
    $previousToken = $env:TUNNEL_TOKEN
    try {
      $env:TUNNEL_TOKEN = $plain
      $p = Start-Process -FilePath $Cloudflared -ArgumentList @('tunnel','run') -RedirectStandardOutput $StdoutLog -RedirectStandardError $StderrLog -WindowStyle Hidden -PassThru
      Set-Content -Path $PidFile -Value $p.Id -NoNewline
      Start-Sleep -Seconds 3
      if ($p.HasExited) { throw "cloudflared exited early. See $StderrLog" }
      Write-Host "cloudflared running (PID $($p.Id))."
    }
    finally {
      if ($null -eq $previousToken) { Remove-Item Env:TUNNEL_TOKEN -ErrorAction SilentlyContinue }
      else { $env:TUNNEL_TOKEN = $previousToken }
      $plain = $null
    }
  }
  'stop' {
    $p = Get-CloudflaredProcess
    if ($p) { Stop-Process -Id $p.Id -Force; Write-Host "cloudflared stopped (PID $($p.Id))." }
    else { Write-Host 'cloudflared is not running.' }
    Remove-Item $PidFile -Force -ErrorAction SilentlyContinue
  }
  'status' {
    $p = Get-CloudflaredProcess
    $localOk = $false
    try { $localOk = (Invoke-WebRequest 'http://127.0.0.1:8742/healthz' -UseBasicParsing -TimeoutSec 2).StatusCode -eq 200 } catch {}
    $versionText = if (Test-Path $Cloudflared) { (& $Cloudflared --version) -join ' ' } else { 'missing' }
    [pscustomobject]@{ Version=$versionText; TokenStored=(Test-Path $TokenXml); Running=[bool]$p; Pid=$(if($p){$p.Id}else{$null}); McpLocal=$localOk; PublicTarget='https://mcp.vorcommander.app/mcp'; StalePlaintextToken=(Test-Path $StaleTokenFile) } | Format-List
  }
  'doctor' {
    $binaryOk = Test-CloudflaredBinary
    $localOk = $false
    try { $localOk = (Invoke-WebRequest 'http://127.0.0.1:8742/healthz' -UseBasicParsing -TimeoutSec 2).StatusCode -eq 200 } catch {}
    [pscustomobject]@{ BinaryVerified=$binaryOk; TokenStored=(Test-Path $TokenXml); LocalVorHealthy=$localOk; TunnelRunning=[bool](Get-CloudflaredProcess); StalePlaintextToken=(Test-Path $StaleTokenFile); TunnelStdout=$StdoutLog; TunnelStderr=$StderrLog } | Format-List
  }
}
