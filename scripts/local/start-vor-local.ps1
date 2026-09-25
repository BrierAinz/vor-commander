. (Join-Path $PSScriptRoot 'common.ps1')
$config = Get-LocalConfig
$runtime = Join-Path $LocalState 'runtime'
$logs = Join-Path $LocalState 'logs'
New-Item -ItemType Directory -Force -Path $runtime,$logs | Out-Null
$cpExe = Join-Path $BinDir 'vor-control-plane.exe'
$agentExe = Join-Path $BinDir 'vor-agent.exe'
if (-not (Test-Path $cpExe) -or -not (Test-Path $agentExe)) { throw 'Release binaries missing. Run bootstrap-vor-local.ps1.' }
$cpPid = Join-Path $runtime 'control-plane.pid'
$agentPid = Join-Path $runtime 'agent.pid'
if (-not (Test-VorProcess $cpPid $cpExe)) {
  $args = @('--gateway-state',$config.gateway_state,'--relay-state',$config.relay_state,'--ca',$config.ca,'--server-cert',$config.server_cert,'--server-key',$config.server_key,'--device-registry',$config.device_registry)
  $p = Start-Process -FilePath $cpExe -ArgumentList $args -WorkingDirectory $RepoRoot -RedirectStandardOutput (Join-Path $logs 'control-plane.out.log') -RedirectStandardError (Join-Path $logs 'control-plane.err.log') -WindowStyle Hidden -PassThru
  Set-Content -Path $cpPid -Value $p.Id -NoNewline
}
if (-not (Wait-VorHttp 'http://127.0.0.1:8742/healthz')) { throw 'Gateway health check failed. See state/local/logs/control-plane.err.log' }
if (-not (Wait-VorHttp 'http://127.0.0.1:8789/healthz')) { throw 'Relay health check failed. See state/local/logs/control-plane.err.log' }
if (-not (Test-VorProcess $agentPid $agentExe)) {
  $args = @('private-run','--endpoint','https://127.0.0.1:8790','--server-name','localhost','--device',$config.device_id,'--ca',$config.ca,'--cert',$config.device_cert,'--secret-store',$config.secret_store,'--policy',$config.policy,'--approvers',$config.approvers)
  $roots = if ($config.PSObject.Properties['allowed_roots']) { @($config.allowed_roots) } else { @($config.allowed_root) }
  foreach ($root in $roots) { $args += @('--root', [string]$root) }
  $args += @('--git',$config.git,'--state',$config.agent_state)
  $p = Start-Process -FilePath $agentExe -ArgumentList $args -WorkingDirectory $RepoRoot -RedirectStandardOutput (Join-Path $logs 'agent.out.log') -RedirectStandardError (Join-Path $logs 'agent.err.log') -WindowStyle Hidden -PassThru
  Set-Content -Path $agentPid -Value $p.Id -NoNewline
}
Start-Sleep -Milliseconds 800
if (-not (Test-VorProcess $agentPid $agentExe)) { throw 'Device Agent exited early. See state/local/logs/agent.err.log' }
Write-Host 'Vor Local Pilot: RUNNING'
