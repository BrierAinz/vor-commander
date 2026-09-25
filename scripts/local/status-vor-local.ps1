. (Join-Path $PSScriptRoot 'common.ps1')
$config = Get-LocalConfig
$runtime = Join-Path $LocalState 'runtime'
$cpExe = Join-Path $BinDir 'vor-control-plane.exe'
$agentExe = Join-Path $BinDir 'vor-agent.exe'
$cpAlive = Test-VorProcess (Join-Path $runtime 'control-plane.pid') $cpExe
$agentAlive = Test-VorProcess (Join-Path $runtime 'agent.pid') $agentExe
$gateway = Wait-VorHttp 'http://127.0.0.1:8742/healthz' 2
$relay = Wait-VorHttp 'http://127.0.0.1:8789/healthz' 2
$tcp = $false
try { $c = [Net.Sockets.TcpClient]::new(); $c.Connect('127.0.0.1',8790); $tcp=$true; $c.Dispose() } catch {}
[pscustomobject]@{
  DeviceId = $config.device_id
  ControlPlane = $cpAlive
  Agent = $agentAlive
  Gateway8742 = $gateway
  Relay8789 = $relay
  PrivateGrpc8790 = $tcp
  McpUrl = 'http://127.0.0.1:8742/mcp'
} | Format-List
if (-not ($cpAlive -and $agentAlive -and $gateway -and $relay -and $tcp)) { exit 1 }