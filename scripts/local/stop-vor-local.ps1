. (Join-Path $PSScriptRoot 'common.ps1')
$runtime = Join-Path $LocalState 'runtime'
$targets = @(
  @{ Name='agent'; Pid=(Join-Path $runtime 'agent.pid'); Exe=(Join-Path $BinDir 'vor-agent.exe') },
  @{ Name='control-plane'; Pid=(Join-Path $runtime 'control-plane.pid'); Exe=(Join-Path $BinDir 'vor-control-plane.exe') }
)
foreach ($t in $targets) {
  if (Test-VorProcess $t.Pid $t.Exe) {
    $id = [int](Get-Content -Raw $t.Pid)
    Stop-Process -Id $id -Force
    Write-Host "Stopped $($t.Name) (PID $id)"
  }
  Remove-Item $t.Pid -Force -ErrorAction SilentlyContinue
}
Write-Host 'Vor Local Pilot: STOPPED'
