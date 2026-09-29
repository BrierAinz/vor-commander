$ErrorActionPreference = 'Stop'
$hostsPath = "$env:WINDIR\System32\drivers\etc\hosts"
$marker = '# VOR-P4C-TEMP'
$lookup = (& cmd.exe /d /c "nslookup relay.vorcommander.app 2>&1") -join [Environment]::NewLine

if ($lookup -match 'Non-existent domain|can''t find') {
  Write-Host 'ISP_DNS_READY=False'
  exit 2
}

if (-not (Select-String -Path $hostsPath -Pattern $marker -SimpleMatch -Quiet)) {
  Write-Host 'HOSTS_OVERRIDE=ABSENT'
  Write-Host 'ISP_DNS_READY=True'
  exit 0
}

$lines = Get-Content $hostsPath | Where-Object { $_ -notlike "*$marker*" }
Set-Content -Path $hostsPath -Value $lines -Encoding ascii
Clear-DnsClientCache
Write-Host 'HOSTS_OVERRIDE=REMOVED'
Write-Host 'ISP_DNS_READY=True'

