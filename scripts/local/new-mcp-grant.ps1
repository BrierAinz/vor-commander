param([int]$TtlSeconds = 604800)
. (Join-Path $PSScriptRoot 'common.ps1')
$config = Get-LocalConfig
$gateway = Join-Path $BinDir 'vor-gateway.exe'
$credPath = Join-Path $LocalState 'mcp-credential.clixml'
$grant = & $gateway grant --state $config.gateway_state --actor 'local-pilot' --scope mcp --scope gateway.read --ttl-seconds $TtlSeconds
if ($LASTEXITCODE -ne 0) { throw 'MCP grant creation failed.' }
$tokenLine = $grant | Where-Object { $_ -like 'token=*' } | Select-Object -First 1
if (-not $tokenLine) { throw 'Grant command did not return a token.' }
$token = $tokenLine.Substring(6)
$secure = ConvertTo-SecureString $token -AsPlainText -Force
[pscredential]::new('vor-mcp',$secure) | Export-Clixml -Path $credPath
$token = $null; $secure = $null
Write-Host "New MCP credential stored with DPAPI: $credPath"
Write-Host 'Run show-mcp-token.ps1 only when you need to copy it.'