param([int]$TtlSeconds = 604800, [switch]$RevokePrevious)
. (Join-Path $PSScriptRoot 'common.ps1')
$config = Get-LocalConfig
$gateway = Join-Path $BinDir 'vor-gateway.exe'
$credPath = Join-Path $LocalState 'mcp-credential.clixml'
$previousGrantId = $null
if ($RevokePrevious -and (Test-Path -LiteralPath $credPath)) {
  $previous = Import-Clixml $credPath
  if ($previous.UserName -like 'vor-mcp:*') { $previousGrantId = $previous.UserName.Substring(8) }
  else {
    # Credentials stored by 0.1.0-beta.1 do not record their grant id, so they cannot be revoked by id.
    throw 'The stored MCP credential predates grant tracking (0.1.0-beta.1) and cannot be revoked by id. Nothing was changed. That grant expires on its own 7 days after it was issued; run this script without -RevokePrevious to issue a new credential now, and later rotations will revoke by id.'
  }
}
$grant = & $gateway grant --state $config.gateway_state --actor 'local-pilot' --scope mcp --scope gateway.read --ttl-seconds $TtlSeconds
if ($LASTEXITCODE -ne 0) { throw 'MCP grant creation failed.' }
$tokenLine = $grant | Where-Object { $_ -like 'token=*' } | Select-Object -First 1
$grantIdLine = $grant | Where-Object { $_ -like 'grant_id=*' } | Select-Object -First 1
if (-not $tokenLine -or -not $grantIdLine) { throw 'Grant command did not return a token and grant id.' }
$token = $tokenLine.Substring(6)
$grantId = $grantIdLine.Substring(9)
$secure = ConvertTo-SecureString $token -AsPlainText -Force
if ($previousGrantId) {
  & $gateway revoke --state $config.gateway_state --grant-id $previousGrantId
  if ($LASTEXITCODE -ne 0) { throw 'Revoking the previous grant failed; the existing stored credential was kept.' }
  Write-Host "Revoked previous MCP grant: $previousGrantId"
}
[pscredential]::new("vor-mcp:$grantId",$secure) | Export-Clixml -Path $credPath
$token = $null; $secure = $null
Write-Host "New MCP credential stored with DPAPI: $credPath"
Write-Host 'Run show-mcp-token.ps1 only when you need to copy it.'
