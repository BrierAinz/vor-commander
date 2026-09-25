param([Parameter(Mandatory=$true)][string]$PackageZip,[string]$TestRoot=(Join-Path 'D:\Proyectos\30_Labs' ('vor-pilot-installer-test-'+[guid]::NewGuid().ToString('N'))))
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
function Invoke-McpTool([string]$Name,$Arguments,[int]$Id) {
  $headers=@{Authorization="Bearer $script:Token";Accept='application/json, text/event-stream';'MCP-Protocol-Version'='2026-07-28';'Mcp-Method'='tools/call';'Mcp-Name'=$Name}
  $meta=[ordered]@{'io.modelcontextprotocol/protocolVersion'='2026-07-28';'io.modelcontextprotocol/clientInfo'=[ordered]@{name='vor-installer-e2e';version='1.0'};'io.modelcontextprotocol/clientCapabilities'=[ordered]@{}}
  $body=[ordered]@{jsonrpc='2.0';id=$Id;method='tools/call';params=[ordered]@{name=$Name;arguments=$Arguments;_meta=$meta}}|ConvertTo-Json -Depth 20 -Compress
  $response=Invoke-WebRequest -UseBasicParsing -Uri 'http://127.0.0.1:8742/mcp' -Method Post -Headers $headers -ContentType 'application/json' -Body $body
  if ($response.StatusCode -ne 200) { throw "$Name returned HTTP $($response.StatusCode)" }
  $rpc=$response.Content|ConvertFrom-Json
  if($rpc.PSObject.Properties["error"] -and $rpc.error){throw "$Name returned JSON-RPC error: $($rpc.error|ConvertTo-Json -Compress)"}
  return (($rpc.result.content|Select-Object -First 1).text|ConvertFrom-Json)
}
foreach($port in 8742,8789,8790){if(Get-NetTCPConnection -State Listen -LocalPort $port -ErrorAction SilentlyContinue){throw "Required port $port is already in use."}}
Write-Host 'PHASE ports-before: PASS (8742, 8789, 8790 free)'
$extract=Join-Path $TestRoot 'package';$install=Join-Path $TestRoot 'installed';$allowed=Join-Path $TestRoot 'allowed';$configs=Join-Path $TestRoot 'client-configs'
New-Item -ItemType Directory -Force -Path $extract,$allowed,$configs|Out-Null
Expand-Archive -LiteralPath $PackageZip -DestinationPath $extract
$package=Get-ChildItem -LiteralPath $extract -Directory|Select-Object -First 1
if(-not $package){throw 'Package root was not found.'}
$manifest=Join-Path $package.FullName 'release-manifest.sha256'
foreach($line in Get-Content -LiteralPath $manifest){if($line -notmatch '^([0-9a-f]{64})  (.+)$'){throw "Invalid manifest line: $line"};$actual=(Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $package.FullName $Matches[2])).Hash.ToLowerInvariant();if($actual -ne $Matches[1]){throw "Manifest mismatch: $($Matches[2])"}}
foreach($required in 'vor-agent.exe','vor-control-plane.exe','vor-gateway.exe','vor-approver.exe'){if(-not(Test-Path -LiteralPath(Join-Path $package.FullName "target\release\$required"))){throw "Package omits $required"}}
Write-Host 'PHASE manifest-and-binaries: PASS'
$cursor=Join-Path $configs 'cursor.json';$vscode=Join-Path $configs 'vscode.json';$claude=Join-Path $configs 'claude.json';$encoding=New-Object System.Text.UTF8Encoding($false)
[IO.File]::WriteAllText($cursor,'{"mcpServers":{"other":{"command":"keep-me"}},"keep":"cursor"}',$encoding);[IO.File]::WriteAllText($vscode,'{"servers":{"other":{"command":"keep-me"}},"keep":"vscode"}',$encoding);[IO.File]::WriteAllText($claude,'{"mcpServers":{"other":{"command":"keep-me"}},"keep":"claude"}',$encoding)
$installScript=Join-Path $package.FullName 'scripts\installer\install-vor-pilot.ps1';$common=@{InstallRoot=$install;AllowedRoot=@($allowed);DeviceId='vor-installer-e2e';SkipStartupTask=$true;CursorConfigPath=$cursor;VsCodeConfigPath=$vscode;ClaudeConfigPath=$claude}
Write-Host 'PHASE install'; & $installScript @common
$verify=Join-Path $install 'scripts\installer\verify-vor-pilot.ps1'; & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $verify -InstallRoot $install
if($LASTEXITCODE -ne 0){throw 'Verification failed in a fresh powershell.exe process.'};Write-Host 'PHASE fresh-process-verify: PASS'
$cred=Import-Clixml(Join-Path $install 'state\local\mcp-credential.clixml');$ptr=[Runtime.InteropServices.Marshal]::SecureStringToBSTR($cred.Password);try{$script:Token=[Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr)}finally{[Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr)}
$writePath=Join-Path $allowed 'approved-write.txt';$content='beta2 approved write';$prepared=Invoke-McpTool 'prepare_write' ([ordered]@{device_id='vor-installer-e2e';path=$writePath;content_base64=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($content));expected_target_sha256='absent'}) 10
if($prepared.status -ne 'approval_required'){throw "prepare_write did not require approval: $($prepared.status)"}
$approval=&(Join-Path $install 'scripts\local\approve-vor-request.ps1') -RequestBase64 $prepared.request_base64 -Challenge $prepared.challenge -Confirm;$approval=@($approval)[-1]
$commitArgs=[ordered]@{device_id='vor-installer-e2e';request_base64=$prepared.request_base64;approval_base64=$approval};$committed=Invoke-McpTool 'commit_write' $commitArgs 11
if($committed.status -ne 'ok' -or (Get-Content -Raw -LiteralPath $writePath) -ne $content){throw 'Approved write did not commit exact content.'};$replayed=Invoke-McpTool 'commit_write' $commitArgs 12
if($replayed.status -ne 'approval_replayed'){throw "Write replay was not rejected: $($replayed.status)"};Write-Host 'PHASE approved-write-and-replay: PASS'
$terminal=Invoke-McpTool 'prepare_terminal' ([ordered]@{device_id='vor-installer-e2e';cwd=$allowed;argv=@('whoami.exe');timeout_ms=10000;max_output_bytes=65536}) 20
if($terminal.status -ne 'approval_required'){throw "prepare_terminal did not require approval: $($terminal.status)"};$terminalApproval=&(Join-Path $install 'scripts\local\approve-vor-request.ps1') -RequestBase64 $terminal.request_base64 -Challenge $terminal.challenge -Confirm;$terminalApproval=@($terminalApproval)[-1]
$terminalArgs=[ordered]@{device_id='vor-installer-e2e';request_base64=$terminal.request_base64;approval_base64=$terminalApproval};$terminalCommit=Invoke-McpTool 'commit_terminal' $terminalArgs 21
if($terminalCommit.status -ne 'ok'){throw "Approved terminal did not start: $($terminalCommit.status)"};$terminalReplay=Invoke-McpTool 'commit_terminal' $terminalArgs 22
if($terminalReplay.status -ne 'approval_replayed'){throw "Terminal replay was not rejected: $($terminalReplay.status)"};Write-Host 'PHASE approved-terminal-and-replay: PASS (default policy command: whoami.exe)'
$policy=Join-Path $install 'config\policy.example.yaml';Add-Content -LiteralPath $policy -Value '# owner customization';$policyHash=(Get-FileHash -Algorithm SHA256 -LiteralPath $policy).Hash
Write-Host 'PHASE reinstall'; & $installScript @common
if((Get-FileHash -Algorithm SHA256 -LiteralPath $policy).Hash-ne$policyHash){throw 'Reinstall overwrote the edited policy.'};if(-not(Test-Path -LiteralPath($policy+'.new'))){throw 'Reinstall did not retain the new packaged policy as .new.'}
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $verify -InstallRoot $install;if($LASTEXITCODE -ne 0){throw 'Post-reinstall verification failed in a fresh process.'};Write-Host 'PHASE policy-preservation-and-reinstall: PASS'
$uninstall=Join-Path $install 'scripts\installer\uninstall-vor-pilot.ps1';Write-Host 'PHASE uninstall'; & $uninstall -InstallRoot $install -SkipStartupTask
if(Test-Path -LiteralPath $install){throw 'Install directory remains after uninstall.'};$archives=@(Get-ChildItem -LiteralPath $TestRoot -Directory -Filter 'VorCommanderPilot-audit-*');if($archives.Count -ne 1){throw 'Default uninstall did not preserve one audit archive.'};Remove-Item -LiteralPath $archives[0].FullName -Recurse -Force
foreach($backup in($cursor+'.vor-backup'),($vscode+'.vor-backup')){if(Test-Path -LiteralPath $backup){throw "Unchanged installer backup remains: $backup"}}
$cursorJson=Get-Content -Raw -LiteralPath $cursor|ConvertFrom-Json;$vscodeJson=Get-Content -Raw -LiteralPath $vscode|ConvertFrom-Json
if($cursorJson.mcpServers.PSObject.Properties['vor-commander'] -or $vscodeJson.servers.PSObject.Properties['vor-commander']){throw 'A Vor client entry remains.'};if(-not $cursorJson.mcpServers.PSObject.Properties['other'] -or -not $vscodeJson.servers.PSObject.Properties['other']){throw 'Another client entry was removed.'}
$script:Token=$null;foreach($port in 8742,8789,8790){if(Get-NetTCPConnection -State Listen -LocalPort $port -ErrorAction SilentlyContinue){throw "Port $port remains in use after uninstall."}}
Write-Host 'PHASE ports-after-and-process-cleanup: PASS';Write-Host 'RESULT PASS: manifest, real install, fresh-process verify, approved write/terminal, replay rejection, reinstall policy preservation, backup cleanup, uninstall';Write-Host "Test root: $TestRoot"
