param(
  [Parameter(Mandatory=$true)][string]$RequestBase64,
  [Parameter(Mandatory=$true)]$Challenge,
  [string]$DiffSummary,
  [switch]$Confirm
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'common.ps1')
$config = Get-LocalConfig
$approver = Join-Path $BinDir 'vor-approver.exe'
if (-not (Test-Path -LiteralPath $approver)) { throw "Missing approver: $approver" }
$challengeObject = if ($Challenge -is [string]) { $Challenge | ConvertFrom-Json } else { $Challenge }
$work = Join-Path $env:TEMP ('vor-approval-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $work | Out-Null
try {
  $requestFile = Join-Path $work 'request.b64'
  $challengeFile = Join-Path $work 'challenge.json'
  $approvalFile = Join-Path $work 'approval.b64'
  Write-Utf8NoBom $requestFile $RequestBase64.Trim()
  Write-Utf8NoBom $challengeFile ($challengeObject | ConvertTo-Json -Depth 10)
  $summary = (& $approver describe --request-file $requestFile --challenge-file $challengeFile) -join "`n"
  if ($LASTEXITCODE -ne 0) { throw 'The prepared request or challenge is invalid.' }
  Write-Host ''
  Write-Host $summary
  if ($challengeObject.PSObject.Properties['expires_at_unix_ms']) {
    $expiry = [DateTimeOffset]::FromUnixTimeMilliseconds([int64]$challengeObject.expires_at_unix_ms).ToLocalTime()
    Write-Host ("Readable expiry: {0}" -f $expiry.ToString('yyyy-MM-dd HH:mm:ss zzz'))
  }
  if ($DiffSummary) {
    Write-Host ''
    Write-Host 'Diff summary supplied by prepare_edit:'
    Write-Host $DiffSummary
  }
  $approved = $Confirm
  if (-not $approved) { $approved = ((Read-Host 'Type APPROVE to sign this one-use request') -ceq 'APPROVE') }
  if (-not $approved) { throw 'Approval declined by owner.' }
  & $approver sign --approver-id $config.approver_id --secret-store $config.secret_store --request-file $requestFile --challenge-file $challengeFile --out $approvalFile --confirmed | Out-Host
  if ($LASTEXITCODE -ne 0) { throw 'Approval signing failed.' }
  $approval = (Get-Content -Raw -LiteralPath $approvalFile).Trim()
  Write-Output $approval
} finally {
  if (Test-Path -LiteralPath $work) { Remove-Item -LiteralPath $work -Recurse -Force }
}
