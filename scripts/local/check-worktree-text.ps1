param(
  [string]$Root = (Get-Location).Path
)

$ErrorActionPreference = 'Stop'
$rootPath = (Resolve-Path -LiteralPath $Root).Path

$sourceExtensions = @(
  '.rs', '.toml', '.lock', '.md', '.yaml', '.yml', '.proto',
  '.ps1', '.py', '.service', '.sh', '.json', '.txt'
)
$excludedPrefixes = @(
  '.git/',
  'target/',
  'target-linux/',
  'target-m3-stage/',
  'state/'
)
$sensitivePatterns = @(
  '(^|/)\.env($|\.)',
  '(^|/)id_rsa($|\.)',
  '(^|/)id_ed25519($|\.)',
  '(^|/).*\.(pem|key|pfx|p12)$'
)

function Invoke-GitUtf8Z([string[]]$Arguments) {
  $psi = [Diagnostics.ProcessStartInfo]::new()
  $psi.FileName = 'git'
  $allArguments = @('-C', $rootPath) + $Arguments
  $psi.Arguments = ($allArguments | ForEach-Object {
    '"' + ($_ -replace '"', '\"') + '"'
  }) -join ' '
  $psi.RedirectStandardOutput = $true
  $psi.RedirectStandardError = $true
  $psi.UseShellExecute = $false
  $process = [Diagnostics.Process]::Start($psi)
  $stdout = New-Object IO.MemoryStream
  $process.StandardOutput.BaseStream.CopyTo($stdout)
  $stderr = $process.StandardError.ReadToEnd()
  $process.WaitForExit()
  if ($process.ExitCode -ne 0) {
    throw "git $($Arguments -join ' ') failed with exit $($process.ExitCode): $stderr"
  }
  $bytes = $stdout.ToArray()
  if ($bytes.Length -eq 0) {
    return @()
  }
  $text = [Text.UTF8Encoding]::new($false, $true).GetString($bytes)
  return @($text.Split([char[]]@([char]0), [StringSplitOptions]::RemoveEmptyEntries))
}

function Convert-ToRepoPath([string]$Path) {
  return (($Path -replace '\\', '/') -replace '^\./', '')
}

function Is-Excluded([string]$Name) {
  foreach ($prefix in $excludedPrefixes) {
    if ($Name.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
      return $true
    }
  }
  foreach ($pattern in $sensitivePatterns) {
    if ($Name -match $pattern) {
      return $true
    }
  }
  return $false
}

$tracked = [string[]]@(Invoke-GitUtf8Z @('ls-files', '-z'))
$others = [string[]]@(Invoke-GitUtf8Z @('ls-files', '--others', '--exclude-standard', '-z'))
$gitNames = @($tracked + $others | ForEach-Object { Convert-ToRepoPath $_ } | Sort-Object -Unique)

$selected = New-Object System.Collections.Generic.List[string]
$excluded = New-Object System.Collections.Generic.List[string]
$omitted = New-Object System.Collections.Generic.List[string]
foreach ($name in $gitNames) {
  $extension = [IO.Path]::GetExtension($name)
  if (Is-Excluded $name) {
    $excluded.Add($name)
  } elseif ($sourceExtensions -contains $extension) {
    $selected.Add($name)
  } else {
    $omitted.Add($name)
  }
}

$errors = New-Object System.Collections.Generic.List[string]
$read = New-Object System.Collections.Generic.List[string]
$disappeared = New-Object System.Collections.Generic.List[string]

foreach ($name in $selected) {
  $path = Join-Path $rootPath ($name -replace '/', [IO.Path]::DirectorySeparatorChar)
  if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
    $disappeared.Add($name)
    $errors.Add("${name}: selected by git but not readable as a file")
    continue
  }
  $read.Add($name)
  $lineNo = 0
  foreach ($line in [IO.File]::ReadLines($path, [Text.UTF8Encoding]::new($false, $true))) {
    $lineNo += 1
    if ($line -match '[ \t]+$') {
      $errors.Add("${name}:${lineNo}: trailing whitespace")
    }
    if ($line -match '^(<<<<<<<|=======|>>>>>>>)') {
      $errors.Add("${name}:${lineNo}: conflict marker")
    }
  }
}

$unexpectedOmissions = @($selected | Where-Object { -not $read.Contains($_) })
foreach ($name in $unexpectedOmissions) {
  if (-not $disappeared.Contains($name)) {
    $errors.Add("${name}: selected but not checked")
  }
}

$report = [ordered]@{
  status = if ($errors.Count -eq 0) { 'ok' } else { 'fail' }
  selected_files = $selected.Count
  read_files = $read.Count
  excluded_files = $excluded.Count
  omitted_files = $omitted.Count
  git_names = $gitNames.Count
  disappeared_files = @($disappeared)
  errors = @($errors)
}

$report | ConvertTo-Json -Compress -Depth 5
if ($errors.Count -gt 0) {
  exit 1
}
