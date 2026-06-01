# Keep this script ASCII-only so Windows PowerShell 5.1 can parse the raw GitHub download reliably.
param(
  [Parameter(Mandatory = $true)]
  [string]$ServerUrl,
  [Parameter(Mandatory = $true)]
  [string]$AgentToken,
  [string]$NodeId = "",
  [switch]$DisableUpdate,
  [string]$Version = ""
)

$ErrorActionPreference = "Stop"

function Assert-Admin {
  $current = [Security.Principal.WindowsIdentity]::GetCurrent()
  $principal = New-Object Security.Principal.WindowsPrincipal($current)
  if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "Please run PowerShell as Administrator."
    exit 1
  }
}

function Ensure-Tls12 {
  if ($PSVersionTable.PSVersion.Major -lt 7) {
    try {
      [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    } catch {
    }
  }
}

function Get-TrimmedText {
  param(
    [string]$Value
  )
  if ($null -eq $Value) {
    return ""
  }
  return $Value.Trim()
}

function Assert-NotReparsePath {
  param(
    [string]$Path,
    [switch]$AllowMissingLeaf
  )
  $trimmedPath = Get-TrimmedText -Value $Path
  if (-not $trimmedPath) {
    return
  }
  $fullPath = [System.IO.Path]::GetFullPath($trimmedPath)
  $current = $fullPath
  while ($current) {
    if (Test-Path -LiteralPath $current) {
      $item = Get-Item -LiteralPath $current -Force
      if ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
        throw "Refusing reparse point path: $current"
      }
    }
    $parent = Split-Path -Parent $current
    if (-not $parent -or $parent -eq $current) {
      break
    }
    $current = $parent
  }
}

function New-WebRequestParams {
  param(
    [string]$Uri,
    [string]$Method = "Get",
    [hashtable]$Headers = @{},
    [string]$OutFile = ""
  )
  $requestHeaders = @{ "User-Agent" = "CyberMonitor" }
  foreach ($name in $Headers.Keys) {
    $requestHeaders[$name] = $Headers[$name]
  }
  $params = @{
    Uri     = (Get-TrimmedText -Value $Uri)
    Method  = $Method
    Headers = $requestHeaders
  }
  $trimmedOutFile = Get-TrimmedText -Value $OutFile
  if ($trimmedOutFile) {
    $params.OutFile = $trimmedOutFile
  }
  if ($PSVersionTable.PSVersion.Major -lt 6) {
    $params.UseBasicParsing = $true
  }
  return $params
}

function Invoke-WebCall {
  param(
    [ValidateSet("WebRequest", "RestMethod")]
    [string]$Kind,
    [string]$Uri,
    [string]$Method = "Get",
    [hashtable]$Headers = @{},
    [string]$OutFile = ""
  )
  $params = New-WebRequestParams -Uri $Uri -Method $Method -Headers $Headers -OutFile $OutFile
  if ($Kind -eq "RestMethod") {
    return Invoke-RestMethod @params
  }
  return Invoke-WebRequest @params
}

function Invoke-Sc {
  param(
    [string[]]$Arguments
  )
  & sc.exe @Arguments | Out-Null
  if ($LASTEXITCODE -ne 0) {
    throw ('sc.exe failed: {0}' -f ($Arguments -join ' '))
  }
}

function Wait-ServiceRunning {
  param(
    [string]$Name,
    [int]$TimeoutSeconds = 15
  )
  $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
  do {
    $service = Get-Service -Name $Name -ErrorAction Stop
    if ($service.Status -eq [System.ServiceProcess.ServiceControllerStatus]::Running) {
      return
    }
    Start-Sleep -Seconds 1
  } while ((Get-Date) -lt $deadline)
  throw ('Service failed to reach Running state: {0}' -f $service.Status)
}

function Wait-ServiceDeleted {
  param(
    [string]$Name,
    [int]$TimeoutSeconds = 15
  )
  $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
  do {
    if (-not (Get-Service -Name $Name -ErrorAction SilentlyContinue)) {
      return
    }
    Start-Sleep -Seconds 1
  } while ((Get-Date) -lt $deadline)
  throw ('Service failed to delete within {0} seconds: {1}' -f $TimeoutSeconds, $Name)
}

function Stop-ServiceIfExists {
  param(
    [string]$Name
  )
  if (-not (Get-Service -Name $Name -ErrorAction SilentlyContinue)) {
    return
  }
  Stop-Service -Name $Name -Force -ErrorAction SilentlyContinue
}

function Remove-ServiceIfExists {
  param(
    [string]$Name
  )
  if (-not (Get-Service -Name $Name -ErrorAction SilentlyContinue)) {
    return
  }
  Stop-ServiceIfExists -Name $Name
  Invoke-Sc -Arguments @("delete", $Name)
  Wait-ServiceDeleted -Name $Name
}

function Get-ServiceSnapshot {
  param(
    [string]$Name
  )
  $trimmedName = Get-TrimmedText -Value $Name
  if (-not $trimmedName) {
    return [pscustomobject]@{ Exists = $false; PathName = ""; StartMode = ""; Running = $false }
  }
  try {
    $escapedName = $trimmedName.Replace("'", "''")
    $service = Get-CimInstance -ClassName Win32_Service -Filter "Name='$escapedName'" -ErrorAction SilentlyContinue
    if ($service) {
      return [pscustomobject]@{
        Exists = $true
        PathName = [string]$service.PathName
        StartMode = [string]$service.StartMode
        Running = ([string]$service.State -eq "Running")
      }
    }
  } catch {
  }
  return [pscustomobject]@{ Exists = $false; PathName = ""; StartMode = ""; Running = $false }
}

function Backup-FileIfExists {
  param(
    [string]$Path
  )
  $trimmedPath = Get-TrimmedText -Value $Path
  if (-not $trimmedPath) {
    return ""
  }
  Assert-NotReparsePath -Path $trimmedPath -AllowMissingLeaf
  if (-not (Test-Path -LiteralPath $trimmedPath -PathType Leaf)) {
    return ""
  }
  $parent = Split-Path -Parent $trimmedPath
  $name = Split-Path -Leaf $trimmedPath
  if (-not $parent) {
    $parent = "."
  }
  $backupPath = Join-Path $parent ("." + $name + "." + [guid]::NewGuid().ToString("N") + ".bak")
  try {
    Copy-Item -LiteralPath $trimmedPath -Destination $backupPath -Force
    Protect-SecretFile -Path $backupPath
  } catch {
    Remove-Item -LiteralPath $backupPath -Force -ErrorAction SilentlyContinue
    throw
  }
  return $backupPath
}

function Restore-FileBackup {
  param(
    [string]$Path,
    [string]$BackupPath
  )
  $trimmedPath = Get-TrimmedText -Value $Path
  $trimmedBackupPath = Get-TrimmedText -Value $BackupPath
  if (-not $trimmedPath) {
    return
  }
  Assert-NotReparsePath -Path $trimmedPath -AllowMissingLeaf
  if ($trimmedBackupPath -and (Test-Path -LiteralPath $trimmedBackupPath -PathType Leaf)) {
    Assert-NotReparsePath -Path $trimmedBackupPath
    Move-Item -LiteralPath $trimmedBackupPath -Destination $trimmedPath -Force
    return
  }
  Remove-Item -LiteralPath $trimmedPath -Force -ErrorAction SilentlyContinue
}

function Protect-SecretFile {
  param(
    [string]$Path
  )
  $trimmedPath = Get-TrimmedText -Value $Path
  if (-not $trimmedPath) {
    throw "secret file path required"
  }
  Assert-NotReparsePath -Path $trimmedPath
  if (-not (Test-Path -LiteralPath $trimmedPath -PathType Leaf)) {
    throw "secret file does not exist: $trimmedPath"
  }
  & icacls.exe $trimmedPath /inheritance:r /grant:r "*S-1-5-18:F" "*S-1-5-32-544:F" | Out-Null
  if ($LASTEXITCODE -ne 0) {
    throw "Unable to protect secret file ACL: $trimmedPath"
  }
}

function ConvertTo-ServiceArgument {
  param(
    [string]$Value
  )
  $trimmed = Get-TrimmedText -Value $Value
  if (-not $trimmed) {
    throw "Windows service argument must not be empty."
  }
  if ($trimmed.Contains('"')) {
    throw "Windows service argument must not contain double quotes."
  }
  if ($trimmed -match '[\x00-\x1F\x7F]') {
    throw "Windows service argument must not contain control characters."
  }
  $trailingBackslashes = [regex]::Match($trimmed, '\\+$').Value
  if ($trailingBackslashes) {
    $trimmed = $trimmed + $trailingBackslashes
  }
  return ('"{0}"' -f $trimmed)
}

function New-AgentServiceBinPath {
  param(
    [string]$BinaryPath,
    [string]$ServerUrl,
    [string]$NodeIdFile,
    [string]$TokenFile,
    [switch]$DisableUpdate
  )
  $args = @(
    (ConvertTo-ServiceArgument -Value $BinaryPath)
    "--server-url"
    (ConvertTo-ServiceArgument -Value $ServerUrl)
    "--node-id-file"
    (ConvertTo-ServiceArgument -Value $NodeIdFile)
    "--agent-token-file"
    (ConvertTo-ServiceArgument -Value $TokenFile)
  )
  if ($DisableUpdate) {
    $args += "--disable-update"
  }
  return ($args -join ' ')
}

function Get-InstallDir {
  $programData = $env:ProgramData
  if (-not $programData) {
    $programData = $env:ALLUSERSPROFILE
  }
  if (-not $programData) {
    $programData = "C:\ProgramData"
  }
  return Join-Path $programData "CyberMonitor"
}

function Get-Arch {
  $raw = $env:PROCESSOR_ARCHITEW6432
  if (-not $raw) {
    $raw = $env:PROCESSOR_ARCHITECTURE
  }
  $raw = ($raw | ForEach-Object { $_.ToUpper() })
  switch ($raw) {
    "ARM64" { return "arm64" }
    "AMD64" { return "amd64" }
    "X86" {
      Write-Host "Windows 32-bit is not supported."
      exit 1
    }
    default { throw "Unsupported Windows processor architecture: $raw" }
  }
}

function Get-LatestVersion {
  param(
    [string]$Repo,
    [string]$FallbackVersion
  )
  $normalizedFallbackVersion = Normalize-ReleaseVersion -Version $FallbackVersion
  if ($normalizedFallbackVersion) {
    return $normalizedFallbackVersion
  }
  try {
    $release = Invoke-WebCall -Kind RestMethod -Uri "https://api.github.com/repos/$Repo/releases/latest"
    if ($release -and $release.tag_name) {
      return Normalize-ReleaseVersion -Version ([string]$release.tag_name)
    }
  } catch {
  }
  try {
    $resp = Invoke-WebCall -Kind WebRequest -Uri "https://github.com/$Repo/releases/latest"
    $final = $resp.BaseResponse.ResponseUri.AbsoluteUri
    $tag = $final.Split('/')[-1]
    if ($tag -and $tag -ne "latest") {
      return Normalize-ReleaseVersion -Version $tag
    }
  } catch {
  }
  Write-Host "Unable to fetch latest version. Use -Version to specify."
  exit 1
}

function Normalize-ReleaseVersion {
  param(
    [string]$Version
  )
  $trimmed = Get-TrimmedText -Value $Version
  if (-not $trimmed) {
    return ""
  }
  if ($trimmed -match '^(?i:v?latest)$') {
    return ""
  }
  if ($trimmed -match '^v?[0-9]+(\.[0-9]+){2}([.-][0-9A-Za-z][0-9A-Za-z.-]*)?$') {
    if ($trimmed -notmatch '^v') {
      return "v$trimmed"
    }
    return $trimmed
  }
  throw "Version must look like v0.1.0 or v0.1.0-rc.1."
}

function Read-TrimmedFile {
  param(
    [string]$Path
  )
  $trimmedPath = Get-TrimmedText -Value $Path
  if (-not $trimmedPath) {
    return ""
  }
  if (-not (Test-Path -LiteralPath $trimmedPath -PathType Leaf)) {
    return ""
  }
  Assert-NotReparsePath -Path $trimmedPath
  try {
    return Get-TrimmedText -Value ([System.IO.File]::ReadAllText($trimmedPath))
  } catch {
    return ""
  }
}

function Write-TrimmedFile {
  param(
    [string]$Path,
    [string]$Value
  )
  Write-PrivateStateFile -Path $Path -Value $Value
}

function Write-PrivateStateFile {
  param(
    [string]$Path,
    [string]$Value
  )
  $trimmedPath = Get-TrimmedText -Value $Path
  $trimmedValue = Get-TrimmedText -Value $Value
  if (-not $trimmedPath) {
    throw "file path required"
  }
  if (-not $trimmedValue) {
    throw "file value required"
  }
  Assert-NotReparsePath -Path $trimmedPath -AllowMissingLeaf
  $parent = Split-Path -Parent $trimmedPath
  if ($parent) {
    New-Item -ItemType Directory -Path $parent -Force | Out-Null
  }
  $leaf = Split-Path -Leaf $trimmedPath
  $tmpPath = Join-Path $parent ("." + $leaf + "." + [guid]::NewGuid().ToString("N") + ".tmp")
  try {
    Assert-NotReparsePath -Path $tmpPath
    [System.IO.File]::WriteAllText($tmpPath, "")
    Protect-SecretFile -Path $tmpPath
    [System.IO.File]::WriteAllText($tmpPath, $trimmedValue + [Environment]::NewLine)
    Move-Item -LiteralPath $tmpPath -Destination $trimmedPath -Force
    Protect-SecretFile -Path $trimmedPath
  } catch {
    Remove-Item -LiteralPath $tmpPath -Force -ErrorAction SilentlyContinue
    throw
  }
}

function New-NodeId {
  return ([guid]::NewGuid().ToString()).ToLowerInvariant()
}

function Resolve-NodeId {
  param(
    [string]$ExplicitNodeId,
    [string]$NodeIdFile
  )
  $resolvedNodeId = Get-TrimmedText -Value $ExplicitNodeId
  if ($resolvedNodeId) {
    return $resolvedNodeId
  }
  $persisted = Read-TrimmedFile -Path $NodeIdFile
  if ($persisted) {
    return $persisted
  }
  return New-NodeId
}

function Test-DownloadedAssetChecksum {
  param(
    [string]$Repo,
    [string]$Version,
    [string]$AssetName,
    [string]$AssetPath
  )
  $checksumUrl = "https://github.com/$Repo/releases/download/$Version/SHA256SUMS"
  $checksumFile = Join-Path ([System.IO.Path]::GetTempPath()) ("cybermonitor-sha256-" + [guid]::NewGuid().ToString("N") + ".txt")
  try {
    try {
      Invoke-WebCall -Kind WebRequest -Uri $checksumUrl -OutFile $checksumFile | Out-Null
    } catch {
      throw "Unable to download SHA256SUMS. This release may not include checksums; use a newer release with SHA256SUMS or the matching older installer."
    }
    $expected = ""
    foreach ($line in [System.IO.File]::ReadLines($checksumFile)) {
      if ($line -match '^([A-Fa-f0-9]{64})\s+\*?(.+)$') {
        if ($Matches[2].Trim() -eq $AssetName) {
          $expected = $Matches[1].ToLowerInvariant()
          break
        }
      }
    }
    if (-not $expected) {
      throw "SHA256SUMS entry not found for $AssetName. Check that the installer and release version match."
    }
    $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $AssetPath).Hash.ToLowerInvariant()
    if ($actual -ne $expected) {
      throw "Downloaded file checksum mismatch: $AssetName"
    }
  } finally {
    Remove-Item -LiteralPath $checksumFile -Force -ErrorAction SilentlyContinue
  }
}

function Register-Agent {
  param(
    [string]$RegisterServerUrl,
    [string]$BootstrapToken,
    [string]$CurrentNodeId
  )
  $registerNodeId = [Uri]::EscapeDataString($CurrentNodeId)
  $baseServerUrl = Get-TrimmedText -Value $RegisterServerUrl
  $uri = "{0}/api/v1/agent/register?node_id={1}" -f $baseServerUrl.TrimEnd('/'), $registerNodeId
  $response = Invoke-WebCall -Kind RestMethod -Method Post -Uri $uri -Headers @{ "X-AGENT-TOKEN" = $BootstrapToken }
  if (-not $response -or -not $response.agent_token) {
    throw "Agent registration succeeded but the server did not return a dedicated token."
  }
  return [string]$response.agent_token
}

Assert-Admin
Ensure-Tls12

$repo = "crazy0x70/CyberMonitor"
$installDir = Get-InstallDir
$binary = Join-Path $installDir "cyber-monitor-agent.exe"
$nodeIDFile = Join-Path $installDir ".cybermonitor-node-id"
$tokenFile = Join-Path $installDir ".cybermonitor-agent-token"
$serviceName = "CyberMonitorAgent"
Assert-NotReparsePath -Path $installDir -AllowMissingLeaf
Assert-NotReparsePath -Path $binary -AllowMissingLeaf
Assert-NotReparsePath -Path $nodeIDFile -AllowMissingLeaf
Assert-NotReparsePath -Path $tokenFile -AllowMissingLeaf
$arch = Get-Arch
$resolvedVersion = Get-LatestVersion -Repo $repo -FallbackVersion $Version
New-Item -ItemType Directory -Path $installDir -Force | Out-Null
Assert-NotReparsePath -Path $installDir
$ServerUrl = Get-TrimmedText -Value $ServerUrl
$AgentToken = Get-TrimmedText -Value $AgentToken
if (-not $ServerUrl) {
  throw "ServerUrl is required."
}
if (-not $AgentToken) {
  throw "AgentToken is required."
}
$NodeId = Resolve-NodeId -ExplicitNodeId $NodeId -NodeIdFile $nodeIDFile

$assetName = "cyber-monitor-agent-windows-$arch.exe"
$url = "https://github.com/$repo/releases/download/$resolvedVersion/$assetName"
$tmpBinary = Join-Path $installDir ("." + $assetName + "." + [guid]::NewGuid().ToString("N") + ".tmp")
try {
  Assert-NotReparsePath -Path $tmpBinary
  Invoke-WebCall -Kind WebRequest -Uri $url -OutFile $tmpBinary
  Test-DownloadedAssetChecksum -Repo $repo -Version $resolvedVersion -AssetName $assetName -AssetPath $tmpBinary
  Assert-NotReparsePath -Path $tmpBinary
} catch {
  Remove-Item -LiteralPath $tmpBinary -Force -ErrorAction SilentlyContinue
  throw
}
$serviceBinPath = New-AgentServiceBinPath -BinaryPath $binary -ServerUrl $ServerUrl -NodeIdFile $nodeIDFile -TokenFile $tokenFile -DisableUpdate:$DisableUpdate

$hadExistingBinary = Test-Path -LiteralPath $binary
$binaryReplaced = $false
$backupBinary = $null
$previousService = $null
$nodeIDFileBackup = ""
$tokenFileBackup = ""
$serviceTouched = $false
$serviceCreated = $false
$nodeRegistered = $false
try {
  $previousService = Get-ServiceSnapshot -Name $serviceName
  $nodeIDFileBackup = Backup-FileIfExists -Path $nodeIDFile
  $tokenFileBackup = Backup-FileIfExists -Path $tokenFile
  if ($hadExistingBinary) {
    $backupBinary = Join-Path $installDir (".cyber-monitor-agent." + [guid]::NewGuid().ToString("N") + ".bak")
  }
  $nodeToken = Register-Agent -RegisterServerUrl $ServerUrl -BootstrapToken $AgentToken -CurrentNodeId $NodeId
  $nodeRegistered = $true
  Write-TrimmedFile -Path $nodeIDFile -Value $NodeId
  Write-TrimmedFile -Path $tokenFile -Value $nodeToken

  $serviceTouched = $true
  if ($previousService.Exists) {
    Stop-ServiceIfExists -Name $serviceName
  }
  if ($backupBinary) {
    Move-Item -LiteralPath $binary -Destination $backupBinary -Force
  }
  Move-Item -LiteralPath $tmpBinary -Destination $binary -Force
  $binaryReplaced = $true

  if ($previousService.Exists) {
    Invoke-Sc -Arguments @("config", $serviceName, "binPath=", $serviceBinPath, "start=", "auto")
    Invoke-Sc -Arguments @("start", $serviceName)
    Wait-ServiceRunning -Name $serviceName
  } else {
    Invoke-Sc -Arguments @("create", $serviceName, "binPath=", $serviceBinPath, "start=", "auto")
    $serviceCreated = $true
    Invoke-Sc -Arguments @("failure", $serviceName, "reset=", "0", "actions=", "restart/5000/restart/5000/restart/5000")
    Invoke-Sc -Arguments @("failureflag", $serviceName, "1")
    Invoke-Sc -Arguments @("start", $serviceName)
    Wait-ServiceRunning -Name $serviceName
  }

  if ($backupBinary) {
    Remove-Item -LiteralPath $backupBinary -Force -ErrorAction SilentlyContinue
  }
} catch {
  $installError = $_
  Write-Host ("Install failed, attempting rollback: {0}" -f $installError.Exception.Message)
  try {
    if ($serviceCreated) {
      Remove-ServiceIfExists -Name $serviceName
    } elseif ($serviceTouched -and $previousService.Exists) {
      Stop-ServiceIfExists -Name $serviceName
    }
    if ((-not $nodeRegistered) -or $nodeIDFileBackup) {
      Restore-FileBackup -Path $nodeIDFile -BackupPath $nodeIDFileBackup
    }
    Restore-FileBackup -Path $tokenFile -BackupPath $tokenFileBackup
    $rollbackBinaryAvailable = $false
    if ($backupBinary -and (Test-Path -LiteralPath $backupBinary)) {
      Assert-NotReparsePath -Path $binary
      Assert-NotReparsePath -Path $backupBinary
      Remove-Item -LiteralPath $binary -Force -ErrorAction SilentlyContinue
      Move-Item -LiteralPath $backupBinary -Destination $binary -Force
      $rollbackBinaryAvailable = $true
    } elseif ($hadExistingBinary -and (Test-Path -LiteralPath $binary)) {
      $rollbackBinaryAvailable = $true
    } elseif ($binaryReplaced -and -not $hadExistingBinary) {
      Assert-NotReparsePath -Path $binary
      Remove-Item -LiteralPath $binary -Force -ErrorAction SilentlyContinue
    }
    if ($previousService.Exists -and $rollbackBinaryAvailable -and $previousService.PathName) {
      Invoke-Sc -Arguments @("config", $serviceName, "binPath=", $previousService.PathName)
      if ($previousService.Running) {
        Invoke-Sc -Arguments @("start", $serviceName)
        Wait-ServiceRunning -Name $serviceName
      }
      Write-Host "Rollback restored the previous agent binary and service path."
    }
  } catch {
    Write-Host ("Rollback failed: {0}" -f $_.Exception.Message)
  }
  throw $installError
} finally {
  if ($tmpBinary) {
    Assert-NotReparsePath -Path $tmpBinary
    Remove-Item -LiteralPath $tmpBinary -Force -ErrorAction SilentlyContinue
  }
  if ($nodeIDFileBackup) {
    Assert-NotReparsePath -Path $nodeIDFileBackup
    Remove-Item -LiteralPath $nodeIDFileBackup -Force -ErrorAction SilentlyContinue
  }
  if ($tokenFileBackup) {
    Assert-NotReparsePath -Path $tokenFileBackup
    Remove-Item -LiteralPath $tokenFileBackup -Force -ErrorAction SilentlyContinue
  }
  if ($backupBinary) {
    Assert-NotReparsePath -Path $backupBinary
    Remove-Item -LiteralPath $backupBinary -Force -ErrorAction SilentlyContinue
  }
}

Write-Host "Service installed: $serviceName"
Write-Host "Node ID: $NodeId"
