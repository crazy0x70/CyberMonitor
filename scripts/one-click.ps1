# CyberMonitor one-click install/uninstall script for Windows (server + agent).
# Keep this script ASCII-only so Windows PowerShell 5.1 can parse the raw GitHub download reliably.
param(
  [string]$Command = "",
  [string]$ServerUrl = "",
  [string]$AgentToken = "",
  [string]$NodeId = "",
  [switch]$DisableUpdate,
  [string]$Listen = "",
  [string]$DataDir = "",
  [string]$AdminPass = "",
  [switch]$KeepData,
  [string]$Version = ""
)

$ErrorActionPreference = "Stop"

function Assert-Admin {
  $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
  $principal = New-Object Security.Principal.WindowsPrincipal($identity)
  if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "This script must be run as Administrator."
  }
}

function Ensure-Tls12 {
  try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
  } catch {
  }
}

function Get-TrimmedText {
  param([string]$Value)
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
  if (-not $Path) {
    return
  }
  $current = [System.IO.Path]::GetFullPath($Path)
  if ($AllowMissingLeaf -and -not (Test-Path -LiteralPath $current)) {
    $parent = Split-Path -Parent $current
    if ($parent -and (Test-Path -LiteralPath $parent)) {
      $current = $parent
    }
  }
  $item = Get-Item -LiteralPath $current -Force -ErrorAction SilentlyContinue
  while ($item) {
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
      throw ("Refuses reparse point path: {0}" -f $current)
    }
    $parentPath = Split-Path -Parent $item.FullName
    if (-not $parentPath -or $parentPath -eq $item.FullName) {
      break
    }
    $item = Get-Item -LiteralPath $parentPath -Force -ErrorAction SilentlyContinue
  }
}

function New-WebRequestParams {
  param(
    [string]$Uri,
    [string]$OutFile
  )
  $params = @{ UseBasicParsing = $true }
  if ($Uri) {
    $params.Uri = $Uri
  }
  if ($OutFile) {
    $params.OutFile = $OutFile
  }
  return $params
}

function Invoke-WebCall {
  param(
    [ValidateSet("WebRequest", "RestMethod")]
    [string]$Kind,
    [string]$Method,
    [string]$Uri,
    [hashtable]$Headers,
    [string]$OutFile
  )
  $params = New-WebRequestParams -Uri $Uri -OutFile $OutFile
  if ($Method) {
    $params.Method = $Method
  }
  if ($Headers) {
    $params.Headers = $Headers
  }
  if ($Kind -eq "RestMethod") {
    return Invoke-RestMethod @params
  }
  return Invoke-WebRequest @params
}

function Invoke-Sc {
  param([string[]]$Arguments)
  & sc.exe @Arguments | Out-Null
  if ($LASTEXITCODE -ne 0) {
    throw ('sc.exe failed: {0}' -f ($Arguments -join ' '))
  }
}

function Wait-ServiceRunning {
  param(
    [string]$Name,
    [int]$TimeoutSeconds = 30
  )
  $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
  do {
    $service = Get-Service -Name $Name -ErrorAction SilentlyContinue
    if ($service -and $service.Status -eq "Running") {
      return
    }
    Start-Sleep -Seconds 1
  } while ((Get-Date) -lt $deadline)
  throw ('Service failed to start within {0} seconds: {1}' -f $TimeoutSeconds, $Name)
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
  param([string]$Name)
  $service = Get-Service -Name $Name -ErrorAction SilentlyContinue
  if ($service) {
    try {
      Stop-Service -Name $Name -Force -ErrorAction Stop
    } catch {
      & sc.exe stop $Name | Out-Null
    }
    Wait-ServiceState -Name $Name -TargetState "Stopped"
  }
}

function Wait-ServiceState {
  param(
    [string]$Name,
    [string]$TargetState,
    [int]$TimeoutSeconds = 15
  )
  $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
  do {
    $service = Get-Service -Name $Name -ErrorAction SilentlyContinue
    if (-not $service -or $service.Status.ToString() -eq $TargetState) {
      return
    }
    Start-Sleep -Seconds 1
  } while ((Get-Date) -lt $deadline)
}

function Remove-ServiceIfExists {
  param([string]$Name)
  if (Get-Service -Name $Name -ErrorAction SilentlyContinue) {
    Stop-ServiceIfExists -Name $Name
    Invoke-Sc -Arguments @("delete", $Name)
    Wait-ServiceDeleted -Name $Name
  }
}

function Get-ServiceSnapshot {
  param([string]$Name)
  $service = Get-Service -Name $Name -ErrorAction SilentlyContinue
  $wmi = Get-CimInstance -ClassName Win32_Service -Filter ("Name='" + $Name + "'") -ErrorAction SilentlyContinue
  if (-not $service -and -not $wmi) {
    return [pscustomobject]@{ Exists = $false }
  }
  $startMode = ""
  $delayed = $false
  if ($wmi) {
    $startMode = [string]$wmi.StartMode
    $delayed = [bool]$wmi.DelayedAutoStart
  }
  return [pscustomobject]@{
    Exists = $true
    Running = ($service.Status -eq "Running")
    StartMode = $startMode
    DelayedAutoStart = $delayed
    PathName = [string]$wmi.PathName
  }
}

function ConvertTo-ScStartMode {
  param(
    [string]$StartMode,
    [bool]$DelayedAutoStart
  )
  if ($StartMode -eq "Auto") {
    if ($DelayedAutoStart) {
      return "delayed-auto"
    }
    return "auto"
  }
  if ($StartMode -eq "Manual") {
    return "demand"
  }
  if ($StartMode -eq "Disabled") {
    return "disabled"
  }
  return ""
}

function Backup-FileIfExists {
  param([string]$Path)
  if (-not (Test-Path -LiteralPath $Path)) {
    return ""
  }
  Assert-NotReparsePath -Path $Path
  $backupPath = Join-Path ([System.IO.Path]::GetDirectoryName($Path)) ("." + [System.IO.Path]::GetFileName($Path) + "." + [guid]::NewGuid().ToString("N") + ".bak")
  Copy-Item -LiteralPath $Path -Destination $backupPath -Force
  return $backupPath
}

function Restore-FileBackup {
  param(
    [string]$Path,
    [string]$BackupPath
  )
  if ($BackupPath -and (Test-Path -LiteralPath $BackupPath)) {
    Assert-NotReparsePath -Path $Path
    Assert-NotReparsePath -Path $BackupPath
    Move-Item -LiteralPath $BackupPath -Destination $Path -Force
    return
  }
  if (Test-Path -LiteralPath $Path) {
    Assert-NotReparsePath -Path $Path
    Remove-Item -LiteralPath $Path -Force
  }
}

function Remove-FileIfBackuped {
  param(
    [string]$Path,
    [string]$BackupPath
  )
  if ($BackupPath) {
    Assert-NotReparsePath -Path $BackupPath
    Remove-Item -LiteralPath $BackupPath -Force -ErrorAction SilentlyContinue
  }
}

function Protect-SecretFile {
  param([string]$Path)
  if (Test-Path -LiteralPath $Path) {
    $item = Get-Item -LiteralPath $Path -Force
    $item.Attributes = $item.Attributes -band (-bnot [IO.FileAttributes]::ReadOnly)
  }
}

function ConvertTo-ServiceArgument {
  param([string]$Value)
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
  try {
    $release = Invoke-WebCall -Kind RestMethod -Uri ("https://api.github.com/repos/{0}/releases/latest" -f $Repo)
    if ($release -and $release.tag_name) {
      return [string]$release.tag_name
    }
  } catch {
  }
  if ($FallbackVersion) {
    return $FallbackVersion
  }
  throw "Unable to resolve the latest release version. Specify -Version manually."
}

function Normalize-ReleaseVersion {
  param([string]$Version)
  $trimmed = Get-TrimmedText -Value $Version
  if (-not $trimmed) {
    return ""
  }
  $lowered = $trimmed.ToLowerInvariant()
  if ($lowered -eq "latest" -or $lowered -eq "vlatest") {
    return ""
  }
  if ($trimmed -match '^v?[0-9]+(\.[0-9]+){2}([.-][0-9A-Za-z][0-9A-Za-z.-]*)?$') {
    if (-not $trimmed.StartsWith("v")) {
      $trimmed = "v" + $trimmed
    }
    return $trimmed
  }
  throw "Version must look like v0.1.0 or v0.1.0-rc.1"
}

function Read-TrimmedFile {
  param([string]$Path)
  if (-not (Test-Path -LiteralPath $Path)) {
    return ""
  }
  return (Get-Content -LiteralPath $Path -Raw).Trim()
}

function Write-TrimmedFile {
  param(
    [string]$Path,
    [string]$Value
  )
  $parent = Split-Path -Parent $Path
  if ($parent -and -not (Test-Path -LiteralPath $parent)) {
    New-Item -ItemType Directory -Path $parent -Force | Out-Null
  }
  [IO.File]::WriteAllText($Path, $Value)
}

function Write-PrivateStateFile {
  param(
    [string]$Path,
    [string]$Value
  )
  Write-TrimmedFile -Path $Path -Value $Value
  Protect-SecretFile -Path $Path
}

function New-NodeId {
  $bytes = New-Object byte[] 6
  try {
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $rng.GetBytes($bytes)
  } finally {
    if ($rng) {
      $rng.Dispose()
    }
  }
  $hex = ($bytes | ForEach-Object { $_.ToString("x2") }) -join ""
  return ("node-" + $hex)
}

function Resolve-NodeId {
  param(
    [string]$ExplicitNodeId,
    [string]$NodeIdFile
  )
  $trimmed = Get-TrimmedText -Value $ExplicitNodeId
  if ($trimmed) {
    return $trimmed
  }
  $saved = Read-TrimmedFile -Path $NodeIdFile
  if ($saved) {
    return $saved
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

function New-AgentServiceBinPath {
  param(
    [string]$BinaryPath,
    [string]$ServerUrl,
    [string]$NodeIdFile,
    [string]$TokenFile,
    [switch]$DisableUpdate
  )
  $svcArgs = @(
    (ConvertTo-ServiceArgument -Value $BinaryPath)
    "--server-url"
    (ConvertTo-ServiceArgument -Value $ServerUrl)
    "--node-id-file"
    (ConvertTo-ServiceArgument -Value $NodeIdFile)
    "--agent-token-file"
    (ConvertTo-ServiceArgument -Value $TokenFile)
  )
  if ($DisableUpdate) {
    $svcArgs += "--disable-update"
  }
  return ($svcArgs -join ' ')
}

function Install-Agent {
  param(
    [string]$ServerUrl,
    [string]$AgentToken,
    [string]$NodeId,
    [switch]$DisableUpdate,
    [string]$Version
  )
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
    $previousStartMode = ConvertTo-ScStartMode -StartMode $previousService.StartMode -DelayedAutoStart $previousService.DelayedAutoStart
    $serviceConfigStartMode = $previousStartMode
    $deferDisabledStartMode = $previousStartMode -eq "disabled"
    if ($deferDisabledStartMode) {
      $serviceConfigStartMode = "demand"
    }
    if (-not $serviceConfigStartMode) {
      $serviceConfigStartMode = "auto"
    }
    Invoke-Sc -Arguments @("config", $serviceName, "binPath=", $serviceBinPath, "start=", $serviceConfigStartMode)
    Invoke-Sc -Arguments @("start", $serviceName)
    Wait-ServiceRunning -Name $serviceName
    if ($deferDisabledStartMode) {
      Invoke-Sc -Arguments @("config", $serviceName, "start=", $previousStartMode)
    }
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
      $previousStartMode = ConvertTo-ScStartMode -StartMode $previousService.StartMode -DelayedAutoStart $previousService.DelayedAutoStart
      $deferDisabledStartMode = $previousService.Running -and $previousStartMode -eq "disabled"
      $restoreServiceArgs = @("config", $serviceName, "binPath=", $previousService.PathName)
      if ($deferDisabledStartMode) {
        $restoreServiceArgs += @("start=", "demand")
      } elseif ($previousStartMode) {
        $restoreServiceArgs += @("start=", $previousStartMode)
      }
      Invoke-Sc -Arguments $restoreServiceArgs
      if ($previousService.Running) {
        try {
          Invoke-Sc -Arguments @("start", $serviceName)
          Wait-ServiceRunning -Name $serviceName
        } finally {
          if ($deferDisabledStartMode) {
            Invoke-Sc -Arguments @("config", $serviceName, "start=", $previousStartMode)
          }
        }
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
}

function Uninstall-Agent {
$serviceName = "CyberMonitorAgent"
$installDir = Get-InstallDir

if (Get-Service -Name $serviceName -ErrorAction SilentlyContinue) {
  try {
    Stop-Service -Name $serviceName -Force
  } catch {
  }
  Invoke-Sc -Arguments @("delete", $serviceName)
  Wait-ServiceDeleted -Name $serviceName
}

if (Test-Path -LiteralPath $installDir) {
  Assert-NotReparsePath -Path $installDir
  $agentFiles = @(
    "cyber-monitor-agent.exe",
    ".cybermonitor-agent-token",
    ".cybermonitor-node-id"
  )
  foreach ($fileName in $agentFiles) {
    $filePath = Join-Path $installDir $fileName
    if (Test-Path -LiteralPath $filePath) {
      Assert-NotReparsePath -Path $filePath
      Remove-Item -LiteralPath $filePath -Force
    }
  }
  $remaining = Get-ChildItem -LiteralPath $installDir -Force -ErrorAction SilentlyContinue
  if (-not $remaining) {
    Assert-NotReparsePath -Path $installDir
    Remove-Item -LiteralPath $installDir -Force
  }
}

Write-Host "Service removed: $serviceName"
}

function New-ServerServiceBinPath {
  param(
    [string]$BinaryPath,
    [string]$Listen,
    [string]$DataDir,
    [string]$AdminPass
  )
  $svcArgs = @(
    (ConvertTo-ServiceArgument -Value $BinaryPath)
    "-listen"
    (ConvertTo-ServiceArgument -Value $Listen)
    "-data-dir"
    (ConvertTo-ServiceArgument -Value $DataDir)
  )
  if ($AdminPass) {
    $svcArgs += @("-admin-pass", (ConvertTo-ServiceArgument -Value $AdminPass))
  }
  return ($svcArgs -join ' ')
}

function Wait-ServerStateFile {
  param(
    [string]$DataDir,
    [int]$TimeoutSeconds = 30
  )
  $stateFile = Join-Path $DataDir "state.json"
  $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
  do {
    if (Test-Path -LiteralPath $stateFile) {
      return
    }
    Start-Sleep -Seconds 1
  } while ((Get-Date) -lt $deadline)
  Write-Host ("Warning: timed out waiting for {0}; continuing." -f $stateFile)
}

function Read-ServerAdminInfo {
  param([string]$DataDir)
  $stateFile = Join-Path $DataDir "state.json"
  if (-not (Test-Path -LiteralPath $stateFile)) {
    return $null
  }
  $raw = Get-Content -LiteralPath $stateFile -Raw
  $adminPath = ""
  $adminUser = ""
  if ($raw -match '"admin_path"\s*:\s*"([^"]+)"') { $adminPath = $Matches[1] }
  if ($raw -match '"admin_user"\s*:\s*"([^"]+)"') { $adminUser = $Matches[1] }
  return [pscustomobject]@{ AdminPath = $adminPath; AdminUser = $adminUser }
}

function New-RandomPassword {
  $bytes = New-Object byte[] 18
  try {
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $rng.GetBytes($bytes)
  } finally {
    if ($rng) { $rng.Dispose() }
  }
  $password = [Convert]::ToBase64String($bytes).Replace("+", "-").Replace("/", "_")
  return $password.Substring(0, 24)
}

function Install-Server {
  param(
    [string]$Listen,
    [string]$DataDir,
    [string]$AdminPass,
    [string]$Version
  )
  $repo = "crazy0x70/CyberMonitor"
  $installDir = Get-InstallDir
  $binary = Join-Path $installDir "cyber-monitor-server.exe"
  $serviceName = "CyberMonitorServer"
  Assert-NotReparsePath -Path $installDir -AllowMissingLeaf
  Assert-NotReparsePath -Path $binary -AllowMissingLeaf
  if (-not $Listen) {
    $Listen = ":25012"
  }
  if (-not $DataDir) {
    $DataDir = Join-Path $installDir "data"
  }
  $arch = Get-Arch
  # Release only ships the amd64 server build for Windows; ARM64 hosts run it via emulation.
  if ($arch -eq "arm64") {
    Write-Host "Windows ARM64 detected: installing the amd64 server build (runs via x64 emulation)."
    $arch = "amd64"
  }
  $resolvedVersion = Get-LatestVersion -Repo $repo -FallbackVersion $Version
  New-Item -ItemType Directory -Path $DataDir -Force | Out-Null
  $generatedPassword = ""
  if (-not (Test-Path -LiteralPath (Join-Path $DataDir "state.json"))) {
    if ($AdminPass) {
      $generatedPassword = $AdminPass
    } else {
      $generatedPassword = New-RandomPassword
    }
  }

  $assetName = "cyber-monitor-server-windows-$arch.exe"
  $url = "https://github.com/$repo/releases/download/$resolvedVersion/$assetName"
  New-Item -ItemType Directory -Path $installDir -Force | Out-Null
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

  $hadExistingBinary = Test-Path -LiteralPath $binary
  $backupBinary = $null
  $previousService = $null
  $serviceCreated = $false
  $binaryReplaced = $false
  try {
    $previousService = Get-ServiceSnapshot -Name $serviceName
    if ($previousService.Exists) {
      Stop-ServiceIfExists -Name $serviceName
    }
    if ($hadExistingBinary) {
      $backupBinary = Join-Path $installDir (".cyber-monitor-server." + [guid]::NewGuid().ToString("N") + ".bak")
      Move-Item -LiteralPath $binary -Destination $backupBinary -Force
    }
    Move-Item -LiteralPath $tmpBinary -Destination $binary -Force
    $binaryReplaced = $true

    $serviceBinPath = New-ServerServiceBinPath -BinaryPath $binary -Listen $Listen -DataDir $DataDir -AdminPass $generatedPassword
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

    if ($generatedPassword) {
      # First boot persists state.json; rebuild the service without the plaintext password.
      Wait-ServerStateFile -DataDir $DataDir
      $cleanBinPath = New-ServerServiceBinPath -BinaryPath $binary -Listen $Listen -DataDir $DataDir
      Invoke-Sc -Arguments @("config", $serviceName, "binPath=", $cleanBinPath)
      Invoke-Sc -Arguments @("restart", $serviceName)
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
      }
      if ($backupBinary -and (Test-Path -LiteralPath $backupBinary)) {
        Assert-NotReparsePath -Path $binary
        Assert-NotReparsePath -Path $backupBinary
        Remove-Item -LiteralPath $binary -Force -ErrorAction SilentlyContinue
        Move-Item -LiteralPath $backupBinary -Destination $binary -Force
      } elseif ($binaryReplaced -and -not $hadExistingBinary) {
        Assert-NotReparsePath -Path $binary
        Remove-Item -LiteralPath $binary -Force -ErrorAction SilentlyContinue
      }
      if ($previousService.Exists -and $previousService.PathName) {
        Invoke-Sc -Arguments @("config", $serviceName, "binPath=", $previousService.PathName, "start=", "auto")
        if ($previousService.Running) {
          Invoke-Sc -Arguments @("start", $serviceName)
        }
      }
    } catch {
      Write-Host ("Rollback failed: {0}" -f $_.Exception.Message)
    }
    throw $installError
  } finally {
    if ($tmpBinary -and (Test-Path -LiteralPath $tmpBinary)) {
      Assert-NotReparsePath -Path $tmpBinary
      Remove-Item -LiteralPath $tmpBinary -Force -ErrorAction SilentlyContinue
    }
    if ($backupBinary -and (Test-Path -LiteralPath $backupBinary)) {
      Assert-NotReparsePath -Path $backupBinary
      Remove-Item -LiteralPath $backupBinary -Force -ErrorAction SilentlyContinue
    }
  }

  Write-Host "Service installed: $serviceName"
  $adminInfo = Read-ServerAdminInfo -DataDir $DataDir
  if ($adminInfo -and $adminInfo.AdminPath) {
    Write-Host ("Admin path: /{0}" -f $adminInfo.AdminPath.TrimStart('/'))
    Write-Host ("Admin user: {0}" -f $adminInfo.AdminUser)
  }
  if ($generatedPassword) {
    Write-Host ("Initial admin password: {0}" -f $generatedPassword)
  } else {
    Write-Host "Initial admin password: unchanged (existing state.json found)."
  }
}

function Uninstall-Server {
  param([switch]$KeepData)
  $serviceName = "CyberMonitorServer"
  $installDir = Get-InstallDir
  Remove-ServiceIfExists -Name $serviceName
  $binary = Join-Path $installDir "cyber-monitor-server.exe"
  if (Test-Path -LiteralPath $binary) {
    Assert-NotReparsePath -Path $binary
    Remove-Item -LiteralPath $binary -Force
  }
  if ($KeepData) {
    Write-Host "Data directory kept."
  } else {
    $dataDir = Join-Path $installDir "data"
    if (Test-Path -LiteralPath $dataDir) {
      Assert-NotReparsePath -Path $dataDir
      Remove-Item -LiteralPath $dataDir -Recurse -Force
    }
  }
  $remaining = Get-ChildItem -LiteralPath $installDir -Force -ErrorAction SilentlyContinue
  if (-not $remaining) {
    Assert-NotReparsePath -Path $installDir
    Remove-Item -LiteralPath $installDir -Force
  }
  Write-Host "Service removed: $serviceName"
}

function Show-Usage {
  Write-Host "Usage:"
  Write-Host "  .\one-click.ps1                                    # interactive menu"
  Write-Host "  .\one-click.ps1 install-server  [-Listen :25012] [-DataDir DIR] [-AdminPass P] [-Version V]"
  Write-Host "  .\one-click.ps1 install-agent   -ServerUrl URL -AgentToken T [-NodeId N] [-DisableUpdate] [-Version V]"
  Write-Host "  .\one-click.ps1 uninstall-server [-KeepData]"
  Write-Host "  .\one-click.ps1 uninstall-agent"
}

function Invoke-Menu {
  :loop while ($true) {
    Write-Host ""
    Write-Host "CyberMonitor one-click script (Windows)"
    Write-Host "1) Install server"
    Write-Host "2) Install agent"
    Write-Host "3) Uninstall server"
    Write-Host "4) Uninstall agent"
    Write-Host "0) Exit"
    $choice = Read-Host "Select"
    switch ($choice) {
      "1" {
        $listen = Read-Host "Listen address (default :25012)"
        $dataDir = Read-Host "Data directory (default ProgramData\CyberMonitor\data)"
        $version = Read-Host "Version (default latest)"
        Install-Server -Listen $listen -DataDir $dataDir -Version $version
      }
      "2" {
        $serverUrl = Read-Host "Server URL (e.g. http://1.2.3.4:25012)"
        $token = Read-Host "Agent Token"
        $nodeId = Read-Host "Node ID (empty = reuse or auto-generate)"
        $disableAnswer = Read-Host "Disable server-side remote update? [y/N]"
        $version = Read-Host "Version (default latest)"
        $disable = $disableAnswer -match '^[Yy]'
        Invoke-InstallAgent -ServerUrl $serverUrl -Token $token -NodeId $nodeId -Disable:$disable -Version $version
      }
      "3" {
        Uninstall-Server
      }
      "4" {
        Uninstall-Agent
      }
      "0" {
        break :loop
      }
      default {
        Write-Host "Invalid choice."
      }
    }
  }
}

function Invoke-InstallAgent {
  param(
    [string]$ServerUrl,
    [string]$Token,
    [string]$NodeId,
    [switch]$Disable,
    [string]$Version
  )
  if (-not $ServerUrl) {
    throw "ServerUrl is required."
  }
  if (-not $Token) {
    throw "AgentToken is required."
  }
  Install-Agent -ServerUrl $ServerUrl -AgentToken $Token -NodeId $NodeId -DisableUpdate:$Disable -Version $Version
}

Assert-Admin
Ensure-Tls12

switch ($Command) {
  "" {
    Invoke-Menu
  }
  "install" {
    Invoke-Menu
  }
  "install-server" {
    Install-Server -Listen $Listen -DataDir $DataDir -AdminPass $AdminPass -Version $Version
  }
  "install-agent" {
    Invoke-InstallAgent -ServerUrl $ServerUrl -Token $AgentToken -NodeId $NodeId -Disable:$DisableUpdate -Version $Version
  }
  "uninstall-server" {
    Uninstall-Server -KeepData:$KeepData
  }
  "uninstall-agent" {
    Uninstall-Agent
  }
  default {
    Show-Usage
    throw ("Unknown command: {0}" -f $Command)
  }
}
