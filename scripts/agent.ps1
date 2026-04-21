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

function Remove-ServiceIfExists {
  param(
    [string]$Name
  )
  if (-not (Get-Service -Name $Name -ErrorAction SilentlyContinue)) {
    return
  }
  Stop-Service -Name $Name -Force
  Invoke-Sc -Arguments @("delete", $Name)
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
    default { return "amd64" }
  }
}

function Get-LatestVersion {
  param(
    [string]$Repo,
    [string]$FallbackVersion
  )
  if ($FallbackVersion) {
    return $FallbackVersion
  }
  try {
    $release = Invoke-WebCall -Kind RestMethod -Uri "https://api.github.com/repos/$Repo/releases/latest"
    if ($release -and $release.tag_name) {
      return $release.tag_name
    }
  } catch {
  }
  try {
    $resp = Invoke-WebCall -Kind WebRequest -Uri "https://github.com/$Repo/releases/latest"
    $final = $resp.BaseResponse.ResponseUri.AbsoluteUri
    $tag = $final.Split('/')[-1]
    if ($tag -and $tag -ne "latest") {
      return $tag
    }
  } catch {
  }
  Write-Host "Unable to fetch latest version. Use -Version to specify."
  exit 1
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
  $trimmedPath = Get-TrimmedText -Value $Path
  $trimmedValue = Get-TrimmedText -Value $Value
  if (-not $trimmedPath) {
    throw "file path required"
  }
  if (-not $trimmedValue) {
    throw "file value required"
  }
  $parent = Split-Path -Parent $trimmedPath
  if ($parent) {
    New-Item -ItemType Directory -Path $parent -Force | Out-Null
  }
  [System.IO.File]::WriteAllText($trimmedPath, $trimmedValue + [Environment]::NewLine)
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
    Write-Host "Agent registration succeeded but the server did not return a dedicated token."
    exit 1
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
$arch = Get-Arch
$resolvedVersion = Get-LatestVersion -Repo $repo -FallbackVersion $Version
New-Item -ItemType Directory -Path $installDir -Force | Out-Null
$NodeId = Resolve-NodeId -ExplicitNodeId $NodeId -NodeIdFile $nodeIDFile
$nodeToken = Register-Agent -RegisterServerUrl $ServerUrl -BootstrapToken $AgentToken -CurrentNodeId $NodeId

$url = "https://github.com/$repo/releases/download/$resolvedVersion/cyber-monitor-agent-windows-$arch.exe"
Invoke-WebCall -Kind WebRequest -Uri $url -OutFile $binary
Write-TrimmedFile -Path $nodeIDFile -Value $NodeId
Write-TrimmedFile -Path $tokenFile -Value $nodeToken

$serviceName = "CyberMonitorAgent"
$serviceArgs = @(
  "--server-url"
  ('"{0}"' -f $ServerUrl)
  "--node-id-file"
  ('"{0}"' -f $nodeIDFile)
  "--agent-token-file"
  ('"{0}"' -f $tokenFile)
)
if ($DisableUpdate) {
  $serviceArgs += "--disable-update"
}
$serviceBinPath = ('"{0}" {1}' -f $binary, ($serviceArgs -join ' '))

Remove-ServiceIfExists -Name $serviceName
Invoke-Sc -Arguments @("create", $serviceName, "binPath=", $serviceBinPath, "start=", "auto")
Invoke-Sc -Arguments @("failure", $serviceName, "reset=", "0", "actions=", "restart/5000/restart/5000/restart/5000")
Invoke-Sc -Arguments @("failureflag", $serviceName, "1")
Invoke-Sc -Arguments @("start", $serviceName)
Wait-ServiceRunning -Name $serviceName

Write-Host "Service installed: $serviceName"
Write-Host "Node ID: $NodeId"
