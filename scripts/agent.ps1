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

function Invoke-WebRequestCompat {
  param(
    [string]$Uri,
    [string]$OutFile = ""
  )
  $params = @{
    Uri     = $Uri
    Headers = @{ "User-Agent" = "CyberMonitor" }
  }
  if ($OutFile) {
    $params.OutFile = $OutFile
  }
  if ($PSVersionTable.PSVersion.Major -lt 6) {
    $params.UseBasicParsing = $true
  }
  return Invoke-WebRequest @params
}

function Invoke-RestMethodCompat {
  param(
    [string]$Uri
  )
  $params = @{
    Uri     = $Uri
    Headers = @{ "User-Agent" = "CyberMonitor" }
  }
  if ($PSVersionTable.PSVersion.Major -lt 6) {
    $params.UseBasicParsing = $true
  }
  return Invoke-RestMethod @params
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
    $release = Invoke-RestMethodCompat "https://api.github.com/repos/$Repo/releases/latest"
    if ($release -and $release.tag_name) {
      return $release.tag_name
    }
  } catch {
  }
  try {
    $resp = Invoke-WebRequestCompat "https://github.com/$Repo/releases/latest"
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

function New-NodeId {
  return "node-" + ([guid]::NewGuid().ToString("N").Substring(0, 16))
}

function Register-Agent {
  param(
    [string]$RegisterServerUrl,
    [string]$BootstrapToken,
    [string]$CurrentNodeId
  )
  $registerNodeId = [Uri]::EscapeDataString($CurrentNodeId)
  $uri = "{0}/api/v1/agent/register?node_id={1}" -f $RegisterServerUrl.TrimEnd('/'), $registerNodeId
  $response = Invoke-RestMethod -Method Post -Uri $uri -Headers @{ "X-AGENT-TOKEN" = $BootstrapToken }
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
$arch = Get-Arch
$resolvedVersion = Get-LatestVersion -Repo $repo -FallbackVersion $Version
if (-not $NodeId) {
  $NodeId = New-NodeId
}
$nodeToken = Register-Agent -RegisterServerUrl $ServerUrl -BootstrapToken $AgentToken -CurrentNodeId $NodeId

New-Item -ItemType Directory -Path $installDir -Force | Out-Null
$url = "https://github.com/$repo/releases/download/$resolvedVersion/cyber-monitor-agent-windows-$arch.exe"
Invoke-WebRequestCompat -Uri $url -OutFile $binary
[System.IO.File]::WriteAllText((Join-Path $installDir ".cybermonitor-agent-token"), $nodeToken + [Environment]::NewLine)

$serviceName = "CyberMonitorAgent"
$serviceArgs = @(
  "--server-url"
  ('"{0}"' -f $ServerUrl)
  "--node-id"
  ('"{0}"' -f $NodeId)
  "--agent-token"
  ('"{0}"' -f $nodeToken)
)
if ($DisableUpdate) {
  $serviceArgs += "--disable-update"
}
$serviceBinPath = ('"{0}" {1}' -f $binary, ($serviceArgs -join ' '))

if (Get-Service -Name $serviceName -ErrorAction SilentlyContinue) {
  Stop-Service -Name $serviceName -Force
  sc.exe delete $serviceName | Out-Null
}

sc.exe create $serviceName binPath= $serviceBinPath start= auto | Out-Null
sc.exe failure $serviceName reset= 0 actions= restart/5000/restart/5000/restart/5000 | Out-Null
sc.exe failureflag $serviceName 1 | Out-Null
sc.exe start $serviceName | Out-Null

Write-Host "Service installed: $serviceName"
Write-Host "Node ID: $NodeId"
