# CyberMonitor one-click script for Windows (server + agent). Run as Administrator.
#
#   .\one-click.ps1                                     interactive menu
#   .\one-click.ps1 install-server   [-Listen :25012] [-DataDir DIR] [-Version V]
#   .\one-click.ps1 install-agent    -ServerUrl URL -AgentToken TOKEN [-NodeId ID] [-DisableUpdate] [-Version V]
#   .\one-click.ps1 upgrade-server   [-Version V]
#   .\one-click.ps1 upgrade-agent    [-Version V]
#   .\one-click.ps1 uninstall-server [-KeepData]
#   .\one-click.ps1 uninstall-agent
#
# Keep this file ASCII-only so Windows PowerShell 5.1 parses the raw download correctly.
param(
  [string]$Command = "",
  [string]$ServerUrl = "",
  [string]$AgentToken = "",
  [string]$NodeId = "",
  [switch]$DisableUpdate,
  [string]$Listen = "",
  [string]$DataDir = "",
  [switch]$KeepData,
  [string]$Version = ""
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$Repo = "crazy0x70/CyberMonitor"
$InstallDir = Join-Path $env:ProgramData "CyberMonitor"
$ServerService = "CyberMonitorServer"
$AgentService = "CyberMonitorAgent"
$NodeIdFile = Join-Path $InstallDir ".cybermonitor-node-id"
$TokenFile = Join-Path $InstallDir ".cybermonitor-agent-token"

function Get-BinaryPath([string]$Type) {
  return Join-Path $InstallDir ("cyber-monitor-{0}.exe" -f $Type)
}

function Resolve-Version([string]$Value) {
  $v = "$Value".Trim()
  if (-not $v -or $v -eq "latest") {
    $v = (Invoke-RestMethod -UseBasicParsing "https://api.github.com/repos/$Repo/releases/latest").tag_name
    if (-not $v) { throw "Unable to resolve the latest release; pass -Version." }
  }
  if (-not $v.StartsWith("v")) { $v = "v" + $v }
  return $v
}

# Download, verify and place the binary. The service must already be stopped.
function Install-Binary([string]$Type, [string]$Ver) {
  $arch = "amd64"
  $cpu = $env:PROCESSOR_ARCHITEW6432
  if (-not $cpu) { $cpu = $env:PROCESSOR_ARCHITECTURE }
  # Releases ship an arm64 build for the agent only; the server runs under x64 emulation.
  if ($cpu -eq "ARM64" -and $Type -eq "agent") { $arch = "arm64" }
  $asset = "cyber-monitor-$Type-windows-$arch.exe"
  $base = "https://github.com/$Repo/releases/download/$Ver"
  New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
  $tmp = Join-Path $InstallDir (".download-" + [guid]::NewGuid().ToString("N"))
  try {
    Write-Host "Downloading $asset $Ver ..."
    Invoke-WebRequest -UseBasicParsing "$base/$asset" -OutFile $tmp
    $sums = (Invoke-WebRequest -UseBasicParsing "$base/SHA256SUMS").Content
    if ($sums -is [byte[]]) { $sums = [Text.Encoding]::ASCII.GetString($sums) }
    $expected = ""
    foreach ($line in ($sums -split "`n")) {
      if ($line -match '^([A-Fa-f0-9]{64})\s+\*?(\S+)') {
        if ($Matches[2] -eq $asset) { $expected = $Matches[1].ToLowerInvariant() }
      }
    }
    $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $tmp).Hash.ToLowerInvariant()
    if (-not $expected -or $actual -ne $expected) { throw "Checksum mismatch: $asset" }
    Move-Item -LiteralPath $tmp -Destination (Get-BinaryPath $Type) -Force
  } finally {
    Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
  }
}

function Quote([string]$Value) {
  return '"' + $Value.TrimEnd('\') + '"'
}

function Stop-IfRunning([string]$Name) {
  if (Get-Service -Name $Name -ErrorAction SilentlyContinue) {
    Stop-Service -Name $Name -Force -ErrorAction SilentlyContinue
    (Get-Service -Name $Name).WaitForStatus("Stopped", [TimeSpan]::FromSeconds(30))
  }
}

# Create the service, or update its command line, then start it.
function Set-ServiceCommand([string]$Name, [string]$Display, [string]$CommandLine) {
  if (Get-Service -Name $Name -ErrorAction SilentlyContinue) {
    Stop-IfRunning $Name
    $svc = Get-CimInstance -ClassName Win32_Service -Filter "Name='$Name'"
    $result = Invoke-CimMethod -InputObject $svc -MethodName Change -Arguments @{ PathName = $CommandLine }
    if ($result.ReturnValue -ne 0) { throw "Failed to update service $Name (code $($result.ReturnValue))" }
  } else {
    New-Service -Name $Name -DisplayName $Display -BinaryPathName $CommandLine -StartupType Automatic | Out-Null
    & sc.exe failure $Name reset= 86400 actions= restart/5000/restart/5000/restart/5000 | Out-Null
  }
  Start-Service -Name $Name
}

function Get-ServiceCommand([string]$Name) {
  $svc = Get-CimInstance -ClassName Win32_Service -Filter "Name='$Name'"
  if ($svc) { return [string]$svc.PathName }
  return ""
}

function Remove-ServiceIfExists([string]$Name) {
  if (Get-Service -Name $Name -ErrorAction SilentlyContinue) {
    Stop-IfRunning $Name
    & sc.exe delete $Name | Out-Null
  }
}

function Remove-InstallDirIfEmpty {
  if ((Test-Path $InstallDir) -and -not (Get-ChildItem -LiteralPath $InstallDir -Force)) {
    Remove-Item -LiteralPath $InstallDir -Force
  }
}

# ---------- Server ----------

function Install-Server([string]$ListenAddr, [string]$Dir, [string]$Ver) {
  # Reinstall keeps the existing listen address and data directory.
  $existing = Get-ServiceCommand $ServerService
  if (-not $ListenAddr -and $existing -match '-listen "([^"]*)"') { $ListenAddr = $Matches[1] }
  if (-not $Dir -and $existing -match '-data-dir "([^"]*)"') { $Dir = $Matches[1] }
  if (-not $ListenAddr) { $ListenAddr = ":25012" }
  if (-not $Dir) { $Dir = Join-Path $InstallDir "data" }
  $Ver = Resolve-Version $Ver
  $stateFile = Join-Path $Dir "state.json"
  $password = ""
  if (-not (Test-Path $stateFile)) {
    $password = [guid]::NewGuid().ToString("N").Substring(0, 24)
  }
  New-Item -ItemType Directory -Path $Dir -Force | Out-Null
  Stop-IfRunning $ServerService
  Install-Binary "server" $Ver

  $cmd = "{0} -listen {1} -data-dir {2}" -f (Quote (Get-BinaryPath "server")), (Quote $ListenAddr), (Quote $Dir)
  if ($password) {
    Set-ServiceCommand $ServerService "CyberMonitor Server" ("{0} -admin-pass {1}" -f $cmd, (Quote $password))
    # After the first start writes state.json, drop the plain-text password from the service.
    for ($i = 0; $i -lt 30 -and -not (Test-Path $stateFile); $i++) { Start-Sleep -Seconds 1 }
  }
  Set-ServiceCommand $ServerService "CyberMonitor Server" $cmd

  $port = $ListenAddr.Split(":")[-1]
  $raw = ""
  if (Test-Path $stateFile) { $raw = Get-Content -LiteralPath $stateFile -Raw }
  Write-Host ""
  Write-Host "CyberMonitor Server $Ver installed and started"
  Write-Host "  Status page: http://<server-ip>:$port/"
  if ($raw -match '"admin_path"\s*:\s*"([^"]+)"') { Write-Host ("  Admin:       http://<server-ip>:{0}/{1}" -f $port, $Matches[1].TrimStart("/")) }
  if ($raw -match '"admin_user"\s*:\s*"([^"]+)"') { Write-Host ("  Username:    {0}" -f $Matches[1]) }
  if ($password) { Write-Host "  Password:    $password (shown once; change it after signing in)" }
  Write-Host "  Data dir:    $Dir"
}

function Uninstall-Server([bool]$Keep) {
  $dataDir = Join-Path $InstallDir "data"
  $existing = Get-ServiceCommand $ServerService
  if ($existing -match '-data-dir "([^"]*)"') { $dataDir = $Matches[1] }
  Remove-ServiceIfExists $ServerService
  Remove-Item -LiteralPath (Get-BinaryPath "server") -Force -ErrorAction SilentlyContinue
  if ($Keep) {
    Write-Host "Data directory kept: $dataDir"
  } elseif ($dataDir -eq (Join-Path $InstallDir "data")) {
    Remove-Item -LiteralPath $dataDir -Recurse -Force -ErrorAction SilentlyContinue
  } else {
    Write-Host "Custom data directory not removed: $dataDir"
  }
  Remove-InstallDirIfEmpty
  Write-Host "CyberMonitor Server uninstalled"
}

# ---------- Agent ----------

function Install-Agent([string]$Url, [string]$Token, [string]$Id, [bool]$NoUpdate, [string]$Ver) {
  $Url = "$Url".Trim().TrimEnd("/")
  if (-not $Url) { throw "-ServerUrl is required." }
  if (-not $Token) { throw "-AgentToken is required." }
  if (-not $Id -and (Test-Path $NodeIdFile)) { $Id = (Get-Content -LiteralPath $NodeIdFile -Raw).Trim() }
  if (-not $Id) { $Id = "node-" + [guid]::NewGuid().ToString("N").Substring(0, 16) }
  $Ver = Resolve-Version $Ver

  # Exchange the shared agent token for a token dedicated to this node.
  $resp = Invoke-RestMethod -UseBasicParsing -Method Post -Headers @{ "X-AGENT-TOKEN" = $Token } `
    ("{0}/api/v1/agent/register?node_id={1}" -f $Url, [Uri]::EscapeDataString($Id))
  if (-not $resp.agent_token) { throw "Registration failed: the server returned no node token." }

  Stop-IfRunning $AgentService
  Install-Binary "agent" $Ver
  [IO.File]::WriteAllText($NodeIdFile, $Id)
  [IO.File]::WriteAllText($TokenFile, [string]$resp.agent_token)

  $cmd = "{0} --server-url {1} --node-id-file {2} --agent-token-file {3}" -f `
    (Quote (Get-BinaryPath "agent")), (Quote $Url), (Quote $NodeIdFile), (Quote $TokenFile)
  if ($NoUpdate) { $cmd += " --disable-update" }
  Set-ServiceCommand $AgentService "CyberMonitor Agent" $cmd
  Write-Host ""
  Write-Host "CyberMonitor Agent $Ver installed and started"
  Write-Host "  Node ID: $Id"
}

function Uninstall-Agent {
  Remove-ServiceIfExists $AgentService
  foreach ($f in @((Get-BinaryPath "agent"), $NodeIdFile, $TokenFile)) {
    Remove-Item -LiteralPath $f -Force -ErrorAction SilentlyContinue
  }
  Remove-InstallDirIfEmpty
  Write-Host "CyberMonitor Agent uninstalled"
}

# ---------- Upgrade ----------

function Upgrade-Component([string]$Type, [string]$Name, [string]$Ver) {
  if (-not (Test-Path (Get-BinaryPath $Type))) { throw "CyberMonitor $Type is not installed." }
  $Ver = Resolve-Version $Ver
  Stop-IfRunning $Name
  Install-Binary $Type $Ver
  Start-Service -Name $Name
  Write-Host "CyberMonitor $Type upgraded to $Ver"
}

# ---------- Entry ----------

function Show-Menu {
  Write-Host "CyberMonitor one-click script"
  Write-Host "  1) Install server     2) Install agent"
  Write-Host "  3) Upgrade server     4) Upgrade agent"
  Write-Host "  5) Uninstall server   6) Uninstall agent"
  Write-Host "  0) Exit"
  switch (Read-Host "Select") {
    "1" { Install-Server (Read-Host "Listen address [:25012]") (Read-Host "Data directory [$InstallDir\data]") "" }
    "2" { Install-Agent (Read-Host "Server URL (e.g. http://1.2.3.4:25012)") (Read-Host "Agent token") "" $false "" }
    "3" { Upgrade-Component "server" $ServerService "" }
    "4" { Upgrade-Component "agent" $AgentService "" }
    "5" { Uninstall-Server ((Read-Host "Keep data directory? [y/N]") -match '^[Yy]') }
    "6" { Uninstall-Agent }
    default { }
  }
}

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  throw "Run this script as Administrator."
}

switch ($Command) {
  "" { Show-Menu }
  "install-server" { Install-Server $Listen $DataDir $Version }
  "install-agent" { Install-Agent $ServerUrl $AgentToken $NodeId $DisableUpdate.IsPresent $Version }
  "upgrade-server" { Upgrade-Component "server" $ServerService $Version }
  "upgrade-agent" { Upgrade-Component "agent" $AgentService $Version }
  "uninstall-server" { Uninstall-Server $KeepData.IsPresent }
  "uninstall-agent" { Uninstall-Agent }
  default { Get-Content -LiteralPath $PSCommandPath -TotalCount 9 | Select-Object -Skip 2 | ForEach-Object { $_ -replace '^# ?', '' } }
}
