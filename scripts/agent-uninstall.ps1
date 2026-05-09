# Keep this script ASCII-only so Windows PowerShell 5.1 can parse the raw GitHub download reliably.
param()

$ErrorActionPreference = "Stop"

function Assert-Admin {
  $current = [Security.Principal.WindowsIdentity]::GetCurrent()
  $principal = New-Object Security.Principal.WindowsPrincipal($current)
  if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "Please run PowerShell as Administrator."
    exit 1
  }
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

Assert-Admin

$serviceName = "CyberMonitorAgent"
$installDir = Get-InstallDir

if (Get-Service -Name $serviceName -ErrorAction SilentlyContinue) {
  try {
    Stop-Service -Name $serviceName -Force
  } catch {
  }
  sc.exe delete $serviceName | Out-Null
}

if (Test-Path $installDir) {
  $agentFiles = @(
    "cyber-monitor-agent.exe",
    ".cybermonitor-agent-token",
    ".cybermonitor-node-id"
  )
  foreach ($fileName in $agentFiles) {
    $filePath = Join-Path $installDir $fileName
    if (Test-Path -LiteralPath $filePath) {
      Remove-Item -LiteralPath $filePath -Force
    }
  }
  $remaining = Get-ChildItem -LiteralPath $installDir -Force -ErrorAction SilentlyContinue
  if (-not $remaining) {
    Remove-Item -LiteralPath $installDir -Force
  }
}

Write-Host "Service removed: $serviceName"
