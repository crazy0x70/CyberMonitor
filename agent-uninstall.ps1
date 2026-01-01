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
  Remove-Item -Path $installDir -Recurse -Force
}

Write-Host "Service removed: $serviceName"
