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

function Invoke-Sc {
  param(
    [string[]]$Arguments
  )
  & sc.exe @Arguments | Out-Null
  if ($LASTEXITCODE -ne 0) {
    throw ('sc.exe failed: {0}' -f ($Arguments -join ' '))
  }
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

Assert-Admin

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
