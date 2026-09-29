#Requires -Version 5.1
<#
.SYNOPSIS
Installs or updates the Threat Intelligence Edge extension.

.DESCRIPTION
Copies the extension into %LOCALAPPDATA%\ThreatIntelligence, then guides the
analyst through a one-time Edge "Load unpacked" step. Subsequent runs pull
the latest from GitHub (if git is present) or copy the latest local source,
then Edge picks it up after clicking the reload icon in edge://extensions.

.PARAMETER Path
Override the install path. Default: %LOCALAPPDATA%\ThreatIntelligence

.PARAMETER Repo
Git repo URL used when files aren't already local. Default: the public repo URL.

.PARAMETER Quiet
Skip prompts and auto-launching Edge.
#>
[CmdletBinding()]
param(
  [string]$Path = (Join-Path $env:LOCALAPPDATA 'ThreatIntelligence'),
  [string]$Repo = 'https://github.com/0xelikhan/threat-intelligence-extension.git',
  [switch]$Quiet
)

$ErrorActionPreference = 'Stop'
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

# ─── Helpers ────────────────────────────────────────────────────────────────
function Write-Head($msg) {
  Write-Host ''
  Write-Host "  $msg" -ForegroundColor Cyan
  Write-Host ''
}
function Write-Ok($msg)   { Write-Host "  [OK] $msg" -ForegroundColor Green }
function Write-Warn2($msg){ Write-Host "  [!!] $msg" -ForegroundColor Yellow }
function Write-Info($msg) { Write-Host "  $msg" -ForegroundColor Gray }

function Copy-ExtensionFiles([string]$From, [string]$To) {
  if (-not (Test-Path $To)) {
    New-Item -ItemType Directory -Path $To -Force | Out-Null
  }
  $exclude = @('.git', 'node_modules', '.vscode', '.idea', 'test-page.html')
  Get-ChildItem -Path $From -Force | Where-Object {
    $exclude -notcontains $_.Name
  } | ForEach-Object {
    Copy-Item -Path $_.FullName -Destination $To -Recurse -Force
  }
}

function Get-EdgeExecutable {
  $candidates = @(
    "$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe",
    "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe",
    "$env:LOCALAPPDATA\Microsoft\Edge\Application\msedge.exe"
  )
  return $candidates | Where-Object { Test-Path $_ } | Select-Object -First 1
}

function Test-EdgeExtensionLoaded([string]$Path) {
  # Best-effort: scan all Edge profiles for a Preferences entry referencing this path
  $edgeUser = Join-Path $env:LOCALAPPDATA 'Microsoft\Edge\User Data'
  if (-not (Test-Path $edgeUser)) { return $false }
  $normalized = $Path.TrimEnd('\').ToLower()
  $prefsFiles = Get-ChildItem -Path $edgeUser -Recurse -Filter 'Preferences' -ErrorAction SilentlyContinue |
                Select-Object -First 20
  foreach ($p in $prefsFiles) {
    try {
      $content = (Get-Content $p.FullName -Raw -ErrorAction Stop).ToLower()
      if ($content.Contains($normalized.Replace('\', '\\')) -or $content.Contains($normalized.Replace('\', '/'))) {
        return $true
      }
    } catch {}
  }
  return $false
}

# ─── Header ─────────────────────────────────────────────────────────────────
try { Clear-Host } catch {}
Write-Host ""
Write-Host "  ================================================" -ForegroundColor DarkCyan
Write-Host "   Threat Intelligence Installer" -ForegroundColor White
Write-Host "  ================================================" -ForegroundColor DarkCyan

$hasGit = [bool](Get-Command git -ErrorAction SilentlyContinue)
$sourceIsExtension = Test-Path (Join-Path $scriptDir 'manifest.json')

# ─── Install / update files ─────────────────────────────────────────────────
Write-Head "1. Preparing install path"
Write-Info "Target: $Path"

if (Test-Path $Path) {
  $isRepo = Test-Path (Join-Path $Path '.git')
  if ($isRepo -and $hasGit) {
    Write-Info "Existing git checkout found. Pulling latest..."
    Push-Location $Path
    try {
      $out = git pull --ff-only 2>&1
      Write-Info ($out -join "`n")
      Write-Ok "Updated from git"
    } catch {
      Write-Warn2 "git pull failed: $_"
    } finally {
      Pop-Location
    }
  } elseif ($sourceIsExtension) {
    Write-Info "Refreshing files from local source: $scriptDir"
    Copy-ExtensionFiles -From $scriptDir -To $Path
    Write-Ok "Files updated"
  } else {
    Write-Warn2 "Install path exists but is not a git checkout, and no local source found."
    if (-not $Quiet) {
      $ans = Read-Host "  Reinstall by cloning from GitHub? (y/N)"
      if ($ans -match '^[Yy]') {
        Remove-Item -Recurse -Force $Path
      } else {
        Write-Warn2 "Aborting."
        exit 1
      }
    } else {
      Remove-Item -Recurse -Force $Path
    }
  }
}

if (-not (Test-Path $Path)) {
  if ($sourceIsExtension) {
    Write-Info "Copying from local source: $scriptDir"
    Copy-ExtensionFiles -From $scriptDir -To $Path
    Write-Ok "Files copied"
  } elseif ($hasGit) {
    Write-Info "Cloning from $Repo"
    git clone --depth 1 $Repo $Path 2>&1 | ForEach-Object { Write-Info $_ }
    if (-not (Test-Path (Join-Path $Path 'manifest.json'))) {
      Write-Warn2 "Clone did not produce manifest.json. Aborting."
      exit 1
    }
    Write-Ok "Cloned"
  } else {
    Write-Warn2 "No local source and git is not installed."
    Write-Warn2 "Install Git for Windows or run this script from the extension folder."
    exit 1
  }
}

# ─── Verify ────────────────────────────────────────────────────────────────
$manifestPath = Join-Path $Path 'manifest.json'
if (-not (Test-Path $manifestPath)) {
  Write-Warn2 "manifest.json missing at $Path. Install failed."
  exit 1
}
try {
  $manifest = Get-Content $manifestPath -Raw | ConvertFrom-Json
  Write-Ok "manifest.json OK, version $($manifest.version)"
} catch {
  Write-Warn2 "manifest.json invalid: $_"
  exit 1
}

# ─── Edge integration ──────────────────────────────────────────────────────
$Path | Set-Clipboard
Write-Ok "Install path copied to clipboard"

$loaded = Test-EdgeExtensionLoaded -Path $Path

Write-Head "2. Loading into Microsoft Edge"

if ($loaded) {
  Write-Ok "Extension already registered in an Edge profile"
  Write-Info "In edge://extensions, click the reload icon on 'Threat Intelligence' to pick up changes."
} else {
  Write-Info "One-time steps:"
  Write-Host ""
  Write-Host "     1) Edge will open to edge://extensions" -ForegroundColor White
  Write-Host "     2) Toggle 'Developer mode' on (bottom-left)" -ForegroundColor White
  Write-Host "     3) Click 'Load unpacked'" -ForegroundColor White
  Write-Host "     4) Paste the install path (already in your clipboard):" -ForegroundColor White
  Write-Host "        $Path" -ForegroundColor DarkCyan
  Write-Host "     5) Click 'Select Folder'" -ForegroundColor White
  Write-Host ""
}

if (-not $Quiet) {
  $edge = Get-EdgeExecutable
  if ($edge) {
    Start-Process -FilePath $edge -ArgumentList 'edge://extensions' | Out-Null
    Write-Ok "Edge opened"
  } else {
    Write-Warn2 "Could not locate msedge.exe. Open edge://extensions manually."
  }
}

# ─── Desktop shortcut for future updates ───────────────────────────────────
$shortcutPath = Join-Path ([Environment]::GetFolderPath('Desktop')) 'Update Threat Intelligence.lnk'
try {
  $shell = New-Object -ComObject WScript.Shell
  $sc = $shell.CreateShortcut($shortcutPath)
  $sc.TargetPath = 'powershell.exe'
  $sc.Arguments = "-ExecutionPolicy Bypass -File `"$Path\install.ps1`" -Quiet"
  $sc.WorkingDirectory = $Path
  $sc.IconLocation = 'powershell.exe,0'
  $sc.Description = 'Update Threat Intelligence extension'
  $sc.Save()
  Write-Ok "Desktop shortcut: Update Threat Intelligence"
} catch {
  Write-Warn2 "Could not create desktop shortcut: $_"
}

Write-Host ""
Write-Host "  ================================================" -ForegroundColor DarkCyan
Write-Host "   Done" -ForegroundColor White
Write-Host "  ================================================" -ForegroundColor DarkCyan
Write-Host ""
Write-Host "  Update: double-click 'Update Threat Intelligence' on Desktop." -ForegroundColor Gray
Write-Host "  Uninstall: run uninstall.ps1 from $Path" -ForegroundColor Gray
Write-Host ""
