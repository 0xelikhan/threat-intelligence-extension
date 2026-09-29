#Requires -Version 5.1
[CmdletBinding()]
param(
  [string]$Path = (Join-Path $env:LOCALAPPDATA 'ThreatIntelligence')
)
$ErrorActionPreference = 'Stop'

Write-Host ""
Write-Host "  Threat Intelligence Uninstaller" -ForegroundColor Cyan
Write-Host ""

if (Test-Path $Path) {
  Write-Host "  Removing $Path" -ForegroundColor Gray
  Remove-Item -Recurse -Force $Path
  Write-Host "  [OK] Files removed" -ForegroundColor Green
} else {
  Write-Host "  Nothing at $Path" -ForegroundColor Yellow
}

$shortcut = Join-Path ([Environment]::GetFolderPath('Desktop')) 'Update Threat Intelligence.lnk'
if (Test-Path $shortcut) {
  Remove-Item $shortcut -Force
  Write-Host "  [OK] Desktop shortcut removed" -ForegroundColor Green
}

Write-Host ""
Write-Host "  Also remove the extension from edge://extensions." -ForegroundColor Gray
Write-Host ""
