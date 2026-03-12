# ClawGuard One-Click Installer for Windows
# Usage: irm https://raw.githubusercontent.com/jnMetaCode/clawguard/main/install.ps1 | iex

$ErrorActionPreference = "Stop"

Write-Host ""
Write-Host "==================================================" -ForegroundColor Cyan
Write-Host "  ClawGuard Security Plugin - One-Click Install" -ForegroundColor Cyan
Write-Host "==================================================" -ForegroundColor Cyan
Write-Host ""

# Check Node.js
Write-Host "Checking environment..." -ForegroundColor Blue
try {
    $nodeVer = & node -v 2>$null
    $major = [int]($nodeVer -replace 'v(\d+)\..*', '$1')
    if ($major -lt 18) {
        Write-Host "Node.js too old ($nodeVer). Need v18+. Download: https://nodejs.org" -ForegroundColor Red
        exit 1
    }
    Write-Host "Node.js $nodeVer" -ForegroundColor Green
} catch {
    Write-Host "Node.js not found. Download: https://nodejs.org" -ForegroundColor Red
    exit 1
}

# Check OpenClaw
try {
    $ocVer = & openclaw --version 2>$null | Select-Object -First 1
    Write-Host "OpenClaw $ocVer" -ForegroundColor Green
} catch {
    Write-Host "OpenClaw not found. Run: npm install -g openclaw" -ForegroundColor Red
    exit 1
}

Write-Host ""

# Install
$pluginDir = Join-Path $env:USERPROFILE ".openclaw\plugins\clawguard"

if (Test-Path $pluginDir) {
    Write-Host "ClawGuard already installed, updating..." -ForegroundColor Yellow
    Remove-Item -Recurse -Force $pluginDir
}

$parentDir = Split-Path $pluginDir -Parent
if (!(Test-Path $parentDir)) {
    New-Item -ItemType Directory -Path $parentDir -Force | Out-Null
}

Write-Host "Downloading ClawGuard..." -ForegroundColor Blue
try {
    & git clone --depth 1 https://github.com/jnMetaCode/clawguard.git $pluginDir 2>$null
    Remove-Item -Recurse -Force (Join-Path $pluginDir ".git") -ErrorAction SilentlyContinue
} catch {
    Write-Host "Download failed. Check: https://github.com/jnMetaCode/clawguard" -ForegroundColor Red
    exit 1
}

# Verify
Write-Host ""
Write-Host "Verifying..." -ForegroundColor Blue
$indexFile = Join-Path $pluginDir "src\index.ts"
$pluginJson = Join-Path $pluginDir "openclaw.plugin.json"

if ((Test-Path $indexFile) -and (Test-Path $pluginJson)) {
    Write-Host "Installation successful!" -ForegroundColor Green
} else {
    Write-Host "Installation failed - files missing" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "==================================================" -ForegroundColor Cyan
Write-Host "Done! ClawGuard will auto-load next time OpenClaw starts." -ForegroundColor Green
Write-Host ""
Write-Host "Usage:" -ForegroundColor Yellow
Write-Host '  openclaw agent --local -m "hello"   # Start agent with security'
Write-Host '  /security                            # View security status'
Write-Host '  /audit                               # View audit log'
Write-Host '  /harden                              # Security scan'
Write-Host ""
Write-Host "Docs: https://github.com/jnMetaCode/clawguard" -ForegroundColor Blue
Write-Host ""
