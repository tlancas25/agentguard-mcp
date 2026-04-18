# AgentGuard MCP installer for Windows (PowerShell 5.1+ or PowerShell 7+)
#
# Usage (one-liner):
#   irm https://raw.githubusercontent.com/tlancas25/agentguard-mcp/main/install.ps1 | iex
#
# Or clone and run:
#   git clone https://github.com/tlancas25/agentguard-mcp.git
#   cd agentguard-mcp
#   .\install.ps1
#
# What this does:
#   1. Checks for Python 3.11+
#   2. Installs uv (Astral's fast Python package manager) if missing
#   3. Installs AgentGuard as an isolated tool via `uv tool install`
#   4. Verifies the install and prints next steps
#
# Idempotent. Safe to re-run.

[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"

$Repo  = "tlancas25/agentguard-mcp"
$MinPy = "3.11"

function Write-Info  ($msg) { Write-Host "==> $msg" -ForegroundColor Cyan }
function Write-OK    ($msg) { Write-Host "OK  $msg" -ForegroundColor Green }
function Write-Warn2 ($msg) { Write-Host "!!  $msg" -ForegroundColor Yellow }
function Write-Err   ($msg) { Write-Host "X   $msg" -ForegroundColor Red }

Write-Info "AgentGuard MCP installer (Windows)"

# ---------- Python check ----------
$pyCmd = Get-Command python -ErrorAction SilentlyContinue
if (-not $pyCmd) { $pyCmd = Get-Command python3 -ErrorAction SilentlyContinue }

if (-not $pyCmd) {
    Write-Warn2 "Python 3 not found on PATH."
    Write-Warn2 "uv will bootstrap a compatible Python automatically, but you can also install from https://python.org (3.11 or later)."
} else {
    try {
        $pyVerRaw = & $pyCmd.Source --version 2>&1
        $pyVer    = ($pyVerRaw -replace 'Python ', '').Trim()
        $parts    = $pyVer.Split('.')
        $major    = [int]$parts[0]; $minor = [int]$parts[1]
        if ($major -lt 3 -or ($major -eq 3 -and $minor -lt 11)) {
            Write-Warn2 "Python $pyVer found, but AgentGuard requires Python $MinPy or later."
            Write-Info  "uv will install a compatible Python automatically."
        } else {
            Write-OK "Python $pyVer detected"
        }
    } catch {
        Write-Warn2 "Could not parse Python version. Continuing; uv will manage it."
    }
}

# ---------- uv install ----------
$uvCmd = Get-Command uv -ErrorAction SilentlyContinue
if (-not $uvCmd) {
    Write-Info "Installing uv (Astral's fast Python package manager)"
    try {
        powershell -ExecutionPolicy Bypass -NoProfile -Command "irm https://astral.sh/uv/install.ps1 | iex"
    } catch {
        Write-Err "uv install failed: $($_.Exception.Message)"
        exit 1
    }
    # Refresh PATH from the registry so the current session picks up uv
    $machinePath = [System.Environment]::GetEnvironmentVariable("Path", "Machine")
    $userPath    = [System.Environment]::GetEnvironmentVariable("Path", "User")
    $env:Path    = "$machinePath;$userPath"
    $uvCmd = Get-Command uv -ErrorAction SilentlyContinue
    if (-not $uvCmd) {
        Write-Err "uv installed but not on PATH in this session."
        Write-Warn2 "Close and reopen PowerShell, then re-run this installer."
        exit 1
    }
    Write-OK "uv installed"
} else {
    Write-OK "uv already installed ($(& uv --version 2>&1))"
}

# ---------- AgentGuard install ----------
Write-Info "Installing AgentGuard MCP from github.com/$Repo"
try {
    uv tool install --force --python $MinPy "git+https://github.com/$Repo.git"
} catch {
    Write-Err "AgentGuard install failed: $($_.Exception.Message)"
    exit 1
}

# ---------- Verify ----------
# Refresh PATH so freshly installed tools are visible
$machinePath = [System.Environment]::GetEnvironmentVariable("Path", "Machine")
$userPath    = [System.Environment]::GetEnvironmentVariable("Path", "User")
$env:Path    = "$machinePath;$userPath"

$agCmd = Get-Command agentguard -ErrorAction SilentlyContinue
if (-not $agCmd) {
    Write-Warn2 "agentguard is installed but not on PATH in this terminal session."
    Write-Warn2 "Open a new PowerShell window, or run: refreshenv"
    Write-Warn2 "Then try: agentguard version"
    exit 0
}

try {
    $agVer = (& agentguard version 2>&1)
} catch {
    $agVer = "unknown"
}

Write-Host ""
Write-OK "AgentGuard MCP installed: $agVer"
Write-Host ""
Write-Host "Next steps:" -ForegroundColor White
Write-Host "  1. agentguard init           # scaffold agentguard.yaml in current dir"
Write-Host "  2. agentguard run --mode dev # start in dev mode (permissive, log-only)"
Write-Host ""
Write-Host "Claude Code integration:" -ForegroundColor White
Write-Host "  https://github.com/$Repo/blob/main/examples/claude_code_integration.md"
Write-Host ""
Write-Host "Federal deployment guide:" -ForegroundColor White
Write-Host "  https://github.com/$Repo/blob/main/examples/federal_deployment.md"
Write-Host ""
