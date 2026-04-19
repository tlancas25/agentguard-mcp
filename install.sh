#!/usr/bin/env bash
#
# AgentGuard MCP installer for Linux and macOS
#
# Usage (one-liner):
#   curl -sSL https://raw.githubusercontent.com/tlancas25/agentguard-mcp/main/install.sh | bash
#
# Or clone and run:
#   git clone https://github.com/tlancas25/agentguard-mcp.git
#   cd agentguard-mcp && ./install.sh
#
# What this does:
#   1. Detects your OS (macOS or Linux) and checks for Python 3.11+
#   2. Installs uv (Astral's fast Python package manager) if missing
#   3. Installs AgentGuard as an isolated tool via `uv tool install`
#   4. Verifies the install and prints next steps
#
# Idempotent. Safe to re-run.

set -euo pipefail

REPO="tlancas25/agentguard-mcp"
MIN_PY="3.11"
NEED_PATH_HINT=0

# AGENTGUARD_REF pins the git ref (tag or commit SHA) installed from the
# upstream repo. Defaults to the latest signed release tag. Override with:
#   AGENTGUARD_REF=v0.2.0 curl ... | bash
AGENTGUARD_REF="${AGENTGUARD_REF:-v0.1.1}"
# Optional: AGENTGUARD_UV_SHA256 of astral's uv installer, if you want an
# extra integrity check on the chained upstream. See README "Install options".
AGENTGUARD_UV_SHA256="${AGENTGUARD_UV_SHA256:-}"

# ---------- styling ----------
if [ -t 1 ]; then
  BOLD=$(printf '\033[1m'); RESET=$(printf '\033[0m')
  GREEN=$(printf '\033[32m'); BLUE=$(printf '\033[34m'); RED=$(printf '\033[31m'); YELLOW=$(printf '\033[33m')
else
  BOLD=""; RESET=""; GREEN=""; BLUE=""; RED=""; YELLOW=""
fi
info()  { printf "%s==>%s %s\n" "$BLUE" "$RESET" "$1"; }
ok()    { printf "%s✓%s  %s\n"  "$GREEN" "$RESET" "$1"; }
warn()  { printf "%s!!%s %s\n" "$YELLOW" "$RESET" "$1"; }
die()   { printf "%s✗%s  %s\n" "$RED" "$RESET" "$1" >&2; exit 1; }

# ---------- OS detection ----------
OS="$(uname -s)"
case "$OS" in
  Darwin) PLATFORM="macOS" ;;
  Linux)  PLATFORM="Linux" ;;
  *)      die "Unsupported OS: $OS. See install.ps1 for Windows." ;;
esac
info "AgentGuard MCP installer ($PLATFORM)"

# ---------- Python check ----------
if ! command -v python3 >/dev/null 2>&1; then
  die "Python 3 not found. Install Python $MIN_PY or later from https://python.org"
fi
PY_VER=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
PY_OK=$(python3 -c "import sys; print('yes' if sys.version_info >= (3, 11) else 'no')")
if [ "$PY_OK" != "yes" ]; then
  warn "Python $PY_VER found, but AgentGuard requires Python $MIN_PY or later."
  info "uv will install a compatible Python automatically."
else
  ok "Python $PY_VER detected"
fi

# ---------- uv install ----------
if ! command -v uv >/dev/null 2>&1; then
  info "Installing uv (Astral's fast Python package manager)"
  UV_TMP=$(mktemp)
  curl -LsSf https://astral.sh/uv/install.sh -o "$UV_TMP"
  if [ -n "$AGENTGUARD_UV_SHA256" ]; then
    ACTUAL=$(shasum -a 256 "$UV_TMP" 2>/dev/null | awk '{print $1}')
    if [ -z "$ACTUAL" ]; then
      ACTUAL=$(sha256sum "$UV_TMP" | awk '{print $1}')
    fi
    if [ "$ACTUAL" != "$AGENTGUARD_UV_SHA256" ]; then
      rm -f "$UV_TMP"
      die "uv installer SHA-256 mismatch. Got $ACTUAL expected $AGENTGUARD_UV_SHA256"
    fi
    ok "uv installer SHA-256 verified"
  else
    warn "Skipping uv installer checksum (set AGENTGUARD_UV_SHA256 to pin)"
  fi
  sh "$UV_TMP"
  rm -f "$UV_TMP"
  # uv installs to ~/.local/bin by default
  if [ -d "$HOME/.local/bin" ]; then
    export PATH="$HOME/.local/bin:$PATH"
    NEED_PATH_HINT=1
  fi
  if ! command -v uv >/dev/null 2>&1; then
    die "uv installation did not add uv to PATH. Add \$HOME/.local/bin to your PATH and retry."
  fi
  ok "uv installed"
else
  ok "uv already installed ($(uv --version 2>/dev/null || echo uv))"
fi

# ---------- AgentGuard install ----------
info "Installing AgentGuard MCP from github.com/$REPO@$AGENTGUARD_REF"
# --force makes re-runs upgrade cleanly; --python pins the interpreter
uv tool install --force --python "$MIN_PY" \
  "git+https://github.com/$REPO.git@$AGENTGUARD_REF"

# ---------- Verify ----------
# uv tool install puts binaries in $HOME/.local/bin or a uv-managed bin dir.
UV_TOOL_BIN="$(uv tool dir 2>/dev/null | head -1 || true)"
if [ -n "$UV_TOOL_BIN" ] && [ -d "$UV_TOOL_BIN/../bin" ]; then
  export PATH="$UV_TOOL_BIN/../bin:$PATH"
fi

if ! command -v agentguard >/dev/null 2>&1; then
  warn "agentguard not on PATH yet. This is normal on a first install."
  warn "Open a new terminal, or add this line to your shell rc file:"
  warn "  export PATH=\"\$HOME/.local/bin:\$PATH\""
  exit 0
fi

AG_VER=$(agentguard version 2>/dev/null || echo "unknown")
echo ""
ok "AgentGuard MCP installed: $AG_VER"
echo ""
printf "%sNext steps:%s\n" "$BOLD" "$RESET"
echo "  1. agentguard init           # scaffold agentguard.yaml in current dir"
echo "  2. agentguard run --mode dev # start in dev mode (permissive, log-only)"
echo ""
printf "%sClaude Code integration:%s\n" "$BOLD" "$RESET"
echo "  https://github.com/$REPO/blob/main/examples/claude_code_integration.md"
echo ""
printf "%sFederal deployment guide:%s\n" "$BOLD" "$RESET"
echo "  https://github.com/$REPO/blob/main/examples/federal_deployment.md"
echo ""
if [ "$NEED_PATH_HINT" = "1" ]; then
  warn "If 'agentguard' is not found in a new terminal, add this to your shell rc:"
  warn "  export PATH=\"\$HOME/.local/bin:\$PATH\""
fi
