"""End-to-end smoke test for the AgentGuard MCP stdio server.

Spawns a real ``agentguard run`` subprocess, drives it with JSON-RPC
over stdin, and asserts the handshake + a few representative tool
calls. Intended as a fast "is my install actually functional" check.

Run it:
    python tests/e2e/smoke_test.py

Exit 0 = pass. Non-zero = fail with a diagnostic on stderr.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Any


def _agentguard_exe() -> str:
    """Resolve the agentguard binary regardless of install style."""
    on_path = shutil.which("agentguard")
    if on_path:
        return on_path
    candidates = [
        Path(sys.prefix) / "Scripts" / "agentguard.exe",
        Path.home() / "AppData/Roaming/Python/Python313/Scripts/agentguard.exe",
        Path.home() / ".local/bin/agentguard",
    ]
    for c in candidates:
        if c.exists():
            return str(c)
    raise SystemExit(
        "Could not locate agentguard. Install first: "
        "pip install -e . OR uv tool install --from . agentguard-mcp"
    )


class MCPSession:
    """Minimal MCP client over a subprocess's stdio pipes."""

    def __init__(self, cmd: list[str], env: dict[str, str]) -> None:
        self.proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            text=True,
            encoding="utf-8",
        )
        self._next_id = 0
        self._stderr_buf: list[str] = []
        self._stderr_thread = threading.Thread(
            target=self._drain_stderr, daemon=True
        )
        self._stderr_thread.start()

    def _drain_stderr(self) -> None:
        assert self.proc.stderr is not None
        for line in self.proc.stderr:
            self._stderr_buf.append(line)

    def call(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        self._next_id += 1
        req = {
            "jsonrpc": "2.0",
            "id": self._next_id,
            "method": method,
            "params": params,
        }
        assert self.proc.stdin is not None
        self.proc.stdin.write(json.dumps(req) + "\n")
        self.proc.stdin.flush()

        assert self.proc.stdout is not None
        for _ in range(40):  # ~10 seconds at 0.25s/loop
            line = self.proc.stdout.readline()
            if not line:
                time.sleep(0.25)
                continue
            try:
                return json.loads(line.strip())
            except json.JSONDecodeError:
                continue
        raise TimeoutError(f"No response to {method} within 10 seconds")

    def stderr(self) -> str:
        return "".join(self._stderr_buf)

    def close(self) -> None:
        assert self.proc.stdin is not None
        try:
            self.proc.stdin.close()
        except Exception:
            pass
        try:
            self.proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            self.proc.kill()


def _write_config(home: Path, sp_mode: str = "off") -> Path:
    home.mkdir(parents=True, exist_ok=True)
    cfg_path = home / "agentguard.yaml"
    cfg_path.write_text(
        "mode: dev\n"
        f"audit_db_path: {home / 'audit.db'}\n"
        "upstream_servers: []\n"
        "policy_bundles: []\n"
        "self_protection:\n"
        f"  mode: {sp_mode}\n"
        "  approval_timeout_seconds: 3\n"
    )
    return cfg_path


def _run_case(name: str, home: Path, sp_mode: str, asserts) -> bool:
    ag = _agentguard_exe()
    cfg = _write_config(home, sp_mode=sp_mode)
    env = {
        **os.environ,
        "AGENTGUARD_APPROVALS_DIR": str(home / "approvals"),
        # Force unbuffered stdio inside the child so Windows pipes
        # don't block-buffer JSON-RPC responses.
        "PYTHONUNBUFFERED": "1",
    }
    session = MCPSession([ag, "run", "--config", str(cfg), "--mode", "dev"], env)
    try:
        asserts(session, home)
        print(f"  OK   {name}")
        return True
    except AssertionError as e:
        print(f"  FAIL {name}: {e}")
        return False
    except Exception as e:
        print(f"  FAIL {name}: {type(e).__name__}: {e}")
        return False
    finally:
        session.close()


# -------- assertions per case --------

def _assert_handshake(s: MCPSession, _home: Path) -> None:
    resp = s.call(
        "initialize",
        {
            "protocolVersion": "2025-03-26",
            "capabilities": {},
            "clientInfo": {"name": "smoke-test", "version": "1"},
        },
    )
    assert resp.get("id") == 1, resp
    assert resp["result"]["serverInfo"]["name"] == "agentguard", resp

    resp = s.call("tools/list", {})
    assert resp["result"].get("tools") == [], resp


def _assert_off_passthrough(s: MCPSession, home: Path) -> None:
    _assert_handshake(s, home)
    # With no upstream, even "dangerous"-looking tool calls return the
    # synthesized no-content result. We just verify we got a response.
    resp = s.call(
        "tools/call",
        {"name": "shell_exec", "arguments": {"cmd": "rm -rf /tmp/x"}},
    )
    assert "result" in resp or "error" in resp, resp


def _assert_strict_denies(s: MCPSession, home: Path) -> None:
    _assert_handshake(s, home)
    resp = s.call(
        "tools/call",
        {
            "name": "read_file",
            "arguments": {"path": str(Path.home() / ".agentguard/audit.db")},
        },
    )
    assert "error" in resp, f"strict should have returned an error: {resp}"
    assert "self-protection" in resp["error"]["message"].lower(), resp


def _assert_standard_mutation_timeout(s: MCPSession, home: Path) -> None:
    _assert_handshake(s, home)
    # approval_timeout_seconds = 3; we don't approve, expect deny.
    resp = s.call(
        "tools/call",
        {
            "name": "shell_exec",
            "arguments": {"cmd": f"rm -rf {Path.home()}/.agentguard/audit.db"},
        },
    )
    assert "error" in resp, resp
    body = (resp["error"].get("message") or "").lower()
    assert "timeout" in body or "denied" in body, resp


def main() -> int:
    tmp = Path(tempfile.mkdtemp(prefix="agentguard-smoke-"))
    print(f"smoke-test home: {tmp}")
    print("Running 4 cases...")

    fails = 0
    fails += 0 if _run_case("handshake",              tmp / "c1", "off",      _assert_handshake)             else 1
    fails += 0 if _run_case("off mode pass-through",  tmp / "c2", "off",      _assert_off_passthrough)       else 1
    fails += 0 if _run_case("strict denies tamper",   tmp / "c3", "strict",   _assert_strict_denies)         else 1
    fails += 0 if _run_case("standard mutation times out", tmp / "c4", "standard", _assert_standard_mutation_timeout) else 1

    print()
    if fails:
        print(f"[FAIL] {fails} case(s) failed.")
        return 1
    print("[PASS] All 4 cases passed. AgentGuard MCP is healthy.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
