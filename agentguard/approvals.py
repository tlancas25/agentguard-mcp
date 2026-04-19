"""Operator approval channel for self-protection standard mode.

The proxy is a single stdio subprocess; it can't pop a UI. When a
mutation of AgentGuard's own state is requested, the proxy parks the
call, writes a pending-request JSON file into
``~/.agentguard/approvals/``, prints a clear banner to stderr, and then
polls the directory for an approval or denial sentinel created by
``agentguard approve <code>`` running in a separate terminal.

No network, no webhook, no OS-specific notifier — one directory watched
by short polls. Cross-process safe because the approver is a sibling
process touching the same filesystem.
"""

from __future__ import annotations

import json
import logging
import os
import secrets
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)

POLL_INTERVAL_SEC = 0.25


@dataclass
class ApprovalResult:
    approved: bool
    code: str
    reason: str = ""


class ApprovalManager:
    """File-based approval channel.

    One directory, three sentinel kinds per request:
      <code>.pending.json  — request context, written by the proxy
      <code>.approved      — empty sentinel, written by ``agentguard approve``
      <code>.denied        — empty sentinel, written by ``agentguard approve --deny``
    """

    def __init__(self, approvals_dir: Path) -> None:
        self.dir = approvals_dir
        self.dir.mkdir(parents=True, exist_ok=True)

    def request(
        self,
        tool_name: str,
        tool_args_preview: str,
        agent_id: str,
        mutate_reason: str,
        path_hit: str,
        timeout_seconds: int = 60,
    ) -> ApprovalResult:
        """Publish a request, block until resolved or timed out."""
        code = f"{secrets.randbelow(1_000_000):06d}"
        pending_path = self.dir / f"{code}.pending.json"
        approved_path = self.dir / f"{code}.approved"
        denied_path = self.dir / f"{code}.denied"
        created_at = time.time()
        expires_at = created_at + timeout_seconds

        pending_path.write_text(
            json.dumps(
                {
                    "code": code,
                    "agent_id": agent_id,
                    "tool_name": tool_name,
                    "tool_args_preview": tool_args_preview,
                    "mutate_reason": mutate_reason,
                    "path_hit": path_hit,
                    "created_at": created_at,
                    "expires_at": expires_at,
                },
                indent=2,
            )
        )

        self._print_banner(
            code=code,
            agent_id=agent_id,
            tool_name=tool_name,
            preview=tool_args_preview,
            path_hit=path_hit,
            timeout_seconds=timeout_seconds,
        )

        deadline = expires_at
        while time.time() < deadline:
            if approved_path.exists():
                self._cleanup(code)
                return ApprovalResult(approved=True, code=code, reason="operator_approved")
            if denied_path.exists():
                self._cleanup(code)
                return ApprovalResult(
                    approved=False, code=code, reason="operator_denied"
                )
            time.sleep(POLL_INTERVAL_SEC)

        self._cleanup(code)
        return ApprovalResult(approved=False, code=code, reason="timeout")

    def approve(self, code: str) -> bool:
        """Approve a pending request. Returns True if a matching request exists."""
        pending = self.dir / f"{code}.pending.json"
        if not pending.exists():
            return False
        (self.dir / f"{code}.approved").write_text("")
        return True

    def deny(self, code: str) -> bool:
        """Deny a pending request. Returns True if a matching request exists."""
        pending = self.dir / f"{code}.pending.json"
        if not pending.exists():
            return False
        (self.dir / f"{code}.denied").write_text("")
        return True

    def list_pending(self) -> list[dict[str, Any]]:
        """List every currently pending request (may be stale; caller filters by expires_at)."""
        out: list[dict[str, Any]] = []
        for f in sorted(self.dir.glob("*.pending.json")):
            try:
                out.append(json.loads(f.read_text()))
            except Exception as e:
                logger.warning("Could not parse pending approval %s: %s", f, e)
        return out

    def _cleanup(self, code: str) -> None:
        for suffix in ("pending.json", "approved", "denied"):
            p = self.dir / f"{code}.{suffix}"
            try:
                p.unlink()
            except FileNotFoundError:
                pass
            except OSError as e:
                logger.debug("Could not unlink %s: %s", p, e)

    @staticmethod
    def _print_banner(
        code: str,
        agent_id: str,
        tool_name: str,
        preview: str,
        path_hit: str,
        timeout_seconds: int,
    ) -> None:
        msg = (
            "\n"
            "============================================================\n"
            "  AGENTGUARD APPROVAL REQUIRED\n"
            "============================================================\n"
            f"  Agent      : {agent_id}\n"
            f"  Tool       : {tool_name}\n"
            f"  Path hit   : {path_hit}\n"
            f"  Preview    : {preview[:200]}\n"
            f"  Challenge  : {code}\n"
            f"  To approve : agentguard approve {code}\n"
            f"  To deny    : agentguard approve {code} --deny\n"
            f"  Expires in : {timeout_seconds} seconds.\n"
            "============================================================\n"
        )
        try:
            sys.stderr.write(msg)
            sys.stderr.flush()
        except Exception:
            pass


def default_approvals_dir() -> Path:
    """``~/.agentguard/approvals/`` by default; override with
    ``AGENTGUARD_APPROVALS_DIR``."""
    env = os.environ.get("AGENTGUARD_APPROVALS_DIR")
    if env:
        return Path(os.path.expanduser(os.path.expandvars(env)))
    from agentguard.config import DEFAULT_AGENTGUARD_HOME

    return DEFAULT_AGENTGUARD_HOME / "approvals"
