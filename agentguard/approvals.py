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
import re
import secrets
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)

POLL_INTERVAL_SEC = 0.25
# Approval codes are always 6 ASCII digits. Validate before any code
# flows into a filename so a compromised caller can't inject ../../
# or absolute paths.
CODE_RE = re.compile(r"^\d{6}$")
MAX_CODE_GENERATION_ATTEMPTS = 10


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
        self.dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        # mkdir(mode=) respects umask on POSIX; chmod after to guarantee
        # 0o700 regardless of the caller's environment. No-op on Windows.
        try:
            os.chmod(self.dir, 0o700)
        except OSError as e:
            logger.debug("Could not chmod approval dir %s: %s", self.dir, e)

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
        created_at = time.time()
        expires_at = created_at + timeout_seconds

        # Generate a non-colliding 6-digit code and atomically create the
        # pending file. O_CREAT|O_EXCL prevents an attacker who can guess
        # a code from racing to pre-create the file.
        code = ""
        pending_path: Optional[Path] = None
        for _ in range(MAX_CODE_GENERATION_ATTEMPTS):
            candidate = f"{secrets.randbelow(1_000_000):06d}"
            candidate_path = self.dir / f"{candidate}.pending.json"
            approved_probe = self.dir / f"{candidate}.approved"
            denied_probe = self.dir / f"{candidate}.denied"
            if (
                candidate_path.exists()
                or approved_probe.exists()
                or denied_probe.exists()
            ):
                continue
            try:
                fd = os.open(
                    str(candidate_path),
                    os.O_CREAT | os.O_EXCL | os.O_WRONLY,
                    0o600,
                )
            except FileExistsError:
                continue
            code = candidate
            pending_path = candidate_path
            body = json.dumps(
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
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(body)
            try:
                os.chmod(pending_path, 0o600)
            except OSError as e:
                logger.debug("Could not chmod pending approval %s: %s", pending_path, e)
            break
        else:
            logger.error(
                "Could not allocate an approval code after %d attempts.",
                MAX_CODE_GENERATION_ATTEMPTS,
            )
            return ApprovalResult(approved=False, code="", reason="code_collision")

        approved_path = self.dir / f"{code}.approved"
        denied_path = self.dir / f"{code}.denied"

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
        if not CODE_RE.fullmatch(code or ""):
            return False
        pending = self.dir / f"{code}.pending.json"
        if not pending.exists():
            return False
        sentinel = self.dir / f"{code}.approved"
        sentinel.write_text("", encoding="utf-8")
        try:
            os.chmod(sentinel, 0o600)
        except OSError as e:
            logger.debug("Could not chmod approval sentinel %s: %s", sentinel, e)
        return True

    def deny(self, code: str) -> bool:
        """Deny a pending request. Returns True if a matching request exists."""
        if not CODE_RE.fullmatch(code or ""):
            return False
        pending = self.dir / f"{code}.pending.json"
        if not pending.exists():
            return False
        sentinel = self.dir / f"{code}.denied"
        sentinel.write_text("", encoding="utf-8")
        try:
            os.chmod(sentinel, 0o600)
        except OSError as e:
            logger.debug("Could not chmod denial sentinel %s: %s", sentinel, e)
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
