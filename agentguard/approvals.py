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

import hashlib
import hmac
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

# Operator-held HMAC key lives here. The CLI `agentguard approve` reads
# the file to compute the expected token; the agent sandbox cannot
# reach it when self-protection is in standard or strict mode because
# the path resolves under ~/.agentguard/ which is a protected path.
# (AG-BL-003)
OPERATOR_SECRET_FILENAME = "operator.secret"


@dataclass
class ApprovalResult:
    approved: bool
    code: str
    reason: str = ""


MIN_OPERATOR_SECRET_BYTES = 32


def _load_operator_secret() -> Optional[bytes]:
    """Return the operator HMAC key, or None if unavailable / too weak.

    Order of precedence:
        1. ``AGENTGUARD_OPERATOR_SECRET`` env var (hex or raw string).
        2. ``~/.agentguard/operator.secret`` file.

    AG-V11 (trial 4 hardening): reject secrets shorter than
    ``MIN_OPERATOR_SECRET_BYTES`` (32 bytes). The prior implementation
    accepted a 1-byte env var and produced valid tokens, which is a
    trivial brute-force target. Weak secrets are logged loudly and
    treated as absent.
    """
    from agentguard.config import DEFAULT_AGENTGUARD_HOME

    candidate: Optional[bytes] = None
    source: str = ""
    env = os.environ.get("AGENTGUARD_OPERATOR_SECRET")
    if env:
        candidate = env.strip().encode("utf-8")
        source = "AGENTGUARD_OPERATOR_SECRET env var"
    else:
        secret_path = DEFAULT_AGENTGUARD_HOME / OPERATOR_SECRET_FILENAME
        if secret_path.exists():
            try:
                candidate = secret_path.read_text(
                    encoding="utf-8"
                ).strip().encode("utf-8")
                source = str(secret_path)
            except OSError as e:
                logger.warning("Could not read operator secret %s: %s", secret_path, e)
                return None

    if candidate is None:
        return None
    if len(candidate) < MIN_OPERATOR_SECRET_BYTES:
        logger.error(
            "Operator secret from %s is %d bytes; minimum is %d. "
            "Rejecting. Rotate the secret or unset the env var.",
            source, len(candidate), MIN_OPERATOR_SECRET_BYTES,
        )
        return None
    return candidate


def _ensure_operator_secret() -> Optional[Path]:
    """Auto-provision ``~/.agentguard/operator.secret`` if it does not exist.

    Returns the path (even if we were unable to create it). The file is
    0o600 and contains 32 bytes of hex-encoded entropy. AG-BL-003.R4a:
    without this provisioning step, any install that skipped
    ``agentguard init --gen-key`` shipped with no secret, which meant
    request() fell through to hmac_required=False — a library-import
    call could then approve its own mutation.
    """
    from agentguard.config import DEFAULT_AGENTGUARD_HOME

    DEFAULT_AGENTGUARD_HOME.mkdir(parents=True, exist_ok=True)
    secret_path = DEFAULT_AGENTGUARD_HOME / OPERATOR_SECRET_FILENAME
    if secret_path.exists():
        return secret_path
    secret_path.write_text(secrets.token_hex(32) + "\n", encoding="utf-8")
    try:
        os.chmod(secret_path, 0o600)
    except OSError:
        pass
    return secret_path


def compute_operator_token(code: str) -> Optional[str]:
    """HMAC-SHA256(operator_secret, code) hex digest, or None if no secret.

    Used by both the ``agentguard approve`` CLI (to generate the token)
    and the ApprovalManager (to validate it). A compromised caller that
    cannot read the operator secret cannot forge the token.
    """
    if not CODE_RE.fullmatch(code or ""):
        return None
    secret = _load_operator_secret()
    if secret is None:
        return None
    return hmac.new(secret, code.encode("utf-8"), hashlib.sha256).hexdigest()


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

        # AG-BL-003.R4a: ensure operator.secret exists so every install
        # has an HMAC secret by default. The trial-3 red team showed
        # that when the secret was missing, request() wrote pending
        # records with hmac_required=False and approve() accepted
        # no-token calls — a backdoor that shipped live.
        try:
            _ensure_operator_secret()
        except OSError as e:
            logger.warning(
                "Could not provision operator.secret: %s. Approvals will "
                "not enforce HMAC tokens until the secret is available.", e,
            )

    def request(
        self,
        tool_name: str,
        tool_args_preview: str,
        agent_id: str,
        mutate_reason: str,
        path_hit: str,
        timeout_seconds: int = 60,
    ) -> ApprovalResult:
        """Publish a request, block until resolved or timed out.

        AG-BL-003.R4a: refuse to publish a pending record at all if we
        cannot reach an operator secret. The earlier behavior of writing
        ``hmac_required=False`` when no secret was available was a
        self-declared opt-out of the enforcement layer, which defeats
        the purpose. Mutations simply do not proceed in that state —
        the operator must provision a secret first.
        """
        if _load_operator_secret() is None:
            logger.error(
                "ApprovalManager.request called but no operator secret is "
                "available. Refusing to write a pending record. "
                "Run 'agentguard init --gen-key' or set "
                "AGENTGUARD_OPERATOR_SECRET."
            )
            return ApprovalResult(
                approved=False, code="", reason="no_operator_secret"
            )

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
            # AG-BL-003: compute and persist the expected HMAC token so
            # approve()/deny() can refuse library-import calls that did
            # not obtain the operator secret.
            expected_hmac = compute_operator_token(code)
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
                    "expected_hmac": expected_hmac,
                    "hmac_required": expected_hmac is not None,
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

    def _check_hmac(
        self, code: str, token: Optional[str]
    ) -> Optional[dict[str, Any]]:
        """Validate an approve/deny request.

        Returns the parsed pending record when acceptance is permitted,
        or None when the request must be rejected. Rejects on:
            - malformed code
            - missing pending file
            - operator secret is currently reachable AND caller did not
              present a token matching HMAC(secret, code)

        AG-BL-003.R4b: the earlier implementation gated enforcement on
        the record's self-declared ``hmac_required`` field, which meant
        an attacker who could write a pending.json with
        ``hmac_required: False`` bypassed the check entirely. The gate
        now keys off CURRENT operator-secret availability instead: if
        the gateway can compute a token right now, approve/deny must
        present one that matches.

        Caller should treat a None return as 'deny the approve/deny call'.
        """
        if not CODE_RE.fullmatch(code or ""):
            return None
        pending = self.dir / f"{code}.pending.json"
        if not pending.exists():
            return None
        try:
            record = json.loads(pending.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None

        current_expected = compute_operator_token(code)
        if current_expected is not None:
            if not token or not hmac.compare_digest(token, current_expected):
                logger.warning(
                    "approval rejected: current operator secret requires "
                    "a valid HMAC token for code %s; caller did not present one",
                    code,
                )
                return None
        # No operator secret reachable: fall back to the record's
        # declared state only as a last resort so the test harness can
        # still exercise the legacy no-secret path. Production installs
        # always have a secret because ApprovalManager provisions one
        # on __init__.
        elif record.get("hmac_required"):
            expected = record.get("expected_hmac") or ""
            if not token or not hmac.compare_digest(token, expected):
                logger.warning(
                    "approval rejected: record-level hmac required for "
                    "code %s but caller did not present a valid token",
                    code,
                )
                return None
        return record

    def approve(self, code: str, token: Optional[str] = None) -> bool:
        """Approve a pending request. Returns True if accepted.

        When the pending file was written while an operator secret was
        available, ``token`` must be the HMAC computed by
        :func:`compute_operator_token`. The CLI ``agentguard approve``
        computes this from the local operator.secret file; callers that
        cannot reach that file cannot forge the token (AG-BL-003).
        """
        if self._check_hmac(code, token) is None:
            return False
        sentinel = self.dir / f"{code}.approved"
        sentinel.write_text("", encoding="utf-8")
        try:
            os.chmod(sentinel, 0o600)
        except OSError as e:
            logger.debug("Could not chmod approval sentinel %s: %s", sentinel, e)
        return True

    def deny(self, code: str, token: Optional[str] = None) -> bool:
        """Deny a pending request. Requires the same HMAC token as approve()."""
        if self._check_hmac(code, token) is None:
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
