"""Self-protection for AgentGuard.

Hard-coded, always-on path guard that prevents the protected agent from
reaching into AgentGuard's own configuration, audit log, or signing keys
through any MCP tool call.

The check runs BEFORE the policy engine and detector stack, so an
attacker who has compromised the user's communication channel cannot
instruct the agent to "delete ~/.agentguard/audit.db" or "unregister
the AgentGuard MCP server" without the attempt being denied and
permanently recorded in the hash-chained audit log.

This is a backstop. It does not replace OS-level filesystem isolation;
a truly paranoid deployment still runs the gateway under its own service
account with the audit directory chmod 600 and an immutable-bit offsite
mirror.

NIST 800-53 controls addressed:
- AC-3  Access Enforcement
- AU-9  Protection of Audit Information
- SC-3  Security Function Isolation
- SI-7  Software, Firmware, and Information Integrity
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from typing import Any, Iterable, Optional

from agentguard.detectors.normalize import iter_strings, nfkc_stripped

NIST_CONTROLS = ["AC-3", "AU-9", "SC-3", "SI-7"]

EVENT_TAMPER_ATTEMPT = "agentguard_tamper_attempt"


@dataclass
class SelfProtectResult:
    """Outcome of a self-protection scan."""

    matched: bool
    path_hit: Optional[str] = None
    arg_preview: Optional[str] = None
    reason: str = ""


def _normalize_path(p: str) -> str:
    """Expand ~ and env vars, collapse separators, case-fold.

    Path comparison is case-insensitive because Windows filesystems are
    case-insensitive and we never want a trivial case-swap to slip past.
    """
    s = os.path.expandvars(os.path.expanduser(p))
    s = s.replace("\\", "/")
    s = re.sub(r"/+", "/", s)
    return s.rstrip("/").casefold()


def default_protected_paths() -> list[str]:
    """Always-on protected set.

    Deliberately narrow: only AgentGuard's own home directory.
    Operators who want more coverage add paths via config
    (self_protection.extra_paths) or AGENTGUARD_SELF_PROTECT_EXTRA_PATHS.
    """
    # Import lazily to avoid a circular import with config.
    from agentguard.config import DEFAULT_AGENTGUARD_HOME

    return [_normalize_path(str(DEFAULT_AGENTGUARD_HOME))]


def _path_hit(candidate: str, needle: str) -> bool:
    """Does the tool-call string contain a reference to the protected path?

    Uses both a normalized startswith check (exact path or a child of it)
    and a substring check on the normalized forms so URL-encoded or
    concatenated forms still trip the guard.
    """
    norm_c = _normalize_path(candidate)
    if not norm_c or not needle:
        return False
    if norm_c == needle:
        return True
    if norm_c.startswith(needle + "/"):
        return True
    # Substring catch: an attacker might embed the path inside a larger
    # payload like "rm -rf ~/.agentguard/ && ...". Use the needle as a
    # bare substring to catch that.
    return needle in norm_c


def scan_tool_call(
    tool_name: str,
    tool_args: dict[str, Any],
    extra_paths: Optional[Iterable[str]] = None,
) -> SelfProtectResult:
    """Return matched=True if tool_name or any nested string arg references
    a protected path."""
    protected = list(default_protected_paths())
    if extra_paths:
        for extra in extra_paths:
            if extra:
                protected.append(_normalize_path(extra))
    # De-dupe while preserving order.
    protected = list(dict.fromkeys(p for p in protected if p))

    candidates: list[str] = [tool_name] if isinstance(tool_name, str) else []
    candidates.extend(s for s in iter_strings(tool_args) if isinstance(s, str))

    for raw in candidates:
        normalized_candidate = nfkc_stripped(raw)
        for needle in protected:
            if _path_hit(normalized_candidate, needle):
                return SelfProtectResult(
                    matched=True,
                    path_hit=needle,
                    arg_preview=raw[:120],
                    reason=(
                        f"Tool call references AgentGuard-protected path "
                        f"'{needle}'. Deny by self-protection."
                    ),
                )
    return SelfProtectResult(matched=False)
