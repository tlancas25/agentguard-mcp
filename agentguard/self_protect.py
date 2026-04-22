"""Self-protection for AgentGuard.

Scans every tool call for references to AgentGuard's own state
(``~/.agentguard/`` plus any operator extras) and classifies each hit
as a read or a mutation so the proxy can apply the right policy.

Three modes:
  off       — classifier returns NONE for every call (feature disabled)
  standard  — reads allowed (and logged); mutations held for operator approval
  strict    — any reference denied

Threat model: the user's communication channel is compromised and the
agent receives an instruction like "delete ~/.agentguard/audit.db" or
"uninstall the AgentGuard MCP server". Without this guard the agent
would gladly run those commands. With it, the attempt is either
blocked outright (strict) or parked until a human approves via
``agentguard approve <code>`` in a separate terminal (standard).

Not a replacement for OS-level isolation — it's a backstop that turns
a silent compromise into a loud, recorded one.

NIST 800-53 controls:
- AC-3  Access Enforcement
- AU-9  Protection of Audit Information
- SC-3  Security Function Isolation
- SI-7  Software, Firmware, and Information Integrity
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from enum import Enum
from typing import Any, Iterable, Optional

from agentguard.detectors.normalize import iter_strings, nfkc_stripped

NIST_CONTROLS = ["AC-3", "AU-9", "SC-3", "SI-7"]

EVENT_TAMPER_ATTEMPT = "agentguard_tamper_attempt"
EVENT_TAMPER_APPROVED = "agentguard_tamper_approved"
EVENT_TAMPER_DENIED = "agentguard_tamper_denied"


class ReferenceKind(str, Enum):
    NONE = "none"
    READ = "read"
    MUTATE = "mutate"


@dataclass
class SelfProtectResult:
    """Outcome of a self-protection scan."""

    kind: ReferenceKind
    path_hit: Optional[str] = None
    arg_preview: Optional[str] = None
    mutate_reason: Optional[str] = None

    @property
    def matched(self) -> bool:
        return self.kind is not ReferenceKind.NONE

    @property
    def is_mutate(self) -> bool:
        return self.kind is ReferenceKind.MUTATE


# Tool names that are inherently mutating regardless of argument content.
# Direct file-writing / destructive surfaces with no read path.
_MUTATING_TOOL_NAMES = {
    "write_file", "write", "create_file", "edit_file", "patch_file",
    "str_replace", "str_replace_editor", "append_file", "set_file_contents",
    "delete_file", "rm_file", "remove_file", "unlink",
    "move_file", "rename_file", "copy_file",
    "fs_write", "fs_delete", "fs_mkdir", "fs_rmdir",
}

# Shells and generic command runners: classification is driven by the
# content of the command string, not the tool name alone. A shell can
# read or mutate; we defer to the mutate-pattern scan below.
_SHELL_TOOL_NAMES = {
    "run_shell", "shell_exec", "execute_command", "bash", "sh", "exec",
    "terminal", "run_command",
}

# Regex patterns whose presence in tool args OR tool name promotes the
# classification to MUTATE. Matched case-insensitively against the
# NFKC-stripped form of every string argument.
# Generic mutation patterns. These require a protected-path hit to be
# meaningful — "rm /tmp/foo" is not self-tampering.
_MUTATE_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("rm",          re.compile(r"\b(?:rm|rmdir|del|rd)\b", re.IGNORECASE)),
    ("mv",          re.compile(r"\b(?:mv|move|rename|rename-item)\b", re.IGNORECASE)),
    ("cp_write",    re.compile(r"\b(?:cp|copy)\b", re.IGNORECASE)),
    ("truncate",    re.compile(r"\btruncate\b|\btee\b", re.IGNORECASE)),
    ("chmod",       re.compile(r"\b(?:chmod|chown|icacls|set-acl|takeown)\b", re.IGNORECASE)),
    ("kill",        re.compile(r"\b(?:kill|pkill|killall|taskkill|stop-process)\b", re.IGNORECASE)),
    # Require SQL syntactic context to avoid matching bare 'update' in
    # shell commands like 'agentguard update'.
    ("sql_write",   re.compile(
        r"\b(?:UPDATE\s+\w+\s+SET|DELETE\s+FROM|DROP\s+(?:TABLE|INDEX|DATABASE|VIEW)"
        r"|INSERT\s+INTO|ALTER\s+TABLE|REPLACE\s+INTO)\b",
        re.IGNORECASE,
    )),
    ("shell_write", re.compile(r"(?<![&|>])>{1,2}\s*[^&|]", re.IGNORECASE)),
    ("write_api",   re.compile(r"\b(?:write_file|write_text|fs\.write|setfile|writefile)\b", re.IGNORECASE)),
]

# Self-command patterns. These mutate AgentGuard state by identity alone,
# even when the command text never names the protected path. A bare
# `agentguard update` or `claude mcp remove agentguard` will happily
# remove the gateway without mentioning ``~/.agentguard/`` — so these
# must fire independently of path matching.
_SELF_COMMAND_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("mcp_remove_agentguard",
     re.compile(r"\bclaude\s+mcp\s+remove\s+agentguard\b", re.IGNORECASE)),
    ("ag_init_force",
     re.compile(r"\bagentguard\s+init\b[^\n]*--force", re.IGNORECASE)),
    ("ag_update",
     re.compile(r"\bagentguard\s+update\b(?![^\n]*--dry-run)", re.IGNORECASE)),
    ("ag_repair",
     re.compile(r"\bagentguard\s+repair\b(?![^\n]*--dry-run)", re.IGNORECASE)),
    # Agents must never approve their own pending mutations; that would
    # turn a compromise into instant self-authorization.
    ("ag_approve",
     re.compile(r"\bagentguard\s+approve\b", re.IGNORECASE)),
    # Kill targeted at AgentGuard process names specifically.
    ("kill_agentguard",
     re.compile(
         r"\b(?:kill|pkill|killall|taskkill|stop-process)\b[^\n]*\bagentguard\b",
         re.IGNORECASE,
     )),
]


def _normalize_path(p: str) -> str:
    """Expand ~ and env vars, resolve symlinks, collapse separators, case-fold.

    Path comparison is case-insensitive because Windows filesystems are
    case-insensitive and we never want a trivial case-swap to slip past.

    AG-BL-004: the earlier implementation used literal path comparison
    which meant a symlink like ``/tmp/shortcut -> ~/.agentguard`` or a
    hardlinked ``audit.db`` bypassed the guard entirely. We now resolve
    real paths for both the candidate and every protected needle before
    comparison. Paths that can't be resolved fall back to normalized
    form so we never fail-open on a nonexistent path.
    """
    s = os.path.expandvars(os.path.expanduser(p))
    try:
        # realpath() resolves symlinks on POSIX and reparse points on
        # modern Windows. On targets that don't exist it still canonicalizes.
        s = os.path.realpath(s)
    except (OSError, ValueError):
        pass
    s = s.replace("\\", "/")
    s = re.sub(r"/+", "/", s)
    return s.rstrip("/").casefold()


def default_protected_paths() -> list[str]:
    """Always-on protected set.

    Deliberately narrow: only AgentGuard's own home directory. Operators
    add extras via ``self_protection.extra_paths`` or
    ``AGENTGUARD_SELF_PROTECT_EXTRA_PATHS``.
    """
    from agentguard.config import DEFAULT_AGENTGUARD_HOME

    return [_normalize_path(str(DEFAULT_AGENTGUARD_HOME))]


def _path_hit(candidate: str, needle: str) -> bool:
    """Does the tool-call string reference the protected path?"""
    norm_c = _normalize_path(candidate)
    if not norm_c or not needle:
        return False
    if norm_c == needle:
        return True
    if norm_c.startswith(needle + "/"):
        return True
    return needle in norm_c


def _detect_mutation(tool_name: str, candidates: list[str]) -> Optional[str]:
    """Return the name of the first mutation signal found, else None."""
    tn = (tool_name or "").lower()
    # Direct-write tool names are always mutations.
    if tn in _MUTATING_TOOL_NAMES:
        return f"tool_name:{tool_name}"
    # For shells and generic runners, look at the command text itself —
    # many legitimate reads (cat, ls, --dry-run) are shells too. Use the
    # same NFKC-stripped form so unicode evasion can't dodge the regex.
    for raw in candidates:
        if not isinstance(raw, str):
            continue
        normalized = nfkc_stripped(raw)
        for label, pat in _MUTATE_PATTERNS:
            if pat.search(normalized):
                return label
    return None


def _detect_self_command(candidates: list[str]) -> Optional[str]:
    """Detect AgentGuard-specific mutation commands independent of path.

    These are always treated as MUTATE because they modify gateway state
    by identity alone (reinstall, reconfigure, remove registration,
    self-approve, kill process), even when the command string never
    mentions the protected directory.
    """
    for raw in candidates:
        if not isinstance(raw, str):
            continue
        normalized = nfkc_stripped(raw)
        for label, pat in _SELF_COMMAND_PATTERNS:
            if pat.search(normalized):
                return label
    return None


def classify_self_reference(
    tool_name: str,
    tool_args: dict[str, Any],
    extra_paths: Optional[Iterable[str]] = None,
) -> SelfProtectResult:
    """Return how a tool call relates to AgentGuard-protected paths.

    ReferenceKind.NONE    — the call does not reference any protected path.
    ReferenceKind.READ    — protected path referenced, no mutation signals.
    ReferenceKind.MUTATE  — protected path referenced AND mutation signals
                            present (destructive tool name, denylist regex,
                            or SQL write verb).
    """
    protected = list(default_protected_paths())
    if extra_paths:
        for extra in extra_paths:
            if extra:
                protected.append(_normalize_path(extra))
    protected = list(dict.fromkeys(p for p in protected if p))

    candidates: list[str] = [tool_name] if isinstance(tool_name, str) else []
    candidates.extend(s for s in iter_strings(tool_args) if isinstance(s, str))

    # 0. Self-command? Fires even when the call does not name a path.
    self_command = _detect_self_command(candidates)
    if self_command is not None:
        preview = next(
            (c for c in candidates if isinstance(c, str) and c), ""
        )
        return SelfProtectResult(
            kind=ReferenceKind.MUTATE,
            path_hit=protected[0] if protected else None,
            arg_preview=preview[:120],
            mutate_reason=self_command,
        )

    # 1. Any protected-path hit?
    path_hit: Optional[str] = None
    offending_arg: Optional[str] = None
    for raw in candidates:
        normalized_candidate = nfkc_stripped(raw)
        for needle in protected:
            if _path_hit(normalized_candidate, needle):
                path_hit = needle
                offending_arg = raw
                break
        if path_hit:
            break

    if path_hit is None:
        return SelfProtectResult(kind=ReferenceKind.NONE)

    # 2. Classify: mutation or read?
    mutation = _detect_mutation(tool_name, candidates)
    if mutation is not None:
        return SelfProtectResult(
            kind=ReferenceKind.MUTATE,
            path_hit=path_hit,
            arg_preview=(offending_arg or "")[:120],
            mutate_reason=mutation,
        )
    return SelfProtectResult(
        kind=ReferenceKind.READ,
        path_hit=path_hit,
        arg_preview=(offending_arg or "")[:120],
    )


# Backwards-compatible alias kept for the earlier all-or-nothing callers.
# Returns matched=True whenever kind != NONE.
def scan_tool_call(
    tool_name: str,
    tool_args: dict[str, Any],
    extra_paths: Optional[Iterable[str]] = None,
) -> SelfProtectResult:
    return classify_self_reference(tool_name, tool_args, extra_paths)
