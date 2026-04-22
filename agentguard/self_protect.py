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
from pathlib import Path
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
    """Always-on protected set, normalized for string comparison."""
    return [_normalize_path(p) for p in _raw_default_protected_paths()]


def _raw_default_protected_paths() -> list[str]:
    """Original (un-normalized) protected paths for inode-layer checks."""
    from agentguard.config import DEFAULT_AGENTGUARD_HOME

    return [str(DEFAULT_AGENTGUARD_HOME)]


def _high_sensitivity_files() -> list[str]:
    """Files that agents must NEVER read, even in standard mode.

    Trial-4 V1 showed that the auto-provisioned operator.secret sitting
    in the standard protected directory is accessible to a standard-mode
    read (which allows reads of AgentGuard state for convenience). The
    secret is the keying material for both the approval HMAC and the
    audit sidecar, so any read of it collapses both defenses at once.

    Any candidate tool-call string that references one of these paths
    is classified MUTATE regardless of the verb used against it.
    """
    from agentguard.config import DEFAULT_AGENTGUARD_HOME

    return [
        str(DEFAULT_AGENTGUARD_HOME / "operator.secret"),
    ]


def _high_sensitivity_inodes() -> set[tuple[int, int]]:
    """(st_dev, st_ino) pairs for high-sensitivity files that exist now.

    Used to catch hardlink and symlink aliases that point at the same
    inode as a real protected file (AG-BL-004.R5a.CARRYOVER). The prior
    inode check statted the parent directory, so aliases to the
    audit.db never matched the directory inode. Now we stat specific
    protected files and compare candidate inodes against that concrete
    set.
    """
    out: set[tuple[int, int]] = set()
    for p in _high_sensitivity_files() + _enumerate_protected_files():
        try:
            expanded = os.path.expandvars(os.path.expanduser(p))
            st = os.stat(expanded)
        except OSError:
            continue
        if st.st_ino == 0:
            continue
        out.add((st.st_dev, st.st_ino))
    return out


def _enumerate_protected_files() -> list[str]:
    """Concrete files inside the AgentGuard home that the guard covers."""
    from agentguard.config import DEFAULT_AGENTGUARD_HOME

    return [
        str(DEFAULT_AGENTGUARD_HOME / "audit.db"),
        str(DEFAULT_AGENTGUARD_HOME / "audit.db.hwm"),
        str(DEFAULT_AGENTGUARD_HOME / "agentguard.yaml"),
        str(DEFAULT_AGENTGUARD_HOME / ".install-receipt"),
    ]


def _inode_matches(candidate: str, needle: str) -> bool:
    """Compare (st_dev, st_ino) of two paths, treating missing paths as mismatch.

    AG-BL-004.R5a: ``os.path.realpath`` collapses symlinks but NOT
    hardlinks, so an attacker who runs ``os.link(audit.db, alias.db)``
    can reference the alias and slip past a string-based path guard.
    Inode-pair comparison catches this: a hardlinked alias points to
    the same (st_dev, st_ino) as the original.
    """
    try:
        cand_exp = os.path.expandvars(os.path.expanduser(candidate))
        need_exp = os.path.expandvars(os.path.expanduser(needle))
        if not os.path.exists(cand_exp) or not os.path.exists(need_exp):
            return False
        cs = os.stat(cand_exp)
        ns = os.stat(need_exp)
    except OSError:
        return False
    # Some Windows filesystems return st_ino == 0 — don't false-positive.
    if cs.st_ino == 0 or ns.st_ino == 0:
        return False
    return cs.st_dev == ns.st_dev and cs.st_ino == ns.st_ino


def _path_hit(candidate: str, needle: str) -> bool:
    """Does the tool-call string reference the protected path (string layer)?"""
    norm_c = _normalize_path(candidate)
    if not norm_c or not needle:
        return False
    if norm_c == needle:
        return True
    if norm_c.startswith(needle + "/"):
        return True
    return needle in norm_c


def _extract_path_tokens(raw: str) -> list[str]:
    """Best-effort extraction of filesystem paths embedded in a string.

    A tool argument might be ``rm -rf /path/to/file``; we need the raw
    "/path/to/file" token to stat it for inode comparison. Splitting
    on whitespace + keeping tokens that contain path separators covers
    most shell-command shapes without building a full parser.
    """
    candidates: list[str] = [raw]
    for piece in re.split(r"[\s'\"]+", raw):
        piece = piece.strip()
        if not piece:
            continue
        if "/" in piece or (len(piece) > 2 and piece[1:3] in (":/", ":\\")):
            candidates.append(piece)
    return candidates


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
    # String-layer protected set. The inode-layer check runs over
    # _high_sensitivity_inodes() (concrete files inside the AgentGuard
    # home) PLUS any extra_paths the operator provided. That way a
    # caller who passes extra_paths=[audit_db_path] still gets inode
    # coverage for hardlink aliases of the specific file.
    protected: list[str] = list(default_protected_paths())
    extra_inodes: set[tuple[int, int]] = set()
    if extra_paths:
        for extra in extra_paths:
            if not extra:
                continue
            protected.append(_normalize_path(extra))
            try:
                exp = os.path.expandvars(os.path.expanduser(extra))
                if os.path.exists(exp):
                    st = os.stat(exp)
                    if st.st_ino != 0:
                        extra_inodes.add((st.st_dev, st.st_ino))
            except OSError:
                pass
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

    # 0b. High-sensitivity secret reference? Always MUTATE, even on read.
    # AG-BL-001.V1: operator.secret is the keying material for approval
    # HMAC AND audit sidecar. Standard-mode reads of AgentGuard state
    # are ordinarily allowed, but a read of the secret compromises both
    # defenses at once and must require operator approval.
    secret_files = _high_sensitivity_files()
    secret_norm = [_normalize_path(p) for p in secret_files]
    for raw in candidates:
        normalized_candidate = nfkc_stripped(raw)
        for i, needle in enumerate(secret_norm):
            if _path_hit(normalized_candidate, needle):
                return SelfProtectResult(
                    kind=ReferenceKind.MUTATE,
                    path_hit=needle,
                    arg_preview=raw[:120],
                    mutate_reason=f"high_sensitivity:{Path(secret_files[i]).name}",
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

    # 1b. Inode-layer fallback: attacker created a hardlink to a
    # protected FILE and passed the alias path. String compare missed;
    # compare against the concrete set of protected-file inodes.
    #
    # AG-BL-004.R5a.CARRYOVER (trial 4): the earlier version statted
    # the protected DIRECTORY (~/.agentguard/) — a directory has a
    # different inode from the files inside it, so an alias to
    # audit.db never matched. Now we stat each specific protected
    # FILE (audit.db, audit.db.hwm, operator.secret, agentguard.yaml,
    # .install-receipt) and compare candidate inodes against that set.
    if path_hit is None:
        protected_inodes = _high_sensitivity_inodes() | extra_inodes
        if protected_inodes:
            for raw in candidates:
                if not isinstance(raw, str):
                    continue
                for token in _extract_path_tokens(raw):
                    try:
                        expanded = os.path.expandvars(os.path.expanduser(token))
                        if not os.path.exists(expanded):
                            continue
                        st = os.stat(expanded)
                    except OSError:
                        continue
                    if st.st_ino == 0:
                        continue
                    if (st.st_dev, st.st_ino) in protected_inodes:
                        path_hit = protected[0] if protected else _normalize_path(token)
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
