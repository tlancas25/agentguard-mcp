"""Policy evaluation engine for AgentGuard.

Evaluates MCP tool call requests against YAML policy bundles and returns
a Decision indicating whether to allow, deny, or log the call.

NIST 800-53 controls addressed:
- AC-3: Access Enforcement (tool allowlist/denylist)
- AC-6: Least Privilege (deny by default in federal mode)
- SI-10: Information Input Validation (detector integration)
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

import yaml

from agentguard.detectors.normalize import ZERO_WIDTH_CHARS, nfkc_stripped
from agentguard.modes import Mode

# Characters an attacker might splice into a tool name to dodge exact
# allowlist/denylist comparison. We reject any tool_name that contains
# zero-width / control chars after normalization — a bare-naked
# "fire_missile" and "fire\u200bmissile" must not both evaluate to the
# same cleaned string unless the normalization pipeline strips the
# invisible glyph first. (AG-MT-001)
_ZERO_WIDTH_SET = set(ZERO_WIDTH_CHARS)
_CONTROL_CHAR_RE = re.compile(r"[\x00-\x08\x0b-\x0c\x0e-\x1f\x7f]")

logger = logging.getLogger(__name__)

ACTION_ALLOW = "allow"
ACTION_DENY = "deny"
ACTION_LOG = "log"


def _normalize_tool_name(tool_name: str) -> str:
    """Return the canonical form used for allowlist/denylist comparison.

    Strips zero-widths, applies NFKC normalization, casefolds, and trims
    surrounding whitespace. Mirrors the approach self_protect uses for
    path comparison so ``Shell``, ``SHELL``, ``shell`` (trailing space),
    ``shell\u200b`` (ZWSP), and ``ｓhell`` (fullwidth) all collapse to
    the same key.
    """
    if not isinstance(tool_name, str):
        return ""
    return nfkc_stripped(tool_name).strip().casefold()


def _tool_name_contains_invisible(tool_name: str) -> bool:
    """True if tool_name has zero-width or control chars — likely evasion."""
    if not isinstance(tool_name, str):
        return False
    for ch in tool_name:
        if ch in _ZERO_WIDTH_SET:
            return True
    return bool(_CONTROL_CHAR_RE.search(tool_name))


def _tool_name_is_confusable(tool_name: str) -> bool:
    """True if tool_name contains non-ASCII characters after NFKC.

    AG-MT-001.OPEN: NFKC normalization preserves Cyrillic / Greek /
    fullwidth-ASCII homoglyphs (``ѕhell``, ``ｓhell``, etc.), letting an
    attacker sidestep an ASCII denylist. Legitimate MCP tool names are
    ASCII — reject anything else in federal and standard postures.
    Operators who really need non-ASCII names can add them to an
    allowlist rule with the exact codepoints spelled out, which fails
    closed by default.
    """
    if not isinstance(tool_name, str) or not tool_name:
        return False
    normalized = nfkc_stripped(tool_name)
    try:
        normalized.encode("ascii")
    except UnicodeEncodeError:
        return True
    return False


@dataclass
class Decision:
    """The result of evaluating a tool call against policy."""

    action: str  # "allow" | "deny" | "log"
    reason: str
    matched_rule: Optional[str] = None
    nist_controls: list[str] = field(default_factory=list)
    policy_bundle: Optional[str] = None

    @property
    def is_allowed(self) -> bool:
        """Return True if the tool call should proceed."""
        return self.action in (ACTION_ALLOW, ACTION_LOG)

    @property
    def is_denied(self) -> bool:
        """Return True if the tool call should be blocked."""
        return self.action == ACTION_DENY


@dataclass
class PolicyBundle:
    """A loaded, parsed policy bundle."""

    name: str
    source_path: str
    default_action: str = ACTION_LOG
    tool_allowlist: list[str] = field(default_factory=list)
    tool_denylist: list[str] = field(default_factory=list)
    rules: list[dict[str, Any]] = field(default_factory=list)
    pii_scan: bool = False
    injection_scan: bool = False
    tool_poisoning_scan: bool = False
    require_signing: bool = False

    @classmethod
    def from_yaml(cls, path: Path) -> "PolicyBundle":
        """Load a PolicyBundle from a YAML file."""
        with open(path) as f:
            data = yaml.safe_load(f) or {}

        return cls(
            name=data.get("name", path.stem),
            source_path=str(path),
            default_action=data.get("default_action", ACTION_LOG),
            tool_allowlist=data.get("tool_allowlist", []),
            tool_denylist=data.get("tool_denylist", []),
            rules=data.get("rules", []),
            pii_scan=data.get("pii_scan", False),
            injection_scan=data.get("injection_scan", False),
            tool_poisoning_scan=data.get("tool_poisoning_scan", False),
            require_signing=data.get("require_signing", False),
        )


class PolicyEngine:
    """Evaluates tool call requests against loaded policy bundles.

    Evaluation order:
    1. Check tool denylist (explicit deny wins)
    2. Check tool allowlist (explicit allow)
    3. Check named rules (first match wins)
    4. Apply default action (from bundle or mode)
    """

    def __init__(self, mode: Mode, bundles: Optional[list[PolicyBundle]] = None) -> None:
        """Initialize the policy engine.

        Args:
            mode: Operating mode (dev or federal).
            bundles: Pre-loaded policy bundles. If empty, mode defaults apply.
        """
        self.mode = mode
        self.bundles: list[PolicyBundle] = bundles or []

    @classmethod
    def from_config(
        cls,
        mode: Mode,
        bundle_paths: list[str],
    ) -> "PolicyEngine":
        """Create a PolicyEngine by loading bundle files from paths."""
        bundles: list[PolicyBundle] = []
        for path_str in bundle_paths:
            path = Path(path_str)
            if not path.exists():
                logger.warning("Policy bundle not found: %s", path_str)
                continue
            try:
                bundle = PolicyBundle.from_yaml(path)
                bundles.append(bundle)
                logger.info("Loaded policy bundle: %s (%s)", bundle.name, path_str)
            except Exception as e:
                logger.error("Failed to load policy bundle %s: %s", path_str, e)

        return cls(mode=mode, bundles=bundles)

    def evaluate(
        self,
        tool_name: str,
        tool_args: dict[str, Any],
        agent_id: str,
    ) -> Decision:
        """Evaluate a tool call and return a Decision.

        In dev mode, the default action is 'log' (never deny unless explicitly listed).
        In federal mode, the default is 'deny' unless explicitly allowed.

        Args:
            tool_name: The MCP tool name being called.
            tool_args: The arguments passed to the tool.
            agent_id: Identity of the calling agent.

        Returns:
            Decision with action, reason, matched rule, and NIST controls.
        """
        if not self.bundles:
            # No policy bundles: dev mode logs, federal mode denies
            if self.mode == Mode.FEDERAL:
                return Decision(
                    action=ACTION_DENY,
                    reason="No policy bundles loaded. Federal mode requires explicit policy.",
                    nist_controls=["AC-3", "AC-6"],
                )
            return Decision(
                action=ACTION_LOG,
                reason="No policy bundles. Dev mode: logging all tool calls.",
                nist_controls=["AU-2"],
            )

        for bundle in self.bundles:
            decision = self._evaluate_bundle(bundle, tool_name, tool_args, agent_id)
            if decision is not None:
                return decision

        # No bundle produced a decision — fall back to mode default
        return self._mode_default(tool_name)

    def _evaluate_bundle(
        self,
        bundle: PolicyBundle,
        tool_name: str,
        tool_args: dict[str, Any],
        agent_id: str,
    ) -> Optional[Decision]:
        """Evaluate a single bundle. Returns Decision or None if no match."""

        # AG-MT-001 evasion guard: refuse tool names containing zero-width
        # or control characters, OR non-ASCII homoglyphs. Legitimate MCP
        # tool names never use those; their presence is an evasion signal.
        if _tool_name_contains_invisible(tool_name):
            action = ACTION_DENY if self.mode == Mode.FEDERAL else ACTION_LOG
            return Decision(
                action=action,
                reason=(
                    f"Tool name {tool_name!r} contains zero-width or control "
                    "characters; refused as likely denylist evasion."
                ),
                matched_rule=f"invisible_char_reject:{bundle.name}",
                nist_controls=["AC-3", "SI-10"],
                policy_bundle=bundle.name,
            )
        if _tool_name_is_confusable(tool_name):
            action = ACTION_DENY if self.mode == Mode.FEDERAL else ACTION_LOG
            return Decision(
                action=action,
                reason=(
                    f"Tool name {tool_name!r} contains non-ASCII "
                    "characters after NFKC normalization; refused as "
                    "likely confusable/homoglyph evasion."
                ),
                matched_rule=f"confusable_reject:{bundle.name}",
                nist_controls=["AC-3", "SI-10"],
                policy_bundle=bundle.name,
            )

        normalized_tool = _normalize_tool_name(tool_name)
        denylist_norm = {_normalize_tool_name(t) for t in bundle.tool_denylist}
        allowlist_norm = {_normalize_tool_name(t) for t in bundle.tool_allowlist}

        # 1. Explicit denylist
        if normalized_tool in denylist_norm:
            action = ACTION_DENY if self.mode == Mode.FEDERAL else ACTION_LOG
            return Decision(
                action=action,
                reason=(
                    f"Tool '{tool_name}' is in the denylist."
                    + (
                        " Denied (federal mode)."
                        if action == ACTION_DENY
                        else " Logged (dev mode)."
                    )
                ),
                matched_rule=f"tool_denylist:{bundle.name}",
                nist_controls=["AC-3", "AC-6"],
                policy_bundle=bundle.name,
            )

        # 2. Explicit allowlist
        if bundle.tool_allowlist:
            if normalized_tool in allowlist_norm:
                return Decision(
                    action=ACTION_ALLOW,
                    reason=f"Tool '{tool_name}' is in the allowlist.",
                    matched_rule=f"tool_allowlist:{bundle.name}",
                    nist_controls=["AC-3"],
                    policy_bundle=bundle.name,
                )
            # Allowlist is populated but tool not in it
            action = ACTION_DENY if self.mode == Mode.FEDERAL else ACTION_LOG
            return Decision(
                action=action,
                reason=(
                    f"Tool '{tool_name}' not in allowlist."
                    + (" Denied (federal mode)." if action == ACTION_DENY else " Logged (dev mode).")
                ),
                matched_rule=f"allowlist_miss:{bundle.name}",
                nist_controls=["AC-3", "AC-6"],
                policy_bundle=bundle.name,
            )

        # 3. Named rules
        for rule in bundle.rules:
            match = self._match_rule(rule, tool_name, tool_args)
            if match:
                rule_action = rule.get("action", bundle.default_action)
                # Dev mode: downgrade denies to log
                if self.mode == Mode.DEV and rule_action == ACTION_DENY:
                    rule_action = ACTION_LOG
                return Decision(
                    action=rule_action,
                    reason=rule.get("reason", f"Matched rule: {rule.get('name', 'unnamed')}"),
                    matched_rule=rule.get("name", "unnamed"),
                    nist_controls=rule.get("nist_controls", ["AC-3"]),
                    policy_bundle=bundle.name,
                )

        # 4. Bundle default
        action = bundle.default_action
        if self.mode == Mode.DEV and action == ACTION_DENY:
            action = ACTION_LOG

        return Decision(
            action=action,
            reason=f"Bundle default action: {action}",
            matched_rule=f"default:{bundle.name}",
            nist_controls=["AU-2"],
            policy_bundle=bundle.name,
        )

    @staticmethod
    def _match_rule(rule: dict[str, Any], tool_name: str, tool_args: dict[str, Any]) -> bool:
        """Return True if a rule matches the given tool call.

        AG-MT-001.R3a: the earlier implementation compared ``rule_tool``
        to ``tool_name`` with raw ``!=``, so a rule ``{tool: shell,
        action: deny}`` would not fire for ``Shell``, ``SHELL``,
        ``shell\u200b``, ``ｓhell``, etc. Normalize both sides with the
        same pipeline denylists and allowlists use so the three
        matching paths behave consistently.
        """
        # Match by tool name (case/NFKC/whitespace-normalized)
        rule_tool = rule.get("tool")
        if rule_tool and rule_tool != "*":
            if _normalize_tool_name(rule_tool) != _normalize_tool_name(tool_name):
                return False

        # Match by tool name prefix (normalized on both sides too)
        rule_prefix = rule.get("tool_prefix")
        if rule_prefix:
            norm_prefix = _normalize_tool_name(rule_prefix)
            norm_name = _normalize_tool_name(tool_name)
            if not norm_name.startswith(norm_prefix):
                return False

        # Match by arg key presence
        required_args = rule.get("has_args", [])
        for arg_key in required_args:
            if arg_key not in tool_args:
                return False

        return True

    def _mode_default(self, tool_name: str) -> Decision:
        """Return the mode-level default decision."""
        if self.mode == Mode.FEDERAL:
            return Decision(
                action=ACTION_DENY,
                reason=f"Tool '{tool_name}' not matched by any policy. Federal mode denies by default.",
                nist_controls=["AC-3", "AC-6"],
            )
        return Decision(
            action=ACTION_LOG,
            reason=f"Tool '{tool_name}' logged. Dev mode permits all unmatched calls.",
            nist_controls=["AU-2"],
        )

    def validate_bundle_file(self, path: Path) -> list[str]:
        """Validate a policy YAML file. Returns list of errors (empty = valid)."""
        errors: list[str] = []
        try:
            bundle = PolicyBundle.from_yaml(path)
        except Exception as e:
            return [f"Failed to parse YAML: {e}"]

        if bundle.default_action not in (ACTION_ALLOW, ACTION_DENY, ACTION_LOG):
            errors.append(
                f"Invalid default_action '{bundle.default_action}'. "
                f"Must be 'allow', 'deny', or 'log'."
            )

        for i, rule in enumerate(bundle.rules):
            if "action" not in rule:
                errors.append(f"Rule {i} missing 'action' field.")
            elif rule["action"] not in (ACTION_ALLOW, ACTION_DENY, ACTION_LOG):
                errors.append(
                    f"Rule {i} has invalid action '{rule['action']}'."
                )
            if "tool" not in rule and "tool_prefix" not in rule:
                errors.append(f"Rule {i} has no 'tool' or 'tool_prefix' matcher.")

        return errors
