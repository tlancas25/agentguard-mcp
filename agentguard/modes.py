"""Mode definitions and mode-specific defaults for AgentGuard.

Two modes exist:
- dev: Permissive pass-through. Logs everything, blocks nothing.
- federal: Strict enforcement. Deny by default, full scanning, signed audit.
"""

from __future__ import annotations

from enum import Enum
from dataclasses import dataclass, field


class Mode(str, Enum):
    """Operating mode for the AgentGuard gateway."""

    DEV = "dev"
    FEDERAL = "federal"


@dataclass(frozen=True)
class ModeDefaults:
    """Immutable defaults for a given operating mode."""

    mode: Mode
    deny_by_default: bool
    require_signing: bool
    pii_scan_enabled: bool
    injection_scan_enabled: bool
    tool_poisoning_scan_enabled: bool
    secret_scan_enabled: bool
    block_on_pii: bool
    block_on_injection: bool
    require_policy_bundle: bool
    default_policy_file: str
    description: str


DEV_DEFAULTS = ModeDefaults(
    mode=Mode.DEV,
    deny_by_default=False,
    require_signing=False,
    pii_scan_enabled=False,
    injection_scan_enabled=False,
    tool_poisoning_scan_enabled=True,
    secret_scan_enabled=True,
    block_on_pii=False,
    block_on_injection=False,
    require_policy_bundle=False,
    default_policy_file="agentguard/policies/defaults/dev_mode.yaml",
    description="Permissive pass-through. All tool calls are logged and forwarded.",
)

FEDERAL_DEFAULTS = ModeDefaults(
    mode=Mode.FEDERAL,
    deny_by_default=True,
    require_signing=True,
    pii_scan_enabled=True,
    injection_scan_enabled=True,
    tool_poisoning_scan_enabled=True,
    secret_scan_enabled=True,
    block_on_pii=True,
    block_on_injection=True,
    require_policy_bundle=True,
    default_policy_file="agentguard/policies/defaults/federal_mode.yaml",
    description="Strict enforcement. Deny by default. Full scanning. Signed audit.",
)

MODE_DEFAULTS: dict[Mode, ModeDefaults] = {
    Mode.DEV: DEV_DEFAULTS,
    Mode.FEDERAL: FEDERAL_DEFAULTS,
}


def get_defaults(mode: Mode) -> ModeDefaults:
    """Return the ModeDefaults for the given mode."""
    return MODE_DEFAULTS[mode]
