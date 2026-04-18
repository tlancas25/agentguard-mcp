"""Event-type to NIST 800-53 control mappings for AgentGuard.

Maps each audit event type to the NIST controls that apply when that
event occurs. Also maps to OWASP LLM Top 10 2025 IDs, MITRE ATLAS v5.4.0
technique IDs, and NIST AI 600-1 risk areas.

Used to annotate audit events and populate compliance reports.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Final


@dataclass(frozen=True)
class FrameworkMapping:
    """Multi-framework mapping for a single AgentGuard event type.

    Aggregates control and technique IDs across NIST 800-53, OWASP LLM 2025,
    MITRE ATLAS v5.4.0, and NIST AI 600-1 for a given event type.
    """

    nist_controls: list[str] = field(default_factory=list)
    owasp_llm: list[str] = field(default_factory=list)
    mitre_atlas: list[str] = field(default_factory=list)
    nist_ai_600_1_risk_areas: list[str] = field(default_factory=list)

# Event types used in audit log
EVENT_TOOL_CALL = "tool_call"
EVENT_TOOL_DENIED = "tool_denied"
EVENT_TOOL_ALLOWED = "tool_allowed"
EVENT_PII_DETECTED = "pii_detected"
EVENT_INJECTION_DETECTED = "injection_detected"
EVENT_SECRET_DETECTED = "secret_detected"
EVENT_TOOL_POISONING_DETECTED = "tool_poisoning_detected"
EVENT_SESSION_START = "session_start"
EVENT_SESSION_END = "session_end"
EVENT_AUDIT_VERIFY = "audit_verify"
EVENT_POLICY_LOADED = "policy_loaded"
EVENT_CHAIN_VIOLATION = "chain_violation"
EVENT_RESOURCES_READ = "resources_read"
EVENT_PROMPTS_GET = "prompts_get"

# Map: event_type -> list of NIST control IDs that apply
# Preserved for backward compatibility. See EVENT_FRAMEWORK_MAP for full multi-framework mapping.
EVENT_CONTROL_MAP: Final[dict[str, list[str]]] = {
    EVENT_TOOL_CALL: ["AU-2", "AU-3", "AU-12"],
    EVENT_TOOL_DENIED: ["AC-3", "AC-6", "AU-2", "AU-3", "AU-12"],
    EVENT_TOOL_ALLOWED: ["AC-3", "AU-2", "AU-3", "AU-12"],
    EVENT_PII_DETECTED: ["SI-10", "SC-28", "AU-2", "AU-12"],
    EVENT_INJECTION_DETECTED: ["SI-10", "SI-4", "AU-2", "AU-12"],
    EVENT_SECRET_DETECTED: ["SI-10", "SC-8", "AC-3", "AU-2"],
    EVENT_TOOL_POISONING_DETECTED: ["SI-10", "SI-4", "AC-3", "AU-2"],
    EVENT_SESSION_START: ["IA-2", "AU-2", "AU-3"],
    EVENT_SESSION_END: ["IA-2", "AU-2"],
    EVENT_AUDIT_VERIFY: ["AU-9", "AU-10"],
    EVENT_POLICY_LOADED: ["AC-3", "AU-2"],
    EVENT_CHAIN_VIOLATION: ["AU-9", "AU-10", "SI-4"],
    EVENT_RESOURCES_READ: ["AC-3", "AU-2", "AU-3", "AU-12"],
    EVENT_PROMPTS_GET: ["AC-3", "AU-2", "AU-3", "AU-12"],
}

# Full multi-framework mapping: event_type -> FrameworkMapping
# OWASP IDs follow the 2025 list (e.g., "LLM01:2025").
# MITRE ATLAS technique IDs follow v5.4.0 (e.g., "AML.T0051.000").
# NIST AI 600-1 risk area names match GenAIRiskArea enum values.
EVENT_FRAMEWORK_MAP: Final[dict[str, FrameworkMapping]] = {
    EVENT_TOOL_CALL: FrameworkMapping(
        nist_controls=["AU-2", "AU-3", "AU-12"],
        owasp_llm=["LLM06:2025"],           # Excessive Agency — any tool call is agency
        mitre_atlas=[],
        nist_ai_600_1_risk_areas=["information_security"],
    ),
    EVENT_TOOL_DENIED: FrameworkMapping(
        nist_controls=["AC-3", "AC-6", "CM-7", "AU-2", "AU-3", "AU-12"],
        owasp_llm=["LLM06:2025"],
        mitre_atlas=[],
        nist_ai_600_1_risk_areas=["information_security"],
    ),
    EVENT_TOOL_ALLOWED: FrameworkMapping(
        nist_controls=["AC-3", "AU-2", "AU-3", "AU-12"],
        owasp_llm=["LLM06:2025"],
        mitre_atlas=[],
        nist_ai_600_1_risk_areas=["information_security"],
    ),
    EVENT_PII_DETECTED: FrameworkMapping(
        nist_controls=["SI-10", "SI-15", "AC-4", "SC-28", "AU-2", "AU-12"],
        owasp_llm=["LLM02:2025"],           # Sensitive Information Disclosure
        mitre_atlas=["AML.T0048"],           # External Harms (closest ATLAS mapping)
        nist_ai_600_1_risk_areas=["data_privacy", "information_security"],
    ),
    EVENT_INJECTION_DETECTED: FrameworkMapping(
        nist_controls=["SI-10", "SI-4", "AU-2", "AU-12"],
        owasp_llm=["LLM01:2025"],           # Prompt Injection
        mitre_atlas=["AML.T0051.000", "AML.T0051.001"],  # Direct + Indirect PI
        nist_ai_600_1_risk_areas=["information_security"],
    ),
    EVENT_SECRET_DETECTED: FrameworkMapping(
        nist_controls=["SI-10", "SI-15", "SC-8", "AC-3", "AC-4", "AU-2"],
        owasp_llm=["LLM02:2025"],           # Sensitive Information Disclosure
        mitre_atlas=["AML.T0051.000"],
        nist_ai_600_1_risk_areas=["information_security", "data_privacy"],
    ),
    EVENT_TOOL_POISONING_DETECTED: FrameworkMapping(
        nist_controls=["SI-7", "SI-10", "SI-4", "RA-5", "AC-3", "AU-2"],
        owasp_llm=["LLM03:2025", "LLM07:2025"],  # Supply Chain + System Prompt Leakage
        mitre_atlas=["AML.T0066", "AML.T0051.001"],  # Poisoned Tool + Indirect PI
        nist_ai_600_1_risk_areas=["value_chain_integration", "information_security"],
    ),
    EVENT_SESSION_START: FrameworkMapping(
        nist_controls=["IA-2", "IA-9", "AU-2", "AU-3"],
        owasp_llm=[],
        mitre_atlas=[],
        nist_ai_600_1_risk_areas=["information_security"],
    ),
    EVENT_SESSION_END: FrameworkMapping(
        nist_controls=["IA-2", "AU-2"],
        owasp_llm=[],
        mitre_atlas=[],
        nist_ai_600_1_risk_areas=["information_security"],
    ),
    EVENT_AUDIT_VERIFY: FrameworkMapping(
        nist_controls=["AU-9", "AU-10"],
        owasp_llm=[],
        mitre_atlas=[],
        nist_ai_600_1_risk_areas=["information_security"],
    ),
    EVENT_POLICY_LOADED: FrameworkMapping(
        nist_controls=["AC-3", "CM-7", "AU-2"],
        owasp_llm=[],
        mitre_atlas=["AML.T0065"],           # Modify AI Agent Configuration
        nist_ai_600_1_risk_areas=["information_security"],
    ),
    EVENT_CHAIN_VIOLATION: FrameworkMapping(
        nist_controls=["AU-9", "AU-10", "SI-4", "SI-7"],
        owasp_llm=[],
        mitre_atlas=["AML.T0063"],           # Memory Manipulation
        nist_ai_600_1_risk_areas=["information_security"],
    ),
    EVENT_RESOURCES_READ: FrameworkMapping(
        nist_controls=["AC-3", "AC-4", "AU-2", "AU-3", "AU-12"],
        owasp_llm=["LLM02:2025"],
        mitre_atlas=[],
        nist_ai_600_1_risk_areas=["information_security", "data_privacy"],
    ),
    EVENT_PROMPTS_GET: FrameworkMapping(
        nist_controls=["AC-3", "AU-2", "AU-3", "AU-12"],
        owasp_llm=["LLM07:2025"],           # System Prompt Leakage
        mitre_atlas=["AML.T0051.001"],       # Indirect Prompt Injection
        nist_ai_600_1_risk_areas=["information_security"],
    ),
}


def get_controls_for_event(event_type: str) -> list[str]:
    """Return the NIST control IDs that apply to a given event type.

    Args:
        event_type: One of the EVENT_* constants defined in this module.

    Returns:
        List of control IDs, or a minimal fallback set if event type is unknown.
    """
    return EVENT_CONTROL_MAP.get(event_type, ["AU-2"])


def get_framework_mapping(event_type: str) -> FrameworkMapping:
    """Return the full multi-framework mapping for a given event type.

    Includes NIST 800-53 controls, OWASP LLM 2025 IDs, MITRE ATLAS technique
    IDs, and NIST AI 600-1 risk area names.

    Args:
        event_type: One of the EVENT_* constants defined in this module.

    Returns:
        FrameworkMapping, or a minimal fallback if event type is unknown.
    """
    return EVENT_FRAMEWORK_MAP.get(
        event_type,
        FrameworkMapping(nist_controls=["AU-2"]),
    )


def get_all_event_types() -> list[str]:
    """Return all known event type strings."""
    return list(EVENT_CONTROL_MAP.keys())


def get_controls_summary() -> dict[str, list[str]]:
    """Return a reverse mapping: control_id -> list of event types it covers."""
    summary: dict[str, list[str]] = {}
    for event_type, controls in EVENT_CONTROL_MAP.items():
        for control in controls:
            if control not in summary:
                summary[control] = []
            summary[control].append(event_type)
    return summary
