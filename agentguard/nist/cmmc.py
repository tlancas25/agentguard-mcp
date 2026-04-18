"""CMMC 2.0 requirement stubs for AgentGuard (v0.2 scaffold).

Provides structured definitions for Cybersecurity Maturity Model Certification
(CMMC) 2.0 requirements at Levels 1, 2, and 3. This module is a v0.2 scaffold
with representative requirements from each level. Full coverage of all 110+
Level 2 and 24 Level 3 requirements is planned for AgentGuard v0.2.

References:
- CMMC 2.0 Final Rule (effective December 16, 2024)
- Level 1: FAR 52.204-21 (15 requirements)
- Level 2: NIST SP 800-171 Rev 2 (110 requirements)
- Level 3: NIST SP 800-172 (24 additional requirements above Level 2)
- https://www.acq.osd.mil/cmmc/
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

CMMC_VERSION = "2.0"


class CmmcLevel(Enum):
    """CMMC 2.0 maturity levels.

    LEVEL_1: Foundational — 15 requirements, self-assessment, covers Federal
             Contract Information (FCI). Source: FAR 52.204-21.
    LEVEL_2: Advanced — 110 requirements, self-assessment or C3PAO, covers
             Controlled Unclassified Information (CUI). Source: NIST 800-171 Rev 2.
    LEVEL_3: Expert — Level 2 + 24 additional requirements, DoD assessment,
             covers high-value CUI. Source: NIST SP 800-172.
    """

    LEVEL_1 = 1
    LEVEL_2 = 2
    LEVEL_3 = 3


@dataclass(frozen=True)
class CmmcRequirement:
    """A single CMMC 2.0 requirement with AgentGuard implementation notes."""

    id: str                          # e.g., "FAR-AC.1.001" or "171-AC.1.001"
    level: CmmcLevel
    source_standard: str             # e.g., "FAR 52.204-21", "NIST 800-171 Rev 2"
    description: str
    agentguard_implementation: str


# ---------------------------------------------------------------------------
# Level 1 — FAR 52.204-21 (15 requirements, FCI)
# Representative sample: 10 of 15
# TODO (v0.2): add remaining 5 FAR 52.204-21 requirements
# ---------------------------------------------------------------------------
_LEVEL_1_REQUIREMENTS: list[CmmcRequirement] = [
    CmmcRequirement(
        id="FAR-AC.1.001",
        level=CmmcLevel.LEVEL_1,
        source_standard="FAR 52.204-21",
        description=(
            "Limit information system access to authorized users, processes acting "
            "on behalf of authorized users, and devices (including other systems)."
        ),
        agentguard_implementation=(
            "Policy engine enforces tool allowlist/denylist per agent identity. "
            "Federal mode deny-by-default ensures only authorized tool access. "
            "Implements NIST 800-53 AC-3 and AC-6."
        ),
    ),
    CmmcRequirement(
        id="FAR-AC.1.002",
        level=CmmcLevel.LEVEL_1,
        source_standard="FAR 52.204-21",
        description=(
            "Limit information system access to the types of transactions and "
            "functions that authorized users are permitted to execute."
        ),
        agentguard_implementation=(
            "Tool-level granular policy grants (per-tool allowlist entries) restrict "
            "each agent to exactly the transactions it needs. CM-7 Least Functionality "
            "is the primary control."
        ),
    ),
    CmmcRequirement(
        id="FAR-AC.1.003",
        level=CmmcLevel.LEVEL_1,
        source_standard="FAR 52.204-21",
        description=(
            "Verify and control/limit connections to external information systems."
        ),
        agentguard_implementation=(
            "SC-7 Boundary Protection is implemented by the proxy gateway. All "
            "connections to upstream MCP servers (external systems from the agent "
            "perspective) are logged and policy-evaluated. IA-9 validates upstream "
            "server identity in federal mode."
        ),
    ),
    CmmcRequirement(
        id="FAR-AC.1.004",
        level=CmmcLevel.LEVEL_1,
        source_standard="FAR 52.204-21",
        description=(
            "Control information posted or processed on publicly accessible information "
            "systems."
        ),
        agentguard_implementation=(
            "SI-15 Information Output Filtering scans tool results and arguments for "
            "PII and secrets before they are forwarded. AC-4 Information Flow "
            "Enforcement restricts sensitive data from flowing to external tool calls."
        ),
    ),
    CmmcRequirement(
        id="FAR-AU.2.001",
        level=CmmcLevel.LEVEL_1,
        source_standard="FAR 52.204-21",
        description=(
            "Create and retain system audit logs and records to the extent needed "
            "to enable the monitoring, analysis, investigation, and reporting of "
            "unlawful or unauthorized system activity."
        ),
        agentguard_implementation=(
            "Hash-chained SQLite audit log records every tool call, denial, detection, "
            "and session event. AU-2, AU-3, AU-9, AU-10, AU-12 are all implemented. "
            "Ed25519 signing provides cryptographic non-repudiation in federal mode."
        ),
    ),
    CmmcRequirement(
        id="FAR-CM.1.001",
        level=CmmcLevel.LEVEL_1,
        source_standard="FAR 52.204-21",
        description=(
            "Establish and maintain baseline configurations and inventories of "
            "organizational information systems."
        ),
        agentguard_implementation=(
            "agentguard.yaml configuration file defines the baseline. Policy bundles "
            "(YAML) define the tool inventory and access baseline. CM-7 deny-by-default "
            "ensures the baseline starts with zero permitted tools."
        ),
    ),
    CmmcRequirement(
        id="FAR-IA.1.001",
        level=CmmcLevel.LEVEL_1,
        source_standard="FAR 52.204-21",
        description=(
            "Identify information system users, processes acting on behalf of users, "
            "or devices."
        ),
        agentguard_implementation=(
            "Agent identity is extracted from the MCP initialize handshake "
            "(clientInfo name and version). A session UUID is generated per connection. "
            "IA-2 Identification and Authentication is implemented."
        ),
    ),
    CmmcRequirement(
        id="FAR-IA.1.002",
        level=CmmcLevel.LEVEL_1,
        source_standard="FAR 52.204-21",
        description=(
            "Authenticate the identities of those users, processes, or devices as a "
            "prerequisite to allowing access to organizational information systems."
        ),
        agentguard_implementation=(
            "Session UUID assignment at initialize time constitutes lightweight "
            "identity binding. IA-9 validates upstream MCP server identity in "
            "federal mode. Full PKI-based authentication is a v0.2 roadmap item."
        ),
    ),
    CmmcRequirement(
        id="FAR-SI.1.001",
        level=CmmcLevel.LEVEL_1,
        source_standard="FAR 52.204-21",
        description=(
            "Identify, report, and correct information and information system flaws "
            "in a timely manner."
        ),
        agentguard_implementation=(
            "POA&M report (agentguard/reports/poam.py) tracks open security findings "
            "from the audit log. Each finding includes description, severity, and "
            "remediation status. SI-4 System Monitoring detects attack patterns."
        ),
    ),
    CmmcRequirement(
        id="FAR-SI.1.002",
        level=CmmcLevel.LEVEL_1,
        source_standard="FAR 52.204-21",
        description=(
            "Provide protection from malicious code at appropriate locations within "
            "organizational information systems."
        ),
        agentguard_implementation=(
            "Prompt injection detector, tool poisoning detector, PII detector, and "
            "secret detector collectively implement malicious content screening at "
            "the MCP tool call layer. SI-7 Software Integrity covers tool description "
            "integrity."
        ),
    ),
    # TODO (v0.2): Add remaining 5 FAR 52.204-21 Level 1 requirements
]

# ---------------------------------------------------------------------------
# Level 2 — NIST SP 800-171 Rev 2 (110 requirements, CUI)
# Representative sample: 10 of 110
# TODO (v0.2): add remaining 100 NIST 800-171 Rev 2 requirements
# ---------------------------------------------------------------------------
_LEVEL_2_REQUIREMENTS: list[CmmcRequirement] = [
    CmmcRequirement(
        id="171-AC.2.005",
        level=CmmcLevel.LEVEL_2,
        source_standard="NIST SP 800-171 Rev 2",
        description=(
            "Provide privacy and security notices consistent with CUI rules."
        ),
        agentguard_implementation=(
            "Audit log records all CUI-adjacent tool calls. Federal mode policy "
            "can be configured to alert operators when tool calls involve CUI "
            "data categories. Notice generation is a v0.2 roadmap item."
        ),
    ),
    CmmcRequirement(
        id="171-AC.2.006",
        level=CmmcLevel.LEVEL_2,
        source_standard="NIST SP 800-171 Rev 2",
        description=(
            "Limit use of portable storage devices on external systems."
        ),
        agentguard_implementation=(
            "Tool allowlist controls which filesystem tools the agent can invoke. "
            "Removable media paths can be denied via denylist patterns in policy. "
            "AC-3 and CM-7 are the primary controls."
        ),
    ),
    CmmcRequirement(
        id="171-AU.2.041",
        level=CmmcLevel.LEVEL_2,
        source_standard="NIST SP 800-171 Rev 2",
        description=(
            "Ensure that the actions of individual system users can be uniquely "
            "traced to those users so they can be held accountable for their actions."
        ),
        agentguard_implementation=(
            "Every audit event is tied to the agent_id extracted from MCP initialize. "
            "Ed25519 signatures in federal mode make audit records non-repudiable. "
            "AU-10 Non-repudiation is the primary control."
        ),
    ),
    CmmcRequirement(
        id="171-AU.2.042",
        level=CmmcLevel.LEVEL_2,
        source_standard="NIST SP 800-171 Rev 2",
        description=(
            "Create and retain system audit logs and records to the extent needed "
            "to enable the monitoring, analysis, investigation, and reporting of "
            "unlawful or unauthorized system activity."
        ),
        agentguard_implementation=(
            "Hash-chained SQLite audit log with JSONL/CSV export. Records are "
            "retained in the database until explicitly purged. Exportable for "
            "SIEM ingestion. AU-2, AU-3, AU-9, AU-12 all implemented."
        ),
    ),
    CmmcRequirement(
        id="171-CM.2.061",
        level=CmmcLevel.LEVEL_2,
        source_standard="NIST SP 800-171 Rev 2",
        description=(
            "Establish and maintain baseline configurations and inventories of "
            "organizational systems (including hardware, software, firmware, and "
            "documentation) throughout the respective system development life cycles."
        ),
        agentguard_implementation=(
            "agentguard.yaml is the configuration baseline. Policy YAML files define "
            "the tool inventory baseline. Version-controlled policy files constitute "
            "the CM baseline artifact."
        ),
    ),
    CmmcRequirement(
        id="171-CM.2.062",
        level=CmmcLevel.LEVEL_2,
        source_standard="NIST SP 800-171 Rev 2",
        description=(
            "Establish and enforce security configuration settings for information "
            "technology products employed in organizational systems."
        ),
        agentguard_implementation=(
            "Federal mode enforces security configuration via deny-by-default policy. "
            "The federal_mode.yaml policy file is the enforceable security baseline. "
            "CM-7 Least Functionality is implemented in federal mode."
        ),
    ),
    CmmcRequirement(
        id="171-IA.3.083",
        level=CmmcLevel.LEVEL_2,
        source_standard="NIST SP 800-171 Rev 2",
        description=(
            "Use multifactor authentication for local and network access to privileged "
            "accounts and for network access to non-privileged accounts."
        ),
        agentguard_implementation=(
            "Out of scope for v0.1. AgentGuard extracts agent identity from MCP "
            "initialize but does not enforce MFA. MFA at the human-to-agent layer "
            "is an infrastructure concern. DoD PKI integration is a v0.2 roadmap item."
        ),
    ),
    CmmcRequirement(
        id="171-RA.2.141",
        level=CmmcLevel.LEVEL_2,
        source_standard="NIST SP 800-171 Rev 2",
        description=(
            "Periodically assess the risk to organizational operations, assets, "
            "and individuals resulting from the operation of organizational systems "
            "and the associated processing, storage, or transmission of CUI."
        ),
        agentguard_implementation=(
            "NIST AI RMF assessment reports (agentguard/reports/nist_ai_rmf.py) "
            "and FedRAMP evidence reports (agentguard/reports/fedramp.py) provide "
            "periodic risk assessment artifacts. POA&M tracks open findings. "
            "RA-5 Vulnerability Monitoring maps to threat feed integration (v0.2)."
        ),
    ),
    CmmcRequirement(
        id="171-SI.2.214",
        level=CmmcLevel.LEVEL_2,
        source_standard="NIST SP 800-171 Rev 2",
        description=(
            "Check the validity of the following information inputs."
        ),
        agentguard_implementation=(
            "SI-10 Information Input Validation is implemented by the full detector "
            "stack: prompt injection, PII, secret, and tool poisoning detectors "
            "validate all tool call inputs. Federal mode enforces deny on detection."
        ),
    ),
    CmmcRequirement(
        id="171-SI.2.216",
        level=CmmcLevel.LEVEL_2,
        source_standard="NIST SP 800-171 Rev 2",
        description=(
            "Monitor organizational systems, including the security alerts and "
            "advisories from organizations to identify threats."
        ),
        agentguard_implementation=(
            "SI-4 System Monitoring is implemented by the detector stack running "
            "on every tool call. RA-5 maps to CISA KEV and MITRE ATLAS threat feed "
            "integration planned for v0.2. Current detection is signature-based "
            "using internal pattern libraries."
        ),
    ),
    # TODO (v0.2): Add remaining 100 NIST 800-171 Rev 2 Level 2 requirements
]

# ---------------------------------------------------------------------------
# Level 3 — NIST SP 800-172 (24 additional requirements above Level 2)
# Representative sample: 10 of 24
# TODO (v0.2): add remaining 14 NIST 800-172 Level 3 requirements
# ---------------------------------------------------------------------------
_LEVEL_3_REQUIREMENTS: list[CmmcRequirement] = [
    CmmcRequirement(
        id="172-AC.3.012",
        level=CmmcLevel.LEVEL_3,
        source_standard="NIST SP 800-172",
        description=(
            "Protect wireless access using authentication and encryption."
        ),
        agentguard_implementation=(
            "Transport-level TLS in HTTP gateway mode addresses encryption in "
            "transit. Wireless-specific controls are an infrastructure concern "
            "outside the MCP proxy scope."
        ),
    ),
    CmmcRequirement(
        id="172-AC.3.017",
        level=CmmcLevel.LEVEL_3,
        source_standard="NIST SP 800-172",
        description=(
            "Separate the duties of individuals to reduce the risk of malevolent "
            "activity without collusion."
        ),
        agentguard_implementation=(
            "Policy bundles can assign separate tool permission sets to separate "
            "agent identities, enforcing duty separation at the MCP tool call level. "
            "Administrative separation (policy author vs. runtime operator) is "
            "supported via the YAML-based policy architecture."
        ),
    ),
    CmmcRequirement(
        id="172-AC.3.018",
        level=CmmcLevel.LEVEL_3,
        source_standard="NIST SP 800-172",
        description=(
            "Prevent non-privileged users from executing privileged functions and "
            "capture the execution of such functions in audit logs."
        ),
        agentguard_implementation=(
            "AC-6 Least Privilege and CM-7 Least Functionality prevent agents from "
            "calling privileged tools. All privilege escalation attempts are logged "
            "with AC-3 and AU-2 control tags. MITRE ATLAS AML.T0067 (Escape to Host) "
            "is the relevant threat technique."
        ),
    ),
    CmmcRequirement(
        id="172-AU.3.045",
        level=CmmcLevel.LEVEL_3,
        source_standard="NIST SP 800-172",
        description=(
            "Review audit logs to identify unauthorized system activity."
        ),
        agentguard_implementation=(
            "agentguard/audit_log.py:AuditLog.query provides structured query API "
            "for audit review. agentguard/audit_log.py:AuditLog.tail provides live "
            "streaming for real-time review. Automated review scheduling is a "
            "v0.2 roadmap item (AU-6 Audit Record Review)."
        ),
    ),
    CmmcRequirement(
        id="172-AU.3.046",
        level=CmmcLevel.LEVEL_3,
        source_standard="NIST SP 800-172",
        description=(
            "Automate analysis of audit logs to identify and act upon critical "
            "indicators."
        ),
        agentguard_implementation=(
            "Detection alerts in SI-4 (System Monitoring) automate identification "
            "of critical indicators. SIEM export (JSONL/CSV) enables downstream "
            "automated analysis. In-process automated response is a v0.2 roadmap item."
        ),
    ),
    CmmcRequirement(
        id="172-CM.3.068",
        level=CmmcLevel.LEVEL_3,
        source_standard="NIST SP 800-172",
        description=(
            "Restrict, disable, or prevent the use of nonessential programs, "
            "functions, ports, protocols, and services."
        ),
        agentguard_implementation=(
            "CM-7 deny-by-default in federal mode is the primary implementation. "
            "Every MCP tool not on the allowlist is restricted. The allowlist is "
            "the authoritative set of essential functions. Non-essential MCP servers "
            "are excluded via the upstream server allowlist (IA-9)."
        ),
    ),
    CmmcRequirement(
        id="172-IA.3.083",
        level=CmmcLevel.LEVEL_3,
        source_standard="NIST SP 800-172",
        description=(
            "Employ replay-resistant authentication mechanisms for network access "
            "to privileged and non-privileged accounts."
        ),
        agentguard_implementation=(
            "Ed25519 signed audit events include timestamps and sequential hash "
            "chains that are replay-resistant by construction. Full replay-resistant "
            "authentication at the MCP session layer (e.g., challenge-response) "
            "is a v0.2 roadmap item."
        ),
    ),
    CmmcRequirement(
        id="172-RA.3.077",
        level=CmmcLevel.LEVEL_3,
        source_standard="NIST SP 800-172",
        description=(
            "Develop, implement, and maintain processes to actively identify and "
            "remove unauthorized software and detect and respond to indicators of "
            "compromise."
        ),
        agentguard_implementation=(
            "Tool poisoning detector actively identifies unauthorized embedded "
            "instructions in MCP tool software (SI-7). RA-5 maps to threat feed "
            "integration (v0.2). POA&M tracks active indicators of compromise. "
            "MITRE ATLAS AML.T0066 (Poisoned AI Agent Tool) is the target threat."
        ),
    ),
    CmmcRequirement(
        id="172-SI.3.218",
        level=CmmcLevel.LEVEL_3,
        source_standard="NIST SP 800-172",
        description=(
            "Implement a system security engineering approach integrating information "
            "security requirements into all phases of system development."
        ),
        agentguard_implementation=(
            "AgentGuard is designed as a security-first MCP proxy. NIST 800-53 "
            "controls are built in from the start. The dual-mode design integrates "
            "security into the development workflow (dev mode) and production "
            "enforcement (federal mode). NIST AI 600-1 and MITRE ATLAS mappings "
            "are embedded in the codebase."
        ),
    ),
    CmmcRequirement(
        id="172-SI.3.219",
        level=CmmcLevel.LEVEL_3,
        source_standard="NIST SP 800-172",
        description=(
            "Implement a process for proactively identifying and mitigating "
            "supply chain risks."
        ),
        agentguard_implementation=(
            "Value chain risk process: tool poisoning detector scans MCP tool "
            "supply (SI-7, RA-5). Upstream server allowlist restricts supply chain "
            "to approved vendors (IA-9). MITRE ATLAS AML.T0066 is the primary "
            "threat technique. CMMC Level 3 supply chain artifacts are a v0.2 "
            "evidence pack item."
        ),
    ),
    # TODO (v0.2): Add remaining 14 NIST 800-172 Level 3 requirements
]

# Master requirements list (all levels combined)
ALL_REQUIREMENTS: list[CmmcRequirement] = (
    _LEVEL_1_REQUIREMENTS + _LEVEL_2_REQUIREMENTS + _LEVEL_3_REQUIREMENTS
)

# Index by ID
REQUIREMENTS_BY_ID: dict[str, CmmcRequirement] = {r.id: r for r in ALL_REQUIREMENTS}


def get_requirements_for_level(level: CmmcLevel) -> list[CmmcRequirement]:
    """Return all requirements for a given CMMC level.

    Note: In CMMC 2.0, Level 2 includes Level 1 requirements, and Level 3
    includes all Level 1 and 2 requirements. This function returns only the
    requirements defined at the specified level. For cumulative requirements,
    iterate through all levels up to and including the target level.

    Args:
        level: The CMMC level to retrieve requirements for.

    Returns:
        List of CmmcRequirement for the specified level.
    """
    return [r for r in ALL_REQUIREMENTS if r.level == level]


def get_cumulative_requirements(level: CmmcLevel) -> list[CmmcRequirement]:
    """Return all requirements at or below the specified level (cumulative).

    CMMC 2.0 is cumulative: Level 3 requires all Level 1 + Level 2 +
    Level 3 requirements.

    Args:
        level: The maximum CMMC level to include.

    Returns:
        List of CmmcRequirement for all levels up to and including the target.
    """
    return [r for r in ALL_REQUIREMENTS if r.level.value <= level.value]
