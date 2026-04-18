"""NIST 800-53 Rev 5.2 control library for AgentGuard.

Each ControlDefinition represents a NIST 800-53 Rev 5.2 security control
implemented or addressed by AgentGuard. These are used to annotate audit
events and generate compliance reports.

Reference: NIST SP 800-53 Rev 5.2
https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final
"""

from __future__ import annotations

from dataclasses import dataclass, field

NIST_800_53_VERSION = "Rev 5.2"


@dataclass(frozen=True)
class ControlDefinition:
    """A single NIST 800-53 Rev 5 control as implemented by AgentGuard."""

    control_id: str
    family: str
    title: str
    description: str
    agentguard_implementation: str
    code_references: list[str] = field(default_factory=list)
    enhancement_ids: list[str] = field(default_factory=list)


# Control family prefixes
FAMILY_AC = "Access Control"
FAMILY_AU = "Audit and Accountability"
FAMILY_CM = "Configuration Management"
FAMILY_IA = "Identification and Authentication"
FAMILY_RA = "Risk Assessment"
FAMILY_SC = "System and Communications Protection"
FAMILY_SI = "System and Information Integrity"

CONTROLS: dict[str, ControlDefinition] = {
    "AC-3": ControlDefinition(
        control_id="AC-3",
        family=FAMILY_AC,
        title="Access Enforcement",
        description=(
            "Enforce approved authorizations for logical access to information "
            "and system resources in accordance with applicable access control policies."
        ),
        agentguard_implementation=(
            "The policy engine enforces tool allowlists and denylists on every "
            "MCP tool call. In federal mode, a tool not in the allowlist is denied "
            "before it reaches the upstream MCP server. The decision is logged with "
            "the AC-3 control tag."
        ),
        code_references=["agentguard/policy_engine.py:PolicyEngine.evaluate"],
    ),
    "AC-4": ControlDefinition(
        control_id="AC-4",
        family=FAMILY_AC,
        title="Information Flow Enforcement",
        description=(
            "Enforce approved authorizations for controlling the flow of information "
            "within the system and between connected systems based on applicable "
            "information flow control policies."
        ),
        agentguard_implementation=(
            "AgentGuard intercepts every downstream tool call and applies information "
            "flow policy before the request is forwarded. In federal mode, tool calls "
            "carrying PII, secrets, or injection patterns are blocked, preventing "
            "unauthorized data flows from the agent context to external MCP servers. "
            "Each flow decision is logged with the AC-4 control tag."
        ),
        code_references=[
            "agentguard/proxy.py",
            "agentguard/policy_engine.py:PolicyEngine.evaluate",
            "agentguard/detectors/pii.py",
            "agentguard/detectors/secrets.py",
        ],
    ),
    "AC-6": ControlDefinition(
        control_id="AC-6",
        family=FAMILY_AC,
        title="Least Privilege",
        description=(
            "Employ the principle of least privilege, allowing only authorized "
            "accesses for users (or processes acting on behalf of users) that are "
            "necessary to accomplish assigned organizational tasks."
        ),
        agentguard_implementation=(
            "Federal mode defaults to deny-by-default. AI agents are granted access "
            "only to tools explicitly listed in the policy allowlist. No implicit "
            "permissions exist in federal mode."
        ),
        code_references=[
            "agentguard/modes.py:FEDERAL_DEFAULTS",
            "agentguard/policy_engine.py:PolicyEngine._mode_default",
        ],
    ),
    "AC-7": ControlDefinition(
        control_id="AC-7",
        family=FAMILY_AC,
        title="Unsuccessful Logon Attempts",
        description=(
            "Enforce a limit of consecutive invalid logon attempts by a user "
            "during a specified time period."
        ),
        agentguard_implementation=(
            "AgentGuard logs repeated policy denials per agent identity. The audit "
            "log records each denied tool call, enabling threshold alerting and "
            "session termination policies based on denial frequency."
        ),
        code_references=[
            "agentguard/audit_log.py:AuditLog.append_event",
            "agentguard/proxy.py",
        ],
    ),
    "AC-17": ControlDefinition(
        control_id="AC-17",
        family=FAMILY_AC,
        title="Remote Access",
        description=(
            "Establish and document usage restrictions, configuration/connection "
            "requirements, and implementation guidance for each type of remote access "
            "allowed."
        ),
        agentguard_implementation=(
            "The HTTP gateway mode enforces transport-level policy for remote MCP "
            "clients. All remote connections are logged with agent identity and "
            "timestamp. TLS enforcement is configurable."
        ),
        code_references=["agentguard/gateway.py"],
    ),
    "AU-2": ControlDefinition(
        control_id="AU-2",
        family=FAMILY_AU,
        title="Event Logging",
        description=(
            "Identify the types of events that the system is capable of logging "
            "in support of the audit function."
        ),
        agentguard_implementation=(
            "Every MCP tool call generates an audit event regardless of mode. "
            "Logged event types include: tool_call, tool_denied, pii_detected, "
            "injection_detected, secret_detected, tool_poisoning_detected, "
            "session_start, session_end."
        ),
        code_references=[
            "agentguard/audit_log.py",
            "agentguard/proxy.py",
        ],
    ),
    "AU-3": ControlDefinition(
        control_id="AU-3",
        family=FAMILY_AU,
        title="Content of Audit Records",
        description=(
            "Ensure that audit records contain information that establishes what "
            "type of event occurred, when the event occurred, where the event "
            "occurred, the source of the event, the outcome of the event, and "
            "the identity of any individuals or subjects associated with the event."
        ),
        agentguard_implementation=(
            "Each audit event includes: timestamp (UTC ISO 8601), agent_id, "
            "event_type, tool_name, tool_args_json, tool_result_json, decision, "
            "policy_matched, and nist_controls_json. Full traceability per control."
        ),
        code_references=["agentguard/audit_log.py:AuditEvent"],
    ),
    "AU-9": ControlDefinition(
        control_id="AU-9",
        family=FAMILY_AU,
        title="Protection of Audit Information",
        description=(
            "Protect audit information and audit tools from unauthorized access, "
            "modification, and deletion."
        ),
        agentguard_implementation=(
            "Audit events are stored in a hash-chained SQLite database. Each event "
            "includes the SHA-256 hash of the previous event, making any modification, "
            "deletion, or insertion detectable via verify_chain(). In federal mode, "
            "events are also signed with Ed25519."
        ),
        code_references=[
            "agentguard/audit_log.py:AuditLog.verify_chain",
            "agentguard/audit_log.py:AuditLog._compute_hash",
        ],
    ),
    "AU-10": ControlDefinition(
        control_id="AU-10",
        family=FAMILY_AU,
        title="Non-repudiation",
        description=(
            "Provide irrefutable evidence that an individual (or process acting on "
            "behalf of an individual) has performed a specific action on the system."
        ),
        agentguard_implementation=(
            "In federal mode, each audit event is signed with an Ed25519 private key. "
            "The signature covers the event hash, which includes all event fields. "
            "The corresponding public key can verify any event's authenticity without "
            "the private key."
        ),
        code_references=[
            "agentguard/audit_log.py:AuditLog._sign",
            "agentguard/audit_log.py:generate_signing_keypair",
        ],
    ),
    "AU-12": ControlDefinition(
        control_id="AU-12",
        family=FAMILY_AU,
        title="Audit Record Generation",
        description=(
            "Provide audit record generation capability for the event types the "
            "system is capable of auditing."
        ),
        agentguard_implementation=(
            "Audit record generation is automatic and cannot be disabled in federal "
            "mode. The proxy writes an audit event for every intercepted MCP message "
            "before forwarding or denying it. Dev mode also generates audit records "
            "but does not enforce policy."
        ),
        code_references=["agentguard/proxy.py", "agentguard/audit_log.py"],
    ),
    "CM-7": ControlDefinition(
        control_id="CM-7",
        family=FAMILY_CM,
        title="Least Functionality",
        description=(
            "Configure the system to provide only essential capabilities, prohibiting "
            "or restricting the use of functions, ports, protocols, software, and "
            "services not required."
        ),
        agentguard_implementation=(
            "Federal mode implements deny-by-default: every tool is prohibited unless "
            "explicitly listed in the policy allowlist. No MCP tool capability is "
            "exposed to the agent unless an operator grants it. The allowlist in "
            "`agentguard/policies/defaults/federal_mode.yaml` is the explicit surface "
            "area. Each denied call is logged with the CM-7 control tag."
        ),
        code_references=[
            "agentguard/policies/defaults/federal_mode.yaml",
            "agentguard/policy_engine.py:PolicyEngine._mode_default",
            "agentguard/modes.py:FEDERAL_DEFAULTS",
        ],
    ),
    "IA-2": ControlDefinition(
        control_id="IA-2",
        family=FAMILY_IA,
        title="Identification and Authentication",
        description=(
            "Uniquely identify and authenticate organizational users and processes "
            "acting on behalf of organizational users."
        ),
        agentguard_implementation=(
            "Agent identity is extracted from the MCP initialize handshake (clientInfo "
            "name and version). A session UUID is generated per connection. All audit "
            "events reference this agent_id. Future versions will support DoD PKI "
            "certificate-based identity."
        ),
        code_references=["agentguard/identity.py:IdentityExtractor"],
    ),
    "IA-9": ControlDefinition(
        control_id="IA-9",
        family=FAMILY_IA,
        title="Service Identification and Authentication",
        description=(
            "Uniquely identify and authenticate services before establishing "
            "communications with those services."
        ),
        agentguard_implementation=(
            "AgentGuard records the identity of upstream MCP servers from the "
            "server info returned during session initialization. In federal mode, "
            "upstream server identity is validated against an approved server list "
            "before tool calls are forwarded. This prevents agent tool calls from "
            "being silently redirected to unapproved MCP servers."
        ),
        code_references=[
            "agentguard/identity.py:IdentityExtractor",
            "agentguard/proxy.py",
            "agentguard/policies/defaults/federal_mode.yaml",
        ],
    ),
    "RA-5": ControlDefinition(
        control_id="RA-5",
        family=FAMILY_RA,
        title="Vulnerability Monitoring and Scanning",
        description=(
            "Monitor and scan for vulnerabilities in the system and hosted "
            "applications periodically and when new vulnerabilities potentially "
            "affecting the system are identified."
        ),
        agentguard_implementation=(
            "The tool poisoning detector continuously scans MCP tool descriptions "
            "for known attack patterns on every tools/list response. This functions "
            "as a runtime vulnerability scan of the MCP tool surface. Threat feed "
            "integration is planned for v0.2 to enable signature-based detection "
            "of newly discovered MCP attack patterns from CISA KEV and MITRE ATLAS."
        ),
        code_references=[
            "agentguard/detectors/tool_poisoning.py",
            "agentguard/proxy.py",
        ],
    ),
    "SC-7": ControlDefinition(
        control_id="SC-7",
        family=FAMILY_SC,
        title="Boundary Protection",
        description=(
            "Monitor and control communications at the external managed interfaces "
            "to the system and at key internal managed interfaces within the system."
        ),
        agentguard_implementation=(
            "AgentGuard acts as the managed boundary between AI agent clients and "
            "upstream MCP servers. Every communication crossing this boundary is "
            "inspected, policy-evaluated, and logged. The HTTP gateway mode extends "
            "this to network-level boundary enforcement for remote MCP clients. No "
            "tool call traverses the boundary without passing through the proxy core."
        ),
        code_references=[
            "agentguard/proxy.py",
            "agentguard/gateway.py",
            "agentguard/policy_engine.py",
        ],
    ),
    "SC-8": ControlDefinition(
        control_id="SC-8",
        family=FAMILY_SC,
        title="Transmission Confidentiality and Integrity",
        description=(
            "Implement cryptographic mechanisms to prevent unauthorized disclosure "
            "of information and detect changes to information during transmission."
        ),
        agentguard_implementation=(
            "HTTP gateway mode supports TLS for encrypted transport. Stdio mode "
            "relies on OS-level process isolation. Secret detection prevents "
            "credentials from being transmitted through tool calls."
        ),
        code_references=[
            "agentguard/gateway.py",
            "agentguard/detectors/secrets.py",
        ],
    ),
    "SI-4": ControlDefinition(
        control_id="SI-4",
        family=FAMILY_SI,
        title="System Monitoring",
        description=(
            "Monitor the system to detect attacks and indicators of potential "
            "attacks in accordance with monitoring objectives."
        ),
        agentguard_implementation=(
            "Prompt injection, PII, secret, and tool poisoning detectors run on "
            "every tool call. Detection results are logged with NIST control tags. "
            "Tool description poisoning is scanned at session start and on every "
            "tools/list response."
        ),
        code_references=[
            "agentguard/detectors/prompt_injection.py",
            "agentguard/detectors/pii.py",
            "agentguard/detectors/secrets.py",
            "agentguard/detectors/tool_poisoning.py",
        ],
    ),
    "SI-7": ControlDefinition(
        control_id="SI-7",
        family=FAMILY_SI,
        title="Software, Firmware, and Information Integrity",
        description=(
            "Employ integrity verification tools to detect unauthorized changes to "
            "software, firmware, and information."
        ),
        agentguard_implementation=(
            "The tool poisoning detector (`agentguard/detectors/tool_poisoning.py`) "
            "implements software integrity checking for the MCP tool layer. It scans "
            "every tool description for embedded instructions, known attack signatures, "
            "and anomalous content that indicates tampering. The audit hash chain "
            "provides integrity verification for the audit log itself."
        ),
        code_references=[
            "agentguard/detectors/tool_poisoning.py",
            "agentguard/audit_log.py:AuditLog.verify_chain",
            "agentguard/audit_log.py:AuditLog._compute_hash",
        ],
    ),
    "SI-10": ControlDefinition(
        control_id="SI-10",
        family=FAMILY_SI,
        title="Information Input Validation",
        description=(
            "Check the validity of the following information inputs: "
            "syntax, semantics, and format of information inputs."
        ),
        agentguard_implementation=(
            "All tool call arguments are validated by the detector stack before "
            "forwarding. PII detector validates against known personal data patterns. "
            "Injection detector validates against known attack patterns. Secret "
            "detector validates against known credential formats."
        ),
        code_references=[
            "agentguard/detectors/prompt_injection.py:detect_in_tool_args",
            "agentguard/detectors/pii.py:detect_in_tool_args",
            "agentguard/detectors/secrets.py:detect_in_tool_args",
        ],
    ),
    "SI-15": ControlDefinition(
        control_id="SI-15",
        family=FAMILY_SI,
        title="Information Output Filtering",
        description=(
            "Validate information output from systems to ensure that the information "
            "is consistent with the expected content."
        ),
        agentguard_implementation=(
            "Response filtering in the proxy core scans tool results for PII, "
            "secrets, and system prompt content before returning them to the agent. "
            "The PII detector (`agentguard/detectors/pii.py`) and secret detector "
            "(`agentguard/detectors/secrets.py`) run on both inbound tool arguments "
            "and outbound tool results. System prompt leakage (OWASP LLM07) is "
            "addressed by scanning responses for known prompt header patterns."
        ),
        code_references=[
            "agentguard/proxy.py",
            "agentguard/detectors/pii.py",
            "agentguard/detectors/secrets.py",
        ],
    ),
}


def get_control(control_id: str) -> ControlDefinition:
    """Return a control definition by ID. Raises KeyError if not found."""
    return CONTROLS[control_id]


def list_controls() -> list[ControlDefinition]:
    """Return all control definitions sorted by control ID."""
    return sorted(CONTROLS.values(), key=lambda c: c.control_id)


def get_controls_for_family(family: str) -> list[ControlDefinition]:
    """Return controls for a given family (e.g., 'AU', 'AC')."""
    prefix = family.upper() + "-"
    return [c for c in CONTROLS.values() if c.control_id.startswith(prefix)]
