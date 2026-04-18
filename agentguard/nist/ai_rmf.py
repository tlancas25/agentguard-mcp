"""NIST AI Risk Management Framework (AI RMF) function library for AgentGuard.

Maps AgentGuard capabilities to the four NIST AI RMF Core Functions:
GOVERN, MAP, MEASURE, MANAGE.

Also includes NIST AI 600-1 Generative AI Profile risk area definitions.

References:
- NIST AI 100-1 (January 2023): https://www.nist.gov/itl/ai-risk-management-framework
- NIST AI 600-1 (July 2024): https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.600-1.pdf
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

NIST_AI_600_1_VERSION = "1.0"


class GenAIRiskArea(Enum):
    """The 12 risk areas defined in NIST AI 600-1 Generative AI Profile (July 2024).

    Each member corresponds to a risk area from Section 2 of NIST AI 600-1.
    AgentGuard directly addresses INFORMATION_SECURITY and VALUE_CHAIN_INTEGRATION.
    The remaining areas are out of scope for this tool.
    """

    CBRN_INFORMATION = "cbrn_information"
    CONFABULATION = "confabulation"
    DANGEROUS_VIOLENT_HATEFUL = "dangerous_violent_hateful"
    DATA_PRIVACY = "data_privacy"
    ENVIRONMENTAL = "environmental"
    HARMFUL_BIAS_HOMOGENIZATION = "harmful_bias_homogenization"
    HUMAN_AI_CONFIGURATION = "human_ai_configuration"
    INFORMATION_INTEGRITY = "information_integrity"
    INFORMATION_SECURITY = "information_security"
    INTELLECTUAL_PROPERTY = "intellectual_property"
    OBSCENE_DEGRADING = "obscene_degrading"
    VALUE_CHAIN_INTEGRATION = "value_chain_integration"


@dataclass(frozen=True)
class GenAIRiskAreaDefinition:
    """Metadata for a single NIST AI 600-1 risk area."""

    risk_area: GenAIRiskArea
    description: str
    rmf_functions: list[str]          # Which of GOVERN/MAP/MEASURE/MANAGE apply
    agentguard_coverage: str          # How (or whether) AgentGuard addresses this


GEN_AI_RISK_AREAS: dict[GenAIRiskArea, GenAIRiskAreaDefinition] = {
    GenAIRiskArea.CBRN_INFORMATION: GenAIRiskAreaDefinition(
        risk_area=GenAIRiskArea.CBRN_INFORMATION,
        description=(
            "Gen AI systems producing or facilitating access to information about "
            "chemical, biological, radiological, or nuclear (CBRN) weapons or agents."
        ),
        rmf_functions=["GOVERN", "MAP", "MANAGE"],
        agentguard_coverage=(
            "Out of scope. AgentGuard does not classify or filter for CBRN content. "
            "Organizations handling CBRN-adjacent AI workloads should implement "
            "content classification at the model layer."
        ),
    ),
    GenAIRiskArea.CONFABULATION: GenAIRiskAreaDefinition(
        risk_area=GenAIRiskArea.CONFABULATION,
        description=(
            "Gen AI producing false or misleading outputs presented with unwarranted "
            "confidence (hallucination). Mapped to OWASP LLM09 Misinformation."
        ),
        rmf_functions=["MAP", "MEASURE", "MANAGE"],
        agentguard_coverage=(
            "Out of scope for core detection. AgentGuard does not validate the "
            "factual accuracy of LLM outputs. Output validators are a stub interface "
            "for future integration. The OWASP LLM09 mapping is included in "
            "agentguard/nist/owasp_llm.py for reference."
        ),
    ),
    GenAIRiskArea.DANGEROUS_VIOLENT_HATEFUL: GenAIRiskAreaDefinition(
        risk_area=GenAIRiskArea.DANGEROUS_VIOLENT_HATEFUL,
        description=(
            "Gen AI generating content that facilitates violence, self-harm, "
            "or promotes hateful ideologies."
        ),
        rmf_functions=["GOVERN", "MAP", "MANAGE"],
        agentguard_coverage=(
            "Out of scope. AgentGuard does not perform content moderation on "
            "LLM outputs. This responsibility belongs to the model provider or "
            "an inline content safety layer."
        ),
    ),
    GenAIRiskArea.DATA_PRIVACY: GenAIRiskAreaDefinition(
        risk_area=GenAIRiskArea.DATA_PRIVACY,
        description=(
            "Gen AI systems processing, memorizing, or disclosing personal data "
            "without authorization. Mapped to OWASP LLM02 Sensitive Information "
            "Disclosure and NIST 800-53 SC-28."
        ),
        rmf_functions=["GOVERN", "MAP", "MEASURE", "MANAGE"],
        agentguard_coverage=(
            "Partially addressed. The PII detector (agentguard/detectors/pii.py) "
            "scans tool call arguments and results for SSNs, credit card numbers, "
            "PHI, and other personal data patterns. In federal mode, calls containing "
            "PII can be blocked (SI-15, AC-4). This covers data flow through the "
            "MCP layer; it does not address model memorization."
        ),
    ),
    GenAIRiskArea.ENVIRONMENTAL: GenAIRiskAreaDefinition(
        risk_area=GenAIRiskArea.ENVIRONMENTAL,
        description=(
            "Environmental impacts of large-scale AI compute, including energy "
            "consumption and carbon footprint."
        ),
        rmf_functions=["GOVERN", "MAP"],
        agentguard_coverage=(
            "Out of scope. AgentGuard does not measure or report on compute "
            "resource consumption. Rate limiting (AC-7, OWASP LLM10) has an "
            "incidental effect of reducing unbounded compute use but is not "
            "designed for environmental management."
        ),
    ),
    GenAIRiskArea.HARMFUL_BIAS_HOMOGENIZATION: GenAIRiskAreaDefinition(
        risk_area=GenAIRiskArea.HARMFUL_BIAS_HOMOGENIZATION,
        description=(
            "Gen AI producing outputs that reflect, amplify, or homogenize "
            "harmful societal biases."
        ),
        rmf_functions=["GOVERN", "MAP", "MEASURE"],
        agentguard_coverage=(
            "Out of scope. AgentGuard does not evaluate LLM outputs for bias. "
            "This is a model evaluation and training concern, not an MCP gateway concern."
        ),
    ),
    GenAIRiskArea.HUMAN_AI_CONFIGURATION: GenAIRiskAreaDefinition(
        risk_area=GenAIRiskArea.HUMAN_AI_CONFIGURATION,
        description=(
            "Risks from inappropriate levels of human oversight, over-reliance, "
            "or under-reliance on AI systems."
        ),
        rmf_functions=["GOVERN", "MAP", "MANAGE"],
        agentguard_coverage=(
            "Partially addressed via dual-mode design. Federal mode requires explicit "
            "human-defined policy for every tool grant, enforcing human configuration "
            "of AI autonomy. Dev mode retains full human visibility via audit logs "
            "without blocking workflow. AgentGuard does not enforce human-in-the-loop "
            "review of individual decisions."
        ),
    ),
    GenAIRiskArea.INFORMATION_INTEGRITY: GenAIRiskAreaDefinition(
        risk_area=GenAIRiskArea.INFORMATION_INTEGRITY,
        description=(
            "Gen AI facilitating disinformation, synthetic media, or manipulation "
            "of information ecosystems."
        ),
        rmf_functions=["GOVERN", "MAP", "MANAGE"],
        agentguard_coverage=(
            "Out of scope. AgentGuard does not classify or filter content for "
            "information integrity at the societal level. The audit log provides "
            "provenance for MCP tool calls, which is a supporting capability for "
            "narrow information integrity claims."
        ),
    ),
    GenAIRiskArea.INFORMATION_SECURITY: GenAIRiskAreaDefinition(
        risk_area=GenAIRiskArea.INFORMATION_SECURITY,
        description=(
            "Gen AI systems used to conduct or enable cyberattacks, or Gen AI "
            "systems themselves as targets of attack. Includes prompt injection, "
            "tool poisoning, credential theft, and supply chain compromise. "
            "Primary zone of AgentGuard coverage."
        ),
        rmf_functions=["GOVERN", "MAP", "MEASURE", "MANAGE"],
        agentguard_coverage=(
            "PRIMARY COVERAGE. AgentGuard directly addresses this risk area across "
            "all four RMF functions: GOVERN via policy bundles and access control; "
            "MAP via detector stack (prompt injection, PII, secrets, tool poisoning); "
            "MEASURE via hash-chained audit log with Ed25519 signatures; MANAGE via "
            "federal mode enforcement and POA&M reporting. Relevant NIST 800-53 "
            "controls: SI-4, SI-7, SI-10, SI-15, AC-3, AC-4, AU-9, AU-10."
        ),
    ),
    GenAIRiskArea.INTELLECTUAL_PROPERTY: GenAIRiskAreaDefinition(
        risk_area=GenAIRiskArea.INTELLECTUAL_PROPERTY,
        description=(
            "Gen AI reproducing copyrighted material, trade secrets, or other "
            "protected intellectual property without authorization."
        ),
        rmf_functions=["GOVERN", "MAP"],
        agentguard_coverage=(
            "Out of scope. AgentGuard does not classify outputs for IP violations. "
            "This is a model-layer and legal compliance concern."
        ),
    ),
    GenAIRiskArea.OBSCENE_DEGRADING: GenAIRiskAreaDefinition(
        risk_area=GenAIRiskArea.OBSCENE_DEGRADING,
        description=(
            "Gen AI generating obscene, sexually explicit, or otherwise degrading "
            "content, including non-consensual synthetic imagery."
        ),
        rmf_functions=["GOVERN", "MAP", "MANAGE"],
        agentguard_coverage=(
            "Out of scope. AgentGuard does not perform content moderation. "
            "This is a model provider responsibility."
        ),
    ),
    GenAIRiskArea.VALUE_CHAIN_INTEGRATION: GenAIRiskAreaDefinition(
        risk_area=GenAIRiskArea.VALUE_CHAIN_INTEGRATION,
        description=(
            "Risks from the AI supply chain: third-party model weights, datasets, "
            "plugins, APIs, and MCP servers that the AI system depends on. Mapped "
            "to OWASP LLM03 Supply Chain Vulnerabilities and MITRE ATLAS "
            "AML.T0066 Publish Poisoned AI Agent Tool. Primary zone of AgentGuard coverage."
        ),
        rmf_functions=["GOVERN", "MAP", "MEASURE", "MANAGE"],
        agentguard_coverage=(
            "PRIMARY COVERAGE. AgentGuard addresses MCP tool supply chain risks "
            "directly. The tool poisoning detector (agentguard/detectors/tool_poisoning.py) "
            "scans every tool description for embedded instructions from third-party "
            "MCP servers. Upstream server identity is validated against approved lists "
            "in federal mode (IA-9, SC-7). The RA-5 control maps to threat feed "
            "integration planned for v0.2. This covers the MCP-specific slice of the "
            "value chain; it does not audit model weights or training data."
        ),
    ),
}


def get_risk_area(area: GenAIRiskArea) -> GenAIRiskAreaDefinition:
    """Return the definition for a NIST AI 600-1 risk area."""
    return GEN_AI_RISK_AREAS[area]


def list_risk_areas() -> list[GenAIRiskAreaDefinition]:
    """Return all 12 NIST AI 600-1 risk area definitions."""
    return list(GEN_AI_RISK_AREAS.values())


def get_agentguard_primary_risk_areas() -> list[GenAIRiskAreaDefinition]:
    """Return only the risk areas where AgentGuard has primary coverage."""
    primary = {GenAIRiskArea.INFORMATION_SECURITY, GenAIRiskArea.VALUE_CHAIN_INTEGRATION}
    return [d for area, d in GEN_AI_RISK_AREAS.items() if area in primary]


@dataclass(frozen=True)
class AIRMFFunction:
    """A single NIST AI RMF subcategory addressed by AgentGuard."""

    function: str           # GOVERN | MAP | MEASURE | MANAGE
    subcategory: str        # e.g., "1.2"
    full_id: str            # e.g., "GOVERN 1.2"
    title: str
    description: str
    agentguard_implementation: str
    code_references: list[str] = field(default_factory=list)


AI_RMF_FUNCTIONS: dict[str, AIRMFFunction] = {
    "GOVERN-1.2": AIRMFFunction(
        function="GOVERN",
        subcategory="1.2",
        full_id="GOVERN 1.2",
        title="Accountability and Transparency",
        description=(
            "Accountability structures, ownership, and decision-making authority over "
            "AI risk are clearly defined, understood, and communicated."
        ),
        agentguard_implementation=(
            "Every agent session is tied to a client identity extracted from the MCP "
            "initialize handshake. All tool calls are logged with agent_id, making it "
            "clear which system (and by extension, which operator) is accountable for "
            "each action. Policy bundles define who authorized what."
        ),
        code_references=[
            "agentguard/identity.py",
            "agentguard/audit_log.py",
        ],
    ),
    "GOVERN-1.5": AIRMFFunction(
        function="GOVERN",
        subcategory="1.5",
        full_id="GOVERN 1.5",
        title="Organizational Risk Policies",
        description=(
            "Organizational risk tolerances are established, communicated, and "
            "maintained for AI systems."
        ),
        agentguard_implementation=(
            "Policy bundles encode organizational risk tolerance as YAML. Dev mode "
            "represents permissive tolerance; federal mode represents strict. The "
            "dual-mode design lets organizations graduate their risk posture without "
            "changing the underlying system."
        ),
        code_references=[
            "agentguard/policies/defaults/dev_mode.yaml",
            "agentguard/policies/defaults/federal_mode.yaml",
        ],
    ),
    "GOVERN-4.3": AIRMFFunction(
        function="GOVERN",
        subcategory="4.3",
        full_id="GOVERN 4.3",
        title="Organizational Practices for AI Risk",
        description=(
            "Organizational practices are in place to plan, manage, and "
            "communicate AI risk."
        ),
        agentguard_implementation=(
            "FedRAMP evidence reports and NIST AI RMF assessments are generated "
            "on demand from audit log data. POA&M reports track open findings. "
            "These artifacts support ATO packages and security review boards."
        ),
        code_references=[
            "agentguard/reports/fedramp.py",
            "agentguard/reports/nist_ai_rmf.py",
            "agentguard/reports/poam.py",
        ],
    ),
    "MAP-2.1": AIRMFFunction(
        function="MAP",
        subcategory="2.1",
        full_id="MAP 2.1",
        title="Scientific Knowledge and Threat Mapping",
        description=(
            "The organization identifies and prioritizes the potential negative "
            "impacts of the AI system to individuals, groups, communities, "
            "organizations, and society."
        ),
        agentguard_implementation=(
            "AgentGuard's threat model (docs/threat-model.md) documents the "
            "attack surface of MCP agents. The detector stack maps to specific "
            "threat categories: prompt injection, PII exfiltration, secret leaks, "
            "and tool poisoning."
        ),
        code_references=[
            "docs/threat-model.md",
            "agentguard/detectors/",
        ],
    ),
    "MAP-3.1": AIRMFFunction(
        function="MAP",
        subcategory="3.1",
        full_id="MAP 3.1",
        title="AI Risk Identification",
        description=(
            "Potential impacts from AI errors and limitations are identified."
        ),
        agentguard_implementation=(
            "Detectors identify known AI attack patterns in real time. Injection "
            "detector covers OWASP LLM Top 10 patterns. Tool poisoning detector "
            "covers the Palo Alto Unit 42 MCP attack class. All detections are "
            "logged with NIST control tags."
        ),
        code_references=[
            "agentguard/detectors/prompt_injection.py",
            "agentguard/detectors/tool_poisoning.py",
        ],
    ),
    "MAP-5.1": AIRMFFunction(
        function="MAP",
        subcategory="5.1",
        full_id="MAP 5.1",
        title="Likelihood and Impact Assessment",
        description=(
            "Likelihood and magnitude of each identified impact and associated "
            "AI risk or benefit are estimated."
        ),
        agentguard_implementation=(
            "Policy engine maps a risk response (allow/deny/log) to each detected "
            "threat based on configured risk tolerance. Decision objects include "
            "NIST control tags that inform impact estimation."
        ),
        code_references=["agentguard/policy_engine.py:Decision"],
    ),
    "MEASURE-2.1": AIRMFFunction(
        function="MEASURE",
        subcategory="2.1",
        full_id="MEASURE 2.1",
        title="AI Risk Assessment",
        description=(
            "Test sets, metrics, and details about the tools used during test, "
            "evaluation, validation, and verification are documented."
        ),
        agentguard_implementation=(
            "Detection rates per session are logged and available via the audit "
            "query API. Reports include counts of denied calls, detected threats, "
            "and policy matches per time period."
        ),
        code_references=[
            "agentguard/audit_log.py:AuditLog.query",
            "agentguard/reports/fedramp.py",
        ],
    ),
    "MEASURE-2.6": AIRMFFunction(
        function="MEASURE",
        subcategory="2.6",
        full_id="MEASURE 2.6",
        title="Audit and Accountability",
        description=(
            "The risk or benefit status of deployed AI systems is monitored."
        ),
        agentguard_implementation=(
            "Hash chain provides tamper-evident audit. verify_chain() can be run "
            "on demand or on a schedule to confirm audit integrity. Results are "
            "logged and can trigger alerts."
        ),
        code_references=["agentguard/audit_log.py:AuditLog.verify_chain"],
    ),
    "MEASURE-2.7": AIRMFFunction(
        function="MEASURE",
        subcategory="2.7",
        full_id="MEASURE 2.7",
        title="AI System Performance",
        description=(
            "AI system risks and benefits are evaluated for technical robustness."
        ),
        agentguard_implementation=(
            "POA&M report (poam.py) tracks unresolved security findings from the "
            "audit log. Each open finding has a description, severity, and "
            "remediation status. This feeds back into risk posture updates."
        ),
        code_references=["agentguard/reports/poam.py"],
    ),
    "MEASURE-3.1": AIRMFFunction(
        function="MEASURE",
        subcategory="3.1",
        full_id="MEASURE 3.1",
        title="Effectiveness Assessment",
        description=(
            "Approaches, personnel, and documentation for risk management are "
            "assessed for effectiveness."
        ),
        agentguard_implementation=(
            "Reports surface AI system behavior metrics: total tool calls, "
            "denial rate, detection counts by type, policy match distribution. "
            "Exportable as JSON for SIEM ingestion."
        ),
        code_references=[
            "agentguard/reports/nist_ai_rmf.py",
            "agentguard/reports/fedramp.py",
        ],
    ),
    "MANAGE-1.3": AIRMFFunction(
        function="MANAGE",
        subcategory="1.3",
        full_id="MANAGE 1.3",
        title="Risk Response Planning",
        description=(
            "Responses to the risks associated with AI systems are planned."
        ),
        agentguard_implementation=(
            "Policy updates in the YAML bundle files are the mechanism for "
            "addressing identified risks. A new denylist entry or stricter "
            "allowlist can be deployed without restarting the gateway in "
            "supported configurations."
        ),
        code_references=[
            "agentguard/policies/",
            "agentguard/policy_engine.py",
        ],
    ),
    "MANAGE-3.2": AIRMFFunction(
        function="MANAGE",
        subcategory="3.2",
        full_id="MANAGE 3.2",
        title="Treatment of Identified Risks",
        description=(
            "Treatment of identified and prioritized risks includes developer "
            "or organizational responses to each risk."
        ),
        agentguard_implementation=(
            "Incident response is supported via audit tail (live streaming of "
            "recent events) and JSONL/CSV export for SIEM ingestion. Signed "
            "events provide forensic-quality evidence for after-action review."
        ),
        code_references=[
            "agentguard/audit_log.py:AuditLog.tail",
            "agentguard/audit_log.py:AuditLog.export_jsonl",
        ],
    ),
    "MANAGE-4.1": AIRMFFunction(
        function="MANAGE",
        subcategory="4.1",
        full_id="MANAGE 4.1",
        title="Risk Treatment",
        description=(
            "Post-deployment AI risks are monitored and improvements are made."
        ),
        agentguard_implementation=(
            "Signed audit log provides the basis for after-action review and "
            "continuous improvement. Each signed event is cryptographically "
            "non-repudiable, supporting legal and regulatory post-incident review."
        ),
        code_references=[
            "agentguard/audit_log.py:AuditLog._sign",
            "agentguard/reports/fedramp.py",
        ],
    ),
}


def get_function(full_id: str) -> AIRMFFunction:
    """Return an AI RMF function by its full ID (e.g., 'GOVERN 1.2')."""
    key = full_id.replace(" ", "-")
    return AI_RMF_FUNCTIONS[key]


def list_functions() -> list[AIRMFFunction]:
    """Return all AI RMF functions sorted by function and subcategory."""
    return sorted(
        AI_RMF_FUNCTIONS.values(),
        key=lambda f: (f.function, f.subcategory),
    )


def list_by_function(function: str) -> list[AIRMFFunction]:
    """Return AI RMF functions for a given core function (GOVERN/MAP/MEASURE/MANAGE)."""
    return [f for f in AI_RMF_FUNCTIONS.values() if f.function == function.upper()]
