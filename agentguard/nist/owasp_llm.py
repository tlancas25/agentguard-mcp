"""OWASP Top 10 for LLM Applications 2025 — AgentGuard mapping.

Provides structured definitions for all 10 vulnerabilities, cross-referenced
to AgentGuard defenses, NIST 800-53 Rev 5.2 controls, and MITRE ATLAS v5.4.0
technique IDs.

Source: https://genai.owasp.org/resource/owasp-top-10-for-llm-applications-2025/
"""

from __future__ import annotations

from dataclasses import dataclass, field

OWASP_LLM_VERSION = "2025"


@dataclass(frozen=True)
class OwaspLLMVulnerability:
    """A single OWASP LLM Top 10 2025 vulnerability entry."""

    id: str                             # e.g., "LLM01:2025"
    name: str                           # e.g., "Prompt Injection"
    description: str
    agentguard_defense: str             # Which AgentGuard file/module defends against it
    nist_controls: list[str] = field(default_factory=list)
    mitre_atlas_techniques: list[str] = field(default_factory=list)


OWASP_LLM_TOP_10_2025: dict[str, OwaspLLMVulnerability] = {
    "LLM01:2025": OwaspLLMVulnerability(
        id="LLM01:2025",
        name="Prompt Injection",
        description=(
            "An attacker crafts inputs that manipulate an LLM into ignoring its "
            "instructions or performing unintended actions. Includes direct injection "
            "(user-supplied prompts) and indirect injection (malicious content in data "
            "the LLM retrieves from external sources, such as files, web pages, or "
            "tool responses)."
        ),
        agentguard_defense=(
            "agentguard/detectors/prompt_injection.py — scans all tool call arguments "
            "for known injection patterns using regex and heuristics. In federal mode, "
            "detected injections are denied before reaching the upstream MCP server. "
            "Every detection is logged with SI-10 and SI-4 control tags."
        ),
        nist_controls=["SI-10", "SI-4", "AC-3", "AU-2", "AU-12"],
        mitre_atlas_techniques=["AML.T0051.000", "AML.T0051.001"],
    ),
    "LLM02:2025": OwaspLLMVulnerability(
        id="LLM02:2025",
        name="Sensitive Information Disclosure",
        description=(
            "LLM outputs or agent tool calls inadvertently disclose personally "
            "identifiable information (PII), credentials, internal system details, "
            "or other sensitive data. Includes both model memorization leakage and "
            "runtime data exfiltration through tool calls."
        ),
        agentguard_defense=(
            "agentguard/detectors/pii.py — scans tool call arguments and results for "
            "SSNs, credit card numbers, PHI, email addresses, and other personal data. "
            "agentguard/detectors/secrets.py — scans for API keys, JWTs, private keys, "
            "and other credential formats. SI-15 (output filtering) applied to results. "
            "In federal mode, calls containing PII or secrets can be blocked."
        ),
        nist_controls=["SI-10", "SI-15", "AC-4", "SC-28", "AU-2"],
        mitre_atlas_techniques=["AML.T0048", "AML.T0057"],
    ),
    "LLM03:2025": OwaspLLMVulnerability(
        id="LLM03:2025",
        name="Supply Chain Vulnerabilities",
        description=(
            "Risks from third-party components in the AI system supply chain: "
            "pre-trained models, plugins, MCP servers, and datasets. A compromised "
            "or malicious component can affect the entire AI system. Includes tool "
            "description poisoning (documented by Palo Alto Unit 42) where malicious "
            "MCP servers embed instructions in tool descriptions."
        ),
        agentguard_defense=(
            "agentguard/detectors/tool_poisoning.py — scans every tool description "
            "in tools/list responses for embedded instructions, privilege escalation "
            "attempts, and anomalous content from third-party MCP servers. "
            "agentguard/nist/cmmc.py — CMMC Level 2/3 supply chain requirements "
            "roadmap (v0.2). RA-5 control maps to planned threat feed integration."
        ),
        nist_controls=["SI-7", "RA-5", "SI-4", "AC-3", "AU-2"],
        mitre_atlas_techniques=["AML.T0066", "AML.T0051.001"],
    ),
    "LLM04:2025": OwaspLLMVulnerability(
        id="LLM04:2025",
        name="Data and Model Poisoning",
        description=(
            "Malicious manipulation of training data, fine-tuning datasets, or "
            "retrieval-augmented generation (RAG) knowledge bases to cause the model "
            "to produce harmful, biased, or attacker-controlled outputs."
        ),
        agentguard_defense=(
            "Partially addressed. AgentGuard enforces Value Chain policies in "
            "agentguard/policies/defaults/federal_mode.yaml to restrict which "
            "data sources agents can access. Context hygiene policies (mapped to "
            "OWASP LLM08) reduce RAG poisoning risk at the tool-call layer. "
            "Model training data poisoning is out of scope — it is a model provider "
            "and MLOps responsibility."
        ),
        nist_controls=["SI-7", "AC-4", "RA-5", "AU-2"],
        mitre_atlas_techniques=["AML.T0062", "AML.T0020"],
    ),
    "LLM05:2025": OwaspLLMVulnerability(
        id="LLM05:2025",
        name="Improper Output Handling",
        description=(
            "Downstream systems process LLM-generated output without sufficient "
            "validation, leading to injection attacks (XSS, SSRF, SQL injection) "
            "in consuming applications. The LLM output is treated as trusted input "
            "by backend services."
        ),
        agentguard_defense=(
            "agentguard/proxy.py — response filtering scans tool results before "
            "returning them to the agent. SI-15 (Information Output Filtering) is "
            "the primary control. SI-10 (Input Validation) applies to downstream "
            "consumption. Specific output sanitization for SQL/XSS is a v0.2 roadmap "
            "item requiring integration with consuming application context."
        ),
        nist_controls=["SI-15", "SI-10", "AU-2", "AU-12"],
        mitre_atlas_techniques=["AML.T0051.000", "AML.T0064"],
    ),
    "LLM06:2025": OwaspLLMVulnerability(
        id="LLM06:2025",
        name="Excessive Agency",
        description=(
            "An LLM-based agent is granted more permissions, tools, or capabilities "
            "than necessary, allowing it to take harmful actions — either through "
            "prompt injection or misconfiguration. The agent can read files, execute "
            "code, call APIs, or make purchases beyond its intended scope."
        ),
        agentguard_defense=(
            "agentguard/policy_engine.py — enforces tool allowlist/denylist on every "
            "MCP tool call. agentguard/policies/defaults/federal_mode.yaml — "
            "deny-by-default configuration grants no implicit permissions. "
            "agentguard/modes.py:FEDERAL_DEFAULTS — federal mode is the reference "
            "implementation of CM-7 Least Functionality and AC-6 Least Privilege."
        ),
        nist_controls=["AC-3", "AC-6", "CM-7", "AU-2", "AU-3"],
        mitre_atlas_techniques=["AML.T0065", "AML.T0067"],
    ),
    "LLM07:2025": OwaspLLMVulnerability(
        id="LLM07:2025",
        name="System Prompt Leakage",
        description=(
            "New in 2025. An LLM reveals its system prompt through direct output, "
            "jailbreaks, or indirect inference. System prompts often contain "
            "confidential business logic, security controls, or sensitive context "
            "that attackers can use to craft more effective attacks."
        ),
        agentguard_defense=(
            "agentguard/proxy.py — response scanning checks MCP tool results and "
            "prompts/get responses for system prompt content before returning to agent. "
            "SI-15 (Information Output Filtering) is the primary control. The "
            "EVENT_PROMPTS_GET event type triggers OWASP LLM07 tagging in "
            "agentguard/nist/mappings.py. Full system prompt leakage detection "
            "is a v0.2 roadmap item."
        ),
        nist_controls=["SI-15", "AC-4", "AU-2", "AU-3"],
        mitre_atlas_techniques=["AML.T0051.001", "AML.T0057"],
    ),
    "LLM08:2025": OwaspLLMVulnerability(
        id="LLM08:2025",
        name="Vector and Embedding Weaknesses",
        description=(
            "New in 2025. Vulnerabilities in vector databases and embedding pipelines "
            "used for RAG: embedding inversion attacks (recovering training data from "
            "embeddings), poisoned vector stores, and cross-tenant data leakage in "
            "shared embedding infrastructure."
        ),
        agentguard_defense=(
            "Partially addressed via context hygiene policies. AgentGuard can restrict "
            "which vector database tools an agent can call (AC-3, CM-7) and log all "
            "embedding retrieval calls (AU-2). Direct embedding attack detection is "
            "a v0.2 roadmap item requiring integration with vector DB query patterns. "
            "Organizations should treat this as an infrastructure-layer control."
        ),
        nist_controls=["AC-3", "AC-4", "CM-7", "AU-2"],
        mitre_atlas_techniques=["AML.T0062", "AML.T0043"],
    ),
    "LLM09:2025": OwaspLLMVulnerability(
        id="LLM09:2025",
        name="Misinformation",
        description=(
            "LLMs produce false or misleading information (confabulation/hallucination) "
            "with high confidence. In agentic contexts this can lead to incorrect tool "
            "calls, fabricated API parameters, or actions taken based on false premises. "
            "Maps to NIST AI 600-1 CONFABULATION risk area."
        ),
        agentguard_defense=(
            "Out of scope for core detection. AgentGuard does not validate factual "
            "accuracy of LLM outputs. Output validators are a stub interface in "
            "agentguard/proxy.py for future LLM-based validation integration. "
            "The audit log provides traceability when misinformation-driven tool "
            "calls are later reviewed. Cite NIST AI 600-1 CONFABULATION risk area."
        ),
        nist_controls=["AU-2", "AU-3", "AU-12"],
        mitre_atlas_techniques=[],
    ),
    "LLM10:2025": OwaspLLMVulnerability(
        id="LLM10:2025",
        name="Unbounded Consumption",
        description=(
            "Excessive resource consumption by LLM applications through uncontrolled "
            "API calls, token usage, or compute resources. Enables denial of service, "
            "runaway cost, and degraded availability. Includes model DoS via prompt "
            "flooding and resource exhaustion attacks."
        ),
        agentguard_defense=(
            "agentguard/audit_log.py — logs every tool call, enabling rate analysis "
            "and threshold alerting. AC-7 (Unsuccessful Logon Attempts) provides the "
            "rate limiting control mapping. Configurable denial frequency thresholds "
            "in federal mode restrict per-agent tool call rates. Hard rate limits "
            "are a v0.2 roadmap item requiring session-level token/call counters."
        ),
        nist_controls=["AC-7", "AU-2", "AU-12", "SC-5"],
        mitre_atlas_techniques=["AML.T0029", "AML.T0034"],
    ),
}


def get_vulnerability(owasp_id: str) -> OwaspLLMVulnerability:
    """Return an OWASP LLM vulnerability by its 2025 ID (e.g., 'LLM01:2025')."""
    return OWASP_LLM_TOP_10_2025[owasp_id]


def list_vulnerabilities() -> list[OwaspLLMVulnerability]:
    """Return all 10 OWASP LLM 2025 vulnerability definitions in ranked order."""
    return list(OWASP_LLM_TOP_10_2025.values())
