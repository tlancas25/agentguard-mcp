"""MITRE ATLAS v5.4.0 tactic and technique library for AgentGuard.

Provides structured definitions for AI-agent-critical tactics and techniques
from MITRE ATLAS v5.4.0 (February 2026), cross-referenced to AgentGuard
defenses and NIST 800-53 Rev 5.2 controls.

Source: https://atlas.mitre.org/
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

MITRE_ATLAS_VERSION = "5.4.0"


class AtlasTactic(Enum):
    """The 16 MITRE ATLAS v5.4.0 tactics for adversarial AI attacks.

    COMMAND_AND_CONTROL was added in v5.1.0.
    """

    RECONNAISSANCE = "AML.TA0002"
    RESOURCE_DEVELOPMENT = "AML.TA0000"
    INITIAL_ACCESS = "AML.TA0004"
    ML_MODEL_ACCESS = "AML.TA0005"
    EXECUTION = "AML.TA0008"
    PERSISTENCE = "AML.TA0006"
    DEFENSE_EVASION = "AML.TA0015"         # Note: ATLAS numbering; verify at atlas.mitre.org
    DISCOVERY = "AML.TA0007"
    COLLECTION = "AML.TA0009"
    ML_ATTACK_STAGING = "AML.TA0010"
    EXFILTRATION = "AML.TA0011"
    IMPACT = "AML.TA0013"
    PRIVILEGE_ESCALATION = "AML.TA0016"
    CREDENTIAL_ACCESS = "AML.TA0003"
    LATERAL_MOVEMENT = "AML.TA0012"
    COMMAND_AND_CONTROL = "AML.TA0015"     # Added v5.1.0


@dataclass(frozen=True)
class AtlasTechnique:
    """A single MITRE ATLAS v5.4.0 technique relevant to AI agent security."""

    id: str                                # e.g., "AML.T0051.000"
    name: str
    tactic: AtlasTactic
    description: str
    agentguard_defense: str
    nist_controls: list[str] = field(default_factory=list)


ATLAS_TECHNIQUES: dict[str, AtlasTechnique] = {
    "AML.T0051.000": AtlasTechnique(
        id="AML.T0051.000",
        name="Prompt Injection: Direct",
        tactic=AtlasTactic.INITIAL_ACCESS,
        description=(
            "An attacker directly injects malicious instructions into the prompt "
            "supplied to an LLM, causing it to override its system instructions "
            "and execute attacker-controlled commands. Common in user-facing "
            "chat interfaces and agent input fields."
        ),
        agentguard_defense=(
            "agentguard/detectors/prompt_injection.py — regex and heuristic scanning "
            "of all tool call string arguments for direct injection patterns. "
            "In federal mode, detected injections block the tool call before it "
            "reaches the upstream MCP server. Mapped to OWASP LLM01:2025."
        ),
        nist_controls=["SI-10", "SI-4", "AC-3", "AU-2"],
    ),
    "AML.T0051.001": AtlasTechnique(
        id="AML.T0051.001",
        name="Prompt Injection: Indirect",
        tactic=AtlasTactic.INITIAL_ACCESS,
        description=(
            "An attacker embeds malicious instructions in external data sources "
            "(files, web pages, database results, tool descriptions) that an LLM "
            "agent retrieves and processes. The agent treats the embedded instructions "
            "as legitimate input. Includes tool description poisoning documented by "
            "Palo Alto Unit 42."
        ),
        agentguard_defense=(
            "agentguard/detectors/prompt_injection.py — scans tool arguments including "
            "retrieved content for indirect injection patterns. "
            "agentguard/detectors/tool_poisoning.py — specifically scans MCP tool "
            "descriptions for embedded instructions before the agent reads them. "
            "Mapped to OWASP LLM01:2025 and LLM03:2025."
        ),
        nist_controls=["SI-10", "SI-7", "SI-4", "AC-3", "AU-2"],
    ),
    "AML.T0062": AtlasTechnique(
        id="AML.T0062",
        name="AI Agent Context Poisoning",
        tactic=AtlasTactic.ML_ATTACK_STAGING,
        description=(
            "An attacker manipulates the context window of an AI agent to inject "
            "false information, alter agent state, or introduce malicious content "
            "that persists across agent reasoning steps. Can cause persistent "
            "misbehavior across an entire agent session."
        ),
        agentguard_defense=(
            "agentguard/detectors/prompt_injection.py and "
            "agentguard/detectors/tool_poisoning.py — detect context manipulation "
            "in tool arguments and responses. The audit log records all tool results "
            "that enter the agent context, enabling forensic reconstruction of "
            "what data was in the context when a suspicious action occurred."
        ),
        nist_controls=["SI-10", "SI-4", "AU-2", "AU-3"],
    ),
    "AML.T0063": AtlasTechnique(
        id="AML.T0063",
        name="Memory Manipulation",
        tactic=AtlasTactic.PERSISTENCE,
        description=(
            "An attacker manipulates an AI agent's persistent memory (conversation "
            "history, vector store, tool state) to plant false information that "
            "influences future agent behavior. Enables persistent compromise that "
            "survives context window resets."
        ),
        agentguard_defense=(
            "agentguard/audit_log.py — hash-chained audit log detects tampering with "
            "logged events (AML.T0063 maps to chain_violation events). Memory tool "
            "calls are subject to policy evaluation and logging. Restricting write "
            "access to memory tools via allowlist (AC-3, CM-7) reduces attack surface. "
            "Direct memory store protection requires integration with memory backend."
        ),
        nist_controls=["AU-9", "SI-7", "AC-3", "CM-7"],
    ),
    "AML.T0064": AtlasTechnique(
        id="AML.T0064",
        name="Thread Injection",
        tactic=AtlasTactic.EXECUTION,
        description=(
            "An attacker injects malicious content into an agent's conversation "
            "thread or task queue, causing the agent to execute attacker-controlled "
            "actions as part of its normal workflow. Related to indirect prompt "
            "injection but targets the agent's task management layer."
        ),
        agentguard_defense=(
            "agentguard/detectors/prompt_injection.py — thread injection patterns "
            "are included in the injection signature set. Tool call arguments "
            "sourced from thread/task data are scanned before execution. "
            "SI-10 control applies to all thread-sourced inputs."
        ),
        nist_controls=["SI-10", "SI-4", "AC-4", "AU-2"],
    ),
    "AML.T0065": AtlasTechnique(
        id="AML.T0065",
        name="Modify AI Agent Configuration",
        tactic=AtlasTactic.PERSISTENCE,
        description=(
            "An attacker modifies an AI agent's configuration — system prompts, "
            "tool permissions, model parameters, or policy files — to alter its "
            "behavior persistently. Can be achieved through prompt injection, "
            "supply chain compromise, or direct file system access."
        ),
        agentguard_defense=(
            "agentguard/policy_engine.py — policy files are loaded at startup and "
            "logged (EVENT_POLICY_LOADED). File integrity of policy YAML is not "
            "currently verified at runtime; this is a v0.2 roadmap item (SI-7 "
            "Software Integrity applied to policy files). In federal mode, policy "
            "changes require a gateway restart with a new signed configuration."
        ),
        nist_controls=["CM-7", "SI-7", "AC-3", "AU-2"],
    ),
    "AML.T0066": AtlasTechnique(
        id="AML.T0066",
        name="Publish Poisoned AI Agent Tool",
        tactic=AtlasTactic.RESOURCE_DEVELOPMENT,
        description=(
            "New in ATLAS v5.4.0 (February 2026). An attacker publishes a malicious "
            "MCP server or AI agent tool to a public registry (npm, PyPI, MCP "
            "marketplace) with embedded attack logic. Targets the supply chain by "
            "poisoning the tool ecosystem before deployment."
        ),
        agentguard_defense=(
            "agentguard/detectors/tool_poisoning.py — scans tool descriptions from "
            "any MCP server (including registry-sourced tools) for embedded instructions "
            "and anomalous content. agentguard/policies/defaults/federal_mode.yaml — "
            "upstream server allowlist prevents unapproved registry tools from being "
            "accessible to agents. RA-5 (Vulnerability Monitoring) maps to planned "
            "threat feed integration for known-poisoned tool signatures. "
            "Mapped to OWASP LLM03:2025 Supply Chain Vulnerabilities."
        ),
        nist_controls=["SI-7", "RA-5", "AC-3", "IA-9", "AU-2"],
    ),
    "AML.T0067": AtlasTechnique(
        id="AML.T0067",
        name="Escape to Host",
        tactic=AtlasTactic.PRIVILEGE_ESCALATION,
        description=(
            "New in ATLAS v5.4.0 (February 2026). An AI agent, through prompt "
            "injection or excessive agency, escapes its intended execution boundary "
            "and gains access to the host system or adjacent infrastructure. "
            "Relevant when agents have filesystem, subprocess, or network tool access."
        ),
        agentguard_defense=(
            "agentguard/policy_engine.py — tool allowlist prevents the agent from "
            "calling filesystem, subprocess, or network tools not explicitly permitted "
            "(CM-7, AC-6). agentguard/detectors/prompt_injection.py — detects "
            "injection patterns that attempt to redirect agent actions to host-level "
            "commands. Federal mode deny-by-default is the primary defense: the agent "
            "cannot access a tool it has not been explicitly granted. "
            "Mapped to OWASP LLM06:2025 Excessive Agency."
        ),
        nist_controls=["AC-3", "AC-6", "CM-7", "SI-10", "AU-2"],
    ),
}


def get_technique(technique_id: str) -> AtlasTechnique:
    """Return an ATLAS technique by its ID (e.g., 'AML.T0051.000')."""
    return ATLAS_TECHNIQUES[technique_id]


def list_techniques() -> list[AtlasTechnique]:
    """Return all ATLAS technique definitions."""
    return list(ATLAS_TECHNIQUES.values())


def get_techniques_for_tactic(tactic: AtlasTactic) -> list[AtlasTechnique]:
    """Return all techniques for a given ATLAS tactic."""
    return [t for t in ATLAS_TECHNIQUES.values() if t.tactic == tactic]
