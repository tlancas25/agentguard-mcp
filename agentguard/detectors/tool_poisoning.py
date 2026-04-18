"""MCP tool description poisoning detector for AgentGuard.

Tool poisoning is the attack vector documented by Palo Alto Unit 42 where
malicious instructions are embedded inside MCP tool *descriptions* (not
user prompts). Because agents read tool descriptions to understand how to
use tools, injected instructions in descriptions are executed with high
trust and without user review.

This detector scans tool descriptions at startup and on every tools/list
response.

NIST 800-53 controls addressed:
- SI-10: Information Input Validation
- SI-4: System Monitoring
- AC-3: Access Enforcement
"""

from __future__ import annotations

import re
from typing import Any

from agentguard.detectors import DetectionResult

NIST_CONTROLS = ["SI-10", "SI-4", "AC-3"]

# Patterns specifically targeting tool description poisoning
# These are adapted from Palo Alto Unit 42 MCP attack research (2025)
_POISONING_PATTERNS: list[tuple[str, re.Pattern[str], float]] = [
    # Direct instruction injection in descriptions
    (
        "hidden_instructions",
        re.compile(
            r"(?:IMPORTANT|NOTE|ATTENTION|INSTRUCTION)[:\s].*(?:always|never|must|should)\s+",
            re.IGNORECASE | re.DOTALL,
        ),
        0.7,
    ),
    # System-level instruction markers
    (
        "system_marker",
        re.compile(r"<system>|<instructions?>|<SYSTEM>|\[SYSTEM\]|\[INSTRUCTIONS?\]"),
        0.85,
    ),
    # Data exfiltration instructions in tool descriptions
    (
        "exfil_instruction",
        re.compile(
            r"(?:send|transmit|upload|post|exfiltrate)\s+(?:all|the|any)\s+(?:data|files?|credentials?|secrets?|tokens?)",
            re.IGNORECASE,
        ),
        0.95,
    ),
    # Tool override / redirect instructions
    (
        "tool_redirect",
        re.compile(
            r"(?:instead|before|after)\s+(?:using|calling|executing)\s+this\s+tool",
            re.IGNORECASE,
        ),
        0.7,
    ),
    # Credential harvesting patterns
    (
        "credential_harvest",
        re.compile(
            r"(?:collect|gather|harvest|retrieve)\s+(?:all\s+)?(?:password|credential|token|key|secret)",
            re.IGNORECASE,
        ),
        0.9,
    ),
    # Lateral movement instructions
    (
        "lateral_movement",
        re.compile(
            r"(?:access|connect\s+to|read\s+from)\s+(?:all|other|every)\s+(?:server|system|service|database)",
            re.IGNORECASE,
        ),
        0.75,
    ),
    # Persistence instructions
    (
        "persistence_attempt",
        re.compile(
            r"(?:add|insert|write|create)\s+(?:a\s+)?(?:backdoor|cron|scheduled\s+task|startup|autorun)",
            re.IGNORECASE,
        ),
        0.9,
    ),
    # Steganographic embedding hints
    (
        "hidden_content",
        re.compile(
            r"(?:hidden|invisible|whitespace|zero.width|unicode\s+char)\s+(?:message|instruction|data)",
            re.IGNORECASE,
        ),
        0.85,
    ),
    # Suspicious ASCII art / encoding in descriptions
    (
        "encoded_payload",
        re.compile(r"(?:base64|hex|rot13|caesar)\s+(?:encoded|decode|cipher)", re.IGNORECASE),
        0.8,
    ),
    # Ignore/override safety instructions targeted at tool descriptions
    (
        "safety_override_in_desc",
        re.compile(
            r"(?:ignore|bypass|override)\s+(?:safety|security|policy|restriction|limit)",
            re.IGNORECASE,
        ),
        0.9,
    ),
]


def scan_tool_description(tool_name: str, description: str) -> DetectionResult:
    """Scan a single MCP tool description for poisoning patterns.

    Args:
        tool_name: Name of the tool being scanned.
        description: The tool's description string.

    Returns:
        DetectionResult indicating whether the description appears poisoned.
    """
    if not description or not description.strip():
        return DetectionResult.clean(NIST_CONTROLS)

    patterns_hit: list[str] = []
    max_score: float = 0.0

    for name, pattern, score in _POISONING_PATTERNS:
        if pattern.search(description):
            patterns_hit.append(name)
            if score > max_score:
                max_score = score

    if not patterns_hit:
        return DetectionResult.clean(NIST_CONTROLS)

    return DetectionResult(
        matched=True,
        score=max_score,
        patterns_hit=patterns_hit,
        nist_controls=NIST_CONTROLS,
        detail=f"Tool '{tool_name}' description contains poisoning patterns: {', '.join(patterns_hit)}",
    )


def scan_tools_list(tools: list[dict[str, Any]]) -> list[DetectionResult]:
    """Scan a full MCP tools/list response for poisoned tool descriptions.

    Args:
        tools: List of tool objects from an MCP tools/list response.
                Each tool object should have 'name' and 'description' fields.

    Returns:
        List of DetectionResults, one per tool. Only flagged tools have matched=True.
    """
    results: list[DetectionResult] = []

    for tool in tools:
        name = tool.get("name", "unknown")
        description = tool.get("description", "")
        result = scan_tool_description(name, description)
        if result.matched:
            results.append(result)

    return results
