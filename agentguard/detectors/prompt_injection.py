"""Prompt injection detector for AgentGuard.

Detects attempts to hijack AI agent behavior through tool call arguments.
Covers direct injection (attacker controls the prompt) and indirect injection
(attacker controls data the AI reads, per Palo Alto Unit 42 / OWASP LLM Top 10).

NIST 800-53 controls addressed:
- SI-10: Information Input Validation
- SI-4: System Monitoring
"""

from __future__ import annotations

import logging
import re
from typing import Any, Callable, Optional

from agentguard.detectors import DetectionResult
from agentguard.detectors.normalize import concatenated, expand_variants

logger = logging.getLogger(__name__)

NIST_CONTROLS = ["SI-10", "SI-4"]

# Patterns from Simon Willison's catalog, OWASP LLM Top 10, and Palo Alto Unit 42 research
INJECTION_PATTERNS: list[tuple[str, str, float]] = [
    # (pattern_name, regex, score_contribution)
    ("ignore_previous", r"ignore\s+(all\s+)?previous\s+instructions?", 0.9),
    ("disregard_instructions", r"disregard\s+(your\s+)?(previous\s+)?instructions?", 0.9),
    ("system_prompt_leak", r"(reveal|print|show|output|display)\s+(your\s+)?(system\s+prompt|instructions)", 0.85),
    ("new_instructions", r"(new|updated|revised)\s+instructions?\s*:", 0.75),
    ("assistant_role_hijack", r"(you\s+are\s+now|act\s+as|pretend\s+(to\s+be|you\s+are))\s+\w", 0.8),
    ("jailbreak_dan", r"\bDAN\b", 0.7),
    ("jailbreak_do_anything", r"do\s+anything\s+now", 0.7),
    ("override_safety", r"(override|bypass|disable|ignore)\s+(your\s+)?(safety|ethical|moral|content)", 0.9),
    ("escape_context", r"(end\s+of\s+(context|conversation|prompt)|--- ?end|<<<end)", 0.75),
    ("xml_injection", r"</?system>|</?prompt>|</?instructions?>", 0.8),
    ("markdown_injection", r"```\s*system\b|```\s*instructions\b", 0.75),
    ("base64_instruction", r"base64\s*(decode|encoded)\s*(instruction|command|prompt)", 0.7),
    ("prompt_leaking", r"(what\s+are\s+your|print\s+your|show\s+me\s+your)\s+(initial\s+)?(prompt|instructions)", 0.85),
    ("tool_hijack", r"call\s+(the\s+)?\w+\s+tool\s+with", 0.65),
    ("indirect_injection_marker", r"\[\[INJECT\]\]|\[\[OVERRIDE\]\]|\[\[SYSTEM\]\]", 0.95),
    ("context_terminator", r"(<< ?/?(human|assistant|system) ?>>|<\|im_end\|>|<\|endoftext\|>)", 0.85),
    ("goal_hijack", r"(forget|ignore)\s+(your\s+)?(original\s+)?(goal|task|objective|purpose)", 0.8),
    ("confidential_exfil", r"(send|email|transmit|exfiltrate|upload)\s+(the\s+)?(system\s+)?(prompt|instructions|context)", 0.9),
]

_COMPILED_PATTERNS = [
    (name, re.compile(pattern, re.IGNORECASE | re.MULTILINE), score)
    for name, pattern, score in INJECTION_PATTERNS
]


def detect(
    text: str,
    score_threshold: float = 0.7,
    llm_checker: Optional[Callable[[str], float]] = None,
) -> DetectionResult:
    """Detect prompt injection in a text string.

    Args:
        text: The text to analyze (tool args serialized, file content, etc.)
        score_threshold: Minimum aggregate score to flag as matched.
        llm_checker: Optional callable that takes text and returns injection score 0.0-1.0.
                     For future integration with a classification model.

    Returns:
        DetectionResult with matched flag, score, and patterns hit.
    """
    if not text or not text.strip():
        return DetectionResult.clean(NIST_CONTROLS)

    patterns_hit: list[str] = []
    aggregate_score: float = 0.0

    # Scan the original plus every decoded / normalized variant so
    # unicode-homoglyph, base64, hex, rot13, and URL-encoded wrappers
    # can't hide an injection from the regex layer (F5).
    hit_names: set[str] = set()
    for variant in expand_variants(text):
        for name, compiled, score in _COMPILED_PATTERNS:
            if name in hit_names:
                continue
            if compiled.search(variant):
                hit_names.add(name)
                patterns_hit.append(name)
                aggregate_score = min(1.0, aggregate_score + score)

    # Heuristic: suspicious keyword density over the canonical form
    density_score = _keyword_density_score(expand_variants(text)[1])
    if density_score > 0.3:
        patterns_hit.append(f"keyword_density:{density_score:.2f}")
        aggregate_score = min(1.0, aggregate_score + density_score * 0.5)

    # Optional LLM-based check
    if llm_checker is not None and aggregate_score < score_threshold:
        try:
            llm_score = llm_checker(text)
            if llm_score > 0.5:
                patterns_hit.append(f"llm_classifier:{llm_score:.2f}")
                aggregate_score = min(1.0, aggregate_score + llm_score * 0.4)
        except Exception as e:
            logger.warning("LLM injection check failed: %s", e)

    matched = aggregate_score >= score_threshold
    return DetectionResult(
        matched=matched,
        score=aggregate_score,
        patterns_hit=patterns_hit,
        nist_controls=NIST_CONTROLS,
        detail=(
            f"Injection score {aggregate_score:.2f} >= threshold {score_threshold}"
            if matched
            else f"Injection score {aggregate_score:.2f} < threshold {score_threshold}"
        ),
    )


def detect_in_tool_args(
    tool_args: dict[str, Any],
    score_threshold: float = 0.7,
) -> DetectionResult:
    """Scan all string values in a tool args dict for injection.

    Args:
        tool_args: The MCP tool call arguments.
        score_threshold: Minimum score to flag.

    Returns:
        Worst-case DetectionResult across all string arg values.
    """
    worst = DetectionResult.clean(NIST_CONTROLS)

    for key, value in tool_args.items():
        if isinstance(value, str):
            result = detect(value, score_threshold=score_threshold)
            if result.score > worst.score:
                worst = result
                worst.detail = f"Injection detected in arg '{key}': {result.detail}"
        elif isinstance(value, dict):
            nested = detect_in_tool_args(value, score_threshold)
            if nested.score > worst.score:
                worst = nested

    # Flattened view: defeats payloads split across arg keys.
    flat = concatenated(tool_args)
    if flat:
        flat_result = detect(flat, score_threshold=score_threshold)
        if flat_result.score > worst.score:
            worst = flat_result
            worst.detail = (
                f"Injection detected across combined args: {flat_result.detail}"
            )

    return worst


_SUSPICIOUS_KEYWORDS = [
    "instruction", "prompt", "system", "override", "ignore", "jailbreak",
    "bypass", "forget", "pretend", "roleplay", "act as", "you are now",
    "disregard", "confidential", "hidden", "secret instruction",
]


def _keyword_density_score(text: str) -> float:
    """Return a 0.0-1.0 score based on suspicious keyword density."""
    if not text:
        return 0.0
    text_lower = text.lower()
    word_count = max(len(text.split()), 1)
    hits = sum(1 for kw in _SUSPICIOUS_KEYWORDS if kw in text_lower)
    # Density: hits per 100 words, capped at 1.0
    return min(1.0, (hits / word_count) * 100 / len(_SUSPICIOUS_KEYWORDS))
