"""Secret and API key detector for AgentGuard.

Detects accidental transmission of credentials, API keys, tokens, and
private keys through MCP tool calls.

NIST 800-53 controls addressed:
- SI-10: Information Input Validation
- SC-8: Transmission Confidentiality (prevent secret exfiltration)
- AC-3: Access Enforcement (credentials should not flow through agents)
"""

from __future__ import annotations

import re
from typing import Any

from agentguard.detectors import DetectionResult
from agentguard.detectors.normalize import concatenated, expand_variants

NIST_CONTROLS = ["SI-10", "SC-8", "AC-3"]

# Secret patterns: (type_label, regex, confidence_score)
_SECRET_PATTERNS: list[tuple[str, re.Pattern[str], float]] = [
    # AWS
    (
        "aws_access_key",
        re.compile(r"\b(AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}\b"),
        0.95,
    ),
    (
        "aws_secret_key",
        re.compile(r"\b[0-9a-zA-Z/+]{40}\b"),
        0.5,  # Lower confidence, must be near "secret" keyword
    ),
    # GitHub tokens
    (
        "github_token",
        re.compile(r"\bghp_[0-9a-zA-Z]{36}\b|\bgho_[0-9a-zA-Z]{36}\b|\bghs_[0-9a-zA-Z]{36}\b|\bghr_[0-9a-zA-Z]{36}\b"),
        0.98,
    ),
    # Generic API keys
    (
        "api_key_generic",
        re.compile(r"\b(?:api[_\-]?key|apikey)[=:\s]+['\"]?[0-9a-zA-Z\-_]{20,}\b", re.IGNORECASE),
        0.8,
    ),
    # Bearer tokens
    (
        "bearer_token",
        re.compile(r"\bBearer\s+[0-9a-zA-Z\-._~+/]+=*\b"),
        0.85,
    ),
    # JWT tokens
    (
        "jwt",
        re.compile(r"\beyJ[0-9a-zA-Z\-_]+\.[0-9a-zA-Z\-_]+\.[0-9a-zA-Z\-_]+\b"),
        0.9,
    ),
    # PEM private keys. The trailing "private key" marker alone is enough
    # signal even if dashes have been stripped or case changed.
    (
        "pem_private_key",
        re.compile(
            r"(?:-{2,}\s*)?BEGIN\s+(?:RSA\s+|EC\s+|OPENSSH\s+|DSA\s+|ENCRYPTED\s+)?PRIVATE\s+KEY",
            re.IGNORECASE,
        ),
        0.99,
    ),
    # Slack tokens
    (
        "slack_token",
        re.compile(r"\bxox[baprs]-[0-9a-zA-Z\-]{10,}\b"),
        0.97,
    ),
    # Stripe keys
    (
        "stripe_key",
        re.compile(r"\b(?:sk|rk)_(?:live|test)_[0-9a-zA-Z]{24,}\b"),
        0.98,
    ),
    # Google API key
    (
        "google_api_key",
        re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"),
        0.97,
    ),
    # Twilio keys
    (
        "twilio_key",
        re.compile(r"\bSK[0-9a-fA-F]{32}\b"),
        0.9,
    ),
    # Anthropic API key
    (
        "anthropic_api_key",
        re.compile(r"\bsk-ant-[0-9a-zA-Z\-]{40,}\b"),
        0.99,
    ),
    # OpenAI API key
    (
        "openai_api_key",
        re.compile(r"\bsk-[0-9a-zA-Z]{48,}\b"),
        0.9,
    ),
    # Generic secret keyword patterns
    (
        "secret_assignment",
        re.compile(
            r"\b(?:secret|password|passwd|pwd|token|credential)[=:\s]+['\"]?[^\s'\"]{8,}['\"]?\b",
            re.IGNORECASE,
        ),
        0.65,
    ),
    # Base64 encoded secrets hint
    (
        "base64_secret",
        re.compile(
            r"\b(?:secret|key|token|credential)[=:\s]+['\"]?[A-Za-z0-9+/]{32,}={0,2}['\"]?\b",
            re.IGNORECASE,
        ),
        0.6,
    ),
]


def detect(text: str, confidence_threshold: float = 0.6) -> DetectionResult:
    """Detect secrets and credentials in a text string.

    Args:
        text: Text to scan.
        confidence_threshold: Minimum pattern confidence to flag.

    Returns:
        DetectionResult with matched flag and types found.
    """
    if not text or not text.strip():
        return DetectionResult.clean(NIST_CONTROLS)

    types_found: list[str] = []
    findings: list[dict[str, Any]] = []
    max_score: float = 0.0

    seen: set[str] = set()
    for variant in expand_variants(text):
        for secret_type, pattern, confidence in _SECRET_PATTERNS:
            if confidence < confidence_threshold:
                continue
            if secret_type in seen:
                continue
            matches = pattern.findall(variant)
            if matches:
                seen.add(secret_type)
                types_found.append(secret_type)
                findings.append({
                    "type": secret_type,
                    "count": len(matches),
                    "confidence": confidence,
                })
                if confidence > max_score:
                    max_score = confidence

    if not types_found:
        return DetectionResult.clean(NIST_CONTROLS)

    return DetectionResult(
        matched=True,
        score=max_score,
        types_found=types_found,
        nist_controls=NIST_CONTROLS,
        detail=f"Secrets detected: {', '.join(types_found)}",
        raw_findings=findings,
    )


def detect_in_tool_args(tool_args: dict[str, Any]) -> DetectionResult:
    """Scan all string values in a tool args dict for secrets."""
    worst = DetectionResult.clean(NIST_CONTROLS)
    all_types: list[str] = []

    for key, value in tool_args.items():
        if isinstance(value, str):
            result = detect(value)
            if result.matched:
                all_types.extend(result.types_found)
                if result.score > worst.score:
                    worst = result
                    worst.detail = f"Secret in arg '{key}': {result.detail}"
        elif isinstance(value, dict):
            nested = detect_in_tool_args(value)
            if nested.score > worst.score:
                worst = nested
                all_types.extend(nested.types_found)

    flat = concatenated(tool_args)
    if flat:
        flat_result = detect(flat)
        if flat_result.matched:
            all_types.extend(flat_result.types_found)
            if flat_result.score > worst.score:
                worst = flat_result
                worst.detail = f"Secret in combined args: {flat_result.detail}"

    if all_types:
        worst.types_found = list(set(all_types))

    return worst
