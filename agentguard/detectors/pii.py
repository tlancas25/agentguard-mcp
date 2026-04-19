"""PII (Personally Identifiable Information) detector for AgentGuard.

Scans tool call arguments for sensitive personal data that should not
pass through AI agent tool calls without explicit policy authorization.

NIST 800-53 controls addressed:
- SI-10: Information Input Validation
- SC-28: Protection of Information at Rest (by detecting before storage)
"""

from __future__ import annotations

import re
from typing import Any

from agentguard.detectors import DetectionResult
from agentguard.detectors.normalize import concatenated, expand_variants

NIST_CONTROLS = ["SI-10", "SC-28"]

# Separator characters accepted between SSN groups; covers ASCII -, ASCII space,
# dot, and unicode dashes that attackers swap in to dodge naive regex.
_SSN_SEP = r"[-\u2010-\u2015.\u2212 \u00a0\u2007\u202f]"
_SSN_STRICT_RE = re.compile(
    rf"\b(?!000|666)\d{{3}}{_SSN_SEP}(?!00)\d{{2}}{_SSN_SEP}(?!0000)\d{{4}}\b"
)


# PII regex patterns
_PII_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    # US Social Security Number — accepts ASCII dash/space and common unicode
    # dash variants. Bare 9-digit runs are caught by the unpunctuated pattern.
    (
        "ssn",
        _SSN_STRICT_RE,
    ),
    (
        "ssn_unpunct",
        re.compile(r"(?<!\d)(?!000)(?!666)\d{3}(?!00)\d{2}(?!0000)\d{4}(?!\d)"),
    ),
    # Credit card numbers (Visa, MC, Amex, Discover) with Luhn-plausible structure
    (
        "credit_card",
        re.compile(
            r"\b(?:"
            r"4\d{3}(?:[- ]?\d{4}){3}|"
            r"5[1-5]\d{2}(?:[- ]?\d{4}){3}|"
            r"3[47]\d{2}[- ]?\d{6}[- ]?\d{5}|"
            r"6(?:011|5\d{2})(?:[- ]?\d{4}){3}"
            r")\b"
        ),
    ),
    # US phone numbers
    (
        "phone_us",
        re.compile(
            r"\b(?:\+1[- ]?)?\(?[2-9]\d{2}\)?[- ]?\d{3}[- ]?\d{4}\b"
        ),
    ),
    # Email addresses
    (
        "email",
        re.compile(
            r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b"
        ),
    ),
    # Date of birth patterns (common formats)
    (
        "dob",
        re.compile(
            r"\b(?:DOB|date of birth|born)[:\s]+\d{1,2}[/\-]\d{1,2}[/\-]\d{2,4}\b",
            re.IGNORECASE,
        ),
    ),
    # US Passport number
    (
        "passport",
        re.compile(r"\b[A-Z]{1,2}\d{6,9}\b"),
    ),
    # US Driver's License (generic pattern — varies by state)
    (
        "drivers_license",
        re.compile(r"\b[A-Z]{1,2}\d{5,8}\b"),
    ),
    # IP addresses (may indicate personal device identification)
    (
        "ip_address",
        re.compile(
            r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
        ),
    ),
    # Street addresses (heuristic)
    (
        "street_address",
        re.compile(
            r"\b\d{1,5}\s+[A-Za-z]{2,}\s+(Street|St|Avenue|Ave|Boulevard|Blvd|Road|Rd|Lane|Ln|Drive|Dr|Court|Ct|Circle|Cir|Way|Place|Pl)\b",
            re.IGNORECASE,
        ),
    ),
    # US EIN (Employer ID)
    (
        "ein",
        re.compile(r"\b\d{2}-\d{7}\b"),
    ),
    # Medical record number hints
    (
        "mrn_hint",
        re.compile(r"\b(?:MRN|medical record|patient\s+id)[:\s]+\w+\b", re.IGNORECASE),
    ),
]


def detect(text: str) -> DetectionResult:
    """Detect PII in a text string.

    Args:
        text: Text to scan.

    Returns:
        DetectionResult with matched flag and list of PII types found.
    """
    if not text or not text.strip():
        return DetectionResult.clean(NIST_CONTROLS)

    types_found: list[str] = []
    findings: list[dict[str, Any]] = []

    seen: set[str] = set()
    for variant in expand_variants(text):
        for pii_type, pattern in _PII_PATTERNS:
            if pii_type in seen:
                continue
            matches = pattern.findall(variant)
            if matches:
                seen.add(pii_type)
                types_found.append(pii_type)
                findings.append({"type": pii_type, "count": len(matches)})

    if not types_found:
        return DetectionResult.clean(NIST_CONTROLS)

    # Score based on number and severity of types found
    high_severity = {"ssn", "ssn_unpunct", "credit_card", "passport", "mrn_hint"}
    score = min(
        1.0,
        len(types_found) * 0.2 + sum(0.3 for t in types_found if t in high_severity),
    )

    return DetectionResult(
        matched=True,
        score=score,
        types_found=types_found,
        nist_controls=NIST_CONTROLS,
        detail=f"PII types detected: {', '.join(types_found)}",
        raw_findings=findings,
    )


def detect_in_tool_args(tool_args: dict[str, Any]) -> DetectionResult:
    """Scan all string values in a tool args dict for PII.

    Args:
        tool_args: MCP tool call arguments.

    Returns:
        Worst-case DetectionResult across all string arg values.
    """
    worst = DetectionResult.clean(NIST_CONTROLS)
    all_types: list[str] = []

    for key, value in tool_args.items():
        if isinstance(value, str):
            result = detect(value)
            if result.matched:
                all_types.extend(result.types_found)
                if result.score > worst.score:
                    worst = result
                    worst.detail = f"PII in arg '{key}': {result.detail}"
        elif isinstance(value, dict):
            nested = detect_in_tool_args(value)
            if nested.score > worst.score:
                worst = nested
                all_types.extend(nested.types_found)

    # Flatten every nested string and re-scan so attackers can't hide PII
    # by splitting it across arg keys (F5).
    flat = concatenated(tool_args)
    if flat:
        flat_result = detect(flat)
        if flat_result.matched:
            all_types.extend(flat_result.types_found)
            if flat_result.score > worst.score:
                worst = flat_result
                worst.detail = f"PII in combined args: {flat_result.detail}"

    if all_types:
        worst.types_found = list(set(all_types))

    return worst
