"""AgentGuard detectors package.

Detectors analyze tool call arguments and MCP metadata for security threats.
Each detector returns a DetectionResult with:
- matched: bool indicating whether a threat was found
- score: float 0.0-1.0 indicating confidence
- nist_controls: list of NIST 800-53 controls this detector addresses
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class DetectionResult:
    """Result from any AgentGuard detector."""

    matched: bool
    score: float = 0.0
    patterns_hit: list[str] = field(default_factory=list)
    types_found: list[str] = field(default_factory=list)
    nist_controls: list[str] = field(default_factory=list)
    detail: str = ""
    raw_findings: list[dict[str, Any]] = field(default_factory=list)

    @classmethod
    def clean(cls, nist_controls: list[str]) -> "DetectionResult":
        """Return a DetectionResult indicating no threat detected."""
        return cls(matched=False, score=0.0, nist_controls=nist_controls)


__all__ = ["DetectionResult"]
