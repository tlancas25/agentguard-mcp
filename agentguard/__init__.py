"""AgentGuard MCP — Open-source MCP security gateway for federal and defense AI.

This package provides a transparent proxy layer between MCP clients (AI agents)
and MCP servers, enforcing NIST 800-53 Rev 5 controls and generating FedRAMP
audit evidence.
"""

from __future__ import annotations

__version__ = "0.1.0"
__author__ = "Terrell Lancaster"
__license__ = "MIT"

from agentguard.config import AgentGuardConfig
from agentguard.modes import Mode

__all__ = [
    "__version__",
    "__author__",
    "__license__",
    "AgentGuardConfig",
    "Mode",
]
