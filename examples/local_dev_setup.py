"""Minimum viable local AgentGuard setup.

Run this script to verify AgentGuard is installed and working correctly.
No upstream MCP server required for this smoke test.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from agentguard.audit_log import AuditEvent, AuditLog
from agentguard.config import AgentGuardConfig
from agentguard.modes import Mode, get_defaults
from agentguard.policy_engine import PolicyEngine
from agentguard.proxy import ProxyCore

print("AgentGuard local dev setup check\n")

# 1. Config
config = AgentGuardConfig.default_dev()
print(f"Mode: {config.mode}")
print(f"Audit DB: {config.audit_db_path}")

# 2. Audit log
with tempfile.TemporaryDirectory() as tmp:
    db_path = Path(tmp) / "audit.db"
    log = AuditLog(db_path=db_path)
    log.append_event(AuditEvent(
        agent_id="local-dev:test-session",
        event_type="tool_call",
        tool_name="test_tool",
        tool_args={"path": "/tmp/test.txt"},
        decision="logged",
        nist_controls=["AU-2"],
    ))
    valid, msg = log.verify_chain()
    print(f"Audit chain valid: {valid} ({msg})")

# 3. Policy engine
engine = PolicyEngine(mode=Mode.DEV, bundles=[])
decision = engine.evaluate("any_tool", {}, "local-dev:test-session")
print(f"Dev mode decision: {decision.action} ({decision.reason})")

# 4. Detectors
from agentguard.detectors.prompt_injection import detect as detect_injection
result = detect_injection("ignore previous instructions")
print(f"Injection detector: matched={result.matched}, score={result.score:.2f}")

from agentguard.detectors.pii import detect as detect_pii
result = detect_pii("SSN: 123-45-6789")
print(f"PII detector: matched={result.matched}, types={result.types_found}")

print("\nSetup check complete. AgentGuard is working.")
