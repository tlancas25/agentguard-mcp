"""Pytest fixtures for AgentGuard tests."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Generator

import pytest
import yaml

from agentguard.audit_log import AuditLog
from agentguard.config import AgentGuardConfig, UpstreamServerConfig
from agentguard.modes import Mode
from agentguard.policy_engine import PolicyBundle, PolicyEngine


@pytest.fixture
def tmp_db(tmp_path: Path) -> Path:
    """Provide a temporary SQLite database path."""
    return tmp_path / "test_audit.db"


@pytest.fixture
def audit_log(tmp_db: Path) -> AuditLog:
    """Provide a fresh AuditLog instance backed by a temp database."""
    return AuditLog(db_path=tmp_db)


@pytest.fixture
def audit_log_with_signing(tmp_db: Path) -> AuditLog:
    """Provide an AuditLog instance with Ed25519 signing enabled."""
    from agentguard.audit_log import generate_signing_keypair
    private_b64, _ = generate_signing_keypair()
    return AuditLog(db_path=tmp_db, signing_key=private_b64)


@pytest.fixture
def dev_policy_bundle(tmp_path: Path) -> PolicyBundle:
    """Provide a dev mode policy bundle."""
    policy_data = {
        "name": "test_dev",
        "default_action": "log",
        "tool_allowlist": [],
        "tool_denylist": [],
        "pii_scan": False,
        "injection_scan": False,
        "rules": [],
    }
    policy_path = tmp_path / "dev_policy.yaml"
    policy_path.write_text(yaml.dump(policy_data))
    return PolicyBundle.from_yaml(policy_path)


@pytest.fixture
def federal_policy_bundle(tmp_path: Path) -> PolicyBundle:
    """Provide a federal mode policy bundle with an allowlist."""
    policy_data = {
        "name": "test_federal",
        "default_action": "deny",
        "tool_allowlist": ["allowed_tool", "another_allowed_tool"],
        "tool_denylist": ["dangerous_tool"],
        "pii_scan": True,
        "injection_scan": True,
        "require_signing": True,
        "rules": [],
    }
    policy_path = tmp_path / "federal_policy.yaml"
    policy_path.write_text(yaml.dump(policy_data))
    return PolicyBundle.from_yaml(policy_path)


@pytest.fixture
def dev_policy_engine(dev_policy_bundle: PolicyBundle) -> PolicyEngine:
    """Provide a dev mode policy engine."""
    return PolicyEngine(mode=Mode.DEV, bundles=[dev_policy_bundle])


@pytest.fixture
def federal_policy_engine(federal_policy_bundle: PolicyBundle) -> PolicyEngine:
    """Provide a federal mode policy engine."""
    return PolicyEngine(mode=Mode.FEDERAL, bundles=[federal_policy_bundle])


@pytest.fixture
def dev_config(tmp_path: Path) -> AgentGuardConfig:
    """Provide a minimal dev mode AgentGuardConfig."""
    return AgentGuardConfig(
        mode="dev",
        audit_db_path=tmp_path / "audit.db",
        policy_bundles=[],
    )


@pytest.fixture
def federal_config(tmp_path: Path) -> AgentGuardConfig:
    """Provide a minimal federal mode AgentGuardConfig."""
    return AgentGuardConfig(
        mode="federal",
        audit_db_path=tmp_path / "audit.db",
        policy_bundles=[],
        federal={
            "agency_id": "TEST-AGENCY",
            "system_name": "Test System",
            "impact_level": "MODERATE",
            "require_signing": False,
        },
    )


@pytest.fixture
def sample_tool_calls() -> list[dict]:
    """Load canonical sample tool calls from fixtures."""
    fixture_path = Path(__file__).parent / "fixtures" / "sample_tool_calls.json"
    if fixture_path.exists():
        return json.loads(fixture_path.read_text())
    return []


@pytest.fixture
def mock_mcp_client_info() -> dict:
    """Sample MCP client info for initialize requests."""
    return {
        "clientInfo": {
            "name": "claude-code",
            "version": "1.0.0",
        },
        "protocolVersion": "2024-11-05",
    }
