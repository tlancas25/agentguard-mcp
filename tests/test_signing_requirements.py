"""Tests for federal-mode signing key enforcement."""

from __future__ import annotations

from pathlib import Path

import pytest

from agentguard.audit_log import generate_signing_keypair
from agentguard.config import AgentGuardConfig
from agentguard.server import StdioServer


def _federal_config(tmp_path: Path, signing_key: str) -> AgentGuardConfig:
    """Build a minimal federal config for startup validation tests."""
    return AgentGuardConfig(
        mode="federal",
        audit_db_path=tmp_path / "audit.db",
        signing_key=signing_key,
        policy_bundles=[],
    )


def test_federal_stdio_requires_signing_key(tmp_path: Path) -> None:
    """Federal stdio server should fail fast when no signing key is configured."""
    cfg = _federal_config(tmp_path, signing_key="")
    with pytest.raises(ValueError, match="Federal mode requires a valid Ed25519 signing key"):
        StdioServer(cfg)


def test_federal_stdio_rejects_invalid_signing_key(tmp_path: Path) -> None:
    """Federal stdio server should fail fast for malformed signing keys."""
    cfg = _federal_config(tmp_path, signing_key="not-a-valid-ed25519-key")
    with pytest.raises(ValueError, match="Federal mode requires a valid Ed25519 signing key"):
        StdioServer(cfg)


def test_federal_stdio_accepts_valid_signing_key(tmp_path: Path) -> None:
    """Federal stdio server should start when a valid signing key is provided."""
    private_key, _ = generate_signing_keypair()
    cfg = _federal_config(tmp_path, signing_key=private_key)

    server = StdioServer(cfg)
    assert server.audit_log.signing_enabled
    server.stop()


def test_federal_gateway_requires_signing_key(tmp_path: Path) -> None:
    """Federal HTTP gateway should fail fast without a signing key."""
    pytest.importorskip("fastapi")

    from agentguard.gateway import create_app

    cfg = _federal_config(tmp_path, signing_key="")
    with pytest.raises(ValueError, match="Federal mode requires a valid Ed25519 signing key"):
        create_app(cfg)
