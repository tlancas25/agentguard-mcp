"""Regression guards for the April 2026 redforge trial-4 report.

Covers:
  - AG-BL-001.V1 CRITICAL — secret theft → sidecar forge
  - AG-BL-001.V2 HIGH — factory-reset is benign
  - AG-BL-002.R2.CARRYOVER — closes automatically with V1
  - AG-BL-004.R5a.CARRYOVER — wrong-operand inode check
  - AG-V11 MEDIUM hardening — min-entropy on operator secret
"""
from __future__ import annotations

import json
import os
import sqlite3
import sys
import tempfile
import time
from pathlib import Path

import pytest

from agentguard.approvals import (
    MIN_OPERATOR_SECRET_BYTES,
    _load_operator_secret,
    compute_operator_token,
)
from agentguard.audit_log import (
    AuditEvent,
    AuditLog,
    _install_receipt_path_for,
    _sidecar_path_for,
    generate_signing_keypair,
)
from agentguard.config import AgentGuardConfig, DEFAULT_AGENTGUARD_HOME, SelfProtectionConfig
from agentguard.modes import Mode
from agentguard.policy_engine import PolicyEngine
from agentguard.proxy import ProxyCore
from agentguard.self_protect import (
    ReferenceKind,
    _high_sensitivity_inodes,
    classify_self_reference,
)


# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def isolated_home(tmp_path: Path, monkeypatch):
    """Point DEFAULT_AGENTGUARD_HOME at a fresh tmp dir so tests don't
    stomp on the real user's ~/.agentguard."""
    home = tmp_path / "agentguard-home"
    home.mkdir()
    monkeypatch.setattr("agentguard.config.DEFAULT_AGENTGUARD_HOME", home)
    return home


# ---------------------------------------------------------------------------
# V1 — secret-reachability classification
# ---------------------------------------------------------------------------

class TestV1_SecretTreatedAsMutate:
    def test_reading_operator_secret_is_mutate(
        self, isolated_home: Path
    ) -> None:
        # Pretend the secret file exists.
        (isolated_home / "operator.secret").write_text("x" * 64)
        result = classify_self_reference(
            "shell_exec",
            {"cmd": f"cat {isolated_home / 'operator.secret'}"},
        )
        assert result.kind is ReferenceKind.MUTATE
        assert result.mutate_reason
        assert "high_sensitivity" in result.mutate_reason

    def test_reading_audit_db_remains_read(
        self, isolated_home: Path
    ) -> None:
        # audit.db is standard-protected but NOT high-sensitivity;
        # read access should still be classified READ (allowed in
        # standard mode with logging).
        (isolated_home / "audit.db").write_text("stub")
        result = classify_self_reference(
            "shell_exec",
            {"cmd": f"cat {isolated_home / 'audit.db'}"},
        )
        assert result.kind is ReferenceKind.READ


# ---------------------------------------------------------------------------
# V2 — factory-reset detection via install receipt
# ---------------------------------------------------------------------------

class TestV2_FactoryResetDetected:
    def test_receipt_written_on_first_boot(
        self, isolated_home: Path, monkeypatch
    ) -> None:
        monkeypatch.setenv("AGENTGUARD_OPERATOR_SECRET", "x" * 32)
        db = isolated_home / "audit.db"
        AuditLog(db_path=db)
        assert _install_receipt_path_for(db).exists()

    def test_factory_reset_is_detected(
        self, isolated_home: Path, monkeypatch
    ) -> None:
        """rm audit.db audit.db.hwm on a non-fresh install must not look
        the same as a fresh install."""
        monkeypatch.setenv("AGENTGUARD_OPERATOR_SECRET", "x" * 32)
        priv, _ = generate_signing_keypair()
        log = AuditLog(db_path=isolated_home / "audit.db", signing_key=priv)
        for _ in range(3):
            log.append_event(AuditEvent(
                agent_id="a", event_type="tool_call", tool_name="t",
                decision="logged",
            ))
        # Attacker deletes DB + sidecar; receipt remains.
        (isolated_home / "audit.db").unlink()
        sidecar = _sidecar_path_for(isolated_home / "audit.db")
        if sidecar.exists():
            sidecar.unlink()

        # Force the new DB's mtime noticeably after the receipt.
        time.sleep(1.1)
        log2 = AuditLog(
            db_path=isolated_home / "audit.db", signing_key=priv
        )
        ok, msg = log2.verify_chain()
        assert ok is False, msg
        assert (
            "factory-reset" in msg.lower()
            or "receipt" in msg.lower()
            or "existed before" in msg.lower()
        )


# ---------------------------------------------------------------------------
# R5a.CARRYOVER — inode check compares the right operands now
# ---------------------------------------------------------------------------

class TestR5aCARRY_InodeOperandFix:
    def test_hardlink_alias_to_audit_db_is_detected(
        self, isolated_home: Path, tmp_path: Path
    ) -> None:
        target = isolated_home / "audit.db"
        target.write_text("protected-payload", encoding="utf-8")
        alias = tmp_path / "alias-audit.db"
        try:
            os.link(target, alias)
        except (OSError, NotImplementedError, PermissionError) as e:
            pytest.skip(f"os.link unsupported on this filesystem: {e}")

        inodes = _high_sensitivity_inodes()
        assert inodes, "protected inode set should not be empty when audit.db exists"

        result = classify_self_reference(
            "shell_exec",
            {"cmd": f"cat {alias}"},
        )
        # Pre-fix behavior: ReferenceKind.NONE (directory-inode mismatch).
        # Post-fix: file-level inode compare catches it.
        assert result.kind in (ReferenceKind.READ, ReferenceKind.MUTATE)


# ---------------------------------------------------------------------------
# V11 — minimum entropy on operator secret
# ---------------------------------------------------------------------------

class TestV11_MinEntropy:
    def test_one_byte_env_secret_rejected(
        self, monkeypatch, isolated_home: Path, caplog
    ) -> None:
        monkeypatch.setenv("AGENTGUARD_OPERATOR_SECRET", "x")
        assert _load_operator_secret() is None
        assert compute_operator_token("123456") is None

    def test_exactly_min_len_accepted(
        self, monkeypatch, isolated_home: Path
    ) -> None:
        monkeypatch.setenv(
            "AGENTGUARD_OPERATOR_SECRET", "a" * MIN_OPERATOR_SECRET_BYTES
        )
        assert _load_operator_secret() is not None

    def test_short_file_secret_rejected(
        self, monkeypatch, isolated_home: Path
    ) -> None:
        monkeypatch.delenv("AGENTGUARD_OPERATOR_SECRET", raising=False)
        (isolated_home / "operator.secret").write_text("short")
        assert _load_operator_secret() is None


# ---------------------------------------------------------------------------
# Init scaffolder default flip
# ---------------------------------------------------------------------------

class TestInitDefaultFlip:
    def test_no_interactive_default_is_standard(
        self, isolated_home: Path, tmp_path: Path, monkeypatch
    ) -> None:
        # Emulate the --no-interactive init path without running click.
        from click.testing import CliRunner
        from agentguard.cli import cli

        monkeypatch.chdir(tmp_path)
        runner = CliRunner()
        result = runner.invoke(
            cli, ["init", "--no-interactive", "--no-gen-key", "--local"]
        )
        assert result.exit_code == 0, result.output
        import yaml as _yaml
        with open(tmp_path / "agentguard.yaml") as f:
            data = _yaml.safe_load(f) or {}
        assert data.get("self_protection", {}).get("mode") == "standard", data
