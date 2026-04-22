"""Regression guards for the April 2026 redforge trial-3 report.

Each class locks in the fix for a BOOM finding in
``targets/agentguard-mcp-20260422T145900Z``. Do not relax these
assertions without a follow-up trial report clearing the primitive.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import sqlite3
import sys
import tempfile
from pathlib import Path

import pytest

from agentguard.audit_log import (
    AuditEvent,
    AuditLog,
    _sidecar_path_for,
    _sidecar_read,
    _sidecar_write,
    generate_signing_keypair,
)
from agentguard.approvals import (
    ApprovalManager,
    compute_operator_token,
)
from agentguard.config import AgentGuardConfig, SelfProtectionConfig
from agentguard.modes import Mode
from agentguard.policy_engine import PolicyBundle, PolicyEngine
from agentguard.proxy import ProxyCore
from agentguard.self_protect import ReferenceKind, classify_self_reference


# ---------------------------------------------------------------------------
# R1 — CRITICAL — audit_meta same-surface anchor
# ---------------------------------------------------------------------------

class TestR1_SidecarAnchor:
    def _log(self, tmp_path: Path, monkeypatch) -> AuditLog:
        monkeypatch.setenv("AGENTGUARD_OPERATOR_SECRET", "test-sidecar-secret")
        priv, _ = generate_signing_keypair()
        return AuditLog(db_path=tmp_path / "audit.db", signing_key=priv)

    def test_sidecar_is_written_on_append(
        self, tmp_path: Path, monkeypatch
    ) -> None:
        log = self._log(tmp_path, monkeypatch)
        log.append_event(AuditEvent(
            agent_id="a", event_type="tool_call", tool_name="t",
            decision="logged",
        ))
        sidecar = _sidecar_read(_sidecar_path_for(tmp_path / "audit.db"))
        assert sidecar is not None
        assert sidecar["event_count"] == 1
        assert sidecar["signed"] is True
        assert sidecar["signature"]

    def test_same_surface_wipe_is_detected(
        self, tmp_path: Path, monkeypatch
    ) -> None:
        """The trial-3 primitive: wipe events AND reset audit_meta in one
        SQLite commit. The sidecar outside the DB still remembers."""
        log = self._log(tmp_path, monkeypatch)
        for _ in range(3):
            log.append_event(AuditEvent(
                agent_id="a", event_type="tool_call", tool_name="t",
                decision="logged",
            ))

        conn = sqlite3.connect(str(tmp_path / "audit.db"))
        conn.execute("DELETE FROM events")
        conn.execute(
            "UPDATE audit_meta SET event_count = 0, "
            "high_water_hash = '00000000000000000000000000000000"
            "00000000000000000000000000000000'"
        )
        conn.commit()
        conn.close()

        ok, msg = log.verify_chain()
        assert ok is False, msg
        assert "sidecar" in msg.lower() or "tamper" in msg.lower(), msg

    def test_sidecar_deletion_is_detected(
        self, tmp_path: Path, monkeypatch
    ) -> None:
        log = self._log(tmp_path, monkeypatch)
        log.append_event(AuditEvent(
            agent_id="a", event_type="tool_call", tool_name="t",
            decision="logged",
        ))
        sidecar = _sidecar_path_for(tmp_path / "audit.db")
        sidecar.unlink()

        ok, msg = log.verify_chain()
        assert ok is False
        assert "sidecar" in msg.lower()

    def test_sidecar_signature_forgery_detected(
        self, tmp_path: Path, monkeypatch
    ) -> None:
        log = self._log(tmp_path, monkeypatch)
        log.append_event(AuditEvent(
            agent_id="a", event_type="tool_call", tool_name="t",
            decision="logged",
        ))
        sidecar_path = _sidecar_path_for(tmp_path / "audit.db")
        doc = json.loads(sidecar_path.read_text())
        # Attacker tampers with event_count but can't resign without secret.
        doc["event_count"] = 999
        sidecar_path.write_text(json.dumps(doc))

        ok, msg = log.verify_chain()
        assert ok is False
        assert (
            "signature" in msg.lower()
            or "tamper" in msg.lower()
            or "does not match" in msg.lower()
        )


# ---------------------------------------------------------------------------
# R4a — CRITICAL — No operator.secret → request() must refuse
# ---------------------------------------------------------------------------

class TestR4a_NoSecretRefuse:
    def test_request_refuses_when_no_secret(
        self, tmp_path: Path, monkeypatch
    ) -> None:
        monkeypatch.delenv("AGENTGUARD_OPERATOR_SECRET", raising=False)
        # Point the secret lookup at a dir that does not exist.
        fake_home = tmp_path / "empty-home"
        monkeypatch.setattr(
            "agentguard.config.DEFAULT_AGENTGUARD_HOME", fake_home
        )
        # Also bypass the ApprovalManager auto-create so we can test the
        # hard-fail path. We do that by letting ApprovalManager create
        # the dir but then removing the secret before calling request().
        approvals_dir = tmp_path / "approvals"
        mgr = ApprovalManager(approvals_dir)
        secret_path = fake_home / "operator.secret"
        if secret_path.exists():
            secret_path.unlink()
        # Clear env again after ApprovalManager ran.
        monkeypatch.delenv("AGENTGUARD_OPERATOR_SECRET", raising=False)

        result = mgr.request(
            tool_name="shell_exec",
            tool_args_preview="rm -rf ~/.agentguard",
            agent_id="attacker",
            mutate_reason="rm",
            path_hit="~/.agentguard",
            timeout_seconds=1,
        )
        assert result.approved is False
        assert "secret" in result.reason.lower() or result.reason == "no_operator_secret"

    def test_approval_manager_auto_provisions_secret(
        self, tmp_path: Path, monkeypatch
    ) -> None:
        monkeypatch.delenv("AGENTGUARD_OPERATOR_SECRET", raising=False)
        home = tmp_path / "home"
        monkeypatch.setattr(
            "agentguard.config.DEFAULT_AGENTGUARD_HOME", home
        )
        ApprovalManager(tmp_path / "approvals")
        secret_path = home / "operator.secret"
        assert secret_path.exists()
        assert secret_path.read_text(encoding="utf-8").strip()


# ---------------------------------------------------------------------------
# R4b — HIGH — HMAC required from current-secret availability
# ---------------------------------------------------------------------------

class TestR4b_HmacFromCurrentAvailability:
    def test_attacker_written_pending_cannot_bypass(
        self, tmp_path: Path, monkeypatch
    ) -> None:
        """Attacker creates a pending record with hmac_required=False.
        Gateway has an operator secret available RIGHT NOW, so approve
        must still require a valid token."""
        monkeypatch.setenv("AGENTGUARD_OPERATOR_SECRET", "some-operator-secret")
        mgr = ApprovalManager(tmp_path / "approvals")
        pending = (tmp_path / "approvals" / "123456.pending.json")
        pending.parent.mkdir(parents=True, exist_ok=True)
        pending.write_text(json.dumps({
            "code": "123456",
            "expires_at": 9999999999,
            "hmac_required": False,   # attacker declares opt-out
            "expected_hmac": None,
        }))

        # No token → must reject because secret is currently available.
        assert mgr.approve("123456") is False
        assert mgr.approve("123456", token="wrong") is False
        assert mgr.approve(
            "123456", token=compute_operator_token("123456")
        ) is True


# ---------------------------------------------------------------------------
# R3a — HIGH — rule-based matcher normalization
# ---------------------------------------------------------------------------

class TestR3a_RuleMatcherNormalization:
    def _engine(self) -> PolicyEngine:
        bundle = PolicyBundle(
            name="unit",
            source_path="-",
            default_action="log",
            tool_allowlist=[],
            tool_denylist=[],
            rules=[{"name": "deny-shell", "tool": "shell", "action": "deny"}],
        )
        return PolicyEngine(mode=Mode.FEDERAL, bundles=[bundle])

    @pytest.mark.parametrize(
        "tool_name",
        ["shell", "Shell", "SHELL", "shell ", "shell\u200b"],
    )
    def test_rule_fires_on_normalized_variants(self, tool_name: str) -> None:
        engine = self._engine()
        decision = engine.evaluate(tool_name, {}, "agent:1")
        assert decision.action == "deny", (tool_name, decision)


# ---------------------------------------------------------------------------
# R5a — HIGH — hardlink bypass
# ---------------------------------------------------------------------------

class TestR5a_HardlinkBypass:
    def test_hardlink_alias_still_triggers_self_protect(
        self, tmp_path: Path
    ) -> None:
        """Create a protected target, hardlink to it, reference the alias.
        String-compare misses; inode compare catches."""
        target = tmp_path / "protected" / "audit.db"
        target.parent.mkdir(parents=True)
        target.write_text("protected-payload", encoding="utf-8")
        alias = tmp_path / "alias-audit.db"
        try:
            os.link(target, alias)
        except (OSError, NotImplementedError, PermissionError) as e:
            pytest.skip(f"os.link not supported on this filesystem: {e}")

        result = classify_self_reference(
            "shell_exec",
            {"cmd": f"cat {alias}"},
            extra_paths=[str(target)],
        )
        assert result.kind in (ReferenceKind.READ, ReferenceKind.MUTATE)
        assert result.path_hit


# ---------------------------------------------------------------------------
# OPEN — MEDIUM — non-ASCII tool names rejected
# ---------------------------------------------------------------------------

class TestOPEN_NonAsciiToolNames:
    def _engine(self) -> PolicyEngine:
        bundle = PolicyBundle(
            name="unit",
            source_path="-",
            default_action="deny",
            tool_allowlist=[],
            tool_denylist=["shell"],
        )
        return PolicyEngine(mode=Mode.FEDERAL, bundles=[bundle])

    def test_cyrillic_shell_denied(self) -> None:
        engine = self._engine()
        decision = engine.evaluate("\u0455hell", {}, "agent:1")  # ѕhell
        assert decision.action == "deny"
        assert (
            "non-ascii" in decision.reason.lower()
            or "confusable" in decision.reason.lower()
            or "homoglyph" in decision.reason.lower()
        ), decision.reason

    def test_greek_alpha_denied(self) -> None:
        engine = self._engine()
        decision = engine.evaluate("\u03b1pha_tool", {}, "agent:1")  # αpha_tool
        assert decision.action == "deny"

    def test_pure_ascii_still_passes_through(self) -> None:
        engine = self._engine()
        decision = engine.evaluate("benign_tool", {}, "agent:1")
        # Not in denylist, federal mode, allowlist empty → falls to
        # bundle default_action (deny) — that's correct federal behavior.
        assert decision.action == "deny"
        # But the reason should not mention non-ASCII.
        assert "non-ascii" not in decision.reason.lower()
        assert "confusable" not in decision.reason.lower()
