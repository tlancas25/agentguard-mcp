"""Regression tests for the April 2026 red-team report (redforge-dev run).

Each TestClass below exits non-zero if the corresponding finding
returns. Do not relax these assertions without a follow-up report
concluding the primitive is no longer exploitable.
"""
from __future__ import annotations

import json
import sqlite3
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

from agentguard.audit_log import AuditEvent, AuditLog, generate_signing_keypair
from agentguard.approvals import (
    ApprovalManager,
    compute_operator_token,
)
from agentguard.config import AgentGuardConfig, SelfProtectionConfig
from agentguard.modes import Mode
from agentguard.policy_engine import PolicyBundle, PolicyEngine
from agentguard.proxy import ProxyCore
from agentguard.reports.oscal import generate_component_definition
from agentguard.self_protect import ReferenceKind, classify_self_reference


# ---------------------------------------------------------------------------
# AG-BL-001 — hash-chain reseed / truncation
# ---------------------------------------------------------------------------

class TestAGBL001_HighWaterMark:
    """Report BOOM-1: verify_chain used to accept an emptied or
    GENESIS-reseeded events table as valid. Now it must catch both."""

    def _log(self, tmp_path: Path) -> AuditLog:
        priv, _pub = generate_signing_keypair()
        return AuditLog(db_path=tmp_path / "audit.db", signing_key=priv)

    def test_truncation_of_events_is_detected(self, tmp_path: Path) -> None:
        log = self._log(tmp_path)
        for i in range(5):
            log.append_event(AuditEvent(
                agent_id="a", event_type="tool_call", tool_name=f"t{i}",
                decision="logged",
            ))
        assert log.verify_chain()[0] is True

        conn = sqlite3.connect(str(tmp_path / "audit.db"))
        conn.execute("DELETE FROM events")
        conn.commit()
        conn.close()

        ok, msg = log.verify_chain()
        assert ok is False, msg
        assert "truncation" in msg.lower() or "reseed" in msg.lower(), msg

    def test_reseed_from_genesis_is_detected(self, tmp_path: Path) -> None:
        log = self._log(tmp_path)
        for i in range(3):
            log.append_event(AuditEvent(
                agent_id="a", event_type="tool_call", tool_name=f"t{i}",
                decision="logged",
            ))
        assert log.verify_chain()[0] is True

        # Attacker wipes events AND forges a new short chain from GENESIS.
        # The high-water-mark row still records the previous tip, so the
        # verify_chain call must fail.
        conn = sqlite3.connect(str(tmp_path / "audit.db"))
        conn.execute("DELETE FROM events")
        conn.commit()
        conn.close()

        forger = self._log(tmp_path)  # re-open the same DB
        # Re-appending events will update the high-water-mark; test the
        # mid-state specifically — the empty-table-after-delete is the
        # shape that originally passed.
        ok_mid, msg_mid = forger.verify_chain()
        assert ok_mid is False, msg_mid

    def test_partial_truncation_is_detected(self, tmp_path: Path) -> None:
        log = self._log(tmp_path)
        for i in range(5):
            log.append_event(AuditEvent(
                agent_id="a", event_type="tool_call", tool_name=f"t{i}",
                decision="logged",
            ))
        # Delete tail events only; row count drops below high-water-mark.
        conn = sqlite3.connect(str(tmp_path / "audit.db"))
        conn.execute("DELETE FROM events WHERE id > 2")
        conn.commit()
        conn.close()

        ok, msg = log.verify_chain()
        assert ok is False
        assert "truncation" in msg.lower() or "high-water" in msg.lower()


# ---------------------------------------------------------------------------
# AG-BL-002 — OSCAL generator no longer fabricates evidence
# ---------------------------------------------------------------------------

class TestAGBL002_OscalEvidence:
    """Report BOOM-2: OSCAL output claimed 'implemented' for every control
    regardless of DB presence or chain validity. It must now ground each
    implementation-status in actual events."""

    def test_nonexistent_db_emits_planned_status(self, tmp_path: Path) -> None:
        definition = generate_component_definition(
            audit_db_path=tmp_path / "nope.db",
            system_name="UnitTest",
        )
        requirements = (
            definition["component-definition"]["components"][0]
            ["control-implementations"][0]["implemented-requirements"]
        )
        for req in requirements:
            status_prop = next(
                p for p in req["props"]
                if p["name"] == "implementation-status"
            )
            assert status_prop["value"] == "planned", req

    def test_component_reports_audit_db_missing(self, tmp_path: Path) -> None:
        definition = generate_component_definition(
            audit_db_path=tmp_path / "nope.db",
            system_name="UnitTest",
        )
        component_props = definition["component-definition"]["components"][0]["props"]
        present = next(p for p in component_props if p["name"] == "audit-db-present")
        assert present["value"] == "false"

    def test_populated_db_reflects_exercised_controls(self, tmp_path: Path) -> None:
        priv, _pub = generate_signing_keypair()
        log = AuditLog(db_path=tmp_path / "audit.db", signing_key=priv)
        log.append_event(AuditEvent(
            agent_id="a", event_type="tool_call", tool_name="t",
            decision="allowed", nist_controls=["AC-3"],
        ))
        definition = generate_component_definition(
            audit_db_path=tmp_path / "audit.db",
            system_name="UnitTest",
        )
        reqs = (
            definition["component-definition"]["components"][0]
            ["control-implementations"][0]["implemented-requirements"]
        )
        by_id = {r["control-id"]: r for r in reqs}
        ac3_status = next(
            p for p in by_id["ac-3"]["props"]
            if p["name"] == "implementation-status"
        )
        assert ac3_status["value"] == "implemented"
        # Untouched control stays planned.
        au10_status = next(
            p for p in by_id["au-10"]["props"]
            if p["name"] == "implementation-status"
        )
        assert au10_status["value"] == "planned"


# ---------------------------------------------------------------------------
# AG-MT-001 — denylist exact-match bypass
# ---------------------------------------------------------------------------

class TestAGMT001_DenylistNormalization:
    """Report BOOM-3: 8 tool-name variants bypassed the denylist. Now
    normalization must collapse them all."""

    def _engine(self) -> PolicyEngine:
        # Realistic federal posture: denylist + deny-by-default. Bypass
        # variants must be caught by denylist normalization; tokens that
        # NFKC cannot fold (e.g. Cyrillic homoglyphs) still hit the
        # default-deny floor.
        bundle = PolicyBundle(
            name="unit",
            source_path="-",
            default_action="deny",
            tool_allowlist=[],
            tool_denylist=["shell"],
        )
        return PolicyEngine(mode=Mode.FEDERAL, bundles=[bundle])

    @pytest.mark.parametrize(
        "tool_name",
        [
            "shell",
            "Shell",
            "SHELL",
            "shell ",      # trailing space
            " shell",      # leading space
            "ｓhell",      # fullwidth s
            "shell.exe",   # may or may not match — see below
        ],
    )
    def test_case_and_whitespace_and_fullwidth_denied(
        self, tool_name: str
    ) -> None:
        engine = self._engine()
        decision = engine.evaluate(tool_name, {}, "agent:1")
        # shell.exe is NOT the same token as shell — a suffix isn't
        # semantically a match, so we accept either deny (stricter) or
        # a non-allow non-deny 'log'. Everything else must be a strict deny.
        if tool_name == "shell.exe":
            assert decision.action in ("deny", "log")
            return
        assert decision.action == "deny", (tool_name, decision)

    def test_cyrillic_homoglyph_not_falsely_matched_as_denied(self) -> None:
        """'ѕhell' (Cyrillic ѕ, U+0455) is a different codepoint. NFKC
        does not fold it to Latin 's', so we should NOT treat it as a
        denylist hit — but we also shouldn't silently let it through
        in federal mode: it falls through to the default allowlist-miss
        deny which is still safe."""
        engine = self._engine()
        decision = engine.evaluate("\u0455hell", {}, "agent:1")
        # Either path-hit or default-deny both produce a deny in federal;
        # the important thing is the tool is NOT treated as an
        # allowed/unknown benign tool in federal mode.
        assert decision.action == "deny"

    def test_zero_width_in_tool_name_rejected(self) -> None:
        engine = self._engine()
        # shell + zero-width space should be refused outright as evasion.
        decision = engine.evaluate("shell\u200b", {}, "agent:1")
        assert decision.action == "deny", decision
        assert (
            "zero-width" in decision.reason.lower()
            or "control characters" in decision.reason.lower()
            or "denylist" in decision.reason.lower()
        ), decision.reason


# ---------------------------------------------------------------------------
# AG-BL-003 — Python API approve bypass
# ---------------------------------------------------------------------------

class TestAGBL003_ApproveHMAC:
    """Report BOOM-4: ApprovalManager.approve() was callable without any
    operator-held secret. Now approve/deny must refuse library calls
    that didn't compute the HMAC from ~/.agentguard/operator.secret."""

    def test_approve_without_token_is_rejected_when_hmac_required(
        self, tmp_path: Path, monkeypatch
    ) -> None:
        monkeypatch.setenv("AGENTGUARD_OPERATOR_SECRET", "test-secret-abc-padded-to-min-entropy-32")
        mgr = ApprovalManager(tmp_path)

        # Write a pending file the way request() does, with hmac_required=True.
        pending = tmp_path / "123456.pending.json"
        pending.write_text(json.dumps({
            "code": "123456",
            "expires_at": 9999999999,
            "hmac_required": True,
            "expected_hmac": compute_operator_token("123456"),
        }))

        assert mgr.approve("123456") is False
        assert mgr.approve("123456", token="wrong-token") is False

    def test_approve_with_correct_token_succeeds(
        self, tmp_path: Path, monkeypatch
    ) -> None:
        monkeypatch.setenv("AGENTGUARD_OPERATOR_SECRET", "test-secret-abc-padded-to-min-entropy-32")
        mgr = ApprovalManager(tmp_path)
        pending = tmp_path / "123456.pending.json"
        pending.write_text(json.dumps({
            "code": "123456",
            "expires_at": 9999999999,
            "hmac_required": True,
            "expected_hmac": compute_operator_token("123456"),
        }))

        token = compute_operator_token("123456")
        assert mgr.approve("123456", token=token) is True

    def test_no_secret_fallback_accepts_record_declared_unrequired(
        self, tmp_path: Path, monkeypatch
    ) -> None:
        """Historical fallback: if NO operator secret is reachable AND
        the pending record declared hmac_required=False, approve passes.
        AG-BL-003.R4a closed the gap where the gateway created such a
        record on its own; this path is now only reachable if an
        operator deliberately runs with a broken install (no auto-
        provision, no env var). The test documents that behavior so
        future refactors don't silently drop it."""
        monkeypatch.delenv("AGENTGUARD_OPERATOR_SECRET", raising=False)
        empty_home = tmp_path / "empty-home"
        monkeypatch.setattr(
            "agentguard.config.DEFAULT_AGENTGUARD_HOME", empty_home
        )
        mgr = ApprovalManager(tmp_path)
        # ApprovalManager auto-provisions a secret on __init__; remove
        # it to simulate the legacy no-secret deployment the old tests
        # exercised.
        legacy_secret = empty_home / "operator.secret"
        if legacy_secret.exists():
            legacy_secret.unlink()
        monkeypatch.delenv("AGENTGUARD_OPERATOR_SECRET", raising=False)

        pending = tmp_path / "123456.pending.json"
        pending.write_text(json.dumps({
            "code": "123456",
            "expires_at": 9999999999,
            "hmac_required": False,
            "expected_hmac": None,
        }))
        assert mgr.approve("123456") is True

    def test_compute_token_returns_none_without_secret(
        self, tmp_path: Path, monkeypatch
    ) -> None:
        monkeypatch.delenv("AGENTGUARD_OPERATOR_SECRET", raising=False)
        monkeypatch.setattr(
            "agentguard.config.DEFAULT_AGENTGUARD_HOME", tmp_path / "empty-home"
        )
        assert compute_operator_token("123456") is None


# ---------------------------------------------------------------------------
# AG-BL-004 — audit_db_path auto-injected into self-protect extra_paths
# ---------------------------------------------------------------------------

class TestAGBL004_AuditPathAutoInject:
    """Proxy-level: a tool call whose args reference the live
    audit_db_path must trigger self-protection even when the operator
    did not list that path in extra_paths."""

    def test_audit_db_path_guarded_without_explicit_extra_path(
        self, tmp_path: Path
    ) -> None:
        audit_db = tmp_path / "custom" / "my-audit.db"
        audit_db.parent.mkdir(parents=True, exist_ok=True)
        cfg = AgentGuardConfig(
            mode="dev",
            audit_db_path=audit_db,
            self_protection=SelfProtectionConfig(
                mode="strict", extra_paths=[]
            ),
        )
        log = AuditLog(db_path=cfg.audit_db_path)
        proxy = ProxyCore(cfg, log, PolicyEngine(mode=Mode.DEV))

        should_forward, decision, _ = proxy.handle_tool_call(
            "shell_exec",
            {"cmd": f"cat {audit_db}"},
        )
        assert should_forward is False
        assert decision.action == "deny"
        assert "self-protection" in decision.reason.lower()
