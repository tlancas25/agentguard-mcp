"""Tests for AgentGuard self-protection: classifier + three modes + approvals."""
from __future__ import annotations

import threading
import time
from pathlib import Path

import pytest

from agentguard.approvals import ApprovalManager
from agentguard.audit_log import AuditLog
from agentguard.config import AgentGuardConfig, SelfProtectionConfig
from agentguard.modes import Mode
from agentguard.policy_engine import PolicyEngine
from agentguard.proxy import ProxyCore
from agentguard.self_protect import (
    EVENT_TAMPER_APPROVED,
    EVENT_TAMPER_ATTEMPT,
    EVENT_TAMPER_DENIED,
    ReferenceKind,
    classify_self_reference,
)


HOME = Path.home() / ".agentguard"
HOME_POSIX = str(HOME).replace("\\", "/")


# ---------------------------------------------------------------------------
# Classifier
# ---------------------------------------------------------------------------

class TestClassifier:
    def test_benign_returns_none(self) -> None:
        r = classify_self_reference("read_file", {"path": "/tmp/a"})
        assert r.kind is ReferenceKind.NONE

    def test_read_file_with_protected_path_is_read(self) -> None:
        r = classify_self_reference("read_file", {"path": str(HOME / "audit.db")})
        assert r.kind is ReferenceKind.READ

    def test_ls_of_home_is_read(self) -> None:
        r = classify_self_reference("ls", {"path": str(HOME)})
        assert r.kind is ReferenceKind.READ

    def test_audit_tail_is_read(self) -> None:
        r = classify_self_reference(
            "run_command", {"cmd": f"agentguard audit tail --config {HOME_POSIX}/agentguard.yaml"},
        )
        assert r.kind is ReferenceKind.READ

    def test_rm_on_home_is_mutate(self) -> None:
        r = classify_self_reference(
            "shell_exec", {"cmd": f"rm -rf {HOME_POSIX}/audit.db"},
        )
        assert r.kind is ReferenceKind.MUTATE
        assert r.mutate_reason

    def test_mv_on_home_is_mutate(self) -> None:
        r = classify_self_reference(
            "shell_exec", {"cmd": f"mv {HOME_POSIX}/audit.db /tmp/stolen.db"},
        )
        assert r.kind is ReferenceKind.MUTATE

    def test_sql_drop_on_home_is_mutate(self) -> None:
        r = classify_self_reference(
            "sqlite",
            {"db": str(HOME / "audit.db"), "query": "DROP TABLE events"},
        )
        assert r.kind is ReferenceKind.MUTATE

    def test_claude_mcp_remove_is_mutate(self) -> None:
        r = classify_self_reference(
            "shell_exec",
            {"cmd": f"claude mcp remove agentguard && echo {HOME_POSIX}"},
        )
        assert r.kind is ReferenceKind.MUTATE

    def test_ag_update_is_mutate(self) -> None:
        r = classify_self_reference(
            "shell_exec", {"cmd": f"agentguard update && touch {HOME_POSIX}/x"},
        )
        assert r.kind is ReferenceKind.MUTATE

    def test_ag_update_dry_run_is_read(self) -> None:
        r = classify_self_reference(
            "shell_exec",
            {"cmd": f"agentguard update --dry-run && cat {HOME_POSIX}/agentguard.yaml"},
        )
        assert r.kind is ReferenceKind.READ

    def test_write_file_tool_on_home_is_mutate(self) -> None:
        r = classify_self_reference(
            "write_file", {"path": f"{HOME_POSIX}/agentguard.yaml", "content": "x"},
        )
        assert r.kind is ReferenceKind.MUTATE

    def test_redirect_write_is_mutate(self) -> None:
        r = classify_self_reference(
            "shell_exec",
            {"cmd": f"echo hacked > {HOME_POSIX}/audit.db"},
        )
        assert r.kind is ReferenceKind.MUTATE


class TestBareSelfCommands:
    """Bare AgentGuard mutation commands that never name the protected path.

    These must be classified MUTATE purely on command identity, or a
    compromised agent can reinstall / reconfigure / self-approve the
    gateway without tripping the guard.
    """

    def test_bare_agentguard_update(self) -> None:
        r = classify_self_reference("shell_exec", {"cmd": "agentguard update"})
        assert r.kind is ReferenceKind.MUTATE
        assert r.mutate_reason == "ag_update"

    def test_bare_agentguard_update_dry_run_is_none(self) -> None:
        r = classify_self_reference(
            "shell_exec", {"cmd": "agentguard update --dry-run"}
        )
        assert r.kind is ReferenceKind.NONE

    def test_bare_agentguard_repair(self) -> None:
        r = classify_self_reference("shell_exec", {"cmd": "agentguard repair"})
        assert r.kind is ReferenceKind.MUTATE

    def test_bare_claude_mcp_remove_agentguard(self) -> None:
        r = classify_self_reference(
            "shell_exec", {"cmd": "claude mcp remove agentguard"}
        )
        assert r.kind is ReferenceKind.MUTATE

    def test_bare_claude_mcp_remove_other_is_none(self) -> None:
        r = classify_self_reference(
            "shell_exec", {"cmd": "claude mcp remove some-other-server"}
        )
        assert r.kind is ReferenceKind.NONE

    def test_bare_agentguard_approve_is_mutate(self) -> None:
        r = classify_self_reference(
            "shell_exec", {"cmd": "agentguard approve 123456"}
        )
        assert r.kind is ReferenceKind.MUTATE
        assert r.mutate_reason == "ag_approve"

    def test_bare_agentguard_init_force(self) -> None:
        r = classify_self_reference(
            "shell_exec", {"cmd": "agentguard init --force"}
        )
        assert r.kind is ReferenceKind.MUTATE

    def test_kill_agentguard_is_mutate(self) -> None:
        r = classify_self_reference(
            "shell_exec", {"cmd": "taskkill /F /IM agentguard.exe"}
        )
        assert r.kind is ReferenceKind.MUTATE

    def test_generic_kill_is_none(self) -> None:
        r = classify_self_reference(
            "shell_exec", {"cmd": "kill -9 1234"}
        )
        assert r.kind is ReferenceKind.NONE


# ---------------------------------------------------------------------------
# Mode integration
# ---------------------------------------------------------------------------

def _proxy(tmp_path: Path, sp_mode: str, timeout: int = 2) -> ProxyCore:
    cfg = AgentGuardConfig(
        mode="dev",
        audit_db_path=tmp_path / "audit.db",
        self_protection=SelfProtectionConfig(
            mode=sp_mode, approval_timeout_seconds=timeout
        ),
    )
    log = AuditLog(db_path=cfg.audit_db_path)
    return ProxyCore(cfg, log, PolicyEngine(mode=Mode.DEV))


class TestModeOff:
    def test_off_allows_tamper(self, tmp_path: Path) -> None:
        proxy = _proxy(tmp_path, "off")
        should_forward, _d, warnings = proxy.handle_tool_call(
            "shell_exec", {"cmd": f"rm -rf {HOME_POSIX}/audit.db"},
        )
        # Off = no guarding. The policy engine still decides.
        assert should_forward is True
        assert not any("self-protection" in w.lower() for w in warnings)


class TestModeStandard:
    def test_read_allowed_and_logged(self, tmp_path: Path) -> None:
        proxy = _proxy(tmp_path, "standard")
        should_forward, decision, warnings = proxy.handle_tool_call(
            "read_file", {"path": str(HOME / "audit.db")},
        )
        assert should_forward is True
        assert any("read of" in w.lower() for w in warnings)
        events = proxy.audit_log.tail(n=5)
        assert any(
            e["event_type"] == EVENT_TAMPER_ATTEMPT and e["decision"] == "allowed"
            for e in events
        )

    def test_mutation_blocks_without_approval(self, tmp_path: Path) -> None:
        proxy = _proxy(tmp_path, "standard", timeout=1)
        should_forward, decision, _ = proxy.handle_tool_call(
            "shell_exec", {"cmd": f"rm -rf {HOME_POSIX}/audit.db"},
        )
        assert should_forward is False
        assert decision.action == "deny"
        events = proxy.audit_log.tail(n=5)
        assert any(e["event_type"] == EVENT_TAMPER_DENIED for e in events)

    def test_mutation_allowed_after_approval(self, tmp_path: Path, monkeypatch) -> None:
        approvals = tmp_path / "approvals"
        monkeypatch.setenv("AGENTGUARD_APPROVALS_DIR", str(approvals))
        # Standard mode now requires an HMAC token on approve()
        # (AG-BL-003.R4a/R4b). Pin a known secret so both the gateway
        # and the approver thread compute matching tokens.
        monkeypatch.setenv(
            "AGENTGUARD_OPERATOR_SECRET", "unit-test-operator-secret"
        )
        proxy = _proxy(tmp_path, "standard", timeout=3)

        approver_ready = threading.Event()

        def approver() -> None:
            from agentguard.approvals import compute_operator_token as _tok

            mgr = ApprovalManager(approvals)
            deadline = time.time() + 2.5
            while time.time() < deadline:
                pending = mgr.list_pending()
                if pending:
                    code = pending[0]["code"]
                    mgr.approve(code, token=_tok(code))
                    approver_ready.set()
                    return
                time.sleep(0.1)

        t = threading.Thread(target=approver)
        t.start()
        should_forward, decision, warnings = proxy.handle_tool_call(
            "shell_exec", {"cmd": f"rm -rf {HOME_POSIX}/audit.db"},
        )
        t.join(timeout=3)
        assert approver_ready.is_set(), "approver thread never saw a pending request"
        assert should_forward is True
        assert "operator approved" in decision.reason.lower()

        events = proxy.audit_log.tail(n=5)
        assert any(e["event_type"] == EVENT_TAMPER_APPROVED for e in events)


class TestModeStrict:
    def test_any_reference_denied(self, tmp_path: Path) -> None:
        proxy = _proxy(tmp_path, "strict")
        should_forward, decision, _ = proxy.handle_tool_call(
            "read_file", {"path": str(HOME / "audit.db")},
        )
        assert should_forward is False
        assert decision.action == "deny"
        assert "strict" in decision.reason.lower()

    def test_non_reference_passes(self, tmp_path: Path) -> None:
        proxy = _proxy(tmp_path, "strict")
        should_forward, _d, _w = proxy.handle_tool_call(
            "read_file", {"path": "/tmp/benign"},
        )
        assert should_forward is True


# ---------------------------------------------------------------------------
# ApprovalManager
# ---------------------------------------------------------------------------

class TestApprovalManager:
    def test_list_approve_deny_cycle(self, tmp_path: Path, monkeypatch) -> None:
        # ApprovalManager now auto-provisions ~/.agentguard/operator.secret
        # (AG-BL-003.R4a), so approve() requires an HMAC token computed
        # against that secret. Point the lookup at a throw-away home.
        fake_home = tmp_path / "home"
        monkeypatch.setattr(
            "agentguard.config.DEFAULT_AGENTGUARD_HOME", fake_home
        )
        monkeypatch.delenv("AGENTGUARD_OPERATOR_SECRET", raising=False)
        from agentguard.approvals import compute_operator_token as _tok

        mgr = ApprovalManager(tmp_path)
        # Simulate a request by creating a pending file, then approve
        pending = tmp_path / "123456.pending.json"
        pending.write_text('{"code": "123456", "expires_at": 9999999999}')
        assert len(mgr.list_pending()) == 1
        assert mgr.approve("123456", token=_tok("123456")) is True
        assert (tmp_path / "123456.approved").exists()
        assert mgr.approve("999999", token=_tok("999999")) is False

    @pytest.mark.parametrize(
        "bad_code",
        [
            "",
            "abcdef",
            "12345",
            "1234567",
            "../foo",
            "123/45",
            "1 2 3 4 5 6",
            "%20%20%20",
        ],
    )
    def test_approve_rejects_malformed_codes(
        self, tmp_path: Path, bad_code: str
    ) -> None:
        mgr = ApprovalManager(tmp_path)
        assert mgr.approve(bad_code) is False
        assert mgr.deny(bad_code) is False
        # Nothing should have been written into the directory.
        assert list(tmp_path.iterdir()) == []
