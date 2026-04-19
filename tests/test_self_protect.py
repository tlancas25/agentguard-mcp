"""Tests for AgentGuard self-protection guard."""
from __future__ import annotations

import os
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

from agentguard.audit_log import AuditLog
from agentguard.config import AgentGuardConfig, SelfProtectionConfig
from agentguard.modes import Mode
from agentguard.policy_engine import PolicyEngine
from agentguard.proxy import ProxyCore
from agentguard.self_protect import (
    EVENT_TAMPER_ATTEMPT,
    scan_tool_call,
    default_protected_paths,
)


HOME = Path.home() / ".agentguard"
HOME_POSIX = str(HOME).replace("\\", "/")


class TestScan:
    def test_benign_call_passes(self) -> None:
        r = scan_tool_call("read_file", {"path": "/tmp/hello.txt"})
        assert not r.matched

    def test_exact_home_path_blocks(self) -> None:
        r = scan_tool_call("read_file", {"path": str(HOME)})
        assert r.matched
        assert "agentguard" in (r.path_hit or "")

    def test_child_path_blocks(self) -> None:
        r = scan_tool_call("read_file", {"path": f"{HOME_POSIX}/audit.db"})
        assert r.matched
        assert r.arg_preview is not None

    def test_case_insensitive_match(self) -> None:
        weird = f"{HOME_POSIX}/AUDIT.DB".upper()
        r = scan_tool_call("read_file", {"path": weird})
        assert r.matched

    def test_tilde_home_expands(self) -> None:
        r = scan_tool_call("read_file", {"path": "~/.agentguard/audit.db"})
        assert r.matched

    def test_embedded_in_shell_command(self) -> None:
        r = scan_tool_call(
            "shell_exec",
            {"cmd": f"rm -rf {HOME_POSIX} && echo done"},
        )
        assert r.matched

    def test_nested_dict_args(self) -> None:
        r = scan_tool_call(
            "http_post",
            {"body": {"file": {"path": f"{HOME_POSIX}/audit.db"}}},
        )
        assert r.matched

    def test_list_args(self) -> None:
        r = scan_tool_call(
            "batch_delete",
            {"paths": ["/tmp/a", f"{HOME_POSIX}/audit.db", "/tmp/b"]},
        )
        assert r.matched

    def test_tool_name_itself_references_path(self) -> None:
        r = scan_tool_call(f"exec:{HOME_POSIX}", {})
        assert r.matched

    def test_extra_path_honored(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            r = scan_tool_call(
                "write_file",
                {"path": f"{td}/evil.txt"},
                extra_paths=[td],
            )
            assert r.matched

    def test_default_paths_includes_home(self) -> None:
        paths = default_protected_paths()
        assert any("agentguard" in p for p in paths)


class TestProxyIntegration:
    @pytest.fixture
    def proxy(self, tmp_path: Path) -> ProxyCore:
        cfg = AgentGuardConfig(mode="dev", audit_db_path=tmp_path / "audit.db")
        log = AuditLog(db_path=cfg.audit_db_path)
        engine = PolicyEngine(mode=Mode.DEV)
        return ProxyCore(cfg, log, engine)

    def test_tamper_attempt_denied_in_dev_mode(self, proxy: ProxyCore) -> None:
        should_forward, decision, warnings = proxy.handle_tool_call(
            "read_file", {"path": f"{HOME_POSIX}/audit.db"}
        )
        assert should_forward is False
        assert decision.action == "deny"
        assert "AC-3" in decision.nist_controls
        assert warnings
        events = proxy.audit_log.tail(n=5)
        types = [e["event_type"] for e in events]
        assert EVENT_TAMPER_ATTEMPT in types

    def test_tamper_attempt_denied_in_federal_mode(self, tmp_path: Path) -> None:
        cfg = AgentGuardConfig(
            mode="federal",
            audit_db_path=tmp_path / "audit.db",
            gateway_api_keys=["k"],
        )
        log = AuditLog(db_path=cfg.audit_db_path)
        proxy = ProxyCore(cfg, log, PolicyEngine(mode=Mode.FEDERAL))
        should_forward, decision, _ = proxy.handle_tool_call(
            "shell_exec",
            {"cmd": f"rm -rf {HOME_POSIX}"},
        )
        assert should_forward is False
        assert decision.action == "deny"

    def test_benign_call_still_proceeds(self, proxy: ProxyCore) -> None:
        should_forward, decision, warnings = proxy.handle_tool_call(
            "read_file", {"path": "/tmp/benign.txt"}
        )
        assert should_forward is True
        assert decision.action != "deny"
        assert not warnings

    def test_extra_path_blocks_user_defined(self, tmp_path: Path) -> None:
        forbidden = tmp_path / "secrets"
        forbidden.mkdir()
        cfg = AgentGuardConfig(
            mode="dev",
            audit_db_path=tmp_path / "audit.db",
            self_protection=SelfProtectionConfig(extra_paths=[str(forbidden)]),
        )
        log = AuditLog(db_path=cfg.audit_db_path)
        proxy = ProxyCore(cfg, log, PolicyEngine(mode=Mode.DEV))
        should_forward, decision, _ = proxy.handle_tool_call(
            "read_file", {"path": str(forbidden / "token.txt")}
        )
        assert should_forward is False
        assert decision.action == "deny"

    def test_hash_chain_records_attempt(self, proxy: ProxyCore) -> None:
        proxy.handle_tool_call("read_file", {"path": str(HOME)})
        ok, msg = proxy.audit_log.verify_chain()
        assert ok, msg
