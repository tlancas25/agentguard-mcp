"""Tests for the AgentGuard policy engine.

Covers:
- Dev mode: all calls logged, never denied
- Federal mode: deny by default, allowlist/denylist enforcement
- Named rule matching
- Mode-level fallback behavior
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from agentguard.modes import Mode
from agentguard.policy_engine import (
    ACTION_ALLOW,
    ACTION_DENY,
    ACTION_LOG,
    PolicyBundle,
    PolicyEngine,
)


class TestDevMode:
    """Dev mode should log everything and deny nothing."""

    def test_dev_allows_all_without_bundles(self) -> None:
        """Dev mode with no bundles logs all tool calls."""
        engine = PolicyEngine(mode=Mode.DEV, bundles=[])
        decision = engine.evaluate("any_tool", {}, "agent:s1")
        assert decision.action == ACTION_LOG
        assert decision.is_allowed

    def test_dev_never_denies_even_with_denylist(
        self, dev_policy_bundle: PolicyBundle
    ) -> None:
        """In dev mode, even a denylist match results in log, not deny."""
        # Manually set a denylist on the dev bundle
        dev_policy_bundle = PolicyBundle(
            name="test",
            source_path="",
            default_action=ACTION_LOG,
            tool_denylist=["dangerous_tool"],
        )
        engine = PolicyEngine(mode=Mode.DEV, bundles=[dev_policy_bundle])
        decision = engine.evaluate("dangerous_tool", {}, "agent:s1")
        assert decision.action == ACTION_LOG
        assert decision.is_allowed

    def test_dev_logs_unlisted_tools(self, dev_policy_bundle: PolicyBundle) -> None:
        """Dev mode logs tools not in any list."""
        engine = PolicyEngine(mode=Mode.DEV, bundles=[dev_policy_bundle])
        decision = engine.evaluate("some_tool", {}, "agent:s1")
        assert decision.action == ACTION_LOG
        assert "AU-2" in decision.nist_controls


class TestFederalMode:
    """Federal mode denies by default."""

    def test_federal_denies_without_bundles(self) -> None:
        """Federal mode with no bundles denies all tool calls."""
        engine = PolicyEngine(mode=Mode.FEDERAL, bundles=[])
        decision = engine.evaluate("any_tool", {}, "agent:s1")
        assert decision.action == ACTION_DENY
        assert decision.is_denied
        assert "AC-3" in decision.nist_controls

    def test_federal_allows_allowlisted_tool(
        self, federal_policy_bundle: PolicyBundle
    ) -> None:
        """Federal mode allows tools explicitly in the allowlist."""
        engine = PolicyEngine(mode=Mode.FEDERAL, bundles=[federal_policy_bundle])
        decision = engine.evaluate("allowed_tool", {}, "agent:s1")
        assert decision.action == ACTION_ALLOW
        assert decision.is_allowed

    def test_federal_denies_unlisted_tool_with_allowlist(
        self, federal_policy_bundle: PolicyBundle
    ) -> None:
        """Federal mode denies tools not in a populated allowlist."""
        engine = PolicyEngine(mode=Mode.FEDERAL, bundles=[federal_policy_bundle])
        decision = engine.evaluate("unlisted_tool", {}, "agent:s1")
        assert decision.action == ACTION_DENY

    def test_federal_denies_denylisted_tool(
        self, federal_policy_bundle: PolicyBundle
    ) -> None:
        """Federal mode denies tools on the denylist regardless of allowlist."""
        engine = PolicyEngine(mode=Mode.FEDERAL, bundles=[federal_policy_bundle])
        decision = engine.evaluate("dangerous_tool", {}, "agent:s1")
        assert decision.action == ACTION_DENY
        assert "AC-3" in decision.nist_controls


class TestRuleMatching:
    """Named rule matching tests."""

    def test_rule_match_by_tool_name(self, tmp_path: Path) -> None:
        """Rules match on exact tool name."""
        policy_data = {
            "name": "test_rules",
            "default_action": "log",
            "rules": [
                {
                    "name": "deny_write",
                    "tool": "write_file",
                    "action": "deny",
                    "reason": "File writes not permitted.",
                    "nist_controls": ["AC-3"],
                }
            ],
        }
        path = tmp_path / "policy.yaml"
        path.write_text(yaml.dump(policy_data))
        bundle = PolicyBundle.from_yaml(path)
        engine = PolicyEngine(mode=Mode.FEDERAL, bundles=[bundle])

        deny_decision = engine.evaluate("write_file", {}, "agent:s1")
        assert deny_decision.action == ACTION_DENY

        allow_decision = engine.evaluate("read_file", {}, "agent:s1")
        assert allow_decision.action == ACTION_LOG  # default is log with no allowlist

    def test_rule_match_wildcard(self, tmp_path: Path) -> None:
        """Wildcard tool rule matches any tool."""
        policy_data = {
            "name": "test_wildcard",
            "default_action": "deny",
            "rules": [
                {
                    "name": "allow_all",
                    "tool": "*",
                    "action": "allow",
                    "reason": "Wildcard allow.",
                    "nist_controls": ["AC-3"],
                }
            ],
        }
        path = tmp_path / "policy.yaml"
        path.write_text(yaml.dump(policy_data))
        bundle = PolicyBundle.from_yaml(path)
        engine = PolicyEngine(mode=Mode.FEDERAL, bundles=[bundle])
        decision = engine.evaluate("any_tool_ever", {}, "agent:s1")
        assert decision.action == ACTION_ALLOW

    def test_dev_mode_downgrades_rule_deny(self, tmp_path: Path) -> None:
        """In dev mode, a rule with action=deny is downgraded to log."""
        policy_data = {
            "name": "test_downgrade",
            "default_action": "log",
            "rules": [
                {
                    "name": "deny_rule",
                    "tool": "some_tool",
                    "action": "deny",
                    "reason": "Should be downgraded to log in dev mode.",
                    "nist_controls": ["AC-3"],
                }
            ],
        }
        path = tmp_path / "policy.yaml"
        path.write_text(yaml.dump(policy_data))
        bundle = PolicyBundle.from_yaml(path)
        engine = PolicyEngine(mode=Mode.DEV, bundles=[bundle])
        decision = engine.evaluate("some_tool", {}, "agent:s1")
        assert decision.action == ACTION_LOG


class TestPolicyValidation:
    """Policy bundle validation tests."""

    def test_valid_bundle_passes(self, tmp_path: Path) -> None:
        """A well-formed policy bundle passes validation."""
        policy_data = {
            "name": "valid_bundle",
            "default_action": "log",
            "rules": [
                {"name": "r1", "tool": "t1", "action": "allow"},
            ],
        }
        path = tmp_path / "valid.yaml"
        path.write_text(yaml.dump(policy_data))
        engine = PolicyEngine(mode=Mode.DEV)
        errors = engine.validate_bundle_file(path)
        assert errors == []

    def test_invalid_action_fails(self, tmp_path: Path) -> None:
        """A bundle with an invalid action fails validation."""
        policy_data = {
            "name": "invalid",
            "default_action": "explode",  # Not valid
            "rules": [],
        }
        path = tmp_path / "invalid.yaml"
        path.write_text(yaml.dump(policy_data))
        engine = PolicyEngine(mode=Mode.DEV)
        errors = engine.validate_bundle_file(path)
        assert len(errors) > 0
