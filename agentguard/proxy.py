"""Core proxy logic for AgentGuard MCP.

Intercepts MCP protocol messages, runs policy evaluation and detectors,
logs to audit, and forwards or denies based on mode + decision.

Supported MCP methods:
- initialize (extract agent identity)
- tools/list (scan tool descriptions for poisoning)
- tools/call (full policy + detector stack)
- resources/read (policy check + log)
- prompts/get (policy check + log)
"""

from __future__ import annotations

import json
import logging
from typing import Any, Optional

from agentguard.audit_log import AuditEvent, AuditLog
from agentguard.config import AgentGuardConfig
from agentguard.identity import AgentIdentity, IdentityExtractor
from agentguard.modes import Mode
from agentguard.nist.mappings import (
    EVENT_INJECTION_DETECTED,
    EVENT_PII_DETECTED,
    EVENT_PROMPTS_GET,
    EVENT_RESOURCES_READ,
    EVENT_SECRET_DETECTED,
    EVENT_SESSION_START,
    EVENT_TOOL_ALLOWED,
    EVENT_TOOL_CALL,
    EVENT_TOOL_DENIED,
    EVENT_TOOL_POISONING_DETECTED,
    get_controls_for_event,
)
from agentguard.policy_engine import Decision, PolicyEngine

logger = logging.getLogger(__name__)


class ProxyCore:
    """Core proxy that intercepts MCP messages and applies AgentGuard policy.

    This class is transport-agnostic. The stdio server and HTTP gateway
    both delegate message handling to ProxyCore.
    """

    def __init__(
        self,
        config: AgentGuardConfig,
        audit_log: AuditLog,
        policy_engine: PolicyEngine,
    ) -> None:
        """Initialize the proxy core.

        Args:
            config: Loaded AgentGuard configuration.
            audit_log: Initialized audit log instance.
            policy_engine: Initialized policy engine instance.
        """
        self.config = config
        self.audit_log = audit_log
        self.policy_engine = policy_engine
        self.mode = Mode(config.mode)
        self._identity_extractor = IdentityExtractor()
        self._current_identity: Optional[AgentIdentity] = None

    def handle_initialize(self, params: dict[str, Any]) -> None:
        """Process an MCP initialize request to extract agent identity."""
        self._current_identity = self._identity_extractor.extract_from_initialize(params)
        self.audit_log.append_event(
            AuditEvent(
                agent_id=self._current_identity.agent_id,
                event_type=EVENT_SESSION_START,
                decision="logged",
                nist_controls=get_controls_for_event(EVENT_SESSION_START),
            )
        )
        logger.info("Session started: agent_id=%s", self._current_identity.agent_id)

    def handle_tools_list(self, tools: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Scan tool descriptions for poisoning attacks.

        Args:
            tools: List of tool objects from upstream MCP server.

        Returns:
            The same tools list (AgentGuard does not filter it; it flags and logs).
        """
        if not self.config.detectors.tool_poisoning.enabled:
            return tools

        from agentguard.detectors.tool_poisoning import scan_tools_list

        findings = scan_tools_list(tools)
        for result in findings:
            agent_id = self._get_agent_id()
            self.audit_log.append_event(
                AuditEvent(
                    agent_id=agent_id,
                    event_type=EVENT_TOOL_POISONING_DETECTED,
                    decision="logged",
                    nist_controls=result.nist_controls,
                    tool_args={"detail": result.detail, "patterns": result.patterns_hit},
                )
            )
            logger.warning("Tool poisoning detected: %s", result.detail)

        return tools

    def handle_tool_call(
        self,
        tool_name: str,
        tool_args: dict[str, Any],
    ) -> tuple[bool, Decision, list[str]]:
        """Process a tools/call request.

        Returns:
            Tuple of (should_forward, decision, detection_warnings).
            should_forward=True means the call may proceed to upstream.
            detection_warnings is a list of human-readable warning strings.
        """
        agent_id = self._get_agent_id()
        warnings: list[str] = []

        # Run detector stack
        detection_controls: list[str] = []

        if self.config.detectors.prompt_injection.enabled:
            from agentguard.detectors.prompt_injection import detect_in_tool_args
            inj = detect_in_tool_args(
                tool_args,
                score_threshold=self.config.detectors.prompt_injection.score_threshold,
            )
            if inj.matched:
                detection_controls.extend(inj.nist_controls)
                warnings.append(f"Prompt injection detected (score={inj.score:.2f}): {inj.detail}")
                self.audit_log.append_event(
                    AuditEvent(
                        agent_id=agent_id,
                        event_type=EVENT_INJECTION_DETECTED,
                        tool_name=tool_name,
                        tool_args={"score": inj.score, "patterns": inj.patterns_hit},
                        decision=(
                            "deny"
                            if self.mode == Mode.FEDERAL
                            and self.config.detectors.prompt_injection.action == "deny"
                            else "logged"
                        ),
                        nist_controls=inj.nist_controls,
                    )
                )
                if (
                    self.mode == Mode.FEDERAL
                    and self.config.detectors.prompt_injection.action == "deny"
                ):
                    decision = Decision(
                        action="deny",
                        reason=f"Prompt injection detected: {inj.detail}",
                        nist_controls=inj.nist_controls,
                    )
                    self._log_tool_event(agent_id, tool_name, tool_args, None, decision)
                    return False, decision, warnings

        if self.config.detectors.pii.enabled:
            from agentguard.detectors.pii import detect_in_tool_args as detect_pii
            pii = detect_pii(tool_args)
            if pii.matched:
                detection_controls.extend(pii.nist_controls)
                warnings.append(f"PII detected: {', '.join(pii.types_found)}")
                self.audit_log.append_event(
                    AuditEvent(
                        agent_id=agent_id,
                        event_type=EVENT_PII_DETECTED,
                        tool_name=tool_name,
                        tool_args={"types_found": pii.types_found},
                        decision=(
                            "deny"
                            if self.mode == Mode.FEDERAL
                            and self.config.detectors.pii.action == "deny"
                            else "logged"
                        ),
                        nist_controls=pii.nist_controls,
                    )
                )
                if (
                    self.mode == Mode.FEDERAL
                    and self.config.detectors.pii.action == "deny"
                ):
                    decision = Decision(
                        action="deny",
                        reason=f"PII detected in tool args: {', '.join(pii.types_found)}",
                        nist_controls=pii.nist_controls,
                    )
                    self._log_tool_event(agent_id, tool_name, tool_args, None, decision)
                    return False, decision, warnings

        if self.config.detectors.secrets.enabled:
            from agentguard.detectors.secrets import detect_in_tool_args as detect_secrets
            sec = detect_in_tool_args(tool_args)
            if sec.matched:
                detection_controls.extend(sec.nist_controls)
                warnings.append(f"Secret detected: {', '.join(sec.types_found)}")
                self.audit_log.append_event(
                    AuditEvent(
                        agent_id=agent_id,
                        event_type=EVENT_SECRET_DETECTED,
                        tool_name=tool_name,
                        tool_args={"types_found": sec.types_found},
                        decision=(
                            "deny"
                            if self.config.detectors.secrets.action == "deny"
                            else "logged"
                        ),
                        nist_controls=sec.nist_controls,
                    )
                )

        # Run policy engine
        decision = self.policy_engine.evaluate(tool_name, tool_args, agent_id)

        # Merge detection controls into decision
        all_controls = list(set(decision.nist_controls + detection_controls))
        decision.nist_controls = all_controls

        # Log the tool call event
        self._log_tool_event(agent_id, tool_name, tool_args, None, decision)

        should_forward = decision.is_allowed
        return should_forward, decision, warnings

    def record_tool_result(
        self,
        tool_name: str,
        tool_args: dict[str, Any],
        tool_result: Any,
        decision: Decision,
    ) -> None:
        """Record the result of a tool call after upstream responds."""
        agent_id = self._get_agent_id()
        self.audit_log.append_event(
            AuditEvent(
                agent_id=agent_id,
                event_type=EVENT_TOOL_ALLOWED,
                tool_name=tool_name,
                tool_args=tool_args,
                tool_result=tool_result,
                decision="allowed",
                policy_matched=decision.matched_rule,
                nist_controls=decision.nist_controls,
            )
        )

    def handle_resources_read(self, uri: str, extra_args: dict[str, Any]) -> bool:
        """Log a resources/read request. Returns True if allowed."""
        agent_id = self._get_agent_id()
        decision = self.policy_engine.evaluate("resources/read", {"uri": uri}, agent_id)
        self.audit_log.append_event(
            AuditEvent(
                agent_id=agent_id,
                event_type=EVENT_RESOURCES_READ,
                tool_name="resources/read",
                tool_args={"uri": uri, **extra_args},
                decision=decision.action,
                policy_matched=decision.matched_rule,
                nist_controls=get_controls_for_event(EVENT_RESOURCES_READ),
            )
        )
        return decision.is_allowed

    def handle_prompts_get(self, prompt_name: str, extra_args: dict[str, Any]) -> bool:
        """Log a prompts/get request. Returns True if allowed."""
        agent_id = self._get_agent_id()
        decision = self.policy_engine.evaluate("prompts/get", {"name": prompt_name}, agent_id)
        self.audit_log.append_event(
            AuditEvent(
                agent_id=agent_id,
                event_type=EVENT_PROMPTS_GET,
                tool_name="prompts/get",
                tool_args={"prompt_name": prompt_name, **extra_args},
                decision=decision.action,
                policy_matched=decision.matched_rule,
                nist_controls=get_controls_for_event(EVENT_PROMPTS_GET),
            )
        )
        return decision.is_allowed

    def _log_tool_event(
        self,
        agent_id: str,
        tool_name: str,
        tool_args: dict[str, Any],
        tool_result: Any,
        decision: Decision,
    ) -> None:
        """Write a tool call event to the audit log."""
        event_type = EVENT_TOOL_DENIED if decision.is_denied else EVENT_TOOL_CALL
        self.audit_log.append_event(
            AuditEvent(
                agent_id=agent_id,
                event_type=event_type,
                tool_name=tool_name,
                tool_args=tool_args,
                tool_result=tool_result,
                decision=decision.action,
                policy_matched=decision.matched_rule,
                nist_controls=decision.nist_controls,
            )
        )

    def _get_agent_id(self) -> str:
        """Return current agent ID or anonymous fallback."""
        if self._current_identity:
            return self._current_identity.agent_id
        return self._identity_extractor.get_current().agent_id
