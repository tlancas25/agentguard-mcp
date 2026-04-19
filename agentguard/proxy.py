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
from agentguard.approvals import ApprovalManager, default_approvals_dir
from agentguard.policy_engine import Decision, PolicyEngine
from agentguard.self_protect import (
    EVENT_TAMPER_APPROVED,
    EVENT_TAMPER_ATTEMPT,
    EVENT_TAMPER_DENIED,
    NIST_CONTROLS as SELF_PROTECT_CONTROLS,
    ReferenceKind,
    classify_self_reference,
)

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
        self._approval_manager = ApprovalManager(default_approvals_dir())

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

        # Self-protection: user-selected mode decides how strict we are.
        # A non-None result is terminal — we don't re-evaluate through the
        # policy engine. The operator-approved path shouldn't also have to
        # pass the detector/policy stack, and a strict deny shouldn't be
        # overwritten by the engine's default decision.
        sp_decision = self._evaluate_self_protection(agent_id, tool_name, tool_args)
        if sp_decision is not None:
            should_forward, decision, sp_warnings = sp_decision
            warnings.extend(sp_warnings)
            self._log_tool_event(agent_id, tool_name, tool_args, None, decision)
            return should_forward, decision, warnings

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
            sec = detect_secrets(tool_args)
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

        sp_decision = self._evaluate_self_protection(
            agent_id, "resources/read", {"uri": uri, **extra_args}
        )
        if sp_decision is not None:
            should_forward, _decision, _warn = sp_decision
            if not should_forward:
                return False

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

    def _evaluate_self_protection(
        self,
        agent_id: str,
        tool_name: str,
        tool_args: dict[str, Any],
    ) -> Optional[tuple[bool, Decision, list[str]]]:
        """Apply the self-protection mode to a tool call.

        Returns None when the feature is off or the call does not touch
        AgentGuard state. Otherwise returns (should_forward, decision,
        warnings) that the caller merges into its own flow.
        """
        sp_mode = self.config.self_protection.mode
        if sp_mode == "off":
            return None

        result = classify_self_reference(
            tool_name, tool_args, self.config.self_protection.extra_paths
        )
        if result.kind is ReferenceKind.NONE:
            return None

        # Strict mode: anything goes to deny.
        if sp_mode == "strict":
            decision = Decision(
                action="deny",
                reason=(
                    f"Self-protection (strict): tool call references "
                    f"'{result.path_hit}'. Change self_protection.mode "
                    f"or run this operation from an operator terminal."
                ),
                nist_controls=SELF_PROTECT_CONTROLS,
            )
            self._log_tamper(
                agent_id, tool_name, tool_args, result,
                EVENT_TAMPER_ATTEMPT, "deny",
            )
            logger.warning("[AgentGuard] strict self-protection denied: %s", result.path_hit)
            return False, decision, [decision.reason]

        # Standard mode: reads are allowed (and logged).
        if result.kind is ReferenceKind.READ:
            self._log_tamper(
                agent_id, tool_name, tool_args, result,
                EVENT_TAMPER_ATTEMPT, "allowed",
            )
            decision = Decision(
                action="allow",
                reason=(
                    f"Self-protection (standard): read of '{result.path_hit}' "
                    f"allowed and logged."
                ),
                nist_controls=SELF_PROTECT_CONTROLS,
            )
            return True, decision, [decision.reason]

        # Standard mode + mutation: ask the operator.
        preview = self._preview_args(tool_name, tool_args)
        approval = self._approval_manager.request(
            tool_name=tool_name,
            tool_args_preview=preview,
            agent_id=agent_id,
            mutate_reason=result.mutate_reason or "unknown",
            path_hit=result.path_hit or "",
            timeout_seconds=self.config.self_protection.approval_timeout_seconds,
        )

        if approval.approved:
            self._log_tamper(
                agent_id, tool_name, tool_args, result,
                EVENT_TAMPER_APPROVED, "approved",
                code=approval.code,
            )
            decision = Decision(
                action="allow",
                reason=(
                    f"Self-protection: operator approved code "
                    f"{approval.code} for mutation ({result.mutate_reason})."
                ),
                nist_controls=SELF_PROTECT_CONTROLS,
            )
            return True, decision, [decision.reason]

        # Denied or timed out.
        self._log_tamper(
            agent_id, tool_name, tool_args, result,
            EVENT_TAMPER_DENIED, "deny",
            code=approval.code,
            approval_reason=approval.reason,
        )
        decision = Decision(
            action="deny",
            reason=(
                f"Self-protection: mutation denied ({approval.reason}, "
                f"code {approval.code})."
            ),
            nist_controls=SELF_PROTECT_CONTROLS,
        )
        return False, decision, [decision.reason]

    def _log_tamper(
        self,
        agent_id: str,
        tool_name: str,
        tool_args: dict[str, Any],
        result,
        event_type: str,
        decision: str,
        code: Optional[str] = None,
        approval_reason: Optional[str] = None,
    ) -> None:
        payload: dict[str, Any] = {
            "path_hit": result.path_hit,
            "arg_preview": result.arg_preview,
            "kind": result.kind.value,
        }
        if result.mutate_reason:
            payload["mutate_reason"] = result.mutate_reason
        if code:
            payload["approval_code"] = code
        if approval_reason:
            payload["approval_reason"] = approval_reason
        self.audit_log.append_event(
            AuditEvent(
                agent_id=agent_id,
                event_type=event_type,
                tool_name=tool_name,
                tool_args=payload,
                decision=decision,
                policy_matched="self_protection",
                nist_controls=SELF_PROTECT_CONTROLS,
            )
        )

    @staticmethod
    def _preview_args(tool_name: str, tool_args: dict[str, Any]) -> str:
        try:
            flat = json.dumps(tool_args, sort_keys=True)
        except Exception:
            flat = str(tool_args)
        return f"{tool_name} {flat}"[:300]

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
