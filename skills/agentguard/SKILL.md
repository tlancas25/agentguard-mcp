---
name: agentguard
description: MCP security gateway for AI agents with native NIST 800-53 and FedRAMP compliance. Use when deploying AI agents in regulated environments, configuring policy enforcement for MCP tool calls, or generating audit evidence for federal compliance reviews.
license: MIT
---

# AgentGuard MCP — Skill Principles

## 1. Dev Mode First

Before enabling any enforcement, verify that AgentGuard passes all tool calls through transparently in dev mode. Run `agentguard run --mode dev` and confirm your agent's workflows function normally. A broken dev mode means a broken development experience, which defeats the purpose of the tool.

Dev mode is not a placeholder. It is the production configuration for development teams. It logs everything, blocks nothing, and does not interfere with Claude Code, Cursor, or OpenClaw workflows.

## 2. Least Privilege by Policy

Federal mode is deny by default. This is correct and intentional. When writing policy bundles, start from an empty allowlist and add tools your system legitimately uses. Do not start from "allow all" and try to denylist your way to security.

Every tool in the allowlist should have a documented business justification. If you cannot explain why an AI agent needs `execute_code`, it should not be in the allowlist.

## 3. Every Tool Call Is Evidence

The audit log is the source of truth for compliance assessors. It is hash-chained. It is optionally signed. It cannot be selectively edited without detection.

When something goes wrong — a policy violation, a detected injection, a suspicious denial pattern — the audit log is how you prove what happened and when. Treat it accordingly: protect the database file, back it up, and rotate signing keys when personnel changes occur.

## 4. NIST Controls Map to Reality

Every NIST 800-53 control referenced in AgentGuard documentation has corresponding code that implements it. AC-3 means the policy engine actually enforces access. AU-9 means the hash chain actually detects tampering. SI-10 means the detectors actually scan input.

Do not add control references as decoration. If you extend AgentGuard and claim a new control is implemented, there must be code that implements it.

## 5. Human Accountability

AI agents do not answer to auditors. Their operators do. AgentGuard captures agent identity from the MCP session so that every tool call can be traced to a system (and by extension, the person or team who deployed and operates that system).

This is not about blaming the AI. It is about creating a chain of accountability that federal assessors can follow: tool call -> agent session -> operator identity -> authorized use case.
