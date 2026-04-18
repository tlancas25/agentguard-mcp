# AgentGuard MCP — Project Context for AI Pair Programming

## What This Project Is

AgentGuard MCP is an open-source security gateway for MCP (Model Context Protocol) servers. It sits between an AI agent (Claude Code, Cursor, OpenClaw, etc.) and one or more downstream MCP servers, intercepting every tool call to enforce policy, detect attacks, and generate audit evidence.

The primary use case is federal and defense organizations that need AI agents to operate within NIST 800-53 Rev 5 and FedRAMP compliance boundaries. The secondary use case is any developer who wants visibility into what their AI agent is actually doing.

## Dual-Mode Architecture

This is the most important design constraint. Every change must preserve it.

**Dev Mode** (`AGENTGUARD_MODE=dev`, the default):
- Transparent pass-through
- All tool calls are logged but never blocked
- No PII scanning, no injection scanning (too noisy for daily dev work)
- Zero configuration required to get started
- Must not interfere with Claude Code + OpenClaw daily workflows

**Federal Mode** (`AGENTGUARD_MODE=federal`):
- Deny by default unless explicitly allowed
- Full PII scanning, injection scanning, tool poisoning scanning
- All audit events must be signed with Ed25519
- Generates FedRAMP and NIST AI RMF compliance reports

Do not add enforcement logic that runs in dev mode. Do not add logging gaps that would break federal mode audit chains.

## Tech Stack

| Component | Technology |
|-----------|------------|
| Language | Python 3.11+ |
| MCP SDK | `mcp` Python package |
| Config | `pydantic` v2 models + `pyyaml` |
| CLI | `click` + `rich` |
| Audit storage | SQLite via `sqlite3` (stdlib) |
| Cryptography | `cryptography` (Ed25519) |
| Packaging | `hatchling` via `pyproject.toml` |
| Testing | `pytest` + `pytest-asyncio` |
| Linting | `ruff` + `mypy` + `bandit` |

## Key Files and Responsibilities

| File | Role |
|------|------|
| `agentguard/cli.py` | Entry point for all CLI commands |
| `agentguard/config.py` | Pydantic config models, env var loading |
| `agentguard/modes.py` | Mode enum and mode-specific defaults |
| `agentguard/proxy.py` | Core interception logic (the hot path) |
| `agentguard/server.py` | MCP stdio server using the MCP SDK |
| `agentguard/gateway.py` | HTTP gateway for production deployments |
| `agentguard/audit_log.py` | Hash-chained SQLite audit log |
| `agentguard/policy_engine.py` | YAML policy evaluation, returns Decision |
| `agentguard/identity.py` | Extracts agent identity from MCP session |
| `agentguard/detectors/` | Prompt injection, PII, secrets, tool poisoning |
| `agentguard/nist/` | Control library, AI RMF library, event mappings |
| `agentguard/reports/` | FedRAMP, AI RMF, POA&M report generators |
| `agentguard/policies/defaults/` | Default YAML policies for each mode |

## Development Guidelines

### Surgical Changes

The proxy.py hot path runs on every tool call. Keep it fast. Avoid disk I/O in the synchronous decision path beyond the audit log write.

### NIST Mapping Precision

Every NIST control reference in code or docs must be backed by actual logic. If `SI-10` is listed in a detector's `nist_controls` field, the detector must actually perform input validation. Do not add control references as decoration.

The control library lives in `agentguard/nist/controls_800_53.py`. The event-to-control mapping lives in `agentguard/nist/mappings.py`. Both must stay in sync.

### Backward Compatibility for Dev Mode

The single hardest constraint to maintain: dev mode must never block a tool call. If you add a new scanner or policy check, it must:
1. Check the current mode before enforcing
2. Default to `action: log` in dev mode YAML
3. Be tested in both modes

### Hash Chain Integrity

The audit log is a hash chain. Every append must include the previous event's hash. Never skip an event. Never modify a written event. The `verify_chain()` method must detect any modification, deletion, or insertion. This is AU-9 and AU-10.

### Type Safety

All new code must have type hints. Run `mypy agentguard/` and resolve all errors before committing. Pydantic models are the source of truth for data shapes.

## Testing Strategy

- Unit tests: each module tested in isolation with mocks
- Integration tests: full proxy flow with a fake MCP server
- Fixture data: `tests/fixtures/sample_tool_calls.json` has canonical test cases
- Audit chain tests: tamper detection is non-negotiable, test it explicitly
- Mode tests: every policy test runs in both dev mode and federal mode

Run the full suite with: `pytest`
Run with coverage: `pytest --cov=agentguard --cov-report=html`

## What AgentGuard Does NOT Do

- It is not a WAF or network firewall
- It does not authenticate users (it identifies AI agents via MCP session)
- It does not store the content of AI responses (only tool calls and results)
- It does not prevent a determined adversary with direct MCP server access
- It is not a replacement for proper network security controls
