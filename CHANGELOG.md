# Changelog

All notable changes to AgentGuard MCP will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
AgentGuard uses [Semantic Versioning](https://semver.org/).

---

## [0.1.1] - 2026-04-18

### Added

- `tests/test_signing_requirements.py`: federal-mode signing key enforcement tests for both stdio server and HTTP gateway
- `tests/test_oscal_report.py`: OSCAL control extraction tests covering both current (`events`) and legacy (`audit_events`) audit table names

### Changed

- `agentguard/server.py:StdioServer.__init__` now raises `ValueError` at startup if `mode=federal` and no valid Ed25519 signing key is configured. No silent downgrade to unsigned audit.
- `agentguard/gateway.py:create_app` has the same fail-fast validation for HTTP gateway federal deployments.
- `pyproject.toml`: removed stale pytest asyncio configuration warning.

### Security

- Federal mode can no longer start without non-repudiation signing infrastructure in place. This closes a silent-downgrade vector where an operator could intend federal mode but receive unsigned audit output.

### Repo

- Initial public release to https://github.com/tlancas25/agentguard-mcp
- Published under MIT License

---

## [0.1.0] - 2026-04-18

### Added

- Initial scaffold of AgentGuard MCP security gateway
- Dual-mode architecture: `dev` (permissive, log-only) and `federal` (strict enforcement)
- SQLite-backed hash-chained audit log with Ed25519 signing support
- YAML-based policy engine with allow/deny/log decisions
- NIST 800-53 Rev 5 control library (AC-3, AC-6, AC-7, AC-17, AU-2, AU-3, AU-9, AU-10, AU-12, IA-2, SC-8, SI-4, SI-10)
- NIST AI RMF function library (GOVERN, MAP, MEASURE, MANAGE subcategories)
- Prompt injection detector (regex + heuristic scoring)
- PII detector (SSN, credit card, phone, email, DOB, addresses)
- Secret/token detector (API keys, private keys, bearer tokens)
- Tool poisoning detector (scans MCP tool descriptions per Palo Alto Unit 42 research)
- FedRAMP SSP evidence report generator (Markdown + JSON)
- NIST AI RMF assessment report generator
- Plan of Action and Milestones (POA&M) generator
- Click-based CLI with `init`, `run`, `audit`, `report`, `policy`, `version` commands
- MCP stdio server and HTTP gateway modes
- Dev mode policy defaults (log-only, no enforcement)
- Federal mode policy defaults (deny-by-default, full scanning)
- Example integrations for Claude Code, Cursor, and OpenClaw
- Claude Code plugin manifest (`.claude-plugin/`)
- Cursor rule file (`.cursor/rules/agentguard.mdc`)
- GitHub Actions CI/CD workflows (test, security scan, PyPI release)
- Comprehensive test suite with fixtures

### Security

- Audit log hash chain prevents tamper without detection
- Ed25519 signatures provide non-repudiation for federal deployments
- Tool description scanning catches MCP tool poisoning attacks at startup

### Known Limitations

- HTTP gateway mode requires additional TLS configuration for production
- LLM-based injection detection is a stub interface pending model integration
- CMMC 2.0 report generation deferred to v0.2.0
- OPA/Rego policy integration deferred to v0.2.0

[0.1.0]: https://github.com/tlancas25/agentguard-mcp/releases/tag/v0.1.0
