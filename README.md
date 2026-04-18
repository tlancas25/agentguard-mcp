# AgentGuard MCP

**Open-source MCP security gateway purpose-built for federal and defense AI deployments**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/Python-3.11%2B-blue)](https://python.org)
[![MCP Compatible](https://img.shields.io/badge/MCP-Compatible-green)](https://modelcontextprotocol.io)
[![NIST 800-53 Rev 5.2](https://img.shields.io/badge/NIST%20800--53-Rev%205.2-blue)](docs/nist-mapping.md)
[![NIST AI RMF 1.0](https://img.shields.io/badge/NIST%20AI%20RMF-1.0-blue)](docs/nist-mapping.md)
[![NIST AI 600-1](https://img.shields.io/badge/NIST%20AI%20600--1-Gen%20AI%20Profile-blue)](docs/nist-mapping.md)
[![OWASP LLM 2025](https://img.shields.io/badge/OWASP%20LLM-2025-orange)](docs/nist-mapping.md)
[![MITRE ATLAS v5.4.0](https://img.shields.io/badge/MITRE%20ATLAS-v5.4.0-red)](docs/threat-model.md)
[![FedRAMP 20x](https://img.shields.io/badge/FedRAMP%2020x-Class%20B%2FC-blue)](docs/fedramp-deployment.md)
[![CMMC 2.0](https://img.shields.io/badge/CMMC%202.0-L2%2FL3%20Roadmap-yellow)](docs/nist-mapping.md)
[![OSCAL 1.1.2](https://img.shields.io/badge/OSCAL-1.1.2-green)](agentguard/reports/oscal.py)

---

## The Problem

MCP (Model Context Protocol) agents can read files, execute code, call APIs, and query databases, all on behalf of a human who may not review each individual action. That capability is the point. It is also a significant attack surface.

For federal agencies, defense contractors, and regulated enterprises, deploying MCP agents without a security layer means:

- No audit trail that satisfies ATO requirements
- No mechanism to enforce least-privilege access at the tool level
- No detection for prompt injection attacks that weaponize tool calls
- No PII controls on data flowing through agent sessions
- No evidence artifacts for FedRAMP assessors or CMMC auditors
- No mapping between system behavior and NIST 800-53 controls

Other MCP proxy tools address some of these gaps for commercial environments. AgentGuard is purpose-built for the federal and defense use case, with native NIST 800-53 Rev 5.2 control mapping and FedRAMP 20x OSCAL output.

---

## The Solution

AgentGuard MCP is a transparent security gateway that sits between your AI agent and any MCP server. It intercepts every tool call, evaluates it against policy, logs it to a tamper-evident audit chain, and optionally blocks it, all without changing how your agent or your MCP servers are configured.

It ships in two modes designed for two different realities:

**Dev Mode** is permissive by default. It logs everything and blocks nothing. Use it daily with Claude Code, Cursor, or OpenClaw without any workflow friction. When something looks suspicious in your logs, you investigate. No false positives interrupting your work.

**Federal Mode** flips the defaults. Deny unless explicitly allowed. Full PII and injection scanning. Signed audit events. FedRAMP evidence reports and NIST AI RMF assessments available on demand.

One tool, two modes, the same codebase.

---

## Features

| Capability | Dev Mode | Federal Mode |
|---|---|---|
| Transparent MCP proxy (stdio + HTTP) | Yes | Yes |
| Full tool call audit log (SQLite) | Yes | Yes |
| Hash-chained tamper detection | Yes | Yes |
| Ed25519 audit event signing | Optional | Required |
| NIST 800-53 Rev 5 control mapping | Yes | Yes |
| Prompt injection detection | Off by default | On |
| PII detection (SSN, CC, PHI patterns) | Off by default | On |
| Secret / API key leak detection | On | On |
| MCP tool description poisoning scan | On | On |
| Tool allowlist / denylist enforcement | Log only | Enforced |
| FedRAMP SSP evidence export | Available | Available |
| NIST AI RMF assessment export | Available | Available |
| Plan of Action and Milestones (POA&M) | Available | Available |
| SIEM export endpoint | Available | Available |
| Policy DSL (YAML-based) | Yes | Yes |

---

## Quick Start

### Install

```bash
pip install agentguard-mcp
```

Or run without installing:

```bash
uvx agentguard run
```

### Initialize Config

```bash
agentguard init
```

This creates `agentguard.yaml` in your current directory with dev mode defaults.

### Run the Gateway

```bash
agentguard run --mode dev
```

### Add to Claude Code

In your project's `.mcp.json`:

```json
{
  "mcpServers": {
    "agentguard": {
      "command": "uvx",
      "args": ["agentguard", "run", "--mode", "dev"],
      "env": {
        "AGENTGUARD_UPSTREAM_SERVERS": "./upstream.yaml"
      }
    }
  }
}
```

See `examples/claude_code_integration.md` for the complete setup guide.

---

## Architecture

```
                    ┌─────────────────────────────────┐
                    │         AI Agent / Client        │
                    │  (Claude Code, Cursor, OpenClaw) │
                    └────────────────┬────────────────┘
                                     │ MCP tool calls
                                     ▼
                    ┌─────────────────────────────────┐
                    │          AgentGuard MCP          │
                    │                                  │
                    │  ┌──────────┐  ┌─────────────┐  │
                    │  │ Identity │  │   Policy     │  │
                    │  │ Extract  │  │   Engine     │  │
                    │  └────┬─────┘  └──────┬──────┘  │
                    │       │               │          │
                    │  ┌────▼───────────────▼──────┐  │
                    │  │       Proxy Core           │  │
                    │  │  (intercept + decide)      │  │
                    │  └────────────┬──────────────┘  │
                    │               │                  │
                    │  ┌────────────▼──────────────┐  │
                    │  │      Detectors              │  │
                    │  │  Injection | PII | Secrets │  │
                    │  │  Tool Poisoning             │  │
                    │  └────────────┬──────────────┘  │
                    │               │                  │
                    │  ┌────────────▼──────────────┐  │
                    │  │  Hash-Chained Audit Log    │  │
                    │  │  (SQLite + Ed25519 sigs)   │  │
                    │  └───────────────────────────┘  │
                    └────────────────┬────────────────┘
                                     │ forwarded (or denied)
                                     ▼
                    ┌─────────────────────────────────┐
                    │     Upstream MCP Servers         │
                    │  filesystem | github | database  │
                    └─────────────────────────────────┘

      Side channels:
      ┌─────────────────────┐   ┌──────────────────────┐
      │  Reports (on demand) │   │   SIEM / export       │
      │  FedRAMP evidence    │   │   CSV / JSONL stream  │
      │  NIST AI RMF assess  │   │   (federal mode)      │
      │  POA&M               │   └──────────────────────┘
      └─────────────────────┘
```

---

## Compatibility

| MCP Client | Status | Notes |
|---|---|---|
| Claude Code | Supported | See `examples/claude_code_integration.md` |
| Cursor | Supported | See `examples/cursor_integration.md` |
| OpenClaw | Supported | Complementary, see `examples/openclaw_integration.md` |
| Any MCP stdio client | Supported | Standard MCP protocol |
| Any MCP HTTP client | Supported | Via gateway mode |

---

## Defensible Claims

- Native NIST 800-53 Rev 5.2 control mapping at the tool-call level (`agentguard/nist/controls_800_53.py`)
- NIST AI 600-1 Generative AI Profile alignment, Information Security and Value Chain risk areas (`agentguard/nist/ai_rmf.py`)
- OWASP LLM Top 10 2025 defenses with MITRE ATLAS v5.4.0 technique citations (`agentguard/nist/owasp_llm.py`, `agentguard/nist/mitre_atlas.py`)
- FedRAMP 20x ready: emits OSCAL 1.1.2 Component Definition JSON (`agentguard/reports/oscal.py`)
- CMMC 2.0 Level 2/3 evidence pack (v0.2 roadmap; scaffold in `agentguard/nist/cmmc.py`)
- Dual-mode design: transparent in development, rigorous in production
- Built by a U.S. Army veteran with DoD 8140.03-compliant certifications (CySA+, PenTest+, Security+)

---

## NIST 800-53 Rev 5.2 Controls

AgentGuard implements the following controls. Each has corresponding code in `agentguard/nist/controls_800_53.py` and referenced modules. Full details in `docs/nist-mapping.md`.

| Control | Title | How AgentGuard Addresses It |
|---|---|---|
| AC-3 | Access Enforcement | Policy engine enforces tool allowlist/denylist |
| AC-4 | Information Flow Enforcement | Downstream tool call filtering; blocks PII/secret-laden flows |
| AC-6 | Least Privilege | Federal mode denies by default; explicit grants required |
| AC-7 | Unsuccessful Logon Attempts | Logs repeated policy denials per agent identity |
| AC-17 | Remote Access | Gateway mode enforces transport-level policy |
| AU-2 | Event Logging | Every tool call generates an audit event |
| AU-3 | Content of Audit Records | Events include agent ID, tool name, args, result, decision |
| AU-9 | Protection of Audit Information | Hash chain detects modification; Ed25519 signs each event |
| AU-10 | Non-repudiation | Signed events tied to agent identity cannot be repudiated |
| AU-12 | Audit Record Generation | Audit is automatic; cannot be disabled in federal mode |
| CM-7 | Least Functionality | Deny-by-default federal mode; allowlist defines the permitted surface |
| IA-2 | Identification and Authentication | Agent identity extracted from MCP initialize handshake |
| IA-9 | Service Identification and Authentication | Upstream MCP server identity validation |
| RA-5 | Vulnerability Monitoring | Tool poisoning detector; threat feed integration (v0.2) |
| SC-7 | Boundary Protection | AgentGuard is the managed boundary between agents and MCP servers |
| SC-8 | Transmission Confidentiality | TLS enforced in HTTP gateway mode (config required) |
| SI-4 | System Monitoring | Injection and anomaly detectors run on every request |
| SI-7 | Software Integrity | Tool poisoning detector; hash chain integrity verification |
| SI-10 | Information Input Validation | PII, injection, and secret detectors validate all tool args |
| SI-15 | Information Output Filtering | Response filtering for PII/secrets in tool results |

---

## NIST AI RMF Coverage

| Function | Subcategory | AgentGuard Implementation |
|---|---|---|
| GOVERN | 1.2 | Policy bundle defines accountability chain for agent actions |
| GOVERN | 1.5 | Audit log provides traceability for AI decisions |
| GOVERN | 4.3 | Federal mode reports support organizational risk posture |
| MAP | 2.1 | Tool call intercept maps to threat model in `docs/threat-model.md` |
| MAP | 3.1 | Detectors identify known AI attack patterns |
| MAP | 5.1 | Policy engine maps risk response (allow/deny/log) to each threat |
| MEASURE | 2.1 | Detection rates logged per session for measurement |
| MEASURE | 2.6 | Hash chain provides tamper evidence for audit |
| MEASURE | 2.7 | POA&M report tracks unresolved findings |
| MEASURE | 3.1 | Reports surface AI system behavior metrics |
| MANAGE | 1.3 | Policy updates address identified risks |
| MANAGE | 3.2 | Incident response supported via audit tail and export |
| MANAGE | 4.1 | Signed audit provides basis for after-action review |

---

## Integration Examples

### Claude Code `.mcp.json`

```json
{
  "mcpServers": {
    "agentguard": {
      "command": "uvx",
      "args": ["agentguard", "run", "--transport", "stdio"],
      "env": {
        "AGENTGUARD_MODE": "dev",
        "AGENTGUARD_UPSTREAM_SERVERS": "./upstream.yaml"
      }
    }
  }
}
```

### Python Client

```python
import subprocess
import json

# AgentGuard acts as a transparent MCP proxy
proc = subprocess.Popen(
    ["agentguard", "run", "--mode", "federal"],
    stdin=subprocess.PIPE,
    stdout=subprocess.PIPE,
)
```

### Cursor

See `examples/cursor_integration.md` for the full Cursor configuration.

---

## Comparison

Competitors exist and are worth knowing. This table reflects publicly documented capabilities as of April 2026.

| Feature | AgentGuard | mcp-firewall | Docker MCP Gateway | Microsoft MCP Gateway | IBM ContextForge |
|---|---|---|---|---|---|
| NIST 800-53 Rev 5.2 mapping | Yes | No | No | No | No |
| OWASP LLM 2025 mapping | Yes | Partial (OPA/Rego) | No | No | No |
| MITRE ATLAS v5.4.0 mapping | Yes | No | No | No | No |
| NIST AI 600-1 alignment | Yes | No | No | No | No |
| FedRAMP 20x OSCAL export | Yes | No | No | No | No |
| CMMC 2.0 evidence (roadmap) | v0.2 | No | No | No | No |
| Hash-chained audit log | Yes | No | Partial | No | No |
| Ed25519 audit signing | Yes | No | No | No | No |
| Prompt injection detection | Yes | Partial | No | Partial | No |
| PII detection | Yes | No | No | No | No |
| Tool poisoning detection | Yes | No | No | No | No |
| Dev mode pass-through | Yes | No | No | No | No |
| Open source | Yes | Yes | No | No | No |
| OPA/Rego policy engine | No (YAML only) | Yes | No | No | No |
| SaaS dashboard | No | No | Yes | Yes | Yes |
| Kubernetes-native | No | No | Yes | Yes | No |
| Azure Entra ID integration | No | No | No | Yes | No |
| Federation/registry | No | No | No | No | Yes |
| Community size | Small | Small | Medium | Large | Medium |

**Where AgentGuard wins:** Federal-specific NIST/CMMC/FedRAMP mapping; OSCAL output; MITRE ATLAS technique citations; dual-mode design for developer ergonomics.

**Where AgentGuard does not win:** No SaaS dashboard; smaller community; no Kubernetes-native deployment; OPA/Rego policy engine planned for v0.2 only.

AgentGuard does not claim to be first or exclusive. It claims to be purpose-built for the federal and defense use case with native compliance language.

---

## Security Disclaimer

AgentGuard is a policy enforcement and audit tool. It is not a replacement for proper network security, identity management, or infrastructure hardening. It cannot prevent attacks that bypass the MCP protocol layer entirely. It cannot audit actions taken by the upstream MCP servers themselves, only the calls made to them.

For federal deployments, AgentGuard should be one layer of a defense-in-depth architecture, not a standalone solution.

Report security vulnerabilities to the maintainer directly. Do not open public issues for security bugs.

---

## Contributing

Contributions are welcome, especially NIST control implementations, attack pattern submissions, and integration guides for new MCP clients. See [CONTRIBUTING.md](CONTRIBUTING.md) for the full guide.

---

## License

MIT License. Copyright (c) 2026 Terrell Lancaster.

Built by a U.S. Army veteran (2004-2012, Honorable Discharge) with DoD 8140.03-compliant certifications (CySA+, PenTest+, Security+). If you know what an ATO actually costs, you know why this exists.
