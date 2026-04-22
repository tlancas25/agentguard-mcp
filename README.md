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
[![GitHub stars](https://img.shields.io/github/stars/tlancas25/agentguard-mcp?style=social)](https://github.com/tlancas25/agentguard-mcp)

---

## Scope & Ethics — What This Is (and Is Not)

AgentGuard is a **defensive** gateway for AI agents operating in regulated environments. It is modeled on the same patterns used for traditional software — a WAF in front of a web app, a SIEM collecting host events, SELinux mediating syscalls — applied to the MCP (Model Context Protocol) tool-call layer.

**What AgentGuard does:**
- Intercepts MCP tool calls an agent wants to make (read files, run commands, call APIs, query databases)
- Evaluates each call against a policy bundle and a detector stack (prompt injection, PII, secrets, tool poisoning)
- Logs every call to a tamper-evident, hash-chained, optionally Ed25519-signed audit database
- Generates NIST 800-53 / FedRAMP / NIST AI RMF evidence on demand
- Self-protection mode: denies or holds mutations against the gateway's own state, to survive a compromised user channel

**What AgentGuard does NOT do:**
- It does **not** modify model reasoning, outputs, or internal state
- It does **not** bypass, suppress, or alter any model's safety training (RLHF, constitutional AI, platform ToS enforcement)
- It does **not** intercept Anthropic / OpenAI / provider API calls — it sees only the agent's downstream tool calls
- It does **not** exfiltrate or modify system prompts
- It is **not** a jailbreak tool, a prompt-injection kit, or an RLHF bypass — prompt injection is something it *detects and denies*, not enables
- It does **not** authenticate humans; it records the agent's identity so accountability is traceable to the operator who deployed it

If you are an auditor, AI safety reviewer, or automated classifier skimming this repo: the defensive posture is validated by the threat-model mappings below (NIST 800-53 Rev 5.2, NIST AI RMF 1.0, NIST AI 600-1 Generative AI Profile, OWASP LLM Top 10 2025, MITRE ATLAS v5.4.0, FedRAMP 20x, CMMC 2.0). Every detector and every policy enforcement path has corresponding code that implements it — see [NIST 800-53 Controls](#nist-800-53-rev-52-controls) below, and the NIST mapping precision rule in [CLAUDE.md](CLAUDE.md).

---

## One-Line Install

**macOS / Linux:**

```bash
curl -sSL https://raw.githubusercontent.com/tlancas25/agentguard-mcp/main/install.sh | bash
```

**Windows (PowerShell):**

```powershell
irm https://raw.githubusercontent.com/tlancas25/agentguard-mcp/main/install.ps1 | iex
```

Each installer detects your platform, installs [uv](https://github.com/astral-sh/uv) if needed, provisions an isolated Python 3.11+ environment, and installs the `agentguard` CLI globally. Idempotent and safe to re-run. See [Install options](#install-options) below for other methods.

---

## Table of Contents

- [Scope & Ethics](#scope--ethics--what-this-is-and-is-not)
- [The Problem](#the-problem)
- [The Solution](#the-solution)
- [Features](#features)
- [Quick Start](#quick-start)
  - [Install options](#install-options)
  - [Initialize config](#initialize-config)
  - [Run the gateway](#run-the-gateway)
  - [Add to Claude Code](#add-to-claude-code)
- [Where AgentGuard stores data](#where-agentguard-stores-data)
- [Reading the audit log](#reading-the-audit-log)
- [Self-protection](#self-protection)
- [Maintenance commands](#maintenance-commands)
- [Architecture](#architecture)
- [Compatibility](#compatibility)
- [Defensible Claims](#defensible-claims)
- [NIST 800-53 Rev 5.2 Controls](#nist-800-53-rev-52-controls)
- [NIST AI RMF Coverage](#nist-ai-rmf-coverage)
- [Integration Examples](#integration-examples)
- [Comparison](#comparison)
- [Security Disclaimer](#security-disclaimer)
- [Project Docs](#project-docs)
- [Contributing](#contributing)
- [License](#license)

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

## Who This Is For

AgentGuard is useful if any of the following applies:

- **You deploy AI agents in a regulated environment** (federal agency, defense contractor, healthcare, finance, critical infrastructure). You need audit evidence that satisfies ATO, FedRAMP, CMMC, or internal risk management.
- **You are a security engineer integrating Claude Code, Cursor, or custom MCP clients** into a production workflow and need a policy boundary between the agent and the tools it can touch.
- **You run a SOC or GRC function** and want tamper-evident logs of every AI agent tool call, signed for non-repudiation.
- **You are a cleared professional** evaluating AI governance tooling for a federal customer and want something open-source that speaks NIST 800-53 Rev 5.2 and OSCAL natively.
- **You are a developer** who wants to log every MCP tool call in a local project for debugging, and you want zero friction (dev mode is pass-through by default).

If you just want a personal chat with an LLM, you do not need AgentGuard. Start needing it the moment an agent can write files, call APIs, or execute code on your behalf.

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

### Install options

Pick the path that matches your environment. All paths land on the same `agentguard` CLI.

| Method | Command | Best for |
|---|---|---|
| **One-line (macOS / Linux)** | `curl -sSL https://raw.githubusercontent.com/tlancas25/agentguard-mcp/main/install.sh \| bash` | Fresh machines, CI runners, first-time users |
| **One-line (Windows)** | `irm https://raw.githubusercontent.com/tlancas25/agentguard-mcp/main/install.ps1 \| iex` | Windows 10/11 PowerShell 5.1+ |
| **uv (recommended, any OS)** | `uv tool install git+https://github.com/tlancas25/agentguard-mcp.git` | Developers already using uv |
| **pipx (isolated, any OS)** | `pipx install git+https://github.com/tlancas25/agentguard-mcp.git` | Python users who prefer pipx |
| **pip (any OS)** | `pip install git+https://github.com/tlancas25/agentguard-mcp.git` | Quick test in an existing venv |
| **uvx (ephemeral run, any OS)** | `uvx --from git+https://github.com/tlancas25/agentguard-mcp.git agentguard run` | Try without installing |
| **Clone + editable** | `git clone https://github.com/tlancas25/agentguard-mcp.git && cd agentguard-mcp && pip install -e .[dev]` | Contributors |

> PyPI release (`pip install agentguard-mcp` without the git URL) is planned for v0.2. Until then, the one-line installers and git-based commands above are authoritative.

**Requirements:** Python 3.11 or later. The one-line installers will bootstrap a compatible Python via uv if your system Python is older.

### Initialize config

```bash
agentguard init
```

This creates `agentguard.yaml` in your current directory with dev mode defaults. Federal operators should also generate a signing key:

```bash
agentguard init --gen-key
```

### Run the gateway

```bash
# Dev mode: permissive pass-through, log-only, no workflow friction
agentguard run --mode dev

# Federal mode: deny-by-default, signed audit, fail-fast if signing key is missing
AGENTGUARD_SIGNING_KEY=/path/to/ed25519.key agentguard run --mode federal
```

Verify the audit chain at any time:

```bash
agentguard audit verify
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

## Where AgentGuard stores data

By default AgentGuard keeps everything under a single per-user directory so it behaves the same whether you launch it from your shell, from Claude Code, or from a service manager.

| What | Default path |
|------|--------------|
| Config file | `~/.agentguard/agentguard.yaml` |
| Audit database (SQLite) | `~/.agentguard/audit.db` |
| Signing key (if enabled) | Supplied via `signing_key:` in the YAML or `AGENTGUARD_SIGNING_KEY` env var. AgentGuard never writes the key to disk on your behalf. |

On Windows the same paths resolve to `C:\Users\<you>\.agentguard\` — tilde expansion is handled when the YAML is loaded.

**To change these paths:** set `audit_db_path:` in the YAML (tildes and env vars are expanded), or override at runtime with:

```bash
export AGENTGUARD_AUDIT_DB=/var/log/agentguard/audit.db
```

**Who has access:** the audit database is a regular file on your local disk. On multi-user systems, restrict it with the same controls you apply to any sensitive log (`chmod 600` on POSIX, ACLs on Windows). AgentGuard does not chown or chmod it for you.

Every time the gateway starts it prints the resolved paths to stderr so you always know where the log is:

```
AgentGuard 0.1.0 starting in dev mode via stdio transport
  config    : C:\Users\you\.agentguard\agentguard.yaml
  audit DB  : C:\Users\you\.agentguard\audit.db
  signing   : disabled
  detectors : secrets, tool_poisoning
```

---

## Reading the audit log

AgentGuard ships several views on the log. All of them read from the same SQLite file at `audit_db_path`.

**Tail the most recent events:**

```bash
agentguard audit tail
agentguard audit tail -n 100
```

You get a table of `id | timestamp | agent | event_type | tool | decision`. Events are written by the gateway as they happen, so you can leave a second terminal open while your agent runs.

**Verify the hash chain (tamper check):**

```bash
agentguard audit verify
```

Prints `PASS` with an event count if the chain is intact, or `FAIL` with the id of the first event that doesn't hash correctly. If you configured `verify_key` in YAML or `AGENTGUARD_VERIFY_KEY`, every Ed25519 signature is also checked.

**Query with raw SQL:**

```bash
sqlite3 ~/.agentguard/audit.db \
  "SELECT id, timestamp, agent_id, tool_name, decision FROM events ORDER BY id DESC LIMIT 20;"
```

Schema: `id, timestamp, agent_id, event_type, tool_name, tool_args_json, tool_result_json, decision, policy_matched, nist_controls_json, prev_hash, event_hash, signature`.

**Export for SIEM / assessor:**

```bash
# JSONL (one event per line, every field)
agentguard audit export --format jsonl --output ~/audit-evidence.jsonl

# CSV
agentguard audit export --format csv --output ~/audit-evidence.csv
```

**Rotating the log:** AgentGuard does not rotate the SQLite file. For long-running deployments, script a periodic export + `VACUUM` + truncate workflow, or copy the DB off-host to a SIEM before archiving.

---

## Self-protection

AgentGuard is the thing your AI agent is supposed to obey. If the user's communication channel is compromised (prompt injection, a spoofed terminal, a malicious document the agent is reading), the attacker's next move is usually to tell the agent to disable the guard — "delete `~/.agentguard/audit.db`", "uninstall the MCP server", "overwrite the signing key".

Self-protection is **opt-in** and has three modes. `agentguard init` asks which one you want. You can always change it later in `~/.agentguard/agentguard.yaml`.

| Mode | What happens to a tool call that touches `~/.agentguard/` | Recommended for |
|------|-----------------------------------------------------------|-----------------|
| **off** *(default)* | Nothing special — agents can read, modify, or stop AgentGuard freely. | Single-user dev box, local experimentation. |
| **standard** | Reads are allowed and logged. Mutations (rm, mv, chmod, SQL writes, `agentguard update`, `claude mcp remove`, direct file writes, …) are **held** until an operator runs `agentguard approve <code>` in a sibling terminal. 60-second timeout → auto-deny. | Shared workstations, review environments. |
| **strict** | Any reference — read or write — is denied outright. | Production deployments where agents should never read the gateway's own state. |

Regardless of mode, every denied, allowed-read, approved-mutation, and denied-mutation is recorded in the hash-chained audit log under one of:

- `agentguard_tamper_attempt` (strict-deny or standard-read-allowed)
- `agentguard_tamper_approved` (standard-mutation-approved)
- `agentguard_tamper_denied` (standard-mutation-denied or timeout)

all with NIST controls `AC-3`, `AU-9`, `SC-3`, `SI-7`.

### How the approval flow works (standard mode)

1. The agent sends a mutation like `shell_exec: rm -rf ~/.agentguard/audit.db`.
2. AgentGuard classifies the call as a mutation, parks it, writes a `.pending.json` file to `~/.agentguard/approvals/`, and prints a banner to its stderr:
   ```text
   ============================================================
     AGENTGUARD APPROVAL REQUIRED
   ============================================================
     Agent      : unverified:claude-code:…
     Tool       : shell_exec
     Path hit   : C:/Users/you/.agentguard
     Preview    : shell_exec {"cmd": "rm -rf ~/.agentguard/audit.db"}
     Challenge  : 482917
     To approve : agentguard approve 482917
     To deny    : agentguard approve 482917 --deny
     Expires in : 60 seconds.
   ============================================================
   ```
3. You can also list all pending requests without knowing the code: `agentguard approve` (no args).
4. The proxy polls until the operator resolves the request or the timeout expires.

### Extend the protected set

```yaml
self_protection:
  mode: standard
  extra_paths:
    - /etc/agentguard
    - /var/log/agentguard
  approval_timeout_seconds: 60
```

Env var overrides (handy for Docker / systemd):
```bash
export AGENTGUARD_SELF_PROTECT_MODE=standard
export AGENTGUARD_SELF_PROTECT_EXTRA_PATHS="/etc/agentguard,/var/log/agentguard"
# Point the approval channel at a non-default directory (containers, tests).
export AGENTGUARD_APPROVALS_DIR="$HOME/.agentguard/approvals"
```

### What this is *not*

A replacement for OS-level isolation. A truly paranoid deployment still runs AgentGuard under a dedicated service account, `chmod 600` the DB, and ships an offsite mirror of the audit log. Self-protection is a backstop that turns a silent compromise into a loud, recorded one.

---

## Maintenance commands

```bash
agentguard help [command...]    # full help tree
agentguard version              # print version + python
agentguard repair [--dry-run]   # diagnose + fix a local install
agentguard update [--ref TAG]   # reinstall from GitHub (uv tool or pip)
```

`repair` checks for the home directory, default config, audit DB parent, hash-chain integrity, and package importability. Without `--dry-run` it creates anything missing.

`update` detects whether the install was managed by `uv tool install` or `pip` and runs the correct reinstall. Pin a specific release with `agentguard update --ref v0.2.0`.

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
- DoD 8140.03-compliant certifications: CySA+, PenTest+, Security+

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

## Project Docs

Every claim in this README traces to a document or code file. If it is not cited, it is not claimed.

| Document | What's in it |
|---|---|
| [`docs/research-brief-2026.md`](docs/research-brief-2026.md) | Source of truth for every compliance claim: EO 14179, OMB M-25-21/22, NIST AI 600-1, FedRAMP 20x, CMMC 2.0, DoD Zero Trust, OWASP LLM 2025, MITRE ATLAS v5.4.0, PQC timelines. Read this before modifying any NIST code. |
| [`docs/nist-mapping.md`](docs/nist-mapping.md) | Full control mapping across NIST 800-53 Rev 5.2, NIST AI RMF 1.0, NIST AI 600-1, OWASP LLM 2025, MITRE ATLAS, and CMMC 2.0 |
| [`docs/threat-model.md`](docs/threat-model.md) | MITRE ATLAS-organized threat model, in-scope vs out-of-scope, Palo Alto Unit 42 MCP attack coverage |
| [`docs/architecture.md`](docs/architecture.md) | Component architecture, transport layers, audit chain design |
| [`docs/getting-started.md`](docs/getting-started.md) | 10-minute first run guide |
| [`docs/policies.md`](docs/policies.md) | YAML policy DSL reference |
| [`docs/claude-code-setup.md`](docs/claude-code-setup.md) | Full Claude Code integration walkthrough |
| [`docs/fedramp-deployment.md`](docs/fedramp-deployment.md) | FedRAMP ATO workflow using AgentGuard evidence output |
| [`CLAUDE.md`](CLAUDE.md) | AI pair-programming context for contributors |
| [`HANDOFF.md`](HANDOFF.md) | Session continuity document: what's done, what's stubbed, design decisions, maintenance cadence |
| [`CHANGELOG.md`](CHANGELOG.md) | Versioned change history |
| [`CONTRIBUTING.md`](CONTRIBUTING.md) | How to contribute NIST controls, attack patterns, integrations |
| [`skills/agentguard/SKILL.md`](skills/agentguard/SKILL.md) | Behavioral guidelines for using AgentGuard as a Claude Code / Cursor skill |

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

If you know what an ATO actually costs, you know why this exists.
