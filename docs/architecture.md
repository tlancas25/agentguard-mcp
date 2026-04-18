# Architecture

## System Overview

AgentGuard MCP inserts itself as a transparent proxy between an MCP client (AI agent) and one or more MCP servers. The client sees AgentGuard as if it were the MCP server. The upstream MCP servers see AgentGuard as if it were the MCP client.

```
AI Agent (MCP Client)
        |
        | MCP stdio / HTTP
        |
   [AgentGuard Gateway]
        |
        |-- [Identity Extractor]     <- Extracts agent_id from initialize
        |-- [Policy Engine]          <- YAML-based allow/deny/log
        |-- [Detector Stack]
        |     |-- Prompt Injection
        |     |-- PII
        |     |-- Secrets
        |     `-- Tool Poisoning
        |-- [Audit Log]              <- Hash-chained SQLite + Ed25519
        |
        | MCP stdio / HTTP (forwarded)
        |
  Upstream MCP Server(s)
```

## Key Components

### Identity Extractor (`agentguard/identity.py`)

Reads the MCP `initialize` request to extract the client's name and version. Generates a session UUID. All subsequent audit events reference this session's `agent_id`.

Future versions will support DoD PKI certificate-based identity for stronger non-repudiation.

### Policy Engine (`agentguard/policy_engine.py`)

Evaluates every tool call against YAML policy bundles. Returns a `Decision` with:
- `action`: allow, deny, or log
- `reason`: human-readable explanation
- `matched_rule`: which rule or list triggered the decision
- `nist_controls`: NIST 800-53 control IDs that apply

Evaluation order: denylist, then allowlist, then named rules, then bundle default.

In dev mode, rules that would deny are downgraded to log. In federal mode, deny-by-default applies when no explicit allow exists.

### Detector Stack (`agentguard/detectors/`)

Four detectors run independently on each tool call:

1. **Prompt Injection** (`prompt_injection.py`): Regex + heuristic scoring against known injection patterns. Covers OWASP LLM Top 10 LLM01 and Simon Willison's injection catalog.

2. **PII** (`pii.py`): Regex-based detection of SSN, credit cards, phone numbers, emails, addresses, and other personal data.

3. **Secrets** (`secrets.py`): Pattern matching for API keys, tokens, private keys, and credentials. Covers AWS, GitHub, Stripe, Anthropic, OpenAI, Slack, and generic patterns.

4. **Tool Poisoning** (`tool_poisoning.py`): Scans MCP tool *descriptions* (not just args) for injected instructions. This addresses the Palo Alto Unit 42 MCP attack class where malicious instructions are embedded in the tools an agent reads.

Each detector returns a `DetectionResult` with `matched`, `score`, `types_found`, and `nist_controls`.

### Audit Log (`agentguard/audit_log.py`)

SQLite-backed event log with SHA-256 hash chaining:

- Each event's hash = SHA-256(prev_hash + canonical_json(event_fields))
- The first event chains to a genesis hash of 64 zeros
- `verify_chain()` walks the entire chain to detect any modification, deletion, or insertion
- In federal mode, each event is also signed with Ed25519

The schema stores: `timestamp`, `agent_id`, `event_type`, `tool_name`, `tool_args_json`, `tool_result_json`, `decision`, `policy_matched`, `nist_controls_json`, `prev_hash`, `event_hash`, `signature`.

### Proxy Core (`agentguard/proxy.py`)

The hot path. For every intercepted MCP message:

1. Handle `initialize` — extract identity, log session start
2. Handle `tools/list` — scan tool descriptions for poisoning
3. Handle `tools/call` — run detector stack, run policy engine, log, forward or deny
4. Handle `resources/read` and `prompts/get` — policy check and log

The proxy is transport-agnostic. Both the stdio server and HTTP gateway delegate to ProxyCore.

## Transport Modes

### Stdio (`agentguard/server.py`)

Standard MCP stdio transport. Reads JSON-RPC from stdin, processes through ProxyCore, forwards to upstream subprocess. Used by Claude Code and Cursor.

### HTTP Gateway (`agentguard/gateway.py`)

FastAPI-based HTTP server that accepts MCP-over-HTTP requests. Used for multi-client production deployments. Requires `fastapi` and `uvicorn` (optional dependencies).

## Data Flow for a Tool Call

```
1. Agent sends: {"method": "tools/call", "params": {"name": "read_file", "arguments": {...}}}

2. AgentGuard receives the message

3. Identity: lookup current session agent_id

4. Detector stack (if enabled by mode/config):
   - Prompt injection scan on tool args
   - PII scan on tool args
   - Secret scan on tool args

5. Policy engine:
   - Check denylist: if match, decision=deny, skip to step 7
   - Check allowlist: if match, decision=allow
   - Check named rules: first match wins
   - Fall back to mode default (dev=log, federal=deny)

6. Audit log: write event with decision, nist_controls, prev_hash, event_hash

7. If decision is allow or log:
   - Forward to upstream MCP server
   - Receive response
   - Record tool result in audit log

8. If decision is deny:
   - Return JSON-RPC error to agent
   - Do NOT forward to upstream
```
