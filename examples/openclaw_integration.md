# OpenClaw Integration Guide

AgentGuard and OpenClaw are complementary tools, not competitors.

- **OpenClaw** manages what context the AI agent sees (context window management, memory, retrieval)
- **AgentGuard** controls what the AI agent can do (tool call policy, audit, compliance)

Together they form a complete AI agent governance stack for federal and regulated environments.

## Architecture

```
Claude Code / Cursor
        |
   [OpenClaw]          <- Context management, memory, retrieval filtering
        |
  [AgentGuard]         <- Tool call interception, policy enforcement, audit
        |
  MCP Servers          <- filesystem, GitHub, database, etc.
```

## Setup

Run OpenClaw as usual for context management. Configure AgentGuard to sit between
OpenClaw's output and the downstream MCP servers.

### `upstream.yaml` Configuration

If OpenClaw exposes an MCP-compatible interface, point AgentGuard at it:

```yaml
# upstream.yaml
- name: openclaw
  transport: stdio
  command: uvx
  args: ["openclaw", "run"]
```

### Combined `.mcp.json`

```json
{
  "mcpServers": {
    "agentguard": {
      "command": "agentguard",
      "args": ["run", "--mode", "dev"],
      "env": {
        "AGENTGUARD_UPSTREAM_SERVERS": "./upstream.yaml"
      }
    }
  }
}
```

## Division of Responsibility

| Concern | Tool |
|---------|------|
| What context does the agent see? | OpenClaw |
| What tools can the agent call? | AgentGuard |
| Audit trail for compliance | AgentGuard |
| Memory and retrieval filtering | OpenClaw |
| PII in tool call args | AgentGuard |
| Sensitive content in context | OpenClaw |
| FedRAMP evidence | AgentGuard |

## Notes

- Both tools run as stdio MCP servers and chain naturally
- AgentGuard logs tool calls regardless of what context OpenClaw provided
- In federal mode, AgentGuard's audit log captures the full tool call record
  even when OpenClaw manages what the agent reads
