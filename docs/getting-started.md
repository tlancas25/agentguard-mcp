# Getting Started with AgentGuard MCP

This guide gets you from zero to a working AgentGuard setup in under 10 minutes.

## Requirements

- Python 3.11 or 3.12
- An MCP-compatible AI agent (Claude Code, Cursor, or any MCP stdio client)
- At least one MCP server you want to protect

## Install

```bash
pip install agentguard-mcp
```

Verify the install:

```bash
agentguard version
```

## Initialize Config

```bash
cd your-project/
agentguard init
```

This creates `agentguard.yaml` in your current directory with dev mode defaults.

## Configure Your Upstream MCP Server

Create `upstream.yaml` to tell AgentGuard which MCP server(s) to proxy:

```yaml
# upstream.yaml
- name: filesystem
  transport: stdio
  command: uvx
  args: ["mcp-server-filesystem", "/path/to/your/workspace"]
```

## Add to Claude Code

Edit your project's `.mcp.json`:

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

## Verify It Works

1. Start Claude Code with your updated `.mcp.json`
2. Make a tool call (e.g., ask Claude to read a file)
3. Check the audit log:

```bash
agentguard audit tail
```

You should see tool call events logged.

## Next Steps

- Read [Architecture](architecture.md) to understand how AgentGuard works
- Read [Policies](policies.md) to customize what gets allowed or denied
- Read [FedRAMP Deployment](fedramp-deployment.md) to prepare for federal use
- Explore sample policies in `examples/sample_policies/`
