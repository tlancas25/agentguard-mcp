# Cursor Integration Guide

AgentGuard works with Cursor's MCP support via the standard stdio transport.

## Setup

### 1. Install AgentGuard

```bash
pip install agentguard-mcp
agentguard init
```

### 2. Configure Cursor MCP Settings

In Cursor's MCP configuration (typically `~/.cursor/mcp.json` or via Cursor settings):

```json
{
  "mcpServers": {
    "agentguard": {
      "command": "agentguard",
      "args": ["run", "--mode", "dev", "--transport", "stdio"],
      "env": {
        "AGENTGUARD_CONFIG": "/absolute/path/to/agentguard.yaml",
        "AGENTGUARD_UPSTREAM_SERVERS": "/absolute/path/to/upstream.yaml"
      }
    }
  }
}
```

Use absolute paths in Cursor's MCP config — relative paths may not resolve correctly.

### 3. Add the Cursor Rule

The AgentGuard cursor rule file at `.cursor/rules/agentguard.mdc` provides
context for Cursor's AI about AgentGuard policies and best practices.
Place this file in your project's `.cursor/rules/` directory.

### 4. Verify

After restarting Cursor, check tool calls are being logged:

```bash
agentguard audit tail
```

## Notes

- Cursor uses the same MCP stdio transport as Claude Code
- The same `agentguard.yaml` and policy bundles work for both
- Dev mode is recommended for daily Cursor work
