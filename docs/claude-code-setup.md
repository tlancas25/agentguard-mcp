# Claude Code Setup Guide

This is the full Claude Code integration guide for AgentGuard. See `examples/claude_code_integration.md` for the quick-start version.

## How It Works

Claude Code communicates with MCP servers via the MCP stdio protocol. AgentGuard replaces each MCP server in your `.mcp.json` with a single agentguard entry that proxies all tool calls through the security gateway.

```
Claude Code
    |
    | stdio (JSON-RPC)
    |
AgentGuard  <-- intercepts here
    |
    | stdio (JSON-RPC, forwarded)
    |
Your MCP Servers
```

## Step-by-Step Setup

### Step 1: Install

```bash
pip install agentguard-mcp
```

Or with uvx (no install required):

```bash
uvx agentguard version
```

### Step 2: Init Config

```bash
cd /your/project
agentguard init
```

### Step 3: Describe Your Upstream Servers

Create `upstream.yaml` in your project directory:

```yaml
# One entry per MCP server you want AgentGuard to protect
- name: filesystem
  transport: stdio
  command: uvx
  args: ["mcp-server-filesystem", "/path/to/workspace"]
```

### Step 4: Update `.mcp.json`

Replace your existing MCP server entries with the AgentGuard proxy:

```json
{
  "mcpServers": {
    "agentguard": {
      "command": "agentguard",
      "args": ["run", "--mode", "dev", "--transport", "stdio"],
      "env": {
        "AGENTGUARD_CONFIG": "./agentguard.yaml",
        "AGENTGUARD_UPSTREAM_SERVERS": "./upstream.yaml",
        "AGENTGUARD_AUDIT_DB": "./audit.db",
        "AGENTGUARD_LOG_LEVEL": "INFO"
      }
    }
  }
}
```

### Step 5: Test

Restart Claude Code. Run a tool call. Then verify:

```bash
agentguard audit tail -n 5
```

You should see your tool call logged.

## CLAUDE.md Integration

AgentGuard ships with a `CLAUDE.md` file that gives Claude Code context about what AgentGuard is and how it works. When working on AgentGuard itself, Claude Code will read this file automatically.

For projects that use AgentGuard, you can add a brief note to your project's `CLAUDE.md`:

```markdown
## Security

This project uses AgentGuard MCP as a security gateway for all MCP tool calls.
Policy is configured in `agentguard.yaml`. Audit log is at `audit.db`.
```

## Troubleshooting

**Claude Code can't find the `agentguard` command**
Make sure the Python environment where you installed agentguard-mcp is on your PATH, or use the full path in `.mcp.json`.

**Tool calls fail with permission errors**
Check `agentguard audit tail` to see the denial reason. In dev mode, tool calls should never be denied unless they're on the denylist.

**Audit log not growing**
Verify AgentGuard is actually running: check for the process and confirm the log shows startup events with `agentguard audit tail`.
