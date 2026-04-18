# Claude Code Integration Guide

This guide shows how to add AgentGuard as a security gateway for Claude Code's MCP tool calls.

## Prerequisites

- Claude Code installed
- Python 3.11+
- `pip install agentguard-mcp` (or clone the repo and `pip install -e .`)

## Setup

### 1. Initialize AgentGuard Config

In your project directory:

```bash
agentguard init
```

This creates `agentguard.yaml` with dev mode defaults.

### 2. Create an Upstream Servers File

Create `upstream.yaml` to tell AgentGuard which MCP servers to protect:

```yaml
# upstream.yaml
- name: filesystem
  transport: stdio
  command: uvx
  args: ["mcp-server-filesystem", "/home/user/projects"]
```

### 3. Configure Claude Code

#### Before AgentGuard (direct connection)

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "uvx",
      "args": ["mcp-server-filesystem", "/home/user/projects"]
    }
  }
}
```

#### After AgentGuard (proxied)

```json
{
  "mcpServers": {
    "agentguard": {
      "command": "uvx",
      "args": ["agentguard", "run", "--mode", "dev", "--transport", "stdio"],
      "env": {
        "AGENTGUARD_CONFIG": "./agentguard.yaml",
        "AGENTGUARD_UPSTREAM_SERVERS": "./upstream.yaml",
        "AGENTGUARD_AUDIT_DB": "./audit.db"
      }
    }
  }
}
```

The upstream filesystem server is now configured in `upstream.yaml` instead of `.mcp.json`. AgentGuard intercepts all calls and logs them, then forwards to the filesystem server.

### 4. Verify It Works

Start a Claude Code session and run a tool call. Then check the audit log:

```bash
agentguard audit tail -n 10
```

You should see tool call events logged.

## Switching to Federal Mode

When you need enforcement (federal deployment, FISMA compliance, ATO work):

1. Generate a signing key:
   ```bash
   agentguard init --gen-key
   ```
   Add the private key to `AGENTGUARD_SIGNING_KEY` in your environment.

2. Switch mode in your `.mcp.json`:
   ```json
   "args": ["agentguard", "run", "--mode", "federal"]
   ```

3. Add your allowlist to `agentguard.yaml`:
   ```yaml
   policy_bundles:
     - ./agentguard/policies/defaults/federal_mode.yaml
   ```
   Edit `federal_mode.yaml` to populate `tool_allowlist` with tools your agent needs.

4. Verify audit signing:
   ```bash
   agentguard audit verify
   ```

## Generating Compliance Reports

```bash
# FedRAMP evidence package
agentguard report fedramp --output fedramp_evidence

# NIST AI RMF assessment
agentguard report nist-ai-rmf --output ai_rmf_assessment
```

Reports are written as Markdown and JSON files suitable for inclusion in an ATO package.
