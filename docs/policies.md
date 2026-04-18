# Policy DSL Reference

AgentGuard policies are YAML files that define how the policy engine responds to tool calls.

## Policy Bundle Structure

```yaml
name: my_policy              # Required: bundle identifier
description: "..."           # Optional: human-readable description

default_action: log          # Required: allow | deny | log

tool_allowlist:              # Optional: tools explicitly permitted
  - tool_name_1
  - tool_name_2

tool_denylist:               # Optional: tools explicitly blocked (evaluated first)
  - dangerous_tool

pii_scan: false              # Enable PII detector (default: false)
injection_scan: false        # Enable injection detector (default: false)
tool_poisoning_scan: true    # Enable tool poisoning scan (default: true)
require_signing: false       # Require Ed25519 signed audit (default: false)

rules:                       # Optional: named rules (first match wins)
  - name: my_rule
    tool: tool_name          # Exact tool name, or "*" for wildcard
    tool_prefix: "prefix_"   # Match tools starting with this prefix
    has_args:                # Match if ALL these arg keys are present
      - content
    action: deny             # allow | deny | log
    reason: "Why this rule exists."
    nist_controls:           # NIST controls this rule addresses
      - AC-3
      - AU-2
```

## Evaluation Order

1. **Denylist** — If the tool name is in `tool_denylist`, deny immediately. This always wins.
2. **Allowlist** — If `tool_allowlist` is populated and the tool is in it, allow. If the allowlist is populated and the tool is NOT in it, apply mode default (deny in federal mode, log in dev mode).
3. **Named Rules** — Evaluated in order; the first matching rule's action is applied.
4. **Bundle Default** — If no rule matched, use `default_action`.
5. **Mode Default** — If no bundle produced a decision, use the mode default (dev=log, federal=deny).

## Dev Mode Behavior

In dev mode, explicit denylists are still respected (they always take priority). However, rules and bundle defaults that specify `deny` are downgraded to `log`. This ensures dev mode never blocks tool calls due to policy rules, only due to explicit denylist entries.

If you have tools you want to block even in dev mode, put them in `tool_denylist`.

## Federal Mode Behavior

In federal mode, everything is as configured. Deny rules deny. The default_action is applied as-is. If `tool_allowlist` is populated and the tool is not in it, the tool is denied.

If `tool_allowlist` is empty and `default_action` is `deny`, all tool calls are denied. This is intentional for initial federal deployments: start locked down, then open up what you need.

## Multiple Policy Bundles

You can configure multiple policy bundles. They are evaluated in order; the first bundle that produces a decision wins.

```yaml
policy_bundles:
  - ./policies/global_denies.yaml   # Evaluated first
  - ./policies/app_specific.yaml    # Evaluated if global didn't match
  - ./policies/defaults/federal_mode.yaml  # Final fallback
```

## Rule Matchers

| Field | Description |
|-------|-------------|
| `tool` | Exact tool name, or `"*"` for wildcard |
| `tool_prefix` | Match any tool whose name starts with this string |
| `has_args` | List of arg keys; all must be present in tool_args |

Matchers can be combined. A rule only fires if ALL specified matchers match.
