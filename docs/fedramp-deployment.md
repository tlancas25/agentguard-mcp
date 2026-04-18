# FedRAMP Deployment Guide

This guide covers what an authorizing official or ISSO needs to know about deploying
AgentGuard MCP as part of a FedRAMP Moderate or High system.

## What AgentGuard Provides for Your ATO Package

1. **Continuous audit log** for all AI agent tool calls (AU-2, AU-3, AU-12)
2. **Hash-chain integrity** to prove the audit log has not been tampered with (AU-9)
3. **Ed25519 non-repudiation** signatures on each audit event (AU-10)
4. **Policy enforcement** for tool access control (AC-3, AC-6)
5. **Threat detection** for prompt injection, PII, and credential leaks (SI-4, SI-10)
6. **Evidence reports** generated on demand for assessors

## Deployment Checklist

### Pre-Deployment

- [ ] Review and document which MCP servers will be protected by AgentGuard
- [ ] Define the tool allowlist for each AI agent use case
- [ ] Generate Ed25519 signing keypair and store private key in approved KMS
- [ ] Configure `federal` section in `agentguard.yaml` with agency ID, system name, impact level
- [ ] Enable all detectors in the policy bundle
- [ ] Test with federal mode in a staging environment before production

### Deployment

- [ ] Set `AGENTGUARD_MODE=federal`
- [ ] Set `AGENTGUARD_SIGNING_KEY` from your KMS
- [ ] Protect the audit database file with appropriate OS-level permissions
- [ ] Configure log rotation or archival for the audit database
- [ ] Set up `agentguard audit verify` on a cron schedule with alerting

### Post-Deployment

- [ ] Run `agentguard report fedramp` and review the output
- [ ] Include the FedRAMP evidence report in your SSP appendix
- [ ] Run `agentguard report nist-ai-rmf` for your AI governance documentation
- [ ] Schedule periodic POA&M reviews: `agentguard report poam`

## System Security Plan Language

Suggested SSP language for the AI Agent Subsystem:

> The AI agent subsystem uses AgentGuard MCP (version X.X.X) as a transparent
> security gateway between AI agent clients and MCP-protocol tool servers.
> AgentGuard enforces tool-level access controls per AC-3, logs all tool calls
> per AU-2/AU-3/AU-12, maintains a hash-chained audit log per AU-9, and applies
> Ed25519 signatures to each audit event per AU-10. Prompt injection and PII
> detection are enabled per SI-4 and SI-10. FedRAMP evidence reports are
> generated on demand from the audit database.

## Continuous Monitoring

Schedule these commands as part of your ConMon program:

```bash
# Daily: verify audit integrity
agentguard audit verify

# Weekly: generate updated FedRAMP evidence
agentguard report fedramp --output fedramp_evidence_$(date +%Y%m%d)

# Monthly: generate NIST AI RMF assessment
agentguard report nist-ai-rmf --output ai_rmf_$(date +%Y%m)

# On demand: POA&M for any new findings
agentguard report poam --output poam_$(date +%Y%m%d)
```

## Assessor Questions and Answers

**Q: How do I verify the audit log has not been tampered with?**

Run `agentguard audit verify`. A passing result confirms the hash chain is intact from genesis to the most recent event.

**Q: How do I verify audit event signatures?**

The public key corresponding to the Ed25519 signing key is provided in the ATO package. Use the cryptography library to verify: `public_key.verify(base64.b64decode(event['signature']), event['event_hash'].encode())`.

**Q: What happens if an AI agent attempts to call a non-authorized tool?**

In federal mode, the tool call is denied before reaching the upstream MCP server. The denial is logged to the audit database with the AC-3 and AC-6 control tags. The agent receives a JSON-RPC error response.

**Q: How is agent identity established?**

Agent identity is extracted from the MCP `initialize` handshake (client name and version) combined with a per-session UUID. All audit events reference this agent_id. Stronger identity (DoD PKI certificate-based) is on the roadmap.
