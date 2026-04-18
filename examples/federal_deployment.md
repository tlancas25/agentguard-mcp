# Federal Deployment Guide

This guide covers deploying AgentGuard in federal mode for FISMA/FedRAMP environments.

## Prerequisites

- Python 3.11+ in your deployment environment
- A SIEM solution (Splunk, Elastic, etc.) for audit log forwarding
- A key management solution for signing key storage (HSM recommended for High impact)

## Step 1: Generate a Signing Keypair

```bash
agentguard init --gen-key
```

Store the private key in your organization's key management system (AWS KMS, HashiCorp Vault, DoD PKI, etc.).
Set it as an environment variable in your deployment:

```bash
export AGENTGUARD_SIGNING_KEY="<base64-encoded-private-key>"
```

The public key should be shared with your ISSO and stored in the ATO package for audit verification.

## Step 2: Configure for Federal Mode

```yaml
# agentguard.yaml
mode: federal
audit_db_path: /var/log/agentguard/audit.db
signing_key: ""  # Use AGENTGUARD_SIGNING_KEY env var

federal:
  agency_id: "YOUR-AGENCY-ID"
  system_name: "Your System ATO Package"
  impact_level: MODERATE  # or HIGH

policy_bundles:
  - /etc/agentguard/federal_mode.yaml

detectors:
  prompt_injection:
    enabled: true
    action: deny
    score_threshold: 0.7
  pii:
    enabled: true
    action: deny
  secrets:
    enabled: true
    action: deny
  tool_poisoning:
    enabled: true
    action: log  # Investigate, don't auto-deny
```

## Step 3: Define Your Policy Allowlist

Edit your federal policy bundle to list tools your system is authorized to use:

```yaml
# /etc/agentguard/federal_mode.yaml
name: production_federal
default_action: deny

tool_allowlist:
  - filesystem_read_file
  - filesystem_list_directory
  # Add only the tools your system actually needs
  # Every tool here should have a documented business justification

tool_denylist:
  - run_terminal_command
  - execute_code
  - filesystem_delete_file
  - filesystem_write_file  # Unless your use case requires it
```

## Step 4: Deploy

```bash
agentguard run --mode federal --transport stdio
```

For HTTP gateway mode (multi-client deployments):

```bash
agentguard run --mode federal --transport http --host 0.0.0.0 --port 8443
```

## Step 5: Verify Audit Integrity

```bash
agentguard audit verify
```

Run this on a schedule (cron) and alert on failures. A failed verification
means the audit log has been tampered with and requires incident response.

## Step 6: Generate Compliance Reports

```bash
# For FedRAMP SSP submission
agentguard report fedramp --output fedramp_evidence_$(date +%Y%m%d) --format both

# For NIST AI RMF assessment
agentguard report nist-ai-rmf --output ai_rmf_assessment_$(date +%Y%m%d)
```

## POA&M Workflow

If any security findings appear in your audit log:

1. Review the finding details in the report
2. Document the finding in your POA&M
3. Implement remediation (update policy, rotate credentials, adjust allowlist)
4. Re-run the report after remediation to confirm resolution

## SIEM Export

For continuous monitoring, export audit events periodically:

```bash
# Export to JSONL for SIEM ingestion
agentguard audit tail --config agentguard.yaml
```

Or implement a scheduled export using the Python API:

```python
from agentguard.audit_log import AuditLog
from pathlib import Path

log = AuditLog(db_path=Path("/var/log/agentguard/audit.db"))
log.export_jsonl(Path("/var/log/agentguard/export.jsonl"))
```

## Key Rotation

Rotate the signing key on a schedule appropriate for your impact level:
- LOW: annually
- MODERATE: every 6 months
- HIGH: every 90 days (or per system security plan)

When rotating, export the current audit log before rotation so old events
remain verifiable with the old public key.
