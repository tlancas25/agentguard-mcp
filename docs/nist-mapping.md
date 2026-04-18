# NIST Compliance Mapping

**AgentGuard MCP — Framework Coverage Reference**
Last updated: April 18, 2026

---

## 1. Purpose and Scope

This document maps AgentGuard MCP capabilities to the security and AI risk frameworks that federal and defense AI deployments require. It covers what AgentGuard implements, what it partially addresses, and what is explicitly out of scope.

AgentGuard operates at the MCP tool-call layer. Controls mapped here apply to tool call interception, audit logging, identity extraction, and policy enforcement. Controls that require infrastructure, model-layer, or organizational-level implementation are noted as out of scope.

**Frameworks covered:**

- NIST SP 800-53 Rev 5.2 (control catalog)
- NIST AI RMF 1.0 (GOVERN/MAP/MEASURE/MANAGE)
- NIST AI 600-1 Generative AI Profile (12 risk areas)
- OWASP LLM Top 10 2025
- MITRE ATLAS v5.4.0
- CMMC 2.0 Level 2/3 (v0.2 roadmap)
- FedRAMP 20x (Class A/B/C/D)
- NIST PQC (FIPS 203/204/205) roadmap

---

## 2. NIST SP 800-53 Rev 5.2 Control Table

**Catalog reference:** https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final

| Control | Title | AgentGuard Implementation | Code Reference |
|---------|-------|---------------------------|----------------|
| AC-3 | Access Enforcement | Policy engine enforces tool allowlist/denylist on every MCP tool call | `agentguard/policy_engine.py:PolicyEngine.evaluate` |
| AC-4 | Information Flow Enforcement | Downstream tool call filtering; blocks PII/secret-laden flows | `agentguard/proxy.py`, `agentguard/detectors/pii.py` |
| AC-6 | Least Privilege | Federal mode deny-by-default; explicit grants required | `agentguard/modes.py:FEDERAL_DEFAULTS` |
| AC-7 | Unsuccessful Logon Attempts | Repeated policy denials per agent logged; supports alerting | `agentguard/audit_log.py` |
| AC-17 | Remote Access | HTTP gateway enforces transport-level policy | `agentguard/gateway.py` |
| AU-2 | Event Logging | Every tool call generates an audit event in all modes | `agentguard/audit_log.py`, `agentguard/proxy.py` |
| AU-3 | Content of Audit Records | Events include timestamp, agent_id, tool, args, result, decision | `agentguard/audit_log.py:AuditEvent` |
| AU-9 | Protection of Audit Information | Hash-chained SQLite; verify_chain() detects tampering | `agentguard/audit_log.py:AuditLog.verify_chain` |
| AU-10 | Non-repudiation | Ed25519 signatures on audit events in federal mode | `agentguard/audit_log.py:AuditLog._sign` |
| AU-12 | Audit Record Generation | Automatic; cannot be disabled in federal mode | `agentguard/proxy.py`, `agentguard/audit_log.py` |
| CM-7 | Least Functionality | Deny-by-default federal mode; allowlist defines the permitted surface | `agentguard/policies/defaults/federal_mode.yaml` |
| IA-2 | Identification and Authentication | Agent identity from MCP initialize handshake; session UUID | `agentguard/identity.py:IdentityExtractor` |
| IA-9 | Service Identification and Authentication | Upstream MCP server identity validation | `agentguard/identity.py`, `agentguard/proxy.py` |
| RA-5 | Vulnerability Monitoring | Tool poisoning detector; threat feed integration (v0.2) | `agentguard/detectors/tool_poisoning.py` |
| SC-7 | Boundary Protection | AgentGuard is the managed boundary between agents and MCP servers | `agentguard/proxy.py`, `agentguard/gateway.py` |
| SC-8 | Transmission Confidentiality | TLS in HTTP gateway; secret detector prevents exfiltration | `agentguard/gateway.py`, `agentguard/detectors/secrets.py` |
| SI-4 | System Monitoring | Injection, PII, secret, and tool poisoning detectors on every call | `agentguard/detectors/` |
| SI-7 | Software Integrity | Tool poisoning detector; hash chain integrity verification | `agentguard/detectors/tool_poisoning.py`, `agentguard/audit_log.py` |
| SI-10 | Information Input Validation | All tool call arguments validated by detector stack | `agentguard/detectors/prompt_injection.py`, `agentguard/detectors/pii.py` |
| SI-15 | Information Output Filtering | Response filtering for PII/secrets in tool results | `agentguard/proxy.py`, `agentguard/detectors/pii.py` |

**Machine-readable version:** `agentguard/nist/controls_800_53.py` — `CONTROLS` dict with full implementation details.

**OSCAL export:** `agentguard/reports/oscal.py:export_oscal_json()` — emits OSCAL 1.1.2 Component Definition JSON for FedRAMP 20x submission.

---

## 3. NIST AI 600-1 Generative AI Profile

**Reference:** NIST AI 600-1 (July 2024) — https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.600-1.pdf

The Generative AI Profile defines 12 risk areas that apply to Gen AI systems. AgentGuard operates at the MCP tool-call layer and directly addresses two of the twelve.

| Risk Area | AgentGuard Coverage |
|-----------|---------------------|
| CBRN Information or Capabilities | Out of scope — model layer |
| Confabulation (hallucination) | Out of scope — see OWASP LLM09 note |
| Dangerous/Violent/Hateful Content | Out of scope — model provider |
| Data Privacy | Partial — PII detector covers MCP data flows |
| Environmental Impacts | Out of scope |
| Harmful Bias and Homogenization | Out of scope — model evaluation |
| Human-AI Configuration | Partial — dual-mode design enforces human policy grants |
| Information Integrity | Out of scope (audit provenance is supporting capability only) |
| **Information Security** | **PRIMARY — injection, PII, secrets, tool poisoning, signed audit** |
| Intellectual Property | Out of scope — model layer |
| Obscene/Degrading Content | Out of scope — model provider |
| **Value Chain and Component Integration** | **PRIMARY — tool poisoning, upstream server validation, supply chain** |

**Code reference:** `agentguard/nist/ai_rmf.py` — `GEN_AI_RISK_AREAS` dict and `GenAIRiskArea` enum.

---

## 4. NIST AI RMF 1.0 Function Coverage

**Reference:** NIST AI 100-1 (January 2023) — https://www.nist.gov/itl/ai-risk-management-framework

| Function | Subcategory | AgentGuard Implementation |
|----------|-------------|---------------------------|
| GOVERN | 1.2 | Audit log ties every action to agent identity; policy bundle defines authorization |
| GOVERN | 1.5 | Policy YAML bundles encode organizational risk tolerance (dev vs. federal) |
| GOVERN | 4.3 | FedRAMP evidence reports and NIST AI RMF assessments generated on demand |
| MAP | 2.1 | Threat model documents MCP attack surface; detector stack maps to threat categories |
| MAP | 3.1 | Detectors identify OWASP LLM Top 10 and MITRE ATLAS patterns in real time |
| MAP | 5.1 | Policy engine maps allow/deny/log response to each detected threat |
| MEASURE | 2.1 | Detection rates per session logged; query API returns counts by event type |
| MEASURE | 2.6 | Hash chain provides tamper-evident audit; verify_chain() on demand |
| MEASURE | 2.7 | POA&M report tracks open findings per session |
| MEASURE | 3.1 | Reports surface total calls, denial rate, detection counts exportable as JSON |
| MANAGE | 1.3 | Policy YAML updates address identified risks without gateway restart |
| MANAGE | 3.2 | Audit tail streaming and JSONL/CSV export support incident response |
| MANAGE | 4.1 | Signed audit provides forensic-quality evidence for after-action review |

**Code reference:** `agentguard/nist/ai_rmf.py` — `AI_RMF_FUNCTIONS` dict.

---

## 5. OWASP LLM Top 10 2025 — AgentGuard Defense Table

**Source:** https://genai.owasp.org/resource/owasp-top-10-for-llm-applications-2025/

| ID | Vulnerability | AgentGuard Defense | Status |
|----|---------------|-------------------|--------|
| LLM01:2025 | Prompt Injection | `agentguard/detectors/prompt_injection.py` — scans all tool args | Implemented |
| LLM02:2025 | Sensitive Information Disclosure | `agentguard/detectors/pii.py` + `agentguard/detectors/secrets.py` | Implemented |
| LLM03:2025 | Supply Chain Vulnerabilities | `agentguard/detectors/tool_poisoning.py` + upstream server allowlist | Implemented |
| LLM04:2025 | Data and Model Poisoning | Value Chain policy controls; RAG source restriction via allowlist | Partial |
| LLM05:2025 | Improper Output Handling | Response filtering (SI-15); output sanitization v0.2 | Partial |
| LLM06:2025 | Excessive Agency | Tool allowlist + deny-by-default federal mode (CM-7, AC-6) | Implemented |
| LLM07:2025 | System Prompt Leakage (new 2025) | Response scanning; `EVENT_PROMPTS_GET` triggers LLM07 tag | Partial |
| LLM08:2025 | Vector and Embedding Weaknesses (new 2025) | Tool allowlist restricts vector DB calls; direct detection v0.2 | Partial |
| LLM09:2025 | Misinformation | Out of scope — audit log provides provenance for review | Out of scope |
| LLM10:2025 | Unbounded Consumption | AC-7 rate logging; hard rate limits v0.2 | Partial |

**Code reference:** `agentguard/nist/owasp_llm.py` — `OWASP_LLM_TOP_10_2025` dict.

---

## 6. MITRE ATLAS v5.4.0 Technique — AgentGuard Defense Table

**Source:** https://atlas.mitre.org/
**Version:** v5.4.0 (February 2026) — includes AML.T0066 and AML.T0067 (new)

| Technique ID | Name | Tactic | AgentGuard Defense |
|--------------|------|--------|-------------------|
| AML.T0051.000 | Prompt Injection: Direct | Initial Access | `agentguard/detectors/prompt_injection.py` |
| AML.T0051.001 | Prompt Injection: Indirect | Initial Access | `agentguard/detectors/prompt_injection.py` + `agentguard/detectors/tool_poisoning.py` |
| AML.T0062 | AI Agent Context Poisoning | ML Attack Staging | Injection + tool poisoning detectors; audit log context capture |
| AML.T0063 | Memory Manipulation | Persistence | Hash-chained audit detects tampering; memory tool allowlist |
| AML.T0064 | Thread Injection | Execution | Injection detector covers thread-sourced inputs |
| AML.T0065 | Modify AI Agent Configuration | Persistence | Policy file integrity (SI-7, v0.2); EVENT_POLICY_LOADED logging |
| AML.T0066 | Publish Poisoned AI Agent Tool (new v5.4.0) | Resource Development | `agentguard/detectors/tool_poisoning.py`; upstream server allowlist (IA-9) |
| AML.T0067 | Escape to Host (new v5.4.0) | Privilege Escalation | Deny-by-default (CM-7, AC-6) prevents unauthorized tool access |

**Code reference:** `agentguard/nist/mitre_atlas.py` — `ATLAS_TECHNIQUES` dict.

---

## 7. CMMC 2.0 Level 2/3 Overlap (v0.2 Roadmap)

**Reference:** CMMC 2.0 Final Rule (effective December 16, 2024) — https://www.acq.osd.mil/cmmc/

CMMC 2.0 uses NIST 800-171 Rev 2 (Level 2) and NIST 800-172 (Level 3). Because NIST 800-171 overlaps heavily with NIST 800-53, AgentGuard's existing controls address a significant portion of CMMC Level 2.

| CMMC Level | Source Standard | Total Requirements | AgentGuard Scaffold (v0.1) | Full Coverage |
|------------|-----------------|-------------------|---------------------------|---------------|
| Level 1 | FAR 52.204-21 | 15 | 10 representative (67%) | v0.2 |
| Level 2 | NIST 800-171 Rev 2 | 110 | 10 representative (9%) | v0.2 |
| Level 3 | NIST 800-172 | +24 above L2 | 10 representative (42%) | v0.2 |

**Code reference:** `agentguard/nist/cmmc.py` — `ALL_REQUIREMENTS` list and `get_requirements_for_level()` helper.

**What AgentGuard can contribute to a CMMC evidence pack:**
- Audit log as evidence for AU-family requirements
- Policy bundle YAML as configuration baseline evidence (CM-family)
- Detection events as SI-family monitoring evidence
- FedRAMP reports as structured assessment artifacts

**What AgentGuard cannot do:** self-certify CMMC compliance; that requires a C3PAO assessment (Level 2 third-party) or DoD assessment (Level 3).

---

## 8. FedRAMP 20x — Class Mapping

**Reference:** FedRAMP 20x RFC-0020 — https://www.fedramp.gov/rfcs/0020/

FedRAMP 20x replaced Low/Moderate/High baselines with Class A/B/C/D designations.

| FedRAMP 20x Class | Equivalent | AgentGuard Role |
|-------------------|------------|-----------------|
| Class A | Pilot baseline | Not applicable (pilot only) |
| Class B | LI-SaaS + Low | AgentGuard OSCAL Component Definition covers Class B control subset |
| Class C | Moderate | AgentGuard implements the majority of applicable Moderate controls |
| Class D | High (hyperscale) | AgentGuard covers the MCP tool-call slice; platform-level High controls are out of scope |

**OSCAL output:** `agentguard/reports/oscal.py:export_oscal_json()` emits OSCAL 1.1.2 Component Definition JSON. FedRAMP 20x requires OSCAL submission by Q1-Q2 2027 for all authorized providers.

AgentGuard positions as a component within a larger system's ATO package, not as a standalone ATO candidate. The OSCAL component definition documents what AgentGuard is responsible for.

---

## 9. NIST PQC Roadmap (FIPS 203/204/205)

**Standards finalized:** August 13, 2024

| Algorithm | FIPS | Type | AgentGuard Planned Use |
|-----------|------|------|----------------------|
| ML-KEM-768 | FIPS 203 | Key encapsulation | TLS session keys (v0.3, infrastructure) |
| ML-DSA-65 | FIPS 204 | Digital signature | Replace Ed25519 for audit log signing (v0.3) |
| SLH-DSA-128f | FIPS 205 | Hash-based signature | Alternative signing (v0.3) |

**Current state:** AgentGuard v0.1 uses Ed25519 for audit log signing. Ed25519 is not quantum-resistant. Federal deadlines:

- 2027: NSS new acquisitions must be CNSA 2.0 compliant (NSA requirement)
- 2031: Deprecate 112-bit quantum-vulnerable algorithms (NIST IR 8547)
- 2035: Disallow 128-bit quantum-vulnerable algorithms (NIST IR 8547)

**Code reference:** `agentguard/nist/pqc.py` — `assess_audit_log_pqc_readiness()`, `NSS_NEW_ACQUISITIONS_DEADLINE`, `FEDERAL_112BIT_DEPRECATION`, `FEDERAL_128BIT_DISALLOWED`.

---

## 10. Out of Scope

AgentGuard does NOT claim coverage for the following:

- **Model-layer controls** — hallucination, bias, content moderation, training data governance
- **Network infrastructure** — TLS termination, firewall rules, network segmentation
- **Identity provider** — MFA, PKI, DoD CAC/PIV authentication (IA-2 is lightweight only)
- **Secrets management** — AgentGuard detects secrets in transit; it does not manage or store secrets
- **EO 14110** — Revoked January 20, 2025. Not referenced as current policy anywhere in this codebase
- **FedRAMP certification** — AgentGuard maps to controls; it has not been through a 3PAO assessment
- **CMMC certification** — Same; evidence generation only, not self-certification
- **OWASP LLM09 (Misinformation)** — Factual accuracy of LLM outputs is a model-layer concern
- **EU AI Act / ISO 42001** — International frameworks noted in research brief; not yet mapped in code

---

## Citations

- NIST SP 800-53 Rev 5.2: https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final
- NIST AI 100-1 (AI RMF 1.0): https://www.nist.gov/itl/ai-risk-management-framework
- NIST AI 600-1 (Generative AI Profile): https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.600-1.pdf
- OWASP LLM Top 10 2025: https://genai.owasp.org/resource/owasp-top-10-for-llm-applications-2025/
- MITRE ATLAS v5.4.0: https://atlas.mitre.org/
- FedRAMP 20x RFC-0020: https://www.fedramp.gov/rfcs/0020/
- OSCAL 1.1.2: https://pages.nist.gov/OSCAL/resources/concepts/layer/implementation/component-definition/
- CMMC 2.0: https://www.acq.osd.mil/cmmc/
- FIPS 203 (ML-KEM): https://csrc.nist.gov/pubs/fips/203/final
- FIPS 204 (ML-DSA): https://csrc.nist.gov/pubs/fips/204/final
- FIPS 205 (SLH-DSA): https://csrc.nist.gov/pubs/fips/205/final
- NIST IR 8547 (PQC transition): https://csrc.nist.gov/pubs/ir/8547/ipd
