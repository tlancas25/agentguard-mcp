# Government Security Policy & AI Framework Research Brief
**Prepared for AgentGuard MCP v0.1**
**Research date:** April 18, 2026
**Scope:** Every federal policy, framework, and standard that AgentGuard must speak fluently to land federal/defense AI security roles and ATOs.

---

## PART 1 — EXECUTIVE ORDERS & WHITE HOUSE POLICY

### EO 14110 — REVOKED (Oct 2023 — Jan 2025)
Biden's "Safe, Secure, and Trustworthy Development and Use of AI." **Revoked January 20, 2025** by Trump's "Initial Rescissions of Harmful Executive Orders and Actions."

**Status:** DEAD. Do not reference in marketing or compliance collateral except to note it was rescinded. Legacy reports from 2023-2024 may still cite it.

### EO 14179 — CURRENT (Jan 23, 2025)
**"Removing Barriers to American Leadership in Artificial Intelligence."**
- Trump administration's replacement for EO 14110
- Mandates action plan within 180 days for U.S. AI leadership
- Focuses on human flourishing, economic competitiveness, national security
- Directs revocation/revision of policies that conflict with dominance goals
- Signals minimal federal oversight, industry self-regulation

### EO 14306 — CURRENT (June 2025)
Modifies EO 14028 (the 2021 Cybersecurity EO). **Removed CISA's mandate to centrally validate software attestations.** Attestation still required; validation is decentralized.

### EO 14148 — Revocations EO (Jan 20, 2025)
Trump's omnibus revocation EO that killed 14110 (AI) among others.

### Latest White House AI memo (Dec 2025)
Subject: "Eliminating State Law Obstruction of National AI Policy" — federal preemption push. Watch this space.

### Latest White House AI memo (Dec 2025) — M-26-04
"Increasing Public Trust in Artificial Intelligence Through Unbiased AI Principles." Bias-focused framework for federal use.

---

## PART 2 — OMB MEMORANDA (THE ACTUAL RULES AGENCIES FOLLOW)

### OMB M-25-21 — CURRENT (Apr 3, 2025)
**"Accelerating Federal Use of AI through Innovation, Governance, and Public Trust."**
Replaces Biden-era M-24-10. Implementation vehicle for EO 14179.

**Three pillars:**
1. **Innovation** — Remove bureaucratic barriers to AI adoption
2. **Governance** — Each agency must convene AI Governance Board within 90 days
3. **Public Trust** — AI Use Case Inventories updated annually

**High-Impact AI requirements (MUST implement):**
- Pre-deployment testing
- AI Impact Assessments
- Ongoing monitoring
- Incident response plans

**Agency Strategy Deadline:** 180 days after memo (by October 2025 — past due now)

### OMB M-25-22 — CURRENT (Apr 3, 2025)
**"Driving Efficient Acquisition of Artificial Intelligence in Government."**

**Applies to:** Contracts awarded pursuant to solicitations issued on/after **September 30, 2025**; options/renewals exercised on/after October 1, 2025. **This is live now.**

**Contract requirements:**
- Pre-award testing of proposed AI systems
- AI risk assessment for each proposal
- IP rights and government data clauses
- Vendor lock-in protections
- Compliance with M-25-21 risk management
- **Prefer U.S.-developed AI solutions**

**Key date:** GSA building online repository of AI procurement tools (within 200 days, so by November 2025 — now live).

### OMB M-23-02 — CURRENT (Nov 18, 2022)
"Migrating to Post-Quantum Cryptography." Requires annual quantum-vulnerable system inventories from all federal agencies. Still active.

---

## PART 3 — NIST FRAMEWORKS

### NIST AI Risk Management Framework (AI RMF 1.0) — ACTIVE
Published January 26, 2023. Four core functions:
- **GOVERN** — Cultivate culture of risk management
- **MAP** — Understand context and identify risks
- **MEASURE** — Analyze, assess, benchmark risks
- **MANAGE** — Prioritize and act on risks

**Status:** Foundational. Every agency uses this. AgentGuard maps here.

### NIST AI 600-1 — Generative AI Profile — ACTIVE (Jul 26, 2024)
**The most important AI security document in the federal ecosystem.**

**12 Risk Areas (memorize these):**
1. CBRN Information or Capabilities
2. Confabulation (hallucination)
3. Dangerous, Violent, or Hateful Content
4. Data Privacy
5. Environmental Impacts
6. Harmful Bias and Homogenization
7. Human-AI Configuration
8. Information Integrity
9. Information Security ← **AgentGuard's primary zone**
10. Intellectual Property
11. Obscene or Degrading Content
12. Value Chain and Component Integration ← **AgentGuard's primary zone**

**200+ suggested actions** organized by RMF function. **AgentGuard implements actions in Info Security and Value Chain.**

### NIST SP 800-53 Rev 5.2 — ACTIVE
Security and Privacy Controls for Information Systems. The control catalog every FedRAMP ATO maps to.

**AgentGuard-relevant controls:**
| Control | Name | AgentGuard Function |
|---------|------|---------------------|
| AC-3 | Access Enforcement | Tool allowlist/denylist |
| AC-4 | Information Flow Enforcement | Downstream tool call filtering |
| AC-6 | Least Privilege | Per-agent scopes |
| AC-7 | Unsuccessful Logon Attempts | Rate limiting |
| AC-17 | Remote Access | HTTP transport controls |
| AU-2 | Event Logging | All tool calls audited |
| AU-3 | Content of Audit Records | Structured event schema |
| AU-9 | Protection of Audit Information | Hash-chained SQLite |
| AU-10 | Non-repudiation | Ed25519 signatures |
| AU-12 | Audit Record Generation | Automatic per tool call |
| CM-7 | Least Functionality | Deny-by-default federal mode |
| IA-2 | Identification and Authentication | Agent identity extraction |
| IA-9 | Service Identification and Authentication | Upstream MCP server auth |
| SC-7 | Boundary Protection | Gateway architecture |
| SC-8 | Transmission Confidentiality | TLS/mTLS |
| SI-4 | System Monitoring | Detection alerts |
| SI-7 | Software Integrity | Tool poisoning detection |
| SI-10 | Information Input Validation | Prompt injection detection |
| SI-15 | Information Output Filtering | PII/secret leak detection |
| RA-5 | Vulnerability Monitoring | Threat feed integration |

### NIST SP 800-207 — Zero Trust Architecture — ACTIVE
Foundation for DoD ZT RA. AgentGuard enforces ZT principles at the agent tool-call layer.

### NIST SP 800-218 Rev 1 — SSDF v1.2 — DRAFT
Secure Software Development Framework. Mandated by EO 14028 for federal software suppliers. Draft v1.2 out, final expected 2026.

### NIST SP 800-218A — SSDF for AI — FINAL (2024)
**Specifically covers Gen AI and dual-use foundation models.** Adds AI-specific tasks to SSDF:
- Data poisoning detection
- Model evaluation for security
- Provenance tracking
- Inference-time monitoring

### NIST PQC Standards — FINAL (Aug 13, 2024)
- **FIPS 203** — ML-KEM (Module-Lattice-Based Key Encapsulation)
- **FIPS 204** — ML-DSA (Module-Lattice-Based Digital Signature)
- **FIPS 205** — SLH-DSA (Stateless Hash-Based Digital Signature)

**Federal deadlines (NIST IR 8547):**
- 2031: Deprecate 112-bit quantum-vulnerable algorithms
- 2035: Disallow 128-bit quantum-vulnerable algorithms

**NSS deadlines (NSA CNSA 2.0):**
- **Jan 1, 2027** — All new NSS acquisitions must be CNSA 2.0 compliant
- **Dec 31, 2025** — Existing NSS must meet CNSA 1.0 or request waiver
- **2033** — Final mandatory compliance

**AgentGuard future work:** Support PQC-compliant signing for audit log (post-ML-DSA v0.2).

### NIST IR 8547 — Transition to Post-Quantum Cryptography
Federal civilian migration timeline document. Use this for quoting federal PQC deadlines.

### NIST IR 8400 series — AI adversarial threats
Technical reports on adversarial ML. Feed these into AgentGuard's threat model.

### NIST Concept Note (Apr 7, 2026)
**"AI RMF Profile on Trustworthy AI in Critical Infrastructure"** — upcoming profile. Watch this space; critical infrastructure sector coverage will matter for federal/utility customers.

---

## PART 4 — FEDRAMP (AUTHORITY TO OPERATE)

### FedRAMP Rev 5 — CURRENT
Based on NIST 800-53 Rev 5. Three baselines (Low, Moderate, High) plus Tailored (LI-SaaS).

### FedRAMP 20x — TRANSITION (Live now, full rollout 2026-2027)
**New class structure (replacing baselines):**
- **Class A** — Pilot baseline (new)
- **Class B** — Covers current Li-SaaS and Low
- **Class C** — Covers current Moderate
- **Class D** — Covers current High (hyperscale IaaS/PaaS)

**Critical dates:**
- **March 18, 2026** (tentative) — All cloud services transitioned to new designation
- **Q3-Q4 2026** — Class B and C authorizations formalized
- **Q1-Q2 2027** — Class D pilot begins
- **Q1-Q2 2027** — All Rev 5 authorized providers must transition to **machine-readable authorization data** (OSCAL)

**AgentGuard play:** Position as FedRAMP 20x-ready, emit OSCAL outputs from day one.

### OSCAL — Open Security Controls Assessment Language
NIST machine-readable format for ATO documentation. Versions in use:
- OSCAL 1.0 — Foundation (2021)
- OSCAL 1.1 — Current (2023)
- OSCAL 1.1.2 — Latest patch (2024)

**Why it matters:** FedRAMP 20x requires OSCAL submission. ATO timelines compress from 18 months to weeks with OSCAL automation.

**AgentGuard output:** FedRAMP reports should emit OSCAL Component Definition JSON alongside human-readable Markdown.

---

## PART 5 — DOD SPECIFIC

### CMMC 2.0 — LIVE (Effective Dec 16, 2024)
**Cybersecurity Maturity Model Certification.**

**Three levels:**
- **Level 1** (FCI): 15 requirements from FAR 52.204-21. Self-assessment.
- **Level 2** (CUI): 110 requirements from NIST SP 800-171 Rev 2. Self-assessment OR C3PAO (third-party).
- **Level 3** (High-value CUI): Level 2 + 24 additional from NIST SP 800-172. DoD assessment only.

**Contract flow:**
- **Nov 10, 2025** — CMMC requirements appeared in new DoD contracts (live now)
- **Phase 1** — L1 (self), L2 (self), some L2 (C3PAO)
- Subsequent phases — expand to full C3PAO and DoD assessments

**Flow-down:** CMMC level flows to subcontractors that handle FCI or CUI.

**AgentGuard play:** Include CMMC Level 2 and Level 3 evidence generators as v0.2 feature. The 800-171 overlap with 800-53 makes this low-cost to add.

### DoD Zero Trust Reference Architecture v2.0 — CURRENT (July 2022)
Defines 7 pillars (User, Device, Application/Workload, Data, Network/Environment, Automation/Orchestration, Visibility/Analytics).

**91 capabilities/activities** required for DODIN ZT implementation.

### DoD Zero Trust Strategy 2.0 — PUBLISHING EARLY 2026
Expected to expand on 2022 doc, add weapons systems and defense critical infrastructure guidance.

### DoD AI Strategy — ONGOING
DoD wants "AI-enabled coding tools for tens of thousands of users in its developer workforce." Opportunities for AgentGuard in this space.

### DISA Impact Levels (IL)
Cloud security levels for DoD data:
- **IL2** — Public/non-CUI (AWS US-East, Azure Commercial)
- **IL4** — CUI unclassified (AWS GovCloud, Azure Government)
- **IL5** — CUI/NSS (AWS GovCloud, Azure Government higher)
- **IL6** — Secret (AWS Secret Region, Azure Gov Secret)

**AgentGuard play:** Design docs should specify IL4/IL5 deployment patterns.

### DoD 8140.03 — Cyber Workforce Framework — CURRENT (Feb 2023)
Replaces DoD 8570.01-M. Defines cyber workforce roles and qualifications.
- Formerly "IAT Level II" → now work roles + proficiency levels
- CySA+, PenTest+, Security+ all map
- **Terrell's certs are 8140.03 compliant** — call this out in resume/marketing

---

## PART 6 — AI-SPECIFIC ATTACK FRAMEWORKS

### OWASP Top 10 for LLM Applications 2025 — CURRENT
**Reorganized for production reality. The 2025 list:**

| Rank | ID | Vulnerability | AgentGuard Defense |
|------|----|-----------------------|-------------------|
| 1 | LLM01 | Prompt Injection | `detectors/prompt_injection.py` |
| 2 | LLM02 | Sensitive Information Disclosure | `detectors/pii.py`, `detectors/secrets.py` |
| 3 | LLM03 | Supply Chain Vulnerabilities | `detectors/tool_poisoning.py` |
| 4 | LLM04 | Data and Model Poisoning | Value Chain policies |
| 5 | LLM05 | Improper Output Handling | Response filtering |
| 6 | LLM06 | Excessive Agency | Tool allowlist + scopes |
| 7 | LLM07 | System Prompt Leakage (NEW) | Response scanning |
| 8 | LLM08 | Vector and Embedding Weaknesses (NEW) | Context hygiene policies |
| 9 | LLM09 | Misinformation | Output validators |
| 10 | LLM10 | Unbounded Consumption | Rate limiting (AC-7) |

### MITRE ATLAS — CURRENT (v5.4.0, Feb 2026)
Adversarial Threat Landscape for AI Systems. Now includes:
- **16 tactics** (added Command and Control AML.TA0015 in v5.1.0)
- **84 techniques** (18 new for AI agents in v5.1.0)
- **42 case studies**

**Agent-specific techniques (critical for AgentGuard):**
- AI Agent Context Poisoning
- Memory Manipulation
- Thread Injection
- Modify AI Agent Configuration
- Publish Poisoned AI Agent Tool (v5.4.0, Feb 2026)
- Escape to Host (v5.4.0, Feb 2026)

**AgentGuard mapping:** Every defense should cite both NIST 800-53 controls AND MITRE ATLAS technique IDs.

### Cloud Security Alliance — NIST AI RMF Agentic Profile
CSA Labs is drafting an Agentic Profile for NIST AI RMF. Watch for community input opportunities.

---

## PART 7 — INTERNATIONAL (FOR MULTINATIONAL FEDERAL CONTRACTORS)

### EU AI Act — ENFORCEMENT TIMELINE

| Date | Event |
|------|-------|
| Aug 2, 2025 | GPAI model providers' obligations effective |
| **Aug 2, 2026** | **European Commission enforcement begins** |
| Aug 2, 2027 | Pre-Aug 2, 2025 models must comply |

**Relevance:** Federal contractors with EU operations need ISO 42001 alignment.

### ISO/IEC 42001:2023 — AI Management System — CURRENT
First global AIMS standard. Maps to EU AI Act Articles 9-15:
- Article 9: Risk management
- Article 10: Data governance
- Article 11: Technical documentation
- Article 13: Transparency
- Article 14: Human oversight
- Article 15: Accuracy, robustness, cybersecurity

**AgentGuard play:** Position as ISO 42001 control implementation helper for AI systems.

---

## PART 8 — CISA & SECURE BY DESIGN

### CISA Secure by Design Pledge — ACTIVE
Voluntary pledge for software vendors. Seven goals including MFA, default secure configs, reduced default privileges, supply chain security. Signed by 250+ vendors.

**AgentGuard play:** Sign the pledge at v1.0.0 launch. Signals credibility.

### CISA SBOM — Software Bill of Materials
Required via EO 14028. Generate CycloneDX or SPDX SBOM for AgentGuard releases.

### CISA KEV Catalog — Known Exploited Vulnerabilities
Federal agencies must patch KEV items within defined timelines. Tie to vulnerability monitoring (RA-5).

---

## PART 9 — KEY ACRONYMS GLOSSARY

| Acronym | Full Name | Relevance |
|---------|-----------|-----------|
| AIMS | AI Management System | ISO 42001 |
| ATO | Authority to Operate | FedRAMP, federal |
| C3PAO | Certified Third Party Assessor Organization | CMMC |
| CNSA | Commercial National Security Algorithm | NSA PQC |
| CUI | Controlled Unclassified Information | DoD/federal |
| DFARS | Defense Federal Acquisition Regulation Supplement | DoD contracts |
| FCI | Federal Contract Information | CMMC L1 |
| FIPS | Federal Information Processing Standards | NIST mandatory |
| GPAI | General-Purpose AI | EU AI Act |
| KEV | Known Exploited Vulnerabilities | CISA |
| NSM | National Security Memorandum | White House |
| NSS | National Security Systems | DoD/IC |
| OSCAL | Open Security Controls Assessment Language | NIST machine-readable ATO |
| PQC | Post-Quantum Cryptography | NIST, NSA |
| POA&M | Plan of Action and Milestones | ATO remediation |
| SBOM | Software Bill of Materials | Supply chain |
| SSDF | Secure Software Development Framework | NIST 800-218 |
| SSP | System Security Plan | ATO core doc |

---

## PART 10 — AGENTGUARD STRATEGIC POSITIONING

Based on this research, AgentGuard's honest, defensible marketing claims are:

### ✅ Defensible Claims
- "Open-source MCP security gateway purpose-built for federal and defense AI deployments"
- "Native NIST 800-53 Rev 5 control mapping at the tool-call level"
- "NIST AI 600-1 Generative AI Profile alignment — information security and value chain risk areas"
- "OWASP LLM Top 10 (2025) defenses with MITRE ATLAS technique mapping"
- "FedRAMP 20x ready — emits OSCAL-compatible evidence"
- "CMMC 2.0 Level 2 and Level 3 evidence pack (v0.2 roadmap)"
- "Dual-mode design: transparent in development, rigorous in production"
- "Built by a cleared veteran with DoD 8140.03-compliant certifications (CySA+, PenTest+, Security+)"

### ❌ Claims to Avoid
- "First ever..." (false — mcp-firewall exists)
- "Complete solution" (always say "purpose-built component")
- "Eliminates" threats (say "mitigates" or "reduces")
- Reference EO 14110 as current (revoked)
- Claim FedRAMP certification without going through process

### 🎯 Target Buyer Personas
1. **Federal CIO/CISO** adopting AI under OMB M-25-21
2. **Defense prime contractors** needing CMMC 2.0 + AI risk coverage
3. **FedRAMP authorized CSPs** extending products with AI features
4. **Federal SIs** (Booz, Leidos, CACI, SAIC) building AI agents for clients

---

## PART 11 — IMMEDIATE UPDATES NEEDED IN AGENTGUARD CODEBASE

### Files requiring updates

1. **`agentguard/nist/controls_800_53.py`** — Add 800-53 Rev 5.2 metadata (version string), expand control library to include AC-4, CM-7, IA-9, SC-7, SI-7, SI-15, RA-5 (currently missing)
2. **`agentguard/nist/ai_rmf.py`** — Add NIST AI 600-1 Generative AI Profile integration, reference the 12 risk areas, map to GOVERN/MAP/MEASURE/MANAGE subcategories
3. **`agentguard/nist/mappings.py`** — Add OWASP LLM 2025 + MITRE ATLAS v5.4.0 technique ID mapping per event type
4. **`agentguard/nist/__init__.py`** — Export new modules
5. **NEW: `agentguard/nist/owasp_llm.py`** — OWASP LLM Top 10 2025 mapping
6. **NEW: `agentguard/nist/mitre_atlas.py`** — MITRE ATLAS v5.4.0 technique library
7. **NEW: `agentguard/nist/cmmc.py`** — CMMC 2.0 Level 1/2/3 requirement mapping (stub for v0.2)
8. **NEW: `agentguard/reports/oscal.py`** — OSCAL Component Definition emitter
9. **`docs/nist-mapping.md`** — Update with all frameworks from this brief
10. **`docs/threat-model.md`** — Incorporate MITRE ATLAS tactics
11. **`README.md`** — Update comparison table, add compliance badges for the frameworks we map to

### References to remove

- Any remaining reference to EO 14110 as active policy
- Any implication of "first" or "only" claims

---

## PART 12 — SOURCES & CITATIONS

Primary sources referenced in this brief:

**White House / OMB**
- [EO 14179 — Removing Barriers to American AI Leadership](https://www.whitehouse.gov/presidential-actions/2025/01/removing-barriers-to-american-leadership-in-artificial-intelligence/)
- [EO 14110 — Revoked AI Safety EO (Wikipedia)](https://en.wikipedia.org/wiki/Executive_Order_14110)
- [OMB M-25-21 — Accelerating Federal Use of AI](https://www.whitehouse.gov/wp-content/uploads/2025/02/M-25-21-Accelerating-Federal-Use-of-AI-through-Innovation-Governance-and-Public-Trust.pdf)
- [OMB M-25-22 — Driving Efficient AI Acquisition](https://www.whitehouse.gov/wp-content/uploads/2025/02/M-25-22-Driving-Efficient-Acquisition-of-Artificial-Intelligence-in-Government.pdf)
- [OMB M-23-02 — Migrating to PQC](https://www.whitehouse.gov/wp-content/uploads/2022/11/M-23-02-M-Memo-on-Migrating-to-Post-Quantum-Cryptography.pdf)
- [M-26-04 — Unbiased AI Principles (Dec 2025)](https://www.whitehouse.gov/wp-content/uploads/2025/12/M-26-04-Increasing-Public-Trust-in-Artificial-Intelligence-Through-Unbiased-AI-Principles-1.pdf)

**NIST**
- [AI Risk Management Framework](https://www.nist.gov/itl/ai-risk-management-framework)
- [NIST AI 600-1 Generative AI Profile](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.600-1.pdf)
- [NIST SP 800-218 SSDF](https://csrc.nist.gov/Projects/SSDF)
- [NIST SP 800-218A Gen AI SSDF](https://csrc.nist.gov/pubs/sp/800/218/a/final)
- [NIST PQC Project](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [FIPS 203 ML-KEM](https://csrc.nist.gov/pubs/fips/203/final)

**FedRAMP**
- [FedRAMP 20x RFC-0020](https://www.fedramp.gov/rfcs/0020/)
- [Rev5 Agency Authorization](https://www.fedramp.gov/rev5/agency-authorization/)
- [FedRAMP 20x Roadmap (Secureframe)](https://secureframe.com/blog/fedramp-20x-roadmap)

**DoD**
- [DoD Zero Trust Reference Architecture v2.0](https://dodcio.defense.gov/Portals/0/Documents/Library/(U)ZT_RA_v2.0(U)_Sep22.pdf)
- [DoD Zero Trust Strategy 2.0 (DefenseScoop)](https://defensescoop.com/2025/12/09/dod-zero-trust-strategy-2-0-expected-early-2026/)
- [CMMC Final Rule (DefenseScoop)](https://defensescoop.com/2024/12/16/final-rule-cmmc-cybersecurity-requirements-go-into-effect-defense-contractors/)

**AI Attack Frameworks**
- [OWASP Top 10 for LLM Apps 2025](https://genai.owasp.org/resource/owasp-top-10-for-llm-applications-2025/)
- [MITRE ATLAS](https://atlas.mitre.org/)

**International**
- [ISO/IEC 42001:2023](https://www.iso.org/standard/42001)
- [EU AI Act Enforcement Timeline](https://elevateconsult.com/insights/eu-ai-code-of-practice-iso-42001/)

---

**This research brief is the source of truth for AgentGuard compliance claims.**
**Last updated:** April 18, 2026. Review quarterly; federal policy shifts fast in 2026.
