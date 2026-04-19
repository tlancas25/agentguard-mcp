# AgentGuard MCP -- Handoff Document

**Last updated:** 2026-04-18 (post-hardening patch)
**Project phase:** MVP scaffold + research-backed NIST updates + federal-mode signing enforcement. Published: https://github.com/tlancas25/agentguard-mcp
**Current version:** 0.1.1

## Recent Commits

- `69d962c` test: remove stale pytest asyncio config warning (2026-04-18)
- `50ef894` Initial commit: AgentGuard MCP scaffold and hardening fixes (2026-04-18)

The hardening commit added:
- `tests/test_signing_requirements.py`: enforces federal mode cannot start without a valid Ed25519 signing key (ValueError at init)
- `tests/test_oscal_report.py`: validates OSCAL control extraction against both current (`events`) and legacy (`audit_events`) audit table names
- Fail-fast validation in `agentguard/server.py:StdioServer.__init__` and `agentguard/gateway.py:create_app` when federal mode is selected without signing material

---

## Read These First (in order)

1. `docs/research-brief-2026.md` : Source of truth for all compliance claims. Read in full before touching anything NIST/OWASP/ATLAS-related.
2. `CLAUDE.md` : Project-level AI pair-programming guidance.
3. `README.md` : Product-level description and comparison table.
4. `skills/agentguard/SKILL.md` : Behavioral guidelines for using AgentGuard as an MCP server.

---

## Project Status Snapshot

| Area | Status | Notes |
|------|--------|-------|
| Core proxy (stdio) | Complete | `agentguard/proxy.py` : primary transport |
| HTTP gateway | Stubbed | `agentguard/gateway.py` : v0.1 stub, stdio is primary |
| Policy engine | Complete | `agentguard/policy_engine.py` : dev mode logs, federal mode enforces deny-by-default |
| Dual-mode config | Complete | `agentguard/modes.py`, `agentguard/config.py` |
| Hash-chained audit log | Complete | `agentguard/audit_log.py` |
| Ed25519 signing | Complete + hardened | Optional in dev, startup-enforced in federal (`agentguard/server.py:StdioServer.__init__`, `agentguard/gateway.py:create_app`); ValueError on missing/invalid key |
| Detectors | Complete | prompt_injection, pii, secrets, tool_poisoning |
| NIST 800-53 Rev 5.2 controls | Complete | 20 controls in `agentguard/nist/controls_800_53.py` |
| NIST AI RMF 1.0 mapping | Complete | `agentguard/nist/ai_rmf.py` |
| NIST AI 600-1 (12 risk areas) | Complete | Added to `agentguard/nist/ai_rmf.py` |
| OWASP LLM Top 10 2025 | Complete | `agentguard/nist/owasp_llm.py` |
| MITRE ATLAS v5.4.0 | Complete | `agentguard/nist/mitre_atlas.py` |
| Multi-framework event mapping | Complete | `agentguard/nist/mappings.py:EVENT_FRAMEWORK_MAP` |
| CMMC 2.0 scaffold | Complete (stub) | `agentguard/nist/cmmc.py` : 30 representative requirements |
| OSCAL 1.1.2 emitter | Complete | `agentguard/reports/oscal.py` |
| PQC readiness assessment | Complete (stub) | `agentguard/nist/pqc.py` |
| FedRAMP evidence report | Complete | `agentguard/reports/fedramp.py` |
| NIST AI RMF report | Complete | `agentguard/reports/nist_ai_rmf.py` |
| POA&M report | Complete | `agentguard/reports/poam.py` |
| CLI | Complete | `agentguard/cli.py` |
| POA&M CLI subcommand | Deferred | Report class exists; CLI wiring deferred |
| OPA/Rego policy engine | Planned v0.2 | YAML-only in v0.1 |
| Hard rate limits | Planned v0.2 | AC-7 logging only in v0.1 |
| DoD PKI/CAC auth | Planned v0.2 | IA-2 is lightweight only |
| PQC audit signing (ML-DSA) | Planned v0.3 | Ed25519 in v0.1 |
| React dashboard | Not planned | Stay CLI-first; competitors have dashboards |
| PyPI package | Planned v0.2 | Repo is live; needs release workflow tag-trigger verification |
| Repo description + topics on GitHub | TODO | Currently empty on github.com/tlancas25/agentguard-mcp |

---

## Architecture in One Paragraph

AgentGuard is a transparent MCP proxy that sits between an AI agent client (Claude Code, Cursor, OpenClaw) and one or more upstream MCP servers (filesystem, GitHub, databases). Every tool call crosses AgentGuard, which intercepts it, extracts agent identity, runs it through the detector stack (injection, PII, secrets, tool poisoning), evaluates it against a YAML policy, logs it to a hash-chained SQLite database, and then either forwards or denies it. Dev mode logs everything and blocks nothing, including denylist matches that are downgraded to log-only decisions in dev mode. Federal mode denies by default and enforces the full detector stack. The same binary, the same config format, the same audit log schema in both modes.

---

## What's Done (MVP v0.1.0)

- Core Python package (`agentguard/`) with proxy, policy engine, audit log, CLI, and identity extraction
- Dual-mode config (dev vs. federal) via YAML and environment variable
- Hash-chained SQLite audit log with optional Ed25519 signing
- Four detector modules: prompt injection, PII, secrets, tool poisoning
- NIST 800-53 Rev 5.2 control library (20 controls with code references)
- NIST AI RMF 1.0 function library (13 subcategories)
- NIST AI 600-1 Generative AI Profile (all 12 risk areas with AgentGuard coverage notes)
- OWASP LLM Top 10 2025 (all 10 entries with NIST controls and MITRE ATLAS citations)
- MITRE ATLAS v5.4.0 (8 AI-agent-critical techniques including new AML.T0066 and AML.T0067)
- Multi-framework event mapping (`FrameworkMapping` dataclass covering all four frameworks)
- CMMC 2.0 scaffold (30 representative requirements across Levels 1/2/3)
- OSCAL 1.1.2 Component Definition emitter for FedRAMP 20x submissions
- PQC readiness assessment with federal deadline constants (FIPS 203/204/205)
- FedRAMP evidence report, NIST AI RMF report, and POA&M report generators
- Karpathy plugin pattern (`.claude-plugin/`, `skills/agentguard/SKILL.md`, `.cursor/rules/`)
- Full documentation: `docs/nist-mapping.md`, `docs/threat-model.md`, `README.md`

---

## What's Stubbed / Not Done

- **HTTP upstream forwarding** : `agentguard/gateway.py` is stubbed for v0.1.0; stdio is the primary transport
- **POA&M CLI subcommand** : Report class exists in `agentguard/reports/poam.py`; CLI wiring is deferred
- **CMMC detailed requirements** : `agentguard/nist/cmmc.py` has 30 representative requirements; full 110+ Level 2 and 24 Level 3 requirements are v0.2 (TODO comments in file)
- **PQC audit log signing** : `agentguard/nist/pqc.py` has the assessment infrastructure; ML-DSA signing replaces Ed25519 in v0.3
- **OPA/Rego policy engine** : v0.2; YAML-only in v0.1
- **Hard rate limits** : v0.2; AC-7 control currently logs denial frequency only
- **DoD PKI/CAC authentication** : v0.2; IA-2 is lightweight session UUID only
- **Threat feed integration** : v0.2 for RA-5 (CISA KEV + MITRE ATLAS signature updates)
- **Policy file integrity checking** : v0.2 for SI-7 applied to YAML policy files at runtime

---

## Key Design Decisions (why we built it this way)

1. **Dual-mode default** : Dev mode must never break Terrell's daily Claude Code + OpenClaw workflow. Federal mode is opt-in via env var or CLI flag. A security tool that disrupts daily work gets disabled.

2. **SQLite audit log with hash chain** : Simple, portable, tamper-evident. No external database dependency. Scales to approximately 100K events before PostgreSQL migration makes sense. The hash chain means a compromised database is still detectable.

3. **Ed25519 signing optional in dev, required in federal** : Keeps dev ergonomics simple. Federal organizations need non-repudiation. Startup now fails fast in federal mode if a valid signing key is not configured. PQC migration (ML-DSA-65) is planned for v0.3 per NIST IR 8547 deadlines.

4. **Karpathy plugin pattern** : `.claude-plugin/`, `skills/agentguard/SKILL.md`, `.cursor/rules/agentguard.mdc` for IDE-native discovery. This makes AgentGuard visible to AI assistants as a skill, not just a subprocess.

5. **Python 3.11+ only** : Modern typing, structural pattern matching, `tomllib`. No backport complexity.

6. **YAML policy over OPA/Rego** : Lower barrier for federal operators who need to configure policies without learning a DSL. OPA/Rego integration is v0.2 for operators who need it.

7. **Framework-first data model** : Every audit event carries NIST control IDs. The `FrameworkMapping` dataclass in `mappings.py` provides multi-framework annotations (NIST 800-53, OWASP LLM, MITRE ATLAS, NIST AI 600-1) for every event type. This makes compliance reporting a query, not a manual exercise.

---

## Open Questions (decide before v0.2)

- Do we add an HTTP upstream proxy, or keep stdio-only for v0.1? (HTTP gateway stub exists but is not functional)
- Do we integrate OPA/Rego for policy DSL, or keep YAML-only? (mcp-firewall uses OPA; it is the main differentiator there)
- Should we build a React dashboard (competitors have one) or stay CLI-first? (CLI-first is the current decision; revisit at v0.2)
- Do we ship a PyPI package (`pip install agentguard-mcp`) AND a `uv`-friendly install? (Yes, once git is set up and CI/CD is in place)
- How do we handle the CMMC full 110-requirement expansion in v0.2? (One module vs. split by domain?)

---

## Daily Workflow for Claude Code Sessions

When starting work on this repo:

1. `cd C:\Users\relly\Documents\Projects\agentguard-mcp`
2. Read `HANDOFF.md` (this file)
3. Read `docs/research-brief-2026.md` if touching anything compliance-related
4. Check `CHANGELOG.md` for the last version
5. Before modifying NIST/OWASP/ATLAS mappings: confirm versions are still current (check the research brief's quarterly review trigger in Part 12)

---

## Maintenance Cadence (quarterly)

Every 90 days:

1. Re-run framework version checks: OWASP LLM, MITRE ATLAS, NIST AI RMF, OMB memos
2. Update `docs/research-brief-2026.md` with any deltas
3. Update version constants in `agentguard/nist/*.py` (`NIST_800_53_VERSION`, `OWASP_LLM_VERSION`, `MITRE_ATLAS_VERSION`, `NIST_AI_600_1_VERSION`)
4. Update `README.md` compliance badges
5. Bump `CHANGELOG.md`

Key things to watch quarterly:

- MITRE ATLAS new techniques (v5.4.0 added AML.T0066 and AML.T0067 in Feb 2026)
- OWASP LLM list updates (2025 added LLM07 and LLM08)
- OMB memos (M-25-21 and M-25-22 are live; watch for agency implementation guidance)
- NIST IR 8547 updates (PQC migration timeline)
- FedRAMP 20x class rollout dates (Class B/C formalized Q3-Q4 2026; Class D pilot Q1-Q2 2027)
- CSA Agentic Profile for NIST AI RMF (draft in progress as of April 2026)

---

## Contact

- Author: Terrell Lancaster
- GitHub: github.com/tlancas25
- LinkedIn: linkedin.com/in/tlancas
- Portfolio: terrell-lancaster.com

---

## Anti-AI-Detection Writing Rules (apply to all docs/README edits)

- No em dashes (replace with commas, colons, or periods)
- No "rule of three" adjective patterns ("fast, secure, and reliable" type constructions)
- No hype words: "revolutionary," "cutting-edge," "world-class," "first ever," "seamless"
- Tone: security-pro, concrete, no buzzword salad
- Every feature claim must reference the actual code file that implements it

---

## Terrell's Positioning (context for marketing/resume copy)

- Secret clearance eligible for reinstatement
- Certifications: CompTIA CySA+, PenTest+, Security+ (DoD 8140 IAT Level II / 8140.03 compliant)
- B.S. Cybersecurity and Information Assurance (WGU, 2026)
- MBA in IT Management in progress (expected December 2026)
- Pivoting from general software development toward AI security, governance, and GRC roles in federal and defense
- OpenClaw Context Saver (10 stars, 4 forks) is the current flagship OSS project
- AgentGuard MCP is positioned as the second flagship, demonstrating compliance depth

---

## Claims to NEVER Make

- "First ever" / "only" / "unique": competing projects exist: mcp-firewall, Docker MCP Gateway, Microsoft MCP Gateway, IBM ContextForge, MintMCP, LlamaFirewall, Agent Gateway, Obot MCP Gateway
- "FedRAMP certified": we map to controls; we have not been through a 3PAO assessment
- "CMMC certified" : same; evidence generation only, not self-certification
- "AI/ML model included" : detection is regex and heuristics; LLM-based detection is a pluggable stub, not bundled
- Reference EO 14110 as current policy : it was revoked January 20, 2025

---

## Known Competitors (for comparison tables)

- **mcp-firewall (ressl)** : open source, OPA/Rego policy engine, DORA/FINMA/SOC 2 focus, not NIST
- **Docker MCP Gateway** : container orchestration, enterprise observability, no federal compliance language
- **Microsoft MCP Gateway** : Kubernetes-native, Azure Entra ID, large community, no NIST mapping
- **IBM ContextForge** : federation and registry focus, no compliance mapping
- **MintMCP** : SaaS only, closed-source
- **LlamaFirewall (Meta)** : prompt injection defense, open source, no federal mapping
- **Agent Gateway (agentgateway.dev)** : A2A + MCP proxy, no compliance mapping
- **Obot MCP Gateway** : general purpose, no federal focus
