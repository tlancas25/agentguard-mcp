# Contributing to AgentGuard MCP

Thank you for your interest in contributing. AgentGuard is purpose-built for federal and defense AI governance, so contributions that strengthen compliance coverage, improve detection accuracy, or expand NIST control implementations are especially welcome.

---

## Getting Started

### Prerequisites

- Python 3.11 or 3.12
- `git`
- Familiarity with MCP (Model Context Protocol)
- Optional: background in NIST 800-53 / FedRAMP / CMMC

### Development Setup

```bash
git clone https://github.com/tlancas25/agentguard-mcp.git
cd agentguard-mcp
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

### Running Tests

```bash
pytest
```

### Linting and Type Checks

```bash
ruff check agentguard/ tests/
mypy agentguard/
bandit -r agentguard/
```

---

## What We Need Most

### 1. NIST Control Contributions

If you know NIST 800-53 Rev 5, help us expand coverage beyond the current 13 controls. Each new control needs:

- A `ControlDefinition` entry in `agentguard/nist/controls_800_53.py`
- A mapping in `agentguard/nist/mappings.py` linking it to an event type or detector
- A test in `tests/test_nist/test_controls.py`

### 2. Attack Pattern Submissions

New injection patterns, PII regex improvements, or secret detector rules are high-value contributions. See:

- `agentguard/detectors/prompt_injection.py`
- `agentguard/detectors/pii.py`
- `agentguard/detectors/secrets.py`
- `agentguard/detectors/tool_poisoning.py`

Reference sources: OWASP LLM Top 10, Palo Alto Unit 42 MCP research, Simon Willison's prompt injection catalog.

### 3. Policy Examples

Working policy YAML files for common federal use cases. See `examples/sample_policies/` for the format.

### 4. Integration Guides

Step-by-step guides for MCP clients we haven't documented yet. See `examples/` for the format.

---

## Contribution Guidelines

### Code Standards

- Python 3.11+ with type hints throughout
- `from __future__ import annotations` in all modules
- Docstrings on all public functions and classes
- All new code must pass `ruff`, `mypy`, and `bandit`
- Every new feature needs at least one test

### Commit Style

Use conventional commits:

```
feat: add CMMC 2.0 report generator
fix: correct PII regex false positive on phone numbers
docs: expand FedRAMP deployment guide
test: add injection pattern for indirect prompt injection
```

### Pull Request Checklist

- [ ] Tests pass (`pytest`)
- [ ] Linter passes (`ruff check`)
- [ ] Type checks pass (`mypy agentguard/`)
- [ ] Security scan passes (`bandit -r agentguard/`)
- [ ] NIST control claims in the PR are backed by code
- [ ] Dev mode is not broken (pass-through still works)
- [ ] Federal mode enforcement is not weakened

### NIST Precision Rule

Do not claim a NIST control is "implemented" unless the code actually enforces or logs the behavior the control requires. Inflated compliance claims undermine the project's credibility with federal auditors.

---

## Reporting Security Issues

Do not open a public issue for security vulnerabilities. Email: tlancas25@github.com with subject line `[AgentGuard Security]`.

---

## Code of Conduct

Be professional. This project serves federal and defense organizations where trust matters. Contributions that introduce vulnerabilities, weaken audit integrity, or make false compliance claims will be rejected.

---

## License

By contributing, you agree your contributions are licensed under the MIT License.
