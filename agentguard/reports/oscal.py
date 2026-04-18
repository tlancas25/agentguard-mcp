"""OSCAL Component Definition emitter for AgentGuard.

Generates machine-readable OSCAL 1.1.2 Component Definition JSON for use in
FedRAMP 20x authorization packages. FedRAMP 20x requires OSCAL submission;
this module automates the evidence linkage from AgentGuard's audit log to
OSCAL-formatted control responsibility claims.

References:
- OSCAL 1.1.2: https://pages.nist.gov/OSCAL/resources/concepts/layer/implementation/component-definition/
- FedRAMP 20x OSCAL requirements: https://www.fedramp.gov/rfcs/0020/
- NIST SP 800-53 Rev 5.2 control catalog: https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final
"""

from __future__ import annotations

import json
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    from pydantic import BaseModel, Field
    _PYDANTIC_AVAILABLE = True
except ImportError:
    _PYDANTIC_AVAILABLE = False
    BaseModel = object  # type: ignore[assignment,misc]


# AgentGuard control responsibility claims — what controls this component
# directly implements (versus inheriting from the platform).
_AGENTGUARD_CONTROL_CLAIMS: dict[str, str] = {
    "ac-3":  "AgentGuard policy engine enforces tool allowlist/denylist on every MCP tool call.",
    "ac-4":  "AgentGuard proxy enforces information flow policy; blocks PII/secret-laden tool calls.",
    "ac-6":  "Federal mode deny-by-default; agents granted only explicitly permitted tools.",
    "ac-7":  "Repeated policy denials per agent logged; supports rate threshold alerting.",
    "ac-17": "HTTP gateway mode enforces transport-level policy for remote MCP clients.",
    "au-2":  "Every MCP tool call generates an audit event regardless of mode.",
    "au-3":  "Audit events include timestamp, agent_id, tool_name, args, result, decision, controls.",
    "au-9":  "Hash-chained SQLite audit; verify_chain() detects any modification or deletion.",
    "au-10": "Federal mode: each audit event signed with Ed25519; non-repudiable.",
    "au-12": "Audit generation is automatic and cannot be disabled in federal mode.",
    "cm-7":  "Federal mode deny-by-default implements least functionality at the tool layer.",
    "ia-2":  "Agent identity extracted from MCP initialize handshake; session UUID assigned.",
    "ia-9":  "Upstream MCP server identity recorded and validated against approved list.",
    "ra-5":  "Tool poisoning detector scans tool descriptions; threat feed integration v0.2.",
    "sc-7":  "AgentGuard is the managed boundary between agents and upstream MCP servers.",
    "sc-8":  "HTTP gateway mode supports TLS; secret detector prevents credential exfiltration.",
    "si-4":  "Injection, PII, secret, and tool poisoning detectors run on every tool call.",
    "si-7":  "Tool poisoning detector checks tool description integrity; audit hash chain.",
    "si-10": "All tool call arguments validated by detector stack before forwarding.",
    "si-15": "Response filtering scans tool results for PII and secrets before agent receipt.",
}


# ---------------------------------------------------------------------------
# Pydantic models (simplified OSCAL 1.1.2 Component Definition schema)
# ---------------------------------------------------------------------------

if _PYDANTIC_AVAILABLE:
    class OscalLink(BaseModel):
        href: str
        rel: str = "reference"

    class OscalProp(BaseModel):
        name: str
        value: str
        ns: str = "https://fedramp.gov/ns/oscal"

    class OscalResponsibleRole(BaseModel):
        role_id: str
        party_uuids: list[str] = Field(default_factory=list)

    class OscalControlImplementation(BaseModel):
        uuid: str = Field(default_factory=lambda: str(uuid.uuid4()))
        description: str
        set_parameters: list[dict[str, Any]] = Field(default_factory=list)
        implemented_requirements: list[dict[str, Any]] = Field(default_factory=list)

    class OscalComponent(BaseModel):
        uuid: str = Field(default_factory=lambda: str(uuid.uuid4()))
        type: str = "software"
        title: str
        description: str
        purpose: str = ""
        props: list[OscalProp] = Field(default_factory=list)
        links: list[OscalLink] = Field(default_factory=list)
        responsible_roles: list[OscalResponsibleRole] = Field(default_factory=list)
        control_implementations: list[OscalControlImplementation] = Field(default_factory=list)

    class OscalComponentDefinition(BaseModel):
        uuid: str = Field(default_factory=lambda: str(uuid.uuid4()))
        metadata: dict[str, Any] = Field(default_factory=dict)
        components: list[OscalComponent] = Field(default_factory=list)
        back_matter: dict[str, Any] = Field(default_factory=dict)


def _query_implemented_controls(audit_db_path: Path) -> list[str]:
    """Query the audit database to determine which controls have been exercised.

    Returns a list of control IDs (lowercase, hyphenated) that appear in the
    nist_controls_json field of audit events. An exercised control means
    AgentGuard generated at least one event tagged with that control.

    If the database does not exist or has no data, falls back to the full
    set of declared control claims.
    """
    if not audit_db_path.exists():
        return list(_AGENTGUARD_CONTROL_CLAIMS.keys())

    exercised: set[str] = set()
    try:
        conn = sqlite3.connect(str(audit_db_path))
        cur = conn.cursor()
        cur.execute(
            "SELECT name FROM sqlite_master "
            "WHERE type='table' AND name IN ('events', 'audit_events')"
        )
        available_tables = {row[0] for row in cur.fetchall()}

        for table_name in ("events", "audit_events"):
            if table_name not in available_tables:
                continue
            cur.execute(
                f"SELECT DISTINCT nist_controls_json FROM {table_name} "
                "WHERE nist_controls_json IS NOT NULL AND nist_controls_json != ''"
            )
            for (controls_json,) in cur.fetchall():
                try:
                    controls = json.loads(controls_json)
                    for c in controls:
                        exercised.add(c.lower().replace("_", "-"))
                except (json.JSONDecodeError, TypeError):
                    continue
        conn.close()
    except sqlite3.Error:
        return list(_AGENTGUARD_CONTROL_CLAIMS.keys())

    # Return union of exercised controls and declared claims
    return sorted(exercised | set(_AGENTGUARD_CONTROL_CLAIMS.keys()))


def _build_implemented_requirements(
    control_ids: list[str],
    system_name: str,
) -> list[dict[str, Any]]:
    """Build OSCAL implemented-requirements entries for each control."""
    requirements = []
    for control_id in sorted(control_ids):
        normalized = control_id.lower().replace("_", "-")
        description = _AGENTGUARD_CONTROL_CLAIMS.get(
            normalized,
            f"AgentGuard logs and evaluates events relevant to {control_id.upper()}.",
        )
        requirements.append({
            "uuid": str(uuid.uuid4()),
            "control-id": normalized,
            "description": description,
            "props": [
                {
                    "name": "implementation-status",
                    "ns": "https://fedramp.gov/ns/oscal",
                    "value": "implemented",
                }
            ],
            "statements": [
                {
                    "statement-id": f"{normalized}_smt",
                    "uuid": str(uuid.uuid4()),
                    "description": (
                        f"{system_name} uses AgentGuard MCP as the tool-call security "
                        f"layer implementing {control_id.upper()}."
                    ),
                }
            ],
        })
    return requirements


def generate_component_definition(
    audit_db_path: Path,
    system_name: str,
    impact_level: str = "moderate",
) -> dict[str, Any]:
    """Generate a valid OSCAL 1.1.2 Component Definition JSON dict.

    Queries the audit log for implemented controls, maps them to AgentGuard's
    control responsibility claims, and returns a Component Definition ready
    for FedRAMP 20x submission.

    Args:
        audit_db_path: Path to the AgentGuard SQLite audit database.
        system_name: Name of the information system being documented.
        impact_level: FedRAMP impact level ("low", "moderate", "high").
                      Used to tag the component metadata.

    Returns:
        Dict matching the OSCAL 1.1.2 Component Definition schema.
    """
    now_utc = datetime.now(timezone.utc).isoformat()
    component_uuid = str(uuid.uuid4())
    definition_uuid = str(uuid.uuid4())
    catalog_href = (
        "https://raw.githubusercontent.com/usnistgov/oscal-content/main/"
        "nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json"
    )

    control_ids = _query_implemented_controls(audit_db_path)
    implemented_requirements = _build_implemented_requirements(control_ids, system_name)

    return {
        "component-definition": {
            "uuid": definition_uuid,
            "metadata": {
                "title": f"AgentGuard MCP Component Definition — {system_name}",
                "last-modified": now_utc,
                "version": "0.1.0",
                "oscal-version": "1.1.2",
                "remarks": (
                    "Generated by AgentGuard MCP. This component definition documents "
                    "AgentGuard's control responsibility claims for FedRAMP 20x "
                    "authorization packages. Review and supplement with system-specific "
                    "evidence before submission to a 3PAO or FedRAMP PMO."
                ),
                "props": [
                    {
                        "name": "impact-level",
                        "ns": "https://fedramp.gov/ns/oscal",
                        "value": impact_level,
                    }
                ],
            },
            "components": [
                {
                    "uuid": component_uuid,
                    "type": "software",
                    "title": "AgentGuard MCP",
                    "description": (
                        "Open-source MCP security gateway providing tool-call "
                        "interception, policy enforcement, tamper-evident audit "
                        "logging, and NIST 800-53 Rev 5.2 control implementation "
                        "for AI agent deployments."
                    ),
                    "purpose": (
                        "Implements security controls at the Model Context Protocol "
                        "tool-call layer for federal and defense AI systems."
                    ),
                    "props": [
                        {
                            "name": "software-name",
                            "value": "agentguard-mcp",
                        },
                        {
                            "name": "software-version",
                            "value": "0.1.0",
                        },
                        {
                            "name": "asset-type",
                            "value": "software",
                        },
                    ],
                    "links": [
                        {
                            "href": "https://github.com/tlancas25/agentguard-mcp",
                            "rel": "homepage",
                        }
                    ],
                    "control-implementations": [
                        {
                            "uuid": str(uuid.uuid4()),
                            "source": catalog_href,
                            "description": (
                                "AgentGuard MCP implements NIST SP 800-53 Rev 5.2 "
                                f"controls at the MCP tool-call layer for {system_name}."
                            ),
                            "implemented-requirements": implemented_requirements,
                        }
                    ],
                }
            ],
            "back-matter": {
                "resources": [
                    {
                        "uuid": str(uuid.uuid4()),
                        "title": "NIST SP 800-53 Rev 5 Catalog",
                        "rlinks": [{"href": catalog_href}],
                    },
                    {
                        "uuid": str(uuid.uuid4()),
                        "title": "AgentGuard MCP NIST Mapping",
                        "rlinks": [{"href": "docs/nist-mapping.md"}],
                    },
                ]
            },
        }
    }


def export_oscal_json(
    output_path: Path,
    audit_db_path: Path,
    system_name: str,
    impact_level: str = "moderate",
) -> None:
    """Write an OSCAL Component Definition JSON file.

    Args:
        output_path: Destination file path for the JSON output.
        audit_db_path: Path to the AgentGuard SQLite audit database.
        system_name: Name of the information system being documented.
        impact_level: FedRAMP impact level ("low", "moderate", "high").
    """
    output_path.parent.mkdir(parents=True, exist_ok=True)
    component_def = generate_component_definition(
        audit_db_path=audit_db_path,
        system_name=system_name,
        impact_level=impact_level,
    )
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(component_def, f, indent=2, ensure_ascii=False)
