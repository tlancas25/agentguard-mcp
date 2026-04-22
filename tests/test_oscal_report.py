"""Tests for OSCAL control extraction from audit databases."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from agentguard.reports.oscal import _collect_audit_evidence


def _seed_controls(db_path: Path, table_name: str, controls: list[str]) -> None:
    """Create a minimal table and insert one nist_controls_json row."""
    conn = sqlite3.connect(str(db_path))
    conn.execute(f"CREATE TABLE {table_name} (nist_controls_json TEXT)")
    conn.execute(
        f"INSERT INTO {table_name} (nist_controls_json) VALUES (?)",
        (json.dumps(controls),),
    )
    conn.commit()
    conn.close()


def test_oscal_reads_controls_from_events_table(tmp_path: Path) -> None:
    """OSCAL evidence collection reads the current audit table name: events."""
    db_path = tmp_path / "events.db"
    _seed_controls(db_path, "events", ["ZZ-1"])

    evidence = _collect_audit_evidence(db_path)
    assert evidence["db_exists"] is True
    assert evidence["control_counts"].get("zz-1") == 1


def test_oscal_reads_controls_from_legacy_audit_events_table(tmp_path: Path) -> None:
    """OSCAL evidence collection stays compatible with legacy audit_events tables."""
    db_path = tmp_path / "audit_events.db"
    _seed_controls(db_path, "audit_events", ["YY-2"])

    evidence = _collect_audit_evidence(db_path)
    assert evidence["db_exists"] is True
    assert evidence["control_counts"].get("yy-2") == 1
