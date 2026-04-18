"""Tests for OSCAL control extraction from audit databases."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from agentguard.reports.oscal import _query_implemented_controls


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
    """OSCAL extraction should read the current audit table name: events."""
    db_path = tmp_path / "events.db"
    _seed_controls(db_path, "events", ["ZZ-1"])

    controls = _query_implemented_controls(db_path)
    assert "zz-1" in controls


def test_oscal_reads_controls_from_legacy_audit_events_table(tmp_path: Path) -> None:
    """OSCAL extraction should remain compatible with legacy audit_events tables."""
    db_path = tmp_path / "audit_events.db"
    _seed_controls(db_path, "audit_events", ["YY-2"])

    controls = _query_implemented_controls(db_path)
    assert "yy-2" in controls
