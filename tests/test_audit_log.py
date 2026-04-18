"""Tests for the AgentGuard audit log hash chain.

Covers:
- Basic event appending
- Hash chain integrity verification
- Tamper detection (modification, deletion, insertion)
- Ed25519 signing
- Export (JSONL, CSV)
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from agentguard.audit_log import AuditEvent, AuditLog, GENESIS_HASH, generate_signing_keypair


class TestAuditLogBasics:
    """Basic audit log operations."""

    def test_empty_log_verifies(self, audit_log: AuditLog) -> None:
        """An empty log should verify as valid."""
        valid, msg = audit_log.verify_chain()
        assert valid
        assert "empty" in msg.lower()

    def test_append_event(self, audit_log: AuditLog) -> None:
        """Events can be appended and retrieved."""
        event = AuditEvent(
            agent_id="test-agent:session-1",
            event_type="tool_call",
            tool_name="read_file",
            tool_args={"path": "/tmp/test.txt"},
            decision="logged",
            nist_controls=["AU-2"],
        )
        row_id = audit_log.append_event(event)
        assert row_id > 0
        assert audit_log.count() == 1

    def test_multiple_events(self, audit_log: AuditLog) -> None:
        """Multiple events are stored in order."""
        for i in range(5):
            audit_log.append_event(
                AuditEvent(
                    agent_id="agent:session-1",
                    event_type="tool_call",
                    tool_name=f"tool_{i}",
                    decision="logged",
                )
            )
        assert audit_log.count() == 5

    def test_tail_returns_recent(self, audit_log: AuditLog) -> None:
        """tail() returns the most recent events in order."""
        for i in range(10):
            audit_log.append_event(
                AuditEvent(
                    agent_id="agent:session-1",
                    event_type="tool_call",
                    tool_name=f"tool_{i}",
                    decision="logged",
                )
            )
        tail = audit_log.tail(n=5)
        assert len(tail) == 5
        # Should be ordered oldest to newest in tail()
        names = [e["tool_name"] for e in tail]
        assert "tool_9" in names


class TestHashChainIntegrity:
    """Hash chain correctness and tamper detection tests."""

    def test_single_event_chain_valid(self, audit_log: AuditLog) -> None:
        """A single event produces a valid chain."""
        audit_log.append_event(
            AuditEvent(agent_id="agent:s1", event_type="tool_call", decision="logged")
        )
        valid, _ = audit_log.verify_chain()
        assert valid

    def test_ten_events_chain_valid(self, audit_log: AuditLog) -> None:
        """Ten events produce a valid chain."""
        for _ in range(10):
            audit_log.append_event(
                AuditEvent(agent_id="agent:s1", event_type="tool_call", decision="logged")
            )
        valid, msg = audit_log.verify_chain()
        assert valid, msg

    def test_tamper_detection_modified_event(self, tmp_db: Path) -> None:
        """Modifying an event breaks the chain."""
        log = AuditLog(db_path=tmp_db)
        for _ in range(3):
            log.append_event(
                AuditEvent(agent_id="agent:s1", event_type="tool_call", decision="logged")
            )

        # Directly modify the database
        conn = sqlite3.connect(str(tmp_db))
        conn.execute("UPDATE events SET agent_id='tampered' WHERE id=2")
        conn.commit()
        conn.close()

        valid, msg = log.verify_chain()
        assert not valid
        assert "tampered" in msg.lower() or "mismatch" in msg.lower()

    def test_tamper_detection_deleted_event(self, tmp_db: Path) -> None:
        """Deleting an event from the middle breaks the chain."""
        log = AuditLog(db_path=tmp_db)
        for _ in range(5):
            log.append_event(
                AuditEvent(agent_id="agent:s1", event_type="tool_call", decision="logged")
            )

        conn = sqlite3.connect(str(tmp_db))
        conn.execute("DELETE FROM events WHERE id=3")
        conn.commit()
        conn.close()

        valid, msg = log.verify_chain()
        assert not valid

    def test_prev_hash_chain(self, audit_log: AuditLog) -> None:
        """Each event's prev_hash matches the previous event's event_hash."""
        for _ in range(3):
            audit_log.append_event(
                AuditEvent(agent_id="agent:s1", event_type="tool_call", decision="logged")
            )

        events = audit_log.tail(n=10)
        assert events[0]["prev_hash"] == GENESIS_HASH
        assert events[1]["prev_hash"] == events[0]["event_hash"]
        assert events[2]["prev_hash"] == events[1]["event_hash"]


class TestSigning:
    """Ed25519 signing tests."""

    def test_generate_keypair(self) -> None:
        """Keypair generation returns two non-empty base64 strings."""
        private_b64, public_b64 = generate_signing_keypair()
        assert len(private_b64) > 0
        assert len(public_b64) > 0

    def test_signed_events_have_signature(self, audit_log_with_signing: AuditLog) -> None:
        """Events are signed when a signing key is configured."""
        audit_log_with_signing.append_event(
            AuditEvent(agent_id="agent:s1", event_type="tool_call", decision="logged")
        )
        events = audit_log_with_signing.tail(n=1)
        assert events[0]["signature"] is not None
        assert len(events[0]["signature"]) > 0

    def test_unsigned_events_have_null_signature(self, audit_log: AuditLog) -> None:
        """Events have no signature when signing is not configured."""
        audit_log.append_event(
            AuditEvent(agent_id="agent:s1", event_type="tool_call", decision="logged")
        )
        events = audit_log.tail(n=1)
        assert events[0]["signature"] is None

    def test_signed_chain_verifies(self, audit_log_with_signing: AuditLog) -> None:
        """Signed events still form a valid hash chain."""
        for _ in range(5):
            audit_log_with_signing.append_event(
                AuditEvent(agent_id="agent:s1", event_type="tool_call", decision="logged")
            )
        valid, msg = audit_log_with_signing.verify_chain()
        assert valid, msg


class TestExport:
    """Audit log export tests."""

    def test_export_jsonl(self, audit_log: AuditLog, tmp_path: Path) -> None:
        """JSONL export writes one JSON object per line."""
        for i in range(5):
            audit_log.append_event(
                AuditEvent(agent_id="agent:s1", event_type="tool_call", tool_name=f"t{i}", decision="logged")
            )
        out = tmp_path / "export.jsonl"
        count = audit_log.export_jsonl(out)
        assert count == 5
        lines = out.read_text().strip().split("\n")
        assert len(lines) == 5
        first = json.loads(lines[0])
        assert "event_hash" in first

    def test_export_csv(self, audit_log: AuditLog, tmp_path: Path) -> None:
        """CSV export writes a header row plus data rows."""
        for _ in range(3):
            audit_log.append_event(
                AuditEvent(agent_id="agent:s1", event_type="tool_call", decision="logged")
            )
        out = tmp_path / "export.csv"
        count = audit_log.export_csv(out)
        assert count == 3
        lines = out.read_text().strip().split("\n")
        assert len(lines) == 4  # header + 3 data rows
        assert "event_hash" in lines[0]
