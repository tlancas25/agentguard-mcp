"""Hash-chained, tamper-evident audit log for AgentGuard.

Implements NIST 800-53 Rev 5 controls:
- AU-2: Event Logging (every tool call is recorded)
- AU-3: Content of Audit Records (full event data in each record)
- AU-9: Protection of Audit Information (hash chain detects tampering)
- AU-10: Non-repudiation (Ed25519 signatures tie events to agent identity)
- AU-12: Audit Record Generation (automatic, cannot be disabled in federal mode)
"""

from __future__ import annotations

import hashlib
import json
import logging
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Generator, Optional

logger = logging.getLogger(__name__)

GENESIS_HASH = "0" * 64  # SHA-256 of nothing — the chain anchor


class AuditEvent:
    """A single audit log event."""

    def __init__(
        self,
        agent_id: str,
        event_type: str,
        tool_name: Optional[str] = None,
        tool_args: Optional[dict[str, Any]] = None,
        tool_result: Optional[Any] = None,
        decision: str = "logged",
        policy_matched: Optional[str] = None,
        nist_controls: Optional[list[str]] = None,
    ) -> None:
        """Initialize an audit event."""
        self.agent_id = agent_id
        self.event_type = event_type
        self.tool_name = tool_name
        self.tool_args = tool_args or {}
        self.tool_result = tool_result
        self.decision = decision
        self.policy_matched = policy_matched
        self.nist_controls = nist_controls or []
        self.timestamp = datetime.now(timezone.utc).isoformat()

    def canonical_fields(self) -> dict[str, Any]:
        """Return the fields that are included in the event hash."""
        return {
            "timestamp": self.timestamp,
            "agent_id": self.agent_id,
            "event_type": self.event_type,
            "tool_name": self.tool_name,
            "tool_args_json": json.dumps(self.tool_args, sort_keys=True),
            "decision": self.decision,
            "policy_matched": self.policy_matched,
            "nist_controls_json": json.dumps(sorted(self.nist_controls)),
        }


class AuditLog:
    """SQLite-backed hash-chained audit log.

    The hash chain is maintained by including the previous event's hash in
    each new event's hash computation. This means any modification, deletion,
    or insertion of events will break the chain and be detected by verify_chain().
    """

    def __init__(self, db_path: Path, signing_key: Optional[str] = None) -> None:
        """Initialize the audit log.

        Args:
            db_path: Path to the SQLite database file.
            signing_key: Base64-encoded Ed25519 private key for event signing.
                         If None, events are not signed.
        """
        self.db_path = db_path
        self._signing_key = signing_key
        self._signer: Optional[Any] = None

        if signing_key:
            self._init_signer(signing_key)

        self._init_db()

    def _init_signer(self, signing_key_b64: str) -> None:
        """Initialize the Ed25519 signer from a base64-encoded private key."""
        try:
            import base64
            from cryptography.hazmat.primitives.asymmetric.ed25519 import (
                Ed25519PrivateKey,
            )
            from cryptography.hazmat.primitives.serialization import (
                Encoding,
                PrivateFormat,
                NoEncryption,
                load_der_private_key,
            )

            key_bytes = base64.b64decode(signing_key_b64)
            self._signer = Ed25519PrivateKey.from_private_bytes(key_bytes)
        except Exception as e:
            logger.warning("Failed to initialize signing key: %s. Events will not be signed.", e)
            self._signer = None

    def _sign(self, data: str) -> Optional[str]:
        """Sign data with Ed25519 and return base64-encoded signature."""
        if self._signer is None:
            return None
        try:
            import base64
            sig = self._signer.sign(data.encode())
            return base64.b64encode(sig).decode()
        except Exception as e:
            logger.warning("Failed to sign audit event: %s", e)
            return None

    @property
    def signing_enabled(self) -> bool:
        """Return True if a valid signing key is loaded and usable."""
        return self._signer is not None

    @contextmanager
    def _connection(self) -> Generator[sqlite3.Connection, None, None]:
        """Yield a database connection with WAL mode enabled."""
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _init_db(self) -> None:
        """Create the events table if it does not exist."""
        with self._connection() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    agent_id TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    tool_name TEXT,
                    tool_args_json TEXT,
                    tool_result_json TEXT,
                    decision TEXT,
                    policy_matched TEXT,
                    nist_controls_json TEXT,
                    prev_hash TEXT NOT NULL,
                    event_hash TEXT NOT NULL,
                    signature TEXT
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_events_agent_id ON events(agent_id)
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp)
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_events_event_type ON events(event_type)
            """)

    def _get_last_hash(self, conn: sqlite3.Connection) -> str:
        """Return the hash of the most recent event, or the genesis hash."""
        row = conn.execute(
            "SELECT event_hash FROM events ORDER BY id DESC LIMIT 1"
        ).fetchone()
        return row["event_hash"] if row else GENESIS_HASH

    @staticmethod
    def _compute_hash(prev_hash: str, canonical: dict[str, Any]) -> str:
        """Compute the SHA-256 hash for an event."""
        payload = prev_hash + json.dumps(canonical, sort_keys=True)
        return hashlib.sha256(payload.encode()).hexdigest()

    def append_event(self, event: AuditEvent) -> int:
        """Append an event to the audit log and return its row ID.

        Thread-safe via SQLite WAL mode. The event hash is computed as:
        SHA-256(prev_hash + canonical_json(event_fields))
        """
        with self._connection() as conn:
            prev_hash = self._get_last_hash(conn)
            canonical = event.canonical_fields()
            event_hash = self._compute_hash(prev_hash, canonical)
            signature = self._sign(event_hash)

            tool_result_json: Optional[str] = None
            if event.tool_result is not None:
                try:
                    tool_result_json = json.dumps(event.tool_result)
                except (TypeError, ValueError):
                    tool_result_json = str(event.tool_result)

            cursor = conn.execute(
                """
                INSERT INTO events (
                    timestamp, agent_id, event_type, tool_name, tool_args_json,
                    tool_result_json, decision, policy_matched, nist_controls_json,
                    prev_hash, event_hash, signature
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event.timestamp,
                    event.agent_id,
                    event.event_type,
                    event.tool_name,
                    json.dumps(event.tool_args, sort_keys=True),
                    tool_result_json,
                    event.decision,
                    event.policy_matched,
                    json.dumps(sorted(event.nist_controls)),
                    prev_hash,
                    event_hash,
                    signature,
                ),
            )
            return cursor.lastrowid or 0

    def verify_chain(self) -> tuple[bool, str]:
        """Verify the hash chain integrity of the entire audit log.

        Returns:
            Tuple of (is_valid, message). If invalid, message describes the break.
        """
        with self._connection() as conn:
            rows = conn.execute(
                "SELECT * FROM events ORDER BY id ASC"
            ).fetchall()

        if not rows:
            return True, "Audit log is empty."

        prev_hash = GENESIS_HASH
        for row in rows:
            canonical = {
                "timestamp": row["timestamp"],
                "agent_id": row["agent_id"],
                "event_type": row["event_type"],
                "tool_name": row["tool_name"],
                "tool_args_json": row["tool_args_json"],
                "decision": row["decision"],
                "policy_matched": row["policy_matched"],
                "nist_controls_json": row["nist_controls_json"],
            }
            expected_hash = self._compute_hash(prev_hash, canonical)

            if row["prev_hash"] != prev_hash:
                return (
                    False,
                    f"Chain break at event id={row['id']}: "
                    f"stored prev_hash does not match actual previous hash.",
                )
            if row["event_hash"] != expected_hash:
                return (
                    False,
                    f"Hash mismatch at event id={row['id']}: "
                    f"event has been tampered with.",
                )
            prev_hash = row["event_hash"]

        return True, f"Chain verified. {len(rows)} events intact."

    def tail(self, n: int = 20) -> list[dict[str, Any]]:
        """Return the most recent n audit events as dicts."""
        with self._connection() as conn:
            rows = conn.execute(
                "SELECT * FROM events ORDER BY id DESC LIMIT ?", (n,)
            ).fetchall()
        return [dict(row) for row in reversed(rows)]

    def query(
        self,
        agent_id: Optional[str] = None,
        event_type: Optional[str] = None,
        decision: Optional[str] = None,
        limit: int = 500,
    ) -> list[dict[str, Any]]:
        """Query audit events with optional filters."""
        clauses: list[str] = []
        params: list[Any] = []

        if agent_id:
            clauses.append("agent_id = ?")
            params.append(agent_id)
        if event_type:
            clauses.append("event_type = ?")
            params.append(event_type)
        if decision:
            clauses.append("decision = ?")
            params.append(decision)

        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        params.append(limit)

        with self._connection() as conn:
            rows = conn.execute(
                f"SELECT * FROM events {where} ORDER BY id DESC LIMIT ?",
                params,
            ).fetchall()
        return [dict(row) for row in rows]

    def export_jsonl(self, output_path: Path) -> int:
        """Export all audit events as JSONL. Returns number of records written."""
        with self._connection() as conn:
            rows = conn.execute("SELECT * FROM events ORDER BY id ASC").fetchall()

        with open(output_path, "w") as f:
            for row in rows:
                f.write(json.dumps(dict(row)) + "\n")

        return len(rows)

    def export_csv(self, output_path: Path) -> int:
        """Export all audit events as CSV. Returns number of records written."""
        import csv

        with self._connection() as conn:
            rows = conn.execute("SELECT * FROM events ORDER BY id ASC").fetchall()

        if not rows:
            return 0

        with open(output_path, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=rows[0].keys())
            writer.writeheader()
            for row in rows:
                writer.writerow(dict(row))

        return len(rows)

    def count(self) -> int:
        """Return total number of audit events."""
        with self._connection() as conn:
            row = conn.execute("SELECT COUNT(*) as c FROM events").fetchone()
            return row["c"] if row else 0


def generate_signing_keypair() -> tuple[str, str]:
    """Generate an Ed25519 keypair for audit signing.

    Returns:
        Tuple of (private_key_b64, public_key_b64) suitable for config storage.
    """
    import base64
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        PublicFormat,
    )

    private_key = Ed25519PrivateKey.generate()
    private_bytes = private_key.private_bytes_raw()
    public_key = private_key.public_key()
    public_bytes = public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)

    return (
        base64.b64encode(private_bytes).decode(),
        base64.b64encode(public_bytes).decode(),
    )
