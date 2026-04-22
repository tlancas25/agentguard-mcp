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
import hmac
import json
import logging
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Generator, Optional

logger = logging.getLogger(__name__)

GENESIS_HASH = "0" * 64  # SHA-256 of nothing — the chain anchor

# AG-BL-001.R1: the red-team report (trial 3) demonstrated that the
# audit_meta row inside the SQLite file is a same-surface check — an
# attacker with fs_write on audit.db can UPDATE both tables in one
# primitive. True tamper-evidence requires an anchor OUTSIDE the DB,
# signed with a secret the attacker cannot reach. This module writes
# that anchor to a sibling file and keys its HMAC on the operator
# secret (same secret used for approval tokens).
SIDECAR_SUFFIX = ".hwm"
INSTALL_RECEIPT_FILENAME = ".install-receipt"


def _install_receipt_path_for(db_path: Path) -> Path:
    """Location of the first-install receipt for a specific audit DB."""
    return db_path.parent / INSTALL_RECEIPT_FILENAME


def _ensure_install_receipt(db_path: Path) -> bool:
    """Write a one-time install receipt if missing. Returns True if the
    receipt EXISTED before this call (i.e., this is not the first boot).

    AG-BL-001.V2 (trial 4): the prior design let an attacker run
    ``rm ~/.agentguard/audit.db ~/.agentguard/audit.db.hwm`` and return
    the gateway to a state indistinguishable from a fresh install — next
    boot re-initialized empty, verify_chain returned PASS, the attacker
    re-appended a forged chain. The install receipt is an out-of-band
    marker: once written, its presence means "this install has existed
    before." verify_chain refuses to treat an empty DB as legitimate
    when the receipt predates the DB.
    """
    import secrets as _secrets

    path = _install_receipt_path_for(db_path)
    if path.exists():
        return True
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "install_uuid": _secrets.token_hex(16),
        "created_at": datetime.now(timezone.utc).isoformat(),
        "version": "0.4.0",
    }
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return False


def _install_receipt_path() -> Path:
    """Legacy global accessor kept for the self_protect helper."""
    from agentguard.config import DEFAULT_AGENTGUARD_HOME

    return DEFAULT_AGENTGUARD_HOME / INSTALL_RECEIPT_FILENAME


def _sidecar_path_for(db_path: Path) -> Path:
    """Return the out-of-DB high-water-mark sidecar path for ``db_path``."""
    return Path(str(db_path) + SIDECAR_SUFFIX)


def _load_operator_secret_bytes() -> Optional[bytes]:
    """Best-effort load of the operator HMAC secret.

    Delegates to ``agentguard.approvals._load_operator_secret`` so the
    same minimum-entropy floor (MIN_OPERATOR_SECRET_BYTES) applies to
    both approval tokens and audit sidecar signatures. Weak secrets are
    rejected here too — sidecar writes without a valid key simply fall
    back to unsigned, with verify_chain() requiring an operator secret
    at verify time to validate signatures.
    """
    try:
        from agentguard.approvals import _load_operator_secret as _al
        return _al()
    except Exception as e:
        logger.debug("Could not load operator secret for sidecar: %s", e)
        return None


def _sidecar_canonical(high_water_hash: str, event_count: int, updated_at: str) -> bytes:
    """Stable byte representation used for HMAC signing."""
    body = json.dumps(
        {
            "high_water_hash": high_water_hash,
            "event_count": event_count,
            "updated_at": updated_at,
        },
        sort_keys=True,
    )
    return body.encode("utf-8")


def _sidecar_write(path: Path, high_water_hash: str, event_count: int) -> None:
    """Write the sidecar file atomically (write + rename)."""
    updated_at = datetime.now(timezone.utc).isoformat()
    secret = _load_operator_secret_bytes()
    sig: Optional[str] = None
    if secret is not None:
        sig = hmac.new(
            secret,
            _sidecar_canonical(high_water_hash, event_count, updated_at),
            hashlib.sha256,
        ).hexdigest()

    doc = {
        "high_water_hash": high_water_hash,
        "event_count": event_count,
        "updated_at": updated_at,
        "signed": sig is not None,
        "signature": sig,
    }
    tmp = path.with_suffix(path.suffix + ".tmp")
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp.write_text(json.dumps(doc, indent=2), encoding="utf-8")
    try:
        os.chmod(tmp, 0o600)
    except OSError:
        pass
    os.replace(tmp, path)


def _sidecar_read(path: Path) -> Optional[dict[str, Any]]:
    """Read the sidecar JSON. Returns None when absent or malformed."""
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        logger.warning("Sidecar at %s is unreadable: %s", path, e)
        return None


def _sidecar_signature_valid(doc: dict[str, Any]) -> Optional[bool]:
    """Verify the sidecar HMAC with the current operator secret.

    Returns None when signing is not configured (sidecar was unsigned
    and no secret is available), True/False when a signature was
    present and could be checked. Treat None as a weaker assertion —
    tamper detection still applies on value mismatch.
    """
    if not doc.get("signed"):
        return None
    secret = _load_operator_secret_bytes()
    if secret is None:
        return False  # sidecar claims signed but we can't verify
    expected = hmac.new(
        secret,
        _sidecar_canonical(
            str(doc.get("high_water_hash", GENESIS_HASH)),
            int(doc.get("event_count", 0)),
            str(doc.get("updated_at", "")),
        ),
        hashlib.sha256,
    ).hexdigest()
    provided = doc.get("signature") or ""
    return hmac.compare_digest(expected, provided)


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
        """Return the fields that are included in the event hash.

        tool_result_json is covered here so the hash chain protects the
        actual outcome of each tool call, not only the request side
        (AU-9 / AU-10). Keep this shape in sync with verify_chain().
        """
        if self.tool_result is None:
            tool_result_json: Optional[str] = None
        else:
            try:
                tool_result_json = json.dumps(self.tool_result, sort_keys=True)
            except (TypeError, ValueError):
                tool_result_json = str(self.tool_result)
        return {
            "timestamp": self.timestamp,
            "agent_id": self.agent_id,
            "event_type": self.event_type,
            "tool_name": self.tool_name,
            "tool_args_json": json.dumps(self.tool_args, sort_keys=True),
            "tool_result_json": tool_result_json,
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

    def __init__(
        self,
        db_path: Path,
        signing_key: Optional[str] = None,
        verify_key: Optional[str] = None,
    ) -> None:
        """Initialize the audit log.

        Args:
            db_path: Path to the SQLite database file.
            signing_key: Base64-encoded Ed25519 private key for event signing.
                         If None, events are not signed.
            verify_key: Base64-encoded Ed25519 public key used by verify_chain()
                        to validate each event's signature. If None, the public
                        key is derived from signing_key when possible. If no
                        verify key is available, signatures are not checked and
                        verify_chain() says so in its message.
        """
        self.db_path = db_path
        self._signing_key = signing_key
        self._signer: Optional[Any] = None
        self._verifier: Optional[Any] = None

        if signing_key:
            self._init_signer(signing_key)

        if verify_key:
            self._init_verifier(verify_key)
        elif self._signer is not None:
            try:
                self._verifier = self._signer.public_key()
            except Exception as e:
                logger.warning("Could not derive verify key from signing key: %s", e)

        # AG-BL-001.V2: drop a one-time install receipt on first boot.
        # verify_chain() later refuses to treat an empty DB as a valid
        # fresh-install state if the receipt predates the DB.
        try:
            _ensure_install_receipt(self.db_path)
        except OSError as e:
            logger.warning("Could not write install receipt: %s", e)

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

    def _init_verifier(self, verify_key_b64: str) -> None:
        """Initialize the Ed25519 verifier from a base64-encoded public key."""
        try:
            import base64
            from cryptography.hazmat.primitives.asymmetric.ed25519 import (
                Ed25519PublicKey,
            )

            key_bytes = base64.b64decode(verify_key_b64)
            self._verifier = Ed25519PublicKey.from_public_bytes(key_bytes)
        except Exception as e:
            logger.warning(
                "Failed to initialize verify key: %s. Signatures will not be checked.",
                e,
            )
            self._verifier = None

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
        """Create the events + audit_meta tables if they do not exist.

        audit_meta stores a singleton high-water-mark row that records the
        hash of the most recently appended event and a monotonic counter.
        verify_chain() cross-checks this row against the events table: an
        attacker who deletes or reseeds the events table will be caught
        because the high-water-mark no longer matches the tail of the
        chain (AG-BL-001).
        """
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
            conn.execute("""
                CREATE TABLE IF NOT EXISTS audit_meta (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    high_water_hash TEXT NOT NULL,
                    event_count INTEGER NOT NULL DEFAULT 0,
                    updated_at TEXT NOT NULL
                )
            """)
            conn.execute(
                "INSERT OR IGNORE INTO audit_meta (id, high_water_hash, event_count, updated_at) "
                "VALUES (1, ?, 0, ?)",
                (GENESIS_HASH, datetime.now(timezone.utc).isoformat()),
            )

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
                    canonical["tool_args_json"],
                    canonical["tool_result_json"],
                    event.decision,
                    event.policy_matched,
                    canonical["nist_controls_json"],
                    prev_hash,
                    event_hash,
                    signature,
                ),
            )
            # Update the in-DB high-water-mark so later verify_chain() calls
            # can detect truncation or reseed attacks (AG-BL-001). The
            # in-DB row is a first-line check; it is SAME-SURFACE with the
            # events table and defeatable with a single fs_write primitive
            # — which is why the v0.3 sidecar below is the real barrier.
            conn.execute(
                "UPDATE audit_meta SET high_water_hash = ?, "
                "event_count = event_count + 1, updated_at = ? WHERE id = 1",
                (event_hash, datetime.now(timezone.utc).isoformat()),
            )
            row = conn.execute(
                "SELECT event_count FROM audit_meta WHERE id = 1"
            ).fetchone()
            new_count = int(row["event_count"]) if row else 0

        # Out-of-DB sidecar anchor. Written AFTER the DB commit so a
        # crash mid-write never leaves the sidecar ahead of the DB.
        # AG-BL-001.R1: HMAC-signed with operator_secret when available.
        try:
            _sidecar_write(_sidecar_path_for(self.db_path), event_hash, new_count)
        except OSError as e:
            logger.warning(
                "Could not update audit sidecar at %s: %s",
                _sidecar_path_for(self.db_path),
                e,
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
            meta_row = conn.execute(
                "SELECT high_water_hash, event_count FROM audit_meta WHERE id = 1"
            ).fetchone()

        meta_hash = meta_row["high_water_hash"] if meta_row else GENESIS_HASH
        meta_count = meta_row["event_count"] if meta_row else 0

        # Out-of-DB sidecar: the real anti-tamper anchor (AG-BL-001.R1).
        # The same-surface in-DB meta row is defeated by anyone who can
        # UPDATE audit_meta alongside DELETE FROM events; this sidecar
        # lives outside the SQLite file and is HMAC-signed so forging
        # it requires the operator secret.
        sidecar_path = _sidecar_path_for(self.db_path)
        sidecar = _sidecar_read(sidecar_path)
        if sidecar is None:
            # No sidecar AND no events AND meta is genesis = fresh install,
            # legitimate empty state. Otherwise: missing sidecar is a
            # tamper signal.
            if rows or meta_count > 0 or meta_hash != GENESIS_HASH:
                return (
                    False,
                    f"Audit sidecar {sidecar_path} is missing but the DB "
                    f"shows activity (rows={len(rows)}, meta_count={meta_count}). "
                    "Out-of-DB anchor removed — tamper detected.",
                )
        else:
            sig_ok = _sidecar_signature_valid(sidecar)
            if sig_ok is False:
                return (
                    False,
                    f"Audit sidecar signature at {sidecar_path} is invalid. "
                    "Possible forgery; operator_secret unavailable or rotated.",
                )
            side_hash = str(sidecar.get("high_water_hash", GENESIS_HASH))
            side_count = int(sidecar.get("event_count", 0))
            # Sidecar vs DB meta cross-check: if these disagree, someone
            # touched one but not the other.
            if side_hash != meta_hash or side_count != meta_count:
                return (
                    False,
                    f"Sidecar ({side_hash[:12]}…, {side_count} events) does "
                    f"not match audit_meta ({meta_hash[:12]}…, "
                    f"{meta_count} events). Tamper detected.",
                )
            # Sidecar vs row tail cross-check for the reseed case:
            # events table was wiped AND meta was reset, but the sidecar
            # still remembers the original high-water-mark.
            if not rows and (side_hash != GENESIS_HASH or side_count > 0):
                return (
                    False,
                    f"Sidecar shows {side_count} prior events (last hash "
                    f"{side_hash[:12]}…) but the DB is empty. "
                    "Same-surface reseed detected.",
                )

        # AG-BL-001 (original, in-DB) reseed guard: if the events table
        # is empty but the same-surface high-water-mark shows prior
        # activity, the table was truncated.
        if not rows:
            if meta_hash != GENESIS_HASH or meta_count > 0:
                return (
                    False,
                    f"Events table is empty but high-water-mark shows "
                    f"{meta_count} prior events (last hash {meta_hash[:12]}…). "
                    f"Truncation or reseed detected.",
                )
            # AG-BL-001.V2: factory-reset detector. Empty DB + empty
            # sidecar is only a legitimate state on a BRAND-NEW install.
            # If the install receipt shows this home was initialized
            # earlier, someone deleted both the DB and the sidecar
            # between then and now — fail closed.
            receipt = _install_receipt_path_for(self.db_path)
            try:
                receipt_ctime = receipt.stat().st_mtime if receipt.exists() else None
            except OSError:
                receipt_ctime = None
            # The receipt is written in __init__ of THIS AuditLog. If
            # it predates every write to the DB file, we're inside a
            # legitimate brand-new install. If it predates a deleted DB
            # that existed before, we're looking at factory-reset.
            try:
                db_ctime = (
                    self.db_path.stat().st_mtime if self.db_path.exists() else None
                )
            except OSError:
                db_ctime = None
            if (
                receipt_ctime is not None
                and db_ctime is not None
                and receipt_ctime + 1 < db_ctime
            ):
                # Receipt predates the DB by more than a second → the DB
                # was created after a prior install's receipt was already
                # there. That's the factory-reset shape.
                return (
                    False,
                    "Install receipt predates the current audit DB by more "
                    "than one second. Factory-reset (rm audit.db audit.db.hwm) "
                    "detected. Out-of-band anchor says this install has "
                    "existed before.",
                )
            return True, "Audit log is empty."

        prev_hash = GENESIS_HASH
        signatures_checked = 0
        for row in rows:
            canonical = {
                "timestamp": row["timestamp"],
                "agent_id": row["agent_id"],
                "event_type": row["event_type"],
                "tool_name": row["tool_name"],
                "tool_args_json": row["tool_args_json"],
                "tool_result_json": row["tool_result_json"],
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

            if self._verifier is not None:
                sig_b64 = row["signature"]
                if not sig_b64:
                    return (
                        False,
                        f"Missing signature at event id={row['id']}: "
                        f"a verify key is configured but this event is unsigned.",
                    )
                try:
                    import base64

                    sig_bytes = base64.b64decode(sig_b64)
                    self._verifier.verify(sig_bytes, row["event_hash"].encode())
                    signatures_checked += 1
                except Exception:
                    return (
                        False,
                        f"Invalid signature at event id={row['id']}: "
                        f"Ed25519 verification failed.",
                    )

            prev_hash = row["event_hash"]

        # Final row must match the high-water-mark; if not, tail events
        # were truncated OR the chain was reseeded from GENESIS (AG-BL-001).
        if prev_hash != meta_hash and meta_hash != GENESIS_HASH:
            return (
                False,
                f"Chain tail hash {prev_hash[:12]}… does not match "
                f"high-water-mark {meta_hash[:12]}…. "
                f"Truncation or reseed detected.",
            )
        if meta_count and len(rows) < meta_count:
            return (
                False,
                f"Row count {len(rows)} is below recorded high-water-mark "
                f"event_count {meta_count}. Truncation detected.",
            )

        if self._verifier is not None:
            return (
                True,
                f"Chain verified. {len(rows)} events intact, "
                f"{signatures_checked} signatures validated.",
            )
        return (
            True,
            f"Chain verified. {len(rows)} events intact (signatures not checked: "
            f"no verify key configured).",
        )

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
