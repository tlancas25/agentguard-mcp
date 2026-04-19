"""Agent identity extraction for AgentGuard.

Identifies AI agents from MCP initialize request data.

Identity trust levels:
- unverified: whatever the client claimed in clientInfo. Audit events
  carry the name but it MUST NOT be used for allowlists.
- attested: the client presented a token signed with a pre-shared HMAC
  secret (AGENTGUARD_IDENTITY_SECRETS). Name and optional subject are
  cryptographically bound.

Federal mode requires attested identity and refuses unverified clients.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import time
import uuid
from dataclasses import dataclass, field
from typing import Optional, Any

logger = logging.getLogger(__name__)

IDENTITY_CLOCK_SKEW_SEC = 300


@dataclass
class AgentIdentity:
    """Represents the identity of an MCP client agent.

    In a federal context, this is the entity that will be held accountable
    for the tool calls recorded in the audit log (per NIST AU-10).
    """

    session_id: str
    client_name: str
    client_version: Optional[str] = None
    protocol_version: Optional[str] = None
    # Future: cert thumbprint, user principal name, etc.
    cert_thumbprint: Optional[str] = None
    attested: bool = False
    attested_subject: Optional[str] = None
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def agent_id(self) -> str:
        """Canonical agent identifier string for audit records.

        Attested identities are prefixed with a mark so downstream policy
        evaluation and audit records can tell attested from self-declared
        without having to inspect another field.
        """
        name = self.client_name or "unknown-client"
        if self.attested:
            subj = self.attested_subject or name
            return f"attested:{subj}:{self.session_id}"
        return f"unverified:{name}:{self.session_id}"

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dict for audit log storage."""
        return {
            "session_id": self.session_id,
            "client_name": self.client_name,
            "client_version": self.client_version,
            "protocol_version": self.protocol_version,
            "agent_id": self.agent_id,
        }


class UnattestedIdentityError(RuntimeError):
    """Raised when federal mode receives a client without a valid attestation."""


class IdentityExtractor:
    """Extracts agent identity from MCP protocol messages.

    If an HMAC shared-secret store is configured, clientInfo may include
    an 'attestation' block of the form:
        {"issuer": "<key-id>", "subject": "<stable-id>",
         "issued_at": <unix-seconds>, "sig": "<hex-hmac-sha256>"}
    The signed payload is canonical JSON of {issuer, subject, issued_at,
    client_name}. issued_at is checked against the local clock with a
    configurable skew.
    """

    def __init__(
        self,
        require_attestation: bool = False,
        identity_secrets: Optional[dict[str, str]] = None,
    ) -> None:
        """Initialize the identity extractor.

        Args:
            require_attestation: If True, unattested clients are rejected.
                                 Federal mode should set this.
            identity_secrets: Mapping of issuer key-id -> shared HMAC secret.
                              If None, falls back to the AGENTGUARD_IDENTITY_SECRETS
                              env var ("kid1=secret1,kid2=secret2").
        """
        self._current_identity: Optional[AgentIdentity] = None
        self._require_attestation = require_attestation
        if identity_secrets is None:
            identity_secrets = self._load_secrets_from_env()
        self._secrets = identity_secrets or {}

    @staticmethod
    def _load_secrets_from_env() -> dict[str, str]:
        raw = os.environ.get("AGENTGUARD_IDENTITY_SECRETS", "")
        out: dict[str, str] = {}
        for pair in raw.split(","):
            pair = pair.strip()
            if not pair or "=" not in pair:
                continue
            kid, sec = pair.split("=", 1)
            out[kid.strip()] = sec.strip()
        return out

    def extract_from_initialize(
        self,
        initialize_params: dict[str, Any],
    ) -> AgentIdentity:
        """Extract agent identity from an MCP initialize request.

        Args:
            initialize_params: The params object from the MCP initialize request.

        Returns:
            AgentIdentity populated from the request data.

        Raises:
            UnattestedIdentityError: Federal mode with no valid attestation.
        """
        client_info = initialize_params.get("clientInfo", {})
        client_name = client_info.get("name", "unknown-client")
        client_version = client_info.get("version")
        protocol_version = initialize_params.get("protocolVersion")
        attestation = client_info.get("attestation") or {}

        attested = False
        attested_subject: Optional[str] = None
        if attestation and self._secrets:
            attested, attested_subject = self._check_attestation(
                client_name, attestation
            )

        if self._require_attestation and not attested:
            raise UnattestedIdentityError(
                "Federal mode requires a valid HMAC attestation in "
                "clientInfo.attestation. Reject unverified client "
                f"name={client_name!r}."
            )

        identity = AgentIdentity(
            session_id=str(uuid.uuid4()),
            client_name=client_name,
            client_version=client_version,
            protocol_version=protocol_version,
            attested=attested,
            attested_subject=attested_subject,
        )
        self._current_identity = identity
        return identity

    def _check_attestation(
        self,
        client_name: str,
        attestation: dict[str, Any],
    ) -> tuple[bool, Optional[str]]:
        """Validate an HMAC attestation. Returns (ok, subject)."""
        issuer = attestation.get("issuer")
        subject = attestation.get("subject")
        issued_at = attestation.get("issued_at")
        sig_hex = attestation.get("sig")
        if not (isinstance(issuer, str) and isinstance(subject, str)
                and isinstance(issued_at, (int, float))
                and isinstance(sig_hex, str)):
            return False, None
        secret = self._secrets.get(issuer)
        if not secret:
            logger.warning("Unknown attestation issuer: %s", issuer)
            return False, None
        if abs(time.time() - float(issued_at)) > IDENTITY_CLOCK_SKEW_SEC:
            logger.warning("Attestation issued_at outside acceptable skew")
            return False, None
        payload = json.dumps(
            {
                "issuer": issuer,
                "subject": subject,
                "issued_at": int(issued_at),
                "client_name": client_name,
            },
            sort_keys=True,
        ).encode()
        expected = hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, sig_hex):
            logger.warning("Attestation HMAC mismatch for subject=%s", subject)
            return False, None
        return True, subject

    def get_current(self) -> AgentIdentity:
        """Return the current session's agent identity.

        If no initialize request has been processed yet, returns an anonymous identity.
        """
        if self._current_identity is None:
            return AgentIdentity(
                session_id=str(uuid.uuid4()),
                client_name="anonymous",
            )
        return self._current_identity

    @staticmethod
    def anonymous(label: str = "anonymous") -> AgentIdentity:
        """Create an anonymous agent identity for use in testing or fallback paths."""
        return AgentIdentity(
            session_id=str(uuid.uuid4()),
            client_name=label,
        )
