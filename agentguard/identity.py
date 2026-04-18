"""Agent identity extraction for AgentGuard.

Identifies AI agents from MCP initialize request data.
For MVP, identity is derived from client name + session UUID.
Future versions will support certificate-based identity for DoD PKI.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Optional, Any


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
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def agent_id(self) -> str:
        """Canonical agent identifier string for audit records."""
        name = self.client_name or "unknown-client"
        return f"{name}:{self.session_id}"

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dict for audit log storage."""
        return {
            "session_id": self.session_id,
            "client_name": self.client_name,
            "client_version": self.client_version,
            "protocol_version": self.protocol_version,
            "agent_id": self.agent_id,
        }


class IdentityExtractor:
    """Extracts agent identity from MCP protocol messages.

    The MCP initialize request contains clientInfo with the client name
    and version. AgentGuard uses this plus a generated session ID to
    create a stable, audit-friendly agent identity.
    """

    def __init__(self) -> None:
        """Initialize the identity extractor."""
        self._current_identity: Optional[AgentIdentity] = None

    def extract_from_initialize(
        self,
        initialize_params: dict[str, Any],
    ) -> AgentIdentity:
        """Extract agent identity from an MCP initialize request.

        Args:
            initialize_params: The params object from the MCP initialize request.

        Returns:
            AgentIdentity populated from the request data.
        """
        client_info = initialize_params.get("clientInfo", {})
        client_name = client_info.get("name", "unknown-client")
        client_version = client_info.get("version")
        protocol_version = initialize_params.get("protocolVersion")

        identity = AgentIdentity(
            session_id=str(uuid.uuid4()),
            client_name=client_name,
            client_version=client_version,
            protocol_version=protocol_version,
        )
        self._current_identity = identity
        return identity

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
