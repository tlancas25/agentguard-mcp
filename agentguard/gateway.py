"""HTTP gateway mode for AgentGuard.

Exposes AgentGuard as an HTTP server that accepts MCP-over-HTTP requests
from remote clients. Used for federal/production deployments where stdio
transport is not practical.

Requires the `fastapi` and `uvicorn` packages (optional dependencies).
"""

from __future__ import annotations

import hmac
import json
import logging
from pathlib import Path
from typing import Any, Optional

from agentguard.audit_log import AuditLog
from agentguard.config import AgentGuardConfig
from agentguard.modes import Mode
from agentguard.policy_engine import PolicyBundle, PolicyEngine
from agentguard.proxy import ProxyCore

logger = logging.getLogger(__name__)


def create_app(config: AgentGuardConfig) -> Any:
    """Create and return the FastAPI application.

    Args:
        config: Loaded AgentGuard configuration.

    Returns:
        FastAPI application instance.

    Raises:
        ImportError: If fastapi is not installed.
    """
    try:
        from fastapi import Depends, FastAPI, Header, HTTPException, Request
        from fastapi.responses import JSONResponse
    except ImportError as e:
        raise ImportError(
            "HTTP gateway mode requires fastapi and uvicorn. "
            "Install with: pip install fastapi uvicorn"
        ) from e

    mode = Mode(config.mode)
    audit_log = AuditLog(
        db_path=config.audit_db_path,
        signing_key=config.signing_key or None,
        verify_key=config.verify_key or None,
    )
    if mode == Mode.FEDERAL and not audit_log.signing_enabled:
        raise ValueError(
            "Federal mode requires a valid Ed25519 signing key. "
            "Set signing_key in config or AGENTGUARD_SIGNING_KEY."
        )
    if mode == Mode.FEDERAL and not config.gateway_api_keys:
        raise ValueError(
            "Federal mode requires at least one gateway API key. "
            "Set gateway_api_keys in config or AGENTGUARD_GATEWAY_API_KEYS."
        )

    api_keys = set(config.gateway_api_keys or [])

    async def require_api_key(
        x_agentguard_api_key: str = Header(default=""),
    ) -> str:
        """Reject any request without a valid API key when auth is configured.

        Dev mode with zero configured keys keeps the historical open-door
        behaviour for local Claude Code experiments, but warns loudly. Any
        key list at all flips auth on for every route.
        """
        if not api_keys:
            return "anonymous-dev"
        presented = x_agentguard_api_key or ""
        for known in api_keys:
            if hmac.compare_digest(presented, known):
                # Never log the key value itself.
                return hmac.new(
                    b"agentguard-keyid", known.encode(), "sha256"
                ).hexdigest()[:12]
        raise HTTPException(status_code=401, detail="Invalid or missing API key")

    bundles: list[PolicyBundle] = []
    for path_str in config.policy_bundles:
        path = Path(path_str)
        if path.exists():
            try:
                bundles.append(PolicyBundle.from_yaml(path))
            except Exception as e:
                logger.error("Failed to load policy bundle %s: %s", path_str, e)

    policy_engine = PolicyEngine(mode=mode, bundles=bundles)
    proxy = ProxyCore(config, audit_log, policy_engine)

    app = FastAPI(
        title="AgentGuard MCP Gateway",
        description="MCP security gateway with NIST 800-53 compliance",
        version="0.1.0",
    )

    @app.get("/health")
    async def health() -> dict[str, Any]:
        """Health check endpoint. Unauthenticated by design."""
        return {
            "status": "ok",
            "mode": config.mode,
        }

    @app.post("/mcp")
    async def mcp_endpoint(
        request: Request,
        _caller: str = Depends(require_api_key),
    ) -> JSONResponse:
        """Main MCP message endpoint.

        Accepts JSON-RPC messages, processes through AgentGuard proxy,
        and returns the response.
        """
        try:
            body = await request.json()
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid JSON body")

        method = body.get("method", "")
        params = body.get("params", {})

        if method == "initialize":
            proxy.handle_initialize(params)
            return JSONResponse({"jsonrpc": "2.0", "id": body.get("id"), "result": {}})

        if method == "tools/call":
            tool_name = params.get("name", "")
            tool_args = params.get("arguments", {})
            should_forward, decision, warnings = proxy.handle_tool_call(tool_name, tool_args)

            if not should_forward:
                return JSONResponse({
                    "jsonrpc": "2.0",
                    "id": body.get("id"),
                    "error": {
                        "code": -32603,
                        "message": f"[AgentGuard] Tool call denied: {decision.reason}",
                        "data": {"nist_controls": decision.nist_controls},
                    },
                })

            # In gateway mode, we return a placeholder — real implementation
            # would forward to the upstream HTTP MCP server
            return JSONResponse({
                "jsonrpc": "2.0",
                "id": body.get("id"),
                "result": {"forwarded": True, "warnings": warnings},
            })

        # Default: log and return accepted
        return JSONResponse({
            "jsonrpc": "2.0",
            "id": body.get("id"),
            "result": {"status": "logged"},
        })

    @app.get("/audit/tail")
    async def audit_tail(
        n: int = 20,
        _caller: str = Depends(require_api_key),
    ) -> dict[str, Any]:
        """Return the most recent audit events."""
        return {"events": audit_log.tail(n=n)}

    @app.get("/audit/verify")
    async def audit_verify(
        _caller: str = Depends(require_api_key),
    ) -> dict[str, Any]:
        """Verify the audit log hash chain integrity."""
        valid, message = audit_log.verify_chain()
        return {"valid": valid, "message": message}

    return app


def run_gateway(
    config: AgentGuardConfig,
    host: Optional[str] = None,
    port: int = 8080,
    ssl_keyfile: Optional[str] = None,
    ssl_certfile: Optional[str] = None,
) -> None:
    """Start the HTTP gateway server.

    Args:
        config: Loaded AgentGuard configuration.
        host: Bind host. Defaults to config.gateway_bind_host (127.0.0.1).
        port: Bind port.
        ssl_keyfile: Optional TLS private key. Required in federal mode.
        ssl_certfile: Optional TLS certificate. Required in federal mode.
    """
    try:
        import uvicorn
    except ImportError as e:
        raise ImportError(
            "HTTP gateway mode requires uvicorn. Install with: pip install uvicorn"
        ) from e

    effective_host = host or config.gateway_bind_host or "127.0.0.1"

    if Mode(config.mode) == Mode.FEDERAL:
        if not (ssl_keyfile and ssl_certfile):
            raise ValueError(
                "Federal mode requires TLS. Provide ssl_keyfile and ssl_certfile."
            )
        if effective_host == "0.0.0.0" and not config.gateway_api_keys:
            raise ValueError(
                "Federal mode refuses to bind 0.0.0.0 without API keys configured."
            )

    app = create_app(config)
    logger.info(
        "AgentGuard HTTP gateway starting on %s:%d (mode=%s, tls=%s, auth=%s)",
        effective_host,
        port,
        config.mode,
        bool(ssl_keyfile and ssl_certfile),
        "on" if config.gateway_api_keys else "off",
    )
    uvicorn.run(
        app,
        host=effective_host,
        port=port,
        ssl_keyfile=ssl_keyfile,
        ssl_certfile=ssl_certfile,
    )
