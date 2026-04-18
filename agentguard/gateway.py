"""HTTP gateway mode for AgentGuard.

Exposes AgentGuard as an HTTP server that accepts MCP-over-HTTP requests
from remote clients. Used for federal/production deployments where stdio
transport is not practical.

Requires the `fastapi` and `uvicorn` packages (optional dependencies).
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

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
        from fastapi import FastAPI, HTTPException, Request
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
    )
    if mode == Mode.FEDERAL and not audit_log.signing_enabled:
        raise ValueError(
            "Federal mode requires a valid Ed25519 signing key. "
            "Set signing_key in config or AGENTGUARD_SIGNING_KEY."
        )

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
        """Health check endpoint."""
        return {
            "status": "ok",
            "mode": config.mode,
            "audit_events": audit_log.count(),
        }

    @app.post("/mcp")
    async def mcp_endpoint(request: Request) -> JSONResponse:
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
    async def audit_tail(n: int = 20) -> dict[str, Any]:
        """Return the most recent audit events."""
        return {"events": audit_log.tail(n=n)}

    @app.get("/audit/verify")
    async def audit_verify() -> dict[str, Any]:
        """Verify the audit log hash chain integrity."""
        valid, message = audit_log.verify_chain()
        return {"valid": valid, "message": message}

    return app


def run_gateway(config: AgentGuardConfig, host: str = "0.0.0.0", port: int = 8080) -> None:
    """Start the HTTP gateway server.

    Args:
        config: Loaded AgentGuard configuration.
        host: Bind host address.
        port: Bind port.
    """
    try:
        import uvicorn
    except ImportError as e:
        raise ImportError(
            "HTTP gateway mode requires uvicorn. Install with: pip install uvicorn"
        ) from e

    app = create_app(config)
    logger.info("AgentGuard HTTP gateway starting on %s:%d (mode=%s)", host, port, config.mode)
    uvicorn.run(app, host=host, port=port)
