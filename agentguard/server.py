"""MCP stdio server entry point for AgentGuard.

Wraps the ProxyCore in an MCP server that communicates via stdio.
This is the primary transport for Claude Code and Cursor integrations.
"""

from __future__ import annotations

import asyncio
import json
import logging
import subprocess
import sys
import threading
from pathlib import Path
from typing import Any, Optional

AGENTGUARD_MCP_VERSION = "0.1.0"
MCP_PROTOCOL_VERSION = "2025-03-26"

from agentguard.audit_log import AuditLog
from agentguard.config import AgentGuardConfig
from agentguard.modes import Mode
from agentguard.policy_engine import PolicyBundle, PolicyEngine
from agentguard.proxy import ProxyCore

logger = logging.getLogger(__name__)


class StdioServer:
    """AgentGuard stdio MCP server.

    Reads JSON-RPC messages from stdin, processes them through ProxyCore,
    and forwards allowed messages to the upstream MCP server subprocess.
    """

    def __init__(self, config: AgentGuardConfig) -> None:
        """Initialize the stdio server.

        Args:
            config: Loaded AgentGuard configuration.
        """
        self.config = config
        self.mode = Mode(config.mode)

        # Initialize audit log
        self.audit_log = AuditLog(
            db_path=config.audit_db_path,
            signing_key=config.signing_key or None,
        )
        if self.mode == Mode.FEDERAL and not self.audit_log.signing_enabled:
            raise ValueError(
                "Federal mode requires a valid Ed25519 signing key. "
                "Set signing_key in config or AGENTGUARD_SIGNING_KEY."
            )

        # Initialize policy engine
        bundles: list[PolicyBundle] = []
        for path_str in config.policy_bundles:
            path = Path(path_str)
            if path.exists():
                try:
                    bundles.append(PolicyBundle.from_yaml(path))
                except Exception as e:
                    logger.error("Failed to load policy bundle %s: %s", path_str, e)

        self.policy_engine = PolicyEngine(mode=self.mode, bundles=bundles)
        self.proxy = ProxyCore(config, self.audit_log, self.policy_engine)

        # Upstream process (started when the first upstream server is configured)
        self._upstream_proc: Optional[subprocess.Popen[bytes]] = None

    async def run(self) -> None:
        """Run the stdio server event loop.

        stdin is read in a worker thread because asyncio.connect_read_pipe
        on Windows ProactorEventLoop rejects non-overlapped HANDLEs
        (WinError 6). The worker drops decoded lines on an asyncio Queue
        that the main loop awaits.
        """
        logger.info(
            "AgentGuard starting in %s mode. Audit DB: %s",
            self.mode.value,
            self.config.audit_db_path,
        )

        if self.config.upstream_servers:
            upstream = self.config.upstream_servers[0]
            if upstream.transport == "stdio" and upstream.command:
                cmd = [upstream.command] + upstream.args
                logger.info("Starting upstream MCP server: %s", " ".join(cmd))
                self._upstream_proc = subprocess.Popen(
                    cmd,
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )

        loop = asyncio.get_running_loop()
        queue: asyncio.Queue[Optional[str]] = asyncio.Queue()

        def reader_thread() -> None:
            try:
                for line in sys.stdin:
                    asyncio.run_coroutine_threadsafe(
                        queue.put(line.rstrip("\r\n")), loop
                    )
            finally:
                asyncio.run_coroutine_threadsafe(queue.put(None), loop)

        t = threading.Thread(target=reader_thread, daemon=True)
        t.start()

        await self._process_loop(queue)

    async def _process_loop(self, queue: "asyncio.Queue[Optional[str]]") -> None:
        """Main message processing loop."""
        while True:
            try:
                line = await queue.get()
                if line is None:
                    break
                if line.strip():
                    await self._handle_message(line.strip())
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error("Error processing message: %s", e)

    async def _handle_message(self, raw: str) -> None:
        """Process a single JSON-RPC message."""
        if not raw:
            return
        try:
            msg = json.loads(raw)
        except json.JSONDecodeError as e:
            logger.warning("Failed to parse JSON-RPC message: %s", e)
            return

        method = msg.get("method", "")
        params = msg.get("params", {})

        # Handle initialize — extract identity first, then respond.
        if method == "initialize":
            self.proxy.handle_initialize(params)
            if self._upstream_proc is not None:
                self._forward_to_upstream(raw)
            else:
                self._write_response({
                    "jsonrpc": "2.0",
                    "id": msg.get("id"),
                    "result": {
                        "protocolVersion": MCP_PROTOCOL_VERSION,
                        "capabilities": {"tools": {}, "resources": {}, "prompts": {}},
                        "serverInfo": {
                            "name": "agentguard",
                            "version": AGENTGUARD_MCP_VERSION,
                        },
                    },
                })
            return

        # With no upstream configured, every request past initialize gets a
        # minimal synthesized response so the MCP client handshake doesn't hang.
        # Tools/list returns empty; everything else returns an empty result.
        if self._upstream_proc is None:
            if method == "tools/list":
                self._write_response({
                    "jsonrpc": "2.0",
                    "id": msg.get("id"),
                    "result": {"tools": []},
                })
            elif method in ("resources/list", "prompts/list"):
                key = "resources" if method == "resources/list" else "prompts"
                self._write_response({
                    "jsonrpc": "2.0",
                    "id": msg.get("id"),
                    "result": {key: []},
                })
            elif msg.get("id") is not None:
                self._write_response({
                    "jsonrpc": "2.0",
                    "id": msg.get("id"),
                    "result": {},
                })
            return

        # Handle tools/call — full policy + detector stack
        if method == "tools/call":
            tool_name = params.get("name", "")
            tool_args = params.get("arguments", {})
            should_forward, decision, warnings = self.proxy.handle_tool_call(
                tool_name, tool_args
            )
            for w in warnings:
                logger.warning("[AgentGuard] %s", w)

            if should_forward:
                self._forward_to_upstream(raw)
            else:
                # Return a denial response to the client
                error_response = {
                    "jsonrpc": "2.0",
                    "id": msg.get("id"),
                    "error": {
                        "code": -32603,
                        "message": f"[AgentGuard] Tool call denied: {decision.reason}",
                        "data": {
                            "nist_controls": decision.nist_controls,
                            "policy_bundle": decision.policy_bundle,
                        },
                    },
                }
                self._write_response(error_response)
            return

        # Handle tools/list — scan tool descriptions
        if method == "tools/list":
            self._forward_to_upstream(raw)
            return

        # Handle resources/read
        if method == "resources/read":
            uri = params.get("uri", "")
            allowed = self.proxy.handle_resources_read(uri, params)
            if allowed:
                self._forward_to_upstream(raw)
            else:
                self._write_response({
                    "jsonrpc": "2.0",
                    "id": msg.get("id"),
                    "error": {
                        "code": -32603,
                        "message": "[AgentGuard] Resource read denied by policy.",
                    },
                })
            return

        # Handle prompts/get
        if method == "prompts/get":
            prompt_name = params.get("name", "")
            allowed = self.proxy.handle_prompts_get(prompt_name, params)
            if allowed:
                self._forward_to_upstream(raw)
            else:
                self._write_response({
                    "jsonrpc": "2.0",
                    "id": msg.get("id"),
                    "error": {
                        "code": -32603,
                        "message": "[AgentGuard] Prompt access denied by policy.",
                    },
                })
            return

        # Pass through all other messages
        self._forward_to_upstream(raw)

    def _forward_to_upstream(self, raw: str) -> None:
        """Forward a raw message to the upstream MCP server subprocess."""
        if self._upstream_proc and self._upstream_proc.stdin:
            try:
                self._upstream_proc.stdin.write((raw + "\n").encode())
                self._upstream_proc.stdin.flush()
            except BrokenPipeError:
                logger.error("Upstream MCP server pipe broken.")

    def _write_response(self, response: dict[str, Any]) -> None:
        """Write a JSON-RPC response to stdout."""
        print(json.dumps(response), flush=True)

    def stop(self) -> None:
        """Stop the server and clean up the upstream process."""
        if self._upstream_proc:
            self._upstream_proc.terminate()
            try:
                self._upstream_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._upstream_proc.kill()
        logger.info("AgentGuard server stopped.")


def run_server(config: AgentGuardConfig) -> None:
    """Entry point to start the stdio server."""
    server = StdioServer(config)
    try:
        asyncio.run(server.run())
    except KeyboardInterrupt:
        server.stop()
