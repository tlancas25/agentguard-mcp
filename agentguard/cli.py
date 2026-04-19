"""AgentGuard CLI entry point.

Commands:
  agentguard init              — scaffold agentguard.yaml in current dir
  agentguard run               — start gateway
  agentguard audit tail        — live-tail audit log
  agentguard audit verify      — verify hash chain integrity
  agentguard report fedramp    — generate FedRAMP evidence pack
  agentguard report nist-ai-rmf — generate NIST AI RMF assessment
  agentguard policy check      — validate a policy file
  agentguard version           — show version
"""

from __future__ import annotations

import logging
import os
import shutil
import sys
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.table import Table
from rich import box

from agentguard import __version__

console = Console()
err_console = Console(stderr=True)


def _resolve_config_path(config_path: str) -> Path:
    """Pick the right config file.

    If the caller pointed at something real, use it. Otherwise fall back to
    ``~/.agentguard/agentguard.yaml`` so ``agentguard run`` and
    ``agentguard audit tail`` work the same from every cwd.
    """
    from agentguard.config import DEFAULT_CONFIG_PATH

    explicit = Path(os.path.expanduser(os.path.expandvars(config_path)))
    if explicit.exists():
        return explicit
    if config_path == "agentguard.yaml" and DEFAULT_CONFIG_PATH.exists():
        return DEFAULT_CONFIG_PATH
    return explicit


def _load_config(config_path: str, mode: Optional[str] = None) -> "AgentGuardConfig":  # type: ignore[name-defined]
    """Load config from file + env, with optional mode override."""
    from agentguard.config import AgentGuardConfig

    path = _resolve_config_path(config_path)
    cfg = AgentGuardConfig.from_yaml(path)
    if mode:
        cfg = cfg.model_copy(update={"mode": mode})
    return cfg


@click.group()
@click.version_option(version=__version__, prog_name="agentguard")
def cli() -> None:
    """AgentGuard MCP — Open-source MCP security gateway for federal and defense AI."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )


# ---------------------------------------------------------------------------
# init
# ---------------------------------------------------------------------------

@cli.command()
@click.option("--gen-key", is_flag=True, default=False, help="Generate an Ed25519 signing keypair.")
@click.option("--force", is_flag=True, default=False, help="Overwrite existing agentguard.yaml.")
@click.option(
    "--local",
    is_flag=True,
    default=False,
    help="Scaffold in the current directory instead of ~/.agentguard/.",
)
def init(gen_key: bool, force: bool, local: bool) -> None:
    """Scaffold agentguard.yaml.

    By default the config and audit DB live under ``~/.agentguard/`` so the
    gateway is reachable from any shell or subprocess (Claude Code, systemd,
    etc.) without depending on cwd. Pass ``--local`` to scaffold in the
    current directory instead.
    """
    from agentguard.config import DEFAULT_AGENTGUARD_HOME, DEFAULT_CONFIG_PATH

    if local:
        dest = Path("agentguard.yaml")
    else:
        DEFAULT_AGENTGUARD_HOME.mkdir(parents=True, exist_ok=True)
        dest = DEFAULT_CONFIG_PATH

    if dest.exists() and not force:
        err_console.print(
            f"[yellow]{dest} already exists. Use --force to overwrite.[/yellow]"
        )
        sys.exit(1)

    # Find the example config relative to the package
    example_path = Path(__file__).parent.parent / "agentguard.yaml.example"
    if example_path.exists():
        shutil.copy(example_path, dest)
        console.print(f"[green]Created {dest}[/green]")
    else:
        # Write a minimal config if example not found
        dest.write_text(
            "mode: dev\n"
            "audit_db_path: ~/.agentguard/audit.db\n"
            "policy_bundles: []\n"
            "upstream_servers: []\n"
        )
        console.print(f"[green]Created minimal {dest}[/green]")

    console.print(
        f"[dim]Audit DB will be written to "
        f"[bold]{DEFAULT_AGENTGUARD_HOME / 'audit.db'}[/bold] "
        f"unless you change audit_db_path in the YAML.[/dim]"
    )

    if gen_key:
        from agentguard.audit_log import generate_signing_keypair

        private_b64, public_b64 = generate_signing_keypair()
        console.print("\n[bold]Ed25519 Signing Keypair[/bold]")
        console.print(f"[dim]Private key (add to AGENTGUARD_SIGNING_KEY or agentguard.yaml):[/dim]")
        console.print(f"  {private_b64}")
        console.print(f"[dim]Public key (share with auditors for verification):[/dim]")
        console.print(f"  {public_b64}")
        console.print(
            "\n[yellow]Store the private key securely. Do not commit it to version control.[/yellow]"
        )


# ---------------------------------------------------------------------------
# run
# ---------------------------------------------------------------------------

@cli.command()
@click.option(
    "--mode",
    type=click.Choice(["dev", "federal"], case_sensitive=False),
    default=None,
    help="Override operating mode (dev or federal).",
)
@click.option(
    "--config",
    default="agentguard.yaml",
    show_default=True,
    help="Path to agentguard.yaml config file.",
)
@click.option(
    "--transport",
    type=click.Choice(["stdio", "http"], case_sensitive=False),
    default="stdio",
    show_default=True,
    help="MCP transport mode.",
)
@click.option("--host", default="0.0.0.0", show_default=True, help="HTTP gateway bind host.")
@click.option("--port", default=8080, show_default=True, help="HTTP gateway bind port.")
def run(
    mode: Optional[str],
    config: str,
    transport: str,
    host: str,
    port: int,
) -> None:
    """Start the AgentGuard MCP gateway.

    In stdio mode, AgentGuard acts as an MCP stdio proxy between your agent
    and the upstream MCP server. In HTTP mode, it exposes an MCP-over-HTTP
    endpoint for remote clients.
    """
    resolved_config = _resolve_config_path(config)
    cfg = _load_config(config, mode)

    # Banner on stderr so stdio JSON-RPC stream stays clean.
    err_console.print(
        f"[bold green]AgentGuard {__version__}[/bold green] "
        f"starting in [bold]{cfg.mode}[/bold] mode "
        f"via [bold]{transport}[/bold] transport"
    )
    err_console.print(f"  config    : {resolved_config}")
    err_console.print(f"  audit DB  : {cfg.audit_db_path}")
    err_console.print(
        f"  signing   : "
        + ("[green]enabled[/green]" if cfg.signing_key else "[yellow]disabled[/yellow]")
    )
    err_console.print(
        f"  detectors : "
        + ", ".join(
            name
            for name, det in [
                ("prompt_injection", cfg.detectors.prompt_injection),
                ("pii", cfg.detectors.pii),
                ("secrets", cfg.detectors.secrets),
                ("tool_poisoning", cfg.detectors.tool_poisoning),
            ]
            if det.enabled
        )
        or "[dim]none enabled[/dim]"
    )
    err_console.print(
        f"[dim]Read the log: agentguard audit tail  "
        f"|  verify: agentguard audit verify[/dim]"
    )

    # Ensure the audit DB's parent directory exists so we don't crash on first write.
    try:
        Path(cfg.audit_db_path).parent.mkdir(parents=True, exist_ok=True)
    except Exception as e:
        err_console.print(
            f"[yellow]Warning: could not create audit DB directory: {e}[/yellow]"
        )

    if transport == "http":
        from agentguard.gateway import run_gateway
        try:
            run_gateway(cfg, host=host, port=port)
        except ValueError as e:
            err_console.print(f"[bold red]Configuration error:[/bold red] {e}")
            sys.exit(1)
    else:
        from agentguard.server import run_server
        try:
            run_server(cfg)
        except ValueError as e:
            err_console.print(f"[bold red]Configuration error:[/bold red] {e}")
            sys.exit(1)


# ---------------------------------------------------------------------------
# audit group
# ---------------------------------------------------------------------------

@cli.group()
def audit() -> None:
    """Audit log commands."""


@audit.command(name="tail")
@click.option("--config", default="agentguard.yaml", show_default=True)
@click.option("-n", default=20, show_default=True, help="Number of recent events to show.")
def audit_tail(config: str, n: int) -> None:
    """Show the most recent audit log events."""
    from agentguard.audit_log import AuditLog

    cfg = _load_config(config)
    log = AuditLog(db_path=cfg.audit_db_path)
    events = log.tail(n=n)

    if not events:
        console.print("[dim]No audit events found.[/dim]")
        return

    table = Table(box=box.SIMPLE, show_header=True, header_style="bold")
    table.add_column("ID", style="dim", width=6)
    table.add_column("Timestamp", width=26)
    table.add_column("Agent", width=30)
    table.add_column("Event Type", width=22)
    table.add_column("Tool", width=20)
    table.add_column("Decision", width=10)

    for e in events:
        decision_color = {
            "allowed": "green",
            "logged": "blue",
            "deny": "red",
        }.get(str(e.get("decision", "")), "white")
        table.add_row(
            str(e.get("id", "")),
            str(e.get("timestamp", ""))[:26],
            str(e.get("agent_id", ""))[:30],
            str(e.get("event_type", "")),
            str(e.get("tool_name", "") or ""),
            f"[{decision_color}]{e.get('decision', '')}[/{decision_color}]",
        )

    console.print(table)
    console.print(f"[dim]Showing {len(events)} of {log.count()} total events.[/dim]")


@audit.command(name="export")
@click.option("--config", default="agentguard.yaml", show_default=True)
@click.option(
    "--format",
    "fmt",
    type=click.Choice(["jsonl", "csv"]),
    default="jsonl",
    show_default=True,
)
@click.option(
    "--output",
    "output",
    required=True,
    type=click.Path(dir_okay=False),
    help="Output file path.",
)
def audit_export(config: str, fmt: str, output: str) -> None:
    """Export the full audit log to JSONL or CSV for SIEM ingestion."""
    from agentguard.audit_log import AuditLog

    cfg = _load_config(config)
    log = AuditLog(db_path=cfg.audit_db_path)
    dest = Path(os.path.expanduser(os.path.expandvars(output)))
    dest.parent.mkdir(parents=True, exist_ok=True)

    if fmt == "jsonl":
        count = log.export_jsonl(dest)
    else:
        count = log.export_csv(dest)

    console.print(f"[green]Wrote {count} events to {dest}[/green]")


@audit.command(name="verify")
@click.option("--config", default="agentguard.yaml", show_default=True)
def audit_verify(config: str) -> None:
    """Verify the audit log hash chain integrity.

    A passing verification confirms no events have been tampered with,
    deleted, or inserted since the log was created.
    """
    from agentguard.audit_log import AuditLog

    cfg = _load_config(config)
    log = AuditLog(db_path=cfg.audit_db_path)

    console.print("Verifying audit log hash chain...")
    valid, message = log.verify_chain()

    if valid:
        console.print(f"[bold green]PASS[/bold green] {message}")
    else:
        err_console.print(f"[bold red]FAIL[/bold red] {message}")
        sys.exit(1)


# ---------------------------------------------------------------------------
# report group
# ---------------------------------------------------------------------------

@cli.group()
def report() -> None:
    """Compliance report commands."""


@report.command(name="fedramp")
@click.option("--config", default="agentguard.yaml", show_default=True)
@click.option(
    "--output",
    default="fedramp_evidence",
    show_default=True,
    help="Output file prefix (no extension).",
)
@click.option(
    "--format",
    "fmt",
    type=click.Choice(["markdown", "json", "both"]),
    default="both",
    show_default=True,
)
def report_fedramp(config: str, output: str, fmt: str) -> None:
    """Generate a FedRAMP SSP evidence report from the audit log."""
    from agentguard.reports.fedramp import FedRAMPReporter
    from agentguard.audit_log import AuditLog

    cfg = _load_config(config)
    log = AuditLog(db_path=cfg.audit_db_path)
    reporter = FedRAMPReporter(audit_log=log, config=cfg)

    if fmt in ("markdown", "both"):
        md_path = Path(f"{output}.md")
        reporter.generate_markdown(md_path)
        console.print(f"[green]FedRAMP evidence written to {md_path}[/green]")

    if fmt in ("json", "both"):
        json_path = Path(f"{output}.json")
        reporter.generate_json(json_path)
        console.print(f"[green]FedRAMP JSON evidence written to {json_path}[/green]")


@report.command(name="nist-ai-rmf")
@click.option("--config", default="agentguard.yaml", show_default=True)
@click.option("--output", default="nist_ai_rmf_assessment", show_default=True)
def report_nist_ai_rmf(config: str, output: str) -> None:
    """Generate a NIST AI RMF assessment report."""
    from agentguard.reports.nist_ai_rmf import AIRMFReporter
    from agentguard.audit_log import AuditLog

    cfg = _load_config(config)
    log = AuditLog(db_path=cfg.audit_db_path)
    reporter = AIRMFReporter(audit_log=log, config=cfg)

    md_path = Path(f"{output}.md")
    reporter.generate_markdown(md_path)
    console.print(f"[green]NIST AI RMF assessment written to {md_path}[/green]")


# ---------------------------------------------------------------------------
# policy group
# ---------------------------------------------------------------------------

@cli.group()
def policy() -> None:
    """Policy management commands."""


@policy.command(name="check")
@click.argument("file", type=click.Path(exists=True))
@click.option("--mode", type=click.Choice(["dev", "federal"]), default="dev")
def policy_check(file: str, mode: str) -> None:
    """Validate a policy YAML file.

    FILE: Path to the policy YAML file to validate.
    """
    from agentguard.policy_engine import PolicyEngine
    from agentguard.modes import Mode

    engine = PolicyEngine(mode=Mode(mode))
    errors = engine.validate_bundle_file(Path(file))

    if errors:
        err_console.print(f"[bold red]Policy validation failed:[/bold red]")
        for err in errors:
            err_console.print(f"  [red]- {err}[/red]")
        sys.exit(1)
    else:
        console.print(f"[bold green]Policy file is valid:[/bold green] {file}")


@cli.command()
def version() -> None:
    """Show AgentGuard version information."""
    console.print(f"[bold]AgentGuard MCP[/bold] version [green]{__version__}[/green]")
    console.print(f"Python {sys.version.split()[0]}")


if __name__ == "__main__":
    cli()
