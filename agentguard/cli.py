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


def _write_operator_secret(home: Path) -> Path:
    """Drop an operator-held secret for approve() HMAC (AG-BL-003).

    Creates ``~/.agentguard/operator.secret`` with a fresh 256-bit
    random value if one does not already exist. File permissions are
    locked to 0o600. Kept under ``~/.agentguard/`` so self-protection
    in standard or strict mode blocks agent sandbox reads.
    """
    import secrets as _secrets

    home.mkdir(parents=True, exist_ok=True)
    secret_path = home / "operator.secret"
    if secret_path.exists():
        return secret_path
    secret_path.write_text(_secrets.token_hex(32) + "\n", encoding="utf-8")
    try:
        os.chmod(secret_path, 0o600)
    except OSError:
        pass
    return secret_path


def _set_self_protection_mode_in_yaml(yaml_path: Path, mode: str) -> None:
    """Rewrite self_protection.mode in-place without disturbing other keys."""
    import yaml as _yaml

    with open(yaml_path) as f:
        data = _yaml.safe_load(f) or {}
    sp = data.get("self_protection") or {}
    sp["mode"] = mode
    data["self_protection"] = sp
    with open(yaml_path, "w") as f:
        _yaml.safe_dump(data, f, sort_keys=False)


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
@click.option(
    "--gen-key/--no-gen-key",
    default=True,
    help="Generate an Ed25519 signing keypair and bind it to the scaffolded "
         "YAML. Default is on so verify_chain() has a key to validate against "
         "(AG-BL-001).",
)
@click.option("--force", is_flag=True, default=False, help="Overwrite existing agentguard.yaml.")
@click.option(
    "--local",
    is_flag=True,
    default=False,
    help="Scaffold in the current directory instead of ~/.agentguard/.",
)
@click.option(
    "--self-protect",
    "self_protect_mode",
    type=click.Choice(["off", "standard", "strict"]),
    default=None,
    help="Self-protection mode. If omitted, an interactive prompt asks.",
)
@click.option(
    "--no-interactive",
    is_flag=True,
    default=False,
    help="Skip the wizard; use defaults (self_protect=off) for scripted installs.",
)
def init(
    gen_key: bool,
    force: bool,
    local: bool,
    self_protect_mode: Optional[str],
    no_interactive: bool,
) -> None:
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

    # Self-protection prompt / flag
    sp_mode = self_protect_mode
    if sp_mode is None:
        if no_interactive or not sys.stdin.isatty():
            sp_mode = "off"
            console.print(
                "[dim]Self-protection: [bold]off[/bold] "
                "(non-interactive install; use --self-protect standard|strict to change)[/dim]"
            )
        else:
            console.print(
                "\n[bold]Self-protection[/bold]\n"
                "Controls whether agents can modify or stop AgentGuard itself.\n"
                "  [1] [bold]Off[/bold]      — agent has full access (DEFAULT)\n"
                "  [2] Standard — reads logged; mutations need operator approval\n"
                "  [3] Strict   — any reference to ~/.agentguard/ denied outright"
            )
            choice = click.prompt(
                "Pick a self-protection mode", default="1",
                show_default=True, type=click.Choice(["1", "2", "3"]),
            )
            sp_mode = {"1": "off", "2": "standard", "3": "strict"}[choice]
            console.print(f"[green]Self-protection: {sp_mode}[/green]")

    # Patch the YAML if the chosen mode isn't the default off.
    if sp_mode != "off":
        _set_self_protection_mode_in_yaml(dest, sp_mode)

    console.print(
        f"[dim]Audit DB will be written to "
        f"[bold]{DEFAULT_AGENTGUARD_HOME / 'audit.db'}[/bold] "
        f"unless you change audit_db_path in the YAML.[/dim]"
    )
    if sp_mode == "standard":
        console.print(
            "[dim]Approve pending mutations with: "
            "[bold]agentguard approve <code>[/bold][/dim]"
        )

    if gen_key:
        from agentguard.audit_log import generate_signing_keypair
        import yaml as _yaml

        private_b64, public_b64 = generate_signing_keypair()
        # Bind the keypair directly into the scaffolded YAML so every
        # new install has a signing key + verify key by default — the
        # AG-BL-001 release-blocker fix.
        with open(dest) as f:
            data = _yaml.safe_load(f) or {}
        data["signing_key"] = private_b64
        data["verify_key"] = public_b64
        with open(dest, "w") as f:
            _yaml.safe_dump(data, f, sort_keys=False)

        # Also drop an operator secret used for HMAC on approvals.
        # Lives under ~/.agentguard/ so self-protection can guard it
        # from the agent sandbox (AG-BL-003).
        _write_operator_secret(DEFAULT_AGENTGUARD_HOME)

        console.print("\n[bold]Ed25519 Signing Keypair[/bold]")
        console.print(
            f"[green]Written to {dest} as signing_key + verify_key.[/green]"
        )
        console.print(
            f"[dim]Public key (share with auditors for independent verification):[/dim]"
        )
        console.print(f"  {public_b64}")
        console.print(
            "\n[yellow]Restrict YAML file access (chmod 600 / ACL) — it contains "
            "the private signing key.[/yellow]"
        )
    else:
        console.print(
            "\n[yellow]No signing keypair generated. verify_chain() will "
            "not be able to validate signatures. Rerun with --gen-key to "
            "enable AU-10 non-repudiation.[/yellow]"
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
@click.argument("code", required=False)
@click.option(
    "--deny",
    is_flag=True,
    default=False,
    help="Deny the request instead of approving it.",
)
def approve(code: Optional[str], deny: bool) -> None:
    """Approve or deny a pending self-protection mutation.

    Run without arguments to list every pending request. Run with a
    code to resolve it. Use ``--deny`` to explicitly reject.
    """
    from agentguard.approvals import (
        ApprovalManager,
        compute_operator_token,
        default_approvals_dir,
    )
    import time as _time

    mgr = ApprovalManager(default_approvals_dir())

    if not code:
        pending = mgr.list_pending()
        now = _time.time()
        if not pending:
            console.print("[dim]No pending AgentGuard approvals.[/dim]")
            return
        table = Table(box=box.SIMPLE, show_header=True, header_style="bold")
        table.add_column("Code", width=8)
        table.add_column("Agent", width=30)
        table.add_column("Tool", width=18)
        table.add_column("Path hit", width=30)
        table.add_column("Seconds left", justify="right")
        for p in pending:
            remaining = max(0, int(p.get("expires_at", now) - now))
            table.add_row(
                str(p.get("code", "")),
                str(p.get("agent_id", ""))[:30],
                str(p.get("tool_name", ""))[:18],
                str(p.get("path_hit", ""))[:30],
                str(remaining),
            )
        console.print(table)
        console.print(
            "[dim]To resolve: agentguard approve <code>  "
            "(add --deny to reject)[/dim]"
        )
        return

    # AG-BL-003: compute the HMAC token locally so the ApprovalManager
    # can distinguish an operator-issued approve/deny (has access to
    # ~/.agentguard/operator.secret) from a library-imported call.
    token = compute_operator_token(code)
    if deny:
        if mgr.deny(code, token=token):
            console.print(f"[yellow]Denied approval for code {code}.[/yellow]")
        else:
            err_console.print(
                f"[red]No pending request matched — wrong code, expired, or "
                f"missing operator secret.[/red]"
            )
            sys.exit(1)
    else:
        if mgr.approve(code, token=token):
            console.print(f"[green]Approved code {code}.[/green]")
        else:
            err_console.print(
                f"[red]No pending request matched — wrong code, expired, or "
                f"missing operator secret.[/red]"
            )
            sys.exit(1)


@cli.command()
@click.option(
    "--ref",
    default=None,
    help="Git ref (tag or SHA) to install. Defaults to latest main.",
)
@click.option(
    "--repo",
    default="tlancas25/agentguard-mcp",
    show_default=True,
    help="GitHub repo slug to install from.",
)
@click.option(
    "--dry-run",
    is_flag=True,
    default=False,
    help="Print the install command without executing.",
)
def update(ref: Optional[str], repo: str, dry_run: bool) -> None:
    """Re-install AgentGuard from GitHub in place.

    Detects whether the current install is managed by uv tool or pip and
    runs the matching reinstall command. Use ``--ref v0.2.0`` to pin a
    specific release tag or commit SHA.
    """
    import shutil as _shutil
    import subprocess

    ref = ref or "main"
    git_url = f"git+https://github.com/{repo}.git@{ref}"

    uv_available = _shutil.which("uv") is not None
    if uv_available:
        cmd = [
            "uv", "tool", "install", "--force", "--reinstall",
            "--python", "3.11", git_url,
        ]
    else:
        cmd = [sys.executable, "-m", "pip", "install", "-U", git_url]

    console.print(f"[bold]Update plan:[/bold] {' '.join(cmd)}")
    if dry_run:
        console.print("[yellow]--dry-run set; not executing.[/yellow]")
        return

    proc = subprocess.run(cmd, check=False)
    if proc.returncode != 0:
        err_console.print(
            f"[bold red]Update failed[/bold red] (exit {proc.returncode})"
        )
        sys.exit(proc.returncode)
    console.print(f"[green]AgentGuard updated from {ref}.[/green]")
    console.print(
        "[dim]Restart Claude Code (or any MCP client) to pick up the new version.[/dim]"
    )


@cli.command()
@click.option(
    "--dry-run",
    is_flag=True,
    default=False,
    help="Report problems without making changes.",
)
def repair(dry_run: bool) -> None:
    """Diagnose and repair a local AgentGuard install.

    Checks the user home directory, default config, audit DB parent dir,
    and hash-chain integrity. Fixes what it can. Exits non-zero if any
    issue is unresolvable without operator input.
    """
    from agentguard.config import DEFAULT_AGENTGUARD_HOME, DEFAULT_CONFIG_PATH

    problems: list[str] = []
    fixed: list[str] = []

    def _fix(msg: str, do: callable) -> None:  # type: ignore[valid-type]
        if dry_run:
            problems.append(f"{msg} [would fix]")
            return
        try:
            do()
            fixed.append(msg)
        except Exception as e:
            problems.append(f"{msg} [fix failed: {e}]")

    # 1) home dir
    if not DEFAULT_AGENTGUARD_HOME.exists():
        _fix(
            f"Create {DEFAULT_AGENTGUARD_HOME}",
            lambda: DEFAULT_AGENTGUARD_HOME.mkdir(parents=True, exist_ok=True),
        )
    else:
        fixed.append(f"{DEFAULT_AGENTGUARD_HOME} exists")

    # 2) default config
    if not DEFAULT_CONFIG_PATH.exists():
        def _scaffold() -> None:
            example = Path(__file__).parent.parent / "agentguard.yaml.example"
            if example.exists():
                shutil.copy(example, DEFAULT_CONFIG_PATH)
            else:
                DEFAULT_CONFIG_PATH.write_text(
                    "mode: dev\n"
                    "audit_db_path: ~/.agentguard/audit.db\n"
                    "policy_bundles: []\n"
                    "upstream_servers: []\n"
                )
        _fix(f"Scaffold {DEFAULT_CONFIG_PATH}", _scaffold)
    else:
        fixed.append(f"{DEFAULT_CONFIG_PATH} exists")

    # 3) audit DB parent + integrity check
    try:
        cfg = _load_config(str(DEFAULT_CONFIG_PATH))
        audit_parent = Path(cfg.audit_db_path).parent
        if not audit_parent.exists():
            _fix(
                f"Create {audit_parent}",
                lambda: audit_parent.mkdir(parents=True, exist_ok=True),
            )

        from agentguard.audit_log import AuditLog
        log = AuditLog(db_path=cfg.audit_db_path)
        valid, msg = log.verify_chain()
        if valid:
            fixed.append(f"audit chain verified: {msg}")
        else:
            problems.append(f"audit chain broken: {msg}")
    except Exception as e:
        problems.append(f"could not load config / audit log: {e}")

    # 4) binary self-test
    try:
        import agentguard
        fixed.append(f"agentguard package importable (v{agentguard.__version__})")
    except Exception as e:
        problems.append(f"agentguard package not importable: {e}")

    # Report
    for item in fixed:
        console.print(f"  [green]OK[/green]  {item}")
    for item in problems:
        err_console.print(f"  [red]FAIL[/red]  {item}")

    if problems:
        sys.exit(1)
    console.print(f"[bold green]Repair complete.[/bold green] {len(fixed)} checks passed.")


@cli.command(
    context_settings={"ignore_unknown_options": True, "allow_extra_args": True}
)
@click.argument("command_path", nargs=-1, type=click.UNPROCESSED)
@click.pass_context
def help(ctx: click.Context, command_path: tuple[str, ...]) -> None:
    """Show help for agentguard or a subcommand.

    Examples:

      agentguard help
      agentguard help audit
      agentguard help audit tail
      agentguard help run
    """
    target = cli
    resolved: list[str] = []
    for token in command_path:
        if isinstance(target, click.Group):
            nxt = target.get_command(ctx, token)
            if nxt is None:
                err_console.print(
                    f"[red]Unknown command:[/red] agentguard {' '.join(resolved + [token])}"
                )
                err_console.print("Try: [bold]agentguard help[/bold]")
                sys.exit(2)
            target = nxt
            resolved.append(token)
        else:
            err_console.print(
                f"[red]'{' '.join(resolved)}' takes no subcommands[/red]"
            )
            sys.exit(2)

    with click.Context(target, info_name=" ".join(["agentguard", *resolved])) as sub_ctx:
        click.echo(target.get_help(sub_ctx))


@cli.command()
def version() -> None:
    """Show AgentGuard version information."""
    console.print(f"[bold]AgentGuard MCP[/bold] version [green]{__version__}[/green]")
    console.print(f"Python {sys.version.split()[0]}")


if __name__ == "__main__":
    cli()
