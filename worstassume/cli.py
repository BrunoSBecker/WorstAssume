"""
WorstAssume CLI — entry point for the `worst` command.

Commands:
  worst enumerate     Adaptive IAM + resource enumeration for one account
                      (cross-account links are inferred automatically after each run)
  worst accounts      List / manage tracked accounts
  worst privesc       Find attack paths from a starting identity
  worst assess        Per-principal security misconfiguration assessment
  worst viz           Launch the interactive browser visualization
  worst graph-export  Export the resource graph to Cytoscape.js JSON (optional utility)
"""

from __future__ import annotations

import logging
import sys
from datetime import datetime

import click
from rich.console import Console
from rich.table import Table
from rich import box

from worstassume.db.engine import get_db_path, init_db, get_session

console = Console()


# ─── Global options ───────────────────────────────────────────────────────────

@click.group()
@click.option("--db", default=None, envvar="WORST_DB", help="Path to the SQLite DB file.")
@click.option("--debug", is_flag=True, default=False, help="Enable debug logging.")
@click.pass_context
def main(ctx: click.Context, db: str | None, debug: bool):
    """WorstAssume — stealth-first AWS IAM enumeration and multi-account graph tool."""
    ctx.ensure_object(dict)
    ctx.obj["db_path"] = db

    level = logging.DEBUG if debug else logging.WARNING
    logging.basicConfig(format="%(levelname)s [%(name)s] %(message)s", level=level)

    # Initialize DB (creates file if not exists)
    init_db(db)


# ─── enumerate ────────────────────────────────────────────────────────────────

@main.command()
@click.option("--profile", "-p", default=None, help="AWS CLI profile name.")
@click.option("--region", "-r", default="us-east-1", show_default=True, help="AWS region.")
@click.option("--access-key", default=None, envvar="AWS_ACCESS_KEY_ID")
@click.option("--secret-key", default=None, envvar="AWS_SECRET_ACCESS_KEY")
@click.option("--session-token", default=None, envvar="AWS_SESSION_TOKEN")
@click.option("--assume-role", "assume_role_arn", default=None, help="ARN of role to assume before enumerating.")
@click.option("--account-name", default=None, help="Human-readable account name to store in DB.")
@click.option("--stealth", is_flag=True, default=False, help="Add random jitter between API calls (slower but quieter).")
@click.pass_context
def enumerate(
    ctx, profile, region, access_key, secret_key, session_token,
    assume_role_arn, account_name, stealth
):
    """Run adaptive enumeration against an AWS account and store results in the DB."""
    import random
    import time

    from worstassume.session import SessionManager
    from worstassume.modules import identity as identity_mod
    from worstassume.core.capability import probe_capabilities
    from worstassume.modules import iam, ec2, s3, lambda_, ecs, vpc
    from worstassume.db import store

    def jitter():
        if stealth:
            time.sleep(random.uniform(0.3, 1.2))

    # ── 1. Build session ──────────────────────────────────────────────────────
    session = SessionManager(
        profile=profile,
        region=region,
        access_key=access_key,
        secret_key=secret_key,
        session_token=session_token,
        assume_role_arn=assume_role_arn,
    )

    # ── 2. Identity ───────────────────────────────────────────────────────────
    console.rule("[bold]WorstAssume Enumeration[/bold]")
    with console.status("[bold cyan]Identifying caller…"):
        try:
            identity = identity_mod.get_caller_identity(session)
        except RuntimeError as e:
            console.print(f"[red]✗ {e}[/red]")
            sys.exit(1)

    console.print(f"[bold green]✓[/bold green] Identity: [cyan]{identity.arn}[/cyan]")
    console.print(f"  Account: [yellow]{identity.account_id}[/yellow]  Type: {identity.principal_type}")
    jitter()

    # ── 3. DB: get/create account ─────────────────────────────────────────────
    db = get_session()
    try:
        account = store.get_or_create_account(
            db, identity.account_id, account_name=account_name, profile=profile
        )
        run = store.start_run(db, account)
        db.commit()

        # ── 4. Capability probes ───────────────────────────────────────────────
        with console.status("[bold cyan]Probing capabilities…"):
            cap = probe_capabilities(session, identity.arn)
        jitter()

        cap_dict = cap.to_dict()
        allowed = [k for k, v in cap_dict.items() if v]
        console.print(f"[bold green]✓[/bold green] Capabilities detected: [cyan]{', '.join(allowed) or 'none'}[/cyan]")

        # ── 5. Enumeration ─────────────────────────────────────────────────────
        modules_run = []

        def run_module(name, fn, *args):
            with console.status(f"[bold cyan]Enumerating {name}…"):
                fn(*args)
                db.commit()
            jitter()
            modules_run.append(name)

        run_module("IAM",    iam.enumerate,    session, db, account, cap)
        run_module("EC2",    ec2.enumerate,    session, db, account, cap)
        run_module("S3",     s3.enumerate,     session, db, account, cap)
        run_module("Lambda", lambda_.enumerate, session, db, account, cap)
        run_module("ECS",    ecs.enumerate,    session, db, account, cap)
        run_module("VPC",    vpc.enumerate,    session, db, account, cap)

        # ── 6. Finish run ──────────────────────────────────────────────────────
        store.touch_account(db, account)
        store.finish_run(db, run, capabilities=cap_dict, success=True)
        db.commit()

        # ── 6.5 Cross-account link inference (zero AWS calls) ─────────────────
        # Runs automatically after every enumeration so the attack graph always
        # reflects the latest trust relationships across all tracked accounts.
        from worstassume.core.cross_account import build_cross_account_links
        with console.status("[bold cyan]Inferring cross-account trust links…"):
            ca_links = build_cross_account_links(db)
            db.commit()
        if ca_links:
            console.print(f"  [dim]Cross-account links detected: {len(ca_links)}[/dim]")

        console.rule()
        console.print(f"[bold green]✓ Enumeration complete.[/bold green]  DB: [dim]{get_db_path()}[/dim]")
        console.print(f"  Modules run: {', '.join(modules_run)}")
        console.print(f"  Run [bold]worst viz[/bold] to explore the graph in your browser.")

    except Exception as e:
        logging.exception("Enumeration failed")
        console.print(f"[red]✗ Enumeration failed: {e}[/red]")
        store.finish_run(db, run, success=False, error_message=str(e))
        db.commit()
        sys.exit(1)
    finally:
        db.close()


# ─── accounts ─────────────────────────────────────────────────────────────────

@main.group()
def accounts():
    """Manage tracked AWS accounts in the local database."""


@accounts.command("list")
def accounts_list():
    """List all tracked accounts."""
    db = get_session()
    try:
        from worstassume.db.models import Account, Principal, Resource
        rows = db.query(Account).all()
        if not rows:
            console.print("[yellow]No accounts tracked yet. Run [bold]worst enumerate[/bold] first.[/yellow]")
            return

        table = Table(box=box.SIMPLE_HEAD, show_header=True, header_style="bold cyan")
        table.add_column("Account ID", style="cyan", no_wrap=True)
        table.add_column("Name")
        table.add_column("Org ID")
        table.add_column("Principals", justify="right")
        table.add_column("Resources", justify="right")
        table.add_column("Last Enumerated")

        for a in rows:
            p_count = db.query(Principal).filter_by(account_id=a.id).count()
            r_count = db.query(Resource).filter_by(account_id=a.id).count()
            last = str(a.last_enumerated_at)[:16] if a.last_enumerated_at else "—"
            table.add_row(
                a.account_id,
                a.account_name or "—",
                a.org_id or "—",
                str(p_count),
                str(r_count),
                last,
            )

        console.print(table)
    finally:
        db.close()


@accounts.command("delete")
@click.argument("account_id")
def accounts_delete(account_id: str):
    """Delete an account and all its data from the DB."""
    from worstassume.db.models import Account
    db = get_session()
    try:
        acct = db.query(Account).filter_by(account_id=account_id).first()
        if not acct:
            console.print(f"[red]Account {account_id} not found.[/red]")
            sys.exit(1)
        if not click.confirm(f"Delete account {account_id} and all its data?"):
            return
        db.delete(acct)
        db.commit()
        console.print(f"[green]✓ Deleted account {account_id}[/green]")
    finally:
        db.close()


# ─── graph export (standalone utility) ────────────────────────────────────────────────

@main.command("graph-export")
@click.option("--output", "-o", default="graph.json", show_default=True,
              help="Output path for Cytoscape.js-compatible JSON.")
def graph_export(output: str):
    """Export the resource graph to a Cytoscape.js-compatible JSON file.

    Useful for loading into the Cytoscape desktop application or custom frontends.
    The built-in viz server (worst viz) does not require this step.
    """
    import json
    from worstassume.core.resource_graph import build_graph, graph_to_cytoscape
    db = get_session()
    try:
        with console.status("[bold cyan]Building graph…"):
            G = build_graph(db)
            data = graph_to_cytoscape(G)
        with open(output, "w") as f:
            json.dump(data, f, indent=2)
        console.print(
            f"[green]✓ Graph exported to {output}[/green]  "
            f"({G.number_of_nodes()} nodes, {G.number_of_edges()} edges)"
        )
    finally:
        db.close()


# ─── privesc ──────────────────────────────────────────────────────────────────

_SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}
_SEV_COLOR = {"CRITICAL": "red", "HIGH": "yellow", "MEDIUM": "cyan"}


def _path_to_dict(p) -> dict:
    """Serialise a PathResult to a plain dict (JSON output + server re-use)."""
    return {
        "from_arn":  p.from_arn,
        "to_arn":    p.to_arn,
        "severity":  p.severity,
        "hops":      p.hops,
        "objective": p.objective,
        "steps": [
            {
                "actor":       s["actor"],
                "action":      s["action"],
                "target":      s["target"],
                "edge_type":   s["edge_type"],
                "explanation": s["explanation"],
            }
            for s in p.steps
        ],
    }


def _print_paths_table(paths) -> None:
    """Render a list of PathResult objects as a Rich table."""
    table = Table(box=box.SIMPLE_HEAD, header_style="bold red", show_lines=False)
    table.add_column("Severity", no_wrap=True, width=10)
    table.add_column("Hops",     justify="right", width=5)
    table.add_column("From",     width=28)
    table.add_column("Via",      width=40)
    table.add_column("To",       width=28)
    for p in paths:
        color = _SEV_COLOR.get(p.severity, "white")
        via   = ", ".join(dict.fromkeys(s["edge_type"] for s in p.steps))
        table.add_row(
            f"[{color}]{p.severity}[/{color}]",
            str(p.hops),
            p.from_arn.split("/")[-1],
            via,
            p.to_arn.split("/")[-1],
        )
    console.print(table)


@main.command()
@click.option("--from", "from_arn", required=True,
              help="Starting identity ARN (required).")
@click.option("--target", "objective", default=None,
              help=(
                  "Objective to reach. Syntax: permission:<svc>:<action> | "
                  "permission:*:* | resource:* | resource:<arn> | principal:<arn>. "
                  "Omit for unconstrained traversal."
              ))
@click.option("--max-hops", default=10, show_default=True,
              help="Maximum path length (hops).")
@click.option("--account-id", default=None,
              help="Restrict graph to a single AWS account ID.")
@click.option(
    "--min-severity", default="HIGH", show_default=True,
    type=click.Choice(["CRITICAL", "HIGH", "MEDIUM"], case_sensitive=False),
    help="Minimum severity to display.",
)
@click.option(
    "--output", default="table", show_default=True,
    type=click.Choice(["table", "json"], case_sensitive=False),
    help="Output format.",
)
@click.option("--persist/--no-persist", default=True, show_default=True,
              help="Persist discovered paths to the DB.")
@click.option("--verbose", "-v", is_flag=True, default=False,
              help="Print per-phase timing and enable DEBUG logging for the worstassume package.")
def privesc(
    from_arn: str,
    objective: str | None,
    max_hops: int,
    account_id: str | None,
    min_severity: str,
    output: str,
    persist: bool,
    verbose: bool,
):
    """Find attack paths from a starting identity.

    Examples:\n
      worst privesc --from arn:aws:iam::123:user/dev --target permission:*:*\n
      worst privesc --from arn:aws:iam::123:user/dev --target principal:arn:aws:iam::123:role/Admin\n
      worst privesc --from arn:aws:iam::123:user/dev   # unconstrained
    """
    import json as _json
    import time
    from worstassume.db.models import Account
    from worstassume.core.privilege_escalation import analyze_attack_paths

    if verbose:
        import logging as _logging
        _logging.getLogger("worstassume").setLevel(_logging.DEBUG)
        console.print("[dim]verbose mode — DEBUG logging enabled for worstassume[/dim]")

    def _phase(label: str):
        """Context manager that prints elapsed time when verbose is on."""
        import contextlib
        @contextlib.contextmanager
        def _cm():
            if verbose:
                console.print(f"[dim]  → {label}…[/dim]")
            t0 = time.perf_counter()
            yield
            elapsed = time.perf_counter() - t0
            if verbose:
                console.print(f"[dim]  ✓ {label} done in {elapsed:.2f}s[/dim]")
        return _cm()

    db = get_session()
    try:
        account = None
        if account_id:
            account = db.query(Account).filter_by(account_id=account_id).first()
            if not account:
                console.print(f"[red]Account {account_id!r} not found in DB.[/red]")
                return

        # Silently refresh cross-account links so the attack graph is always
        # up-to-date even if the user skipped enumerate on a second account.
        try:
            from worstassume.core.cross_account import build_cross_account_links
            with _phase("cross-account link refresh"):
                build_cross_account_links(db)
                db.commit()
        except Exception:
            pass  # Non-fatal — proceed with whatever is already in the DB

        with _phase("attack path analysis"):
            with console.status("[bold cyan]Analyzing attack paths…"):
                paths = analyze_attack_paths(
                    db,
                    from_arn=from_arn,
                    objective=objective,
                    max_hops=max_hops,
                    account=account,
                    persist_paths=persist,
                )

        # Filter by min_severity for display
        min_ord = _SEV_ORDER.get(min_severity.upper(), 99)
        paths   = [p for p in paths if _SEV_ORDER.get(p.severity, 99) <= min_ord]

        if not paths:
            console.print(f"[green]✓ No paths found at ≥ {min_severity} severity.[/green]")
            return

        if output == "json":
            console.print(_json.dumps([_path_to_dict(p) for p in paths], indent=2))
        else:
            _print_paths_table(paths)
            console.print(
                f"\n[bold]{len(paths)} path(s)[/bold] found — "
                "run [bold]worst viz[/bold] to explore in the browser."
            )
    finally:
        db.close()


# ─── assess ──────────────────────────────────────────────────────────────

@main.command()
@click.option("--account-id", default=None, help="Limit analysis to a single account.")
@click.option(
    "--min-severity",
    default="HIGH",
    show_default=True,
    type=click.Choice(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"], case_sensitive=False),
    help="Minimum severity to persist and display.",
)
@click.option(
    "--severity-config", "severity_config_path",
    default=None,
    help="Path to JSON file with per-rule severity overrides.",
)
def assess(account_id: str | None, min_severity: str, severity_config_path: str | None):
    """Run security misconfiguration assessment and persist findings to DB."""
    from worstassume.core.security_assessment import assess as run_assess, SeverityConfig
    from worstassume.db.models import Account

    db = get_session()
    try:
        account = None
        if account_id:
            account = db.query(Account).filter_by(account_id=account_id).first()
            if not account:
                console.print(f"[red]Account {account_id!r} not found in DB.[/red]")
                return

        cfg = None
        if severity_config_path:
            try:
                cfg = SeverityConfig.from_json(severity_config_path)
                console.print(f"[dim]Loaded severity config: {severity_config_path}[/dim]")
            except Exception as e:
                console.print(f"[yellow]Warning: could not load severity config — {e}[/yellow]")

        with console.status("[bold cyan]Running security assessment…"):
            findings = run_assess(db, account=account, min_severity=min_severity, severity_config=cfg)

        if not findings:
            console.print(f"[green]✓ No findings at or above {min_severity}.[/green]")
            return

        _SEV_COLOR = {"CRITICAL": "red", "HIGH": "yellow", "MEDIUM": "cyan", "LOW": "green", "INFO": "dim"}

        table = Table(box=box.SIMPLE_HEAD, header_style="bold cyan", show_lines=False)
        table.add_column("Severity", no_wrap=True, width=10)
        table.add_column("Category", no_wrap=True, width=18)
        table.add_column("Entity", width=30)
        table.add_column("Rule", width=30)
        table.add_column("Message")

        for f in sorted(findings, key=lambda x: (x.severity, x.category)):
            color = _SEV_COLOR.get(f.severity, "white")
            table.add_row(
                f"[{color}]{f.severity}[/{color}]",
                f.category,
                f.entity_name,
                f.path_id,
                f.message,
            )

        console.print(table)
        console.print(
            f"\n[bold]{len(findings)} finding(s)[/bold] persisted to DB — "
            f"run [bold]worst viz[/bold] to explore via the UI."
        )
    finally:
        db.close()


# ─── viz ──────────────────────────────────────────────────────────────────────

@main.command()
@click.option("--host", default="127.0.0.1", show_default=True)
@click.option("--port", "-p", default=3000, show_default=True)
@click.option("--open-browser", "open_browser", is_flag=True, default=True, show_default=True)
@click.option("--debug", is_flag=True, default=False, help="Enable debug logging in the terminal.")
def viz(host: str, port: int, open_browser: bool, debug: bool):
    """Launch the interactive browser visualization server."""
    import logging
    import uvicorn
    import webbrowser
    import threading
    from pathlib import Path

    # Configure Python logging so our log.info/debug calls are visible
    log_level = logging.DEBUG if debug else logging.INFO
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )
    # Always show worstassume package logs; suppress noisy libs
    logging.getLogger("worstassume").setLevel(log_level)
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING if not debug else logging.DEBUG)

    frontend_dist = Path(__file__).parent / "viz" / "frontend" / "dist"
    if not frontend_dist.exists():
        console.print("[yellow]⚠  React frontend not built yet.[/yellow]")
        console.print("   Run this first:")
        console.print("   [bold cyan]cd worstassume/viz/frontend && npm run build[/bold cyan]")
        console.print("   (falling back to legacy single-file UI)")

    url = f"http://{host}:{port}"
    console.print(f"[bold green]✓ Starting WorstAssume Viz at [link={url}]{url}[/link][/bold green]")
    console.print("  Press [bold]Ctrl+C[/bold] to stop.")
    if debug:
        console.print("  [dim]Debug logging enabled[/dim]")

    if open_browser:
        threading.Timer(1.2, lambda: webbrowser.open(url)).start()

    from worstassume.viz.server import app
    uvicorn.run(
        app,
        host=host,
        port=port,
        log_level="debug" if debug else "info",
    )
