"""``ares`` CLI (spec 26, 29).

Implements the operator surface: service control, investigation, events,
baseline and response commands. Commands that manage the systemd service are
Linux-only and print guidance elsewhere.
"""

from __future__ import annotations

import json
import logging
import platform
import time

import click
from rich.console import Console
from rich.table import Table

from ares.client import Ares
from ares.config import load_config
from ares.daemon import Daemon
from ares.scheduler import InvestigationScheduler

console = Console()


def _client(ctx: click.Context) -> Ares:
    return Ares.from_config(ctx.obj.get("config"))


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(package_name="ares-agent", prog_name="ares")
@click.option("--config", "-c", default=None, help="Path to config.yaml")
@click.option("--verbose", "-v", is_flag=True, help="Verbose logging")
@click.pass_context
def cli(ctx: click.Context, config: str | None, verbose: bool) -> None:
    """Ares — AI-native host security investigator."""
    ctx.ensure_object(dict)
    ctx.obj["config"] = config
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )


# -- status / doctor -------------------------------------------------------


@cli.command()
@click.pass_context
def status(ctx: click.Context) -> None:
    """Show host security status."""
    client = _client(ctx)
    s = client.status()
    table = Table(title="ares status", show_header=False)
    for k, v in s.items():
        table.add_row(str(k), json.dumps(v) if isinstance(v, (dict, list)) else str(v))
    console.print(table)
    client.close()


@cli.command()
@click.pass_context
def doctor(ctx: click.Context) -> None:
    """Run self-checks."""
    client = _client(ctx)
    checks = client.doctor()
    for name, ok in checks.items():
        mark = "[green]✓[/]" if ok else "[red]✗[/]"
        console.print(f"{mark} {name}")
    client.close()


# -- notifications ---------------------------------------------------------


@cli.group()
def notify() -> None:
    """Notification channels."""


@notify.command("channels")
@click.pass_context
def notify_channels(ctx: click.Context) -> None:
    """List the notification channels that are currently active."""
    from ares.config import load_config
    from ares.notifications import NotificationManager

    mgr = NotificationManager(load_config(ctx.obj.get("config")))
    active = [c for c in mgr.channels if c != "console"]
    console.print(f"active channels: {', '.join(mgr.channels) or 'none'}")
    if not active:
        console.print(
            "[yellow]No external channels configured.[/] Set e.g. "
            "ARES_SLACK_WEBHOOK, ARES_PAGERDUTY_ROUTING_KEY, or ARES_SMTP_HOST."
        )


@notify.command("test")
@click.option("--severity", default="high", help="Severity to send the test at")
@click.pass_context
def notify_test(ctx: click.Context, severity: str) -> None:
    """Send a test notification through every configured channel (spec §26.4)."""
    from ares.config import load_config
    from ares.notifications import NotificationManager
    from ares.notifications.base import Notification

    mgr = NotificationManager(load_config(ctx.obj.get("config")))
    console.print(f"sending test to: {', '.join(mgr.channels) or 'none'}")
    mgr.notify(
        Notification(
            title="Ares test notification",
            body="If you can read this, incident alerting is wired up correctly.",
            severity=severity,
        )
    )
    console.print(
        f"[green]done[/] (delivery healthy: {mgr.healthy})"
        if mgr.healthy
        else "[red]one or more channels failed — check logs[/]"
    )


# -- service management (systemd, Linux) -----------------------------------


@cli.command()
@click.pass_context
def init(ctx: click.Context) -> None:
    """Initialize configuration and state directories."""
    cfg = load_config(ctx.obj.get("config"))
    from pathlib import Path

    Path(cfg.storage.path).parent.mkdir(parents=True, exist_ok=True)
    console.print(f"[green]✓[/] state dir ready: {Path(cfg.storage.path).parent}")
    console.print(f"[green]✓[/] storage: {cfg.storage.path}")
    console.print(f"[green]✓[/] mode: {cfg.response.mode}")


@cli.command()
def install() -> None:
    """Install the systemd service (Linux only)."""
    if platform.system() != "Linux":
        console.print("[yellow]systemd install is Linux-only.[/] See systemd/ for unit files.")
        return
    console.print("Copy systemd/*.service and *.timer to /etc/systemd/system and run:")
    console.print("  sudo systemctl daemon-reload && sudo systemctl enable --now ares-daemon")


@cli.command()
@click.pass_context
def start(ctx: click.Context) -> None:
    """Run the continuous daemon in the foreground."""
    cfg = load_config(ctx.obj.get("config"))
    daemon = Daemon(cfg)
    console.print("[green]ares daemon starting[/] (Ctrl-C to stop)")
    console.print(f"capabilities: {daemon.capabilities()}")
    daemon.run_forever()


# -- daemon / investigator workers (spec 6.1, 6.2) -------------------------


@cli.group()
def daemon() -> None:
    """Continuous telemetry daemon."""


@daemon.command("run")
@click.pass_context
def daemon_run(ctx: click.Context) -> None:
    """`ares daemon run` — run the sensor daemon (spec 6.1)."""
    cfg = load_config(ctx.obj.get("config"))
    Daemon(cfg).run_forever()


@cli.group()
def investigator() -> None:
    """Investigation scheduler."""


@investigator.command("run")
@click.option("--once", is_flag=True, help="Run a single cycle and exit")
@click.pass_context
def investigator_run(ctx: click.Context, once: bool) -> None:
    """`ares investigator run` — run the one-minute scheduler (spec 6.2)."""
    from ares.storage import Store

    cfg = load_config(ctx.obj.get("config"))
    store = Store(cfg.storage.path)
    sched = InvestigationScheduler(cfg, store)
    if once:
        report = sched.run_cycle()
        console.print(json.dumps(report.__dict__, default=str, indent=2))
        store.close()
        return
    console.print(f"[green]investigator scheduler[/] every {cfg.investigation.interval_seconds}s")
    try:
        while True:
            sched.run_cycle()
            time.sleep(cfg.investigation.interval_seconds)
    except KeyboardInterrupt:  # pragma: no cover
        store.close()


# -- investigate / cases ---------------------------------------------------


@cli.command()
@click.pass_context
def investigate(ctx: click.Context) -> None:
    """Run a single investigation cycle now."""
    client = _client(ctx)
    console.print(json.dumps(client.investigate_now(), indent=2))
    client.close()


@cli.group()
def cases() -> None:
    """Manage investigation cases."""


@cases.command("list")
@click.option("--status", default=None)
@click.pass_context
def cases_list(ctx: click.Context, status: str | None) -> None:
    client = _client(ctx)
    table = Table("case_id", "priority", "score", "status", "title")
    for c in client.cases.list(status=status):
        table.add_row(
            c["case_id"],
            c.get("priority", ""),
            f"{c.get('risk_score', 0):.2f}",
            c.get("status", ""),
            (c.get("title") or "")[:60],
        )
    console.print(table)
    client.close()


@cases.command("show")
@click.argument("case_id")
@click.pass_context
def cases_show(ctx: click.Context, case_id: str) -> None:
    client = _client(ctx)
    case = client.cases.show(case_id)
    if not case:
        console.print("[red]case not found[/]")
    else:
        console.print_json(json.dumps(case, default=str))
    client.close()


@cases.command("investigate")
@click.argument("case_id")
@click.pass_context
def cases_investigate(ctx: click.Context, case_id: str) -> None:
    client = _client(ctx)
    console.print_json(json.dumps(client.cases.investigate(case_id), default=str))
    client.close()


@cases.command("close")
@click.argument("case_id")
@click.pass_context
def cases_close(ctx: click.Context, case_id: str) -> None:
    client = _client(ctx)
    client.cases.close(case_id)
    console.print(f"[green]closed[/] {case_id}")
    client.close()


@cases.command("feedback")
@click.argument("case_id")
@click.option("--label", required=True, help="benign|confirmed_malicious|false_positive|...")
@click.option("--note", default=None)
@click.pass_context
def cases_feedback(ctx: click.Context, case_id: str, label: str, note: str | None) -> None:
    client = _client(ctx)
    client.cases.feedback(case_id, label, note)
    console.print("[green]feedback recorded[/]")
    client.close()


# -- findings --------------------------------------------------------------


@cli.command()
@click.option("--severity", default=None)
@click.pass_context
def findings(ctx: click.Context, severity: str | None) -> None:
    """List findings."""
    client = _client(ctx)
    table = Table("rule_id", "severity", "score", "title")
    for f in client.findings.list(severity=severity):
        table.add_row(f["rule_id"], f["severity"], f"{f['risk_score']:.2f}", f["title"][:60])
    console.print(table)
    client.close()


# -- events ----------------------------------------------------------------


@cli.group()
def events() -> None:
    """Query collected events."""


@events.command("search")
@click.option("--process", default=None)
@click.option("--destination", default=None)
@click.option("--type", "event_type", default=None)
@click.pass_context
def events_search(ctx, process, destination, event_type) -> None:
    client = _client(ctx)
    results = client.store.search_events(
        process=process, destination=destination, event_type=event_type, limit=50
    )
    table = Table("time_ns", "type", "process_id", "detail")
    for e in results:
        detail = e.get("executable") or e.get("destination") or e.get("path") or ""
        table.add_row(str(e.timestamp_ns), e.type, (e.process_id or "")[:24], str(detail)[:50])
    console.print(table)
    client.close()


# -- baseline --------------------------------------------------------------


@cli.group()
def baseline() -> None:
    """Behavioural baseline."""


@baseline.command("status")
@click.pass_context
def baseline_status(ctx: click.Context) -> None:
    client = _client(ctx)
    console.print_json(json.dumps(client.store.baseline_summary()))
    client.close()


@baseline.command("freeze")
@click.pass_context
def baseline_freeze(ctx: click.Context) -> None:
    client = _client(ctx)
    client.store.freeze_baselines(True)
    console.print("[green]baselines frozen[/]")
    client.close()


@baseline.command("reset")
@click.confirmation_option(prompt="Reset all baselines?")
@click.pass_context
def baseline_reset(ctx: click.Context) -> None:
    client = _client(ctx)
    client.store.reset_baselines()
    console.print("[green]baselines reset[/]")
    client.close()


# -- actions ---------------------------------------------------------------


@cli.group()
def actions() -> None:
    """Response actions."""


@actions.command("list")
@click.option("--status", default=None)
@click.pass_context
def actions_list(ctx: click.Context, status: str | None) -> None:
    client = _client(ctx)
    table = Table("action_id", "type", "status", "approval", "reversible")
    for a in client.actions.list(status=status):
        table.add_row(
            a["action_id"],
            a["type"],
            a["status"],
            "yes" if a["requires_approval"] else "no",
            "yes" if a["reversible"] else "no",
        )
    console.print(table)
    client.close()


@actions.command("approve")
@click.argument("action_id")
@click.pass_context
def actions_approve(ctx: click.Context, action_id: str) -> None:
    client = _client(ctx)
    console.print_json(json.dumps(client.actions.approve(action_id), default=str))
    client.close()


@actions.command("reject")
@click.argument("action_id")
@click.pass_context
def actions_reject(ctx: click.Context, action_id: str) -> None:
    client = _client(ctx)
    client.actions.reject(action_id)
    console.print("[green]rejected[/]")
    client.close()


@actions.command("rollback")
@click.argument("action_id")
@click.pass_context
def actions_rollback(ctx: click.Context, action_id: str) -> None:
    client = _client(ctx)
    console.print_json(json.dumps(client.actions.rollback(action_id), default=str))
    client.close()


if __name__ == "__main__":  # pragma: no cover
    cli()
